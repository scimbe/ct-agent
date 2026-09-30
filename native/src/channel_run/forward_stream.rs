//! The channel TCP forward's stream engine (scimbe/ct-agent#255 slice 2, AUF-20260929-029):
//! the initiate-side local listener and the byte-transparent per-connection pump that rides
//! [`super::forward_wire`]'s framing inside one already-established A2A Noise session.
//!
//! Default off, same as [`super::forward`] (the accept-side policy gate this builds on, merged
//! in #257): neither side of `ct-agent channel` runs any of this unless its own env var is set.
//!
//! * **Initiate** (`CT_CHANNEL_FORWARD=<local>=<target>`, [`parse_forward_spec`]): binds
//!   `<local>` — loopback only, refused otherwise, see [`parse_forward_spec`] — and, for every
//!   TCP connection accepted there, opens one multiplexed stream asking the accepting peer to
//!   forward it to `<target>`.
//! * **Accept** (`CT_CHANNEL_FORWARD_ALLOW` non-empty): for every `Open` request the peer sends,
//!   re-uses [`super::forward::accept_forward_request_with`] — the already-shipped, already-
//!   tested policy gate — and, if allowed, dials `target` itself and pumps.
//!
//! Both engines are one `tokio::select!` loop each ([`run_forward_initiate_engine`],
//! [`run_forward_accept_engine`]), not a task-per-concern design: every per-stream pump lives in
//! a `tokio::task::JoinSet` OWNED by that loop, so when the loop's own task is aborted (the
//! channel session ending, same [`crate::task_guard::TaskGuard`] discipline every other
//! `ChannelLocal` variant already uses) every forwarded stream is torn down with it — no
//! orphaned sockets survive the session that opened them.
//!
//! Half-close is deliberately not modeled on the wire: a [`super::forward_wire::Frame::Close`]
//! ends the WHOLE logical stream in both directions, even though the local half that triggered
//! it may only have seen its own read side EOF. A real TCP half-close (write shutdown, keep
//! reading) surviving the tunnel would need a fourth frame kind; every actual accept criterion
//! for this slice is satisfied by whole-stream teardown, so that stays a documented follow-up
//! rather than added here.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::forward::accept_forward_request_with;
use super::forward_wire::Frame;
use super::service_calls::LocalDuplex;
use crate::events;
use crate::task_guard::TaskGuard;

/// `CT_CHANNEL_FORWARD=<local>=<target>`: the initiate side's one forward mapping. Unset (the
/// shipped default) leaves `channel_local` on whatever else it would otherwise build.
pub const FORWARD_ENV: &str = "CT_CHANNEL_FORWARD";

/// `CT_CHANNEL_FORWARD_MAX_STREAMS`: caps concurrently-open forwarded TCP streams on ONE channel
/// session. Read independently by each side (an operator can bound either member on its own);
/// whichever side's cap is smaller is the one that actually bites.
pub const FORWARD_MAX_STREAMS_ENV: &str = "CT_CHANNEL_FORWARD_MAX_STREAMS";
/// See [`FORWARD_MAX_STREAMS_ENV`]. Small on purpose: a member that wants more says so.
pub const DEFAULT_MAX_STREAMS: usize = 16;

/// `CT_CHANNEL_FORWARD_IDLE_SECS`: a forwarded stream with no bytes moved in EITHER direction
/// for this long is closed (frees the id and, on the accept side, the dialed socket).
pub const FORWARD_IDLE_SECS_ENV: &str = "CT_CHANNEL_FORWARD_IDLE_SECS";
/// See [`FORWARD_IDLE_SECS_ENV`].
pub const DEFAULT_IDLE_SECS: u64 = 300;

/// One direction's read chunk. Matches [`ct_common::noise::noise_pump`]'s own `CHUNK` so a
/// forwarded byte's round trip through this mux costs no more copying than the base pump would.
const DATA_CHUNK_LEN: usize = 16 * 1024;

/// Bound on the per-stream inbound queue (peer→local) and the per-engine outbound queue
/// (every stream's frames, serialized onto the wire by one writer). Backpressure, not data
/// loss: a full queue makes the sender's `.send().await` wait rather than drop a byte.
const CHANNEL_CAP: usize = 64;

/// The application duplex [`run_channel_session_on_stream`](super::run_channel_session_on_stream)
/// pumps has its own internal buffer too; this is that buffer's size for a forward session,
/// matching [`super::service_calls::serve_local`]'s.
const ENGINE_DUPLEX_BUF: usize = 1 << 16;

/// One [`FORWARD_ENV`] mapping, already validated: `listen` is loopback (enforced at parse
/// time, not just documented — see [`parse_forward_spec`]), `target` is the peer-facing
/// `host:port` string the accept side's own allowlist ([`super::forward::FORWARD_ALLOW_ENV`])
/// judges — this side never canonicalizes or validates it beyond "non-empty".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    pub listen: SocketAddr,
    pub target: String,
}

/// Parse `CT_CHANNEL_FORWARD`'s `<local>=<target>` value. `<local>` must parse as a `host:port`
/// **loopback** address — refused otherwise, so a typo (or a deliberately non-loopback value)
/// can never bind this listener beyond the host it runs on ("Listener nur auf Loopback" is an
/// invariant this function enforces, not a convention the caller has to remember). `<target>` is
/// carried to the peer as-is; only its OWN allowlist decides whether it may be dialed.
pub fn parse_forward_spec(raw: &str) -> Result<ForwardSpec, String> {
    let (local, target) = raw
        .split_once('=')
        .ok_or_else(|| format!("{FORWARD_ENV} must be <local>=<target>, got {raw:?}"))?;
    let listen: SocketAddr = local
        .trim()
        .parse()
        .map_err(|e| format!("{FORWARD_ENV}: invalid local address {local:?}: {e}"))?;
    if !listen.ip().is_loopback() {
        return Err(format!(
            "{FORWARD_ENV}: local address {listen} is not loopback -- the forward listener may only bind 127.0.0.1/::1"
        ));
    }
    let target = target.trim();
    if target.is_empty() {
        return Err(format!("{FORWARD_ENV}: empty target in {raw:?}"));
    }
    Ok(ForwardSpec {
        listen,
        target: target.to_string(),
    })
}

/// [`FORWARD_MAX_STREAMS_ENV`] parsed with the shipped default; any non-positive or unparseable
/// value is treated as unset rather than as "no limit" — this cap must never silently disappear.
pub fn max_streams_from_env(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_STREAMS)
}

/// [`FORWARD_IDLE_SECS_ENV`] parsed with the shipped default, same non-positive-is-unset rule
/// as [`max_streams_from_env`].
pub fn idle_timeout_from_env(raw: Option<&str>) -> Duration {
    Duration::from_secs(
        raw.and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_IDLE_SECS),
    )
}

/// The initiate side's local app duplex (#255 slice 2): binds `spec.listen` **synchronously**
/// (a `std::net::TcpListener`, matching [`super::service_calls::spawn_stream_handler`]'s own
/// "surface a construction failure at `channel_local()` time, not on first poll" posture) so an
/// address already in use, or a loopback-only violation ([`parse_forward_spec`]'s own check,
/// belt-and-suspenders here since this is the actual bind), fails loudly before the session is
/// even attempted. Everything after the bind — accepting connections, running the mux — runs in
/// the spawned, [`TaskGuard`]-owned engine task returned inside the [`LocalDuplex`].
///
/// Returns the bound address alongside the duplex: `spec.listen`'s port may be `0` (OS-assigned),
/// so this is the only way a caller — the operator-facing log line in `channel_local`, or a test
/// binding an ephemeral port — learns the address that is actually listening.
pub(crate) fn forward_initiate_local(
    spec: &ForwardSpec,
    max_streams: usize,
    idle: Duration,
) -> io::Result<(LocalDuplex, SocketAddr)> {
    let std_listener = std::net::TcpListener::bind(spec.listen)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let bound = listener.local_addr()?;
    let (session_side, engine_side) = tokio::io::duplex(ENGINE_DUPLEX_BUF);
    let target = spec.target.clone();
    let pump = TaskGuard::spawn(async move {
        run_forward_initiate_engine(engine_side, listener, target, max_streams, idle).await;
    });
    Ok((LocalDuplex::with_pump(session_side, pump), bound))
}

/// The accept side's local app duplex (#255 slice 2): no listener to bind (this side only ever
/// reacts to the peer's `Open` requests), so construction cannot fail the way the initiate side
/// can — the allowlist/non-loopback strings are captured once here (not re-read from the live
/// environment per request) so behavior is pinned to the values `channel_local` saw when it
/// built this session, and so a test can drive the engine without `std::env::set_var` (the same
/// reason [`super::forward::accept_forward_request_with`] itself takes them as parameters).
pub(crate) fn forward_accept_local(
    allow_raw: Option<String>,
    non_loopback_raw: Option<String>,
    max_streams: usize,
    idle: Duration,
) -> LocalDuplex {
    let (session_side, engine_side) = tokio::io::duplex(ENGINE_DUPLEX_BUF);
    let pump = TaskGuard::spawn(async move {
        run_forward_accept_engine(engine_side, allow_raw, non_loopback_raw, max_streams, idle)
            .await;
    });
    LocalDuplex::with_pump(session_side, pump)
}

/// What the demuxer hands a stream's pump for its own inbound side: either bytes the peer sent
/// for this stream, or "the peer says this stream is done" (a received [`Frame::Close`]).
enum StreamIn {
    Data(Vec<u8>),
    Closed,
}

/// Byte-transparent pump for ONE forwarded TCP connection (either side: the initiate side's
/// locally-accepted client, or the accept side's freshly-dialed target) — the "je TCP-
/// Verbindung ein byte-transparenter Stream" primitive both engines spawn one of per stream.
///
/// Ends when both directions are done: `tcp`'s read side EOFs/errors (sends one `Close` out,
/// keeps servicing inbound so a peer reply in flight isn't dropped) AND the peer sends `Close`
/// (shuts `tcp`'s write half). Also ends — sending one `Close{reason: "idle timeout"}` — when a
/// full `idle` period passes with NEITHER direction moving a byte: `tokio::select!` re-creates
/// the `sleep(idle)` future fresh every loop iteration, so any activity on either of the other
/// two branches resets it, exactly the semantics `CT_CHANNEL_FORWARD_IDLE_SECS` promises.
///
/// Returns `(bytes_out, bytes_in)`: bytes read from `tcp` and sent to the peer, and bytes
/// received from the peer and written to `tcp` — the accept side's `forward_open`/`forward_close`
/// events report these directly.
async fn pump_forward_stream(
    id: u32,
    tcp: TcpStream,
    outbound: mpsc::Sender<Frame>,
    mut inbound: mpsc::Receiver<StreamIn>,
    idle: Duration,
) -> (u64, u64) {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let mut buf = vec![0u8; DATA_CHUNK_LEN];
    let mut bytes_out: u64 = 0;
    let mut bytes_in: u64 = 0;
    let mut tcp_eof = false;
    let mut peer_eof = false;
    loop {
        if tcp_eof && peer_eof {
            break;
        }
        tokio::select! {
            r = tcp_r.read(&mut buf), if !tcp_eof => {
                match r {
                    Ok(0) | Err(_) => {
                        tcp_eof = true;
                        let _ = outbound.send(Frame::Close { id, reason: None }).await;
                    }
                    Ok(n) => {
                        bytes_out += n as u64;
                        if outbound.send(Frame::Data { id, payload: buf[..n].to_vec() }).await.is_err() {
                            break; // the engine loop ended -- nothing left to deliver to
                        }
                    }
                }
            }
            msg = inbound.recv(), if !peer_eof => {
                match msg {
                    Some(StreamIn::Data(payload)) => {
                        bytes_in += payload.len() as u64;
                        if tcp_w.write_all(&payload).await.is_err() {
                            tcp_eof = true;
                        }
                    }
                    Some(StreamIn::Closed) | None => {
                        peer_eof = true;
                        let _ = tcp_w.shutdown().await;
                    }
                }
            }
            _ = tokio::time::sleep(idle) => {
                let _ = outbound.send(Frame::Close { id, reason: Some("idle timeout".to_string()) }).await;
                break;
            }
        }
    }
    (bytes_out, bytes_in)
}

/// The initiate side's engine (#255 slice 2): accept TCP connections on `listener` and, for
/// each, allocate a stream id, tell the peer to open it (`Frame::Open`), then run
/// [`pump_forward_stream`]. Concurrently demuxes inbound `Data`/`Close` frames from `engine_side`
/// to the right stream, and serializes every stream's outbound frames back onto it. One
/// `tokio::select!` loop, so a session end (the peer's transport closing, read/write error)
/// drops the whole `JoinSet` — and with it every still-forwarding TCP connection — in one place.
async fn run_forward_initiate_engine(
    engine_side: tokio::io::DuplexStream,
    listener: TcpListener,
    target: String,
    max_streams: usize,
    idle: Duration,
) {
    let (mut mux_read, mut mux_write) = tokio::io::split(engine_side);
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let mut inbound_txs: HashMap<u32, mpsc::Sender<StreamIn>> = HashMap::new();
    let mut streams: JoinSet<u32> = JoinSet::new();
    let mut next_id: u32 = 1;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, _peer_addr)) => {
                        if inbound_txs.len() >= max_streams {
                            // #255 acceptance 3: over the cap, refuse the local connection
                            // immediately (a deterministic close) rather than silently queuing
                            // it in the OS backlog -- a caller sees the limit bite at once.
                            drop(tcp);
                            continue;
                        }
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        let (tx, rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
                        inbound_txs.insert(id, tx);
                        let out_tx2 = out_tx.clone();
                        let target2 = target.clone();
                        streams.spawn(async move {
                            if out_tx2.send(Frame::Open { id, target: target2 }).await.is_ok() {
                                pump_forward_stream(id, tcp, out_tx2, rx, idle).await;
                            }
                            id
                        });
                    }
                    Err(e) => eprintln!("ct-agent channel: forward listener accept error: {e}"),
                }
            }
            frame = Frame::read(&mut mux_read) => {
                match frame {
                    Ok(Frame::Data { id, payload }) => {
                        if let Some(tx) = inbound_txs.get(&id) {
                            let _ = tx.send(StreamIn::Data(payload)).await;
                        }
                    }
                    Ok(Frame::Close { id, .. }) => {
                        if let Some(tx) = inbound_txs.remove(&id) {
                            let _ = tx.send(StreamIn::Closed).await;
                        }
                    }
                    // The initiate side never receives Open -- only ever sends it. A peer that
                    // sends one anyway gets ignored, not a torn-down session over one bad frame.
                    Ok(Frame::Open { .. }) => {}
                    Err(_) => break, // the channel session ended
                }
            }
            frame = out_rx.recv() => {
                // None: out_tx clones always outlive this branch; unreachable in practice
                if let Some(f) = frame {
                    if f.write(&mut mux_write).await.is_err() {
                        break;
                    }
                }
            }
            Some(done) = streams.join_next(), if !streams.is_empty() => {
                if let Ok(id) = done {
                    inbound_txs.remove(&id);
                }
            }
        }
    }
}

/// The accept side's engine (#255 slice 2): for every `Frame::Open` the peer sends, re-check
/// the already-shipped policy gate ([`accept_forward_request_with`] -- it emits the
/// `forward_refused` event itself on a refusal) and, if allowed, dial `target` and run
/// [`pump_forward_stream`], emitting `forward_open`/`forward_close` around it. Same one-loop,
/// one-`JoinSet` shape as [`run_forward_initiate_engine`] and the same session-end teardown.
async fn run_forward_accept_engine(
    engine_side: tokio::io::DuplexStream,
    allow_raw: Option<String>,
    non_loopback_raw: Option<String>,
    max_streams: usize,
    idle: Duration,
) {
    let (mut mux_read, mut mux_write) = tokio::io::split(engine_side);
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let mut inbound_txs: HashMap<u32, mpsc::Sender<StreamIn>> = HashMap::new();
    let mut streams: JoinSet<(u32, u64, u64)> = JoinSet::new();

    loop {
        tokio::select! {
            frame = Frame::read(&mut mux_read) => {
                match frame {
                    Ok(Frame::Open { id, target }) => {
                        if inbound_txs.len() >= max_streams {
                            let _ = out_tx
                                .send(Frame::Close { id, reason: Some(format!("{FORWARD_MAX_STREAMS_ENV} reached")) })
                                .await;
                            continue;
                        }
                        match accept_forward_request_with(&target, allow_raw.as_deref(), non_loopback_raw.as_deref()) {
                            Err(reason) => {
                                // accept_forward_request_with already emitted forward_refused.
                                let _ = out_tx.send(Frame::Close { id, reason: Some(reason) }).await;
                            }
                            Ok(()) => {
                                let (tx, rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
                                inbound_txs.insert(id, tx);
                                let out_tx2 = out_tx.clone();
                                streams.spawn(dial_and_pump_forward_target(id, target, out_tx2, rx, idle));
                            }
                        }
                    }
                    Ok(Frame::Data { id, payload }) => {
                        if let Some(tx) = inbound_txs.get(&id) {
                            let _ = tx.send(StreamIn::Data(payload)).await;
                        }
                    }
                    Ok(Frame::Close { id, .. }) => {
                        if let Some(tx) = inbound_txs.remove(&id) {
                            let _ = tx.send(StreamIn::Closed).await;
                        }
                    }
                    Err(_) => break,
                }
            }
            frame = out_rx.recv() => {
                // None: out_tx clones always outlive this branch; unreachable in practice
                if let Some(f) = frame {
                    if f.write(&mut mux_write).await.is_err() {
                        break;
                    }
                }
            }
            Some(done) = streams.join_next(), if !streams.is_empty() => {
                if let Ok((id, ..)) = done {
                    inbound_txs.remove(&id);
                }
            }
        }
    }
}

/// The accept side's per-stream body: dial `target` (already policy-approved by the caller),
/// bracket the dial + [`pump_forward_stream`] with `forward_open`/`forward_close`
/// (scimbe/ct-agent#255 acceptance 2 — `bytes_in`/`bytes_out` on the close event), and on a dial
/// failure tell the peer via `Close` instead of ever opening (never a bare stall). Returns
/// `(id, bytes_out, bytes_in)` -- the engine only needs `id` back, but returning the byte
/// counts too lets a test call this directly and assert the SAME numbers the emitted
/// `forward_close` event carries, without needing to intercept `events::emit` itself.
async fn dial_and_pump_forward_target(
    id: u32,
    target: String,
    outbound: mpsc::Sender<Frame>,
    inbound: mpsc::Receiver<StreamIn>,
    idle: Duration,
) -> (u32, u64, u64) {
    match TcpStream::connect(&target).await {
        Ok(tcp) => {
            events::emit(
                events::FORWARD_OPEN,
                serde_json::json!({ "target": target }),
            );
            let (bytes_out, bytes_in) = pump_forward_stream(id, tcp, outbound, inbound, idle).await;
            events::emit(
                events::FORWARD_CLOSE,
                serde_json::json!({ "target": target, "bytes_in": bytes_in, "bytes_out": bytes_out }),
            );
            (id, bytes_out, bytes_in)
        }
        Err(e) => {
            let _ = outbound
                .send(Frame::Close {
                    id,
                    reason: Some(format!("dial failed: {e}")),
                })
                .await;
            (id, 0, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forward_spec_requires_loopback_and_both_parts() {
        assert_eq!(
            parse_forward_spec("127.0.0.1:2222=127.0.0.1:5432").unwrap(),
            ForwardSpec {
                listen: "127.0.0.1:2222".parse().unwrap(),
                target: "127.0.0.1:5432".to_string()
            }
        );
        assert_eq!(
            parse_forward_spec("[::1]:2222=db.internal:5432").unwrap(),
            ForwardSpec {
                listen: "[::1]:2222".parse().unwrap(),
                target: "db.internal:5432".to_string()
            },
            "the target is carried opaquely -- only the accept side's allowlist judges it"
        );
        for bad in [
            "no-equals-sign",
            "127.0.0.1:2222=",
            "=127.0.0.1:5432",
            "not-an-addr=127.0.0.1:5432",
        ] {
            assert!(parse_forward_spec(bad).is_err(), "{bad}");
        }
        let non_loopback = parse_forward_spec("203.0.113.9:2222=127.0.0.1:5432")
            .expect_err("must refuse a non-loopback local address");
        assert!(non_loopback.contains("loopback"), "{non_loopback}");
    }

    #[test]
    fn max_streams_and_idle_env_parsing_falls_back_on_anything_non_positive() {
        assert_eq!(max_streams_from_env(None), DEFAULT_MAX_STREAMS);
        assert_eq!(max_streams_from_env(Some("0")), DEFAULT_MAX_STREAMS);
        assert_eq!(max_streams_from_env(Some("nope")), DEFAULT_MAX_STREAMS);
        assert_eq!(max_streams_from_env(Some("3")), 3);

        assert_eq!(
            idle_timeout_from_env(None),
            Duration::from_secs(DEFAULT_IDLE_SECS)
        );
        assert_eq!(
            idle_timeout_from_env(Some("0")),
            Duration::from_secs(DEFAULT_IDLE_SECS)
        );
        assert_eq!(idle_timeout_from_env(Some("45")), Duration::from_secs(45));
    }

    #[tokio::test]
    async fn pump_forward_stream_is_byte_transparent_both_directions_and_reports_byte_counts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let mut server = accept.await.unwrap();

        let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        let (in_tx, in_rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
        let pump = tokio::spawn(pump_forward_stream(
            1,
            client,
            out_tx,
            in_rx,
            Duration::from_secs(30),
        ));

        // tcp -> outbound Data frame
        server.write_all(b"from-target").await.unwrap();
        let got = out_rx.recv().await.unwrap();
        assert_eq!(
            got,
            Frame::Data {
                id: 1,
                payload: b"from-target".to_vec()
            }
        );

        // inbound Data -> tcp
        in_tx
            .send(StreamIn::Data(b"from-peer".to_vec()))
            .await
            .unwrap();
        let mut buf = [0u8; 9];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from-peer");

        // tcp EOF -> one Close out, pump keeps servicing inbound until told Closed too
        drop(server);
        assert_eq!(
            out_rx.recv().await.unwrap(),
            Frame::Close {
                id: 1,
                reason: None
            }
        );
        in_tx.send(StreamIn::Closed).await.unwrap();
        let (bytes_out, bytes_in) = pump.await.unwrap();
        assert_eq!(bytes_out, "from-target".len() as u64);
        assert_eq!(bytes_in, "from-peer".len() as u64);
    }

    #[tokio::test]
    async fn pump_forward_stream_closes_on_idle_with_no_traffic_either_way() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap(); // held open -- no EOF on its own

        let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        let (_in_tx, in_rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
        let idle = Duration::from_millis(50);
        let pump = tokio::spawn(pump_forward_stream(1, client, out_tx, in_rx, idle));

        let closed = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("idle timeout must fire")
            .expect("a Close frame is sent");
        assert_eq!(
            closed,
            Frame::Close {
                id: 1,
                reason: Some("idle timeout".to_string())
            }
        );
        let _ = pump.await;
    }

    #[tokio::test]
    async fn dial_and_pump_forward_target_emits_forward_open_and_close_with_the_returned_byte_counts(
    ) {
        // #255 acceptance 2: forward_open/forward_close actually fire around a real dial, and
        // the byte counts the forward_close event carries are exactly what was moved -- proven
        // here by asserting the SAME numbers this function returns (see its own doc comment for
        // why returning them is how this gets tested without intercepting events::emit).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            tcp.read_exact(&mut buf).await.unwrap();
            tcp.write_all(b"world!").await.unwrap();
            drop(tcp);
        });

        let open_before = events::EVENT_COUNTS.get(events::FORWARD_OPEN);
        let close_before = events::EVENT_COUNTS.get(events::FORWARD_CLOSE);

        let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        let (in_tx, in_rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
        let task = tokio::spawn(dial_and_pump_forward_target(
            1,
            addr.to_string(),
            out_tx,
            in_rx,
            Duration::from_secs(30),
        ));

        in_tx.send(StreamIn::Data(b"hello".to_vec())).await.unwrap();
        assert_eq!(
            out_rx.recv().await.unwrap(),
            Frame::Data {
                id: 1,
                payload: b"world!".to_vec()
            }
        );
        echo.await.unwrap();
        assert_eq!(
            out_rx.recv().await.unwrap(),
            Frame::Close {
                id: 1,
                reason: None
            }
        );
        in_tx.send(StreamIn::Closed).await.unwrap();

        let (id, bytes_out, bytes_in) = task.await.unwrap();
        assert_eq!(id, 1);
        assert_eq!(
            bytes_out,
            "world!".len() as u64,
            "bytes read from the target and sent to the peer"
        );
        assert_eq!(
            bytes_in,
            "hello".len() as u64,
            "bytes received from the peer and written to the target"
        );

        assert_eq!(
            events::EVENT_COUNTS.get(events::FORWARD_OPEN),
            open_before + 1
        );
        assert_eq!(
            events::EVENT_COUNTS.get(events::FORWARD_CLOSE),
            close_before + 1
        );

        // The shape a real forward_close event carries, built from the same values this
        // function just returned -- the codebase's established pattern (see forward.rs's own
        // `a_refused_request_writes_a_forward_refused_event`) for pinning an emitted event's
        // fields without a capture hook on `events::emit` itself.
        let ev = events::Event::new(
            events::FORWARD_CLOSE,
            serde_json::json!({ "target": addr.to_string(), "bytes_in": bytes_in, "bytes_out": bytes_out }),
        );
        assert_eq!(ev.kind, "forward_close");
        assert_eq!(ev.to_json()["bytes_in"], bytes_in);
        assert_eq!(ev.to_json()["bytes_out"], bytes_out);
    }

    #[tokio::test]
    async fn dial_and_pump_forward_target_closes_the_stream_instead_of_opening_on_a_failed_dial() {
        // An unreachable target must never leave the peer waiting -- Close, not a silent stall,
        // and no forward_open (nothing was ever actually opened).
        let unbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unbound.local_addr().unwrap();
        drop(unbound); // now nothing listens there

        let open_before = events::EVENT_COUNTS.get(events::FORWARD_OPEN);
        let (out_tx, mut out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        let (_in_tx, in_rx) = mpsc::channel::<StreamIn>(CHANNEL_CAP);
        let (id, bytes_out, bytes_in) = dial_and_pump_forward_target(
            9,
            dead_addr.to_string(),
            out_tx,
            in_rx,
            Duration::from_secs(30),
        )
        .await;

        assert_eq!((id, bytes_out, bytes_in), (9, 0, 0));
        match out_rx.recv().await {
            Some(Frame::Close {
                id: 9,
                reason: Some(reason),
            }) => assert!(reason.contains("dial failed"), "{reason}"),
            other => panic!("expected a Close with a dial-failed reason, got {other:?}"),
        }
        assert_eq!(
            events::EVENT_COUNTS.get(events::FORWARD_OPEN),
            open_before,
            "a failed dial never opens"
        );
    }
}
