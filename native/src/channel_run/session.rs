//! The A2A **session-I/O** cluster -- drives an already-established transport (a QUIC
//! `Connection`, or already-split TLS-TCP relay stream halves) through one A2A channel
//! session, independent of how the connection came to be (direct, edge relay, `:443`
//! front door). One-directional: everything here is called BY the join/admission/relay
//! machinery still in `mod.rs` and its siblings, but nothing here calls back into them
//! (consolidation program: module split, slice 6 -- moved verbatim out of the former
//! single-file `channel_run.rs`, ct-agent#44).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::Connection;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use ct_common::a2a::{a2a_initiate, a2a_respond_verified};
use ct_common::channel_quic::DIRECT_STREAM_SETUP_TIMEOUT;
use ct_common::noise::noise_pump;

/// Which side of the A2A session this agent drives. Selected from the channel
/// grant's `Direction`: the initiator dials + opens the stream; the responder
/// accepts. (In `Noise_IK` the initiator also pins the peer's static key.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    /// Dial the peer and open the bi-stream (grant `Direction::Initiate`).
    Initiate,
    /// Accept the peer's bi-stream (grant `Direction::Accept`).
    Accept,
}

/// A quinn bi-stream (`SendStream` + `RecvStream`) presented as one combined
/// `AsyncRead + AsyncWrite`, so [`noise_pump`] (which `tokio::io::split`s a single
/// duplex) can relay over it. Reads delegate to `recv`, writes to `send`.
// A combined duplex from separate write/read halves. Generic over the halves so it
// wraps both a quinn `SendStream`/`RecvStream` pair (the direct/QUIC path) and the
// split halves of a `:443`/TLS-TCP relay stream (#106 relay-leg-443).
struct BiStream<W, R> {
    send: W,
    recv: R,
}

// quinn's Send/RecvStream carry inherent poll_* methods (quinn error types) that
// shadow the tokio trait methods, so delegate with fully-qualified trait syntax
// (harmless for the generic case, where no inherent methods exist).
impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncRead for BiStream<W, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncWrite for BiStream<W, R> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// #248: process-lifetime channel traffic counters — deliberately unconditional (no debug
/// flag gates this), same "can't be turned off" basic status every other real system
/// exposes. Counts ciphertext bytes actually pumped over the network transport, at the
/// one point every channel session (QUIC direct, QUIC relay, `:443` front door, and the
/// relay-gate/circuit-relay DCUtR paths) converges: [`run_channel_session_on_stream`]'s
/// `send`/`recv` halves, wrapped in [`CountingWriter`]/[`CountingReader`] before the pump.
/// Process-wide, not per-session, since a long-lived `--serve` process handles many
/// sessions over its life and "how much traffic has this identity carried" is the more
/// useful cumulative number — a per-session breakdown is what the round-level dashboard
/// events are for.
static TOTAL_BYTES_SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TOTAL_BYTES_RECV: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Call once, as early as possible (`main`) — safe to call more than once (only the first
/// call's instant sticks), but a session that starts before this call would under-report
/// its own uptime, so this belongs at actual process start, not lazily on first use.
pub fn mark_process_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
}

/// Seconds since [`mark_process_start`] (or, if that was never called, since the
/// first call here); also `/status`'s `uptime_secs` (ct-agent#178).
pub fn process_uptime_secs() -> u64 {
    PROCESS_START.get_or_init(std::time::Instant::now).elapsed().as_secs()
}

/// The always-on status line itself — callers decide *when* (periodic tick, session end),
/// this just formats the current unconditional counters.
fn traffic_status_line() -> String {
    format!(
        "ct-agent channel: status uptime={}s sent={}B recv={}B",
        process_uptime_secs(),
        TOTAL_BYTES_SENT.load(std::sync::atomic::Ordering::Relaxed),
        TOTAL_BYTES_RECV.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// How often a live session's background ticker prints [`traffic_status_line`] — frequent
/// enough to be genuinely live on a monitor channel, not so frequent it floods one.
const TRAFFIC_STATUS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// #248: extends the *existing* `CT_DEBUG_A2A_TIMING` debug mode (already real —
/// `ct_common::a2a` uses it for per-message Noise handshake wait timing, the
/// `ct-a2a-timing: ...` lines already visible in bob-1's logs) with coarser,
/// crate-level timing this repo is in a better position to measure: total handshake
/// duration, and direct dial/accept-to-connected duration. Same env var, same
/// presence-based activation (`is_some()`, matching `ct_common::a2a::debug_a2a_timing_enabled`
/// exactly rather than introducing a second, differently-triggered flag) — one switch
/// turns on both layers of detail. Checked once and cached since it's now read per
/// handshake/dial, not just at startup.
pub(crate) fn debug_timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CT_DEBUG_A2A_TIMING").is_some())
}

struct CountingWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let n = std::task::ready!(AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf))?;
        TOTAL_BYTES_SENT.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

struct CountingReader<R> {
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        std::task::ready!(AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf))?;
        let n = buf.filled().len() - before;
        TOTAL_BYTES_RECV.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

/// ct-agent#314: the session's `local` side, reporting its first READ error through a oneshot.
/// `noise_pump` hands a local read error back from its outbound direction without closing the
/// cipher side, and its `join!` then waits for the inbound direction -- which ends only when the
/// PEER sends a byte or closes. A peer that completed the Noise handshake and then stays silent
/// therefore held a session whose own side had already failed (the field case: the peer-grant
/// gate giving up after `PEER_GRANT_TIMEOUT`) for ever, and with it a forward initiator's
/// reconnect loop or a serve slot. [`run_channel_session_on_stream`] watches this signal and stops
/// waiting for such a peer after [`LOCAL_FAILURE_GRACE`].
///
/// Only the read side reports. A gate that refuses the peer on the write side (a grant that does
/// not verify) fails both directions, so its next read reports it. A plain local write error --
/// a stream handler that closed its stdin, a closed stdout -- ends only the inbound direction,
/// while the outbound one may still be delivering what the local side produces; cutting that after
/// the grace would truncate a response the peer is still receiving.
struct LocalFailSignal<P> {
    inner: P,
    /// Taken on the first read error; the session runner holds the receiver.
    failed: Option<tokio::sync::oneshot::Sender<io::Error>>,
}

impl<P: AsyncRead + Unpin> AsyncRead for LocalFailSignal<P> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Err(e)) = &polled {
            if let Some(tx) = this.failed.take() {
                let _ = tx.send(io::Error::new(e.kind(), e.to_string()));
            }
        }
        polled
    }
}

// Writes pass through unreported (see the type's doc).
impl<P: AsyncWrite + Unpin> AsyncWrite for LocalFailSignal<P> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Open (Initiate) or accept (Accept) the channel bi-stream on `conn`, **bounded** by `setup_timeout`
/// (#139) so a stalled direct link fails fast (`io::ErrorKind::TimedOut`) instead of hanging — the
/// exact `open_bi`/`accept_bi` gap central traced. The timeout is a parameter so tests can drive it
/// deterministically without waiting the production bound.
///
/// Phase-2 PR5: the body (and [`DIRECT_STREAM_SETUP_TIMEOUT`]'s #139 rationale) moved VERBATIM to
/// ct_common's `channel_quic::open_channel_streams`, which takes `initiator: bool` because
/// [`ChannelRole`] is this crate's session-level notion; this is the one-line adapter, signature
/// unchanged for every caller.
pub(crate) async fn open_channel_streams(
    conn: &Connection,
    role: ChannelRole,
    setup_timeout: std::time::Duration,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    ct_common::channel_quic::open_channel_streams(conn, matches!(role, ChannelRole::Initiate), setup_timeout).await
}

/// The relay-leg twin of [`open_channel_streams`]: after `Admitted` the partner is paired, so the
/// stream opens at once, and a live-but-silent relay would otherwise hold the session (and a serve
/// slot) forever. Bounded by the same #139 limit; a timeout is reported as a *relay* stall, since
/// ct_common's message names the direct leg.
pub(crate) async fn open_relay_channel_streams(
    relay_conn: &Connection,
    role: ChannelRole,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    open_channel_streams(relay_conn, role, DIRECT_STREAM_SETUP_TIMEOUT).await.map_err(|e| {
        if e.kind() == io::ErrorKind::TimedOut {
            io::Error::new(io::ErrorKind::TimedOut, "relay channel stream setup stalled after admission (#139)")
        } else {
            e
        }
    })
}

/// Run one side of an A2A channel session over the established `conn`, then pump
/// `local` (the CLI's stdio, or any duplex) over the encrypted tunnel until either
/// end closes (#72 AF4-session-wire). `role` selects initiator/responder;
/// `own_noise_private` is this agent's member Noise key; `peer_noise_public` is the
/// peer's, pinned by the initiator. Returns when the session ends (EOF either way).
pub async fn run_channel_session<P>(
    conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // #139: bound the channel stream setup. `dial_peer_direct` bounds only the QUIC *connect*; once
    // it returns Ok(conn), `open_bi`/`accept_bi` here were unbounded — a conn that handshaked at the
    // transport level then went dead hangs forever (the Noise handshake past this is already bounded,
    // #126; this was the remaining gap). The dialer's idle-timeout (#139) is the transport-level
    // backstop; this is the direct, tight bound on the exact call central traced.
    let (mut send, mut recv) = open_channel_streams(conn, role, DIRECT_STREAM_SETUP_TIMEOUT).await?;
    // Pass the streams by `&mut` so `send` survives the pump (it moves the halves into a
    // `BiStream`), letting us drain it afterwards. #134: the pump FINs on plaintext EOF via
    // `shutdown()` = quinn `SendStream::finish()`, which only QUEUES the FIN — it does NOT wait
    // for the peer to acknowledge the buffered data. QUIC is userspace, so if the connection is
    // then dropped (the agent process exits right after the session returns) quinn discards the
    // unacknowledged tail and the peer receives a silently-truncated prefix of a large transfer.
    // (The `:443`/TLS-TCP relay path — `run_channel_session_on_stream` called directly — has its own
    // bounded `graceful_stream_drain` at the end of that fn: #150 found the "OS keeps draining a FIN'd
    // socket after close" assumption FALSE when `ct-agent` is a container's PID 1, since the netns is
    // torn down on exit with no stack left to flush the tail.)
    run_channel_session_on_stream(&mut send, &mut recv, role, own_noise_private, peer_noise_public, local).await?;
    // Graceful send-drain: wait until the peer has acknowledged receipt of all our stream data
    // (`stopped()` resolves after our `finish()` once the peer acks) BEFORE returning — so the
    // caller can drop the connection / exit without truncating the tail. Bounded so a vanished
    // peer can never hang teardown; on timeout or a lost connection we've done our best.
    const SEND_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    // The SIGTERM drain must not exit under this wait either: the session stopped counting as
    // established when the pump returned, so the tail counts on its own until the peer acked it
    // (health.rs). No await lies between the two, so a drain look can catch at most a passing
    // zero, never the two zero looks in a row it needs to end.
    let _tail = super::health::health().quic_tail();
    let _ = send.finish(); // idempotent — the pump already FIN'd on EOF; ignore "already closed"
    let _ = tokio::time::timeout(SEND_DRAIN_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// #150: how long [`graceful_stream_drain`] waits for the peer to close before giving up — matches
/// the QUIC send-drain bound (#134) so a vanished peer can never hang teardown.
const RELAY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// ct-agent#314: once this member's own side of a session failed (see [`LocalFailSignal`]), how
/// long the peer still gets to end the session the normal way before the runner stops waiting.
/// A live peer answers within one round trip; nothing it sends after this side failed could be
/// delivered anyway.
pub(crate) const LOCAL_FAILURE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// ct-agent#314: the drain bound after the runner gave up on such a peer. It stayed silent for the
/// whole grace, so the 30 s of [`RELAY_DRAIN_TIMEOUT`] would only delay the caller's reconnect.
pub(crate) const LOCAL_FAILURE_DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// #150: graceful teardown of a stream session before the process may exit. FIN our write half, then
/// read the peer to EOF (bounded by `timeout`) — keeping the process, and in a container its network
/// namespace, alive until the peer has closed, by which point the OS has transmitted + had acknowledged
/// our send buffer. The `:443`/TLS-TCP relay path needs this: unlike a bare host (whose OS TCP stack
/// keeps draining a FIN'd socket after the process closes it), a container tied to `ct-agent`'s PID 1
/// tears down the network namespace on exit, so there's no persisting stack left to flush an unsent
/// tail — the last bytes of a large single-shot transfer would be truncated. Best-effort + bounded: a
/// vanished peer can't hang teardown, and I/O errors are ignored (we've done our best to drain).
pub(crate) async fn graceful_stream_drain<W, R>(send: &mut W, recv: &mut R, timeout: std::time::Duration)
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let _ = send.shutdown().await;
    let _ = tokio::time::timeout(timeout, tokio::io::copy(recv, &mut tokio::io::sink())).await;
}

/// The transport-agnostic core of [`run_channel_session`] (#106 relay-leg-443): run one
/// side of the A2A Noise_IK handshake over already-split write/read halves, then pump
/// `local` over the encrypted tunnel until either end closes. The QUIC path reaches this
/// via [`run_channel_session`] (`open_bi`/`accept_bi`), but a `:443`/TLS-TCP relay stream
/// — whose data path IS the single stream it joined on — runs the identical session by
/// `tokio::io::split`ting the stream and passing the halves here. So a member whose relay
/// port is also blocked (a truly `:443`-only network) relays over `:443` unchanged; the
/// Noise_IK session stays end-to-end and the edge only forwards ciphertext.
///
/// When reading `local` fails (e.g. the peer-grant gate refusing the peer), the session ends with
/// that error within [`LOCAL_FAILURE_GRACE`] plus [`LOCAL_FAILURE_DRAIN`], whether or not the peer
/// ever sends another byte (ct-agent#314). The same bound holds once the session's grant ended,
/// for a session run inside a grant-end record (ct-agent#308).
pub async fn run_channel_session_on_stream<W, R, P>(
    send: W,
    recv: R,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    // #248: count every wire byte this session moves, handshake included — real traffic
    // either way, and simpler than carving the handshake out. Shadows send/recv with
    // counting wrappers for the rest of this function; noise_pump and a2a_initiate/
    // a2a_respond see the identical AsyncRead/AsyncWrite behavior, just counted.
    let mut send = CountingWriter { inner: send };
    let mut recv = CountingReader { inner: recv };
    // #126: bound the post-pairing Noise_IK handshake. Every dial/accept step around this
    // is already timed (DIRECT_DIAL_TIMEOUT / accept_timeout), but the handshake exchange
    // itself was unbounded — a paired peer that never sends its message (crash, partition,
    // a peer that admits then stalls) would block `read_frame` forever, hanging the session.
    const A2A_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let handshake_started = std::time::Instant::now();
    let handshake = async {
        match role {
            ChannelRole::Initiate => {
                a2a_initiate(&mut send, &mut recv, own_noise_private, peer_noise_public).await
            }
            // ct-agent#35: was the plain, unverified `a2a_respond` -- the caller had already
            // attestation-verified `peer_noise_public` (run_channel_join_with_admission,
            // #101 SEC101c-ii) and simply never used it here, so the responder authenticated
            // nothing about who it was talking to at the Noise layer. `a2a_respond_verified`
            // refuses the session if the live peer's static key doesn't match.
            ChannelRole::Accept => {
                a2a_respond_verified(&mut send, &mut recv, own_noise_private, peer_noise_public).await
            }
        }
    };
    let session = tokio::time::timeout(A2A_HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "a2a Noise_IK handshake timed out (#126)"))?
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if debug_timing_enabled() {
        eprintln!(
            "ct-agent channel: debug handshake completed in {}ms (role={role:?})",
            handshake_started.elapsed().as_millis()
        );
    }

    eprintln!("{}", traffic_status_line());
    // ct-agent#178: one structured open/close pair per session, keyed by the peer's
    // (attestation-verified) Noise static key.
    let peer_hex = super::cli_config::hex_encode(peer_noise_public);
    crate::events::emit(
        crate::events::CHANNEL_SESSION,
        serde_json::json!({ "state": "open", "peer": peer_hex }),
    );
    // #248: unconditional (no debug flag) periodic status while this session's pump runs —
    // aborted the moment the pump finishes, one way or another, via the handle drop below.
    // Guarded (ct-agent#180): when this future is dropped mid-pump -- a caller's select!
    // taking another branch -- a bare spawn kept printing every interval, forever.
    let ticker = crate::task_guard::TaskGuard::spawn(async {
        loop {
            tokio::time::sleep(TRAFFIC_STATUS_INTERVAL).await;
            eprintln!("{}", traffic_status_line());
        }
    });
    // Readiness (`/readyz`) and the shutdown drain count this session as established until the
    // function returns, the #150 drain below included (health.rs).
    let _established = super::health::health().session_established();

    // Reborrow the halves so they survive the pump: after the session ends we must drain before
    // returning (#150), because a caller may exit immediately (a single-shot `ct-agent channel` as a
    // container's PID 1) and a container tears down its netns on exit — so the OS won't flush a FIN'd
    // `:443`/TLS-TCP relay socket's tail the way a bare host would. `graceful_stream_drain` FINs and
    // waits (bounded) for the peer to close, keeping the process + netns alive until our tail is
    // delivered. (The QUIC path keeps its stronger `stopped()` ack-wait in `run_channel_session`.)
    //
    // ct-agent#314: the pump alone never ends while a silent peer holds the transport open, even
    // after this side failed (see `LocalFailSignal`). So it races that failure: the peer gets
    // LOCAL_FAILURE_GRACE to end the session the normal way, then the pump is dropped (releasing
    // the reborrowed halves) and the session ends with the local error.
    //
    // ct-agent#308: the same bound once the session's grant ended. The gate hands the pump an EOF
    // then -- a clean end, not an error -- and the pump FINs the peer and waits for its close, so
    // a peer that never closes (a wedged process, a half-open path) held the session: a forward
    // initiator's reconnect after the PEER's grant end, or a serve slot. The signal exists for a
    // session that runs inside a grant-end record (forward, one-shot and serve sessions).
    let (failed_tx, mut failed_rx) = tokio::sync::oneshot::channel();
    let local = LocalFailSignal { inner: local, failed: Some(failed_tx) };
    let grant_end = super::peer_grant::current_grant_end_record();
    let grant_end_signal = async {
        match &grant_end {
            Some(record) => record.wait().await,
            None => std::future::pending().await,
        }
    };
    let (pumped, gave_up) = {
        let pump = noise_pump(session, BiStream { send: &mut send, recv: &mut recv }, local);
        tokio::pin!(pump);
        tokio::pin!(grant_end_signal);
        tokio::select! {
            biased;
            pumped = &mut pump => (pumped, false),
            Ok(failure) = &mut failed_rx => match tokio::time::timeout(LOCAL_FAILURE_GRACE, &mut pump).await {
                Ok(pumped) => (pumped, false),
                Err(_) => {
                    eprintln!(
                        "ct-agent channel: this side of the session failed ({failure}) and the peer \
                         did not end it within {LOCAL_FAILURE_GRACE:?} -- ending the session (#314)"
                    );
                    (Err(failure), true)
                }
            },
            () = &mut grant_end_signal => match tokio::time::timeout(LOCAL_FAILURE_GRACE, &mut pump).await {
                Ok(pumped) => (pumped, false),
                Err(_) => {
                    eprintln!(
                        "ct-agent channel: the session's channel grant ended and the peer did not \
                         close the session within {LOCAL_FAILURE_GRACE:?} -- ending it (#308)"
                    );
                    let why = "the channel grant ended and the peer did not close the session";
                    (Err(io::Error::new(io::ErrorKind::PermissionDenied, why)), true)
                }
            },
        }
    };
    drop(ticker);
    let drain = if gave_up { LOCAL_FAILURE_DRAIN } else { RELAY_DRAIN_TIMEOUT };
    graceful_stream_drain(&mut send, &mut recv, drain).await;
    eprintln!("{}", traffic_status_line());
    // ct-agent#308: a session the grant ended was cut short, even when its pump saw only clean
    // EOFs -- not `ok`.
    let grant_ended = grant_end.as_ref().and_then(super::peer_grant::GrantEndRecord::ended);
    crate::events::emit(
        crate::events::CHANNEL_SESSION,
        serde_json::json!({ "state": "close", "peer": peer_hex, "ok": pumped.is_ok() && grant_ended.is_none() }),
    );
    pumped
}
