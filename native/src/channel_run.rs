//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::channel::{
    present_channel_join, present_channel_join_on_stream, present_channel_relay_join_on_stream,
    ChannelJoinOutcome, ADMISSION_EXCHANGE_TIMEOUT,
};
use ct_common::a2a::{a2a_initiate, a2a_respond};
use ct_common::noise::noise_pump;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

fn process_uptime_secs() -> u64 {
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

/// #139: how long a channel's QUIC stream setup (`open_bi`/`accept_bi`) may take past a successful
/// `dial_peer_direct` connect before the direct path is treated as dead. A healthy connection sets
/// the stream up sub-second; a conn that handshaked then went silent would otherwise hang here
/// forever (the Noise handshake beyond this is already bounded, #126). Sits below the dialer's 20s
/// idle-timeout (#139) so this tight bound fires first on the direct path.
const DIRECT_STREAM_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Open (Initiate) or accept (Accept) the channel bi-stream on `conn`, **bounded** by `setup_timeout`
/// (#139) so a stalled direct link fails fast (`io::ErrorKind::TimedOut`) instead of hanging — the
/// exact `open_bi`/`accept_bi` gap central traced. The timeout is a parameter so tests can drive it
/// deterministically without waiting the production bound.
async fn open_channel_streams(
    conn: &Connection,
    role: ChannelRole,
    setup_timeout: std::time::Duration,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let open = async {
        match role {
            ChannelRole::Initiate => conn.open_bi().await.map_err(|e| map_err(Box::new(e))),
            ChannelRole::Accept => conn.accept_bi().await.map_err(|e| map_err(Box::new(e))),
        }
    };
    tokio::time::timeout(setup_timeout, open)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct channel stream setup stalled after connect (#139)"))?
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
    let _ = send.finish(); // idempotent — the pump already FIN'd on EOF; ignore "already closed"
    let _ = tokio::time::timeout(SEND_DRAIN_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// #150: how long [`graceful_stream_drain`] waits for the peer to close before giving up — matches
/// the QUIC send-drain bound (#134) so a vanished peer can never hang teardown.
const RELAY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// #150: graceful teardown of a stream session before the process may exit. FIN our write half, then
/// read the peer to EOF (bounded by `timeout`) — keeping the process, and in a container its network
/// namespace, alive until the peer has closed, by which point the OS has transmitted + had acknowledged
/// our send buffer. The `:443`/TLS-TCP relay path needs this: unlike a bare host (whose OS TCP stack
/// keeps draining a FIN'd socket after the process closes it), a container tied to `ct-agent`'s PID 1
/// tears down the network namespace on exit, so there's no persisting stack left to flush an unsent
/// tail — the last bytes of a large single-shot transfer would be truncated. Best-effort + bounded: a
/// vanished peer can't hang teardown, and I/O errors are ignored (we've done our best to drain).
async fn graceful_stream_drain<W, R>(send: &mut W, recv: &mut R, timeout: std::time::Duration)
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
            ChannelRole::Accept => a2a_respond(&mut send, &mut recv, own_noise_private).await,
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
    // #248: unconditional (no debug flag) periodic status while this session's pump runs —
    // aborted the moment the pump finishes, one way or another, via the handle drop below.
    let ticker = tokio::spawn(async {
        loop {
            tokio::time::sleep(TRAFFIC_STATUS_INTERVAL).await;
            eprintln!("{}", traffic_status_line());
        }
    });

    // Reborrow the halves so they survive the pump: after the session ends we must drain before
    // returning (#150), because a caller may exit immediately (a single-shot `ct-agent channel` as a
    // container's PID 1) and a container tears down its netns on exit — so the OS won't flush a FIN'd
    // `:443`/TLS-TCP relay socket's tail the way a bare host would. `graceful_stream_drain` FINs and
    // waits (bounded) for the peer to close, keeping the process + netns alive until our tail is
    // delivered. (The QUIC path keeps its stronger `stopped()` ack-wait in `run_channel_session`.)
    let pumped = noise_pump(session, BiStream { send: &mut send, recv: &mut recv }, local).await;
    ticker.abort();
    graceful_stream_drain(&mut send, &mut recv, RELAY_DRAIN_TIMEOUT).await;
    eprintln!("{}", traffic_status_line());
    pumped
}

/// Hands-off A2A join with automatic **direct-then-relay** recovery (#72 AF4 /
/// AF4-session-resilience): present `request` to the edge broker over `broker_conn`,
/// learn the peer endpoint + Noise key the rendezvous relays, then try the **direct**
/// path and, if it can't connect, transparently fall back to the edge **relay**
/// (`relay_conn`) — so a blocked direct path (NAT/firewall) recovers with no caller
/// intervention. `role` (from the grant `Direction`) selects the side: an `Initiate`
/// peer dials `peer_endpoint` (bounded by `dial_timeout`; `Unreachable` → relay); an
/// `Accept` peer waits on its `listener` (bounded by `accept_timeout`; timeout →
/// relay, since the initiator that can't reach it directly went to the relay too). The
/// relay carries ciphertext only — the Noise_IK session stays end-to-end either way.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join<P>(
    broker_conn: &Connection,
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // Admit over the single pre-dialed QUIC broker connection, then run the
    // outcome-driven data path. The plane CLI instead admits over the broker *ladder*
    // (direct QUIC → the `:443` front door) and calls [`run_channel_join_with_admission`]
    // directly — same data path, but the broker leg reachable when the ports are blocked.
    let admission = present_channel_join(broker_conn, request, holder).await?;
    run_channel_join_with_admission(
        admission,
        RelayFallback::Quic(relay_conn),
        request,
        holder,
        role,
        own_noise_private,
        listener,
        dial_timeout,
        accept_timeout,
        local,
        false, // #104: this entry point predates the option and stays opt-out by default
    )
    .await
}

/// The **outcome-driven** core of [`run_channel_join`] (#106 client-dial-wire): given the
/// broker's already-computed `admission` — obtained over a direct QUIC broker connection
/// *or* the broker fallback ladder (direct QUIC → the `:443` TLS-TCP front door) — verify
/// the peer's attested Noise key (#101) and run the same **direct-then-relay** data path.
/// Decoupling admission (how we *reach* the broker) from the data path (how the two
/// members *connect*) is what lets a restrictive network admit over `:443` while the
/// direct/relay data legs stay unchanged. `role`, `listener`, and the timeouts behave
/// exactly as in [`run_channel_join`]. `relay` selects the relay-leg transport used on
/// direct-dial failure: [`RelayFallback::Quic`] (a pre-dialed QUIC relay connection) or —
/// for a member whose relay port is also blocked — [`RelayFallback::Ladder`], which walks
/// the relay ladder (direct QUIC → the `:443` front door) via [`join_via_relay_ladder`].
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join_with_admission<P>(
    admission: ChannelJoinOutcome,
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
    // #104, opt-in via CT_CHANNEL_DIRECT_UPGRADE (default false -> unchanged behavior):
    // whether to attempt the in-band relay->direct upgrade if/when this session ends up
    // on the relay leg.
    direct_upgrade: bool,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (peer_endpoint, peer_noise, observed_reflexive) = match admission {
        ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
            let noise = peer_noise_pubkey
                .ok_or("broker admitted the join but relayed no peer Noise key (registry has none)")?;
            // #101 SEC101c-ii: verify the peer's Noise key is attested by its
            // grant-authenticated holder before pinning it — so even a tampered DB
            // can't make us pin a substituted key (the attestation wouldn't verify).
            let peer_holder = peer_holder
                .ok_or("broker relayed a Noise key without the peer holder — cannot verify (#101)")?;
            let attestation = peer_attestation
                .ok_or("broker relayed a Noise key without an attestation (#101)")?;
            if !ct_common::channel::verify_member_noise_attestation(
                &request.grant.grant.channel,
                &peer_holder,
                &noise,
                &attestation,
            ) {
                return Err("peer Noise-key attestation failed — refusing to pin a possibly-substituted key (#101)".into());
            }
            (peer_endpoint, noise, observed_reflexive)
        }
        ChannelJoinOutcome::Refused => return Err(AdmissionRefused::boxed("edge broker refused the channel join")),
        // #21: unreachable in practice (admit_one_peer converts a ParkExpired before spawning a
        // session), kept as the typed error so a future caller can never misread it as refused.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("channel park expired with no partner within the edge park window (#21) -- re-parking"))
        }
    };
    // #104: built once, moved into whichever single relay-fallback call site below
    // actually fires (they're mutually exclusive). `None` whenever direct_upgrade is off
    // (the default) or the edge reported no reflexive address for this admission.
    let upgrade = if direct_upgrade { build_upgrade_candidate(observed_reflexive).await } else { None };
    match role {
        // #121: the paired peer advertised the relay-only sentinel — it has no dialable
        // address, so skip the wasted direct dial + timeout and go straight to the relay.
        ChannelRole::Initiate if peer_endpoint == ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY => {
            eprintln!("ct-agent channel: peer is relay-only (no dialable address) — using the edge relay (#121)");
            join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local, upgrade).await?;
        }
        ChannelRole::Initiate => {
            let addr = peer_endpoint
                .parse()
                .map_err(|_| format!("broker returned an unparseable peer endpoint: {peer_endpoint:?}"))?;
            let dial_started = std::time::Instant::now();
            match dial_peer_direct(addr, dial_timeout).await {
                Ok(conn) => {
                    if debug_timing_enabled() {
                        eprintln!("ct-agent channel: debug direct dial to {addr} connected in {}ms", dial_started.elapsed().as_millis());
                    }
                    run_channel_session(&conn, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
                }
                Err(ChannelDialError::Unreachable) => {
                    eprintln!(
                        "ct-agent channel: direct dial to {addr} unreachable after {}ms — falling back to the edge relay (#72)",
                        dial_started.elapsed().as_millis()
                    );
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local, upgrade).await?;
                }
                Err(ChannelDialError::Failed(e)) => return Err(e),
            }
        }
        ChannelRole::Accept => match listener {
            // #121: a relay-only acceptor has no bound listener — it can't be dialed, so it
            // relays directly instead of waiting for a direct connection that can never come.
            None => {
                eprintln!("ct-agent channel: relay-only acceptor (no listener) — using the edge relay (#121)");
                join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
            }
            Some(ep) => {
                let accept_started = std::time::Instant::now();
                match tokio::time::timeout(accept_timeout, ep.accept()).await {
                    Ok(Some(incoming)) => {
                        let conn = incoming.await?;
                        if debug_timing_enabled() {
                            eprintln!("ct-agent channel: debug direct accept connected in {}ms", accept_started.elapsed().as_millis());
                        }
                        run_channel_session(&conn, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
                    }
                    Ok(None) => return Err("channel listener closed with no incoming".into()),
                    Err(_timeout) => {
                        eprintln!("ct-agent channel: no direct connection within {accept_timeout:?} — falling back to the edge relay (#72)");
                        join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
                    }
                }
            }
        },
    }
    Ok(())
}

/// Agent-side relay fallback (#72 AF4-session-resilience): when the direct dial to a
/// paired peer is [`ChannelDialError::Unreachable`], the agent reconnects to the edge
/// **relay** endpoint (`ct_edge::channel_broker::broker_channel_relay`), presents its
/// grant (proving possession), and runs the Noise_IK session over the stream the edge
/// splices to the peer. Both members call this; the edge pairs + splices them while
/// preserving the direct-path stream roles, so this simply presents the join and then
/// reuses [`run_channel_session`] over the edge connection. Noise stays end-to-end —
/// the edge only forwards ciphertext.
///
/// `upgrade`, when `Some((listener, own_direct_endpoint))` (#104, opt-in via
/// `CT_CHANNEL_DIRECT_UPGRADE`), runs [`run_channel_session_upgradable`] instead of the
/// plain session: the two peers negotiate a direct-dial candidate **in-band, over this
/// same already-admitted, already-Noise-authenticated relay stream** and opportunistically
/// upgrade to it, falling back to the relay transparently on failure. `None` (the default)
/// is byte-for-byte the pre-existing behavior.
pub async fn join_via_relay<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    upgrade: Option<(Endpoint, String)>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    match present_channel_join(relay_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { .. } => {}
        ChannelJoinOutcome::Refused => return Err(AdmissionRefused::boxed("edge relay refused the channel join")),
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    }
    match upgrade {
        Some((listener, own_direct_endpoint)) => run_channel_session_upgradable(
            relay_conn,
            role,
            own_noise_private,
            peer_noise_public,
            local,
            Some(listener),
            Some(own_direct_endpoint),
            DIRECT_DIAL_TIMEOUT,
        )
        .await,
        None => run_channel_session(relay_conn, role, own_noise_private, peer_noise_public, local)
            .await
            .map_err(Into::into),
    }
}

/// **#136 N-wire — DCUtR-upgradable relay join for a NAT-to-NAT (relay-only) member.** Like
/// [`join_via_relay`], but instead of running a plain edge-relay session it runs the
/// **upgradable DCUtR** session ([`crate::p2p::run_channel_session_upgradable_dcutr`]): the byte
/// stream starts on the edge relay (both members are NAT'd, so neither can be dialed directly),
/// and in the background the pair opportunistically hole-punches to a **direct** link via the
/// configured libp2p Circuit-Relay v2 `circuit_relay` and cuts the stream over — offloading the
/// edge. Hole-punch failure stays on the relay; the relay leg is end-to-end throughout. The
/// peer's Noise key is learned from the relayed admission (no out-of-band exchange). The actual
/// cross-NAT punch is proven in the Docker 2-NAT lab (N-rig-2) / the live plane (N-rig-3); on
/// loopback it degrades to the relay.
pub async fn join_via_relay_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
    circuit_relay: libp2p::Multiaddr,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let peer_noise = match present_channel_join(relay_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(k), .. } => k,
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused => return Err(AdmissionRefused::boxed("edge relay refused the channel join")),
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    };
    // The DCUtR session runs the Noise_IK over the relay bi-stream as its base leg, punching to
    // direct in the background. Initiator opens the bi-stream; acceptor accepts the edge-opened one.
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    let client = crate::p2p::build_dcutr_relay_client_swarm()?;
    crate::p2p::run_channel_session_upgradable_dcutr(
        relay_send,
        relay_recv,
        local,
        role,
        own_noise_private,
        &peer_noise,
        client,
        circuit_relay,
    )
    .await
}

/// Dial the edge's `:443` **relay-gate** leg (`CT_EDGE_RELAY_GATE`) for a real NAT-to-NAT
/// hole-punch, multiplexed onto the same front door every other `:443` leg uses — no new
/// public port. TLS-connects with ALPN `ct-edge-relay`
/// ([`crate::transport::tcp_tls_connect_with_alpn`]), then runs the pre-auth wire protocol
/// `crates/edge/src/relay_gate.rs` on the edge side implements: present `grant` (the fixed-size
/// [`ct_common::channel::SignedChannelGrant`] wire form, no framing needed), sign the edge's
/// fresh 32-byte challenge with `holder`, and on `OK` read the trailing `u16-BE len + utf8`
/// relay-node `PeerId` the edge's ack carries (needed because this connection never reaches the
/// relay-node directly — see `relay_gate.rs`'s own doc comment for why). Returns the
/// still-open, now-pre-authed TLS stream plus that `PeerId`, ready for
/// [`crate::p2p::build_relay_gate_client`].
pub async fn dial_relay_gate_over_443(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    grant: &ct_common::channel::SignedChannelGrant,
    holder: &SigningKey,
) -> Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, libp2p::PeerId), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // #248: per-step timing under CT_DEBUG_A2A_TIMING -- this function's own errors (from
    // run_channel_join_command's retry wrapper) were all indistinguishable generic messages
    // ("Connection refused", "early eof") with no way to tell which of these six sequential
    // steps actually failed. Live-reproduced needing exactly this while debugging bob1/bob2's
    // real hole-punch failures.
    let dbg = debug_timing_enabled();
    let t0 = std::time::Instant::now();
    let mut stream = crate::transport::tcp_tls_connect_with_alpn(addr, edge_cert, b"ct-edge-relay").await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate tcp+tls connect to {addr} failed after {:?}: {e}", t0.elapsed()); } e })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate tcp+tls connect to {addr} ok in {:?}", t0.elapsed()); }
    let t1 = std::time::Instant::now();
    stream.write_all(&grant.encode()).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate write grant failed after {:?}: {e}", t1.elapsed()); } e })?;
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read challenge failed after {:?}: {e}", t1.elapsed()); } e })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate grant+challenge round-trip ok in {:?}", t1.elapsed()); }
    let sig = holder.sign(&challenge).to_bytes();
    stream.write_all(&sig).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate write possession sig failed: {e}"); } e })?;
    let mut ack = [0u8; 2];
    let t2 = std::time::Instant::now();
    stream.read_exact(&mut ack).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read ack failed after {:?}: {e}", t2.elapsed()); } e })?;
    if &ack != b"OK" {
        if dbg { eprintln!("ct-agent channel: debug relay-gate pre-auth refused, ack={ack:?}"); }
        return Err("relay-gate: pre-auth refused (grant not authorized -- see the edge's own log)".into());
    }
    if dbg { eprintln!("ct-agent channel: debug relay-gate pre-auth ok (ack=OK) in {:?} total", t0.elapsed()); }
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read peer-id length failed: {e}"); } e })?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut peer_buf = vec![0u8; len];
    stream.read_exact(&mut peer_buf).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read peer-id bytes ({len}B) failed: {e}"); } e })?;
    let peer_str = String::from_utf8(peer_buf)
        .map_err(|e| -> BoxError { format!("relay-gate: relay-node peer id not utf8: {e}").into() })?;
    let relay_peer: libp2p::PeerId = peer_str
        .parse()
        .map_err(|e| -> BoxError { format!("relay-gate: malformed relay-node peer id {peer_str:?}: {e}").into() })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate handshake complete, relay-node peer={relay_peer} in {:?} total", t0.elapsed()); }
    Ok((stream, relay_peer))
}

/// #248/#238: the edge's QUIC "whoami" query address (its 'W' reflexive-address echo, on
/// the SAME QUIC listener Browser-Plane agents register on) -- same host as the `:443`
/// relay-gate, this deployment's stable QUIC port (4433) unless an operator overrides it
/// via `CT_CHANNEL_REFLEXIVE_EDGE` (host:port; e.g. if the edge's QUIC listener is
/// NAT/port-mapped differently from its `:443` front door).
pub fn reflexive_query_addr(relay_gate_addr: SocketAddr, override_raw: Option<&str>) -> Result<SocketAddr, String> {
    match override_raw {
        Some(s) if !s.trim().is_empty() => resolve_socket_addr(s.trim()),
        _ => Ok(SocketAddr::new(relay_gate_addr.ip(), 4433)),
    }
}

/// #248/#238: query the edge's 'W' reflexive-address echo to learn this member's GENUINE
/// UDP-observed reflexive address -- the piece missing from #248's original candidate-pool
/// fix, which only ever had a TCP-observed address (from the `:443` relay-gate's own
/// admission handshake) to seed. A NAT maps a TCP flow and a UDP flow from the same host to
/// DIFFERENT external ports, so DCUtR's QUIC direct-dial attempt (its preferred one) was
/// consistently seeded with the wrong transport's address and timed out even against
/// cone-type (punchable) NATs.
///
/// Best-effort by construction: any failure (edge unreachable on that port, timeout,
/// malformed reply) returns `None`, exactly like an edge that never observed a reflexive
/// address at all — this is a pure enhancement layered on top of the existing TCP-derived
/// candidate, never a hard requirement for the relay-gate join to proceed. Uses
/// [`crate::transport::build_channel_dialer`] (accepts any server cert): the reply isn't
/// sensitive and needs no authentication — a MITM lying about the observed address can only
/// make the punch fail, never weaken the channel's real security, which rests entirely on the
/// Noise_IK/grant/possession layers elsewhere.
///
/// Deliberately does NOT apply the `#137`/`is_global_unicast` safety filter itself — the
/// caller does, exactly like `own_observed_reflexive` above, so this function stays testable
/// against a real (loopback, in tests) server without the filter masking a wiring bug.
pub async fn discover_udp_reflexive(edge_quic_addr: SocketAddr, timeout: std::time::Duration) -> Option<SocketAddr> {
    let attempt = async {
        let endpoint = crate::transport::build_channel_dialer().ok()?;
        let conn = endpoint.connect(edge_quic_addr, "localhost").ok()?.await.ok()?;
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        send.write_all(b"W").await.ok()?;
        send.finish().ok()?;
        let mut len = [0u8; 1];
        recv.read_exact(&mut len).await.ok()?;
        let mut buf = vec![0u8; len[0] as usize];
        recv.read_exact(&mut buf).await.ok()?;
        std::str::from_utf8(&buf).ok()?.parse::<SocketAddr>().ok()
    };
    tokio::time::timeout(timeout, attempt).await.ok().flatten()
}

/// **#136 N-wire — DCUtR-upgradable relay join over the `:443` relay-gate.** Like
/// [`join_via_relay_dcutr`], but reaches the Circuit-Relay v2 relay through
/// [`dial_relay_gate_over_443`] instead of a directly-dialable `CT_CHANNEL_CIRCUIT_RELAY`
/// multiaddr — the deployment this session actually ships: no new public port, the relay-node
/// gated by grant + possession before a single byte reaches it. `own_grant` is this member's
/// own signed grant (presented to the relay-gate, distinct from the channel-join grant already
/// consumed by `present_channel_join`, though today they are the same value).
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay_gate_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
    relay_gate_addr: SocketAddr,
    relay_gate_cert: CertificateDer<'static>,
    own_grant: &ct_common::channel::SignedChannelGrant,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let (peer_noise, own_observed_reflexive) = match present_channel_join(relay_conn, request, holder).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(k), observed_reflexive, .. } => (k, observed_reflexive),
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay-gate join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused => return Err(AdmissionRefused::boxed("edge relay refused the channel join")),
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    };
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    let (gate_stream, relay_peer) =
        dial_relay_gate_over_443(relay_gate_addr, relay_gate_cert, own_grant, holder).await?;
    // #248: seed the DCUtR swarm with this member's OWN reflexive address, when the edge
    // observed one and it's actually safe to advertise (same #137 global-unicast filter
    // every other candidate-address path in this file already applies). Without this,
    // DCUtR has no real external address to offer the peer at all -- it can only ever
    // advertise the relay-node's own address (learned via identify over the circuit,
    // which is the EDGE's address, not this member's own, since the edge proxies every
    // relay-gate connection) or nothing, so the hole-punch had no real candidate to try.
    // Live-reproduced: dozens of real relay-gate sessions with admission + circuit
    // genuinely established, never once a completed hole-punch -- this is why.
    // #248/#238-follow, CORRECTING an earlier (wrong) belief about this value: `own_observed_reflexive`
    // is NOT observed over any TCP connection -- `relay_conn` (this fn's `present_channel_join` call
    // just above) is unconditionally a QUIC connection (`dial_relay_preferring_direct` ->
    // `build_channel_dialer` -> `quinn::Endpoint::connect`), to the relay/broker port, not the
    // `:443` relay-gate leg at all. It's a real, genuinely-observed external port -- just for an
    // unrelated ephemeral QUIC socket, not any TCP one and not the swarm's own QUIC punch listener
    // either. There is currently no TCP-reflexive-discovery mechanism anywhere in this codebase (that
    // would need the edge to report back the observed remote address for the actual `dial_relay_gate_over_443`
    // TCP+TLS connection specifically -- a new edge-side wire-protocol addition, mirroring the 'W'
    // echo op below, not yet built). So `own_observed_reflexive` is diagnostic-only now (logged
    // below), never used to seed a dial candidate -- see `p2p::build_relay_gate_client`'s doc
    // comment for why constructing one from it was actively wrong, not just suboptimal.
    //
    // Query the edge's 'W' echo (its normal QUIC :4433 listener) for a genuine UDP-observed
    // reflexive address, so DCUtR's preferred QUIC direct-dial attempt gets seeded with a real
    // address. Best-effort, bounded, never blocks the join on failure.
    let reflexive_edge_addr = reflexive_query_addr(
        relay_gate_addr,
        std::env::var("CT_CHANNEL_REFLEXIVE_EDGE").ok().as_deref(),
    )
    .ok();
    let own_reflexive_udp = match reflexive_edge_addr {
        Some(addr) => discover_udp_reflexive(addr, std::time::Duration::from_secs(5)).await,
        None => None,
    }
    .filter(|a| ct_common::channel::is_global_unicast(*a));
    if debug_timing_enabled() {
        eprintln!(
            "ct-agent channel: debug relay-gate DCUtR own reflexive: relay/broker-observed (QUIC, NOT a TCP candidate) {:?}; own reflexive (udp, queried at {:?}) = {:?}",
            own_observed_reflexive,
            reflexive_edge_addr,
            own_reflexive_udp
        );
    }
    let (client, circuit_relay) =
        crate::p2p::build_relay_gate_client(gate_stream.compat(), relay_peer, own_reflexive_udp)?;
    crate::p2p::run_channel_session_upgradable_dcutr(
        relay_send,
        relay_recv,
        local,
        role,
        own_noise_private,
        &peer_noise,
        client,
        circuit_relay,
    )
    .await
}

/// **#104 direct-P2P wire-in.** Run one side of an A2A channel session over `relay_conn` as an
/// **upgradable** session: it starts on the relay and, in the background, opportunistically dials a
/// direct link and cuts the byte stream over to it (offloading the edge) — transparently to the
/// app, no byte lost at the seam. Composes
/// [`ct_common::upgrade::run_upgradable_session_initiator`]/`_responder` with the real quinn
/// dial/accept: the channel **initiator** advertises `own_direct_endpoint` (its `direct_listener`'s
/// address) in-band and, on the peer's `Ready`, accepts the incoming direct dial; the channel
/// **responder**, on the `Offer`, dials that endpoint ([`dial_peer_direct`]) and handshakes the
/// direct Noise session. The direct-Noise role is tied to who-dials (the dialer is the Noise
/// initiator) so `a2a_initiate`/`a2a_respond` never block each other. If the hole-punch fails, the
/// session stays on the relay. An initiator with no listener to offer (a relay-only member) runs a
/// plain [`run_channel_session_on_stream`]. The relay leg stays end-to-end either way; the live
/// cross-NAT hole-punch is proven on the deploy (#104 H4), this over loopback.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_session_upgradable<P>(
    relay_conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    direct_listener: Option<Endpoint>,
    own_direct_endpoint: Option<String>,
    dial_timeout: std::time::Duration,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    use ct_common::a2a::establish_direct_session;
    use ct_common::upgrade::{
        run_upgradable_session_initiator, run_upgradable_session_responder, Role, UpgradeCoordinator,
    };

    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    // The relay handshake borrows these; the direct-establishment closures need owned copies.
    let (relay_priv, relay_peer) = (*own_noise_private, *peer_noise_public);
    let (direct_priv, direct_peer) = (*own_noise_private, *peer_noise_public);

    match role {
        ChannelRole::Initiate => {
            let (listener, endpoint) = match (direct_listener, own_direct_endpoint) {
                (Some(l), Some(e)) => (l, e),
                // Relay-only initiator (no dialable direct address): run the plain relay session.
                _ => {
                    return run_channel_session_on_stream(
                        relay_send, relay_recv, ChannelRole::Initiate, &relay_priv, &relay_peer, local,
                    )
                    .await
                    .map_err(Into::into)
                }
            };
            let coord = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
            eprintln!("ct-agent channel: #104 upgrade — offering direct candidate {endpoint} in-band");
            run_upgradable_session_initiator(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                &relay_peer,
                coord,
                1,
                || async move { Some(endpoint) },
                move || async move {
                    // Accept the incoming direct dial (the responder dials us), then handshake as the
                    // direct-Noise RESPONDER (the dialer is the Noise initiator).
                    let incoming = match tokio::time::timeout(dial_timeout, listener.accept()).await {
                        Ok(Some(i)) => i,
                        Ok(None) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct listener closed with no incoming — staying on relay");
                            return None;
                        }
                        Err(_) => {
                            eprintln!(
                                "ct-agent channel: #104 upgrade — no incoming direct dial within {dial_timeout:?} — staying on relay"
                            );
                            return None;
                        }
                    };
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — incoming direct connection failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    let (s, r) = match conn.accept_bi().await {
                        Ok(sr) => sr,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct bi-stream accept failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    match establish_direct_session(s, r, false, &direct_priv, &direct_peer).await {
                        Ok(session) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise session established, cutting over from relay");
                            Some(session)
                        }
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise handshake failed ({e}) — staying on relay");
                            None
                        }
                    }
                },
            )
            .await
            .map_err(Into::into)
        }
        ChannelRole::Accept => {
            let coord = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);
            run_upgradable_session_responder(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                coord,
                1,
                // #137 SSRF guard (reflexive candidate) / #276 same-subnet guard (local
                // candidate): the offered endpoint is peer-conveyed and never passed the edge
                // broker's `safe_endpoint` gate, so `select_upgrade_candidate` applies the
                // appropriate filter to whichever half it ends up choosing — refuse to even
                // signal Ready when neither candidate is dialable.
                |ep: String| async move {
                    let chosen = select_upgrade_candidate(&ep);
                    eprintln!(
                        "ct-agent channel: #104 upgrade — peer offered direct candidate {ep}{}",
                        match chosen {
                            Some(a) => format!(" -> selected {a}"),
                            None => " (rejected: no dialable candidate — neither a same-subnet local nor a global-unicast reflexive address, #137/#276)".to_string(),
                        }
                    );
                    chosen.is_some()
                },
                move |ep: String| async move {
                    // Dial the selected candidate (SSRF/same-subnet-guarded, #137/#276) and
                    // handshake as the direct-Noise INITIATOR. No dialable candidate → stay on relay.
                    let addr = match select_upgrade_candidate(&ep) {
                        Some(a) => a,
                        None => return None, // already logged as rejected above
                    };
                    let conn = match dial_peer_direct(addr, dial_timeout).await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct dial to {addr} failed ({e:?}) — staying on relay");
                            return None;
                        }
                    };
                    let (s, r) = match conn.open_bi().await {
                        Ok(sr) => sr,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct bi-stream open to {addr} failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    match establish_direct_session(s, r, true, &direct_priv, &direct_peer).await {
                        Ok(session) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise session established with {addr}, cutting over from relay");
                            Some(session)
                        }
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise handshake with {addr} failed ({e}) — staying on relay");
                            None
                        }
                    }
                },
            )
            .await
            .map_err(Into::into)
        }
    }
}

/// Which relay-leg transport [`run_channel_join_with_admission`] falls back to when the
/// direct dial fails (#106 relay-leg-443). The direct-QUIC relay works for a member that
/// can still reach the relay port; a member on a truly `:443`-only network (relay port
/// FILTERED too) needs the relay itself walked over the fallback ladder — direct QUIC,
/// then the unified `:443` TLS-TCP front door — so it can relay at all. Selecting on this
/// keeps every existing QUIC caller unchanged while adding the ladder-capable relay leg.
pub enum RelayFallback<'a> {
    /// A pre-dialed QUIC relay connection (the original relay leg): present the join over
    /// it and run the session over a fresh bi-stream ([`join_via_relay`]).
    Quic(&'a Connection),
    /// A relay endpoint to dial **lazily** — only if the direct path fails and the relay
    /// fallback actually fires (#103 fix). The eager variant held an idle QUIC connection
    /// open through admission + the whole direct-dial/accept wait; the edge's accept loop
    /// reaped that idle connection as a spurious `closed by peer: 0` (a `[quic-bistream]`
    /// drop) before any join, masking the real outcome. Dialing on demand removes it.
    QuicLazy(std::net::SocketAddr),
    /// Walk the relay ladder (direct QUIC → the `:443` front door) via
    /// [`join_via_relay_ladder`]. `rungs` is [`ChannelJoinCliConfig::relay_ladder`];
    /// `edge_cert` is the trust anchor the front-door TLS dial needs; `direct_timeout`
    /// bounds each direct QUIC relay dial before it falls through to `:443`.
    Ladder {
        rungs: &'a [ChannelDialRung],
        edge_cert: CertificateDer<'static>,
        direct_timeout: std::time::Duration,
    },
}

/// Dispatch the relay fallback to the selected transport (#106 relay-leg-443): a
/// [`RelayFallback::Quic`] connection reuses the original [`join_via_relay`]; a
/// [`RelayFallback::Ladder`] walks the relay ladder via [`join_via_relay_ladder`]. This
/// is the single seam both fallback arms of [`run_channel_join_with_admission`] call, so
/// the outcome-driven data path stays identical regardless of the relay transport.
#[allow(clippy::too_many_arguments)]
async fn join_via_relay_fallback<P>(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    upgrade: Option<(Endpoint, String)>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    match relay {
        RelayFallback::Quic(conn) => {
            join_via_relay(conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade).await
        }
        RelayFallback::QuicLazy(addr) => {
            // #103 fix: dial the relay only now, when the fallback has actually fired —
            // no idle connection is held during admission/direct-dial for the edge to reap.
            let conn = crate::transport::build_channel_dialer()?
                .connect(addr, "localhost")?
                .await?;
            join_via_relay(&conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade).await
        }
        RelayFallback::Ladder { rungs, edge_cert, direct_timeout } => {
            join_via_relay_ladder(
                rungs,
                edge_cert,
                direct_timeout,
                request,
                holder,
                role,
                own_noise_private,
                peer_noise_public,
                local,
                upgrade,
            )
            .await
        }
    }
}

/// The relay-leg analog of [`present_channel_join_via_ladder`] (#106 relay-leg-443): walk
/// the relay `rungs`, and on the first rung whose **transport connects**, present the join
/// and run the Noise session over that rung — committing `local` to it. A rung whose
/// transport can't connect (a blocked direct relay port → [`ChannelDialError::Unreachable`],
/// or a `Failed` TLS/connect) falls through to the next; once a rung connects, the session
/// is the terminal action, so we never retry after it starts (`local` is single-move). A
/// **direct** rung dials QUIC to the relay port and delegates to [`join_via_relay`] (join +
/// session on a fresh bi-stream of the same connection). A **front-door** rung opens the
/// `:443` TLS-TCP route ([`crate::transport::tcp_tls_connect_channel`], ALPN
/// `ct-edge-channel`), presents the join *without* consuming the stream
/// ([`present_channel_relay_join_on_stream`]), and — on `Admitted` — runs the session over
/// that **same** relay-spliced stream ([`run_channel_session_on_stream`]); a `Refused` is a
/// finished handshake, not a transport failure, so it errors rather than falling through.
/// This is what lets a fully `:443`-only member (relay port also blocked) relay at all —
/// closing the exact gap the #103 sink reported. Errors only when every rung is blocked.
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay_ladder<P>(
    rungs: &[ChannelDialRung],
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    // #104: only the direct-QUIC rung can carry the in-band upgrade (it hands off a real
    // `&Connection` to `join_via_relay`); the `:443` front-door rung is a plain TLS-TCP
    // byte stream with no independent QUIC connection to open a second stream on, so it
    // stays a plain relay session regardless of this option.
    upgrade: Option<(Endpoint, String)>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // `local` is single-move: hold it in an Option and commit it to the first rung whose
    // transport connects. Fall through ONLY on a transport error, tracked in `last`.
    let mut local = Some(local);
    let mut last: Option<BoxError> = None;
    for rung in rungs {
        if rung.kind.is_front_door() {
            // The `:443` front door over TLS-TCP. The SAME stream carries the join AND the
            // spliced session, so present without consuming it. The boring rung differs
            // only in its ClientHello (ALPN h2 / SNI edge-cdn.invalid); the edge
            // routes both to the same handler, so the leg below is identical.
            let connect = match rung.kind {
                ChannelDialKind::FrontDoorBoring => {
                    crate::transport::tcp_tls_connect_channel_boring(rung.endpoint, edge_cert.clone()).await
                }
                _ => crate::transport::tcp_tls_connect_channel(rung.endpoint, edge_cert.clone()).await,
            };
            match connect {
                Ok(stream) => {
                    eprintln!(
                        "ct-agent channel: relay leg via the {} rung ({}) (#106)",
                        rung.kind.label(),
                        rung.endpoint
                    );
                    let (mut recv, mut send) = tokio::io::split(stream);
                    let local = local.take().expect("local is committed to exactly one rung");
                    match present_channel_relay_join_on_stream(&mut send, &mut recv, request, holder).await? {
                        ChannelJoinOutcome::Admitted { .. } => {}
                        ChannelJoinOutcome::Refused => {
                            return Err(AdmissionRefused::boxed("edge relay refused the channel join over the :443 front door"));
                        }
                        // #21: the relay park was reaped before a partner arrived -- return the
                        // typed error immediately (no further rungs: the rung WORKED, there was
                        // just nobody to pair with yet; re-dialing this same leg is the recovery).
                        ChannelJoinOutcome::ParkExpired => {
                            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"));
                        }
                    }
                    return run_channel_session_on_stream(
                        send,
                        recv,
                        role,
                        own_noise_private,
                        peer_noise_public,
                        local,
                    )
                    .await
                    .map_err(Into::into);
                }
                Err(e) => last = Some(e),
            }
        } else {
            // Direct: QUIC to the relay port. Unreachable/Failed falls through to :443.
            match dial_peer_direct(rung.endpoint, direct_timeout).await {
                Ok(conn) => {
                    eprintln!("ct-agent channel: relay leg via QUIC ({}) (#106)", rung.endpoint);
                    let local = local.take().expect("local is committed to exactly one rung");
                    return join_via_relay(
                        &conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade,
                    )
                    .await;
                }
                Err(ChannelDialError::Unreachable) => last = Some(ChannelDialError::Unreachable.into()),
                Err(ChannelDialError::Failed(e)) => last = Some(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| "relay ladder had no rungs to dial".into()))
}

/// How long the acceptor waits for a direct connection before falling back to the
/// edge relay in the plane-brokered CLI flow (#72 / #98 / #103).
const CHANNEL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Config for the **plane-brokered** `ct-agent channel` flow (#98 / #103): present a
/// grant to the edge rendezvous, learn the peer via the broker (keys relayed — no
/// out-of-band `CT_CHANNEL_*` exchange), and connect direct-then-relay. Read from
/// `CT_CHANNEL_*` so it fits the `/channel.sh` one-liner. This is the cross-host path
/// (NAT traversal via the broker), distinct from the direct-address [`ChannelRunConfig`].
pub struct ChannelJoinCliConfig {
    pub role: ChannelRole,
    /// Edge rendezvous endpoint (`CT_CHANNEL_BROKER`, `CT_EDGE_CHANNEL_LISTEN` on the plane).
    pub broker_addr: SocketAddr,
    /// Edge relay endpoint used on direct-dial failure (`CT_CHANNEL_RELAY`).
    pub relay_addr: SocketAddr,
    /// The operator-signed channel grant this member holds (`CT_CHANNEL_GRANT`, hex).
    pub grant: ct_common::channel::SignedChannelGrant,
    /// The holder ed25519 private key that proves possession (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// This member's Noise (X25519) private key (`CT_CHANNEL_NOISE_KEY`, hex). SECRET.
    pub own_noise_private: [u8; 32],
    /// The host:port this member **binds** its direct-path QUIC listener to
    /// (`CT_CHANNEL_LISTEN`). Inside a NAT/container this is typically `0.0.0.0:<port>`
    /// or a private bridge address — see `advertise_addr` for what a peer actually dials.
    pub listen_addr: SocketAddr,
    /// The host:port this member **advertises** to a peer for the direct path
    /// (`CT_CHANNEL_ADVERTISE`, optional — defaults to `listen_addr` when unset). Exists
    /// because a containerized/NAT'd accept-side member cannot bind the address the
    /// outside world reaches it on (e.g. a Docker port-published `<public-ip>:<port>`
    /// while the process itself binds `0.0.0.0:<port>`) — mirrors the same split
    /// `CT_AGENT_DIRECT_ADVERTISE` already provides for the Browser-Plane tunnel path.
    /// Relay-only auto-detection and the peer-facing admission `endpoint` both use THIS
    /// address, not `listen_addr` — what matters for dialability is what's advertised.
    pub advertise_addr: SocketAddr,
    /// Whether this member joins in **relay-only** mode (#121): forced by
    /// `CT_CHANNEL_RELAY_ONLY`, or auto-detected when `listen_addr` is not globally routable
    /// (a NAT-only host). A relay-only member skips binding the direct listener and advertises
    /// the relay-only sentinel, participating purely via the edge relay + the `:443` fallback.
    pub relay_only: bool,
    /// Optional unified `:443` front door (`CT_CHANNEL_FRONT_DOOR`, host:port) — the #106
    /// fallback for restrictive networks that block the channel broker/relay ports. When
    /// set, the dial ladder tries the direct broker/relay first, then this front door over
    /// TLS-TCP with the `ct-edge-channel` ALPN.
    pub front_door: Option<SocketAddr>,
    /// The edge's TLS certificate (DER) the `:443` front-door dial trusts
    /// (`CT_CHANNEL_FRONT_DOOR_CERT`, hex) — the trust anchor a front-door TLS-TCP dial
    /// needs (#106). Present ⇒ `run_channel_join_command` admits over the broker *ladder*
    /// (direct QUIC → the `:443` front door). Absent ⇒ direct-QUIC-only broker admission,
    /// even if `front_door` is set (a front door you have no root for is unusable).
    pub front_door_cert: Option<CertificateDer<'static>>,
    /// Optional libp2p **Circuit-Relay v2** multiaddr (`CT_CHANNEL_CIRCUIT_RELAY`, #136 N-wire).
    /// When set for a **relay-only** member, the join starts on the edge relay and then
    /// opportunistically hole-punches to a **direct** NAT-to-NAT link via DCUtR through this
    /// circuit relay ([`join_via_relay_dcutr`]). Absent ⇒ the plain edge-relay session (no punch).
    pub circuit_relay: Option<libp2p::Multiaddr>,
    /// The edge's `:443` **relay-gate** leg (`CT_CHANNEL_RELAY_GATE`, host:port) — the real
    /// gated Circuit-Relay v2 hole-punch this project ships (no new public port; grant +
    /// possession pre-auth before a byte reaches the relay-node, see `crates/edge/src/relay_gate.rs`
    /// on the edge side). When set for a **relay-only** member, takes priority over
    /// `circuit_relay` (a directly-dialable relay multiaddr, kept for the nat-lab test rig) —
    /// [`join_via_relay_gate_dcutr`] is used instead of [`join_via_relay_dcutr`].
    pub relay_gate_addr: Option<SocketAddr>,
    /// The trust anchor (DER) for the `:443` relay-gate TLS-TCP dial (`CT_CHANNEL_RELAY_GATE_CERT`,
    /// hex) — required alongside `relay_gate_addr`, same treatment as `front_door_cert`.
    pub relay_gate_cert: Option<CertificateDer<'static>>,
    /// **#104 in-band relay→direct upgrade**, opt-in (`CT_CHANNEL_DIRECT_UPGRADE=1`, default
    /// off — unset, nothing changes). When true and a relay-leg session forms (this member's
    /// own [`ChannelJoinOutcome::Admitted::observed_reflexive`] was learned during THIS
    /// admission), the session negotiates a direct-dial candidate **in-band, over the
    /// already-Noise_IK-authenticated relay stream itself** — never a new advertised/open
    /// port, never anything the broker relays — and opportunistically upgrades to it,
    /// falling back to the relay transparently on failure. This is the real payoff for two
    /// members on genuinely separate networks; on a single co-located host (e.g. this
    /// project's own demos) the observed-reflexive address is a private bridge IP, so the
    /// SSRF guard (`upgrade_safe_endpoint`) correctly refuses it and the session simply
    /// stays on the relay, exactly as it did before this option existed.
    pub direct_upgrade: bool,
    /// #276: this member's OWN genuinely direct edge relay address (`CT_CHANNEL_RELAY_DIRECT`,
    /// host:port), tried BEFORE `relay_addr` on the relay-gate DCUtR path — "always look for
    /// direct communication; relay is only the last line of defense," specifically for a
    /// member whose configured `CT_CHANNEL_RELAY` points at a same-network super-peer relay
    /// (`#276` piece 2) rather than the real edge. Absent (the common case) ⇒ unchanged
    /// behavior, dial `relay_addr` directly with no extra latency. Present ⇒ try this address
    /// first (bounded timeout), falling through to `relay_addr` only on failure — see
    /// [`dial_relay_preferring_direct`].
    pub relay_addr_direct: Option<SocketAddr>,
    /// #16 escape hatch, channel-path counterpart of `CT_AGENT_REGISTER_TCP_ONLY`:
    /// when true (`CT_CHANNEL_FRONT_DOOR_ONLY`), the broker/relay dial ladders skip
    /// the direct QUIC rung entirely and dial the `:443` front door exclusively —
    /// for deployments whose UDP path to the edge is known-flaky ("UDP flapping"),
    /// where a session admitted over QUIC dies with the next flap while the TLS-TCP
    /// front door stays up. Requires `front_door` + `front_door_cert` (refused at
    /// parse time otherwise — a front-door-only ladder with no front door would have
    /// zero rungs). Default `false`: ladder order unchanged.
    pub front_door_only: bool,
}

/// Parse the optional `CT_CHANNEL_CIRCUIT_RELAY` libp2p circuit-relay multiaddr (#136 N-wire):
/// absent/empty ⇒ `None` (no DCUtR upgrade — plain relay session); set-but-malformed ⇒ an error
/// (a typo shouldn't silently disable the hole-punch, mirroring the `:443` front-door handling).
/// Pure — the multiaddr is validated here so a bad value fails config load, not mid-session.
pub fn parse_circuit_relay(value: Option<String>) -> Result<Option<libp2p::Multiaddr>, String> {
    match value {
        Some(s) if !s.trim().is_empty() => s
            .trim()
            .parse::<libp2p::Multiaddr>()
            .map(Some)
            .map_err(|e| format!("CT_CHANNEL_CIRCUIT_RELAY invalid multiaddr: {e}")),
        _ => Ok(None),
    }
}

/// How one rung of the channel dial ladder reaches the edge (#106). Ordered from the most
/// direct transport to the least conspicuous one; see [`ChannelJoinCliConfig::ladder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDialKind {
    /// A direct QUIC dial to the channel port.
    Direct,
    /// The unified `:443` front door (TLS-TCP) advertising the `ct-edge-channel` ALPN, so a
    /// network that blocks the channel ports can still reach the broker/relay (the #31/#46
    /// pattern). Presents SNI `localhost`.
    FrontDoor,
    /// The same `:443` front door, dialed so that the ClientHello looks like ordinary
    /// HTTPS: ALPN `h2` under SNI `edge-cdn.invalid`
    /// ([`crate::transport::tcp_tls_connect_channel_boring`]). For networks whose DPI
    /// fingerprints the distinctive `ct-edge-channel` ALPN or the obviously-wrong
    /// `localhost` SNI and drops the connection before the join bytes reach the broker.
    FrontDoorBoring,
}

impl ChannelDialKind {
    /// Whether this rung goes over the `:443` front door (either ClientHello flavour)
    /// rather than a direct QUIC dial.
    pub fn is_front_door(self) -> bool {
        matches!(self, Self::FrontDoor | Self::FrontDoorBoring)
    }

    /// The operator-facing rung name used in the dial diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::FrontDoor => "front-door(:443)",
            Self::FrontDoorBoring => "front-door-boring-alpn(:443)",
        }
    }
}

/// One rung of the channel dial **fallback ladder** (#106): where + how to reach the edge
/// channel broker or relay. Tried in order; the first rung that connects wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelDialRung {
    /// The endpoint to dial.
    pub endpoint: SocketAddr,
    /// Which transport/ClientHello flavour to reach [`Self::endpoint`] with.
    pub kind: ChannelDialKind,
}

/// Decide whether this member joins in **relay-only** mode (#121): `explicit` (the
/// `CT_CHANNEL_RELAY_ONLY` flag) always forces it on; otherwise it auto-detects relay-only
/// when `listen_addr` is not a globally-routable (global-unicast) address — a NAT-only /
/// private-address-only host that the edge would refuse to advertise (#94) and that no peer
/// could dial. A relay-only member skips binding the direct listener and advertises the
/// [`ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel, participating purely via the
/// edge relay + the #106 `:443` fallback (outbound-only). Pure — it decides from the address
/// alone, so it is unit-testable without touching real network interfaces.
pub fn relay_only_mode(explicit: bool, listen_addr: SocketAddr) -> bool {
    explicit || !is_globally_routable(listen_addr.ip())
}

/// Whether `ip` is a globally-routable (global-unicast) address — the mirror of the edge's
/// `safe_endpoint` range check (#94): loopback / unspecified / multicast, RFC1918 private,
/// link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`) and IPv6 unique-local
/// (`fc00::/7`) are all NOT routable. A member with only such an address can't be dialed, so
/// it defaults to relay-only.
fn is_globally_routable(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return false;
            }
            let o = v4.octets();
            !(o[0] == 100 && (64..=127).contains(&o[1])) // reject CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) != 0xfc00 && (s0 & 0xffc0) != 0xfe80 // reject fc00::/7 + fe80::/10
        }
    }
}

/// #137 SSRF guard for the #104 in-band relay→direct upgrade. The responder dials a
/// **peer-conveyed** `Offer.direct_endpoint`; because the upgrade is negotiated peer-to-peer over
/// the relay pump, that endpoint **never passed the edge broker's `safe_endpoint` admission gate**
/// (#94). Apply the IDENTICAL range filter here — the shared [`ct_common::channel::is_global_unicast`],
/// the exact primitive the edge's `safe_endpoint` is built on — so a malicious/compromised initiator
/// cannot make the responder dial an internal address: loopback, RFC1918/LAN, cloud metadata
/// `169.254.169.254`, link-local, CGNAT, IPv6 ULA, unspecified. Returns the parsed address ONLY if
/// it is safe to dial; `None` (unparseable **or** non-global-unicast) refuses the upgrade and the
/// session stays on the relay. This is an unconditional security guard — no test bypass.
fn upgrade_safe_endpoint(ep: &str) -> Option<SocketAddr> {
    ep.parse::<SocketAddr>()
        .ok()
        .filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

/// Resolve an edge endpoint (`CT_CHANNEL_BROKER` / `CT_CHANNEL_RELAY`) that may be given as either a
/// literal `IP:port` **or** a `host:port` hostname (#214: the plane's rendezvous/relay is often handed
/// out as e.g. `bunsenbrenner.org:4433`). A literal address is taken as-is (no name lookup, so the
/// common case and the tests stay resolver-free); otherwise it is resolved via DNS and the first
/// address is used. A string with no port, or a name that resolves to nothing, is a clear error rather
/// than the previous opaque "invalid socket address syntax".
fn resolve_socket_addr(raw: &str) -> Result<SocketAddr, String> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(sa);
    }
    use std::net::ToSocketAddrs;
    raw.to_socket_addrs()
        .map_err(|e| format!("{raw:?} is not an IP:port and did not resolve as host:port: {e}"))?
        .next()
        .ok_or_else(|| format!("{raw:?} resolved to no addresses"))
}

impl ChannelJoinCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The ordered dial plan for the **rendezvous broker**: the direct port first, then
    /// (if `CT_CHANNEL_FRONT_DOOR` is configured) the `:443` front door — or the front
    /// door alone under `CT_CHANNEL_FRONT_DOOR_ONLY` (#16). Pure.
    pub fn broker_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.broker_addr, self.front_door, self.front_door_only)
    }

    /// The ordered dial plan for the **relay** (used on direct-dial failure): the direct
    /// port first, then (if configured) the `:443` front door — or the front door alone
    /// under `CT_CHANNEL_FRONT_DOOR_ONLY` (#16). Pure.
    pub fn relay_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.relay_addr, self.front_door, self.front_door_only)
    }

    /// Direct QUIC first, then — if a front door is configured — the two `:443` rungs, the
    /// established `ct-edge-channel` one before the DPI-resistant boring-ALPN one. That
    /// order is deliberate: the boring rung is strictly a last resort for networks that
    /// fingerprint the ClientHello (#106 boring-alpn, from a real 2026-08-12 support case),
    /// so on every network where the existing rungs work, nothing about the dial changes.
    /// Pure.
    fn ladder(
        direct: SocketAddr,
        front_door: Option<SocketAddr>,
        front_door_only: bool,
    ) -> Vec<ChannelDialRung> {
        // #16: `front_door_only` drops the direct QUIC rung — an operator pinning a
        // known-flaky-UDP deployment to the TLS-TCP front door outright. Guarded at
        // parse time to require a configured front door, so this can never yield an
        // empty ladder.
        let mut rungs = Vec::with_capacity(3);
        if !(front_door_only && front_door.is_some()) {
            rungs.push(ChannelDialRung { endpoint: direct, kind: ChannelDialKind::Direct });
        }
        if let Some(fd) = front_door {
            rungs.push(ChannelDialRung { endpoint: fd, kind: ChannelDialKind::FrontDoor });
            rungs.push(ChannelDialRung { endpoint: fd, kind: ChannelDialKind::FrontDoorBoring });
        }
        rungs
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = |k: &str, what: &str| -> Result<SocketAddr, String> {
            let raw = f(k).ok_or_else(|| format!("{k} required ({what})"))?;
            resolve_socket_addr(raw.trim()).map_err(|e| format!("{k} invalid ({what}): {e}"))
        };
        let broker_addr = addr("CT_CHANNEL_BROKER", "edge rendezvous host:port")?;
        let relay_addr = addr("CT_CHANNEL_RELAY", "edge relay host:port")?;
        // #121/#173: relay-only mode. `CT_CHANNEL_RELAY_ONLY` forces it on; otherwise it is
        // auto-detected below from the advertised listen address. Parsed BEFORE CT_CHANNEL_LISTEN
        // because a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is OPTIONAL in
        // that mode — it's never bound or advertised (the relay-only sentinel stands in). #173: both
        // source-2 and sink independently hit the old unconditional hard-error and had to invent a
        // dummy value; a relay-only operator no longer has to.
        let relay_only_explicit = f("CT_CHANNEL_RELAY_ONLY")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        let listen_addr = match f("CT_CHANNEL_LISTEN") {
            Some(s) if !s.trim().is_empty() => s.trim().parse().map_err(|e| format!("CT_CHANNEL_LISTEN invalid: {e}"))?,
            // Relay-only has no dialable address → an unbound placeholder is never used.
            _ if relay_only_explicit => SocketAddr::from(([0, 0, 0, 0], 0)),
            _ => return Err("CT_CHANNEL_LISTEN required (advertised host:port) — or set CT_CHANNEL_RELAY_ONLY=1 for a relay-only member with no dialable address".to_string()),
        };
        // Optional: the address a peer actually dials, when it differs from what this
        // process binds (`listen_addr`) — e.g. a Docker port-published `<public-ip>:<port>`
        // while the container itself binds `0.0.0.0:<port>`. Absent ⇒ advertise_addr ==
        // listen_addr, unchanged from before this field existed. A set-but-malformed value
        // is an error, same treatment as every other CT_CHANNEL_* address.
        let advertise_addr = match f("CT_CHANNEL_ADVERTISE") {
            Some(s) if !s.trim().is_empty() => {
                resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_ADVERTISE invalid: {e}"))?
            }
            _ => listen_addr,
        };
        let grant_bytes = f("CT_CHANNEL_GRANT")
            .as_deref()
            .and_then(hex_bytes)
            .ok_or("CT_CHANNEL_GRANT required (hex signed grant)")?;
        let grant = ct_common::channel::SignedChannelGrant::decode(&grant_bytes)
            .map_err(|e| format!("CT_CHANNEL_GRANT malformed: {e}"))?;
        let holder = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let own_noise_private = req_hex32(&f, "CT_CHANNEL_NOISE_KEY", "64 hex")?;
        // #106: optional :443 front-door fallback. Absent -> direct-only ladder; a set but
        // malformed value is an error (a typo shouldn't silently drop the fallback).
        let front_door = match f("CT_CHANNEL_FRONT_DOOR") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_FRONT_DOOR invalid: {e}"))?)
            }
            _ => None,
        };
        // #106: the trust anchor for the `:443` front-door TLS-TCP dial. Optional and
        // independent of `front_door` (a set-but-malformed value is an error — a typo
        // shouldn't silently drop the fallback); absent ⇒ direct-QUIC-only admission.
        let front_door_cert = match f("CT_CHANNEL_FRONT_DOOR_CERT") {
            Some(s) if !s.trim().is_empty() => Some(CertificateDer::from(
                hex_bytes(s.trim()).ok_or("CT_CHANNEL_FRONT_DOOR_CERT must be hex DER")?,
            )),
            _ => None,
        };
        // Auto-detect relay-only when not forced: a non-globally-routable ADVERTISED address
        // (a NAT-only host the edge would refuse to advertise, #94) is treated as relay-only.
        // Uses advertise_addr, not listen_addr — a container legitimately binds a private/
        // unspecified address while advertising a real public one; what matters for
        // dialability is what's advertised, not what's bound.
        let relay_only = relay_only_mode(relay_only_explicit, advertise_addr);
        // #136 N-wire: optional libp2p circuit-relay multiaddr for the DCUtR NAT-to-NAT punch.
        let circuit_relay = parse_circuit_relay(f("CT_CHANNEL_CIRCUIT_RELAY"))?;
        // The real gated relay-gate leg: same optional/malformed-is-an-error treatment as
        // CT_CHANNEL_FRONT_DOOR/_CERT above.
        let relay_gate_addr = match f("CT_CHANNEL_RELAY_GATE") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_RELAY_GATE invalid: {e}"))?)
            }
            _ => None,
        };
        let relay_gate_cert = match f("CT_CHANNEL_RELAY_GATE_CERT") {
            Some(s) if !s.trim().is_empty() => Some(CertificateDer::from(
                hex_bytes(s.trim()).ok_or("CT_CHANNEL_RELAY_GATE_CERT must be hex DER")?,
            )),
            _ => None,
        };
        // #104 in-band relay->direct upgrade: opt-in, off by default (unset -> false,
        // identical truthy-string handling as CT_CHANNEL_RELAY_ONLY above).
        let direct_upgrade = f("CT_CHANNEL_DIRECT_UPGRADE")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        // #276: optional, same treatment as CT_CHANNEL_FRONT_DOOR above (a set-but-malformed
        // value is an error, not a silently-dropped preference).
        let relay_addr_direct = match f("CT_CHANNEL_RELAY_DIRECT") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_RELAY_DIRECT invalid: {e}"))?)
            }
            _ => None,
        };
        // #16: front-door-only dialing (same truthy handling as CT_CHANNEL_RELAY_ONLY).
        // Requires a usable front door — refusing at parse time beats a zero-rung ladder
        // that would fail every join with an unhelpful "no rungs to dial".
        let front_door_only = f("CT_CHANNEL_FRONT_DOOR_ONLY")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if front_door_only && (front_door.is_none() || front_door_cert.is_none()) {
            return Err(
                "CT_CHANNEL_FRONT_DOOR_ONLY requires CT_CHANNEL_FRONT_DOOR and CT_CHANNEL_FRONT_DOOR_CERT"
                    .to_string(),
            );
        }
        Ok(Self {
            role,
            broker_addr,
            relay_addr,
            grant,
            holder,
            own_noise_private,
            listen_addr,
            advertise_addr,
            relay_only,
            front_door,
            front_door_cert,
            circuit_relay,
            relay_gate_addr,
            relay_gate_cert,
            direct_upgrade,
            relay_addr_direct,
            front_door_only,
        })
    }
}

/// A freshly-minted Agent-Fabric channel identity for **self-service** participation
/// (#117): the ed25519 *holder* keypair (proves possession of a grant) and the X25519
/// *Noise* keypair (the member's session key). Both are generated **locally** so the
/// private keys never leave the participant's machine — which is why self-service
/// channel setup is a local CLI step, not a browser/server flow: it preserves the
/// provider-blind property (the operator never sees a private key). Before this, a
/// participant had to hand-craft these keys or have the operator provision them by hand
/// for every new member. The hex accessors emit exactly what the `ct-agent channel` CLI
/// consumes (`CT_CHANNEL_HOLDER_KEY`, `CT_CHANNEL_NOISE_KEY`) plus the two **public**
/// keys an operator needs to register the channel / sign this member's grant.
pub struct ChannelIdentity {
    /// The holder ed25519 keypair (its private half proves grant possession).
    pub holder: SigningKey,
    /// The member's X25519 Noise static keypair.
    pub noise: ct_common::noise::StaticKeypair,
}

impl ChannelIdentity {
    /// Mint a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut holder_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut holder_seed);
        let holder = SigningKey::from_bytes(&holder_seed);
        let noise = ct_common::noise::generate_static_keypair();
        Self { holder, noise }
    }

    /// Value for `CT_CHANNEL_HOLDER_KEY` — the 64-hex ed25519 holder **private** key. SECRET.
    pub fn holder_key_hex(&self) -> String {
        hex_encode(&self.holder.to_bytes())
    }
    /// Value for `CT_CHANNEL_NOISE_KEY` — the 64-hex X25519 Noise **private** key. SECRET.
    pub fn noise_key_hex(&self) -> String {
        hex_encode(&self.noise.private)
    }
    /// The 64-hex ed25519 holder **public** key — an operator signs this member's grant over it.
    pub fn holder_pubkey_hex(&self) -> String {
        hex_encode(self.holder.verifying_key().as_bytes())
    }
    /// The 64-hex X25519 Noise **public** key — the member's attested session key.
    pub fn noise_pubkey_hex(&self) -> String {
        hex_encode(&self.noise.public)
    }

    /// A copy-pasteable shell block a self-service participant `eval`s (or sources)
    /// before running `ct-agent channel` (#117): the two **secret** private keys as
    /// `export`s the CLI reads, plus the two **public** keys as comments to hand to the
    /// channel operator (who signs this member's grant / registers the channel). The
    /// operator still supplies `CT_CHANNEL_GRANT` and the broker/relay/front-door
    /// addresses. Private keys are generated locally and never printed as anything but
    /// the participant's own env — they never reach the operator or the server.
    pub fn env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel identity — generated locally, keep the private keys secret.\n\
             # Give these PUBLIC keys to the channel operator (to sign your grant / register):\n\
             #   holder_pubkey = {holder_pub}\n\
             #   noise_pubkey  = {noise_pub}\n\
             export CT_CHANNEL_HOLDER_KEY={holder_priv}\n\
             export CT_CHANNEL_NOISE_KEY={noise_priv}\n\
             #\n\
             # #330: if you're behind a NAT and can't reach the operator's broker/relay ports\n\
             # directly, you ALSO need CT_CHANNEL_RELAY_GATE (+ _CERT) — a separate, relay-gate\n\
             # protocol from plain CT_CHANNEL_RELAY, not interchangeable with it. Ask your\n\
             # operator whether this deployment needs it; if so, CT_CHANNEL_RELAY_GATE is the\n\
             # deployment's unified front-door address (ask the operator, or fetch it from this\n\
             # control plane's GET /network-info -> channel_relay_gate_port, same host as\n\
             # CT_AGENT_CP_URL) and CT_CHANNEL_RELAY_GATE_CERT is the DER from GET /pki/ca (same\n\
             # CA root you already trust for everything else). Omitting this when your side of a\n\
             # channel pairing needs it fails silently downstream (an unhelpful early-eof), not\n\
             # with an error naming the missing var — see docs.bunsenbrenner.org for details.\n",
            holder_pub = self.holder_pubkey_hex(),
            noise_pub = self.noise_pubkey_hex(),
            holder_priv = self.holder_key_hex(),
            noise_priv = self.noise_key_hex(),
        )
    }
}

/// One overlay link compiled into a concrete A2A channel (#107-nway): the derived
/// [`ct_common::channel::ChannelId`] and the two operator-signed grants the link's members
/// present to join it. The initiator holder is the canonically-smaller node id of the link
/// (the `Initiate`-direction side); the acceptor is the other. Both members independently
/// derive the same `channel` from their holder keys, so no coordination round-trip is
/// needed to agree on the channel address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledLink {
    pub channel: ct_common::channel::ChannelId,
    pub initiator_holder: [u8; 32],
    pub acceptor_holder: [u8; 32],
    pub initiator_grant: ct_common::channel::SignedChannelGrant,
    pub acceptor_grant: ct_common::channel::SignedChannelGrant,
}

/// A channel **operator's** signing identity (#117-operator-flow): the ed25519 key that
/// *authorizes* a channel — its public key is the channel's authority (registered with
/// the control plane so the edge can verify member grants), and it signs every member's
/// grant. Generated locally, like a member's [`ChannelIdentity`]; the operator private
/// key never leaves the operator's machine (provider-blind — the server sees only the
/// public key). This lets an account create channels and admit members with no manual
/// crypto provisioning by central.
pub struct OperatorIdentity {
    /// The operator ed25519 keypair (its private half signs member grants).
    pub key: SigningKey,
}

impl OperatorIdentity {
    /// Mint a fresh operator key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The 64-hex operator **private** key (`CT_CHANNEL_OPERATOR_KEY`). SECRET.
    pub fn key_hex(&self) -> String {
        hex_encode(&self.key.to_bytes())
    }
    /// The 64-hex operator **public** key — the channel's authority, registered with the
    /// control plane so the edge verifies member grants against it.
    pub fn pubkey_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Issue a member grant: sign a `ChannelGrant` binding `holder_pubkey` (the member's
    /// `channel init` holder public key) to `channel` with `direction`/`expires_at`, and
    /// return the hex the member sets as `CT_CHANNEL_GRANT`. Pure crypto — the operator
    /// runs this locally after the member hands over their holder public key; no server
    /// round-trip and no private key ever leaves either machine.
    pub fn issue_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> String {
        hex_encode(&self.sign_member_grant(channel, holder_pubkey, direction, expires_at).encode())
    }

    /// Sign a `ChannelGrant` binding `holder_pubkey` to `channel` with `direction`/
    /// `expires_at` under the local operator key, returning the structured grant. The
    /// crypto shared by [`issue_member_grant`](Self::issue_member_grant) (which hex-encodes
    /// this for the member one-liner) and [`compile_overlay_grants`](Self::compile_overlay_grants).
    fn sign_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> ct_common::channel::SignedChannelGrant {
        use ct_common::channel::{ChannelGrant, Rights, SignedChannelGrant};
        let g = ChannelGrant {
            channel,
            holder: holder_pubkey,
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = self.key.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// scimbe/ct-agent#9: sign a `ChannelInvitation` for `invitee_identity` to join `channel`,
    /// returning the hex the invitee redeems (`ct-agent channel invite` prints this; the
    /// receiving-side endpoints and `verify_invitation`/`redeem_invitation` already exist in
    /// `ct_common::channel` and in the control plane — this was the missing producer). Pure
    /// crypto, same shape as [`issue_member_grant`]: the operator runs this locally, no server
    /// round-trip, no private key ever leaves either machine. Unlike a grant (which binds a
    /// `holder` key the operator already has in hand), an invitation targets an **identity**
    /// key the operator may only know from, e.g., a registry lookup or an out-of-band email —
    /// this is the actual cross-account case a plain `channel grant` can't cover.
    pub fn issue_member_invitation(
        &self,
        channel: ct_common::channel::ChannelId,
        invitee_identity: [u8; 32],
        direction: ct_common::channel::Direction,
        rights: ct_common::channel::Rights,
        delegable: bool,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> String {
        hex_encode(
            &self
                .sign_member_invitation(channel, invitee_identity, direction, rights, delegable, expires_at)
                .encode(),
        )
    }

    /// Sign a `ChannelInvitation` binding `invitee_identity` to `channel` under the local
    /// operator key, returning the structured invitation. Mirrors [`sign_member_grant`]:
    /// `ChannelInvitation::signing_bytes()` is domain-separated from a grant's (`"ct-chan-
    /// invite:v1|..."` vs. the grant's own prefix), so a captured invitation can never be
    /// replayed as a grant or vice versa.
    fn sign_member_invitation(
        &self,
        channel: ct_common::channel::ChannelId,
        invitee_identity: [u8; 32],
        direction: ct_common::channel::Direction,
        rights: ct_common::channel::Rights,
        delegable: bool,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> ct_common::channel::SignedChannelInvitation {
        use ct_common::channel::{ChannelInvitation, SignedChannelInvitation};
        let i = ChannelInvitation { channel, invitee_identity, direction, rights, delegable, expires_at };
        let signature = self.key.sign(&i.signing_bytes()).to_bytes();
        SignedChannelInvitation { invitation: i, signature }
    }

    /// Compile a topology's overlay `plan` into per-link A2A channels (#107-nway): each
    /// link (a canonical pair of agent node-ids) becomes a channel
    /// ([`ct_common::channel::channel_id_for_link`]) plus the two operator-signed grants its
    /// members present to join it. `holder_of` maps a node id to that agent's member holder
    /// pubkey (the controller knows each registered agent's key). The canonically-smaller
    /// node id of each link is the **Initiate** side — a stable, caller-independent split,
    /// like the broker's `authorize_channel_pair`. Returns `Err(node_id)` if a link names an
    /// agent with no holder mapping (the plan can't be wired without every endpoint's key).
    ///
    /// Pure given `holder_of`: the operator mints every grant **locally** with its own key
    /// (invariant #6) — no central round-trip; central only distributes the compiled grants.
    pub fn compile_overlay_grants(
        &self,
        plan: &ct_common::overlay::OverlayPlan,
        holder_of: impl Fn(&str) -> Option<[u8; 32]>,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> Result<Vec<CompiledLink>, String> {
        use ct_common::channel::{channel_id_for_link, Direction};
        let op_pub = self.key.verifying_key().to_bytes();
        let mut out = Vec::with_capacity(plan.links.len());
        for (a_id, b_id) in &plan.links {
            let initiator_holder = holder_of(a_id).ok_or_else(|| a_id.clone())?;
            let acceptor_holder = holder_of(b_id).ok_or_else(|| b_id.clone())?;
            // channel_id_for_link sorts by holder bytes, so both members derive the same id.
            let channel = channel_id_for_link(&op_pub, &initiator_holder, &acceptor_holder);
            out.push(CompiledLink {
                channel,
                initiator_holder,
                acceptor_holder,
                initiator_grant: self.sign_member_grant(
                    channel,
                    initiator_holder,
                    Direction::Initiate,
                    expires_at,
                ),
                acceptor_grant: self.sign_member_grant(
                    channel,
                    acceptor_holder,
                    Direction::Accept,
                    expires_at,
                ),
            });
        }
        Ok(out)
    }

    /// Issue a short-lived **membership staple** (E-fail-static, invariant #7): the operator
    /// re-affirms that `holder_pubkey` is *currently* a member of `channel`, valid for
    /// `ttl_secs` from `stapled_at`. Unlike [`issue_member_grant`](Self::issue_member_grant)
    /// — a long-lived capability — a staple is minted **frequently** and gossiped so peers
    /// keep admitting the member (via [`ct_common::channel::StapleCache`]) while central is
    /// unreachable, and it dies within one TTL once the operator stops re-issuing it
    /// (revocation latency = staple TTL).
    ///
    /// Minted with the **local** operator key (invariant #6): central never holds the key,
    /// so it can *distribute/refresh* staples but can never mint — nor forge — one. This is
    /// why a central compromise degrades to DoS/metadata, never impersonation. Returns the
    /// staple object (the gossip transport encodes it); the operator runs this locally on a
    /// refresh timer, no server round-trip.
    pub fn issue_membership_staple(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        stapled_at: ct_common::channel::UnixSeconds,
        ttl_secs: u64,
    ) -> ct_common::channel::MembershipStaple {
        use ct_common::channel::MembershipStaple;
        let expires_at = stapled_at.saturating_add(ttl_secs);
        let signature = self
            .key
            .sign(&MembershipStaple::signing_bytes(
                &channel,
                &holder_pubkey,
                stapled_at,
                expires_at,
            ))
            .to_bytes();
        MembershipStaple {
            channel,
            holder: holder_pubkey,
            stapled_at,
            expires_at,
            signature,
        }
    }

    /// A copy-pasteable, `eval`-safe shell block for `ct-agent channel operator-init`
    /// (#117): the operator private key as the `export` the `channel grant` command
    /// reads, plus the operator public key as a comment (the channel authority to
    /// register with the control plane). Generated locally; the private key never leaves.
    pub fn operator_env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel OPERATOR identity — generated locally, keep the key secret.\n\
             # Register this PUBLIC key as the channel authority (POST /channel/register):\n\
             #   operator_pubkey = {op_pub}\n\
             export CT_CHANNEL_OPERATOR_KEY={op_priv}\n",
            op_pub = self.pubkey_hex(),
            op_priv = self.key_hex(),
        )
    }
}

/// Inputs for `ct-agent channel join-pipeline-role` (#214 follow-up: generic pipeline
/// provisioning). Unlike [`MemberMaterialRequest`] — which needs `CT_CHANNEL_BRIDGE_HOLDER`, the
/// COUNTERPART's public key, so both sides must exchange keys before either can derive the
/// channel id — this derives the id from PUBLIC, PUBLISHED information only (the operator's
/// pubkey, the pipeline's id, and the role tag: exactly what `GET /registry/pipelines/:id`
/// returns). A bridge that needs a role's output and any agent capable of serving it each run this
/// independently and land on the *same* channel id with **no coordination round-trip** — no
/// GitHub-comment pubkey relay, no waiting on the other side. Reads the operator's PUBLIC key +
/// the pipeline id + role tag (all public, from the pipeline registry), the caller's own holder
/// PRIVATE key (to derive its pubkey and sign the attestation), and the caller's noise PUBLIC key.
/// Pure local compute — nothing is minted, nothing leaves the box.
pub struct PipelineRoleMaterialRequest {
    operator_pubkey: [u8; 32],
    pipeline_id: String,
    role: String,
    holder: SigningKey,
    noise_pubkey: [u8; 32],
}

impl PipelineRoleMaterialRequest {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        Ok(Self {
            operator_pubkey: req_hex32(
                &f,
                "CT_CHANNEL_OPERATOR_PUBKEY",
                "64 hex operator pubkey (from the pipeline registry entry's operator_pubkey_hex)",
            )?,
            pipeline_id: req_str(&f, "CT_PIPELINE_ID", "the pipeline's published id")?,
            role: req_str(&f, "CT_PIPELINE_ROLE", "the role tag you're joining (a role.tag from the pipeline spec)")?,
            holder: req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex; your holder PRIVATE key")?,
            noise_pubkey: req_hex32(&f, "CT_CHANNEL_NOISE_PUBKEY", "64 hex; your noise PUBLIC key")?,
        })
    }

    /// `(channel_id, holder_pubkey, noise_attestation)` — the derived material. The channel id is
    /// this pipeline role's canonical address (independent of who else has or hasn't joined yet);
    /// the attestation is this holder's signed binding of its noise key (#101), which the
    /// pipeline's channel owner relays so the peer can pin the key safely.
    fn compute(&self) -> (ct_common::channel::ChannelId, [u8; 32], [u8; 64]) {
        use ct_common::channel::{channel_id_for_pipeline_role, member_noise_attest_bytes};
        let holder_pubkey = self.holder.verifying_key().to_bytes();
        let channel = channel_id_for_pipeline_role(&self.operator_pubkey, &self.pipeline_id, &self.role);
        let attestation = self
            .holder
            .sign(&member_noise_attest_bytes(&channel, &holder_pubkey, &self.noise_pubkey))
            .to_bytes();
        (channel, holder_pubkey, attestation)
    }

    /// The paste-able block the caller hands to the pipeline's channel owner (whoever ran
    /// `POST /me/channels` for this role) so it can `POST /me/channels/:channel/members` on the
    /// caller's behalf.
    pub fn render(&self) -> String {
        let (channel, holder_pubkey, attestation) = self.compute();
        format!(
            "pipeline_id       = {}\nrole              = {}\nholder_pubkey     = {}\nnoise_pubkey      = {}\nchannel_id        = {}\nnoise_attestation = {}\n",
            self.pipeline_id,
            self.role,
            hex_encode(&holder_pubkey),
            hex_encode(&self.noise_pubkey),
            hex_encode(&channel.0),
            hex_encode(&attestation),
        )
    }
}

/// Inputs for `ct-agent channel grant` (#117-operator-flow): an operator signs one
/// member's grant from the environment, parsed like [`ChannelJoinCliConfig::from_lookup`].
/// `CT_CHANNEL_OPERATOR_KEY` is the operator's own key (from `channel operator-init`);
/// `CT_GRANT_*` describe the member being admitted (their `channel init`
/// `holder_pubkey`, the channel id, the direction, and an expiry).
pub struct OperatorGrantRequest {
    pub operator: SigningKey,
    pub channel: ct_common::channel::ChannelId,
    pub member_holder: [u8; 32],
    pub direction: ct_common::channel::Direction,
    pub expires_at: ct_common::channel::UnixSeconds,
}

impl OperatorGrantRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let channel = ct_common::channel::ChannelId(req_hex32(&f, "CT_GRANT_CHANNEL", "64 hex channel id")?);
        let member_holder = req_hex32(&f, "CT_GRANT_MEMBER_HOLDER", "64 hex member holder pubkey")?;
        let direction = match f("CT_GRANT_DIRECTION").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref d) if d == "initiate" || d == "initiator" => ct_common::channel::Direction::Initiate,
            Some(ref d) if d == "accept" || d == "responder" => ct_common::channel::Direction::Accept,
            other => return Err(format!("CT_GRANT_DIRECTION must be initiate|accept, got {other:?}")),
        };
        let expires_at = req_str(&f, "CT_GRANT_EXPIRES", "unix seconds")?
            .trim()
            .parse()
            .map_err(|e| format!("CT_GRANT_EXPIRES invalid: {e}"))?;
        Ok(Self { operator, channel, member_holder, direction, expires_at })
    }

    /// The signed grant hex the member sets as `CT_CHANNEL_GRANT`.
    pub fn issue(&self) -> String {
        OperatorIdentity { key: self.operator.clone() }.issue_member_grant(
            self.channel,
            self.member_holder,
            self.direction,
            self.expires_at,
        )
    }
}

/// scimbe/ct-agent#9 `ct-agent channel invite`: as the operator, sign an invitation for an
/// **identity** key you don't otherwise coordinate holder/noise material with directly — the
/// cross-account case `channel grant`/`provision-link-channel.sh` can't cover, since those
/// both assume you already have the other side's holder pubkey in hand. Reads
/// CT_CHANNEL_OPERATOR_KEY + CT_INVITE_*.
pub struct OperatorInviteRequest {
    pub operator: SigningKey,
    pub channel: ct_common::channel::ChannelId,
    pub invitee_identity: [u8; 32],
    pub direction: ct_common::channel::Direction,
    pub rights: ct_common::channel::Rights,
    pub delegable: bool,
    pub expires_at: ct_common::channel::UnixSeconds,
}

impl OperatorInviteRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let channel = ct_common::channel::ChannelId(req_hex32(&f, "CT_INVITE_CHANNEL", "64 hex channel id")?);
        let invitee_identity =
            req_hex32(&f, "CT_INVITE_IDENTITY", "64 hex invitee identity pubkey")?;
        let direction = match f("CT_INVITE_DIRECTION").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref d) if d == "initiate" || d == "initiator" => ct_common::channel::Direction::Initiate,
            Some(ref d) if d == "accept" || d == "responder" => ct_common::channel::Direction::Accept,
            Some(ref d) if d == "both" => ct_common::channel::Direction::Both,
            other => return Err(format!("CT_INVITE_DIRECTION must be initiate|accept|both, got {other:?}")),
        };
        let rights = match f("CT_INVITE_RIGHTS").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            None => ct_common::channel::Rights::ReadWrite, // matches OperatorGrantRequest's fixed ReadWrite default
            Some(ref r) if r == "read" || r == "r" => ct_common::channel::Rights::Read,
            Some(ref r) if r == "write" || r == "w" => ct_common::channel::Rights::Write,
            Some(ref r) if r == "readwrite" || r == "read-write" || r == "rw" => {
                ct_common::channel::Rights::ReadWrite
            }
            other => return Err(format!("CT_INVITE_RIGHTS must be read|write|readwrite, got {other:?}")),
        };
        let delegable = match f("CT_INVITE_DELEGABLE").as_deref() {
            None => false,
            Some(v) => v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"),
        };
        let expires_at = req_str(&f, "CT_INVITE_EXPIRES", "unix seconds")?
            .trim()
            .parse()
            .map_err(|e| format!("CT_INVITE_EXPIRES invalid: {e}"))?;
        Ok(Self { operator, channel, invitee_identity, direction, rights, delegable, expires_at })
    }

    /// The signed invitation hex the invitee redeems (see `ct_common::channel::redeem_invitation`
    /// / `invitation_redeem_bytes` for the receiving-side flow this feeds).
    pub fn issue(&self) -> String {
        OperatorIdentity { key: self.operator.clone() }.issue_member_invitation(
            self.channel,
            self.invitee_identity,
            self.direction,
            self.rights,
            self.delegable,
            self.expires_at,
        )
    }
}

/// #207 Slice A onboarding helper — compute the material a channel MEMBER hands its operator/central
/// so the operator can mint its grant and admit it to a link channel (e.g. sink's standby joining a
/// bridge role for failover). A member otherwise has to hand-roll `channel_id_for_link` +
/// `member_noise_attest_bytes` + an ed25519 signature; this does it in one local command. Reads the
/// operator + bridge-holder PUBLIC keys the operator supplies, the member's own holder PRIVATE key
/// (to derive its holder pubkey and sign the attestation), and the member's noise PUBLIC key. Pure
/// local compute — nothing is minted, nothing leaves the box.
pub struct MemberMaterialRequest {
    operator_pubkey: [u8; 32],
    bridge_holder: [u8; 32],
    holder: SigningKey,
    noise_pubkey: [u8; 32],
}

impl MemberMaterialRequest {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        Ok(Self {
            operator_pubkey: req_hex32(&f, "CT_CHANNEL_OPERATOR_PUBKEY", "64 hex operator pubkey (from central)")?,
            bridge_holder: req_hex32(&f, "CT_CHANNEL_BRIDGE_HOLDER", "64 hex bridge holder pubkey (from central)")?,
            holder: req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex; your member holder PRIVATE key")?,
            noise_pubkey: req_hex32(&f, "CT_CHANNEL_NOISE_PUBKEY", "64 hex; your member noise PUBLIC key")?,
        })
    }

    /// `(channel_id, holder_pubkey, noise_attestation)` — the derived material. The channel id is the
    /// operator-scoped link between the bridge holder and this member (order-independent); the
    /// attestation is this member's holder-signed binding of its noise key (#101), which the operator
    /// relays so the peer can pin the key safely.
    fn compute(&self) -> (ct_common::channel::ChannelId, [u8; 32], [u8; 64]) {
        use ct_common::channel::{channel_id_for_link, member_noise_attest_bytes};
        let holder_pubkey = self.holder.verifying_key().to_bytes();
        let channel = channel_id_for_link(&self.operator_pubkey, &self.bridge_holder, &holder_pubkey);
        let attestation = self
            .holder
            .sign(&member_noise_attest_bytes(&channel, &holder_pubkey, &self.noise_pubkey))
            .to_bytes();
        (channel, holder_pubkey, attestation)
    }

    /// The paste-able block the member posts back to the operator/central.
    pub fn render(&self) -> String {
        let (channel, holder_pubkey, attestation) = self.compute();
        format!(
            "holder_pubkey     = {}\nnoise_pubkey      = {}\nchannel_id        = {}\nnoise_attestation = {}\n",
            hex_encode(&holder_pubkey),
            hex_encode(&self.noise_pubkey),
            hex_encode(&channel.0),
            hex_encode(&attestation),
        )
    }
}

/// Inputs for `ct-agent channel register` (#117-operator-register): register the
/// operator's channel authority with the control plane (`POST /me/channels`) so the edge
/// accepts the member grants the operator signs — the last CP round-trip for an
/// end-to-end self-service Agent-Fabric channel. Parsed from the environment like
/// [`OperatorGrantRequest::from_lookup`], reusing the onboarding/operator vars:
/// the control-plane URL (`CT_AGENT_CP_URL`, as onboarding uses), the channel id
/// (`CT_GRANT_CHANNEL`), the OIDC bearer token (`CT_OIDC_TOKEN`), and the operator public
/// key — derived from `CT_CHANNEL_OPERATOR_KEY` (the operator's own private key from
/// `channel operator-init`) or supplied directly as `CT_CHANNEL_OPERATOR_PUBKEY`.
pub struct ChannelRegisterRequest {
    /// Control-plane base URL (`POST {cp_url}/me/channels`).
    pub cp_url: String,
    /// The channel id, canonical 64-hex.
    pub channel_hex: String,
    /// The operator ed25519 public key, canonical 64-hex — the channel's authority.
    pub operator_pubkey_hex: String,
    /// The OIDC bearer token identifying the owner (the verified subject).
    pub token: String,
}

impl ChannelRegisterRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_AGENT_CP_URL required (control-plane base URL)")?;
        let channel_hex = hex_encode(&req_hex32(&f, "CT_GRANT_CHANNEL", "64 hex channel id")?);
        // The channel authority: derive from the operator's own private key
        // (CT_CHANNEL_OPERATOR_KEY, from `channel operator-init`), or take the public key
        // directly (CT_CHANNEL_OPERATOR_PUBKEY) when only the pubkey is at hand.
        let operator_pubkey_hex = if let Some(pk) = opt_hex32(&f, "CT_CHANNEL_OPERATOR_PUBKEY") {
            hex_encode(&pk)
        } else if let Some(sk) = opt_hex32(&f, "CT_CHANNEL_OPERATOR_KEY") {
            OperatorIdentity { key: SigningKey::from_bytes(&sk) }.pubkey_hex()
        } else {
            return Err(
                "CT_CHANNEL_OPERATOR_KEY (64 hex operator private, from `channel operator-init`) \
                 or CT_CHANNEL_OPERATOR_PUBKEY (64 hex) required"
                    .to_string(),
            );
        };
        let token = f("CT_OIDC_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_OIDC_TOKEN required (OIDC bearer token for the channel owner)")?;
        Ok(Self { cp_url, channel_hex, operator_pubkey_hex, token })
    }
}

/// Configuration for `ct-agent channel allowlist add|remove|list` (#248-follow): the
/// owner-scoped self-service channel-allowlist CLI, so an operator can manage a
/// channel's e-mail allow-list without leaving the terminal for the portal web UI.
/// Shares its shape with [`ChannelRegisterRequest`] (same `CT_AGENT_CP_URL`/
/// `CT_GRANT_CHANNEL`/`CT_OIDC_TOKEN`), minus the operator pubkey — the allow-list
/// routes are owner-scoped by the bearer token alone, no operator key needed.
pub struct ChannelAllowlistRequest {
    /// Control-plane base URL (`{cp_url}/me/channels/:channel/allowlist`).
    pub cp_url: String,
    /// The channel id, canonical 64-hex.
    pub channel_hex: String,
    /// The OIDC bearer token identifying the owner (the verified subject).
    pub token: String,
}

impl ChannelAllowlistRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_AGENT_CP_URL required (control-plane base URL)")?;
        let channel_hex = hex_encode(&req_hex32(&f, "CT_GRANT_CHANNEL", "64 hex channel id")?);
        let token = f("CT_OIDC_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_OIDC_TOKEN required (OIDC bearer token for the channel owner)")?;
        Ok(Self { cp_url, channel_hex, token })
    }
}

/// The channel session's local application duplex (#135 L2.1-cli). **Pipe** mode (default) is the
/// CLI's stdin/stdout — the historical one-shot behaviour (stdin-EOF tears the session down).
/// **Serve** mode (`CT_CHANNEL_SERVE=1`) makes the channel a persistent request/response *service*:
/// the session side of an in-process duplex whose other half runs
/// [`serve_request_loop`](ct_common::a2a::serve_request_loop), so the peer can call it many times
/// over one Noise tunnel. A single enum keeps the two shapes one concrete type for the generic pump.
enum ChannelLocal {
    Pipe(tokio::io::Join<tokio::io::Stdin, tokio::io::Stdout>),
    Serve(tokio::io::DuplexStream),
}

impl AsyncRead for ChannelLocal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_read(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ChannelLocal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_write(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_flush(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_shutdown(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_shutdown(cx),
        }
    }
}

/// Serve-mode local (#135 L2.1-cli): spawn [`serve_request_loop`](ct_common::a2a::serve_request_loop)
/// with `handle` on one half of an in-process duplex and return the *session* half — the pump drives
/// it, so the peer's framed requests are answered by `handle` over the one persistent Noise tunnel.
fn serve_local<H, F>(handle: H) -> tokio::io::DuplexStream
where
    H: FnMut(Vec<u8>) -> F + Send + 'static,
    F: std::future::Future<Output = Vec<u8>> + Send,
{
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        let _ = ct_common::a2a::serve_request_loop(&mut send, &mut recv, handle).await;
    });
    session_side
}

/// Call-mode local (#135 L2.3, client side): spawn a one-shot MCP client on one half of an in-process
/// duplex — write ONE JSON-RPC request, print the peer's response body, then close — and return the
/// session half for the pump. So `ct-agent channel --call <method>` = connect, invoke a peer's tool
/// once, print the JSON-RPC reply, exit.
/// One MCP request/response over a duplex's split halves (#135 L2.3 client core): frame + write the
/// request, then read + return the peer's response body. Testable in isolation; `call_local` prints
/// what it returns.
async fn mcp_call_over<W, R>(
    send: &mut W,
    recv: &mut R,
    method: &str,
    params: serde_json::Value,
) -> io::Result<Vec<u8>>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let request = ct_common::mcp::encode_request(1, method, params);
    ct_common::a2a::write_message(send, &request).await?;
    ct_common::noise::read_frame(recv).await
}

/// Crew-bridge c2 atom (#171/#173): call a peer's `service/<slug>` tool over an already-established
/// channel duplex and return the service's `output` string. Frames the fixed
/// `service/<slug>({input}) -> {output}` shape (#149-A.1), reads the reply, and extracts
/// `result.output`. **Fails closed:** a transport error, a JSON-RPC `error` (the service
/// rejected/failed), or a reply missing `result.output` all return `Err` — never a bogus fragment.
/// The crew bridge calls this once per role (safety_check, physics, art) over each dialed channel
/// and feeds the returned JSON into [`ct_common::crew`].
pub async fn call_role_service<W, R>(
    send: &mut W,
    recv: &mut R,
    slug: &str,
    input: &str,
) -> io::Result<String>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let params = serde_json::json!({ "name": format!("service/{slug}"), "arguments": { "input": input } });
    let body = mcp_call_over(send, recv, "tools/call", params).await?;
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(err) = v.get("error") {
        return Err(io::Error::other(format!("service/{slug} returned an error: {err}")));
    }
    v.get("result")
        .and_then(|r| r.get("output"))
        .and_then(|o| o.as_str())
        .map(String::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("service/{slug} reply missing result.output")))
}

/// Crew-bridge c2 driver (#171/#173): given already-connected channel duplexes to the three role
/// agents, run the crew end to end and return the browser's `{safety, auction, config}` — the
/// orchestration the `/crew/build` server (c3) wraps.
///
/// Order + fail-closed semantics:
/// 1. **safety_check** runs FIRST over the safety agent's channel; its output is `{ok, reason}`. A
///    `false` verdict short-circuits to a **rejection** (no fragment calls, no build) — the
///    authoritative live guard.
/// 2. **physics** then **art** run over their agents' channels (`service/text_generation`), and the
///    fragments are assembled by [`ct_common::crew`].
///
/// A transport/parse failure at any step returns `Err(reason)` — the c3 HTTP layer maps that to a
/// 5xx so the **browser fails closed to its local stand-in**. A clean policy rejection is
/// `Ok(rejected)`; a clean build is `Ok(built)`. `auction` (who won each role) is supplied by the
/// caller — the bridge derives it from a real `match_offer`/`convene`; a demo may pass the fixed crew.
pub async fn crew_build_over<S, P, A>(
    prompt: &str,
    safety_conn: S,
    physics_conn: P,
    art_conn: A,
    auction: Vec<ct_common::crew::RoleAuction>,
) -> Result<ct_common::crew::CrewBuildResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // 1. safety_check — the authoritative live guard.
    let (mut sr, mut sw) = tokio::io::split(safety_conn);
    let safety_out = call_role_service(&mut sw, &mut sr, "safety_check", prompt)
        .await
        .map_err(|e| format!("safety_check service unreachable: {e}"))?;
    let verdict: serde_json::Value =
        serde_json::from_str(&safety_out).map_err(|e| format!("safety_check reply not JSON: {e}"))?;
    if verdict.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let reason = verdict.get("reason").and_then(|r| r.as_str()).unwrap_or("rejected by the safety agent");
        return Ok(ct_common::crew::CrewBuildResponse::rejected(reason.to_string()));
    }
    // 2. physics + art fragments — run CONCURRENTLY. They are independent (each only depends on
    //    safety_check having passed) and use separate channels, so their wall-clock is max(physics,
    //    art), not the sum. Measured (#173): each role's real `claude -p` is ~14s and the tunnel
    //    overhead is negligible, so sequential was safety+physics+art ≈ 40–55s; joining the two
    //    independent roles cuts it to ≈ safety + max(physics, art) ≈ ~28s.
    let physics = async {
        let (mut pr, mut pw) = tokio::io::split(physics_conn);
        call_role_service(&mut pw, &mut pr, "text_generation", prompt)
            .await
            .map_err(|e| format!("physics role unreachable: {e}"))
    };
    let art = async {
        let (mut ar, mut aw) = tokio::io::split(art_conn);
        call_role_service(&mut aw, &mut ar, "text_generation", prompt)
            .await
            .map_err(|e| format!("art role unreachable: {e}"))
    };
    let (physics_json, art_json) = tokio::join!(physics, art);
    let (physics_json, art_json) = (physics_json?, art_json?);
    // 3. assemble the real config from the fragments (fail-closed on a malformed fragment).
    let cfg = ct_common::crew::CrewConfig::from_fragment_json(&physics_json, &art_json)
        .map_err(|e| format!("crew fragments malformed: {e}"))?;
    Ok(ct_common::crew::CrewBuildResponse::built(cfg, auction))
}

fn call_local(method: String, params: serde_json::Value) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        match mcp_call_over(&mut send, &mut recv, &method, params).await {
            Ok(response) => println!("{}", String::from_utf8_lossy(&response)),
            // #211: a failed one-shot call (e.g. `write_message` rejecting an oversized request past
            // MAX_MESSAGE_BYTES) must exit NON-ZERO, not exit-0-with-empty-stdout — otherwise the
            // caller can't tell "the call failed" from "the call produced nothing", and a size
            // rejection surfaces downstream as a cryptic empty-output/JSON-parse failure. stderr is
            // unbuffered, so the message is out before we exit.
            Err(e) => {
                eprintln!("ct-agent channel --call: no response ({e})");
                std::process::exit(1);
            }
        }
        // Dropping serve_side EOFs the session side → the channel session ends → the process exits.
    });
    session_side
}

/// Invoke the peer's `service/<slug>` tool with `input` over the channel's `local` duplex and return
/// the **bare** service output (`result.output`) — reusing the tested [`call_role_service`]. Unlike
/// [`call_local`]'s raw-method mode (which prints the whole JSON-RPC envelope for a caller-supplied
/// method + static params), this is the crew-native contract: one `service/<slug>` call, plain
/// output. Split out so it can be frozen-tested against an in-process serve peer.
async fn run_service_call<S>(local: S, slug: &str, input: &str) -> std::io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut recv, mut send) = tokio::io::split(local);
    let result = call_role_service(&mut send, &mut recv, slug, input).await;
    // #248: a one-shot call used to drop `local` (tearing the whole session down) the
    // INSTANT the reply arrived -- structurally too fast for any concurrent relay->direct
    // upgrade (#104's in-band candidate exchange, or the relay-gate DCUtR hole-punch,
    // both of which need real network round-trips: address exchange, then a simultaneous
    // connect attempt) to ever land, even when the upgrade is actively in flight and
    // would otherwise have succeeded. Live-reproduced: dozens of real relay-gate DCUtR
    // sessions, admission+circuit genuinely established, none ever showed a completed
    // hole-punch -- every one raced the reply against a sub-200ms teardown and lost.
    // Give a real upgrade attempt a fair window before tearing down, but ONLY when one
    // could plausibly be in flight (either upgrade mechanism configured) -- unconditional
    // added latency on every call would be a real regression for latency-sensitive
    // production use (the crew bridge also drives this same one-shot path).
    if result.is_ok() {
        let upgrade_configured = std::env::var_os("CT_CHANNEL_RELAY_GATE").is_some()
            || std::env::var_os("CT_CHANNEL_CIRCUIT_RELAY").is_some()
            || std::env::var_os("CT_CHANNEL_DIRECT_UPGRADE").is_some();
        if upgrade_configured {
            // #248: 2s (the original fb5a799 value, tuned against local-loopback tests where a
            // hole-punch is near-instant) turned out too short for a REAL cross-NAT relay-gate
            // DCUtR attempt over genuine WAN paths -- live-reproduced on the bob-1<->bob-2
            // pairing after aad49fb finally got both sides' real reflexive addresses into
            // DCUtR's candidate pool: the swarm logged `Dialing` toward the peer's real address,
            // then the one-shot process exited (reply already received over the relay leg,
            // concurrently) before any `ConnectionEstablished`/`OutgoingConnectionError` for that
            // dial appeared, even with CT_DEBUG_A2A_TIMING on. A real hole-punch involves actual
            // network round-trips over the internet (address exchange, then a simultaneous
            // connect attempt, possibly retried) -- meaningfully slower than anything on
            // loopback. This is still a blind fixed sleep, not "wait for the actual upgrade
            // outcome" -- a real fix would have the channel session signal completion
            // (success/failure/timeout) instead of guessing a window, which remains open.
            const UPGRADE_GRACE: std::time::Duration = std::time::Duration::from_secs(6);
            tokio::time::sleep(UPGRADE_GRACE).await;
        }
    }
    result
}

/// #19: the initiator-side PERSISTENT service-call driver — the calling-side counterpart of the
/// accept side's `--serve` (#200). ONE channel session is established and then held for the
/// process's whole life; each line arriving on `lines` becomes one `service/<slug>` call over that
/// same session, answered as one NDJSON envelope line on `out`:
///
/// - success: `{"ok":true,"output":"<bare service output>"}`
/// - failure: `{"ok":false,"error":"<message>"}` — written BEFORE the `Err` return, so the
///   supervising caller always gets a structured last line to attribute, then sees the non-zero
///   exit and can re-spawn + retry the in-flight request.
///
/// Why this exists (measured, 2026-08-13): a caller making many calls to the same peer (the sort
/// arena bridge: ~1 call/second for ~95 rounds) previously paid a full join+pair+Noise handshake
/// per call via the one-shot `--call-service` — and rolled the accept side's re-park gap every
/// time, a structural 15-22% per-round transport-fault rate (#18). Holding the session makes it
/// ONE pairing per run: the gap is practically never rolled, and the per-round handshake overhead
/// disappears. The envelope (rather than raw output lines) is what keeps the stream parseable:
/// service outputs may legitimately contain anything, including newlines, so raw framing cannot
/// delimit responses — JSON-string escaping can.
///
/// The line source is an injected channel (not `stdin` directly) so the loop is testable without a
/// real process; production feeds it from a dedicated stdin-reader thread
/// ([`call_service_persistent_local`]). Returns `Ok(())` on source EOF (clean end-of-run teardown:
/// the caller closed stdin), `Err` after the first failed call — a persistent session that broke
/// mid-run is NOT silently re-dialed in-process: the process-supervision model (the bridge spawns
/// one process per RUN and can retry a round) stays the recovery layer, exactly as before, just at
/// run granularity instead of round granularity.
async fn run_service_calls_persistent<S, W>(
    local: S,
    slug: &str,
    lines: &mut tokio::sync::mpsc::Receiver<String>,
    out: &mut W,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let (mut recv, mut send) = tokio::io::split(local);
    while let Some(line) = lines.recv().await {
        let input = line.trim();
        if input.is_empty() {
            continue; // a blank line is a keep-alive/no-op, not a call
        }
        match call_role_service(&mut send, &mut recv, slug, input).await {
            Ok(output) => {
                let envelope = serde_json::json!({ "ok": true, "output": output });
                out.write_all(format!("{envelope}\n").as_bytes()).await?;
                out.flush().await?;
            }
            Err(e) => {
                let envelope = serde_json::json!({ "ok": false, "error": e.to_string() });
                let _ = out.write_all(format!("{envelope}\n").as_bytes()).await;
                let _ = out.flush().await;
                return Err(std::io::Error::other(format!(
                    "persistent service call failed mid-run: {e}"
                )));
            }
        }
    }
    Ok(()) // stdin EOF -> drop the halves -> the session ends cleanly
}

/// #19 production glue for [`run_service_calls_persistent`]: bridge the real process stdin into
/// the injected line channel via a dedicated blocking reader thread (tokio's async stdin is a
/// thread pool anyway, and a plain `BufRead::lines` thread is the simplest EOF-correct feed), run
/// the persistent loop against real stdout, and translate its outcome into the process contract:
/// clean source EOF ends the session (normal exit through the session driver), a mid-run call
/// failure exits non-zero AFTER the structured error envelope is out (same #211 fail-closed
/// discipline as the one-shot mode).
fn call_service_persistent_local(slug: String) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.blocking_send(l).is_err() {
                        break; // consumer gone (session over) -- stop reading
                    }
                }
                Err(_) => break,
            }
        }
        // Thread end drops `tx` -> the loop sees source EOF -> clean teardown.
    });
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        if let Err(e) = run_service_calls_persistent(serve_side, &slug, &mut rx, &mut stdout).await {
            eprintln!("ct-agent channel --call-service {slug} (persistent): {e}");
            std::process::exit(1);
        }
        // Ok: serve_side was moved+dropped -> session EOF -> the process exits through the
        // normal session teardown (drain + exit 0), same as the one-shot mode's happy path.
    });
    session_side
}

/// The initiator-side one-shot **service** call (#173 distributed crew topology): dial done by the
/// channel session, this drives the local side — call the peer's `service/<slug>` with `input`, print
/// the bare service output, then EOF the session so the process exits. This is exactly the
/// stdin→stdout contract the crew bridge's `CREW_*_CMD` expects, so `CREW_PHYSICS_CMD="ct-agent
/// channel"` (with `CT_CHANNEL_CALL_SERVICE=text_generation` + the source-2 channel-join env) dials
/// source-2 over the real Agent-Fabric tunnel and yields its fragment JSON — no jq/wrapper needed.
fn call_service_local(slug: String, input: String) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        match run_service_call(serve_side, &slug, &input).await {
            Ok(output) => println!("{output}"),
            // #211: fail closed AND exit NON-ZERO. Previously this only `eprintln!`'d and let the
            // process exit 0 with empty stdout — indistinguishable from "the role produced no output"
            // (the empty-stdout bugs #206/a3412fc). An oversized `input` is correctly rejected by
            // `write_message` (MAX_MESSAGE_BYTES, u16 wire ceiling) as an `Err` that propagates up
            // here; turning it into a non-zero exit lets the bridge surface the clear "message too
            // large" stderr instead of a cryptic downstream JSON-parse failure. stderr is unbuffered.
            Err(e) => {
                eprintln!("ct-agent channel --call-service {slug}: {e}");
                std::process::exit(1);
            }
        }
        // Dropping serve_side (moved into run_service_call) EOFs the session → the session ends.
    });
    session_side
}

/// Parse a `CT_AGENT_SERVICES` entry (the same slugs `ct_common::mcp`'s `service/<slug>` tool
/// names use) into a [`ct_common::channel::ServiceType`]. The four fixed slugs above map to their
/// matching built-in variant; anything else becomes `ServiceType::Custom(s)` (#382 follow-up:
/// CADS-Tunnel core generalized `RequiredRole`/`convene()` beyond a closed service catalog, so a
/// pipeline designer can declare e.g. `static_analysis`/`android_instrumented_test` without a
/// CADS-Tunnel core release per new pipeline-stage type) — never silently dropped anymore. An
/// empty string still parses to nothing useful downstream but isn't specially rejected here; the
/// caller's own offer/catalog matching is still the real gate on what actually gets served.
fn parse_service_type(s: &str) -> Option<ct_common::channel::ServiceType> {
    use ct_common::channel::ServiceType::*;
    if s.is_empty() {
        // e.g. a stray double-comma in CT_AGENT_SERVICES -- still filtered out, same as before
        // Custom existed (an empty custom-service name is never a meaningful declaration).
        return None;
    }
    Some(match s {
        "code_generation" => CodeGeneration,
        "security_review" => SecurityReview,
        "safety_check" => SafetyCheck,
        "text_generation" => TextGeneration,
        other => Custom(other.to_string()),
    })
}

/// Bound how long a `CT_AGENT_SERVICE_HANDLER_CMD` child may run before it's killed (#149-A.1
/// serve-wiring: every other blocking step in this file is timed — `A2A_HANDSHAKE_TIMEOUT`,
/// `DIRECT_STREAM_SETUP_TIMEOUT`, `*_DRAIN_TIMEOUT` — this was the one unbounded exception, flagged
/// in review). Generous: a real LLM-backed handler can legitimately take tens of seconds.
const SERVICE_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Run the configured `CT_AGENT_SERVICE_HANDLER_CMD` for one `service/<slug>` call (#149-A.1
/// serve-wiring follow): spawn it via `sh -c`, write `input` to its stdin, and return its trimmed
/// stdout as the result. `CT_SERVICE_TYPE` is set in the child's environment so one handler script
/// can branch on which of several registered services was actually invoked. A non-zero exit, a
/// spawn/IO failure, or exceeding `timeout` becomes the tool error (surfaced to the caller as a
/// JSON-RPC error, never a panic). `timeout` is a parameter (the real call site below always passes
/// [`SERVICE_HANDLER_TIMEOUT`]) so the kill-on-timeout path is unit-testable without an actual
/// 120-second wait.
///
/// Two fixes from review, both real (caught reading `#149`'s wiring, not hypothetical):
/// - **stdin is written on its own thread**, concurrently with the wait/output-read below — writing
///   it inline, then calling `wait_with_output()`, is the textbook `std::process` pipe deadlock: an
///   `input` over the OS pipe buffer (~64 KiB) whose handler writes to stdout *before* finishing its
///   stdin read blocks both sides forever, and a consumer fully controls `input`'s size (`register_service_tools`
///   reads `args["input"]` with no cap) — a remote DoS on the provider, not just a footgun.
/// - **the child is bounded by `timeout` and killed if it's exceeded**, closing the one unbounded
///   blocking step in this file.
fn run_service_handler_with_timeout(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    // Reuse ct_common's own slug derivation (now `pub`, #382 follow-up) rather than a second,
    // driftable copy of this match here -- this is the SAME name the `service/<slug>` MCP tool
    // this call is answering was registered under, including the Custom(name) case.
    let slug = ct_common::mcp::service_slug(&service);
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("CT_SERVICE_TYPE", slug.as_ref())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // #183: put the child in its OWN process group (pgid == its pid) on Unix so the timeout
    // kill below can signal the WHOLE subtree, not just the immediate `sh -c`. The handler
    // scripts shell out to a real LLM CLI as a GRANDCHILD; killing only the `sh` pid leaves an
    // orphaned (costed, running) LLM subprocess whenever the script pipes/backgrounds,
    // defeating SERVICE_HANDLER_TIMEOUT. `std::process::Command` has no process-group concept
    // on Windows, so the timeout kill there (below) only ever reaches the immediate child --
    // a narrower, documented guarantee than Unix's whole-group kill.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| format!("service handler spawn failed: {e}"))?;
    let pid = child.id();

    // Write stdin on its own thread so it can proceed concurrently with the wait/output-read
    // below (the deadlock fix). Best-effort: a handler that never reads stdin (or exits before
    // fully consuming it) makes this fail with a broken-pipe error, which we deliberately ignore
    // here — the child's own exit status/output is the actual verdict, not whether every stdin
    // byte landed.
    let mut stdin = child.stdin.take().ok_or("service handler: no stdin pipe")?;
    let input_owned = input.to_string();
    let _stdin_writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });

    // Run wait_with_output() (which itself reads stdout/stderr concurrently on its own threads —
    // std's own implementation, not reproduced here) on a background thread so this call can be
    // bounded: recv_timeout enforces SERVICE_HANDLER_TIMEOUT, and on timeout we kill the child by
    // pid (captured above, before ownership moved into the thread) so the still-running background
    // wait unblocks on its own rather than leaking a wedged process.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| format!("service handler wait failed: {e}"))?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // #183: kill the whole process GROUP so a grandchild (the LLM CLI) can't survive the
            // timeout as an orphan. `process_group(0)` above made pgid == pid, and a NEGATIVE pid to
            // kill(2) signals every process in that group. Done via libc, not `Command::new("kill")`:
            // minimal images ship no `kill` binary, so the old spawn silently no-op'd there.
            #[cfg(unix)]
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
            // Windows: no raw kill-by-pid in std and no process-group equivalent (see the
            // process_group comment above) -- shell out to the always-present taskkill,
            // which only reaches the immediate child, not any grandchild the handler
            // script spawned.
            #[cfg(not(unix))]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .status();
            }
            return Err(format!(
                "service handler timed out after {}s (pid {pid} killed)",
                timeout.as_secs()
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("service handler: wait thread disconnected unexpectedly".to_string())
        }
    };
    if !output.status.success() {
        return Err(format!(
            "service handler exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        // #206: every shipped handler script unconditionally prints either its real result or a
        // fallback on every code path — an exit-0-with-empty-stdout result is never a legitimate
        // success, only a process torn down externally (e.g. OOM) between spawn and its final print,
        // after this function's own timeout-kill path (which returns Err before reaching here). Left
        // untreated, the empty string flows on as a "successful" fragment and produces a cryptic
        // downstream `serde_json` "EOF while parsing a value" instead of an honest, attributable error.
        return Err(format!(
            "service handler exited {} but produced no output (killed mid-run?)",
            output.status
        ));
    }
    Ok(stdout)
}

/// [`run_service_handler_with_timeout`] bound to the real [`SERVICE_HANDLER_TIMEOUT`] — the seam
/// every non-test call site uses.
fn run_service_handler(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
) -> Result<String, String> {
    run_service_handler_with_timeout(cmd, service, input, SERVICE_HANDLER_TIMEOUT)
}

/// Build the channel session's local app duplex from the environment (#135 L2.x). `CT_CHANNEL_CALL=<method>`
/// → one-shot MCP **client** (invoke a peer's tool, print the reply, exit). `CT_CHANNEL_SERVE=1` → the
/// persistent MCP **service** (JSON-RPC `tools/list`/`tools/call` via the tool registry). Neither → the
/// historical stdin/stdout pipe.
fn channel_local() -> ChannelLocal {
    // #173 distributed crew: one-shot `service/<slug>` client. Reads the prompt on stdin, calls the
    // peer's service, prints the BARE output — the crew-bridge `CREW_*_CMD` contract. Checked before
    // the raw CT_CHANNEL_CALL below because it's the service-specific (and jq-free) path.
    if let Ok(slug) = std::env::var("CT_CHANNEL_CALL_SERVICE") {
        let slug = slug.trim().to_string();
        // #19: persistent call mode -- hold ONE session and multiplex line-framed calls over it
        // until stdin EOF, instead of one pairing per call. Checked before the one-shot path so
        // the flag simply upgrades an existing CT_CHANNEL_CALL_SERVICE deployment. Deliberately
        // NOT combined with the DCUtR retry modes yet (their per-attempt channel_local() re-entry
        // would contend for the single stdin feed -- the same class of trap #248 documents below);
        // the arena/front-door path this exists for calls channel_local() exactly once.
        let persistent = std::env::var("CT_CHANNEL_CALL_PERSISTENT")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if persistent {
            eprintln!(
                "ct-agent channel: --call-service {slug} (persistent: one held session, NDJSON calls over stdio until EOF, #19)"
            );
            return ChannelLocal::Serve(call_service_persistent_local(slug));
        }
        // #248: cache the stdin read -- this function is called fresh on every
        // relay-gate/circuit-relay DCUtR retry attempt (each attempt needs its own owned
        // ChannelLocal), and stdin is only readable to EOF once. A naive re-read on retry
        // doesn't error, it silently returns empty ("" is a valid, if useless, read) --
        // the real message only ever reached the FIRST attempt; every retry silently sent
        // nothing, which the peer can reasonably react to by closing early. Live-reproduced
        // on bob2's retried rounds: no input-related error anywhere, just an unexplained
        // "early eof" a step later than expected.
        static INPUT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let input = INPUT
            .get_or_init(|| {
                let mut input = String::new();
                use std::io::Read;
                let _ = std::io::stdin().read_to_string(&mut input);
                input.trim().to_string()
            })
            .clone();
        eprintln!("ct-agent channel: --call-service {slug} (one service call over the channel, then exit)");
        return ChannelLocal::Serve(call_service_local(slug, input));
    }
    // #135 L2.3 client: one MCP request/response over the channel, then exit.
    if let Ok(method) = std::env::var("CT_CHANNEL_CALL") {
        let method = method.trim().to_string();
        let params = std::env::var("CT_CHANNEL_CALL_PARAMS")
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .unwrap_or(serde_json::Value::Null);
        eprintln!("ct-agent channel: --call {method} (one MCP request over the channel, then exit)");
        return ChannelLocal::Serve(call_local(method, params));
    }
    let serve = std::env::var("CT_CHANNEL_SERVE")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    if serve {
        // #135 L2.3: each framed request body is a JSON-RPC 2.0 message dispatched against the agent's
        // MCP tool registry; the response body is the JSON-RPC reply. Arc so the registry is shared
        // across the persistent session's calls. #144×#135: if the agent has AgentCard config
        // (CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_*), also expose `agent/card` — its signed identity
        // over the authenticated channel; otherwise just the default `ping` tool.
        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
        let mut reg = match AgentCardCliConfig::from_env() {
            Ok(cfg) => {
                let card_json = serde_json::to_value(cfg.build_card(now_secs()))
                    .unwrap_or(serde_json::Value::Null);
                eprintln!("ct-agent channel: --serve mode (MCP-over-channel; tools: ping, agent/card)");
                ct_common::mcp::registry_with_card(card_json)
            }
            Err(_) => {
                eprintln!(
                    "ct-agent channel: --serve mode (MCP-over-channel; tool: ping — set CT_AGENT_CARD_* to also expose agent/card)"
                );
                ct_common::mcp::default_registry()
            }
        };
        // #152: if an offer is configured (CT_AGENT_OFFER_*), also expose the #147 auction tools
        // (`auction/offer` + `auction/bid`) over the same authenticated channel — the CLI parity that
        // lets the marketplace be demoed live the way `agent/card` is. The seller stamps time itself
        // (`now_secs`), never the caller.
        // #152/#167: build the offer config ONCE — the signed offer drives both the auction tools
        // and the ceiling on which `service/<slug>` tools may be registered, so the two can't drift.
        let offer_cfg = AgentOfferCliConfig::from_env().ok();
        if let Some(cfg) = &offer_cfg {
            let offer = cfg.build_offer(now_secs());
            ct_common::mcp::register_auction_tools(
                &mut reg,
                offer,
                now_secs,
                cfg.max_bids_per_window,
                cfg.window_secs,
            );
            eprintln!(
                "ct-agent channel: --serve also exposing auction/offer + auction/bid (CT_AGENT_OFFER_*)"
            );
        }
        // #149-A.1 serve-wiring + #167 declared-vs-served: expose one schema-typed `service/<slug>`
        // tool per service, backed by shelling out to `CT_AGENT_SERVICE_HANDLER_CMD` (`input` on
        // stdin, trimmed stdout is the result, `CT_SERVICE_TYPE` names the slug; runs synchronously —
        // fine for a low-concurrency demo, a multi-tenant host would want `spawn_blocking`).
        //
        // #167: the signed offer's **declared** service catalog is the ceiling. A service is
        // registered only if the offer declares it, so what a buyer can cryptographically verify the
        // agent offers is exactly what it will serve. `CT_AGENT_SERVICES`, when set, is an explicit
        // override *filtered to* the declared catalog (undeclared entries are refused loudly, never
        // registered); when unset with an offer, the declared catalog itself is the list (one knob).
        // With no offer configured there is no cryptographic ceiling and `CT_AGENT_SERVICES` stands
        // alone — the unchanged self-asserted regime.
        if let Ok(handler_cmd) = std::env::var("CT_AGENT_SERVICE_HANDLER_CMD") {
            let requested: Vec<ct_common::channel::ServiceType> = match std::env::var("CT_AGENT_SERVICES") {
                Ok(s) => s.split(',').filter_map(|t| parse_service_type(t.trim())).collect(),
                Err(_) => offer_cfg.as_ref().map(|c| c.services.clone()).unwrap_or_default(),
            };
            let services: Vec<ct_common::channel::ServiceType> = match &offer_cfg {
                Some(cfg) => {
                    let (allowed, refused): (Vec<_>, Vec<_>) =
                        requested.into_iter().partition(|s| cfg.services.contains(s));
                    if !refused.is_empty() {
                        eprintln!(
                            "ct-agent channel: REFUSING {} service tool(s) not in the signed offer's declared catalog (#167): {:?}",
                            refused.len(),
                            refused
                        );
                    }
                    allowed
                }
                None => requested,
            };
            if !services.is_empty() {
                let n = services.len();
                ct_common::mcp::register_service_tools(&mut reg, &services, move |service, input| {
                    run_service_handler(&handler_cmd, service, input)
                });
                eprintln!(
                    "ct-agent channel: --serve also exposing {n} service tool(s) via CT_AGENT_SERVICE_HANDLER_CMD"
                );
            }
        }
        let registry = std::sync::Arc::new(reg);
        ChannelLocal::Serve(serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            // #248-follow: `ToolRegistry::dispatch` is synchronous, and when a
            // `CT_AGENT_SERVICE_HANDLER_CMD` service tool is registered it can block this
            // call for real wall-clock time (`run_service_handler`'s
            // `std::process::Command::wait`, up to `SERVICE_HANDLER_TIMEOUT`). Calling it
            // inline inside this async block used to block whichever Tokio worker thread
            // was running this connection's task for that whole duration -- starving the
            // SAME connection's own read/write pump (no bytes flow while the handler runs)
            // and, on a runtime with few worker threads (this host: 2 CPUs), starving
            // *other* connections' admission/keepalive handling too. Live-reproduced: a
            // registered service handler -- even a near-instant one -- made the responder's
            // reply never reach the initiator (seen as a clean, fast "early eof"), and under
            // slightly different timing a completely unrelated fresh channel's own admission
            // exchange stalled for the full #140 window while this one was blocked. Moving
            // the actual dispatch onto Tokio's dedicated blocking-thread pool fixes both:
            // the async worker stays free to keep pumping bytes and servicing other
            // connections while the handler subprocess runs.
            async move {
                tokio::task::spawn_blocking(move || registry.dispatch(&req))
                    .await
                    .unwrap_or_default()
            }
        }))
    } else {
        ChannelLocal::Pipe(tokio::io::join(tokio::io::stdin(), tokio::io::stdout()))
    }
}

/// #276: dial the edge relay leg, preferring a genuinely direct connection over a configured
/// fallback (e.g. a same-network super-peer relay) whenever one is available and reachable —
/// "always look for direct communication; relay is only the last line of defense," per
/// explicit design guidance for the super-peer mechanism. Tries `direct` first, bounded by
/// `timeout` so an unreachable direct address can't stall the whole join indefinitely; on any
/// failure (connect error or timeout) falls through to `fallback`. When `direct` is `None` —
/// the common case, a member with no direct edge reachability of its own, which is PRECISELY
/// why it configured a super-peer fallback in the first place — dials `fallback` immediately
/// with no extra latency, unaffected by this preference.
async fn dial_relay_preferring_direct(
    direct: Option<SocketAddr>,
    fallback: SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, BoxError> {
    if let Some(direct_addr) = direct {
        let attempt = async {
            crate::transport::build_channel_dialer()?.connect(direct_addr, "localhost")?.await.map_err(BoxError::from)
        };
        match tokio::time::timeout(timeout, attempt).await {
            Ok(Ok(conn)) => {
                eprintln!("ct-agent channel: dialed direct edge {direct_addr} (#276, preferred over the configured relay fallback)");
                return Ok(conn);
            }
            Ok(Err(e)) => {
                eprintln!("ct-agent channel: direct edge dial to {direct_addr} failed ({e}), falling back to {fallback} (#276)")
            }
            Err(_) => eprintln!(
                "ct-agent channel: direct edge dial to {direct_addr} timed out after {timeout:?}, falling back to {fallback} (#276)"
            ),
        }
    }
    crate::transport::build_channel_dialer()?.connect(fallback, "localhost")?.await.map_err(BoxError::from)
}

/// #248: what a relay-gate/circuit-relay DCUtR join loop should do after one attempt,
/// given whether it succeeded, whether this member is a persistent `--serve`, and the
/// one-shot retry budget already spent. Pure decision core, extracted from the two live
/// loops (relay-gate, circuit-relay) below so it's unit-testable without a real network.
///
/// Found live via bob-2's own crash-log capture: a persistent `--serve` member that
/// COMPLETES a session -- even one whose DCUtR upgrade attempt failed with
/// `AttemptsExceeded` and fell back to relay, which is still `Ok(())` ("hole-punch failure
/// stays on the relay" is this whole mechanism's own design) -- must loop back to admit the
/// NEXT peer, not stop. Before this fix both live loops only special-cased `Err` for
/// `serve_loop`; `Ok(())` fell through to an unconditional `return`, silently ending the
/// whole process after exactly one session. Reproduced 2/2 by bob-2's supervisor: always
/// exactly 3 DCUtR `OutgoingConnectionError`s (a genuine, correctly-handled hole-punch
/// failure), then a clean `exit(0)` with no error logged anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DcutrLoopAction {
    /// This peer's session is over (successfully or not) and this is a persistent serve
    /// member: sleep, reset the one-shot retry counter to 0, and admit the next peer.
    RetryReset,
    /// An error, and a one-shot caller's own bounded retry budget still has room: sleep,
    /// bump the counter to `next_attempt`, and try again.
    RetryBounded { next_attempt: u32 },
    /// Stop the loop; return the original result to the caller (a one-shot caller out of
    /// retries, or a non-`serve_loop` result of either kind).
    Stop,
}

fn dcutr_loop_action(ok: bool, serve_loop: bool, attempt: u32, max_one_shot_retries: u32) -> DcutrLoopAction {
    if serve_loop {
        return DcutrLoopAction::RetryReset;
    }
    if !ok && attempt < max_one_shot_retries {
        return DcutrLoopAction::RetryBounded { next_attempt: attempt + 1 };
    }
    DcutrLoopAction::Stop
}

/// Run the plane-brokered `ct-agent channel` flow (#98 / #103): connect to the edge
/// rendezvous + relay, present the grant, and pipe **stdin/stdout** over the A2A tunnel
/// with automatic direct-then-relay recovery via [`run_channel_join`]. The broker
/// relays the peer's Noise key, so no `CT_CHANNEL_PEER_*` is needed.
pub async fn run_channel_join_command(cfg: ChannelJoinCliConfig) -> Result<(), BoxError> {
    // Capture what the broker/relay ladders need before `cfg.grant` is moved into
    // `request` (a partial move would forbid the `cfg.broker_ladder()` `&self` call).
    let broker_ladder = cfg.broker_ladder();
    let relay_ladder = cfg.relay_ladder();
    let front_door_cert = cfg.front_door_cert.clone();
    // #121: a relay-only member advertises the sentinel instead of a dialable address — it
    // can't be reached directly, so it participates purely via the relay + `:443` fallback.
    let request = ChannelJoinRequest {
        // #179: clone (not move) the grant so `cfg` stays whole for the multi-session serve loop
        // below, which re-runs admission for each successive peer.
        grant: cfg.grant.clone(),
        endpoint: if cfg.relay_only {
            ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string()
        } else {
            cfg.advertise_addr.to_string()
        },
    };
    // #136 N-wire: a relay-only (NAT-to-NAT) member with a libp2p circuit relay configured runs
    // the DCUtR-upgradable relay join — start on the edge relay, then opportunistically hole-punch
    // to a direct link via the circuit relay. Both members are NAT'd, so this is the only path that
    // can ever go direct; without a circuit relay it falls through to the plain relay session below.
    //
    // #248-follow: a long-lived `Accept`+`--serve` member on this path must retry a transient
    // stall exactly like the plain broker path a few lines below already does (see that path's
    // own comment for the #179 lesson this mirrors) -- NOT propagate the error out of this
    // function and take the whole process down. Live-reproduced: this path's first-ever real
    // cross-NAT test hit a transient "#140" stall (nothing DCUtR-specific -- the same admission
    // hiccup the plain path tolerates fine) and, before this fix, that killed an otherwise
    // perfectly healthy long-lived --serve process instead of just re-admitting. `Initiate`
    // (and `Accept` without `--serve`) stay single-attempt, matching every other one-shot path.
    let serve_loop = should_serve_loop(cfg.role, std::env::var("CT_CHANNEL_SERVE").ok().as_deref());
    // #248: a one-shot Initiate (or non-serve Accept) on the relay-gate/circuit-relay DCUtR
    // path shouldn't fail on the very first #140 stall either -- live-reproduced on the
    // a2a-demo's plain "bob" scenario (previously thought stable, now exercising this same
    // path): the persistent --serve side eventually gets past a stall by retrying forever,
    // while the one-shot side had zero tolerance and failed the whole call on one hiccup.
    // Bounded (unlike `serve_loop`'s retry) because a one-shot CLI/demo call must still
    // terminate in reasonable time -- a few attempts at the same 200ms backoff, not forever.
    const ONE_SHOT_DCUTR_ADMISSION_RETRIES: u32 = 2;
    if cfg.relay_only {
        // The real gated relay-gate leg (no new public port, grant+possession pre-auth) takes
        // priority when configured — `circuit_relay` (a directly-dialable relay multiaddr) is
        // kept for the nat-lab test rig, not the deployed path.
        if let Some(relay_gate_addr) = cfg.relay_gate_addr {
            let relay_gate_cert = cfg
                .relay_gate_cert
                .clone()
                .ok_or("CT_CHANNEL_RELAY_GATE set without CT_CHANNEL_RELAY_GATE_CERT")?;
            eprintln!(
                "ct-agent channel: relay-only DCUtR-upgradable {:?} via relay-gate (relay {}, gate {}){}",
                cfg.role, cfg.relay_addr, relay_gate_addr,
                if serve_loop { " — persistent serve: retries transient stalls (#248)" } else { "" }
            );
            let mut attempt: u32 = 0;
            loop {
                let relay_conn =
                    dial_relay_preferring_direct(cfg.relay_addr_direct, cfg.relay_addr, DIRECT_DIAL_TIMEOUT).await?;
                let local = channel_local();
                let result = join_via_relay_gate_dcutr(
                    &relay_conn,
                    &request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    relay_gate_addr,
                    relay_gate_cert.clone(),
                    &cfg.grant,
                )
                .await;
                match dcutr_loop_action(result.is_ok(), serve_loop, attempt, ONE_SHOT_DCUTR_ADMISSION_RETRIES) {
                    DcutrLoopAction::RetryReset => {
                        if let Err(e) = &result {
                            eprintln!("ct-agent channel: relay-gate admission error, re-admitting (#248): {e}");
                        }
                        attempt = 0;
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    DcutrLoopAction::RetryBounded { next_attempt } => {
                        attempt = next_attempt;
                        if let Err(e) = &result {
                            eprintln!(
                                "ct-agent channel: relay-gate admission error, retrying ({attempt}/{ONE_SHOT_DCUTR_ADMISSION_RETRIES}) (#248): {e}"
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    DcutrLoopAction::Stop => return result,
                }
            }
        }
        if let Some(circuit) = cfg.circuit_relay.clone() {
            eprintln!(
                "ct-agent channel: relay-only DCUtR-upgradable {:?} (relay {}, circuit {}){}",
                cfg.role, cfg.relay_addr, circuit,
                if serve_loop { " — persistent serve: retries transient stalls (#248)" } else { "" }
            );
            let mut attempt: u32 = 0;
            loop {
                let relay_conn = crate::transport::build_channel_dialer()?
                    .connect(cfg.relay_addr, "localhost")?
                    .await?;
                let local = channel_local();
                let result = join_via_relay_dcutr(
                    &relay_conn,
                    &request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    circuit.clone(),
                )
                .await;
                match dcutr_loop_action(result.is_ok(), serve_loop, attempt, ONE_SHOT_DCUTR_ADMISSION_RETRIES) {
                    DcutrLoopAction::RetryReset => {
                        if let Err(e) = &result {
                            eprintln!("ct-agent channel: relay-gate admission error, re-admitting (#248): {e}");
                        }
                        attempt = 0;
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    DcutrLoopAction::RetryBounded { next_attempt } => {
                        attempt = next_attempt;
                        if let Err(e) = &result {
                            eprintln!(
                                "ct-agent channel: relay-gate admission error, retrying ({attempt}/{ONE_SHOT_DCUTR_ADMISSION_RETRIES}) (#248): {e}"
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    DcutrLoopAction::Stop => return result,
                }
            }
        }
    }
    // Broker admission (the grant + possession proof are the auth; Noise_IK authenticates
    // the peer end-to-end). With a `:443` front-door cert configured, walk the broker
    // ladder — direct QUIC first, then the `:443` TLS-TCP front door — so a network that
    // blocks the channel port still reaches the broker (#106 client-dial-wire). Otherwise
    // the direct-QUIC broker join, unchanged. Borrow the cert so it survives for the relay
    // leg's ladder below.
    // #179: an accept-side SERVE member must stay parked across MANY sequential peer sessions —
    // admit one, serve it, loop back to admit the next — instead of exiting after the first. Exiting
    // forced every operator (central, sink, source-2, …) into an external restart loop whose ~0.2s
    // re-park gap dropped real user calls ("art role unreachable" on first try, ok on retry). A
    // transient per-session error (admission stall #140, peer drop) is logged and retried, not fatal;
    // one-shot roles (initiator / `--call` / non-serve) run exactly once, unchanged.
    // (`serve_loop` already computed above, ahead of the relay-gate/circuit-relay block, which
    // needs the same value.)
    eprintln!(
        "ct-agent channel: plane-brokered {:?} (relay {}){}",
        cfg.role,
        cfg.relay_addr,
        if serve_loop { " — persistent serve: concurrent sessions (#200)" } else { "" }
    );
    if !serve_loop {
        // One-shot roles (initiator / `--call` / a non-serve accept): exactly one session, unchanged.
        return run_one_admission_session(&cfg, &request, &broker_ladder, &relay_ladder, &front_door_cert).await;
    }
    // #200: persistent serve is now CONCURRENT. The #179 loop admitted a peer, served it to
    // completion, and only THEN re-admitted the next — so two users clicking Build within the same
    // window collided: whoever wasn't currently being served got a fast "role unreachable" and fell
    // back to the stand-in (central's 5-at-once test: 1 built, 4 unreachable, incl. central's own
    // safety_check — the serve model, not a per-role bug). We now ADMIT sequentially (one parked
    // accept at a time, so the edge pairer never has to hold two accepts for one channel) but SPAWN
    // each paired session, looping straight back to admit the next peer. A bounded semaphore caps how
    // many sessions run at once so a flood of Builds can't fork-bomb the host (each session may spawn
    // a `claude -p`); at capacity the next peer simply waits at the broker.
    //
    // The direct listener is bound ONCE and shared across sessions (quinn `Endpoint` is a cheap
    // clonable handle) — a per-session re-bind of the same advertised port would conflict. Over the
    // plane the direct accept times out to the edge relay, so each session's relay leg is independent
    // and fully concurrent; central must e2e the concurrent case (the regression bar: N concurrent
    // builds all succeed, no `role unreachable` fallbacks, single-request builds unchanged).
    let shared_listener: Option<Endpoint> = match cfg.role {
        ChannelRole::Accept if !cfg.relay_only => Some(crate::transport::build_direct_listener_at(cfg.listen_addr)?.0),
        _ => None,
    };
    let ctx = std::sync::Arc::new(ServeSessionCtx {
        request: request.clone(),
        holder: cfg.holder.clone(),
        role: cfg.role,
        own_noise_private: cfg.own_noise_private,
        broker_addr: cfg.broker_addr,
        relay_addr: cfg.relay_addr,
        broker_ladder: broker_ladder.clone(),
        relay_ladder: relay_ladder.clone(),
        front_door_cert: front_door_cert.clone(),
        listener: shared_listener,
        direct_upgrade: cfg.direct_upgrade,
    });
    let max = serve_concurrency_from_env(std::env::var("CT_CHANNEL_SERVE_CONCURRENCY").ok().as_deref());
    eprintln!("ct-agent channel: persistent serve — up to {max} concurrent sessions (#200)");
    let admit_ctx = ctx.clone();
    serve_loop_concurrent(
        max,
        std::time::Duration::from_millis(200),
        move || {
            let c = admit_ctx.clone();
            async move { admit_one_peer(&c).await }
        },
        move |admission| {
            let c = ctx.clone();
            async move { serve_admitted_session(c, admission).await }
        },
    )
    .await
}

/// #200: the owned, `Send + Sync` context a persistent serve member needs to run each of its
/// concurrent sessions independently of the parking loop. Built ONCE (cloning the config's
/// request/holder/ladders + cert, and binding the shared direct listener) so each spawned session
/// borrows only from an `Arc<ServeSessionCtx>` and never from the loop's stack.
struct ServeSessionCtx {
    request: ChannelJoinRequest,
    holder: SigningKey,
    role: ChannelRole,
    own_noise_private: [u8; 32],
    broker_addr: SocketAddr,
    relay_addr: SocketAddr,
    broker_ladder: Vec<ChannelDialRung>,
    relay_ladder: Vec<ChannelDialRung>,
    front_door_cert: Option<CertificateDer<'static>>,
    /// Bound once (Accept + not relay-only) and cloned per session; `None` for relay-only members
    /// (they can't be dialed directly) — those serve purely over the edge relay.
    listener: Option<Endpoint>,
    /// #104, mirrors [`ChannelJoinCliConfig::direct_upgrade`] (`CT_CHANNEL_DIRECT_UPGRADE`).
    direct_upgrade: bool,
}

/// #200: present the grant to the broker and park until the edge pairs the NEXT peer, returning that
/// peer's admission. This is the sequential part of the serve loop — only one admission is ever
/// parked, so the pairer is never asked to hold two accepts for one channel. Mirrors the admission
/// half of [`run_one_admission_session`], reading from the shared `Arc` instead of borrowed config.
///
/// A **refused** outcome (a clean broker round-trip whose answer is "no") is turned into an `Err`
/// here — not returned as `Ok(ChannelJoinOutcome::Refused)` — so [`serve_loop_concurrent`] routes it
/// through its existing error/backoff path instead of its `Ok(work) => spawn(..)` path. Before this,
/// a refusal-as-a-value was indistinguishable from a real admission at that match: it got spawned as
/// a full session (through `channel_local()`'s "--serve mode" setup and the rest of
/// [`run_channel_join_with_admission`]) only to immediately fail there with the very same "refused
/// the channel join" message — resetting `consecutive_refusals` to 0 on every attempt (since the
/// outer loop saw `Ok`, not `Err`) and so **never** engaging #231's exponential backoff for this
/// failure mode. Live-observed via #248: a channel's outer loop hammering `admit_one_peer` at a near-
/// zero-backoff rate whenever every admission attempt came back refused-as-a-value, spawning (and
/// immediately discarding) hundreds of sessions an hour instead of backing off between attempts.
async fn admit_one_peer(ctx: &ServeSessionCtx) -> Result<ChannelJoinOutcome, BoxError> {
    let outcome = match &ctx.front_door_cert {
        Some(edge_cert) => {
            present_channel_join_via_ladder(&ctx.broker_ladder, &ctx.request, &ctx.holder, edge_cert.clone(), DIRECT_DIAL_TIMEOUT).await?
        }
        None => {
            let broker_conn = crate::transport::build_channel_dialer()?
                .connect(ctx.broker_addr, "localhost")?
                .await?;
            present_channel_join(&broker_conn, &ctx.request, &ctx.holder).await?
        }
    };
    reject_refused_outcome(outcome)
}

/// Pure translation step for [`admit_one_peer`], pulled out so it's unit-testable without a real
/// broker: turn a **refused** outcome into the same `Err` string [`is_definitive_admission_refusal`]
/// already recognizes, so [`serve_loop_concurrent`] routes it through its error/backoff path instead
/// of spawning it as if it were a real session. See [`admit_one_peer`]'s doc comment for why this
/// matters (#248).
fn reject_refused_outcome(outcome: ChannelJoinOutcome) -> Result<ChannelJoinOutcome, BoxError> {
    match outcome {
        ChannelJoinOutcome::Refused => Err(AdmissionRefused::boxed("edge broker refused the channel join")),
        // #21: a park expiry becomes the DISTINCT typed error so [`serve_loop_concurrent`]
        // routes it through its immediate-re-park path (no refusal backoff, no ladder advance)
        // instead of spawning it as a session or backing off as if refused.
        ChannelJoinOutcome::ParkExpired => Err(ParkExpired::boxed(
            "channel park expired with no partner within the edge park window (#21) -- re-parking",
        )),
        admitted => Ok(admitted),
    }
}

/// #200: run one already-admitted peer's session to completion — the SPAWNED part of the serve loop.
/// Rebuilds the relay fallback + a fresh local app stream and clones the shared direct listener, then
/// runs the session exactly as [`run_one_admission_session`] does. A fresh `channel_local()` per
/// session matches the pre-existing per-session behaviour (the #179 loop rebuilt it each peer too).
async fn serve_admitted_session(
    ctx: std::sync::Arc<ServeSessionCtx>,
    admission: ChannelJoinOutcome,
) -> Result<(), BoxError> {
    let relay = match &ctx.front_door_cert {
        Some(edge_cert) => RelayFallback::Ladder {
            rungs: &ctx.relay_ladder,
            edge_cert: edge_cert.clone(),
            direct_timeout: DIRECT_DIAL_TIMEOUT,
        },
        None => RelayFallback::QuicLazy(ctx.relay_addr),
    };
    let listener = ctx.listener.clone(); // cheap quinn handle; shared across concurrent sessions
    let local = channel_local();
    run_channel_join_with_admission(
        admission,
        relay,
        &ctx.request,
        &ctx.holder,
        ctx.role,
        &ctx.own_noise_private,
        listener,
        DIRECT_DIAL_TIMEOUT,
        CHANNEL_ACCEPT_TIMEOUT,
        local,
        ctx.direct_upgrade,
    )
    .await
}

/// #200: default number of concurrent serve sessions when `CT_CHANNEL_SERVE_CONCURRENCY` is unset —
/// comfortably covers realistic demo concurrency (central's 5/10-at-once test) while bounding the
/// fan-out of handler subprocesses (`claude -p`) a flood of Builds can trigger.
const DEFAULT_SERVE_CONCURRENCY: usize = 8;

/// #231: ceiling on the exponential backoff a persistent serve loop applies after consecutive
/// **refused** (not transient) admission attempts — see [`serve_loop_concurrent`].
const REFUSED_ADMISSION_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// #250 ("flapping peer"): a session that dies within this long of being admitted is treated as
/// a FAILED pairing, not a completed one — live-diagnosed 2026-08-13 (a Windows accept-side
/// member and a front-door-only bridge): admission succeeded every single time (grant verified,
/// both sides acked), but the underlying TLS-TCP connection then died before/during the Noise
/// handshake, near-instantly, on essentially every attempt — ~98 pair-then-die cycles in 30s
/// (~300ms apart), matching this loop's UNTHROTTLED re-admit cadence exactly (there was no
/// backoff at all between a failed session and the next admit). Root cause (Windows-side
/// AV/firewall DPI killing the connection post-handshake, or a platform-specific transport bug)
/// is still open -- but regardless of cause, hammering the edge at native RTT speed while it
/// persists serves nobody: it floods the edge's admission/relay path for no gain (the failure
/// recurs every time) and produces a wall of noise that hides every other signal. A genuine
/// session (even a very short, single-call one) legitimately completes well under this: the
/// sort arena's own measured per-round session lifetime is ~85ms end-to-end including the Noise
/// handshake -- this threshold is 6x that, so a real, working session is never mistaken for a
/// flap.
const FLAPPING_SESSION_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(500);

/// #250: ceiling on the exponential backoff applied after consecutive flapping (pair-then-
/// near-instant-death) sessions — same shape as [`REFUSED_ADMISSION_BACKOFF_CAP`], deliberately
/// shorter: unlike a definitive refusal (which literally cannot resolve without operator
/// action), a flap's underlying cause (a transient AV heuristic, a flaky corporate firewall
/// rule) can clear on its own, so this loop should keep checking meaningfully sooner.
const FLAPPING_SESSION_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(10);

/// Parse `CT_CHANNEL_SERVE_CONCURRENCY` into a concurrency cap: a positive integer overrides the
/// default; anything absent/blank/zero/malformed falls back to [`DEFAULT_SERVE_CONCURRENCY`]. Pure.
fn serve_concurrency_from_env(value: Option<&str>) -> usize {
    value
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_SERVE_CONCURRENCY)
}

/// #200: drive a persistent serve member as CONCURRENT sessions. `admit` parks at the broker and
/// returns the next paired peer's session work `W` (called sequentially — only one admission is ever
/// in flight); `serve` runs a session to completion and is SPAWNED, so the loop returns to `admit`
/// the next peer immediately instead of blocking on the whole session. `max` bounds in-flight
/// sessions via a semaphore whose permit is taken BEFORE parking (backpressure: we never admit a peer
/// we have no capacity to serve) and released when the session ends. A transient `admit` error is
/// logged and retried after `retry_backoff`; a **refused** (definitive, not-a-member) admission
/// backs off exponentially instead — see [`admission_retry_backoff`]. A `serve` error is a single
/// peer's problem, logged and dropped. Never returns under normal operation. Injectable so the
/// concurrency contract is unit-testable without a real broker/relay.
async fn serve_loop_concurrent<A, Fa, S, Fs, W>(
    max: usize,
    retry_backoff: std::time::Duration,
    mut admit: A,
    serve: S,
) -> Result<(), BoxError>
where
    A: FnMut() -> Fa,
    Fa: std::future::Future<Output = Result<W, BoxError>>,
    S: Fn(W) -> Fs,
    Fs: std::future::Future<Output = Result<(), BoxError>> + Send + 'static,
    W: Send + 'static,
{
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max.max(1)));
    let mut consecutive_refusals: u32 = 0;
    // #250: shared across spawned sessions (all admissions on this loop are for the SAME
    // channel/holder -- an accept-side member has exactly one fixed remote grant, so there is
    // no "other peer" a global backoff could unfairly delay). Incremented by a session that
    // dies within FLAPPING_SESSION_THRESHOLD of being admitted; reset by any session that
    // either succeeds or simply lives long enough to not look like a flap.
    let consecutive_flaps = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("serve concurrency semaphore is never closed");
        // #250: back off BEFORE the next admit if the last several sessions all died
        // near-instantly -- otherwise a flapping peer re-pairs and dies again at native RTT
        // speed forever, with no gap for the underlying interference (if transient) to clear
        // and no relief for the edge (every pairing round-trips a full admission + relay
        // splice for nothing).
        let flaps = consecutive_flaps.load(std::sync::atomic::Ordering::Relaxed);
        if flaps > 0 {
            let backoff = flapping_session_backoff(retry_backoff, flaps);
            eprintln!(
                "ct-agent channel: {flaps} consecutive session(s) died within {}ms of pairing (#250) -- \
                 backing off {backoff:?} before the next admit (peer may be experiencing network \
                 interference: AV/firewall DPI killing the connection post-handshake is the leading \
                 cause seen in the field)",
                FLAPPING_SESSION_THRESHOLD.as_millis()
            );
            tokio::time::sleep(backoff).await;
        }
        match admit().await {
            Ok(work) => {
                consecutive_refusals = 0;
                let fut = serve(work);
                let flap_counter = consecutive_flaps.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for the whole session; frees a slot on drop
                    let started = std::time::Instant::now();
                    let result = fut.await;
                    let flapped = is_flapping_session(started.elapsed(), result.is_err());
                    flap_counter.store(
                        if flapped {
                            flap_counter.load(std::sync::atomic::Ordering::Relaxed).saturating_add(1)
                        } else {
                            0
                        },
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if let Err(e) = result {
                        eprintln!("ct-agent channel: serve session ended with error (#200): {e}");
                    }
                });
            }
            Err(e) => {
                drop(permit);
                // #21: a park expiry re-parks IMMEDIATELY on the same transport -- it is neither
                // a refusal (never counts toward the #231 backoff) nor a failure worth the
                // generic "admission error" log line (the named line below is the field-visible
                // contract the #21 measurement greps for). The single fast `retry_backoff` sleep
                // (200ms in production) is only a tight-loop guard against a misbehaving edge
                // that reaps instantly; a healthy edge parks for the full TTL between expiries.
                if is_park_expired(&e) {
                    consecutive_refusals = 0;
                    eprintln!("ct-agent channel: {e}");
                    tokio::time::sleep(retry_backoff).await;
                    continue;
                }
                let refused = is_definitive_admission_refusal(&e);
                consecutive_refusals = if refused { consecutive_refusals.saturating_add(1) } else { 0 };
                let backoff = admission_retry_backoff(retry_backoff, refused, consecutive_refusals);
                eprintln!("ct-agent channel: admission error, re-admitting (#200): {e}");
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// #250: pure classifier -- did a just-ended session look like a "flap" (pair, then die near-
/// instantly)? Only an ERRORED session that ended within [`FLAPPING_SESSION_THRESHOLD`]
/// qualifies; a session that succeeded (even a fast single-call one) or that ran long before
/// failing is a real session, not a flap, and must reset the counter rather than extend it.
fn is_flapping_session(elapsed: std::time::Duration, errored: bool) -> bool {
    errored && elapsed < FLAPPING_SESSION_THRESHOLD
}

/// #250: exponential backoff after `consecutive_flaps` near-instant session deaths in a row,
/// same shape as [`admission_retry_backoff`]'s refused-admission path but capped lower (see
/// [`FLAPPING_SESSION_BACKOFF_CAP`]'s doc for why). Pure.
fn flapping_session_backoff(
    retry_backoff: std::time::Duration,
    consecutive_flaps: u32,
) -> std::time::Duration {
    let shift = consecutive_flaps.min(16);
    retry_backoff
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(FLAPPING_SESSION_BACKOFF_CAP)
}

/// #231: does an admission error mean the presenting holder was **definitively** refused (not a
/// channel member — see `channel-join NO [not-member]` on the edge) rather than a transient
/// failure (`edge broker/relay refused the channel join` are the exact strings
/// [`run_one_admission_session`]'s ladder produces for this case; `channel join admission exchange
/// stalled (#140)` and any other error are treated as transient/retryable-fast)? Pure string match
/// on `Display` — the call chain flattens every failure to `BoxError` by the time it reaches
/// [`serve_loop_concurrent`], so this is the only signal available without a wider error-type
/// refactor across the admission ladder.
fn is_definitive_admission_refusal(e: &BoxError) -> bool {
    // #20 (consolidation): typed classification first -- every in-process creation site now
    // returns [`AdmissionRefused`], so a future rewording of the operator-facing text can no
    // longer silently disable the #231 backoff (the failure mode of the old substring-only
    // check was not an error but a behavioral regression: definitive refusals retried at the
    // fast cadence, i.e. the exact edge-flood #231 was filed about). The substring fallback
    // stays for ONE release, documented: it covers errors that crossed a stringifying boundary
    // (e.g. a subprocess's stderr re-parsed into a fresh error) and is scheduled for removal
    // once no such path exists.
    if e.downcast_ref::<AdmissionRefused>().is_some() {
        return true;
    }
    e.to_string().contains("refused the channel join")
}

/// #20: typed marker for a DEFINITIVE broker/relay refusal -- the peer's wire `NO`. `Display`
/// emits the exact historical strings (field-visible contract: operators grep these, docs quote
/// them, the sort bridge's fault attribution matches on them), but in-process classification
/// ([`is_definitive_admission_refusal`]) is a downcast, not a substring search. The client-side
/// sibling of the edge's `DefinitiveJoinRefusal` (CADS-Tunnel, same day, same class of fix).
#[derive(Debug)]
pub(crate) struct AdmissionRefused(pub(crate) &'static str);

impl std::fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for AdmissionRefused {}

impl AdmissionRefused {
    /// The one constructor every refusal site uses -- boxed, ready to return.
    fn boxed(text: &'static str) -> BoxError {
        Box::new(AdmissionRefused(text))
    }
}

/// #21: typed marker for a park expiry -- the edge reaped this member's park because no partner
/// arrived within the park TTL, and SAID SO on the wire (the bare `EX` token / the named QUIC
/// close reason). Deliberately a DISTINCT type from [`AdmissionRefused`]: a park expiry is
/// neither a refusal (nothing about the grant or holder is wrong -- there was simply nobody to
/// pair with yet) nor a transport failure (the rung worked end to end). The correct reaction is
/// to re-park immediately on the same transport; before this type existed the silent reap was
/// misread as a rung failure, advancing the dial ladder and burning a fresh 0-40s window per
/// expiry (the tester's measured 271 phantom "rung failures").
#[derive(Debug)]
pub(crate) struct ParkExpired(pub(crate) &'static str);

impl std::fmt::Display for ParkExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParkExpired {}

impl ParkExpired {
    fn boxed(text: &'static str) -> BoxError {
        Box::new(ParkExpired(text))
    }
}

/// #21: is this admission error a park expiry (see [`ParkExpired`])? Typed downcast first; the
/// string half covers a park-expiry close reason that reached us flattened inside some other
/// error (e.g. an `open_bi`/write failure racing the edge's ApplicationClose) -- like
/// [`crate::channel::error_names_park_expiry`], that is wire-token parsing, not an in-process
/// substring contract.
fn is_park_expired(e: &BoxError) -> bool {
    if e.downcast_ref::<ParkExpired>().is_some() {
        return true;
    }
    crate::channel::error_names_park_expiry(e.as_ref())
}

/// #231: how long to wait before the next admission attempt. A definitive refusal (see
/// [`is_definitive_admission_refusal`]) will never resolve itself without operator action — a
/// holder that isn't a channel member stays that way until someone adds it — so retrying at the
/// same fast `retry_backoff` used for transient errors (200ms in production) does nothing but
/// flood the edge's admission path with attempts that can never succeed. Live-reproduced: an
/// orphaned process retrying a not-member holder measured at ~24-47 admission attempts/second
/// against the production edge, plausibly starving OTHER, genuinely valid joins of admission
/// capacity (the exact symptom #231 describes). Backs off exponentially
/// (`retry_backoff * 2^consecutive_refusals`), capped at [`REFUSED_ADMISSION_BACKOFF_CAP`]; a
/// transient error always gets the fast, unchanged `retry_backoff` so a genuine brief CP/edge
/// blip (#140) still recovers quickly. Pure — the loop supplies `consecutive_refusals`.
fn admission_retry_backoff(
    retry_backoff: std::time::Duration,
    refused: bool,
    consecutive_refusals: u32,
) -> std::time::Duration {
    if !refused {
        return retry_backoff;
    }
    let shift = consecutive_refusals.min(16); // avoids overflow in 2^shift well before the cap binds
    retry_backoff
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(REFUSED_ADMISSION_BACKOFF_CAP)
}

/// #179: should `ct-agent channel` stay parked and re-admit successive peers? Only the **accept**
/// side in **serve** mode (`CT_CHANNEL_SERVE` truthy) — the parking side of a role a pipeline dials
/// repeatedly. An initiator (or a non-serve accept) does exactly one session and exits. Pure.
fn should_serve_loop(role: ChannelRole, serve_env: Option<&str>) -> bool {
    role == ChannelRole::Accept
        && serve_env
            .map(|v| {
                let t = v.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
}

/// One admit→serve cycle of the plane-brokered flow: re-present the grant to the broker (a fresh
/// admission per peer), build the relay fallback + optional direct listener, and run the session
/// with a fresh local app stream. Factored out so [`run_channel_join_command`]'s #179 serve loop can
/// repeat it for each successive peer without re-parsing config.
async fn run_one_admission_session(
    cfg: &ChannelJoinCliConfig,
    request: &ChannelJoinRequest,
    broker_ladder: &[ChannelDialRung],
    relay_ladder: &[ChannelDialRung],
    front_door_cert: &Option<CertificateDer<'static>>,
) -> Result<(), BoxError> {
    let admission = match front_door_cert {
        Some(edge_cert) => {
            present_channel_join_via_ladder(broker_ladder, request, &cfg.holder, edge_cert.clone(), DIRECT_DIAL_TIMEOUT).await?
        }
        None => {
            let broker_conn = crate::transport::build_channel_dialer()?
                .connect(cfg.broker_addr, "localhost")?
                .await?;
            present_channel_join(&broker_conn, request, &cfg.holder).await?
        }
    };
    // The relay data leg mirrors the broker leg (#106 relay-leg-443): with a `:443` front-door cert
    // the relay fallback walks its own ladder — direct QUIC to the relay port, then the `:443` front
    // door — so a member whose relay port is ALSO filtered can still relay. Without a cert, the eager
    // direct-QUIC relay dial is unchanged.
    let relay = match front_door_cert {
        Some(edge_cert) => RelayFallback::Ladder {
            rungs: relay_ladder,
            edge_cert: edge_cert.clone(),
            direct_timeout: DIRECT_DIAL_TIMEOUT,
        },
        // #103: dial the relay LAZILY (only on direct-dial failure).
        None => RelayFallback::QuicLazy(cfg.relay_addr),
    };
    // #121: a relay-only member skips binding the direct listener even in Accept — it can't be dialed.
    let listener = match cfg.role {
        ChannelRole::Accept if !cfg.relay_only => Some(crate::transport::build_direct_listener_at(cfg.listen_addr)?.0),
        _ => None,
    };
    let local = channel_local();
    run_channel_join_with_admission(
        admission,
        relay,
        request,
        &cfg.holder,
        cfg.role,
        &cfg.own_noise_private,
        listener,
        DIRECT_DIAL_TIMEOUT,
        CHANNEL_ACCEPT_TIMEOUT,
        local,
        cfg.direct_upgrade,
    )
    .await
}

/// Bound on a direct A2A dial before giving up (#72 AF4-session-resilience). Kept
/// short so a peer that's unreachable on the direct path (NAT / firewall / down) fails
/// fast — the signal to fall back to the edge relay — instead of hanging on the QUIC
/// handshake's retransmits.
pub const DIRECT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// #104: build this member's in-band relay->direct upgrade candidate from its own
/// edge-observed reflexive address (learned during THIS admission — the edge tells a
/// member its own address as part of `ChannelJoinOutcome::Admitted`, over the same
/// already-authenticated broker/relay connection, never a new open port). Binds a fresh
/// ephemeral direct listener (`0.0.0.0:0`) purely for this upgrade attempt — a listener
/// distinct from `CT_CHANNEL_LISTEN`'s, never advertised to the broker or to anyone but
/// this one already-Noise-verified peer. `None` when the edge reported no reflexive
/// address for this admission (e.g. the `:443` front-door leg doesn't observe one), the
/// reflexive address isn't global-unicast, or the listener fails to bind — the session
/// then simply stays on the relay, unaffected.
///
/// Found live (#248, 2026-08-01): a member co-located with the edge on the same Docker
/// host (e.g. a demo bridge container) has an edge-observed reflexive address on the
/// **Docker bridge network** (RFC1918, e.g. `172.18.0.19`) — real from the edge's point
/// of view, but meaningless to any genuinely external peer, who can never route to it.
/// Offering it anyway isn't just wasted effort: the peer's own SSRF guard
/// (`upgrade_safe_endpoint`, #137) correctly refuses to dial it, but in production this
/// consistently left the *initiator* blocked for the full outer session timeout rather
/// than falling back to the relay promptly (`drive_initiator_upgrade`'s reply wait is
/// documented as "the caller's concern" to bound and isn't bounded here) — turning an
/// always-doomed direct attempt into a full session failure instead of a same-second
/// relay fallback. The responder already validates the *peer's* offered endpoint this
/// way (#137); this applies the identical filter symmetrically to our OWN candidate
/// before ever offering it, so an unreachable candidate is never offered in the first
/// place and the initiator's own coordinator degrades to relay-only immediately (the
/// `_ => run_channel_session_on_stream(...)` arm in
/// [`run_channel_session_upgradable`](crate::channel_run::run_channel_session_upgradable))
/// — same as if the edge had reported no reflexive address at all. A same-Docker-network
/// peer (this demo's own baseline scenario, both sides on the same host) is unaffected
/// only in the sense that its reflexive address is *also* RFC1918 and would now also
/// skip the direct attempt — a strictly safe trade: that pairing was never a
/// representative test of real cross-network direct-P2P reachability anyway, and it
/// still relays correctly.
async fn build_upgrade_candidate(observed_reflexive: Option<SocketAddr>) -> Option<(Endpoint, String)> {
    let addr = observed_reflexive?;
    if !ct_common::channel::is_global_unicast(addr) {
        eprintln!(
            "ct-agent channel: #104 upgrade — our own edge-observed reflexive address {addr} is not \
             global-unicast (RFC1918/link-local/etc, #248) — skipping the direct-upgrade attempt, staying on relay"
        );
        return None;
    }
    let (listener, _cert) = crate::transport::build_direct_listener().ok()?;
    // #276 piece 1: also offer a LAN-local candidate, when this host has one -- the same
    // ephemeral port `listener` bound on 0.0.0.0 accepts on every interface, including the
    // local one, so pairing the offered local IP with that port is a real, dialable target.
    // Encoded as `reflexive\0local` (see `split_offered_candidates`) so `ct_common::upgrade`'s
    // wire format and generic signatures stay completely untouched -- this is purely how
    // ct-agent packs/unpacks the one `String` field `UpgradeMsg::Offer` already carries. The
    // offering side announces its own real local address truthfully, same as it already does
    // for its reflexive address; the RESPONDER is the one that must not trust it outright
    // (`select_upgrade_candidate`'s `same_local_subnet` gate).
    let endpoint = match (local_egress_ip(), listener.local_addr().ok()) {
        (Some(local_ip), Some(bound)) if is_lan_candidate(local_ip) => {
            format!("{addr}\0{}", SocketAddr::new(local_ip, bound.port()))
        }
        _ => addr.to_string(),
    };
    Some((listener, endpoint))
}

/// #276: whether `ip` is the kind of address worth offering as a LAN-local direct-upgrade
/// candidate at all (private RFC1918 or IPv6 ULA) -- loopback/link-local/multicast/global
/// addresses are never useful here (a global address already goes through the reflexive
/// candidate; loopback/link-local/multicast can never be a peer's real LAN address).
fn is_lan_candidate(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00, // unique-local fc00::/7
    }
}

/// Best-effort local (LAN-facing) IP: "connect" a UDP socket to an unrouted public address
/// (no packet is sent -- it only makes the OS pick the default-route source interface) and
/// read the socket's local address. `None` when there is no route. Mirrors the same trick
/// `CADS-Tunnel`'s `ct-client` crate already uses for its own local-egress classifier
/// (`ladder.rs::local_egress_ip`) -- deliberately no new dependency for interface
/// enumeration.
fn local_egress_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): never a real host, so nothing is contacted --
    // connect() only fixes the source interface via the routing table.
    sock.connect(("192.0.2.1", 9)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// #276: split a peer-offered direct-upgrade endpoint into its required reflexive
/// candidate and an optional LAN-local one, the counterpart to `build_upgrade_candidate`'s
/// `reflexive\0local` encoding. An empty or malformed local segment degrades to "no local
/// candidate" rather than a parse error -- the reflexive candidate alone is always a
/// complete, valid offer on its own (unchanged pre-#276 behavior).
fn split_offered_candidates(ep: &str) -> (&str, Option<&str>) {
    match ep.split_once('\0') {
        Some((reflexive, local)) if !local.is_empty() => (reflexive, Some(local)),
        Some((reflexive, _)) => (reflexive, None),
        None => (ep, None),
    }
}

/// #276: choose which of a peer-offered candidate pair to actually dial. Prefers the
/// LAN-local candidate — cheap, low-latency, and if it connects it's almost certainly the
/// same network — but ONLY after `same_local_subnet` confirms it against THIS host's own
/// local address; a malformed local candidate, a family mismatch, or a candidate outside
/// our own subnet all fall through to the existing `#137`-guarded reflexive candidate,
/// never to an ungated dial. This is the one seam both `dial_probe` and
/// `dial_and_establish` call, so "is this safe" and "what do we actually dial" can never
/// disagree.
fn select_upgrade_candidate(ep: &str) -> Option<SocketAddr> {
    let (reflexive, local) = split_offered_candidates(ep);
    if let Some(local) = local {
        if let Ok(candidate) = local.parse::<SocketAddr>() {
            if let Some(my_local) = local_egress_ip() {
                if ct_common::channel::same_local_subnet(my_local, candidate.ip()) {
                    return Some(candidate);
                }
            }
        }
    }
    upgrade_safe_endpoint(reflexive)
}

/// Why a direct dial to a paired peer did not connect (#72 AF4-session-resilience).
#[derive(Debug)]
pub enum ChannelDialError {
    /// The dial did not complete within the timeout — the peer is unreachable on the
    /// **direct** path. This is the signal to fall back to the edge relay, not an error
    /// to surface to the user.
    Unreachable,
    /// The dial failed for another reason (bad address, endpoint setup, connect error).
    Failed(BoxError),
}

impl std::fmt::Display for ChannelDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDialError::Unreachable => write!(f, "peer unreachable on the direct path"),
            ChannelDialError::Failed(e) => write!(f, "direct dial failed: {e}"),
        }
    }
}

impl std::error::Error for ChannelDialError {}

/// Dial a paired peer's advertised endpoint directly over QUIC (accept-any transport —
/// Noise_IK is the real auth), bounded by `timeout`. A timeout is classified as
/// [`ChannelDialError::Unreachable`] rather than a generic error, so the caller can
/// distinguish "the direct path is blocked, fall back to the relay" from "the dial
/// itself is malformed" — the crux of the connection-difficulty handling.
pub async fn dial_peer_direct(
    addr: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, ChannelDialError> {
    let dialer = crate::transport::build_channel_dialer().map_err(ChannelDialError::Failed)?;
    let connecting = dialer
        .connect(addr, "localhost")
        .map_err(|e| ChannelDialError::Failed(Box::new(e)))?;
    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(ChannelDialError::Failed(Box::new(e))),
        Err(_elapsed) => Err(ChannelDialError::Unreachable),
    }
}

/// Walk a channel dial **fallback ladder** (#106): try each rung in order and return
/// the first that connects. A rung that fails — `Unreachable` (a restrictive network
/// blocked the direct channel port) or `Failed` — falls through to the next, so a
/// blocked *direct* rung falls back to the `:443` front-door rung. Errors only when
/// **every** rung is blocked (all paths down). The per-rung transport connect is
/// injected as `dial`, so the ladder-walk is pure and unit-testable without sockets;
/// the caller supplies the real QUIC-direct / TLS-TCP-`:443` dials (the latter carries
/// the `ct-edge-channel` ALPN so the `:443` front door routes it to the broker).
pub async fn dial_ladder<C, D, Fut>(rungs: &[ChannelDialRung], dial: D) -> Result<C, ChannelDialError>
where
    D: Fn(&ChannelDialRung) -> Fut,
    Fut: std::future::Future<Output = Result<C, ChannelDialError>>,
{
    let mut last: Option<ChannelDialError> = None;
    for rung in rungs {
        match dial(rung).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(ChannelDialError::Unreachable))
}

/// Present a channel join by walking the fallback `rungs` (#106 client-dial-443): for a
/// **direct** rung, dial the channel port over QUIC ([`dial_peer_direct`]) and run the
/// join on a fresh bi-stream ([`present_channel_join`]); for a **front-door** rung, open
/// the unified `:443` route over TLS-TCP ([`crate::transport::tcp_tls_connect_channel`],
/// ALPN `ct-edge-channel`) and run the identical join over the split TLS stream
/// ([`present_channel_join_on_stream`]). Composed over [`dial_ladder`], so the first rung
/// that is genuinely **`Admitted`** wins. A rung whose transport can't connect
/// (`Unreachable` on a blocked direct port, or a `Failed` TLS/connect) falls through to
/// the next, letting a network that blocks the direct channel port recover over `:443` —
/// and so does a rung whose join comes back **`Refused`** ([`reject_refused_outcome`]):
/// a network that corrupts or fingerprints the request differently per rung (exactly what
/// this ladder's `:443` legs exist to route around) can turn a garbled request into a
/// spurious `NO` on one rung while a cleaner rung would have been legitimately admitted,
/// so a single refusal must not end the walk (live-reported gap, ct-agent#15). Errors only
/// when every rung is blocked or refused — that final error still reports a genuine
/// refusal as one, just after every rung has actually been tried. `edge_cert` is the root
/// the front-door TLS dial trusts; `direct_timeout` bounds each direct QUIC dial (the
/// [`DIRECT_DIAL_TIMEOUT`] signal).
pub async fn present_channel_join_via_ladder(
    rungs: &[ChannelDialRung],
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
) -> Result<ChannelJoinOutcome, BoxError> {
    dial_ladder(rungs, |rung: &ChannelDialRung| {
        let endpoint = rung.endpoint;
        let kind = rung.kind;
        let edge_cert = edge_cert.clone();
        async move {
            // Diagnosability (real support case, 2026-08-12): dial_ladder only keeps the
            // LAST rung's error, and ChannelDialError::Failed's Display hardcodes "direct
            // dial failed" regardless of which rung actually produced it -- an operator
            // debugging a blocked-direct-port case sees an identically-worded failure for
            // both the direct attempt AND a subsequent :443 front-door attempt, with no way
            // to tell from the log alone whether the fallback even ran. Name the rung being
            // tried and its outcome explicitly, independent of the generic error text.
            let rung_label = kind.label();
            eprintln!("ct-agent channel: dialing {rung_label} rung {endpoint}");
            let result = if kind.is_front_door() {
                // #106 fallback: the :443 front door over TLS-TCP. Both flavours run the
                // identical join on the resulting stream -- the edge dispatches the boring
                // ClientHello (ALPN h2 / SNI edge-cdn.invalid) to the same channel
                // broker as the ct-edge-channel ALPN, so only the dialer differs.
                async {
                    let stream = match kind {
                        ChannelDialKind::FrontDoorBoring => {
                            crate::transport::tcp_tls_connect_channel_boring(endpoint, edge_cert).await
                        }
                        _ => crate::transport::tcp_tls_connect_channel(endpoint, edge_cert).await,
                    }
                    .map_err(ChannelDialError::Failed)?;
                    let (recv, send) = tokio::io::split(stream);
                    // finish_send_after_sig = false (#21 follow-up): on this TCP/TLS leg the
                    // old post-signature shutdown was a close_notify+FIN that half-closed the
                    // whole connection -- the parked member then waited out its park as a
                    // closing flow, and the edge's reap teardown RST'd the in-flight EX away
                    // (packet-capture-proven). The edge needs no EOF; keep the leg fully open.
                    present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT, false)
                        .await
                        .map_err(ChannelDialError::Failed)
                }
                .await
            } else {
                // Direct: QUIC to the channel port. Unreachable falls through to :443.
                async {
                    let conn = dial_peer_direct(endpoint, direct_timeout).await?;
                    present_channel_join(&conn, request, holder)
                        .await
                        .map_err(ChannelDialError::Failed)
                }
                .await
            };
            // #248-class gap (live-reported, 2026-08-13, ct-agent#15): `reject_refused_outcome`
            // already exists to turn a `Refused` outcome into an `Err` so it isn't mistaken for a
            // finished/successful step -- it's used in `admit_one_peer`, but wasn't wired into
            // THIS closure, so `dial_ladder` saw `Ok(ChannelJoinOutcome::Refused)` as "this rung
            // is done, stop" instead of "this rung's join was refused, try the next one." A
            // network that corrupts/truncates the request bytes differently per rung (the exact
            // DPI interference this ladder exists to route around) can turn a garbled request
            // into a spurious `NO` on one rung while a cleaner rung would have been legitimately
            // admitted -- so a `Refused` must fall through like any other per-rung failure, not
            // end the walk. If every rung is genuinely refused (e.g. a real not-member grant),
            // the ladder still reports that refusal -- just after actually trying every rung.
            let result = result.and_then(|outcome| match outcome {
                // #21: a park expiry is NOT a rung failure -- this rung worked end to end (the
                // join was admitted into a park; the edge answered), there was simply no partner
                // within the park TTL. It must STOP the walk as a successful outcome (the caller
                // converts it to the typed [`ParkExpired`] and re-parks on the same transport),
                // never fall through like `Refused` does -- the fall-through is exactly the
                // ladder-advance misclassification #21 was filed about.
                ChannelJoinOutcome::ParkExpired => Ok(ChannelJoinOutcome::ParkExpired),
                other => reject_refused_outcome(other).map_err(ChannelDialError::Failed),
            });
            match &result {
                Ok(_) => eprintln!("ct-agent channel: {rung_label} rung {endpoint} succeeded"),
                Err(e) => eprintln!("ct-agent channel: {rung_label} rung {endpoint} failed: {e}"),
            }
            result
        }
    })
    .await
    .map_err(Into::into)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_bytes(s)?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// #190: the shared "required env field" parses the CliConfig `from_lookup` parsers repeat. Each was
/// hand-rolling `f(K).and_then(hex32).ok_or("K required (…)")` per field (~a dozen times across the
/// channel-session, grant, register, agent-card and offer parsers), duplicating both the boilerplate
/// and the `X required (…)` message format. These centralise it. `f` is the same env lookup every
/// parser already takes; `what` is the parenthetical hint. Behaviour is byte-identical to the inlined
/// forms (same message text), so a missing var still fails loudly at startup with the exact same error.
fn req_str<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<String, String> {
    f(key).ok_or_else(|| format!("{key} required ({what})"))
}
/// Required 32-byte hex env field: present, valid 64-hex → `[u8;32]`; else the `X required (…)` error.
fn req_hex32<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<[u8; 32], String> {
    f(key).as_deref().and_then(hex32).ok_or_else(|| format!("{key} required ({what})"))
}
/// Required ed25519 key env field: [`req_hex32`] + `SigningKey::from_bytes` (the seed is validated 32 bytes).
fn req_key<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&req_hex32(f, key, what)?))
}
/// Optional 32-byte hex env field: absent or malformed → `None` (the caller decides what that means).
fn opt_hex32<F: Fn(&str) -> Option<String>>(f: &F, key: &str) -> Option<[u8; 32]> {
    f(key).as_deref().and_then(hex32)
}

/// Split a comma-separated env value into trimmed, non-empty tokens (empty input → no tokens).
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Configuration for `ct-agent channel agent-card` (#144 ①-wiring): assemble + sign this
/// agent's holder [`AgentCard`](ct_common::channel::AgentCard) from `CT_CHANNEL_HOLDER_KEY`
/// plus the advertised claims, and write it to `<CT_AGENT_CARD_OUT>/.well-known/agent-card.json`
/// for the operator's origin to serve — the runnable path that closes the emit chain without
/// anyone hand-rolling ed25519. Env-parsed with the clock injected at [`write_card`], so the
/// assembly is a pure, testable function.
pub struct AgentCardCliConfig {
    /// The holder ed25519 signing key the card is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// Advertised role tags (`CT_AGENT_CARD_ROLES`, comma-separated) — at least one required.
    pub role_tags: Vec<String>,
    /// Advertised skills (`CT_AGENT_CARD_SKILLS`, `;`-separated `id|description` entries).
    pub skills: Vec<ct_common::channel::Skill>,
    /// Self-asserted cells (`CT_AGENT_CARD_CELLS`, comma-separated 64-hex) — usually empty.
    pub cells: Vec<ct_common::channel::CellId>,
    /// Channels the agent advertises reachability via (`CT_AGENT_CARD_CHANNELS`, comma-separated 64-hex).
    pub channels: Vec<ct_common::channel::ChannelId>,
    /// Validity window in seconds (`CT_AGENT_CARD_TTL_SECS`, default 86400).
    pub ttl_secs: u64,
    /// Directory the `.well-known/agent-card.json` is written under (`CT_AGENT_CARD_OUT`, default `.`).
    pub out_dir: std::path::PathBuf,
}

impl AgentCardCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let holder = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let role_tags = split_csv(f("CT_AGENT_CARD_ROLES").as_deref().unwrap_or_default());
        if role_tags.is_empty() {
            return Err("CT_AGENT_CARD_ROLES required (comma-separated role tags)".to_string());
        }
        let skills = parse_card_skills(f("CT_AGENT_CARD_SKILLS").as_deref().unwrap_or_default());
        let channels = parse_hex32_ids(f("CT_AGENT_CARD_CHANNELS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CHANNELS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::ChannelId)
            .collect();
        let cells = parse_hex32_ids(f("CT_AGENT_CARD_CELLS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CELLS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::CellId)
            .collect();
        let ttl_secs = match f("CT_AGENT_CARD_TTL_SECS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s
                .parse::<u64>()
                .map_err(|e| format!("CT_AGENT_CARD_TTL_SECS invalid: {e}"))?,
            _ => 86_400,
        };
        let out_dir = std::path::PathBuf::from(
            f("CT_AGENT_CARD_OUT").unwrap_or_else(|| ".".to_string()),
        );
        Ok(Self { holder, role_tags, skills, cells, channels, ttl_secs, out_dir })
    }

    /// Assemble + sign the agent's card (`issued_at = now`, `expires_at = now + ttl_secs`). The clock
    /// is a parameter so the assembly is deterministic + testable. Shared by [`write_card`] (emit to
    /// the origin) and the `agent/card` MCP tool (serve the identity over the authenticated channel).
    pub fn build_card(&self, now: u64) -> ct_common::channel::AgentCard {
        ct_common::channel::AgentCard::sign_new(
            &self.holder,
            self.role_tags.clone(),
            self.skills.clone(),
            self.cells.clone(),
            self.channels.clone(),
            now,
            now.saturating_add(self.ttl_secs),
        )
    }

    /// Sign the card and write it to `<out_dir>/.well-known/agent-card.json`. Returns the written path.
    pub fn write_card(&self, now: u64) -> std::io::Result<std::path::PathBuf> {
        crate::well_known::write_agent_card_for_origin(&self.build_card(now), &self.out_dir)
    }

    /// This card's role tags as its `skill_ids` for `POST /registry/agents` (the id half of each
    /// [`Skill`](ct_common::channel::Skill), matching what the directory search matches against).
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.id.clone()).collect()
    }
}

/// Optional auto-registration inputs for `ct-agent channel agent-card` (#214 follow-up: automatic
/// agent discoverability). Publishing a card used to be TWO separate manual steps — write it
/// locally, then remember to also `POST` it to `/registry/agents` — and the second step was easy
/// to forget entirely (the empty "AI agents" list on the operator landing page was exactly this:
/// nobody had ever run it). When all three of `CT_AGENT_CP_URL`/`CT_AGENT_CARD_URL`/
/// `CT_CP_EDGE_ADMIN_TOKEN` are present, `agent-card` folds both into one command. Absent →
/// unchanged behavior (card written locally only) — this is purely additive, opt-in by presence.
pub struct AgentCardAutoRegister {
    /// Control-plane base URL (`CT_AGENT_CP_URL`, same var other subcommands use).
    pub cp_url: String,
    /// The public `https://` URL this card will be served at once written (`CT_AGENT_CARD_URL`) —
    /// the CP rejects anything else (SSRF defence-in-depth).
    pub card_url: String,
    /// The shared machine-writer admin token (`CT_CP_EDGE_ADMIN_TOKEN`) — self-registration is
    /// gated by this, not an OIDC bearer, since an autonomous agent has no interactive login (#161).
    pub admin_token: String,
}

impl AgentCardAutoRegister {
    /// `None` if any required var is absent — auto-registration is opt-in, never required.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let present = |k: &str| f(k).filter(|s| !s.trim().is_empty());
        Some(Self {
            cp_url: present("CT_AGENT_CP_URL")?,
            card_url: present("CT_AGENT_CARD_URL")?,
            admin_token: present("CT_CP_EDGE_ADMIN_TOKEN")?,
        })
    }
}

/// CLI/env config for a **`CapacityOffer`** (#152 — the seller side of the #147 marketplace over the
/// `ct-agent` CLI, mirroring [`AgentCardCliConfig`]). When these vars are present, `--serve` mode also
/// exposes the `auction/offer` + `auction/bid` MCP tools so an operator can stand up a live offer and
/// have a live bid clear against it over a real authenticated channel — the `#144`-style live proof for
/// the marketplace. The holder key is reused from `CT_CHANNEL_HOLDER_KEY` (same as the card).
pub struct AgentOfferCliConfig {
    /// The holder ed25519 signing key the offer is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    signing_key: SigningKey,
    /// Capacity kind (`CT_AGENT_OFFER_KIND` = `cloud` | `local`).
    kind: ct_common::channel::CapacityKind,
    /// Model ids served (`CT_AGENT_OFFER_MODELS`, comma-separated) — at least one required.
    models: Vec<String>,
    /// Units offered (`CT_AGENT_OFFER_UNITS`).
    units_available: u64,
    /// The buyer's guaranteed-minimum floor (`CT_AGENT_OFFER_MIN_PRICE`).
    min_price: u64,
    /// Opaque settlement-currency id (`CT_AGENT_OFFER_CURRENCY`).
    currency_id: String,
    /// Validity window in seconds (`CT_AGENT_OFFER_TTL_SECS`, default 86400).
    ttl_secs: u64,
    /// #149-A.3 per-consumer bid rate limit (`CT_AGENT_OFFER_MAX_BIDS`, default 60).
    pub max_bids_per_window: u32,
    /// Rate-limit window (`CT_AGENT_OFFER_WINDOW_SECS`, default 60).
    pub window_secs: u64,
    /// #167/#149-A.1: the service catalog this offer **declares** (`CT_AGENT_OFFER_SERVICES`,
    /// comma-separated slugs). Empty = a generic offer that declares no services. This is the
    /// signed, buyer-verifiable ceiling on which `service/<slug>` tools the agent may register —
    /// so what a `CapacityOffer` claims and what the agent actually serves can no longer drift.
    pub services: Vec<ct_common::channel::ServiceType>,
}

impl AgentOfferCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env). An
    /// absent required var is an `Err`, which the caller treats as "no offer configured" (auction tools
    /// stay off), exactly like the card path.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let signing_key = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let kind = match f("CT_AGENT_OFFER_KIND").as_deref().map(str::trim) {
            Some("cloud") | Some("cloud-api") | Some("CloudApiQuota") => {
                ct_common::channel::CapacityKind::CloudApiQuota
            }
            Some("local") | Some("local-hardware") | Some("LocalHardware") => {
                ct_common::channel::CapacityKind::LocalHardware
            }
            Some(other) if !other.is_empty() => {
                return Err(format!("CT_AGENT_OFFER_KIND must be 'cloud' or 'local', got '{other}'"))
            }
            _ => return Err("CT_AGENT_OFFER_KIND required ('cloud' or 'local')".to_string()),
        };
        let models = split_csv(f("CT_AGENT_OFFER_MODELS").as_deref().unwrap_or_default());
        if models.is_empty() {
            return Err("CT_AGENT_OFFER_MODELS required (comma-separated model ids)".to_string());
        }
        let req_u64 = |var: &str| -> Result<u64, String> {
            f(var)
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{var} required"))?
                .parse::<u64>()
                .map_err(|e| format!("{var} invalid: {e}"))
        };
        let units_available = req_u64("CT_AGENT_OFFER_UNITS")?;
        let min_price = req_u64("CT_AGENT_OFFER_MIN_PRICE")?;
        let currency_id = f("CT_AGENT_OFFER_CURRENCY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("CT_AGENT_OFFER_CURRENCY required")?;
        let opt_u64 = |var: &str, default: u64| -> Result<u64, String> {
            match f(var).as_deref().map(str::trim) {
                Some(s) if !s.is_empty() => s.parse::<u64>().map_err(|e| format!("{var} invalid: {e}")),
                _ => Ok(default),
            }
        };
        let ttl_secs = opt_u64("CT_AGENT_OFFER_TTL_SECS", 86_400)?;
        let window_secs = opt_u64("CT_AGENT_OFFER_WINDOW_SECS", 60)?;
        let max_bids_per_window = match f("CT_AGENT_OFFER_MAX_BIDS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                s.parse::<u32>().map_err(|e| format!("CT_AGENT_OFFER_MAX_BIDS invalid: {e}"))?
            }
            _ => 60,
        };
        // #167: the offer's declared service catalog. Comma-separated slugs (same vocabulary as
        // `CT_AGENT_SERVICES`). #382 follow-up: a slug outside the four fixed variants is no
        // longer a hard config error -- it's a real, signed `ServiceType::Custom` declaration
        // (e.g. `static_analysis`), so an operator can offer a pipeline-designer-declared service
        // in a real, buyer-verifiable CapacityOffer without a CADS-Tunnel core release per new
        // service name. `parse_service_type` only returns `None` for an empty token, which the
        // filter below already excludes -- the `None` arm stays as a defensive, never-actually-
        // reached safety net rather than an assumption baked in silently. Absent/empty var =
        // a generic offer (unchanged).
        let services = match f("CT_AGENT_OFFER_SERVICES").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                let mut out = Vec::new();
                for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    match parse_service_type(tok) {
                        Some(st) => out.push(st),
                        None => return Err("CT_AGENT_OFFER_SERVICES has an empty entry (check for a stray comma)".to_string()),
                    }
                }
                out
            }
            _ => Vec::new(),
        };
        Ok(Self {
            signing_key,
            kind,
            models,
            units_available,
            min_price,
            currency_id,
            ttl_secs,
            max_bids_per_window,
            window_secs,
            services,
        })
    }

    /// Assemble + sign the offer (`issued_at = now`, `expires_at = now + ttl_secs`). The clock is a
    /// parameter so the assembly is deterministic + testable, exactly like [`AgentCardCliConfig::build_card`].
    pub fn build_offer(&self, now: u64) -> ct_common::channel::CapacityOffer {
        // #167: when a service catalog is declared, sign it into the offer (so a buyer can
        // cryptographically verify which services the agent offers, and `#149-A.1`'s `match_offer`
        // service filter actually has something to enforce). An empty catalog keeps the historical
        // generic offer (`sign_new`) so nothing changes for offers that make no service claims.
        if self.services.is_empty() {
            ct_common::channel::CapacityOffer::sign_new(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
            )
        } else {
            ct_common::channel::CapacityOffer::sign_new_with_services(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
                self.services.clone(),
            )
        }
    }
}

/// Parse `CT_AGENT_CARD_SKILLS`: `;`-separated entries, each `id|description` (a bare `id`
/// yields an empty description). Empty/blank entries are dropped. Examples are left empty —
/// the card is a discovery advertisement, not an invocation contract.
fn parse_card_skills(s: &str) -> Vec<ct_common::channel::Skill> {
    s.split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|entry| {
            let (id, description) = match entry.split_once('|') {
                Some((i, d)) => (i.trim().to_string(), d.trim().to_string()),
                None => (entry.to_string(), String::new()),
            };
            ct_common::channel::Skill { id, description, examples: Vec::new() }
        })
        .collect()
}

/// Parse a comma-separated list of 64-hex tokens into `[u8; 32]`s. Returns the first
/// malformed token as `Err` so the caller can name the offending field.
fn parse_hex32_ids(s: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        out.push(hex32(tok).ok_or_else(|| tok.to_string())?);
    }
    Ok(out)
}

/// Configuration for the `ct-agent channel` runner (#98/#100), read from the
/// environment so the whole thing fits a copy-paste one-liner. The peer's transport
/// cert and Noise key travel as hex (as the broker/CP will hand them over); Noise_IK
/// is the real mutual authentication, so the QUIC cert is only the transport anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRunConfig {
    pub role: ChannelRole,
    /// Responder: the address to bind. Initiator: the peer address to dial.
    pub addr: SocketAddr,
    /// This agent's member Noise (X25519) private key.
    pub own_noise_private: [u8; 32],
    /// The peer's member Noise public key (pinned by the initiator).
    pub peer_noise_public: [u8; 32],
    /// Initiator only: the peer responder's QUIC cert (DER) to trust for the dial.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl ChannelRunConfig {
    /// Parse from the process environment (`CT_CHANNEL_*`).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key→value lookup (testable without touching real env).
    /// Required: `CT_CHANNEL_ROLE` (initiate|accept), `CT_CHANNEL_ADDR` (host:port),
    /// `CT_CHANNEL_NOISE_KEY` + `CT_CHANNEL_PEER_NOISE_KEY` (64 hex each). For
    /// `initiate`, `CT_CHANNEL_PEER_CERT` (hex DER of the responder's cert) is required.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = f("CT_CHANNEL_ADDR")
            .ok_or("CT_CHANNEL_ADDR required (host:port)")?
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("CT_CHANNEL_ADDR invalid: {e}"))?;
        let own_noise_private = f("CT_CHANNEL_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_NOISE_KEY required (64 hex chars)")?;
        let peer_noise_public = f("CT_CHANNEL_PEER_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_PEER_NOISE_KEY required (64 hex chars)")?;
        // Optional: pin the peer's transport cert. Omit it and the initiator dials
        // accept-any (Noise_IK authenticates), which keeps the one-liner self-contained.
        let peer_cert_der = match f("CT_CHANNEL_PEER_CERT").filter(|s| !s.trim().is_empty()) {
            Some(h) => Some(hex_bytes(&h).ok_or("CT_CHANNEL_PEER_CERT must be hex DER")?),
            None => None,
        };
        Ok(Self { role, addr, own_noise_private, peer_noise_public, peer_cert_der })
    }
}

/// Run the `ct-agent channel` subcommand: bring up this agent as one side of an A2A
/// channel and pipe **stdin/stdout** over the encrypted tunnel (#98/#100). The
/// responder binds `addr` and prints its cert (hex) so the initiator can trust the
/// direct path; the initiator dials `addr` trusting the configured peer cert. The
/// real mutual auth is the Noise_IK session keyed on the member Noise keys.
pub async fn run_channel_command(cfg: ChannelRunConfig) -> Result<(), BoxError> {
    let local = channel_local();
    match cfg.role {
        ChannelRole::Accept => {
            let (endpoint, cert) = crate::transport::build_direct_listener_at(cfg.addr)?;
            eprintln!(
                "ct-agent channel: listening on {} (responder); peer must set \
                 CT_CHANNEL_PEER_CERT={}",
                cfg.addr,
                hex_encode(cert.as_ref())
            );
            let conn = endpoint
                .accept()
                .await
                .ok_or("channel endpoint closed with no incoming")?
                .await?;
            run_channel_session(
                &conn,
                ChannelRole::Accept,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
        ChannelRole::Initiate => {
            // Pin the peer's transport cert if one was supplied; otherwise dial with
            // the accept-any channel dialer — Noise_IK is the real auth, so no cert
            // needs to be conveyed (self-contained one-liner, #100).
            let conn = match cfg.peer_cert_der.clone() {
                Some(der) => crate::transport::dial_quic(cfg.addr, CertificateDer::from(der)).await?,
                None => {
                    let endpoint = crate::transport::build_channel_dialer()?;
                    endpoint.connect(cfg.addr, "localhost")?.await?
                }
            };
            eprintln!("ct-agent channel: connected to {} (initiator)", cfg.addr);
            run_channel_session(
                &conn,
                ChannelRole::Initiate,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Test helper: accept exactly one full QUIC connection on `server` (both stages —
    /// `Incoming` then the handshake-completing `Connecting` — matching the pattern
    /// `stub_broker_admit` above already establishes) within `timeout`, and report whether
    /// one arrived. The accepted `Connection` (and the `Endpoint` itself) is held alive for
    /// the caller-supplied `hold` duration afterward, since a dropped `Endpoint` starts
    /// tearing down in-flight connections immediately.
    async fn accept_one_and_hold(server: Endpoint, timeout: Duration, hold: Duration) -> bool {
        let incoming = match tokio::time::timeout(timeout, server.accept()).await {
            Ok(Some(incoming)) => incoming,
            _ => return false,
        };
        let got = incoming.await.is_ok();
        tokio::time::sleep(hold).await;
        got
    }

    #[test]
    fn reflexive_query_addr_derives_port_4433_by_default_or_honors_an_override() {
        // #248/#238: same host as the relay-gate, this deployment's stable QUIC port,
        // unless an operator overrides it entirely via CT_CHANNEL_REFLEXIVE_EDGE.
        let relay_gate: SocketAddr = "203.0.113.9:443".parse().unwrap();
        assert_eq!(
            reflexive_query_addr(relay_gate, None).unwrap(),
            "203.0.113.9:4433".parse::<SocketAddr>().unwrap(),
            "defaults to the relay-gate's host on the stable QUIC port"
        );
        assert_eq!(
            reflexive_query_addr(relay_gate, Some("")).unwrap(),
            "203.0.113.9:4433".parse::<SocketAddr>().unwrap(),
            "an empty override is treated the same as unset"
        );
        assert_eq!(
            reflexive_query_addr(relay_gate, Some("198.51.100.1:9999")).unwrap(),
            "198.51.100.1:9999".parse::<SocketAddr>().unwrap(),
            "an explicit override wins entirely, including a different host"
        );
        assert!(reflexive_query_addr(relay_gate, Some("not-an-addr")).is_err(), "malformed override is rejected");
    }

    /// Test-only "edge": accepts one QUIC connection and answers exactly the 'W' whoami
    /// wire protocol `discover_udp_reflexive` speaks -- a minimal, from-scratch echo (not
    /// a reuse of the real edge's `serve_connection`, which lives in a separate crate/repo)
    /// so this test exercises ct-agent's OWN client-side protocol handling in isolation.
    async fn serve_one_whoami_echo(server: Endpoint) {
        let incoming = server.accept().await.expect("one connection arrives");
        let conn = incoming.await.expect("handshake completes");
        let remote = conn.remote_address();
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opens a bi stream");
        let mut role = [0u8; 1];
        recv.read_exact(&mut role).await.expect("role byte");
        assert_eq!(role[0], b'W', "discover_udp_reflexive must send the 'W' role byte");
        let addr = remote.to_string();
        let bytes = addr.as_bytes();
        send.write_all(&[bytes.len() as u8]).await.expect("write len");
        send.write_all(bytes).await.expect("write addr");
        send.finish().unwrap();
        // Give the response a moment to actually reach the client before this task (and
        // the `Endpoint`/`Connection` it owns) drops -- dropping immediately after
        // `finish()` can race the client's read with the connection teardown. Not
        // `conn.closed().await`: the client (production `discover_udp_reflexive`) never
        // explicitly closes, it just drops its own endpoint/connection at the end of its
        // async block, so waiting for a graceful close here could hang indefinitely.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn discover_udp_reflexive_queries_the_edges_whoami_echo() {
        use ct_edge::transport::build_server_endpoint_with_cert;

        let (server, _cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(serve_one_whoami_echo(server));

        let reported = discover_udp_reflexive(addr, Duration::from_secs(2))
            .await
            .expect("the edge answered with an observed address");
        assert_eq!(
            reported.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "reports the loopback address this in-process test actually dials from"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn discover_udp_reflexive_returns_none_when_the_edge_is_unreachable() {
        // A bound-then-dropped UDP socket's address: nothing is listening there.
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable = probe.local_addr().unwrap();
        drop(probe);

        assert!(
            discover_udp_reflexive(unreachable, Duration::from_millis(500)).await.is_none(),
            "an unreachable edge yields None, never an error the caller has to handle"
        );
    }

    #[tokio::test]
    async fn discover_udp_reflexive_returns_none_on_timeout_not_a_hang() {
        // A server that accepts the connection but never answers -- discover_udp_reflexive
        // must still return within its own bounded timeout, not hang forever.
        use ct_edge::transport::build_server_endpoint_with_cert;

        let (server, _cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().unwrap();
        let _hold = tokio::spawn(accept_one_and_hold(server, Duration::from_secs(2), Duration::from_secs(2)));

        let started = std::time::Instant::now();
        let result = discover_udp_reflexive(addr, Duration::from_millis(300)).await;
        assert!(result.is_none(), "no reply within the timeout -> None");
        assert!(started.elapsed() < Duration::from_secs(1), "bounded by its own timeout, not the server's hold");
    }

    #[tokio::test]
    async fn dial_relay_preferring_direct_uses_the_direct_address_when_it_is_reachable() {
        // #276: "always look for direct communication; relay is only the last line of
        // defense" -- when a direct address is configured AND reachable, it must be used,
        // never the fallback (e.g. a same-network super-peer relay), even though the
        // fallback is also live and would happily accept the connection.
        use ct_edge::transport::build_server_endpoint_with_cert;

        let (direct_server, _cert) = build_server_endpoint_with_cert().expect("direct server");
        let direct_addr = direct_server.local_addr().unwrap();
        let (fallback_server, _cert2) = build_server_endpoint_with_cert().expect("fallback server");
        let fallback_addr = fallback_server.local_addr().unwrap();

        let direct_hit = tokio::spawn(accept_one_and_hold(direct_server, Duration::from_secs(2), Duration::from_millis(300)));
        // The fallback server is live too, but must never receive a connection in this test.
        let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_millis(400), Duration::ZERO));

        let conn = dial_relay_preferring_direct(Some(direct_addr), fallback_addr, Duration::from_secs(2))
            .await
            .expect("dials the direct address");
        assert!(conn.close_reason().is_none(), "connection is live");

        assert!(direct_hit.await.unwrap(), "the direct server received the connection");
        assert!(!fallback_hit.await.unwrap(), "the fallback server never saw a connection attempt");
    }

    #[tokio::test]
    async fn dial_relay_preferring_direct_falls_back_when_the_direct_address_is_unreachable() {
        // A direct address with nothing listening (a closed UDP port) must not hang or
        // error the whole dial -- it falls through to the fallback within a bounded time.
        use ct_edge::transport::build_server_endpoint_with_cert;

        let (fallback_server, _cert) = build_server_endpoint_with_cert().expect("fallback server");
        let fallback_addr = fallback_server.local_addr().unwrap();
        let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_secs(3), Duration::from_millis(300)));

        // A bound-then-dropped UDP socket's address: nothing is listening there, so a QUIC
        // handshake attempt to it will not complete.
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable = probe.local_addr().unwrap();
        drop(probe);

        let conn = dial_relay_preferring_direct(Some(unreachable), fallback_addr, Duration::from_millis(500))
            .await
            .expect("falls back to the reachable address");
        assert!(conn.close_reason().is_none(), "connection to the fallback is live");
        assert!(fallback_hit.await.unwrap(), "the fallback server received the connection after the direct attempt failed");
    }

    #[tokio::test]
    async fn dial_relay_preferring_direct_with_no_direct_address_dials_the_fallback_immediately() {
        use ct_edge::transport::build_server_endpoint_with_cert;

        let (fallback_server, _cert) = build_server_endpoint_with_cert().expect("fallback server");
        let fallback_addr = fallback_server.local_addr().unwrap();
        let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_secs(2), Duration::from_millis(300)));

        let conn = dial_relay_preferring_direct(None, fallback_addr, Duration::from_secs(2))
            .await
            .expect("dials the fallback directly");
        assert!(conn.close_reason().is_none());
        assert!(fallback_hit.await.unwrap());
    }

    #[test]
    fn dcutr_loop_action_a_persistent_serve_member_always_loops_regardless_of_outcome() {
        // #248: the actual bug -- a completed session (Ok) used to fall through to an
        // unconditional Stop even when serve_loop was true, silently ending the whole
        // process after exactly one session. A persistent serve member must ALWAYS loop
        // back (reset the one-shot counter), whether the session succeeded or errored.
        assert_eq!(dcutr_loop_action(true, true, 0, 2), DcutrLoopAction::RetryReset, "Ok + serve_loop -> keep serving");
        assert_eq!(dcutr_loop_action(false, true, 0, 2), DcutrLoopAction::RetryReset, "Err + serve_loop -> re-admit");
        // Even with the one-shot retry budget already exhausted, serve_loop still wins --
        // that budget is only ever relevant to a ONE-SHOT caller.
        assert_eq!(dcutr_loop_action(false, true, 99, 2), DcutrLoopAction::RetryReset, "serve_loop ignores the one-shot budget entirely");
    }

    #[test]
    fn dcutr_loop_action_a_one_shot_caller_retries_errors_up_to_the_bound_then_stops() {
        assert_eq!(dcutr_loop_action(false, false, 0, 2), DcutrLoopAction::RetryBounded { next_attempt: 1 });
        assert_eq!(dcutr_loop_action(false, false, 1, 2), DcutrLoopAction::RetryBounded { next_attempt: 2 });
        // At the bound, no more retries -- stop and return the (error) result.
        assert_eq!(dcutr_loop_action(false, false, 2, 2), DcutrLoopAction::Stop, "budget exhausted -> stop");
    }

    #[test]
    fn dcutr_loop_action_a_one_shot_callers_success_always_stops_immediately() {
        // A one-shot caller (--call-service, or Accept without --serve) that succeeds must
        // terminate right away -- it never loops just because it COULD have retried.
        assert_eq!(dcutr_loop_action(true, false, 0, 2), DcutrLoopAction::Stop);
        assert_eq!(dcutr_loop_action(true, false, 2, 2), DcutrLoopAction::Stop);
    }

    fn cfg_from(pairs: &[(&str, &str)]) -> Result<ChannelRunConfig, String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        ChannelRunConfig::from_lookup(|k| map.get(k).cloned())
    }

    const K64: &str = "aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20";

    #[test]
    fn agent_card_cli_config_parses_and_writes_a_verifiable_card() {
        // #144 ①-wiring CLI (frozen): the runnable `channel agent-card` path parses
        // CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_* into a signed card and drops it at the RFC-8615
        // well-known path — closing the emit chain with no hand-rolled ed25519. The written file
        // round-trips to a card whose holder signature verifies, bound to the CLI-supplied key.
        use ct_common::channel::AgentCard;

        let dir = std::env::temp_dir().join(format!("ct-agent-card-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chan = "9b".repeat(32);
        let pairs = [
            ("CT_CHANNEL_HOLDER_KEY", K64),
            ("CT_AGENT_CARD_ROLES", "central, orchestrator"),
            ("CT_AGENT_CARD_SKILLS", "orchestrate_task|coordinate an agent network; fire_transfer"),
            ("CT_AGENT_CARD_CHANNELS", chan.as_str()),
            ("CT_AGENT_CARD_TTL_SECS", "4000"),
            ("CT_AGENT_CARD_OUT", dir.to_str().unwrap()),
        ];
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let cfg = AgentCardCliConfig::from_lookup(|k| map.get(k).cloned()).expect("parses");

        // Claims parsed as expected (CSV roles; `id|desc` and bare-`id` skills; TTL).
        assert_eq!(cfg.role_tags, vec!["central".to_string(), "orchestrator".to_string()]);
        assert_eq!(cfg.skills.len(), 2);
        assert_eq!(cfg.skills[0].id, "orchestrate_task");
        assert_eq!(cfg.skills[0].description, "coordinate an agent network");
        assert_eq!(cfg.skills[1].id, "fire_transfer", "a bare id (no |) is allowed");
        assert_eq!(cfg.skills[1].description, "");
        assert_eq!(cfg.channels.len(), 1);
        assert_eq!(cfg.ttl_secs, 4000);

        // Write + read back: a verifiable card bound to the CLI holder key, at the well-known path.
        let path = cfg.write_card(1_000).expect("writes the card");
        assert!(path.ends_with(".well-known/agent-card.json"), "RFC-8615 path, got {path:?}");
        let back: AgentCard = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("parses");
        assert!(back.is_valid(1_000), "the written card verifies");
        assert!(!back.is_valid(5_000), "expires at issued+ttl = 5000");
        let holder_pub = SigningKey::from_bytes(&hex32(K64).unwrap()).verifying_key().to_bytes();
        assert_eq!(back.holder_pubkey, holder_pub, "bound to the CLI-supplied holder key");
        assert_eq!(back.role_tags, cfg.role_tags);
        let _ = std::fs::remove_dir_all(&dir);

        // Missing roles → error; a bad holder key → error.
        let no_roles: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", K64)]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert!(AgentCardCliConfig::from_lookup(|k| no_roles.get(k).cloned()).is_err(), "roles required");
        let bad_key: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", "zz"), ("CT_AGENT_CARD_ROLES", "central")]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert!(AgentCardCliConfig::from_lookup(|k| bad_key.get(k).cloned()).is_err(), "bad holder key rejected");
    }

    #[test]
    fn agent_card_auto_register_is_opt_in_by_presence_of_all_three_vars() {
        // #214 follow-up: auto-registration only activates when CT_AGENT_CP_URL,
        // CT_AGENT_CARD_URL, AND CT_CP_EDGE_ADMIN_TOKEN are ALL present — any one missing means
        // "unchanged behavior" (card written locally only), never a partial/guessed registration.
        let all: HashMap<String, String> = [
            ("CT_AGENT_CP_URL", "https://bunsenbrenner.org"),
            ("CT_AGENT_CARD_URL", "https://you.example/.well-known/agent-card.json"),
            ("CT_CP_EDGE_ADMIN_TOKEN", "deadbeef"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let reg = AgentCardAutoRegister::from_lookup(|k| all.get(k).cloned()).expect("all three present");
        assert_eq!(reg.cp_url, "https://bunsenbrenner.org");
        assert_eq!(reg.card_url, "https://you.example/.well-known/agent-card.json");
        assert_eq!(reg.admin_token, "deadbeef");

        for missing in ["CT_AGENT_CP_URL", "CT_AGENT_CARD_URL", "CT_CP_EDGE_ADMIN_TOKEN"] {
            let mut partial = all.clone();
            partial.remove(missing);
            assert!(
                AgentCardAutoRegister::from_lookup(|k| partial.get(k).cloned()).is_none(),
                "missing {missing} -> no auto-registration, not a best-effort partial call"
            );
        }
        assert!(AgentCardAutoRegister::from_lookup(|_| None).is_none());
    }

    #[tokio::test]
    async fn serve_local_answers_framed_requests_as_a_persistent_service() {
        // #135 L2.1-cli (frozen): serve-mode local turns the channel's app duplex into a persistent
        // request/response SERVICE — the pump-driven session side accepts framed requests and gets
        // the handler's framed responses back, MANY times over ONE duplex (not one-shot pipe). The
        // handler here upper-cases (a stand-in for the L2.3 MCP dispatch that replaces the echo).
        use ct_common::noise::{frame, read_frame};

        let mut local = serve_local(|req: Vec<u8>| async move { req.to_ascii_uppercase() });
        for msg in [&b"one"[..], b"two", b"three"] {
            local.write_all(&frame(msg)).await.expect("write request frame");
            let resp = read_frame(&mut local).await.expect("read response frame");
            assert_eq!(
                resp,
                msg.to_ascii_uppercase(),
                "each framed request is answered over the one persistent session-side duplex"
            );
        }
    }

    #[tokio::test]
    async fn mcp_call_over_invokes_a_serve_local_peer_and_returns_its_response() {
        // #135 L2.3 (frozen): the --call client (mcp_call_over) invokes a --serve peer's MCP endpoint
        // and gets its answer back — the full call↔serve pair over one duplex (the pump would carry
        // exactly these bytes encrypted). Client sends `tools/call ping`, the peer's registry → pong.
        let registry = std::sync::Arc::new(ct_common::mcp::default_registry());
        let server = serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            async move { registry.dispatch(&req) }
        });
        // The server's session side IS a request→response endpoint (write a request, read its reply).
        let (mut r, mut w) = tokio::io::split(server);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            mcp_call_over(&mut w, &mut r, "tools/call", serde_json::json!({ "name": "ping" })),
        )
        .await
        .expect("a response within 2s")
        .expect("got a response");

        let decoded = ct_common::mcp::decode_response(&response).expect("valid JSON-RPC response");
        assert_eq!(
            decoded.result.unwrap(),
            serde_json::json!({ "reply": "pong" }),
            "the peer's ping tool answered the client's call over the pair"
        );
        assert!(decoded.error.is_none());
    }

    #[test]
    fn channel_identity_generates_self_service_keys_the_cli_accepts() {
        // #117-cli-identity (frozen): a participant mints a fresh channel identity
        // LOCALLY, and the emitted hex is exactly what the `ct-agent channel` CLI
        // consumes — so no hand-crafted keys and no central provisioning are needed to
        // get channel crypto material. Round-trip the generated holder + Noise keys
        // through the real `from_lookup` parser.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;

        let id = ChannelIdentity::generate();
        assert_eq!(id.holder_key_hex().len(), 64, "holder private is 64 hex");
        assert_eq!(id.noise_key_hex().len(), 64, "Noise private is 64 hex");
        assert_eq!(id.holder_pubkey_hex().len(), 64, "holder public is 64 hex");
        assert_eq!(id.noise_pubkey_hex().len(), 64, "Noise public is 64 hex");

        // An operator signs a grant over the generated holder public key.
        let op = SigningKey::from_bytes(&[9u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xC7u8; 32]),
            holder: id.holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex =
            hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());

        let pairs: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", id.holder_key_hex()),
            ("CT_CHANNEL_NOISE_KEY", id.noise_key_hex()),
        ];
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
            .expect("the CLI accepts a self-generated channel identity");

        // The parsed keys ARE the generated ones — the generator's output is exactly
        // what the CLI consumes, so self-service key generation needs nothing hand-crafted.
        assert_eq!(cfg.holder.to_bytes(), id.holder.to_bytes(), "holder key round-trips through the CLI");
        assert_eq!(cfg.own_noise_private, id.noise.private, "Noise key round-trips through the CLI");
        assert_eq!(
            cfg.grant.grant.holder,
            id.holder.verifying_key().to_bytes(),
            "the grant binds the generated holder public key"
        );

        // Two mints differ — real randomness, not a fixed/default key.
        let id2 = ChannelIdentity::generate();
        assert_ne!(id.holder.to_bytes(), id2.holder.to_bytes(), "holder keys are unique per mint");
        assert_ne!(id.noise.private, id2.noise.private, "Noise keys are unique per mint");
    }

    #[test]
    fn front_door_only_drops_the_direct_quic_rung_and_requires_a_front_door_16() {
        // #16 ("UDP flapping"): CT_CHANNEL_FRONT_DOOR_ONLY pins the dial ladders to the
        // TLS-TCP `:443` front door — no direct QUIC rung at all — and is refused at
        // parse time without a usable front door (addr + cert), because a ladder with
        // zero rungs would fail every join with an unhelpful error.
        let direct: SocketAddr = "203.0.113.5:9443".parse().unwrap();
        let fd: SocketAddr = "203.0.113.5:443".parse().unwrap();

        // Default order unchanged: direct first, then the two :443 rungs.
        let rungs = ChannelJoinCliConfig::ladder(direct, Some(fd), false);
        assert_eq!(rungs.len(), 3, "default ladder keeps all three rungs");
        assert!(matches!(rungs[0].kind, ChannelDialKind::Direct), "direct QUIC dials first by default");

        // Front-door-only: exactly the two :443 rungs, nothing dials UDP.
        let rungs = ChannelJoinCliConfig::ladder(direct, Some(fd), true);
        assert_eq!(rungs.len(), 2, "front-door-only drops the direct rung");
        assert!(
            rungs.iter().all(|r| r.kind.is_front_door() && r.endpoint == fd),
            "every remaining rung is a :443 front-door dial"
        );

        // Without a configured front door the flag never yields an empty ladder
        // (belt-and-suspenders — the parse guard below refuses the combination first).
        let rungs = ChannelJoinCliConfig::ladder(direct, None, true);
        assert_eq!(rungs.len(), 1, "no front door -> the direct rung survives");

        // Parse guard: FRONT_DOOR_ONLY without FRONT_DOOR(+_CERT) is a clear error.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;
        let id = ChannelIdentity::generate();
        let op = SigningKey::from_bytes(&[9u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0x5Du8; 32]),
            holder: id.holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex = hex_encode(
            &SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode(),
        );
        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", id.holder_key_hex()),
            ("CT_CHANNEL_NOISE_KEY", id.noise_key_hex()),
            ("CT_CHANNEL_FRONT_DOOR_ONLY", "1".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> =
                pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        };
        let err = lookup(&base).err().expect("FRONT_DOOR_ONLY without a front door is refused");
        assert!(
            err.contains("CT_CHANNEL_FRONT_DOOR_ONLY"),
            "the error names the flag and what it needs, got: {err}"
        );

        // With both front-door values present the flag parses and the ladders obey it.
        let mut full = base.clone();
        full.push(("CT_CHANNEL_FRONT_DOOR", "203.0.113.5:443".into()));
        full.push(("CT_CHANNEL_FRONT_DOOR_CERT", "aa".into())); // any hex DER parses here
        let cfg = lookup(&full).expect("a usable front door satisfies the guard");
        assert!(cfg.front_door_only);
        assert!(
            cfg.broker_ladder().iter().all(|r| r.kind.is_front_door()),
            "the broker ladder is :443-only under the flag"
        );
        assert!(
            cfg.relay_ladder().iter().all(|r| r.kind.is_front_door()),
            "the relay ladder is :443-only under the flag"
        );
    }

    #[test]
    fn channel_identity_env_block_exports_the_keys_the_cli_reads() {
        // #117-cli-subcommand (frozen): `ct-agent channel init` prints this block; it must
        // `export` exactly the two private-key env vars the CLI consumes, surface the two
        // public keys (for the operator), and be safe to `eval` (only comments + exports).
        let id = ChannelIdentity::generate();
        let block = id.env_block();

        assert!(
            block.contains(&format!("export CT_CHANNEL_HOLDER_KEY={}", id.holder_key_hex())),
            "exports the holder private key the CLI reads"
        );
        assert!(
            block.contains(&format!("export CT_CHANNEL_NOISE_KEY={}", id.noise_key_hex())),
            "exports the Noise private key the CLI reads"
        );
        assert!(block.contains(&id.holder_pubkey_hex()), "surfaces the holder public key for the operator");
        assert!(block.contains(&id.noise_pubkey_hex()), "surfaces the Noise public key for the operator");

        // Safe to `eval`: every non-blank line is a comment or an `export`.
        for line in block.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with('#') || line.starts_with("export "),
                "every line is a comment or an export, got {line:?}"
            );
        }
    }

    #[test]
    fn operator_issues_a_grant_the_edge_verifies_and_the_member_cli_accepts() {
        // #117-operator-flow (frozen): the create-side crypto. An operator mints a key
        // locally and signs a member's grant over the member's `channel init` holder
        // public key; the edge verifies that grant under the operator's PUBLIC key, and
        // the member CLI accepts it alongside the member's self-generated keys — closing
        // the self-service loop (operator issues -> member joins) with no central step.
        use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let channel = ChannelId([0x5Eu8; 32]);
        let holder_pub = member.holder.verifying_key().to_bytes();

        let grant_hex = op.issue_member_grant(channel, holder_pub, Direction::Initiate, 1_000);

        // The issued grant decodes + verifies under the operator public key, exactly as
        // the edge's admission gate does, and binds the member's holder + channel.
        let signed = SignedChannelGrant::decode(&hex_bytes(&grant_hex).expect("grant hex")).expect("decode");
        let op_pub = op.key.verifying_key().to_bytes();
        assert!(
            ct_common::channel::verify(&op_pub, &signed, 500).is_ok(),
            "the edge verifies the operator-issued grant under the operator key"
        );
        assert_eq!(signed.grant.holder, holder_pub, "grant binds the member's holder pubkey");
        assert_eq!(signed.grant.channel, channel, "grant is for the intended channel");

        // End-to-end: the member CLI accepts the operator-issued grant + the member's own
        // (`channel init`) keys — nothing hand-crafted, no central provisioning.
        let pairs: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", member.holder_key_hex()),
            ("CT_CHANNEL_NOISE_KEY", member.noise_key_hex()),
        ];
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
            .expect("member CLI accepts the operator-issued grant + self-generated keys");
        assert_eq!(cfg.grant.grant.holder, holder_pub, "the CLI's grant binds the member's holder");

        // Operator key hex round-trips to 64-hex private + public.
        assert_eq!(op.key_hex().len(), 64);
        assert_eq!(op.pubkey_hex().len(), 64);
    }

    #[test]
    fn operator_mints_a_staple_the_cache_accepts_and_only_the_operator_can_mint() {
        // #121 E-fail-static (frozen): the operator — holding the key LOCALLY (invariant #6)
        // — mints a short-lived membership staple that a peer's StapleCache accepts under the
        // operator PUBLIC key, admitting the member offline until the TTL. Central never holds
        // the key, so a foreign key can neither mint nor forge a staple the cache would trust:
        // a central compromise degrades to DoS/metadata, never impersonation.
        use ct_common::channel::{ChannelId, StapleCache};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let channel = ChannelId([0x77u8; 32]);
        let holder_pub = member.holder.verifying_key().to_bytes();
        let op_pub = op.key.verifying_key().to_bytes();

        // Operator mints a staple at t=1000 for a 3600s TTL (→ expires 4600).
        let staple = op.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
        assert_eq!(staple.expires_at, 4_600, "expires_at = stapled_at + ttl_secs");

        // A peer caches it under the operator PUBLIC key and admits the member offline...
        let mut cache = StapleCache::new();
        assert!(cache.refresh(&op_pub, staple, 1_000), "the cache accepts the operator's staple");
        assert!(
            cache.is_member(&op_pub, &channel, &holder_pub, 4_000),
            "the member is admitted from cache with no central round-trip (fail-static)"
        );
        // ...and it lapses at the TTL (revocation latency = TTL, invariant #7).
        assert!(
            !cache.is_member(&op_pub, &channel, &holder_pub, 4_600),
            "the cached staple lapses at expires_at"
        );

        // Invariant #6: a FOREIGN operator's staple for the same member is not trusted under
        // this channel's operator key — only the local-key holder can mint an admissible staple.
        let foreign = OperatorIdentity::generate();
        let forged = foreign.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
        let mut cache2 = StapleCache::new();
        assert!(
            !cache2.refresh(&op_pub, forged, 1_000),
            "a staple minted by a different key is rejected — central (keyless) can't forge one (#6)"
        );
    }

    #[test]
    fn operator_compiles_an_overlay_plan_into_verifiable_per_link_grants() {
        // #107-nway (frozen): the controller compiles a topology's overlay links into
        // concrete A2A channels — each link becomes a derived ChannelId plus the two
        // operator-signed grants its members present. The two grants of a link verify under
        // the operator key, bind distinct holders + the same channel, and split
        // Initiate/Accept — exactly what the broker's admission pairing expects. An
        // unmapped node id fails the whole compile (can't wire a link without both keys).
        use ct_common::channel::{channel_id_for_link, verify, Direction};
        use ct_common::overlay::OverlayPlan;

        let op = OperatorIdentity::generate();
        let op_pub = op.key.verifying_key().to_bytes();
        // Three agents a<b<c with distinct holder keys; a line overlay a—b—c.
        let holders = |id: &str| -> Option<[u8; 32]> {
            match id {
                "a" => Some([0xa1u8; 32]),
                "b" => Some([0xb2u8; 32]),
                "c" => Some([0xc3u8; 32]),
                _ => None,
            }
        };
        let plan = OverlayPlan {
            links: vec![("a".into(), "b".into()), ("b".into(), "c".into())],
            total_cost: 0,
            connected: true,
        };

        let compiled = op
            .compile_overlay_grants(&plan, holders, 5_000)
            .expect("every node id maps to a holder");
        assert_eq!(compiled.len(), 2, "one compiled channel per overlay link");

        // Link a—b: the derived channel matches channel_id_for_link, both grants verify
        // under the operator key, bind distinct holders + the SAME channel, and split roles.
        let ab = &compiled[0];
        assert_eq!(
            ab.channel,
            channel_id_for_link(&op_pub, &[0xa1u8; 32], &[0xb2u8; 32]),
            "the link's channel is the deterministic per-link derivation"
        );
        assert!(verify(&op_pub, &ab.initiator_grant, 1_000).is_ok(), "initiator grant verifies");
        assert!(verify(&op_pub, &ab.acceptor_grant, 1_000).is_ok(), "acceptor grant verifies");
        assert_eq!(ab.initiator_grant.grant.channel, ab.channel, "initiator grant is for this channel");
        assert_eq!(ab.acceptor_grant.grant.channel, ab.channel, "acceptor grant is for this channel");
        assert_eq!(ab.initiator_grant.grant.holder, [0xa1u8; 32]);
        assert_eq!(ab.acceptor_grant.grant.holder, [0xb2u8; 32]);
        assert_ne!(
            ab.initiator_grant.grant.holder, ab.acceptor_grant.grant.holder,
            "the two grants bind distinct holders (an agent can't channel to itself)"
        );
        assert!(ab.initiator_grant.grant.direction.permits(Direction::Initiate));
        assert!(ab.acceptor_grant.grant.direction.permits(Direction::Accept));

        // The two links share agent b but are DISTINCT channels (per-link isolation).
        assert_ne!(compiled[0].channel, compiled[1].channel, "distinct links are distinct channels");

        // A plan naming an unmapped agent can't be wired — the whole compile fails, loudly,
        // with the offending node id (no partially-wired overlay).
        let bad = OverlayPlan {
            links: vec![("a".into(), "z".into())],
            total_cost: 0,
            connected: false,
        };
        assert_eq!(
            op.compile_overlay_grants(&bad, holders, 5_000),
            Err("z".to_string()),
            "an unmapped node id fails the compile with that id"
        );
    }

    #[test]
    fn member_material_computes_verifiable_channel_id_and_attestation() {
        // #207 Slice A (frozen): the member-material helper derives the member's channel_id + a
        // holder-signed noise attestation that VERIFY against the canonical primitives — so the block
        // a member posts is exactly what the operator/edge will accept.
        use ct_common::channel::{channel_id_for_link, verify_member_noise_attestation};
        let operator = [0x1eu8; 32];
        let bridge = [0xe1u8; 32];
        let holder_seed = [0x55u8; 32];
        let holder = SigningKey::from_bytes(&holder_seed);
        let noise_pub = [0x77u8; 32];
        let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let env = move |k: &str| match k {
            "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
            "CT_CHANNEL_BRIDGE_HOLDER" => Some(hx(&bridge)),
            "CT_CHANNEL_HOLDER_KEY" => Some(hx(&holder_seed)),
            "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
            _ => None,
        };
        let req = MemberMaterialRequest::from_lookup(env).unwrap();
        let (channel, holder_pub, attestation) = req.compute();
        assert_eq!(holder_pub, holder.verifying_key().to_bytes(), "holder pubkey derived from the private key");
        assert_eq!(channel, channel_id_for_link(&operator, &bridge, &holder_pub), "canonical operator-scoped link id");
        assert!(
            verify_member_noise_attestation(&channel, &holder_pub, &noise_pub, &attestation),
            "the emitted attestation verifies against the canonical verifier"
        );
        // the rendered block carries all four values.
        let block = req.render();
        assert!(block.contains(&hx(&channel.0)) && block.contains(&hx(&attestation)) && block.contains(&hx(&noise_pub)));
        // a missing required input errors clearly.
        assert!(MemberMaterialRequest::from_lookup(|_| None).is_err());
    }

    #[test]
    fn pipeline_role_material_computes_verifiable_channel_id_and_attestation_independent_of_counterpart() {
        // #214 follow-up (generic pipeline provisioning): unlike member-material, this needs NO
        // counterpart pubkey — two independent callers (a bridge and a role-serving agent) with
        // the same (operator, pipeline_id, role) must derive the identical channel_id with zero
        // coordination, and each caller's own attestation must verify.
        use ct_common::channel::{channel_id_for_pipeline_role, verify_member_noise_attestation};
        let operator = [0x1eu8; 32];
        let holder_seed = [0x55u8; 32];
        let holder = SigningKey::from_bytes(&holder_seed);
        let noise_pub = [0x77u8; 32];
        let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let env = move |k: &str| match k {
            "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
            "CT_PIPELINE_ID" => Some("flappy-demo".to_string()),
            "CT_PIPELINE_ROLE" => Some("physics".to_string()),
            "CT_CHANNEL_HOLDER_KEY" => Some(hx(&holder_seed)),
            "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
            _ => None,
        };
        let req = PipelineRoleMaterialRequest::from_lookup(env).unwrap();
        let (channel, holder_pub, attestation) = req.compute();
        assert_eq!(holder_pub, holder.verifying_key().to_bytes(), "holder pubkey derived from the private key");
        assert_eq!(
            channel,
            channel_id_for_pipeline_role(&operator, "flappy-demo", "physics"),
            "canonical pipeline-role id — no CT_CHANNEL_BRIDGE_HOLDER (counterpart pubkey) needed at all"
        );
        assert!(
            verify_member_noise_attestation(&channel, &holder_pub, &noise_pub, &attestation),
            "the emitted attestation verifies against the canonical verifier"
        );

        // A second, independent caller for the SAME pipeline role (different holder identity)
        // derives the SAME channel_id — the whole point: no round-trip needed to agree.
        let other_holder_seed = [0x99u8; 32];
        let other_env = move |k: &str| match k {
            "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
            "CT_PIPELINE_ID" => Some("flappy-demo".to_string()),
            "CT_PIPELINE_ROLE" => Some("physics".to_string()),
            "CT_CHANNEL_HOLDER_KEY" => Some(hx(&other_holder_seed)),
            "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
            _ => None,
        };
        let (other_channel, _, _) = PipelineRoleMaterialRequest::from_lookup(other_env).unwrap().compute();
        assert_eq!(channel, other_channel, "same pipeline+role -> same channel, independent of which holder asks");

        // the rendered block carries pipeline_id, role, and all derived values.
        let block = req.render();
        assert!(block.contains("flappy-demo") && block.contains("physics") && block.contains(&hx(&channel.0)));

        // a missing required input errors clearly.
        assert!(PipelineRoleMaterialRequest::from_lookup(|_| None).is_err());
    }

    #[test]
    fn operator_grant_request_parses_env_and_issues_a_verifiable_grant() {
        // #117-operator-flow (frozen): `ct-agent channel grant` parses the operator key +
        // CT_GRANT_* from env and issues a grant that verifies under the operator key and
        // binds the intended member/channel/direction. Required fields are enforced.
        use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

        let op = OperatorIdentity::generate();
        let member = ChannelIdentity::generate();
        let member_holder = member.holder.verifying_key().to_bytes();
        let channel = [0x77u8; 32];

        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_GRANT_MEMBER_HOLDER", hex_encode(&member_holder)),
            ("CT_GRANT_DIRECTION", "accept".into()),
            ("CT_GRANT_EXPIRES", "1000".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            OperatorGrantRequest::from_lookup(move |k| m.get(k).cloned())
        };

        let req = lookup(&base).expect("valid operator grant request parses");
        assert_eq!(req.channel, ChannelId(channel));
        assert_eq!(req.member_holder, member_holder);
        assert_eq!(req.direction, Direction::Accept);

        // The issued grant verifies under the operator key and binds the member.
        let signed = SignedChannelGrant::decode(&hex_bytes(&req.issue()).expect("hex")).expect("decode");
        assert!(
            ct_common::channel::verify(&op.key.verifying_key().to_bytes(), &signed, 500).is_ok(),
            "the issued grant verifies under the operator key"
        );
        assert_eq!(signed.grant.holder, member_holder);
        assert_eq!(signed.grant.channel, ChannelId(channel));
        assert_eq!(signed.grant.direction, Direction::Accept);

        // Each required field is enforced.
        for drop_key in [
            "CT_CHANNEL_OPERATOR_KEY",
            "CT_GRANT_CHANNEL",
            "CT_GRANT_MEMBER_HOLDER",
            "CT_GRANT_DIRECTION",
            "CT_GRANT_EXPIRES",
        ] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }
    }

    #[test]
    fn operator_invite_request_parses_env_and_issues_a_verifiable_invitation() {
        // scimbe/ct-agent#9: `ct-agent channel invite` parses the operator key + CT_INVITE_*
        // from env and issues an invitation that verifies under the operator key and binds the
        // intended invitee identity/channel/direction/rights/delegable/expiry — the cross-
        // account producer `ct_common::channel::verify_invitation`'s consumer side was missing.
        use ct_common::channel::{ChannelId, Direction, Rights, SignedChannelInvitation};

        let op = OperatorIdentity::generate();
        // The invitee is identified by its IDENTITY key here, not a holder key already
        // coordinated with the operator -- generate a bare random "identity" the operator has
        // never otherwise seen, matching the real cross-account use case.
        let invitee_identity: [u8; 32] = {
            use rand::RngCore;
            let mut b = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut b);
            b
        };
        let channel = [0x88u8; 32];

        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
            ("CT_INVITE_CHANNEL", hex_encode(&channel)),
            ("CT_INVITE_IDENTITY", hex_encode(&invitee_identity)),
            ("CT_INVITE_DIRECTION", "initiate".into()),
            ("CT_INVITE_RIGHTS", "read".into()),
            ("CT_INVITE_DELEGABLE", "true".into()),
            ("CT_INVITE_EXPIRES", "1000".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            OperatorInviteRequest::from_lookup(move |k| m.get(k).cloned())
        };

        let req = lookup(&base).expect("valid operator invite request parses");
        assert_eq!(req.channel, ChannelId(channel));
        assert_eq!(req.invitee_identity, invitee_identity);
        assert_eq!(req.direction, Direction::Initiate);
        assert_eq!(req.rights, Rights::Read);
        assert!(req.delegable);

        // The issued invitation verifies under the operator key and binds the invitee identity.
        let signed =
            SignedChannelInvitation::decode(&hex_bytes(&req.issue()).expect("hex")).expect("decode");
        assert!(
            ct_common::channel::verify_invitation(&op.key.verifying_key().to_bytes(), &signed, 500).is_ok(),
            "the issued invitation verifies under the operator key"
        );
        assert_eq!(signed.invitation.invitee_identity, invitee_identity);
        assert_eq!(signed.invitation.channel, ChannelId(channel));
        assert_eq!(signed.invitation.direction, Direction::Initiate);
        assert_eq!(signed.invitation.rights, Rights::Read);
        assert!(signed.invitation.delegable);

        // An invitation must NOT verify as a grant (domain separation) -- decode it as a
        // SignedChannelGrant and confirm `verify` rejects it rather than accepting garbage.
        use ct_common::channel::SignedChannelGrant;
        if let Some(bytes) = hex_bytes(&req.issue()) {
            if let Ok(as_grant) = SignedChannelGrant::decode(&bytes) {
                assert!(
                    ct_common::channel::verify(&op.key.verifying_key().to_bytes(), &as_grant, 500).is_err(),
                    "an invitation's signature must not verify as a grant's"
                );
            }
        }

        // Default rights (unset) is ReadWrite, matching OperatorGrantRequest's fixed default.
        let no_rights: Vec<(&str, String)> =
            base.iter().filter(|(k, _)| *k != "CT_INVITE_RIGHTS").cloned().collect();
        assert_eq!(lookup(&no_rights).expect("rights optional").rights, Rights::ReadWrite);

        // Default delegable (unset) is false.
        let no_delegable: Vec<(&str, String)> =
            base.iter().filter(|(k, _)| *k != "CT_INVITE_DELEGABLE").cloned().collect();
        assert!(!lookup(&no_delegable).expect("delegable optional").delegable);

        // Each required field is enforced.
        for drop_key in [
            "CT_CHANNEL_OPERATOR_KEY",
            "CT_INVITE_CHANNEL",
            "CT_INVITE_IDENTITY",
            "CT_INVITE_DIRECTION",
            "CT_INVITE_EXPIRES",
        ] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }
    }

    #[test]
    fn channel_register_request_parses_env_and_derives_the_operator_pubkey() {
        // #117-operator-register (frozen): `ct-agent channel register` parses the CP URL,
        // channel id, OIDC token, and the operator authority from env — deriving the
        // operator PUBLIC key from CT_CHANNEL_OPERATOR_KEY (never sending the private key),
        // canonicalizing the channel hex, and enforcing the required fields.
        let op = OperatorIdentity::generate();
        let channel = [0x91u8; 32];

        let base: Vec<(&str, String)> = vec![
            ("CT_AGENT_CP_URL", "http://cp:8090".into()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
            ("CT_OIDC_TOKEN", "the-bearer-token".into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelRegisterRequest::from_lookup(move |k| m.get(k).cloned())
        };

        let req = lookup(&base).expect("valid register request parses");
        assert_eq!(req.cp_url, "http://cp:8090");
        assert_eq!(req.channel_hex, hex_encode(&channel), "channel id round-trips as canonical hex");
        assert_eq!(req.token, "the-bearer-token");
        // The operator PRIVATE key is never surfaced — only its derived public key is sent.
        assert_eq!(req.operator_pubkey_hex, op.pubkey_hex(), "derives the operator public key");
        assert_ne!(req.operator_pubkey_hex, op.key_hex(), "the private key is not sent to the CP");

        // The public key may also be supplied directly (CT_CHANNEL_OPERATOR_PUBKEY),
        // without the private key present.
        let pubkey_only: Vec<(&str, String)> = vec![
            ("CT_AGENT_CP_URL", "http://cp:8090".into()),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_CHANNEL_OPERATOR_PUBKEY", op.pubkey_hex()),
            ("CT_OIDC_TOKEN", "tok".into()),
        ];
        assert_eq!(
            lookup(&pubkey_only).expect("pubkey-only parses").operator_pubkey_hex,
            op.pubkey_hex(),
            "an operator pubkey supplied directly is accepted"
        );

        // Each required field is enforced (the operator key OR pubkey must be present).
        for drop_key in ["CT_AGENT_CP_URL", "CT_GRANT_CHANNEL", "CT_CHANNEL_OPERATOR_KEY", "CT_OIDC_TOKEN"] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }
    }

    #[tokio::test]
    async fn dial_ladder_falls_through_to_the_front_door_then_errors_when_all_blocked() {
        // #106-client-dial (frozen): the ladder-walk tries rungs in order and returns the
        // first that connects, so a direct rung blocked by a restrictive network falls
        // back to the :443 front-door rung; it errors only when EVERY rung is blocked.
        let direct = ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct };
        let fd = ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor };

        // Direct blocked -> fall through to the :443 front-door rung.
        let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
            let via = r.kind.is_front_door();
            async move {
                if via { Ok("front-door") } else { Err(ChannelDialError::Unreachable) }
            }
        })
        .await
        .expect("falls back to the front door when the direct port is blocked");
        assert_eq!(picked, "front-door");

        // First success short-circuits: direct connects -> the front door is never tried.
        let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
            let via = r.kind.is_front_door();
            async move {
                assert!(!via, "the front-door rung must not be tried once the direct rung connects");
                Ok("direct")
            }
        })
        .await
        .expect("direct connects on the first rung");
        assert_eq!(picked, "direct");

        // Every rung blocked -> error (all paths down).
        let all_blocked: Result<&str, _> =
            dial_ladder(&[direct, fd], |_r: &ChannelDialRung| async move { Err(ChannelDialError::Unreachable) })
                .await;
        assert!(all_blocked.is_err(), "all rungs blocked surfaces an error");
    }

    #[tokio::test]
    async fn dial_ladder_falls_through_to_the_boring_alpn_rung_when_the_front_door_is_fingerprinted() {
        // #106 boring-alpn: the DPI case from the real 2026-08-12 support call -- a network
        // that fingerprints the distinctive `ct-edge-channel` ALPN / `localhost` SNI drops
        // the front-door rung too, so BOTH earlier rungs fail and the walk must reach the
        // third rung, which dials the SAME :443 endpoint with an ordinary-HTTPS ClientHello.
        let fd_addr: SocketAddr = "203.0.113.5:443".parse().unwrap();
        let rungs = ChannelJoinCliConfig::ladder("203.0.113.5:9443".parse().unwrap(), Some(fd_addr), false);

        let tried = std::sync::Arc::new(std::sync::Mutex::new(Vec::<ChannelDialKind>::new()));
        let seen = tried.clone();
        let picked: SocketAddr = dial_ladder(&rungs, |r: &ChannelDialRung| {
            let (kind, endpoint) = (r.kind, r.endpoint);
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(kind);
                // Everything but the boring ClientHello is blocked/fingerprinted.
                match kind {
                    ChannelDialKind::FrontDoorBoring => Ok(endpoint),
                    _ => Err(ChannelDialError::Unreachable),
                }
            }
        })
        .await
        .expect("the boring-ALPN rung carries the join when the other two are blocked");

        assert_eq!(picked, fd_addr, "the boring rung dials the same :443 endpoint");
        assert_eq!(
            *tried.lock().unwrap(),
            vec![ChannelDialKind::Direct, ChannelDialKind::FrontDoor, ChannelDialKind::FrontDoorBoring],
            "rungs are tried in order, boring last"
        );

        // The boring rung must NOT be reached once the ordinary front door works -- it is a
        // fallback, not a behaviour change for networks that are already fine.
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<ChannelDialKind>::new()));
        let log = seen.clone();
        let _: SocketAddr = dial_ladder(&rungs, |r: &ChannelDialRung| {
            let (kind, endpoint) = (r.kind, r.endpoint);
            let log = log.clone();
            async move {
                log.lock().unwrap().push(kind);
                match kind {
                    ChannelDialKind::Direct => Err(ChannelDialError::Unreachable),
                    _ => Ok(endpoint),
                }
            }
        })
        .await
        .expect("the ordinary front door still wins when it connects");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![ChannelDialKind::Direct, ChannelDialKind::FrontDoor],
            "the boring rung is never dialed once the ct-edge-channel front door connects"
        );
    }

    #[test]
    fn every_dial_rung_has_a_distinct_operator_facing_label() {
        // The dial diagnostics (`ct-agent channel: dialing {label} rung {endpoint}`) are the
        // only way an operator debugging a live case can tell WHICH rung produced a failure
        // -- the two :443 rungs share an endpoint, so a shared label would make the boring
        // fallback indistinguishable from the front-door attempt in the log.
        let labels = [
            ChannelDialKind::Direct.label(),
            ChannelDialKind::FrontDoor.label(),
            ChannelDialKind::FrontDoorBoring.label(),
        ];
        let mut sorted: Vec<&str> = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "labels must be distinct: {labels:?}");
        assert!(ChannelDialKind::FrontDoorBoring.is_front_door(), "the boring rung goes over :443");
        assert!(!ChannelDialKind::Direct.is_front_door());
    }

    #[tokio::test]
    async fn present_channel_join_via_ladder_falls_back_to_the_443_front_door() {
        // #106 client-dial-443 (frozen): the AGENT actually uses :443. The dial ladder's
        // DIRECT rung points at a dead/closed port (the QUIC dial is Unreachable), so
        // present_channel_join_via_ladder falls through to the FRONT-DOOR rung — a real
        // TLS-TCP `:443`-style edge whose accepted stream is admitted with the production
        // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and completes the
        // join (Admitted) over TLS-over-TCP. This is the fallback for a network that blocks
        // the direct channel port.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        // Operator-signed grant; the edge `authorize` closure yields this operator's key.
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0x06u8; 32];
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        // A real `:443`-style TLS-TCP edge front door.
        let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
            .await
            .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");

        // Edge: accept one TLS-TCP connection, admit the channel join over the duplex, then
        // ack `OK <peer_endpoint>` and close the write half so the client reads the ack to EOF.
        let edge = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64, // now < expires_at (1_000)
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the :443 TLS-TCP duplex");
            stream.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
            stream.shutdown().await.expect("shutdown");
        });

        // The dial ladder: a DEAD direct rung (closed port) then the LIVE :443 front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // nothing on that UDP port -> the direct QUIC dial is Unreachable
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ];

        let outcome = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await
        .expect("the join completes over the :443 front door after the dead direct rung");

        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.9:8008",
                "the agent learns the peer endpoint over the :443 TLS-TCP fallback rung"
            ),
            other => panic!("a valid join over :443 must be Admitted, got {other:?}"),
        }
        edge.await.expect("edge task");
    }

    #[tokio::test]
    async fn present_channel_join_via_ladder_falls_through_a_refused_rung_to_the_next() {
        // Live-reported gap (ct-agent#15, 2026-08-13): a network that corrupts or
        // fingerprints the request differently per rung can turn a garbled request into a
        // spurious `NO` on one rung while a cleaner rung would legitimately admit the SAME
        // grant/holder -- so `present_channel_join_via_ladder` must not stop at the first
        // `Refused`, it must try the next rung, exactly like it already does for a
        // transport-level `Unreachable`/`Failed`. Two REAL `:443`-style TLS-TCP edges: the
        // first's `authorize` closure always refuses (simulating a corrupted/garbled first
        // rung), the second admits the identical grant.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        let op = SigningKey::from_bytes(&[8u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0x09u8; 32];
        let holder = SigningKey::from_bytes(&[0x12u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7008".to_string() };

        // ONE real edge (one listener, one cert) serving the SAME :443-style endpoint for
        // both rungs -- matching production, where the FrontDoor and FrontDoorBoring rungs
        // dial the identical edge address and only their ClientHello differs. The client
        // connects to this address TWICE (once per rung, fresh TCP connections); the edge
        // refuses the first (simulating a corrupted/garbled first rung) and admits the
        // second (the SAME grant/holder a cleaner rung would have gotten through with).
        let (listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            // First connection: refuse unconditionally.
            let (tcp, peer) = listener.accept().await.expect("accept tcp #1");
            let tls = acceptor.accept(tcp).await.expect("tls accept #1");
            let outcome =
                admit_channel_join_on_duplex(tls, peer, 500u64, std::time::Duration::from_secs(5), &|_c, _h| async {
                    None
                })
                .await;
            assert!(outcome.is_err(), "the first connection is refused, not admitted");

            // Second connection: admit the same grant.
            let (tcp, peer) = listener.accept().await.expect("accept tcp #2");
            let tls = acceptor.accept(tcp).await.expect("tls accept #2");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64,
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the second connection's TLS-TCP duplex");
            stream.write_all(b"OK 198.51.100.10:8009").await.expect("ack");
            stream.shutdown().await.expect("shutdown");
        });

        // Two rungs, same endpoint and kind -- this test is about the reject_refused_outcome
        // wiring, not the boring-ALPN wire format (already covered by its own dedicated tests
        // in transport.rs/pki.rs). Using FrontDoorBoring here would present SNI
        // `edge-cdn.invalid`, which this test's plain `self_signed()` cert (SAN: "localhost"
        // only) can't validate -- an unrelated failure that has nothing to do with what this
        // test proves. If the Refused from the first connection wrongly ended the walk, the
        // second `accept()` above would never be reached and `edge` would hang.
        let rungs = vec![
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ];
        let outcome = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await;

        edge.await.expect("edge task");
        match outcome.expect("the ladder falls through the refused rung to the admitting one") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.10:8009",
                "the second rung's admission wins after the first rung's refusal"
            ),
            other => {
                panic!("the ladder must fall through a Refused rung, not terminate on it -- got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn present_channel_join_via_ladder_stops_on_a_park_expiry_instead_of_advancing_21() {
        // #21: a park expiry (the edge's bare `EX` after a fully successful admission) is NOT a
        // rung failure -- the rung worked, there was simply no partner within the park TTL. The
        // ladder must STOP and surface `ParkExpired` so the caller re-parks on the same
        // transport; falling through to the next rung (like `Refused` deliberately does) is
        // exactly the ladder-advance misclassification measured live as 271 phantom "rung
        // failures" and a 0-40s first-contact roulette. The edge below accepts exactly ONE
        // connection then drops the listener: if the walk wrongly advanced, the second rung's
        // dial would fail and the outcome would be that error instead of a clean ParkExpired.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        let op = SigningKey::from_bytes(&[8u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0x21u8; 32];
        let holder = SigningKey::from_bytes(&[0x13u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Accept,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7009".to_string() };

        let (listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64,
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the TLS-TCP duplex");
            // The reaper's park-expiry notification: the bare token, then the close.
            stream.write_all(b"EX").await.expect("park-expiry token");
            stream.shutdown().await.expect("shutdown");
            drop(listener); // any second dial (a wrong ladder advance) now fails loudly
        });

        let rungs = vec![
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ];
        let outcome = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await;

        edge.await.expect("edge task");
        match outcome.expect("a park expiry is a clean outcome, not a walk failure") {
            ChannelJoinOutcome::ParkExpired => {}
            other => panic!("the ladder must stop on ParkExpired without advancing (#21), got {other:?}"),
        }
    }

    #[test]
    fn park_expired_is_neither_a_refusal_nor_a_generic_error_21() {
        // #21: the serve loop's routing contract. `reject_refused_outcome` turns the ParkExpired
        // outcome into the TYPED error; `is_park_expired` recognizes it (and the QUIC close
        // reason that arrives flattened inside another error), while the #231 refusal backoff
        // must never see it as refused -- counting park expiries as refusals would back an
        // idle acceptor off exponentially for the crime of having no partner yet.
        let err = reject_refused_outcome(ChannelJoinOutcome::ParkExpired)
            .expect_err("ParkExpired must become the typed error, not pass as admitted");
        assert!(is_park_expired(&err), "the typed ParkExpired is recognized");
        assert!(
            !is_definitive_admission_refusal(&err),
            "a park expiry must NEVER count toward the #231 refusal backoff"
        );
        assert!(
            err.to_string().contains("park expired") && err.to_string().contains("#21"),
            "the field-visible message names the park expiry and the issue: {err}"
        );
        // The QUIC half: a close reason that crossed a stringifying boundary still classifies.
        let flattened: BoxError =
            "connection lost: closed by peer: 0: park-expired: no partner within the park TTL".into();
        assert!(is_park_expired(&flattened), "the wire close reason classifies at any nesting");
        // And plain transport errors never do.
        let transport: BoxError = "connection reset by peer".into();
        assert!(!is_park_expired(&transport));
        // Refusals stay refusals: the two classifiers are disjoint.
        let refused = reject_refused_outcome(ChannelJoinOutcome::Refused).expect_err("refused");
        assert!(is_definitive_admission_refusal(&refused) && !is_park_expired(&refused));
    }

    #[tokio::test(start_paused = true)]
    async fn run_channel_session_times_out_a_stalled_handshake() {
        // #126 (frozen): if the paired peer never sends its Noise_IK handshake message
        // (crash, partition, admit-then-stall), the session must TIME OUT — not block
        // `read_frame` forever. Hold the transport's peer end OPEN but silent; the
        // initiator writes m1 then blocks reading m2, so the #126 handshake timeout must
        // fire (virtual time auto-advances under start_paused, so the test is instant).
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{duplex, split};

        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (transport, peer_transport) = duplex(16 * 1024);
        let (_local_app, local) = duplex(16 * 1024);
        let session = tokio::spawn(async move {
            let (r, w) = split(transport);
            run_channel_session_on_stream(w, r, ChannelRole::Initiate, &a.private, &b.public, local).await
        });
        let err = session
            .await
            .unwrap()
            .expect_err("a stalled handshake must time out, not hang forever");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "must be the #126 handshake timeout, got: {err}"
        );
        drop(peer_transport);
    }

    #[tokio::test]
    async fn run_channel_session_on_stream_forms_the_noise_tunnel_over_a_plain_duplex() {
        // #106 relay-leg-443 (frozen): the A2A session is transport-agnostic — the
        // Noise_IK handshake + bidirectional pump run over a plain in-memory duplex (the
        // stand-in for a :443/TLS-TCP relay-spliced stream), not just a quinn bi-stream.
        // Two members hand-shake over the transport duplex, then plaintext written to one
        // member's local side arrives DECRYPTED at the other's — proving a :443-only
        // member (relay port also blocked) can relay end-to-end over :443.
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let (a_priv, a_pub) = (a.private, a.public);
        let (b_priv, b_pub) = (b.private, b.public);

        // The relay-spliced transport between the two members.
        let (a_transport, b_transport) = duplex(16 * 1024);
        // Each member's local plaintext side (the CLI's stdio stand-in).
        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);

        let a_task = tokio::spawn(async move {
            let (ar, aw) = split(a_transport);
            run_channel_session_on_stream(aw, ar, ChannelRole::Initiate, &a_priv, &b_pub, a_local).await
        });
        let b_task = tokio::spawn(async move {
            let (br, bw) = split(b_transport);
            run_channel_session_on_stream(bw, br, ChannelRole::Accept, &b_priv, &a_pub, b_local).await
        });

        // A -> B over the encrypted tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the duplex relay");

        // B -> A.
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A");

        // Closing a local side tears the session down cleanly.
        drop(a_app);
        drop(b_app);
        let _ = a_task.await;
        let _ = b_task.await;
    }

    #[tokio::test]
    async fn graceful_stream_drain_returns_when_the_peer_closes() {
        // #150 (frozen): the drain FINs our write half and reads the peer to EOF — so once the peer
        // closes it returns promptly, having kept us alive just long enough to flush our tail (the
        // fix for `:443`/TLS-TCP truncation when `ct-agent` exits as a container's PID 1).
        use std::time::Duration;
        use tokio::io::{duplex, split};
        let (ours, peer) = duplex(64);
        let (mut our_r, mut our_w) = split(ours);
        drop(peer); // the peer closes → our read half EOFs
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_secs(30)),
        )
        .await;
        assert!(done.is_ok(), "drain returns promptly once the peer has closed (well within its bound)");
    }

    #[tokio::test]
    async fn graceful_stream_drain_is_bounded_on_a_silent_peer() {
        // #150 (frozen): a peer that FINs nothing (vanished mid-transfer) must NOT hang teardown —
        // the drain is bounded by its own timeout and returns best-effort, never blocking forever.
        use std::time::Duration;
        use tokio::io::{duplex, split};
        let (ours, peer_kept) = duplex(64);
        let (mut our_r, mut our_w) = split(ours);
        let _peer_kept = peer_kept; // keep the peer open + silent so our read half never EOFs
        let done = tokio::time::timeout(
            Duration::from_secs(3),
            graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_millis(150)),
        )
        .await;
        assert!(done.is_ok(), "a silent peer times out the bounded drain instead of hanging teardown");
    }

    #[test]
    fn agent_offer_cli_config_builds_a_valid_signed_offer_from_env() {
        // #152 (frozen): the --serve offer config parses CT_AGENT_OFFER_* + the shared holder key into
        // a signed CapacityOffer (so channel_local can register auction/offer + auction/bid), bound to
        // the holder, honouring the TTL. Absent required vars → Err (auction tools stay off), exactly
        // like the agent/card path.
        use std::collections::HashMap;
        let key_hex = "11".repeat(32); // 64 hex → [0x11; 32]
        let vars: HashMap<&str, String> = HashMap::from([
            ("CT_CHANNEL_HOLDER_KEY", key_hex.clone()),
            ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
            ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8,local-llama".to_string()),
            ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
            ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
            ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
            ("CT_AGENT_OFFER_TTL_SECS", "3600".to_string()),
        ]);
        let cfg = AgentOfferCliConfig::from_lookup(|k| vars.get(k).cloned()).expect("parses a full offer config");
        let offer = cfg.build_offer(1_000);
        assert!(offer.is_valid(1_000), "the built offer verifies at issue time");
        assert!(offer.is_valid(4_599), "valid up to issued_at + ttl");
        assert!(!offer.is_valid(4_600), "expires at now + ttl (1000 + 3600)");
        assert_eq!(offer.kind, ct_common::channel::CapacityKind::CloudApiQuota);
        assert_eq!(offer.models, vec!["claude-opus-4-8".to_string(), "local-llama".to_string()]);
        assert_eq!((offer.units_available, offer.min_price), (1000, 50));
        assert_eq!(offer.currency_id, "ct-llm-token-chain");
        assert_eq!(
            offer.holder_pubkey,
            SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes(),
            "the offer is bound to CT_CHANNEL_HOLDER_KEY"
        );
        // Defaults applied when optional vars are absent.
        assert_eq!((cfg.max_bids_per_window, cfg.window_secs), (60, 60), "rate-limit defaults");

        // Absent required vars → Err, so channel_local leaves the auction tools off (card/ping only).
        assert!(AgentOfferCliConfig::from_lookup(|_| None).is_err(), "no CT_AGENT_OFFER_* → no offer");
        // A bad kind is a clear error, not a silent default.
        let mut bad = vars.clone();
        bad.insert("CT_AGENT_OFFER_KIND", "chatbot".to_string());
        assert!(
            AgentOfferCliConfig::from_lookup(|k| bad.get(k).cloned()).is_err(),
            "an unknown CT_AGENT_OFFER_KIND is rejected"
        );
    }

    #[test]
    fn agent_offer_declares_its_service_catalog_for_verifiable_enforcement() {
        // #167 (frozen): CT_AGENT_OFFER_SERVICES is signed INTO the offer, so a buyer can
        // cryptographically verify which services the agent offers and #149-A.1's match_offer
        // service filter has something to enforce (closing the declared-vs-served gap where the
        // offer and the registered service tools were two independent, unvalidated surfaces).
        // #382 follow-up: a slug outside the four fixed variants is no longer a hard config error
        // -- it's a real ServiceType::Custom declaration, signed into the offer exactly like any
        // fixed variant, so an operator can offer a pipeline-designer-declared service (e.g.
        // static_analysis) without a CADS-Tunnel core release. Absent → a generic offer
        // (services: []), unchanged.
        use ct_common::channel::ServiceType::*;
        use std::collections::HashMap;
        let base: HashMap<&str, String> = HashMap::from([
            ("CT_CHANNEL_HOLDER_KEY", "11".repeat(32)),
            ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
            ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8".to_string()),
            ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
            ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
            ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
        ]);

        // Absent → generic offer with no declared services (unchanged back-compat).
        let generic = AgentOfferCliConfig::from_lookup(|k| base.get(k).cloned()).unwrap();
        assert!(generic.services.is_empty(), "no CT_AGENT_OFFER_SERVICES → generic offer");
        assert!(generic.build_offer(1_000).services.is_empty(), "generic offer declares no services");

        // A declared catalog is parsed and SIGNED into the offer (order + values preserved).
        let mut with = base.clone();
        with.insert("CT_AGENT_OFFER_SERVICES", "code_generation, security_review".to_string());
        let cfg = AgentOfferCliConfig::from_lookup(|k| with.get(k).cloned()).unwrap();
        assert_eq!(cfg.services, vec![CodeGeneration, SecurityReview], "catalog parsed from env");
        let offer = cfg.build_offer(1_000);
        assert_eq!(
            offer.services,
            vec![CodeGeneration, SecurityReview],
            "the declared catalog is signed into the offer (buyer-verifiable ceiling)"
        );
        assert!(offer.is_valid(1_000), "the offer still verifies with a declared catalog");

        // A slug outside the fixed four is a REAL Custom declaration, not an error -- signed into
        // the offer the exact same way, and a real signature still verifies over it.
        let mut custom = base.clone();
        custom.insert("CT_AGENT_OFFER_SERVICES", "code_generation,static_analysis".to_string());
        let cfg = AgentOfferCliConfig::from_lookup(|k| custom.get(k).cloned()).unwrap();
        assert_eq!(
            cfg.services,
            vec![CodeGeneration, Custom("static_analysis".to_string())],
            "an unrecognized slug becomes ServiceType::Custom, not a parse error"
        );
        let offer = cfg.build_offer(1_000);
        assert_eq!(offer.services, vec![CodeGeneration, Custom("static_analysis".to_string())]);
        assert!(offer.is_valid(1_000), "a real signature verifies over a Custom-service offer");

        // A stray empty entry (double comma) is still rejected -- the ONE thing that stays a
        // hard config error, since an empty custom-service name is never a meaningful declaration.
        let mut empty_entry = base.clone();
        empty_entry.insert("CT_AGENT_OFFER_SERVICES", "code_generation,,text_generation".to_string());
        assert!(
            AgentOfferCliConfig::from_lookup(|k| empty_entry.get(k).cloned()).is_ok(),
            "a stray double-comma is just an empty token the split/filter already drops, not an error"
        );
    }

    #[test]
    fn service_type_parsing_and_handler_shell_out_round_trip() {
        // #149-A.1 serve-wiring follow: parse_service_type covers every fixed slug, and (#382
        // follow-up) anything else becomes ServiceType::Custom rather than being dropped -- so a
        // pipeline designer's own service name (e.g. static_analysis) is a real, usable
        // declaration, not silently unavailable. Only an empty token still parses to nothing.
        // run_service_handler actually spawns the configured command, pipes `input` on stdin, and
        // returns trimmed stdout — the shell-out seam a real LLM CLI plugs into.
        use ct_common::channel::ServiceType::*;
        assert_eq!(parse_service_type("code_generation"), Some(CodeGeneration));
        assert_eq!(parse_service_type("security_review"), Some(SecurityReview));
        assert_eq!(parse_service_type("safety_check"), Some(SafetyCheck));
        assert_eq!(parse_service_type("text_generation"), Some(TextGeneration));
        assert_eq!(parse_service_type("not-a-real-service"), Some(Custom("not-a-real-service".to_string())), "unrecognized -> Custom, not dropped");
        assert_eq!(parse_service_type(""), None, "an empty token still parses to nothing");

        // A Custom service round-trips through the SAME shell-out handler: CT_SERVICE_TYPE is
        // set to its slugified name (ct_common::mcp::service_slug), not a fixed built-in slug.
        let out = run_service_handler(
            "echo \"got:$CT_SERVICE_TYPE\"",
            Custom("Static Analysis!".to_string()),
            "ignored",
        )
        .unwrap();
        assert_eq!(out, "got:static_analysis_", "the Custom name is slugified the same way ct_common::mcp registers its tool under");

        // `cat` echoes stdin back — proves input actually reaches the child and stdout is
        // captured + trimmed (a trailing newline from `echo`-style output must not leak through).
        let out = run_service_handler("cat", CodeGeneration, "hello from the caller").unwrap();
        assert_eq!(out, "hello from the caller");

        // CT_SERVICE_TYPE is set in the child's env so a multi-service handler can branch.
        let out = run_service_handler("echo \"got:$CT_SERVICE_TYPE\"", SecurityReview, "ignored").unwrap();
        assert_eq!(out, "got:security_review");

        // A non-zero exit surfaces as a tool error, not a panic or a silently-empty result.
        let err = run_service_handler("exit 7", TextGeneration, "x").unwrap_err();
        assert!(err.contains("exited"), "the exit status is reported: {err}");
    }

    #[tokio::test]
    async fn call_role_service_calls_a_service_tool_over_a_duplex_and_fails_closed() {
        // #171/#173 c2 atom (frozen): the crew bridge dials a role agent's channel and calls its
        // service/<slug> tool, getting the fragment — exercised here against an IN-PROCESS serve
        // peer (a local fake, exactly the parallel dev-testing #173 asks for). A missing service
        // fails closed.
        use ct_common::channel::ServiceType;
        // A stub service that echoes a fragment-shaped output (stands in for a live LLM handler).
        let mut reg = ct_common::mcp::default_registry();
        ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
            Ok(format!("{{\"echoed\":\"{input}\"}}"))
        });
        let reg = std::sync::Arc::new(reg);
        let session = serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        });
        let (mut recv, mut send) = tokio::io::split(session);
        let out = call_role_service(&mut send, &mut recv, "text_generation", "a matrix theme").await.unwrap();
        assert_eq!(out, "{\"echoed\":\"a matrix theme\"}", "returns the service's output verbatim");

        // Calling a service the peer does NOT offer → JSON-RPC error → Err (fail closed, no fragment).
        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let s2 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        let (mut r2, mut w2) = tokio::io::split(s2);
        assert!(
            call_role_service(&mut w2, &mut r2, "safety_check", "x").await.is_err(),
            "an unoffered service fails closed"
        );
    }

    #[tokio::test]
    async fn call_role_service_propagates_an_oversized_request_as_an_error_211() {
        // #211 (frozen): a service call whose framed request exceeds the u16 wire ceiling
        // (MAX_MESSAGE_BYTES) is rejected by `write_message` BEFORE anything is sent, and that error
        // PROPAGATES up through `call_role_service` as an `Err` (kind InvalidInput) — it is not
        // swallowed. This is exactly the error the one-shot `--call-service`/`--call` wrappers now turn
        // into a NON-ZERO process exit instead of exit-0-with-empty-stdout, so an oversized `input`
        // surfaces as a clear "message too large" rather than a cryptic downstream empty-output failure.
        let (client, _server) = tokio::io::duplex(1 << 16);
        let (mut recv, mut send) = tokio::io::split(client);
        // An `input` past the ceiling → the JSON request is even larger → write_message rejects it.
        let oversized = "x".repeat(ct_common::a2a::MAX_MESSAGE_BYTES + 1);
        let err = call_role_service(&mut send, &mut recv, "text_generation", &oversized)
            .await
            .expect_err("an oversized request must surface as an Err, not be dropped");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "the transport size rejection kind is preserved");
        assert!(
            err.to_string().contains("MAX_MESSAGE_BYTES"),
            "the error names the wire ceiling so the failure is attributable: {err}"
        );
    }

    #[tokio::test]
    async fn channel_call_service_mode_yields_bare_service_output() {
        // #173 distributed (frozen): the initiator CT_CHANNEL_CALL_SERVICE mode's core — invoke the
        // peer's service/<slug> and return the BARE output (result.output), NOT a JSON-RPC envelope
        // (the crew bridge's CREW_*_CMD feeds this straight to ct_common::crew). Against an in-process
        // serve peer. An unoffered service fails closed (→ the bridge 502s → browser local fallback).
        use ct_common::channel::ServiceType;
        let mut reg = ct_common::mcp::default_registry();
        ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
            Ok(format!("{{\"gravity\":2200,\"note\":\"{input}\"}}"))
        });
        let reg = std::sync::Arc::new(reg);
        let peer = serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        });
        let out = run_service_call(peer, "text_generation", "hard matrix").await.unwrap();
        assert_eq!(out, "{\"gravity\":2200,\"note\":\"hard matrix\"}", "bare service output, no JSON-RPC envelope");

        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let peer2 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        assert!(
            run_service_call(peer2, "safety_check", "x").await.is_err(),
            "an unoffered service fails closed",
        );
    }

    #[tokio::test]
    async fn persistent_call_mode_multiplexes_many_calls_over_one_held_session_19() {
        // #19 (frozen contract): ONE session, many line-framed calls, one NDJSON envelope line per
        // call, clean teardown on source EOF. This is the initiator-side counterpart of --serve:
        // the whole point is that call N+1 reuses the SAME session (no re-pairing, no re-park
        // window on the peer), so all three calls here flow over one serve_local peer.
        use ct_common::channel::ServiceType;
        let mut reg = ct_common::mcp::default_registry();
        ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
            Ok(format!("echo:{input}"))
        });
        let reg = std::sync::Arc::new(reg);
        let peer = serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        });

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
        let mut out: Vec<u8> = Vec::new();
        tx.send("first".into()).await.unwrap();
        tx.send("   ".into()).await.unwrap(); // blank line = no-op, must not produce output
        tx.send("second".into()).await.unwrap();
        tx.send("third with spaces".into()).await.unwrap();
        drop(tx); // stdin EOF -> clean end of run

        run_service_calls_persistent(peer, "text_generation", &mut rx, &mut out)
            .await
            .expect("source EOF is the clean end of a run");

        let lines: Vec<serde_json::Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("every response line is one JSON envelope"))
            .collect();
        assert_eq!(lines.len(), 3, "three calls -> three envelopes (blank line produced none)");
        for (envelope, expect) in lines.iter().zip(["echo:first", "echo:second", "echo:third with spaces"]) {
            assert_eq!(envelope["ok"], true);
            assert_eq!(envelope["output"], expect, "bare service output inside the envelope");
        }
    }

    #[tokio::test]
    async fn persistent_call_mode_fails_closed_with_a_structured_error_envelope_19() {
        // #19 + #211 discipline: a failed call mid-run writes {"ok":false,...} as the LAST line
        // BEFORE the Err return -- the supervising caller can attribute the failure structurally,
        // then sees the non-zero exit and retries at run granularity.
        let bare = std::sync::Arc::new(ct_common::mcp::default_registry()); // no services offered
        let peer = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
        let mut out: Vec<u8> = Vec::new();
        tx.send("doomed".into()).await.unwrap();
        drop(tx);

        let err = run_service_calls_persistent(peer, "text_generation", &mut rx, &mut out).await;
        assert!(err.is_err(), "an unoffered service fails the run closed");
        let last: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().lines().last().expect("an envelope was written"))
                .expect("the last line is a JSON envelope");
        assert_eq!(last["ok"], false);
        assert!(last["error"].as_str().unwrap().len() > 0, "the error is named, not swallowed");
    }

    #[test]
    fn serve_loop_only_for_accept_in_serve_mode() {
        // #179 (frozen): the persistent re-admit loop engages ONLY for an accept-side serve member
        // (the parking side a pipeline dials repeatedly). Truthy CT_CHANNEL_SERVE in {1,true,yes}.
        assert!(should_serve_loop(ChannelRole::Accept, Some("1")));
        assert!(should_serve_loop(ChannelRole::Accept, Some("true")));
        assert!(should_serve_loop(ChannelRole::Accept, Some(" yes ")));
        // Not the initiator (it does one call/session and exits), regardless of the env.
        assert!(!should_serve_loop(ChannelRole::Initiate, Some("1")));
        // Not a non-serve accept, and not unset/false.
        assert!(!should_serve_loop(ChannelRole::Accept, None));
        assert!(!should_serve_loop(ChannelRole::Accept, Some("0")));
        assert!(!should_serve_loop(ChannelRole::Accept, Some("false")));
    }

    #[test]
    fn required_env_helpers_keep_the_exact_message_format() {
        // #190 (frozen): the shared req_*/opt_hex32 helpers must produce the SAME "KEY required (what)"
        // text the inlined parses used, so consolidating ~a dozen sites changed no error string and no
        // required-vs-optional semantics. A missing var still fails loudly at startup, identically.
        let empty = |_: &str| None::<String>;
        assert_eq!(req_str(&empty, "CT_X", "hint").unwrap_err(), "CT_X required (hint)");
        assert_eq!(req_hex32(&empty, "CT_K", "64 hex").unwrap_err(), "CT_K required (64 hex)");
        assert_eq!(req_key(&empty, "CT_HOLDER", "64 hex").unwrap_err(), "CT_HOLDER required (64 hex)");
        assert_eq!(opt_hex32(&empty, "CT_O"), None);
        // present + valid → the parsed value (req_key accepts any 32-byte seed).
        let full = |k: &str| match k {
            "CT_S" => Some("value".to_string()),
            "CT_H" => Some("11".repeat(32)), // 64 hex chars → [0x11; 32]
            _ => None,
        };
        assert_eq!(req_str(&full, "CT_S", "x").unwrap(), "value");
        assert_eq!(req_hex32(&full, "CT_H", "x").unwrap(), [0x11u8; 32]);
        assert_eq!(opt_hex32(&full, "CT_H"), Some([0x11u8; 32]));
        assert!(req_key(&full, "CT_H", "x").is_ok());
        // a malformed hex value is treated as absent (opt) / a required error (req) — unchanged.
        let bad = |_: &str| Some("nothex".to_string());
        assert_eq!(opt_hex32(&bad, "CT_H"), None);
        assert!(req_hex32(&bad, "CT_H", "64 hex").is_err());
    }

    #[test]
    fn serve_concurrency_parses_the_cap_or_falls_back() {
        // #200 (frozen): a positive integer overrides; absent/blank/zero/garbage → the default.
        assert_eq!(serve_concurrency_from_env(Some("4")), 4);
        assert_eq!(serve_concurrency_from_env(Some(" 16 ")), 16);
        assert_eq!(serve_concurrency_from_env(None), DEFAULT_SERVE_CONCURRENCY);
        assert_eq!(serve_concurrency_from_env(Some("")), DEFAULT_SERVE_CONCURRENCY);
        assert_eq!(serve_concurrency_from_env(Some("0")), DEFAULT_SERVE_CONCURRENCY);
        assert_eq!(serve_concurrency_from_env(Some("lots")), DEFAULT_SERVE_CONCURRENCY);
    }

    #[tokio::test]
    async fn serve_loop_admits_the_next_peer_while_a_slow_session_is_still_running() {
        // #200 (frozen) — THE regression this fixes. The old serve loop served a peer to
        // completion before re-admitting, so a slow handler starved every concurrent Build. Here
        // `serve` never finishes within the window; we assert the loop still admitted and STARTED
        // all five peers concurrently (proving admission no longer waits on the prior session).
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let admits = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));

        let a = admits.clone();
        let admit = move || {
            let a = a.clone();
            async move {
                let n = a.fetch_add(1, Ordering::SeqCst);
                if n < 5 {
                    Ok::<usize, BoxError>(n)
                } else {
                    // no more peers — park forever so the loop stops admitting
                    std::future::pending::<()>().await;
                    unreachable!()
                }
            }
        };
        let st = started.clone();
        let fi = finished.clone();
        let serve = move |_w: usize| {
            let st = st.clone();
            let fi = fi.clone();
            async move {
                st.fetch_add(1, Ordering::SeqCst);
                // a session that outlives the observation window (aborted at test end)
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                fi.fetch_add(1, Ordering::SeqCst);
                Ok::<(), BoxError>(())
            }
        };

        // cap high so concurrency (not the cap) is what we're testing.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            serve_loop_concurrent(100, std::time::Duration::from_millis(10), admit, serve),
        )
        .await;

        assert!(admits.load(Ordering::SeqCst) >= 5, "admitted every peer without waiting for prior sessions");
        assert_eq!(started.load(Ordering::SeqCst), 5, "all five sessions ran concurrently");
        assert_eq!(finished.load(Ordering::SeqCst), 0, "sessions still running — admission did not block on serve");
    }

    #[tokio::test]
    async fn serve_loop_caps_concurrency_so_a_flood_cannot_fork_bomb() {
        // #200 (frozen): the bounded-concurrency guard the issue asks for. With cap=2 and sessions
        // that never finish, only two may start; the permit is taken BEFORE parking, so the loop
        // stops admitting a third peer it has no capacity to serve (backpressure, not a dropped call).
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let admits = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));

        let a = admits.clone();
        let admit = move || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Ok::<(), BoxError>(())
            }
        };
        let st = started.clone();
        let serve = move |_w: ()| {
            let st = st.clone();
            async move {
                st.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await; // never frees its permit
                Ok::<(), BoxError>(())
            }
        };

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            serve_loop_concurrent(2, std::time::Duration::from_millis(10), admit, serve),
        )
        .await;

        assert_eq!(started.load(Ordering::SeqCst), 2, "never exceeded the concurrency cap");
        assert_eq!(admits.load(Ordering::SeqCst), 2, "backpressure stopped admitting a peer we couldn't serve");
    }

    #[test]
    fn admission_refusal_classification_is_typed_and_survives_rewording_20() {
        // #20 (consolidation): the classification is a DOWNCAST now, not a substring search --
        // proven by classifying an AdmissionRefused whose text deliberately contains none of the
        // historical wording. Under the old substring-only check this would silently fall back
        // to the fast retry cadence (#231's edge-flood failure mode); typed, it stays a
        // definitive refusal no matter how the operator-facing text evolves.
        let reworded: BoxError = AdmissionRefused::boxed("the peer's broker said no");
        assert!(
            is_definitive_admission_refusal(&reworded),
            "a typed AdmissionRefused classifies regardless of its display text"
        );
        // And the Display contract still emits exactly what was constructed (operators grep it).
        assert_eq!(reworded.to_string(), "the peer's broker said no");

        // The real production values are typed too -- classify + display both hold.
        let real = AdmissionRefused::boxed("edge broker refused the channel join");
        assert!(is_definitive_admission_refusal(&real));
        assert_eq!(real.to_string(), "edge broker refused the channel join");
    }

    #[test]
    fn is_definitive_admission_refusal_matches_only_the_refused_strings() {
        // #231 + #20: the substring FALLBACK (kept one release for errors that crossed a
        // stringifying boundary) still recognizes exactly the historical strings -- everything
        // else, including the #140 stall symptom, is transient and must keep the fast retry.
        assert!(is_definitive_admission_refusal(&"edge broker refused the channel join".into()));
        assert!(is_definitive_admission_refusal(&"edge relay refused the channel join".into()));
        assert!(is_definitive_admission_refusal(
            &"edge relay refused the channel join over the :443 front door".into()
        ));
        assert!(
            !is_definitive_admission_refusal(&"channel join admission exchange stalled (#140)".into()),
            "#140 stalls are transient, not a definitive refusal"
        );
        assert!(!is_definitive_admission_refusal(&"connection reset by peer".into()));
    }

    #[test]
    fn admission_retry_backoff_is_flat_for_transient_and_exponential_for_refused() {
        // #231: a transient error always gets the unchanged fast retry regardless of streak length
        // (a genuine CP/edge blip must keep recovering quickly, per #140's own fix).
        let base = std::time::Duration::from_millis(200);
        assert_eq!(admission_retry_backoff(base, false, 0), base);
        assert_eq!(admission_retry_backoff(base, false, 50), base, "transient errors never back off");

        // A definitive refusal doubles per consecutive occurrence...
        assert_eq!(admission_retry_backoff(base, true, 1), base * 2);
        assert_eq!(admission_retry_backoff(base, true, 2), base * 4);
        assert_eq!(admission_retry_backoff(base, true, 3), base * 8);
        // ...and is clamped at the cap instead of growing (or overflowing) without bound.
        assert_eq!(admission_retry_backoff(base, true, 100), REFUSED_ADMISSION_BACKOFF_CAP);
        assert_eq!(admission_retry_backoff(base, true, u32::MAX), REFUSED_ADMISSION_BACKOFF_CAP);
    }

    #[test]
    fn is_flapping_session_only_flags_a_short_errored_session_250() {
        // #250: the classifier's whole job is telling "pair, then die near-instantly" (flap)
        // apart from every other outcome -- success, a fast-but-real session, or a slow failure.
        let short = FLAPPING_SESSION_THRESHOLD - std::time::Duration::from_millis(1);
        let long = FLAPPING_SESSION_THRESHOLD + std::time::Duration::from_millis(1);
        assert!(is_flapping_session(short, true), "short + errored = a flap");
        assert!(!is_flapping_session(short, false), "short + SUCCEEDED is a fast real session, not a flap");
        assert!(!is_flapping_session(long, true), "a failure that took a while is a real failure, not a flap");
        assert!(!is_flapping_session(long, false), "long + succeeded is obviously not a flap");
        // Exactly-at-threshold is NOT a flap (strict `<`) -- a session that runs the full
        // threshold did real work, it didn't die instantly.
        assert!(!is_flapping_session(FLAPPING_SESSION_THRESHOLD, true));
    }

    #[test]
    fn flapping_session_backoff_is_exponential_and_capped_lower_than_refusal_250() {
        let base = std::time::Duration::from_millis(200);
        assert_eq!(flapping_session_backoff(base, 0), base, "zero flaps -> the unchanged fast retry");
        assert_eq!(flapping_session_backoff(base, 1), base * 2);
        assert_eq!(flapping_session_backoff(base, 2), base * 4);
        assert_eq!(flapping_session_backoff(base, 100), FLAPPING_SESSION_BACKOFF_CAP, "clamped, never overflows");
        assert!(
            FLAPPING_SESSION_BACKOFF_CAP < REFUSED_ADMISSION_BACKOFF_CAP,
            "a flap's cause can clear on its own (unlike a definitive refusal) -- keep checking sooner"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn serve_loop_concurrent_backs_off_after_repeated_flapping_sessions_then_recovers_250() {
        // #250 end-to-end (frozen contract): live-diagnosed 2026-08-13 -- admission succeeded on
        // EVERY attempt (this stub always admits), but the session died near-instantly each
        // time, and the unthrottled loop re-admitted at native speed forever (~98 cycles in 30s
        // against a real edge). This proves the loop now inserts a growing gap between the
        // (n-1)th flap's end and the nth admit, and that a session that finally SUCCEEDS resets
        // the streak so a recovered peer isn't punished by a backoff earned before it recovered.
        use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
        let admits = std::sync::Arc::new(AtomicUsize::new(0));
        let should_succeed = std::sync::Arc::new(AtomicU32::new(0)); // flips to 1 after N flaps
        let admits2 = admits.clone();
        let admit = move || {
            admits2.fetch_add(1, Ordering::SeqCst);
            async { Ok::<(), BoxError>(()) }
        };
        let succeed_flag = should_succeed.clone();
        let serve_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let serve_calls2 = serve_calls.clone();
        let serve = move |_: ()| {
            let succeed_flag = succeed_flag.clone();
            let serve_calls = serve_calls2.clone();
            async move {
                let n = serve_calls.fetch_add(1, Ordering::SeqCst);
                if n < 3 {
                    // Instant death -- a flap, exactly the field-observed pattern.
                    Err::<(), BoxError>("session died near-instantly".into())
                } else {
                    // The 4th session "recovers": runs long enough to be a real session, then
                    // succeeds -- must reset the flap streak.
                    succeed_flag.store(1, Ordering::SeqCst);
                    tokio::time::sleep(FLAPPING_SESSION_THRESHOLD * 2).await;
                    Ok(())
                }
            }
        };
        // max=1: forces strictly serial admit -> session -> (backoff) -> next admit, matching
        // the field scenario (one channel, one fixed remote peer) with no concurrency-ordering
        // ambiguity in the test itself.
        let driver = tokio::spawn(serve_loop_concurrent(1, std::time::Duration::from_millis(50), admit, serve));

        // Let the first 3 (flapping) sessions run out and the backoff-then-4th-admit sequence
        // complete, then the 4th (recovering) session's deliberate sleep.
        for _ in 0..20 {
            tokio::time::advance(std::time::Duration::from_secs(3)).await;
            tokio::task::yield_now().await;
        }

        assert!(admits.load(Ordering::SeqCst) >= 4, "the loop kept making progress, not wedged");
        assert_eq!(should_succeed.load(Ordering::SeqCst), 1, "the recovering session was reached and ran");
        driver.abort();
    }

    #[test]
    fn reject_refused_outcome_converts_refused_to_the_err_string_is_definitive_admission_refusal_recognizes() {
        // #248 live-observed bug: `admit_one_peer` used to return `Ok(ChannelJoinOutcome::Refused)`
        // for a broker round-trip whose answer was "no" — indistinguishable, at `serve_loop_concurrent`'s
        // `Ok(work) => spawn(..)` match, from a genuine admission. That spawned the refusal as a full
        // session (through channel_local()'s "--serve mode" setup) which then immediately failed
        // inside run_channel_join_with_admission with the same message — but because the OUTER loop
        // saw `Ok`, not `Err`, `consecutive_refusals` reset to 0 every time and #231's exponential
        // backoff never engaged, hot-looping at near-zero backoff exactly as #231 first fixed for the
        // transport-level case. This proves the translation: a Refused outcome becomes an Err whose
        // string `is_definitive_admission_refusal` recognizes as a definitive refusal.
        let err = reject_refused_outcome(ChannelJoinOutcome::Refused).expect_err("Refused must become an Err");
        assert!(
            is_definitive_admission_refusal(&err),
            "the translated error must be recognized as a definitive refusal so #231's backoff engages, got: {err}"
        );

        // A genuine admission passes through unchanged (not accidentally rejected).
        let admitted = ChannelJoinOutcome::Admitted {
            peer_endpoint: String::new(),
            peer_noise_pubkey: None,
            peer_holder: None,
            peer_attestation: None,
            observed_reflexive: None,
        };
        assert_eq!(
            reject_refused_outcome(admitted.clone()).unwrap(),
            admitted,
            "a real admission must pass through unchanged"
        );
    }

    #[tokio::test]
    async fn serve_loop_never_spawns_a_refused_outcome_as_a_session() {
        // #248: the end-to-end proof that a real `Ok(Refused)` outcome — exactly what
        // `admit_one_peer` used to return before this fix — is rejected before it ever reaches
        // `serve_loop_concurrent`'s spawn path. `admit` here does what `admit_one_peer` now does
        // (call `reject_refused_outcome` on its outcome) rather than injecting a raw `Err` directly,
        // so this covers the actual translation, not just `serve_loop_concurrent`'s own dispatch.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let spawned = Arc::new(AtomicUsize::new(0));
        let admit = move || async move { reject_refused_outcome(ChannelJoinOutcome::Refused) };
        let s = spawned.clone();
        let serve = move |_w: ChannelJoinOutcome| {
            let s = s.clone();
            async move {
                s.fetch_add(1, Ordering::SeqCst);
                Ok::<(), BoxError>(())
            }
        };

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            serve_loop_concurrent(4, std::time::Duration::from_millis(10), admit, serve),
        )
        .await;

        assert_eq!(spawned.load(Ordering::SeqCst), 0, "a refused outcome must never be spawned as a session");
    }

    #[tokio::test]
    async fn serve_loop_backs_off_a_definitive_refusal_instead_of_hot_looping() {
        // #231 live reproduction: a holder that will never be a member (a stray/orphaned process,
        // observed on the real production edge retrying ~24-47x/second at the OLD flat 200ms
        // backoff) must not keep admitting at the fast transient-error rate — it starves other,
        // genuinely valid joins of the edge's admission capacity. With a 10ms base backoff and a
        // 300ms window, an unfixed flat retry would attempt roughly 30 times; the exponential
        // backoff must land far fewer.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let admit = move || {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err::<(), BoxError>("edge broker refused the channel join".into())
            }
        };
        let serve = move |_w: ()| async move { Ok::<(), BoxError>(()) };

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            serve_loop_concurrent(4, std::time::Duration::from_millis(10), admit, serve),
        )
        .await;

        let n = attempts.load(Ordering::SeqCst);
        assert!(n >= 1, "attempted admission at least once");
        assert!(n < 10, "exponential backoff kept the refused holder well under the flat-retry rate, got {n} attempts");
    }

    #[tokio::test]
    async fn crew_build_over_runs_the_crew_and_fails_closed() {
        // #171/#173 c2 driver (frozen): safety_check → physics → art over three role channels,
        // assembled by ct_common::crew. Exercised against in-process serve peers (local fakes).
        use ct_common::channel::ServiceType;
        fn peer(services: &[ServiceType], out: &str) -> tokio::io::DuplexStream {
            let mut reg = ct_common::mcp::default_registry();
            let out = out.to_string();
            ct_common::mcp::register_service_tools(&mut reg, services, move |_svc, _input| Ok(out.clone()));
            let reg = std::sync::Arc::new(reg);
            serve_local(move |req: Vec<u8>| {
                let reg = reg.clone();
                async move { reg.dispatch(&req) }
            })
        }
        let auction: Vec<ct_common::crew::RoleAuction> = vec![];

        // Happy path: safety OK → physics + art fragments assemble into a built config.
        let safety = peer(&[ServiceType::SafetyCheck], r#"{"ok":true,"reason":""}"#);
        let physics = peer(&[ServiceType::TextGeneration], r#"{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}"#);
        let art = peer(&[ServiceType::TextGeneration], r##"{"theme":"night","birdColor":"#00ff41","birdEmoji":"🕶️","title":"Neo"}"##);
        let resp = crew_build_over("matrix theme", safety, physics, art, auction.clone()).await.unwrap();
        assert!(resp.safety.ok, "built when safety passes");
        let cfg = resp.config.as_ref().expect("built carries config");
        assert_eq!((cfg.speed, cfg.jump, cfg.gap), (220, 420, 115), "physics fragment mapped");
        assert_eq!(cfg.bird_emoji, "🕶️", "art fragment carried (emoji intact)");

        // Safety reject → Ok(rejected), no build.
        let safety_r = peer(&[ServiceType::SafetyCheck], r#"{"ok":false,"reason":"anti-prompt"}"#);
        let p2 = peer(&[ServiceType::TextGeneration], "{}");
        let a2 = peer(&[ServiceType::TextGeneration], "{}");
        let rej = crew_build_over("evil", safety_r, p2, a2, auction.clone()).await.unwrap();
        assert!(!rej.safety.ok && rej.config.is_none(), "safety reject carries no build");

        // A role unreachable (bare peer offers no service) → Err → the c3 layer 5xx's → browser falls back.
        let safety3 = peer(&[ServiceType::SafetyCheck], r#"{"ok":true}"#);
        let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
        let physics3 = serve_local(move |req: Vec<u8>| {
            let bare = bare.clone();
            async move { bare.dispatch(&req) }
        });
        let a3 = peer(&[ServiceType::TextGeneration], "{}");
        assert!(crew_build_over("x", safety3, physics3, a3, auction).await.is_err(), "an unreachable role → Err (fail closed)");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn dispatching_a_blocking_service_handler_does_not_starve_the_async_runtime_248() {
        // #248-follow: live-reproduced this exact bug against production -- a registered
        // CT_AGENT_SERVICE_HANDLER_CMD (even a near-instant one) made the responder's own
        // reply never reach the initiator ("early eof"), and under different timing a
        // completely unrelated channel's own admission exchange stalled for the full #140
        // window while this one was blocked. Root cause: `registry.dispatch(&req)` is
        // synchronous, and calling it inline inside an `async move { .. }` block (no
        // `spawn_blocking`) blocks whichever Tokio worker thread is running it for the
        // service handler subprocess's whole wall-clock duration.
        //
        // Single worker thread makes this deterministic: with the bug, a slow dispatch
        // occupies the ONLY worker, so a concurrent unrelated task can't run until it's
        // done. With the fix (spawn_blocking), the blocking work moves to Tokio's separate
        // blocking-pool, leaving the one async worker free.
        use ct_common::channel::ServiceType;
        use ct_common::mcp::{register_service_tools, ToolRegistry};

        let mut reg = ToolRegistry::new();
        register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_service, input| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            Ok(input.to_string())
        });
        let registry = std::sync::Arc::new(reg);

        let req = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "service/text_generation", "arguments": {"input": "x"}}
        }))
        .unwrap();

        // The exact pattern this fix applies in `channel_local()`'s --serve construction.
        let dispatch_task = {
            let registry = registry.clone();
            tokio::spawn(async move {
                tokio::task::spawn_blocking(move || registry.dispatch(&req)).await.unwrap_or_default()
            })
        };

        // A cheap, unrelated async task that should complete almost immediately if the
        // single worker thread is actually free to run it concurrently.
        let start = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let concurrent_elapsed = start.elapsed();

        let resp = dispatch_task.await.unwrap();
        assert!(!resp.is_empty(), "dispatch still produces a real response");

        assert!(
            concurrent_elapsed < std::time::Duration::from_millis(150),
            "an unrelated concurrent task took {concurrent_elapsed:?} to complete a 10ms sleep \
             -- the blocking dispatch starved the runtime's only worker thread instead of \
             running on the blocking-thread pool"
        );
    }

    #[test]
    fn run_service_handler_does_not_deadlock_on_input_larger_than_the_pipe_buffer() {
        // #149-A.1 serve-wiring (frozen, regression from review): writing stdin inline then calling
        // wait_with_output() is the classic std::process pipe deadlock — an `input` over the OS pipe
        // buffer (~64 KiB) whose handler (`cat`) writes to stdout before it has drained stdin blocks
        // both sides forever. A consumer fully controls `input`'s size, so this was a remote DoS on
        // the provider, not just a footgun. 200 KiB comfortably exceeds every common pipe buffer size.
        // Bounded by the test harness's own timeout — a real deadlock here means the test hangs, not
        // panics, which is exactly the failure mode being guarded against.
        use ct_common::channel::ServiceType::CodeGeneration;
        let big = "x".repeat(200_000);
        let out = run_service_handler("cat", CodeGeneration, &big).unwrap();
        assert_eq!(out, big, "the full oversized input round-trips without hanging");
    }

    #[test]
    fn run_service_handler_kills_and_errors_a_child_that_exceeds_its_timeout() {
        // #149-A.1 serve-wiring (frozen, regression from review): every other blocking step in this
        // file is timed; this closes the one that wasn't. A handler that never exits (simulating a
        // stalled LLM API call / wedged subprocess) must be killed and reported as a timeout, not
        // block the caller forever. Uses the injectable-timeout seam (a real 120s wait would make
        // this test itself the problem it's guarding against).
        use ct_common::channel::ServiceType::CodeGeneration;
        let start = std::time::Instant::now();
        let err = run_service_handler_with_timeout(
            "sleep 30",
            CodeGeneration,
            "x",
            std::time::Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(err.contains("timed out"), "the timeout is reported: {err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "the call returns promptly after the timeout, not after the child's own 30s sleep: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn run_service_handler_errors_instead_of_silently_succeeding_on_empty_stdout() {
        // #206 (frozen): every shipped handler script (ingredients/presentation/art/physics) prints
        // either its real result or a hardcoded fallback on EVERY code path, under `set -uo pipefail`
        // (no `-e`) specifically so an internal failure still reaches one of those prints. So exit-0
        // with empty stdout is never a legitimate handler result — only a process torn down externally
        // between spawn and its final print (this function's own timeout path already returns Err
        // before ever reaching here, so it can't be the source). Before this fix, `Ok("")` flowed on as
        // a "successful" fragment and blew up downstream as a cryptic `serde_json` "EOF while parsing a
        // value" instead of an honest, attributable error at the source.
        use ct_common::channel::ServiceType::CodeGeneration;
        let err = run_service_handler("true", CodeGeneration, "x").unwrap_err();
        assert!(
            err.contains("no output"),
            "empty-but-successful stdout must be reported as an error, got: {err}"
        );
    }

    #[test]
    fn timeout_kills_the_whole_process_group_not_just_the_immediate_child() {
        // #183 Finding 1 (frozen): the handler scripts shell out to a real LLM CLI as a GRANDCHILD of
        // the `sh -c`. Killing only the `sh` pid on timeout leaves a backgrounded grandchild running
        // (costed, unbounded) as an orphan. This handler BACKGROUNDS a grandchild that would create a
        // marker file AFTER a sleep, while the foreground `sh` sleeps so the call times out. With a
        // process-GROUP kill the grandchild dies too and the marker never appears; the pre-fix
        // single-pid kill would let it survive and touch the marker. Distinguishes the fix, not just
        // the current behaviour.
        use ct_common::channel::ServiceType::TextGeneration;
        let marker = std::env::temp_dir().join(format!(
            "ct-183-pgkill-{}-{:?}.marker",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let m = marker.to_string_lossy().replace('\'', "");
        // background grandchild: after 4s, touch the marker; foreground sleeps so the call times out.
        let cmd = format!("(sleep 4; : > '{m}') & sleep 4");
        let err = run_service_handler_with_timeout(
            &cmd,
            TextGeneration,
            "",
            std::time::Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(err.contains("timed out"), "expected a timeout error, got: {err}");
        // Wait past the grandchild's own 4s sleep; if the group kill worked, the marker never appears.
        std::thread::sleep(std::time::Duration::from_secs(6));
        let survived = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !survived,
            "a backgrounded grandchild survived the timeout kill — the process group was not killed (#183)"
        );
    }

    #[test]
    fn resolve_socket_addr_takes_ip_literals_and_resolves_hostnames_214() {
        use std::net::SocketAddr;
        // #214: a literal IP:port is taken as-is (no resolver), so the common case + tests are
        // resolver-free and deterministic.
        assert_eq!(
            resolve_socket_addr("57.131.133.91:4433").unwrap(),
            "57.131.133.91:4433".parse::<SocketAddr>().unwrap(),
            "an IP:port literal parses unchanged"
        );
        // A host:port hostname resolves via DNS. `localhost` always resolves to a loopback address
        // without any network (hermetic), so this exercises the resolution path deterministically —
        // this is exactly what previously failed with "invalid socket address syntax".
        let resolved = resolve_socket_addr("localhost:4433").expect("localhost:port resolves");
        assert!(resolved.ip().is_loopback(), "localhost resolves to loopback, got {resolved}");
        assert_eq!(resolved.port(), 4433, "the port is preserved through resolution");
        // A bare host with NO port is a clear error (fast, no slow DNS), not an opaque parse failure.
        let err = resolve_socket_addr("bunsenbrenner.org").expect_err("a host with no port is rejected");
        assert!(err.contains("no IP:port") || err.contains("host:port"), "the error is descriptive: {err}");
    }

    #[test]
    fn channel_join_cli_config_parses_the_plane_one_liner() {
        // #98 / #103: the plane-brokered one-liner's config contract — broker + relay
        // addrs, the operator-signed grant (hex), the holder + Noise keys, and the
        // advertised endpoint. Round-trips a real grant through decode.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xABu8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex = hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());
        let hk = "1111111111111111111111111111111111111111111111111111111111111111";
        let nk = "2222222222222222222222222222222222222222222222222222222222222222";
        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "initiate".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", hk.into()),
            ("CT_CHANNEL_NOISE_KEY", nk.into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        };
        let cfg = lookup(&base).expect("plane-brokered config parses");
        assert_eq!(cfg.role, ChannelRole::Initiate);
        assert_eq!(cfg.broker_addr, "203.0.113.5:9443".parse().unwrap());
        assert_eq!(cfg.relay_addr, "203.0.113.5:9444".parse().unwrap());
        assert_eq!(cfg.listen_addr, "203.0.113.5:7000".parse().unwrap());
        assert_eq!(cfg.grant.grant.channel, ChannelId([0xABu8; 32]), "the grant round-trips through decode");

        // Each required field is enforced.
        for drop_key in ["CT_CHANNEL_BROKER", "CT_CHANNEL_RELAY", "CT_CHANNEL_GRANT", "CT_CHANNEL_HOLDER_KEY", "CT_CHANNEL_LISTEN"] {
            let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
            assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
        }

        // #173 (frozen): a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is
        // OPTIONAL when CT_CHANNEL_RELAY_ONLY=1 — dropping it must NOT error (both source-2 and sink
        // hit the old hard-error and had to supply a dummy). It parses as relay-only with an unbound
        // placeholder listen address that's never used.
        let mut relay_only_no_listen: Vec<(&str, String)> =
            base.iter().filter(|(k, _)| *k != "CT_CHANNEL_LISTEN").cloned().collect();
        relay_only_no_listen.push(("CT_CHANNEL_RELAY_ONLY", "1".into()));
        let ro = lookup(&relay_only_no_listen).expect("relay-only needs no CT_CHANNEL_LISTEN (#173)");
        assert!(ro.relay_only, "explicit CT_CHANNEL_RELAY_ONLY=1 is relay-only");
        assert_eq!(ro.listen_addr, SocketAddr::from(([0, 0, 0, 0], 0)), "unbound placeholder listen");

        // #106: without a front door, the dial ladder is direct-only.
        assert_eq!(cfg.front_door, None);
        assert_eq!(
            cfg.broker_ladder(),
            vec![ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct }]
        );

        // With CT_CHANNEL_FRONT_DOOR set, each ladder tries the direct port then the :443
        // front door (the fallback for networks that block the channel ports).
        let mut with_fd = base.clone();
        with_fd.push(("CT_CHANNEL_FRONT_DOOR", "203.0.113.5:443".into()));
        let cfg = lookup(&with_fd).expect("front-door config parses");
        assert_eq!(cfg.front_door, Some("203.0.113.5:443".parse().unwrap()));
        assert_eq!(
            cfg.broker_ladder(),
            vec![
                ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct },
                ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor },
                ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoorBoring },
            ],
            "broker: direct, then the :443 front door, then the same :443 with a boring ClientHello"
        );
        assert_eq!(
            cfg.relay_ladder(),
            vec![
                ChannelDialRung { endpoint: "203.0.113.5:9444".parse().unwrap(), kind: ChannelDialKind::Direct },
                ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor },
                ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoorBoring },
            ],
            "relay falls back the same way"
        );

        // #106 boring-alpn: the DPI-resistant rung is strictly LAST -- on any network where
        // the existing rungs work it is never reached, so this is purely additive.
        let boring: Vec<usize> = cfg
            .broker_ladder()
            .iter()
            .enumerate()
            .filter(|(_, r)| r.kind == ChannelDialKind::FrontDoorBoring)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(boring, vec![2], "exactly one boring rung, and it is the last one tried");
        assert_eq!(
            cfg.broker_ladder()[2].endpoint,
            cfg.broker_ladder()[1].endpoint,
            "the boring rung reuses the SAME :443 endpoint -- only its ClientHello differs"
        );

        // A set-but-malformed front door is a hard error (a typo must not silently drop it).
        let mut bad_fd = base.clone();
        bad_fd.push(("CT_CHANNEL_FRONT_DOOR", "not-an-addr".into()));
        assert!(lookup(&bad_fd).is_err(), "malformed CT_CHANNEL_FRONT_DOOR rejected");

        // A host:port hostname resolves, exactly like CT_CHANNEL_BROKER/CT_CHANNEL_RELAY
        // already do (#214) -- a real regression: this used to be a bare SocketAddr parse
        // with no resolver, so a compose-network service name like "edge:443" failed with
        // "invalid socket address syntax" even though the identical hostname worked fine
        // for CT_CHANNEL_BROKER/CT_CHANNEL_RELAY on the same line.
        let mut hostname_fd = base.clone();
        hostname_fd.push(("CT_CHANNEL_FRONT_DOOR", "localhost:443".into()));
        let cfg = lookup(&hostname_fd).expect("a host:port hostname resolves for the front door too");
        assert!(cfg.front_door.expect("front door set").ip().is_loopback(), "localhost resolves to loopback");

        // CT_CHANNEL_ADVERTISE absent -> advertise_addr defaults to listen_addr, unchanged
        // behavior from before this field existed.
        assert_eq!(cfg.advertise_addr, cfg.listen_addr, "advertise defaults to listen when unset");
    }

    #[test]
    fn channel_advertise_address_splits_bind_from_dial_target() {
        // A containerized accept-side member binds a private/unspecified address
        // (CT_CHANNEL_LISTEN=0.0.0.0:7000, works inside any container) but is reached at
        // a different, real public one (CT_CHANNEL_ADVERTISE, e.g. a Docker port-published
        // <public-ip>:<port>) -- mirrors CT_AGENT_DIRECT_ADVERTISE's existing split for the
        // Browser-Plane tunnel path. Relay-only auto-detection and the peer-facing
        // admission endpoint must both follow the ADVERTISED address, not the bind one.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ed25519_dalek::Signer;
        let op = SigningKey::from_bytes(&[8u8; 32]);
        let holder = SigningKey::from_bytes(&[0x22u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xCDu8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Accept,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant_hex = hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());
        let hk = "3333333333333333333333333333333333333333333333333333333333333333";
        let nk = "4444444444444444444444444444444444444444444444444444444444444444";
        let base: Vec<(&str, String)> = vec![
            ("CT_CHANNEL_ROLE", "accept".into()),
            ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
            ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
            ("CT_CHANNEL_LISTEN", "0.0.0.0:7000".into()),
            ("CT_CHANNEL_GRANT", grant_hex),
            ("CT_CHANNEL_HOLDER_KEY", hk.into()),
            ("CT_CHANNEL_NOISE_KEY", nk.into()),
        ];
        let lookup = |pairs: &[(&str, String)]| {
            let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        };

        // Bind is 0.0.0.0:7000 (not globally routable) and no CT_CHANNEL_ADVERTISE is set ->
        // auto-detected relay-only, exactly as before this field existed.
        let cfg = lookup(&base).expect("binds on 0.0.0.0 without an advertise override");
        assert!(cfg.relay_only, "an unspecified bind with no advertise override is relay-only");

        // With a real public CT_CHANNEL_ADVERTISE, the member is dialable: relay_only is
        // false, the bind address is unchanged (still 0.0.0.0:7000, what the process
        // actually binds), and the admission endpoint sent to the broker is the
        // ADVERTISED address, not the bind address.
        let mut with_adv = base.clone();
        with_adv.push(("CT_CHANNEL_ADVERTISE", "203.0.113.9:7000".into()));
        let cfg = lookup(&with_adv).expect("advertise override parses");
        assert!(!cfg.relay_only, "a globally-routable advertise override is directly dialable");
        assert_eq!(cfg.listen_addr, "0.0.0.0:7000".parse().unwrap(), "bind address is unchanged");
        assert_eq!(cfg.advertise_addr, "203.0.113.9:7000".parse().unwrap());

        // A set-but-malformed advertise override is a hard error (a typo must not
        // silently fall back to the unroutable bind address).
        let mut bad_adv = base.clone();
        bad_adv.push(("CT_CHANNEL_ADVERTISE", "not-an-addr".into()));
        assert!(lookup(&bad_adv).is_err(), "malformed CT_CHANNEL_ADVERTISE rejected");

        // #104: CT_CHANNEL_DIRECT_UPGRADE absent -> off, unchanged behavior from before
        // this option existed.
        assert!(!cfg.direct_upgrade, "direct-upgrade defaults to off");

        let mut with_upgrade = base.clone();
        with_upgrade.push(("CT_CHANNEL_DIRECT_UPGRADE", "1".into()));
        let cfg = lookup(&with_upgrade).expect("direct-upgrade opt-in parses");
        assert!(cfg.direct_upgrade, "CT_CHANNEL_DIRECT_UPGRADE=1 opts in");
    }

    #[test]
    fn channel_config_parses_roles_keys_and_the_initiator_cert_requirement() {
        // #98/#100: the one-liner's config contract. A responder needs no peer cert;
        // an initiator does. Bad role / missing key / bad addr are rejected.
        let acc = cfg_from(&[
            ("CT_CHANNEL_ROLE", "accept"),
            ("CT_CHANNEL_ADDR", "0.0.0.0:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ])
        .expect("responder config is valid without a peer cert");
        assert_eq!(acc.role, ChannelRole::Accept);
        assert_eq!(acc.addr, "0.0.0.0:9000".parse().unwrap());
        assert!(acc.peer_cert_der.is_none());

        // Initiator without a cert is valid (dials accept-any; Noise authenticates);
        // a hex cert, if given, is parsed and pinned.
        let base = [
            ("CT_CHANNEL_ROLE", "initiate"),
            ("CT_CHANNEL_ADDR", "203.0.113.9:9000"),
            ("CT_CHANNEL_NOISE_KEY", K64),
            ("CT_CHANNEL_PEER_NOISE_KEY", K64),
        ];
        let no_cert = cfg_from(&base).expect("initiator without a cert is valid (accept-any dial)");
        assert!(no_cert.peer_cert_der.is_none());
        let mut with_cert = base.to_vec();
        with_cert.push(("CT_CHANNEL_PEER_CERT", "deadbeef"));
        let init = cfg_from(&with_cert).expect("initiator with a cert is valid");
        assert_eq!(init.peer_cert_der.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));

        // Rejections.
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "bogus"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad role");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "not-an-addr"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad addr");
        assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", "tooshort"), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad key");
    }

    #[tokio::test]
    async fn runner_pipes_local_data_over_the_a2a_tunnel() {
        // #72 AF4-session-wire / #98: the runnable path. Two agents each call
        // run_channel_session with their role over a REAL QUIC connection, each
        // handing it a LOCAL duplex. Bytes written to the initiator's local side come
        // out of the responder's local side — plaintext in, plaintext out, encrypted
        // A2A tunnel in between. This is exactly what the CLI wires to stdin/stdout.
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Responder: accept the connection, run the Accept side, pump its local end.
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Initiator: dial, run the Initiate side (pinning the responder key), pump local.
        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
            // hold the connection until the pump finishes
        });

        // Drive it: write a payload into the initiator's local side; the pump
        // forwards it, so exactly those bytes come out of the responder's local side.
        // (Read the exact length rather than to-EOF: both pumps stay open for the
        // reverse direction, so there is no EOF to wait on here.)
        let payload = b"data flowing agent A -> agent B over the channel";
        init_local_test.write_all(payload).await.expect("write local");
        init_local_test.flush().await.expect("flush local");

        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read peer local");
        assert_eq!(got, payload, "the responder's local side receives exactly what A sent");

        init_task.abort();
        resp_task.abort();
    }

    // A minimal edge-broker stand-in that admits one join and acks a fixed peer
    // endpoint + Noise key. It replicates the broker wire protocol (length-framed
    // request, possession challenge, `OK <endpoint> <noise_hex>`) but omits the
    // `safe_endpoint` SSRF gate — which is tested in `ct_edge::channel_broker` and
    // would (correctly) reject the loopback address a hermetic test must use.
    async fn stub_broker_admit(
        server: &Endpoint,
        peer_addr: std::net::SocketAddr,
        peer_noise: [u8; 32],
        peer_holder: [u8; 32],
        peer_attestation: [u8; 64],
    ) {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.expect("len");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut buf).await.expect("req");
        send.write_all(&[0u8; 32]).await.expect("challenge"); // possession challenge
        let mut sig = [0u8; 64];
        let _ = recv.read_exact(&mut sig).await; // (signature not checked by the stub)
        // Ack the attested-key triple the real broker relays (#101).
        let ack = format!(
            "OK {} {} {} {}",
            peer_addr,
            hex_encode(&peer_noise),
            hex_encode(&peer_holder),
            hex_encode(&peer_attestation)
        );
        send.write_all(ack.as_bytes()).await.expect("ack");
        send.finish().expect("finish");
        conn.closed().await;
    }

    #[tokio::test]
    async fn channel_join_initiator_uses_the_rendezvous_peer_and_pipes_data() {
        // #72 AF4 / #100 hands-off capstone: run_channel_join presents to the broker,
        // takes the peer endpoint AND Noise key from the ack (no out-of-band value),
        // dials the peer (accept-any), and pipes data. Here the peer is a real
        // responder listener; the stub broker supplies its addr+key.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        // Responder: a real direct listener running the Accept side of the session.
        let responder_noise = generate_static_keypair();
        let (resp_listener, _c) = crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let resp_addr = resp_listener.local_addr().expect("resp addr");
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let rnp = responder_noise.private;
        let resp_task = tokio::spawn(async move {
            let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // Stub broker: admits the initiator and relays the responder's addr + key.
        let (broker_ep, broker_cert) = build_server_endpoint_with_cert().expect("broker");
        let broker_addr = broker_ep.local_addr().expect("broker addr");
        let rnpub = responder_noise.public;
        // The stub relays the responder's attested-key triple (#101): a holder that
        // signs the responder's Noise key for the initiator's channel.
        let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
        let resp_hpub = resp_holder.verifying_key().to_bytes();
        let resp_att = resp_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId([0xD0u8; 32]), &resp_hpub, &rnpub))
            .to_bytes();
        let broker_task = tokio::spawn(async move {
            stub_broker_admit(&broker_ep, resp_addr, rnpub, resp_hpub, resp_att).await
        });

        // Initiator: run_channel_join over a connection to the (stub) broker.
        let initiator_noise = generate_static_keypair();
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId([0xD0u8; 32]),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        let req = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let inp = initiator_noise.private;
        let a_task = tokio::spawn(async move {
            let c = build_client_endpoint(broker_cert).expect("client");
            let conn = c.connect(broker_addr, "localhost").expect("cfg").await.expect("conn");
            // Direct dial succeeds here (the stub broker gives a real responder addr),
            // so relay_conn is unused — reuse the broker conn; timeouts don't fire.
            run_channel_join(
                &conn,
                &conn,
                &req,
                &holder,
                ChannelRole::Initiate,
                &inp,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local_run,
            )
            .await
        });

        // Data flows initiator -> responder with zero out-of-band key/cert exchange.
        let payload = b"hands-off: peer addr + Noise key came from the rendezvous ack";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the responder receives the initiator's data, keyed only via rendezvous");

        a_task.abort();
        resp_task.abort();
        broker_task.abort();
    }

    #[tokio::test]
    async fn run_channel_join_with_admission_runs_the_direct_session_from_a_443_ladder_admission() {
        // #106 client-dial-wire (frozen): the seam the plane CLI now uses. The AGENT
        // admits over the broker LADDER — a DEAD direct rung (blocked channel port) then a
        // real `:443` TLS-TCP front door driven by the production
        // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and the resulting
        // ChannelJoinOutcome drives run_channel_join_with_admission's DIRECT data path to a
        // real responder. Broker admission is thereby decoupled from (and reachable over
        // `:443` independently of) the direct/relay data legs; data flows with zero
        // out-of-band key/cert exchange. (The QUIC relay handle is present but unused — the
        // direct dial succeeds — since the relay-leg-over-`:443` is the ⏳ follow slice.)
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at};
        use ed25519_dalek::Signer;
        use tokio::io::AsyncWriteExt;

        let channel = [0x6Au8; 32];

        // Responder: a real direct listener running the Accept side of the session.
        let responder_noise = generate_static_keypair();
        let (resp_listener, _c) =
            crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let resp_addr = resp_listener.local_addr().expect("resp addr");
        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let rnp = responder_noise.private;
        let resp_task = tokio::spawn(async move {
            let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        // The responder's attested-key triple (#101) the front door relays in its ack, so
        // the initiator pins the responder's Noise key with nothing conveyed out-of-band.
        let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
        let resp_hpub = resp_holder.verifying_key().to_bytes();
        let resp_npub = responder_noise.public;
        let resp_att = resp_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &resp_hpub, &resp_npub))
            .to_bytes();

        // Operator-signed initiator grant; the front door authorizes it under op_pub.
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
        // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };

        // A real `:443`-style TLS-TCP edge front door: admit the join over the duplex, then
        // ack the responder's addr + attested Noise triple (as the rendezvous broker would).
        let (fd_listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls-tcp listener");
        let fd_addr = fd_listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let (tcp, peer) = fd_listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500u64, // now < expires_at (1_000)
                std::time::Duration::from_secs(5),
                &move |c: ChannelId, _h: [u8; 32]| {
                    let ok = c.0 == channel;
                    async move { ok.then_some((op_pub, None, None)) }
                },
            )
            .await
            .expect("admit over the :443 TLS-TCP duplex");
            let ack = format!(
                "OK {} {} {} {}",
                resp_addr,
                hex_encode(&resp_npub),
                hex_encode(&resp_hpub),
                hex_encode(&resp_att)
            );
            stream.write_all(ack.as_bytes()).await.expect("ack");
            stream.shutdown().await.expect("shutdown");
        });

        // The broker ladder: a DEAD direct rung (closed UDP port → the QUIC dial is
        // Unreachable) then the LIVE `:443` front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ];

        // Admit over the ladder: direct is Unreachable → the `:443` front door completes it.
        let admission = present_channel_join_via_ladder(
            &rungs,
            &request,
            &holder,
            edge_cert,
            std::time::Duration::from_millis(400),
        )
        .await
        .expect("admitted over the :443 front door after the dead direct rung");

        // A scratch (unused) QUIC relay handle — the direct dial succeeds, so it is never
        // touched; the outcome-driven data path still requires a `&Connection` for the leg.
        let (scratch_ep, scratch_cert) = build_server_endpoint_with_cert().expect("scratch relay ep");
        let scratch_addr = scratch_ep.local_addr().expect("scratch addr");
        tokio::spawn(async move {
            if let Some(inc) = scratch_ep.accept().await {
                let _ = inc.await;
            }
        });
        let sc = build_client_endpoint(scratch_cert).expect("scratch client");
        let unused_relay = sc.connect(scratch_addr, "localhost").expect("cfg").await.expect("scratch conn");

        // The outcome-driven data path dials the responder directly and pumps bytes.
        let initiator_noise = generate_static_keypair();
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let inp = initiator_noise.private;
        let a_task = tokio::spawn(async move {
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&unused_relay),
                &request,
                &holder,
                ChannelRole::Initiate,
                &inp,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local_run,
                false,
            )
            .await
        });

        // Data flows initiator -> responder: `:443` broker admission + direct data leg.
        let payload = b"admitted over :443, then piped over the direct A2A session";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the responder receives the initiator's data (admitted over :443, direct data leg)");

        edge.await.expect("edge task");
        a_task.abort();
        resp_task.abort();
    }

    #[tokio::test]
    async fn agents_tunnel_a_noise_session_over_the_edge_relay() {
        // #72 AF4-session-resilience CAPSTONE — the connection-difficulty case that
        // matters: two agents that can't reach each other directly both fall back to
        // the edge RELAY endpoint, run a real Noise_IK session over the relayed stream,
        // and application data flows THROUGH the edge (the edge only sees ciphertext).
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE1u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // Edge relay endpoint pairs + splices the two members.
        let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
        let relay_addr = relay_ep.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Both agents fall back to the relay (they never reach each other directly).
        let cert_b = cert.clone();
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
            join_via_relay(&conn, &req_a, &holder_a, ChannelRole::Initiate, &na, &nbpub, a_local_run, None).await
        });
        let (nb, napub) = (noise_b.private, noise_a.public);
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
            join_via_relay(&conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &napub, b_local_run, None).await
        });

        // Application data flows A -> B over the relayed, encrypted A2A tunnel.
        let payload = b"tunnel carried over the edge relay when direct was blocked";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "B receives A's data via the edge relay (Noise stays E2E)");

        a.abort();
        b.abort();
        relay_task.abort();
    }

    #[tokio::test]
    async fn join_via_relay_ladder_falls_back_to_the_443_front_door_and_forms_the_noise_tunnel() {
        // #106 relay-leg-443 (frozen): the relay-leg analog of the `:443` broker fallback,
        // and the capstone for a fully `:443`-only member. BOTH members' relay ladders have
        // a DEAD direct rung (the relay port is FILTERED → the QUIC dial is Unreachable) then
        // a LIVE `:443` TLS-TCP front door driven by the PRODUCTION edge relay path
        // (`admit_and_pair_on_stream` → `finish_relay_pair_over_streams`). Each member walks
        // `join_via_relay_ladder`, falls through the dead direct rung, presents its join over
        // `:443` WITHOUT consuming the stream, and runs the Noise_IK session over that SAME
        // relay-spliced stream. A real payload round-trips BOTH directions — proving a member
        // whose relay port is also blocked relays end-to-end over `:443` (the #103 sink),
        // Noise staying end-to-end (the edge splices ciphertext only).
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::{
            admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
        };
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use std::sync::Mutex;
        use std::time::Duration;
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE4u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // Advertised endpoints must be SAFE (non-loopback) to pass the admission gate, even
        // though the relay leg never dials them (the members can't be dialed — that's why
        // they relay).
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // A real `:443`-style TLS-TCP edge front door: admit two independently-arriving
        // members, correlate them by channel, and relay-splice the two `:443` duplexes —
        // the production front-door relay path (#106).
        let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
            .await
            .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((op_pub, None, None)) };
            let mut paired = None;
            for _ in 0..2 {
                let (tcp, peer) = listener.accept().await.expect("accept tcp");
                let tls = acceptor.accept(tcp).await.expect("tls accept");
                if let Some((x, y)) = admit_and_pair_on_stream(
                    tls,
                    peer,
                    500u64, // now < expires_at (1_000)
                    Duration::from_secs(5),
                    &authorize,
                    10_000u64, // parked-member deadline (never reached in this test)
                    &pairer,
                )
                .await
                .expect("admit + pair the :443 member")
                {
                    paired = Some((x, y));
                }
            }
            let (x, y) = paired.expect("two same-channel members paired over :443");
            finish_relay_pair_over_streams(x, y, 500u64).await.expect("relay-splice the two :443 duplexes");
        });

        // Each member's relay ladder: a DEAD direct rung (closed UDP port → the QUIC relay
        // dial is Unreachable) then the LIVE `:443` front door.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // nothing on that UDP port -> the direct QUIC relay dial is Unreachable
        let rungs = vec![
            ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
            ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ];

        // Two members drive `join_via_relay_ladder`: A initiates, B accepts. Each pins the
        // peer's Noise key directly (the relay leg conveys no peer material).
        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let rungs_a = rungs.clone();
        let cert_a = edge_cert.clone();
        let a = tokio::spawn(async move {
            join_via_relay_ladder(
                &rungs_a,
                cert_a,
                Duration::from_millis(400),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                &nbpub,
                a_local,
                None,
            )
            .await
        });
        let (nb, napub) = (noise_b.private, noise_a.public);
        let b = tokio::spawn(async move {
            join_via_relay_ladder(
                &rungs,
                edge_cert,
                Duration::from_millis(400),
                &req_b,
                &holder_b,
                ChannelRole::Accept,
                &nb,
                &napub,
                b_local,
                None,
            )
            .await
        });

        // A -> B over the `:443`-relayed, encrypted A2A tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the :443 relay");

        // B -> A (reverse direction proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

        // Closing both local sides tears the sessions down cleanly (noise_pump shuts down
        // each transport write half → graceful TLS close_notify → the relay sees EOF).
        drop(a_app);
        drop(b_app);
        let _ = a.await.expect("initiator task joins");
        let _ = b.await.expect("acceptor task joins");
        edge.await.expect("edge relay task joins");
    }

    #[tokio::test]
    async fn two_443_only_members_learn_each_others_noise_key_and_form_the_tunnel() {
        // #122 (frozen): the bug that broke EVERY `:443`-only two-party join. Two members
        // FORCED onto the public `:443` front door (relay/broker ports unreachable), each with
        // FRESHLY + independently generated channel keys and grants — NO pre-shared peer Noise
        // key, no reliance on any prior broker-admission step. Each drives the join over the
        // PRODUCTION relay-splice path (`admit_and_pair_on_stream` → `finish_relay_pair_over_
        // streams`) and MUST learn the OTHER's attested Noise key FROM THE ACK itself
        // (`Admitted.peer_noise_pubkey == Some(peer key)`), verify the #101 attestation, pin it,
        // and form the Noise_IK tunnel — a real payload crossing BOTH directions. Before the
        // fix the relay acked a bare `OK` conveying no key, so `peer_noise_pubkey` was `None`
        // and the join failed at the pin step (channel_run.rs). So this test FAILS against the
        // bare-`OK` code and PASSES once the ack carries the peer's attested key.
        use ct_common::channel::{
            member_noise_attest_bytes, verify_member_noise_attestation, ChannelGrant, ChannelId,
            Direction, Rights, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
        };
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::{
            admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
        };
        use ct_edge::transport::build_tcp_tls_listener_at;
        use ed25519_dalek::Signer;
        use std::sync::Mutex;
        use std::time::Duration;
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let op = SigningKey::from_bytes(&[0x5Au8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let channel = [0xC2u8; 32];
        // Fresh, independent identities per member — nothing pre-shared between them.
        let holder_a = SigningKey::from_bytes(&[0x2au8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x2bu8; 32]);
        let ha_pub = holder_a.verifying_key().to_bytes();
        let hb_pub = holder_b.verifying_key().to_bytes();
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let (na, na_pub) = (noise_a.private, noise_a.public);
        let (nb, nb_pub) = (noise_b.private, noise_b.public);
        // Each member attests its OWN Noise key under its holder key (#101).
        let attest_a = holder_a
            .sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &na_pub))
            .to_bytes();
        let attest_b = holder_b
            .sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
            .to_bytes();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // Both are `:443`-only — they advertise the relay-only sentinel (they can't be dialed).
        let req_a = ChannelJoinRequest {
            grant: signed(&holder_a, Direction::Initiate),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed(&holder_b, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };

        // The PRODUCTION `:443` front door: admit two independently-arriving members, correlate
        // them by channel, and relay-splice the two duplexes. The `authorize` closure resolves
        // each member to its OWN (operator, Noise key, attestation) — exactly as the CP-backed
        // registry does — so the relay finisher has the material to relay each side the OTHER's
        // attested key.
        let (listener, acceptor, edge_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .expect("tls-tcp listener");
        let fd_addr = listener.local_addr().expect("front-door addr");
        let edge = tokio::spawn(async move {
            let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
            let authorize = move |c: ChannelId, h: [u8; 32]| async move {
                if c.0 != channel {
                    return None;
                }
                let (noise, attest) =
                    if h == ha_pub { (na_pub, attest_a) } else { (nb_pub, attest_b) };
                Some((op_pub, Some(noise), Some(attest)))
            };
            let mut paired = None;
            for _ in 0..2 {
                let (tcp, peer) = listener.accept().await.expect("accept tcp");
                let tls = acceptor.accept(tcp).await.expect("tls accept");
                if let Some((x, y)) = admit_and_pair_on_stream(
                    tls,
                    peer,
                    500u64,
                    Duration::from_secs(5),
                    &authorize,
                    10_000u64,
                    &pairer,
                )
                .await
                .expect("admit + pair the :443 member")
                {
                    paired = Some((x, y));
                }
            }
            let (x, y) = paired.expect("two same-channel members paired over :443");
            finish_relay_pair_over_streams(x, y, 500u64)
                .await
                .expect("relay-splice the two :443 duplexes");
        });

        let (mut a_app, a_local) = duplex(16 * 1024);
        let (mut b_app, b_local) = duplex(16 * 1024);
        let cert_a = edge_cert.clone();
        // A: connect over `:443`, present the join WITHOUT consuming the stream, LEARN B's
        // attested Noise key from the ack, verify #101, pin it, run the session on the SAME
        // relay-spliced stream.
        let a = tokio::spawn(async move {
            let stream = crate::transport::tcp_tls_connect_channel(fd_addr, cert_a)
                .await
                .expect("A tls-tcp connect");
            let (mut recv, mut send) = split(stream);
            let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_a, &holder_a)
                .await
                .expect("A relay join");
            let peer_noise = match outcome {
                ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                    let n = peer_noise_pubkey.expect("A learns B's Noise key from the ack (#122)");
                    assert_eq!(n, nb_pub, "A learns B's REAL Noise key from the ack");
                    let ph = peer_holder.expect("A learns B's holder from the ack");
                    let att = peer_attestation.expect("A learns B's attestation from the ack");
                    assert!(
                        verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                        "B's #101 attestation verifies against its grant-authenticated holder"
                    );
                    n
                }
                other => panic!("A's :443 join must be Admitted, got {other:?}"),
            };
            run_channel_session_on_stream(send, recv, ChannelRole::Initiate, &na, &peer_noise, a_local).await
        });
        // B: the mirror (Accept role), learning A's key from its ack.
        let b = tokio::spawn(async move {
            let stream = crate::transport::tcp_tls_connect_channel(fd_addr, edge_cert)
                .await
                .expect("B tls-tcp connect");
            let (mut recv, mut send) = split(stream);
            let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_b, &holder_b)
                .await
                .expect("B relay join");
            let peer_noise = match outcome {
                ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                    let n = peer_noise_pubkey.expect("B learns A's Noise key from the ack (#122)");
                    assert_eq!(n, na_pub, "B learns A's REAL Noise key from the ack");
                    let ph = peer_holder.expect("B learns A's holder from the ack");
                    let att = peer_attestation.expect("B learns A's attestation from the ack");
                    assert!(
                        verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                        "A's #101 attestation verifies against its grant-authenticated holder"
                    );
                    n
                }
                other => panic!("B's :443 join must be Admitted, got {other:?}"),
            };
            run_channel_session_on_stream(send, recv, ChannelRole::Accept, &nb, &peer_noise, b_local).await
        });

        // A -> B over the `:443`-relayed, encrypted A2A tunnel keyed on the ACK-LEARNED keys.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B (key learned from the ack)");

        // B -> A (reverse direction proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

        drop(a_app);
        drop(b_app);
        a.await.expect("A task joins").expect("A session ok");
        b.await.expect("B task joins").expect("B session ok");
        edge.await.expect("edge relay task joins");
    }

    #[tokio::test]
    async fn run_channel_join_auto_falls_back_to_the_relay_when_direct_is_blocked() {
        // #72 AF4-relay-orchestrate: the auto-recovery. The rendezvous hands the
        // initiator a peer endpoint that BLACKHOLES (bound-but-silent), so the direct
        // dial times out (Unreachable) and run_channel_join transparently falls back to
        // the edge relay where the responder waits — the tunnel carries data with NO
        // caller intervention.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE2u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // A bound-but-silent UDP socket: the direct dial to it blackholes -> times out.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
        let blackhole_addr = blackhole.local_addr().expect("bh addr");

        // Stub rendezvous: hands the initiator the blackhole addr + B's Noise key.
        let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
        let rdv_addr = rdv_ep.local_addr().expect("rdv addr");
        let nb_pub = noise_b.public;
        // B's attested-key triple, verified by run_channel_join before it falls back.
        let hb_pub = holder_b.verifying_key().to_bytes();
        let b_att = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
            .to_bytes();
        let rdv_task = tokio::spawn(async move {
            stub_broker_admit(&rdv_ep, blackhole_addr, nb_pub, hb_pub, b_att).await
        });

        // Real relay endpoint.
        let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
        let relay_addr = relay_ep.local_addr().expect("relay addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Initiator via run_channel_join: direct -> blackhole -> Unreachable -> relay.
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let na = noise_a.private;
        let relay_cert_a = relay_cert.clone();
        let a = tokio::spawn(async move {
            let bc = build_client_endpoint(rdv_cert).expect("bc");
            let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("bconn");
            let rc = build_client_endpoint(relay_cert_a).expect("rc");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn");
            run_channel_join(
                &broker_conn,
                &relay_conn,
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None,
                std::time::Duration::from_millis(400), // short dial timeout -> fast fallback
                std::time::Duration::from_secs(2),
                a_local_run,
            )
            .await
        });

        // Responder joins the relay directly (its own listen-timeout fallback is covered
        // by run_channel_join's Accept branch; here it goes straight to the relay).
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let nb = noise_b.private;
        let nap = noise_a.public;
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(relay_cert).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run, None).await
        });

        let payload = b"auto-recovered onto the relay after the direct path was blocked";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the tunnel auto-recovered via the relay with no caller intervention");

        a.abort();
        b.abort();
        rdv_task.abort();
        relay_task.abort();
        drop(blackhole);
    }

    #[tokio::test]
    async fn quic_lazy_relay_dials_only_on_fallback_and_forms_the_tunnel() {
        // #103 fix (frozen): RelayFallback::QuicLazy holds NO idle relay connection during
        // admission/direct-dial — it dials the relay only when the direct path fails. Prove
        // the lazily-dialed relay still forms the tunnel end to end. (The eager Quic variant
        // held an idle connection the edge reaped as a spurious pre-admission close.)
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let channel = [0xE4u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
        let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

        // Blackhole direct peer -> the Initiate direct dial times out (Unreachable) -> relay.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
        let blackhole_addr = blackhole.local_addr().expect("bh addr");
        let hb_pub = holder_b.verifying_key().to_bytes();
        let b_att = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public))
            .to_bytes();
        // Pre-computed admission (blackhole peer + B's attested Noise key) — no rendezvous stub.
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: blackhole_addr.to_string(),
            peer_noise_pubkey: Some(noise_b.public),
            peer_holder: Some(hb_pub),
            peer_attestation: Some(b_att),
            observed_reflexive: None,
        };

        // Real relay endpoint.
        let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
        let relay_addr = relay_ep.local_addr().expect("relay addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Initiator: run_channel_join_with_admission with the LAZY relay — direct blackhole
        // -> Unreachable -> QuicLazy dials relay_addr on demand.
        let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
        let na = noise_a.private;
        let a = tokio::spawn(async move {
            run_channel_join_with_admission(
                admission,
                RelayFallback::QuicLazy(relay_addr),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None,
                std::time::Duration::from_millis(400),
                std::time::Duration::from_secs(2),
                a_local_run,
                false,
            )
            .await
        });

        // Responder waits on the relay.
        let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
        let nb = noise_b.private;
        let nap = noise_a.public;
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(relay_cert).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run, None).await
        });

        let payload = b"lazily-dialed relay carries the tunnel (#103)";
        a_local_test.write_all(payload).await.expect("write");
        a_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        b_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the lazily-dialed relay formed the tunnel");

        a.abort();
        b.abort();
        relay_task.abort();
        drop(blackhole);
    }

    #[tokio::test]
    async fn run_channel_join_rejects_a_peer_key_with_a_bad_attestation() {
        // #101 SEC101c-ii: if the relayed peer Noise key's attestation doesn't verify
        // against the peer's holder (a DB-substituted key), run_channel_join REFUSES to
        // pin it — it errors before establishing any session.
        use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let channel = [0xE3u8; 32];
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder_a.verifying_key().to_bytes(),
            direction: Direction::Initiate,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let req_a = ChannelJoinRequest {
            grant: SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() },
            endpoint: "203.0.113.1:7001".to_string(),
        };

        // The stub relays a peer key + holder, but an attestation over a DIFFERENT key
        // (as a tampered DB would produce) — it must not verify.
        let peer_holder = SigningKey::from_bytes(&[0x55u8; 32]);
        let peer_hpub = peer_holder.verifying_key().to_bytes();
        let peer_noise = generate_static_keypair().public;
        let bad_attest = peer_holder
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &peer_hpub, &[0u8; 32]))
            .to_bytes();

        let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
        let rdv_addr = rdv_ep.local_addr().expect("addr");
        let rdv_task = tokio::spawn(async move {
            stub_broker_admit(&rdv_ep, "203.0.113.9:9000".parse().unwrap(), peer_noise, peer_hpub, bad_attest).await
        });

        let bc = build_client_endpoint(rdv_cert).expect("bc");
        let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("conn");
        let noise_a = generate_static_keypair();
        let (_t, local) = tokio::io::duplex(64);
        let result = run_channel_join(
            &broker_conn,
            &broker_conn,
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &noise_a.private,
            None,
            std::time::Duration::from_millis(200),
            std::time::Duration::from_secs(1),
            local,
        )
        .await;
        assert!(result.is_err(), "a peer key with a bad attestation is rejected before pinning (#101)");
        rdv_task.abort();
    }

    #[tokio::test]
    async fn direct_dial_to_an_unreachable_peer_fails_fast_as_unreachable() {
        // #72 AF4-session-resilience — THE case that matters: a peer that can't be
        // reached on the direct path (NAT/firewall/blackhole). The dial must classify
        // as `Unreachable` (the relay-fallback signal) and fail FAST, not hang on the
        // QUIC handshake's retransmits. A bound-but-silent UDP socket blackholes the
        // handshake (the port is "open", so no ICMP reject short-circuits it).
        use std::time::{Duration, Instant};
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sink");
        let addr = sink.local_addr().expect("sink addr"); // occupied, never answers QUIC

        let start = Instant::now();
        let result = dial_peer_direct(addr, Duration::from_millis(400)).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ChannelDialError::Unreachable)),
            "an unreachable peer classifies as Unreachable (relay-fallback signal), got {result:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "failed fast in {elapsed:?}, did not hang");
        drop(sink);
    }

    #[tokio::test]
    async fn initiator_dials_without_a_pre_shared_cert_noise_authenticates() {
        // #100 self-containment: the initiator uses the accept-any channel dialer, so
        // NO transport cert is conveyed — only the peer's Noise key. The responder
        // self-signs (a cert the initiator has never seen); the A2A session still
        // forms and data flows, because Noise_IK is the real mutual auth.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;
        let init_priv = initiator.private;
        let resp_pub = responder.public;

        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
                .await
                .expect("responder session");
        });

        let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
        let endpoint = build_channel_dialer().expect("dialer");
        // Dial with NO peer cert — the accept-any verifier trusts the transport.
        let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let init_task = tokio::spawn(async move {
            run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
                .await
                .expect("initiator session");
        });

        let payload = b"self-contained: no transport cert was conveyed";
        init_local_test.write_all(payload).await.expect("write");
        init_local_test.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        resp_local_test.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "data flows without a pre-shared transport cert");

        init_task.abort();
        resp_task.abort();
    }

    #[tokio::test]
    async fn large_transfer_is_not_truncated_when_the_sender_tears_down_after_the_session(
    ) {
        // #134 (frozen): a large A2A transfer must be delivered in FULL even when the sending
        // agent drops the connection the instant its session returns (the real bug: the process
        // exits right after the pump FINs). quinn `finish()` only queues the FIN; without waiting
        // for the peer's acknowledgement, the userspace QUIC driver dies on connection-drop and
        // the unacked tail is silently lost (the sink saw clean 144/224 KiB prefixes of a 588 KB
        // payload). `run_channel_session`'s send-drain (`stopped()`) is what closes that hole —
        // it returns only once the peer has acknowledged every byte, so the drop below is safe.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let (init_priv, resp_priv, resp_pub) = (initiator.private, responder.private, responder.public);

        // ~1 MiB — well past the ~144 KiB first-flight/window where the truncation was observed.
        let payload: Vec<u8> = (0..(1024u32 * 1024)).map(|i| (i % 251) as u8).collect();
        let len = payload.len();

        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        // Responder: accept, run the Accept session, and collect exactly `len` delivered bytes.
        // Its local read half is closed at once (no responder→initiator app data), so its own
        // send direction FINs immediately; we read the payload out concurrently to open flow
        // control. We do NOT await the responder session (its own drain would wait on the
        // now-gone initiator) — read_exact of the full length is the delivery assertion.
        let resp_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (resp_run, resp_test) = tokio::io::duplex(64 * 1024);
            let (mut resp_test_r, resp_test_w) = tokio::io::split(resp_test);
            drop(resp_test_w); // responder→initiator app source EOF
            let _sess = tokio::spawn(async move {
                let _ = run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_run).await;
                // keep `conn` alive for the session's lifetime, then drop
                drop(conn);
            });
            let mut got = vec![0u8; len];
            let r = resp_test_r.read_exact(&mut got).await;
            (r.is_ok(), got)
        });

        // Initiator: dial, feed the whole payload then EOF the source, run the session to
        // completion (which now blocks on the delivery ack), THEN drop the connection+endpoint
        // — simulating the process exiting the moment the transfer "finished".
        let endpoint = build_channel_dialer().expect("dialer");
        let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (init_run, init_test) = tokio::io::duplex(64 * 1024);
        let (init_test_r, mut init_test_w) = tokio::io::split(init_test);
        drop(init_test_r); // no initiator←responder app data
        let feeder = tokio::spawn(async move {
            init_test_w.write_all(&payload).await.expect("feed payload");
            init_test_w.flush().await.expect("flush");
            drop(init_test_w); // source EOF → initiator outbound FINs
            payload
        });

        run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_run)
            .await
            .expect("initiator session");
        // The drain has returned → the peer acknowledged every byte. Now tear the sender down
        // as abruptly as a process exit would.
        drop(conn);
        drop(endpoint);

        let expected = feeder.await.expect("feeder");
        let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp_task)
            .await
            .expect("responder collected within 20s")
            .expect("responder task");
        assert!(ok, "the full {len}-byte payload was delivered (no truncation) despite the abrupt sender teardown (#134)");
        assert_eq!(got, expected, "delivered bytes are byte-exact and complete");
    }

    #[tokio::test]
    async fn open_channel_streams_bounds_a_stalled_setup_instead_of_hanging() {
        // #139 (frozen): after dial_peer_direct connects, open_bi/accept_bi were unbounded — a QUIC
        // conn that handshaked then went dead hung the direct-session setup forever with no relay
        // fallback. `open_channel_streams` bounds it. Here the client connects but NEVER opens the
        // channel bi-stream, so the server's accept_bi would hang; the bound turns that into a fast
        // `TimedOut`, which lets the direct path fall back to the relay instead of wedging.
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
        let addr = server.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let start = std::time::Instant::now();
            let r = open_channel_streams(&conn, ChannelRole::Accept, std::time::Duration::from_millis(300)).await;
            (r.as_ref().err().map(|e| e.kind()), r.is_ok(), start.elapsed())
        });

        // Connect and hold the connection open, but NEVER open a bi-stream.
        let dialer = build_channel_dialer().expect("dialer");
        let _conn = dialer.connect(addr, "localhost").expect("cfg").await.expect("conn");

        let (kind, ok, elapsed) = tokio::time::timeout(std::time::Duration::from_secs(5), srv)
            .await
            .expect("the bounded setup returns within 5s (a hang here is the #139 regression)")
            .expect("join");
        assert!(!ok, "a stalled stream setup errors, it does not hang or succeed");
        assert_eq!(kind, Some(std::io::ErrorKind::TimedOut), "the stall is reported as TimedOut (#139)");
        assert!(elapsed < std::time::Duration::from_secs(2), "the bound fires fast (~300ms), not after a long wait");
    }

    #[tokio::test]
    async fn upgradable_session_refuses_a_private_direct_target_and_stays_byte_exact_on_relay() {
        // #104 wire-in + #137 SSRF guard (frozen): two agents run an UPGRADABLE A2A session over a
        // relay quinn conn. The initiator advertises a direct listener bound on LOOPBACK
        // (`127.0.0.1`), so the #137 guard (`upgrade_safe_endpoint` = the edge's `is_global_unicast`
        // filter) correctly REFUSES the responder's dial of that peer-conveyed internal endpoint —
        // the session stays on the relay and the payload still arrives byte-exact. This proves the
        // SSRF guard (a) blocks a private/internal upgrade target and (b) does not break delivery.
        // (The full relay→direct upgrade over a *global-unicast* target can't run on loopback — that
        // is H4's live cross-NAT proof; the pure upgrade mechanics are covered by the ct-common
        // orchestration + DCUtR tests.)
        use crate::transport::{build_channel_dialer, build_direct_listener_at};
        use ct_common::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let a = generate_static_keypair(); // channel initiator
        let b = generate_static_keypair(); // channel responder
        let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);
        let dt = std::time::Duration::from_secs(5);

        // Relay leg: the responder is the quinn server, the initiator connects to it.
        let (relay_server, _rc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("relay listener");
        let relay_addr = relay_server.local_addr().expect("relay addr");
        // The initiator's direct listener (the responder dials this to upgrade).
        let (direct_listener, _dc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("direct listener");
        let direct_addr = direct_listener.local_addr().expect("direct addr").to_string();

        // Responder: accept the relay conn, run the upgradable Accept session, collect the payload.
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        let len = payload.len();
        let resp = tokio::spawn(async move {
            let relay_conn = relay_server.accept().await.expect("incoming").await.expect("relay conn");
            let (resp_app, resp_test) = tokio::io::duplex(1 << 16);
            let (mut resp_out, _w) = tokio::io::split(resp_test);
            let sess = tokio::spawn(async move {
                let _ = run_channel_session_upgradable(
                    &relay_conn, ChannelRole::Accept, &b_priv, &a_pub, resp_app, None, None, dt,
                )
                .await;
                drop(relay_conn);
            });
            let mut got = vec![0u8; len];
            let ok = resp_out.read_exact(&mut got).await.is_ok();
            sess.abort();
            (ok, got)
        });

        // Initiator: dial the relay, run the upgradable Initiate session with its direct listener.
        let dialer = build_channel_dialer().expect("dialer");
        let relay_conn = dialer.connect(relay_addr, "localhost").expect("cfg").await.expect("relay conn");
        let (init_app, init_test) = tokio::io::duplex(1 << 16);
        let (_r, mut init_feed) = tokio::io::split(init_test);
        let init = tokio::spawn(async move {
            run_channel_session_upgradable(
                &relay_conn,
                ChannelRole::Initiate,
                &a_priv,
                &b_pub,
                init_app,
                Some(direct_listener),
                Some(direct_addr),
                dt,
            )
            .await
        });

        init_feed.write_all(&payload).await.unwrap();
        init_feed.flush().await.unwrap();
        init_feed.shutdown().await.unwrap();

        let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp)
            .await
            .expect("responder within 20s")
            .expect("responder task");
        assert!(ok, "the full {len}-byte payload was delivered across the upgradable session");
        assert_eq!(got, payload, "relay→direct upgrade over real quinn delivered a byte-exact stream (#104)");
        init.abort();
    }

    #[test]
    fn relay_only_mode_forces_on_explicitly_and_auto_detects_a_non_routable_listen_addr() {
        // #121 (frozen): the pure relay-only decision. The explicit CT_CHANNEL_RELAY_ONLY flag
        // always forces relay-only (even with a routable address); otherwise a member
        // auto-detects relay-only when its advertised listen address is not globally routable
        // (a NAT-only / private-address-only host the edge would refuse to advertise, #94), and
        // stays direct-capable only with a real global-unicast address. It decides from the
        // address alone — no network interfaces touched — so it is deterministically testable.
        assert!(
            relay_only_mode(true, "203.0.113.10:7000".parse().unwrap()),
            "the explicit flag forces relay-only even for a routable address"
        );
        // Auto-detect: private / loopback / unspecified / CGNAT / link-local / ULA => relay-only.
        for private in [
            "10.0.0.5:7000",
            "192.168.1.9:7000",
            "172.16.0.1:7000",
            "127.0.0.1:7000",
            "0.0.0.0:7000",
            "100.64.0.1:7000",
            "169.254.1.1:7000",
            "[fc00::1]:7000",
            "[fe80::1]:7000",
        ] {
            assert!(relay_only_mode(false, private.parse().unwrap()), "{private} auto-detects relay-only");
        }
        // A real global-unicast address stays direct-capable (not forced relay-only).
        for routable in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
            assert!(!relay_only_mode(false, routable.parse().unwrap()), "{routable} stays direct-capable");
        }
    }

    #[test]
    fn parse_circuit_relay_is_optional_and_rejects_a_malformed_multiaddr() {
        // #136 N-wire (frozen): CT_CHANNEL_CIRCUIT_RELAY is the libp2p circuit-relay for the DCUtR
        // punch. Absent/blank => None (plain relay session, no punch); a valid multiaddr parses;
        // a malformed value is an error (a typo must not silently disable the hole-punch).
        assert_eq!(parse_circuit_relay(None), Ok(None));
        assert_eq!(parse_circuit_relay(Some("   ".to_string())), Ok(None));

        // A valid Circuit-Relay v2 multiaddr (relay TCP addr + /p2p-circuit) parses + round-trips.
        let ma = "/ip4/203.0.113.1/tcp/4001/p2p-circuit";
        let parsed = parse_circuit_relay(Some(ma.to_string())).expect("valid multiaddr parses");
        assert_eq!(parsed.map(|m| m.to_string()), Some(ma.to_string()));

        // A malformed value fails config load (not silently dropped).
        assert!(parse_circuit_relay(Some("not-a-multiaddr".to_string())).is_err());
    }

    #[tokio::test]
    async fn build_upgrade_candidate_binds_an_ephemeral_listener_only_when_reflexive_is_known() {
        // #104: no observed_reflexive (e.g. the edge reported none for this admission) ->
        // no candidate, no listener bound -- direct_upgrade being on is a no-op for this
        // session, exactly the same as before the option existed.
        assert!(build_upgrade_candidate(None).await.is_none(), "no reflexive -> no candidate");

        // A real reflexive address -> a real, freshly-bound ephemeral listener, and the
        // offered string's reflexive half is exactly the edge-observed address, never
        // anything self-selected (#276 piece 1 may additionally append a NUL-separated
        // local candidate -- see `split_offered_candidates` -- when this host has a real
        // local egress IP, which the test environment may or may not have).
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        let (listener, offered) = build_upgrade_candidate(Some(addr)).await.expect("candidate built");
        let (reflexive, local) = split_offered_candidates(&offered);
        assert_eq!(reflexive, "203.0.113.7:4433", "offers exactly the edge-observed address");
        if let Some(local) = local {
            let local_addr: SocketAddr = local.parse().expect("appended local candidate is a valid SocketAddr");
            assert!(
                is_lan_candidate(local_addr.ip()),
                "an appended local candidate is always a real private/ULA address, never anything else"
            );
        }
        let bound = listener.local_addr().expect("listener is actually bound");
        assert_eq!(bound.ip(), std::net::Ipv4Addr::UNSPECIFIED, "binds 0.0.0.0, not the offered address");
        assert_ne!(bound.port(), 0, "the ephemeral port was actually assigned by the OS");
    }

    #[test]
    fn split_offered_candidates_recovers_the_optional_local_half() {
        // #276 piece 1: the reflexive-only (pre-#276) format still round-trips unchanged.
        assert_eq!(split_offered_candidates("203.0.113.7:4433"), ("203.0.113.7:4433", None));
        // The new compound format recovers both halves.
        assert_eq!(
            split_offered_candidates("203.0.113.7:4433\0192.168.1.42:5000"),
            ("203.0.113.7:4433", Some("192.168.1.42:5000"))
        );
        // A malformed (empty) local segment degrades to "no local candidate", not a parse
        // error -- the reflexive candidate alone is always a complete, valid offer.
        assert_eq!(split_offered_candidates("203.0.113.7:4433\0"), ("203.0.113.7:4433", None));
    }

    #[test]
    fn select_upgrade_candidate_prefers_a_genuinely_same_subnet_local_candidate() {
        // #276 piece 1's core behavior: when the peer-offered local candidate lands in
        // OUR OWN local subnet, prefer it over the reflexive one.
        let Some(my_local) = local_egress_ip() else {
            return; // no route in this sandbox -- nothing to assert against
        };
        // Construct a same-subnet candidate at a different last octet (v4) or suffix (v6),
        // matching same_local_subnet's own /24 (v4) / /64 (v6) heuristic.
        let same_subnet = match my_local {
            std::net::IpAddr::V4(v4) => {
                let mut o = v4.octets();
                o[3] = o[3].wrapping_add(1).max(1);
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]))
            }
            std::net::IpAddr::V6(_) => return, // v6 egress is environment-dependent; v4 case covers the seam
        };
        if !is_lan_candidate(my_local) {
            return; // this sandbox's egress isn't a private address at all -- nothing to assert
        }
        let ep = format!("203.0.113.7:4433\0{same_subnet}:5000");
        let chosen = select_upgrade_candidate(&ep).expect("a same-subnet local candidate is chosen");
        assert_eq!(chosen.ip(), same_subnet, "the local candidate was preferred over the reflexive one");
    }

    #[test]
    fn select_upgrade_candidate_refuses_an_off_subnet_local_candidate_and_falls_back() {
        // #276 piece 1's safety property, exercised end-to-end through select_upgrade_candidate:
        // a local candidate that is NOT in our own subnet must never be dialed, regardless of
        // how plausible-looking it is -- the reflexive candidate is used instead.
        let ep = "203.0.113.7:4433\0192.168.250.250:5000";
        let chosen = select_upgrade_candidate(ep).expect("falls back to the reflexive candidate");
        assert_eq!(chosen, "203.0.113.7:4433".parse::<SocketAddr>().unwrap(), "off-subnet local candidate refused, reflexive used instead");
    }

    #[test]
    fn select_upgrade_candidate_never_dials_an_unsafe_reflexive_fallback_either() {
        // The pre-#276 #137 guard still applies to the reflexive half when there is no
        // (or an unusable) local candidate.
        assert!(select_upgrade_candidate("192.168.1.1:4433").is_none(), "private reflexive with no local candidate -> refused, not silently dialed");
        assert!(select_upgrade_candidate("203.0.113.7:4433").is_some(), "a plain global-unicast reflexive with no local half still works");
    }

    #[tokio::test]
    async fn build_upgrade_candidate_refuses_a_non_global_unicast_reflexive_248() {
        // #248 (found live, 2026-08-01): a member co-located with the edge on the same
        // Docker host gets an edge-observed reflexive address on the Docker bridge
        // network (RFC1918) -- real, but never reachable by a genuinely external peer.
        // Offering it anyway left the initiator hanging for the full session timeout
        // instead of degrading to relay-only immediately, since the peer's own SSRF
        // guard (#137) silently refuses to dial it. Symmetric with `upgrade_safe_endpoint`'s
        // existing filter on the *peer's* offered endpoint -- applied here to our own.
        for bad in [
            "172.18.0.19:4433",  // RFC1918 (the exact address found live, #248)
            "10.0.0.5:4433",     // RFC1918
            "192.168.1.9:4433",  // RFC1918
            "127.0.0.1:4433",    // loopback
            "169.254.1.1:4433",  // link-local
        ] {
            let addr: SocketAddr = bad.parse().unwrap();
            assert!(
                build_upgrade_candidate(Some(addr)).await.is_none(),
                "{bad} is not global-unicast -- must not be offered as a direct candidate"
            );
        }
        // A genuinely global-unicast reflexive still works (unchanged from the test above).
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        assert!(build_upgrade_candidate(Some(addr)).await.is_some());
    }

    #[test]
    fn upgrade_safe_endpoint_refuses_ssrf_ranges_and_admits_only_global_unicast() {
        // #137 (frozen): the responder's SSRF guard for the peer-conveyed #104 Offer.direct_endpoint.
        // Because the in-band upgrade bypasses the edge broker's `safe_endpoint` gate (#94), the
        // guard must apply the SAME range filter — an internal / private / metadata / link-local /
        // CGNAT / ULA / unspecified target (and anything unparseable) is refused; only a
        // global-unicast address is dialable. Matches the edge's `safe_endpoint` semantics exactly
        // (both are `parse + ct_common::channel::is_global_unicast`).
        for bad in [
            "127.0.0.1:7000",       // loopback
            "10.0.0.5:7000",        // RFC1918
            "192.168.1.9:7000",     // RFC1918
            "172.16.0.1:7000",      // RFC1918
            "169.254.169.254:80",   // cloud metadata / link-local
            "100.64.0.1:7000",      // CGNAT
            "0.0.0.0:7000",         // unspecified
            "[::1]:7000",           // IPv6 loopback
            "[fe80::1]:7000",       // IPv6 link-local
            "[fc00::1]:7000",       // IPv6 ULA
            "not-an-addr",          // unparseable
            "example.com:443",      // hostname, not an IP:port
        ] {
            assert!(upgrade_safe_endpoint(bad).is_none(), "{bad} must be refused (SSRF / unparseable) — #137");
        }
        for ok in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
            assert!(upgrade_safe_endpoint(ok).is_some(), "{ok} must be admitted (global-unicast)");
        }
    }

    #[tokio::test]
    async fn two_relay_only_members_join_without_a_dialable_address_and_relay_splice() {
        // #121 (frozen): the reachability floor. TWO relay-only members — each advertising the
        // relay-only SENTINEL (no dialable address), each with NO bound listener — join and are
        // relay-spliced by the PRODUCTION edge relay path (`broker_channel_relay`). Presenting
        // the sentinel to the real relay proves the edge admits it in production. The initiator's
        // paired peer_endpoint is the sentinel, so `run_channel_join_with_admission` SKIPS the
        // wasted direct dial and relays straight away; the acceptor has no listener, so it relays
        // directly too. A real payload round-trips BOTH directions, the Noise_IK session staying
        // end-to-end (the edge splices ciphertext only) — so a NAT-only member with only a
        // private address participates purely via the relay + the #106 :443 fallback.
        use ct_common::channel::{
            member_noise_attest_bytes, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
            CHANNEL_ENDPOINT_RELAY_ONLY,
        };
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let channel = [0xE5u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        // BOTH members advertise the relay-only sentinel — neither has a dialable address.
        let req_a = ChannelJoinRequest {
            grant: signed(&holder_a, Direction::Initiate),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed(&holder_b, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };

        // Each member's attested-key triple (#101): its holder signs its Noise key for the
        // channel so the peer verifies + pins it with nothing conveyed out-of-band.
        let ha_pub = holder_a.verifying_key().to_bytes();
        let hb_pub = holder_b.verifying_key().to_bytes();
        let a_att = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &noise_a.public)).to_bytes();
        let b_att = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public)).to_bytes();

        // The PRODUCTION edge relay: admits both sentinel-advertising members (proving the edge
        // admits the relay-only sentinel over the real relay path), pairs, and splices them.
        let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
        let relay_addr = relay_ep.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Member A (initiator): its paired peer_endpoint is the SENTINEL → skip the direct dial,
        // relay straight away. The admission is constructed directly (a real rendezvous would
        // swap the two sentinel endpoints); the relay leg is the production edge.
        let cert_a = cert.clone();
        let (mut a_app, a_local) = tokio::io::duplex(8192);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let a = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_a).expect("rc a");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn a");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(nbpub),
                peer_holder: Some(hb_pub),
                peer_attestation: Some(b_att),
                observed_reflexive: None,
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None, // relay-only: no bound listener
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local,
                false,
            )
            .await
        });

        // Member B (acceptor): NO bound listener (relay-only) → relay straight away.
        let cert_b = cert.clone();
        let (mut b_app, b_local) = tokio::io::duplex(8192);
        let (nb, napub) = (noise_b.private, noise_a.public);
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_b).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(napub),
                peer_holder: Some(ha_pub),
                peer_attestation: Some(a_att),
                observed_reflexive: None,
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_b,
                &holder_b,
                ChannelRole::Accept,
                &nb,
                None, // relay-only: no bound listener
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                b_local,
                false,
            )
            .await
        });

        // A -> B over the relay-only, edge-spliced, encrypted A2A tunnel.
        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes");
        assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B via the relay (both relay-only)");

        // B -> A (reverse proves the splice is full-duplex).
        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
        assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A via the relay");

        // Both payloads are confirmed received BEFORE any teardown, so there is no last-byte
        // race to lose; abort the tasks to end the still-open sessions.
        a.abort();
        b.abort();
        relay_task.abort();
    }

    #[tokio::test]
    async fn direct_upgrade_opt_in_still_completes_over_the_relay_when_the_candidate_is_unsafe() {
        // #104 wiring, real proof: with CT_CHANNEL_DIRECT_UPGRADE on and a real
        // edge-observed reflexive address baked into the admission (exactly what a live
        // admission delivers), the session still round-trips a real payload byte-exact —
        // it does NOT hang, error, or silently drop data. On loopback the "reflexive"
        // address is necessarily non-global-unicast, so the responder's #137 SSRF guard
        // (upgrade_safe_endpoint) correctly refuses the in-band upgrade candidate and the
        // session gracefully stays on the relay -- the same behavior this project's own
        // single-host demos get in production, and exactly what "on: but nothing routable
        // to offer" must do: never break the session, never silently accept an unsafe
        // target.
        use ct_common::channel::{
            member_noise_attest_bytes, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
            CHANNEL_ENDPOINT_RELAY_ONLY,
        };
        use ct_common::noise::generate_static_keypair;
        use ct_edge::channel_broker::broker_channel_relay;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use ed25519_dalek::Signer;

        let op = SigningKey::from_bytes(&[9u8; 32]);
        let op_pub = op.verifying_key().to_bytes();
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let channel = [0xE6u8; 32];
        let noise_a = generate_static_keypair();
        let noise_b = generate_static_keypair();
        let signed = |h: &SigningKey, dir| {
            let g = ChannelGrant {
                channel: ChannelId(channel),
                holder: SigningKey::verifying_key(h).to_bytes(),
                direction: dir,
                rights: Rights::ReadWrite,
                delegable: false,
                expires_at: 1_000,
            };
            SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
        };
        let req_a = ChannelJoinRequest {
            grant: signed(&holder_a, Direction::Initiate),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed(&holder_b, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let ha_pub = holder_a.verifying_key().to_bytes();
        let hb_pub = holder_b.verifying_key().to_bytes();
        let a_att = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &noise_a.public)).to_bytes();
        let b_att = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public)).to_bytes();

        let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
        let relay_addr = relay_ep.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
                (c.0 == channel).then_some((op_pub, None, None))
            })
            .await
            .map(|_| ())
        });

        // Member A: direct_upgrade ON, with a real (loopback) observed_reflexive -- exactly
        // the shape a live edge admission delivers, just not a globally-routable address.
        let cert_a = cert.clone();
        let (mut a_app, a_local) = tokio::io::duplex(8192);
        let (na, nbpub) = (noise_a.private, noise_b.public);
        let a = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_a).expect("rc a");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn a");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(nbpub),
                peer_holder: Some(hb_pub),
                peer_attestation: Some(b_att),
                observed_reflexive: Some("127.0.0.1:7001".parse().unwrap()),
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_a,
                &holder_a,
                ChannelRole::Initiate,
                &na,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                a_local,
                true, // #104 direct_upgrade opt-in
            )
            .await
        });

        let cert_b = cert.clone();
        let (mut b_app, b_local) = tokio::io::duplex(8192);
        let (nb, napub) = (noise_b.private, noise_a.public);
        let b = tokio::spawn(async move {
            let rc = build_client_endpoint(cert_b).expect("rc b");
            let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
            let admission = ChannelJoinOutcome::Admitted {
                peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
                peer_noise_pubkey: Some(napub),
                peer_holder: Some(ha_pub),
                peer_attestation: Some(a_att),
                observed_reflexive: Some("127.0.0.1:7002".parse().unwrap()),
            };
            run_channel_join_with_admission(
                admission,
                RelayFallback::Quic(&relay_conn),
                &req_b,
                &holder_b,
                ChannelRole::Accept,
                &nb,
                None,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(5),
                b_local,
                true, // #104 direct_upgrade opt-in
            )
            .await
        });

        a_app.write_all(b"ping-A-to-B").await.expect("a writes");
        let mut got = [0u8; 11];
        b_app.read_exact(&mut got).await.expect("b reads A's bytes despite the upgrade attempt");
        assert_eq!(&got, b"ping-A-to-B", "direct_upgrade=on still delivers real plaintext via the relay");

        b_app.write_all(b"pong-B-to-A").await.expect("b writes");
        let mut got2 = [0u8; 11];
        a_app.read_exact(&mut got2).await.expect("a reads B's bytes despite the upgrade attempt");
        assert_eq!(&got2, b"pong-B-to-A", "full-duplex still works with direct_upgrade on both sides");

        a.abort();
        b.abort();
        relay_task.abort();
    }
}
