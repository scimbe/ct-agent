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
