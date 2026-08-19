//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.
//!
//! ## Mode landscape (#25)
//!
//! Three independent axes select the code path a `ct-agent channel` process runs;
//! confusing them has cost real debugging hours, so they are named here once:
//!
//! 1. **Direct-address vs. Plane** (`main.rs` dispatch): `CT_CHANNEL_BROKER` set means
//!    plane-brokered ([`ChannelJoinCliConfig`] → [`run_channel_join_command`]); unset
//!    means the direct-address [`ChannelRunConfig`] path (`CT_CHANNEL_ADDR` +
//!    `CT_CHANNEL_PEER_NOISE_KEY`, no edge involved at all).
//! 2. **Plain broker vs. Ladder** (within the plane mode): a configured
//!    `CT_CHANNEL_FRONT_DOOR` cert selects the dial LADDER
//!    ([`present_channel_join_via_ladder`]); without it, admission is a single direct
//!    QUIC dial to the broker. The `dialing … rung …` log lines exist ONLY on the
//!    ladder path — their absence on a plain-broker member is a different code path,
//!    not a failure.
//! 3. **Relay-only DCUtR variants** (`CT_CHANNEL_RELAY_GATE`, preferred over
//!    `CT_CHANNEL_CIRCUIT_RELAY`; both via [`run_dcutr_join_loop`]): the gated
//!    relay leg for NAT-hostile networks and the nat-lab rig.

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
    present_channel_join_marked, present_channel_join_on_stream, present_channel_relay_join_on_stream,
    ChannelJoinOutcome, ADMISSION_EXCHANGE_TIMEOUT, PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS,
};
use ct_common::a2a::{a2a_initiate, a2a_respond_verified};
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
    // CADS-Tunnel#495 U2 (a'): broker_conn is admission-only -- the actual session runs
    // over the separately-passed relay_conn/direct connection below -- PHASE_MARKER_RENDEZVOUS.
    let admission = present_channel_join_marked(broker_conn, request, holder, PHASE_MARKER_RENDEZVOUS).await?;
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
        ChannelJoinOutcome::Refused { category } => {
            // #524: the frozen base string stays the prefix; the category (when the
            // edge sent one) appends the actionable class of failure.
            return Err(AdmissionRefused::boxed_with_category(
                "edge broker refused the channel join",
                category.as_deref(),
            ));
        }
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
                Err(ChannelDialError::Failed(e) | ChannelDialError::ConnectFailed(e)) => return Err(e),
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
                // ct-agent#22: do not spend the accept window on a connection that cannot
                // arrive. The edge just told this member which address it is seen on; if
                // that contradicts what it advertises, inbound is not going to happen and
                // the 8 s is pure latency on every single first contact.
                if !own_endpoint_looks_reachable(&request.endpoint, observed_reflexive) {
                    eprintln!(
                        "ct-agent channel: advertised {} but the edge observes this member on {} \
                         -- inbound cannot reach the advertised address, going straight to the \
                         edge relay instead of waiting {accept_timeout:?} (#22). Set \
                         CT_CHANNEL_RELAY_ONLY=1 to make this explicit.",
                        request.endpoint,
                        observed_reflexive.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                    );
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
                    return Ok(());
                }
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
    // CADS-Tunnel#495 U2 (a'): relay_conn's own bi-stream carries the session below --
    // PHASE_MARKER_RELAY, mirroring the :443 relay ladder's phase_marker_for(&stream,
    // PHASE_MARKER_RELAY) call.
    match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted { .. } => {}
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            return Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ));
        }
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
/// cross-NAT punch is proven in the Docker 2-NAT lab (N-rig-2); on loopback it degrades to the
/// relay. **Not on the live plane** — the "/ the live plane (N-rig-3)" this line used to carry
/// is the same overclaim corrected at [`run_channel_session_upgradable`] and
/// [`crate::p2p::run_upgradable_dcutr_session`]: ct-agent#6 (open) measures every real cross-NAT
/// direct dial failing. The lab half of the sentence is accurate and stays.
/// ct-agent#41 (#35 "Path A"): verify a relay-admitted DCUtR peer's Noise key is attested by
/// its grant-authenticated holder before pinning it -- the same check
/// `run_channel_join_with_admission` already does for the main path (mod.rs, #101 SEC101c-ii).
/// Shared by [`join_via_relay_dcutr`] and [`join_via_relay_gate_dcutr`], the two joins that do
/// their OWN [`present_channel_join`] call rather than going through
/// `run_channel_join_with_admission`, so neither had this check at all before.
///
/// Without it, a malicious/compromised edge could substitute its own key in the admission
/// response; the DCUtR "verified" responder downstream (`p2p.rs`, ct-agent#11) only checks the
/// LIVE peer against whatever key this function hands it, so a consistent substitution at both
/// points would defeat that check too. Only the independently-signed attestation (which the
/// edge cannot forge) closes it. Pure (no I/O), so unit-testable without a live relay.
pub(crate) fn verify_relayed_dcutr_peer(
    request: &ChannelJoinRequest,
    noise: [u8; 32],
    peer_holder: Option<[u8; 32]>,
    peer_attestation: Option<[u8; 64]>,
) -> Result<[u8; 32], BoxError> {
    let peer_holder =
        peer_holder.ok_or("relay admitted the DCUtR join but relayed no peer holder -- cannot verify (#101)")?;
    let attestation =
        peer_attestation.ok_or("relay admitted the DCUtR join but relayed no attestation (#101)")?;
    if !ct_common::channel::verify_member_noise_attestation(
        &request.grant.grant.channel,
        &peer_holder,
        &noise,
        &attestation,
    ) {
        return Err("peer Noise-key attestation failed -- refusing to pin a possibly-substituted key (#101)".into());
    }
    Ok(noise)
}

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
    // CADS-Tunnel#495 U2 (a'): relay_conn's own bi-stream carries the DCUtR base leg
    // below -- PHASE_MARKER_RELAY.
    let peer_noise = match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(noise), peer_holder, peer_attestation, .. } => {
            verify_relayed_dcutr_peer(request, noise, peer_holder, peer_attestation)?
        }
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            return Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ));
        }
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
        // #524: on a refusal the edge follows the `NO` sentinel with a length-framed
        // category token and shuts the stream down — opportunistically read it (bounded;
        // an old edge yields EOF at once → None → the generic message below, unchanged).
        let category = if &ack == b"NO" {
            let mut tail = Vec::new();
            let mut bounded = (&mut stream).take(crate::channel::REFUSAL_CATEGORY_MAX_LEN as u64 + 1);
            match tokio::time::timeout(std::time::Duration::from_secs(2), bounded.read_to_end(&mut tail)).await {
                Ok(Ok(_)) => crate::channel::decode_refusal_category(&tail),
                _ => None,
            }
        } else {
            None
        };
        // #24: typed -- this is the relay-gate's wire `NO`, a DEFINITIVE refusal the
        // retry policy must back off on (it was a bare string before, invisible to
        // `is_definitive_admission_refusal`, so the serve loop hot-looped on it).
        return Err(AdmissionRefused::boxed_with_category(
            "relay-gate: pre-auth refused (grant not authorized -- see the edge's own log)",
            category.as_deref(),
        ));
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
            let request = &request;
            let cfg = &cfg;
            let relay_gate_cert = &relay_gate_cert;
            return run_dcutr_join_loop("relay-gate", serve_loop, move || async move {
                let relay_conn =
                    dial_relay_preferring_direct(cfg.relay_addr_direct, cfg.relay_addr, DIRECT_DIAL_TIMEOUT).await?;
                let local = channel_local();
                Ok(join_via_relay_gate_dcutr(
                    &relay_conn,
                    request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    relay_gate_addr,
                    relay_gate_cert.clone(),
                    &cfg.grant,
                )
                .await)
            })
            .await;
        }
        if let Some(circuit) = cfg.circuit_relay.clone() {
            eprintln!(
                "ct-agent channel: relay-only DCUtR-upgradable {:?} (relay {}, circuit {}){}",
                cfg.role, cfg.relay_addr, circuit,
                if serve_loop { " — persistent serve: retries transient stalls (#248)" } else { "" }
            );
            let request = &request;
            let cfg = &cfg;
            let circuit = &circuit;
            // #24: the label is a parameter now -- this branch used to print
            // "relay-gate admission error" from its copied loop body.
            return run_dcutr_join_loop("circuit-relay", serve_loop, move || async move {
                let relay_conn = crate::transport::build_channel_dialer()?
                    .connect(cfg.relay_addr, "localhost")?
                    .await?;
                let local = channel_local();
                Ok(join_via_relay_dcutr(
                    &relay_conn,
                    request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    circuit.clone(),
                )
                .await)
            })
            .await;
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

mod errors;
pub(crate) use errors::*;

mod serving;
pub(crate) use serving::*;

mod service_calls;
pub use service_calls::*;

mod provisioning;
pub use provisioning::*;

mod cli_config;
pub use cli_config::*;

mod dialing;
pub use dialing::*;

mod connectivity;
pub use connectivity::*;

#[cfg(test)]
mod tests;
