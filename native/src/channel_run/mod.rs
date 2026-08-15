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
///
/// #25: this walks the same rung sequence as [`dial_ladder`] but cannot be composed over
/// it — `local` is single-move (committed to exactly one rung's session), while
/// `dial_ladder`'s per-rung closure must be re-callable for every rung. The hand-rolled
/// `last: Option<BoxError>` accumulator here is that constraint, not an oversight.
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
                    // #495 slice 2a (v0.4.14): mark this leg's PHASE when the edge speaks
                    // the KA generation -- phase-compatible pairing removes the mixed-phase
                    // early-eof class. An old edge negotiated a legacy id: no marker sent.
                    let phase_marker = crate::channel::phase_marker_for(&stream, crate::channel::PHASE_MARKER_RELAY);
                    let (mut recv, mut send) = tokio::io::split(stream);
                    let local = local.take().expect("local is committed to exactly one rung");
                    match present_channel_relay_join_on_stream(&mut send, &mut recv, request, holder, phase_marker).await? {
                        ChannelJoinOutcome::Admitted { .. } => {}
                        ChannelJoinOutcome::Refused { category } => {
                            // #524: base string frozen, category appended when present.
                            return Err(AdmissionRefused::boxed_with_category(
                                "edge relay refused the channel join over the :443 front door",
                                category.as_deref(),
                            ));
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
    /// member: sleep `delay`, reset the one-shot retry counter to 0, carry
    /// `consecutive_refusals` forward, and admit the next peer.
    RetryReset { delay: std::time::Duration, consecutive_refusals: u32 },
    /// An error, and a one-shot caller's own bounded retry budget still has room: sleep
    /// `delay`, bump the counter to `next_attempt`, and try again.
    RetryBounded { next_attempt: u32, delay: std::time::Duration },
    /// Stop the loop; return the original result to the caller (a one-shot caller out of
    /// retries or definitively refused, or a non-`serve_loop` result of either kind).
    Stop,
}

/// The fast inter-session cadence of the DCUtR loops (#248) — the delay after a
/// SUCCESSFUL session or a transient error; refusals and park expiries get the
/// policy delays from [`errors`] instead (#24).
const DCUTR_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);

/// #248: a one-shot Initiate (or non-serve Accept) on the relay-gate/circuit-relay
/// DCUtR path shouldn't fail on the very first #140 stall either -- live-reproduced
/// on the a2a-demo's plain "bob" scenario: the persistent --serve side eventually
/// gets past a stall by retrying forever, while the one-shot side had zero tolerance
/// and failed the whole call on one hiccup. Bounded (unlike `serve_loop`'s retry)
/// because a one-shot CLI/demo call must still terminate in reasonable time.
const ONE_SHOT_DCUTR_ADMISSION_RETRIES: u32 = 2;

/// #24: the DCUtR loops used to route on `result.is_ok()` alone, which threw the
/// error CLASS away — a serve member with a definitively refused grant hot-looped
/// at ~5 attempts/s against the edge forever, the exact flood #231 was filed
/// about. This now applies the same policy [`errors`] documents and
/// `serve_loop_concurrent` already follows: definitive refusals back off
/// exponentially (capped, [`admission_retry_backoff`]), park expiries re-park
/// immediately, transients and completed sessions keep the fast cadence. A
/// one-shot caller stops right away on a definitive refusal — its bounded
/// retries cannot succeed without operator action. Pure.
fn dcutr_loop_action<T>(
    result: &Result<T, BoxError>,
    serve_loop: bool,
    attempt: u32,
    max_one_shot_retries: u32,
    consecutive_refusals: u32,
) -> DcutrLoopAction {
    let (errored, refused, expired) = match result {
        Ok(_) => (false, false, false),
        Err(e) => (true, is_definitive_admission_refusal(e), is_park_expired(e)),
    };
    if serve_loop {
        let (delay, refusals) = if expired {
            (std::time::Duration::ZERO, 0) // #21: re-park immediately
        } else if refused {
            (admission_retry_backoff(DCUTR_RETRY_BACKOFF, true, consecutive_refusals), consecutive_refusals + 1)
        } else {
            // A completed session or a transient error: fast cadence, streak broken.
            let _ = errored;
            (DCUTR_RETRY_BACKOFF, 0)
        };
        return DcutrLoopAction::RetryReset { delay, consecutive_refusals: refusals };
    }
    if refused {
        return DcutrLoopAction::Stop; // definitive: retrying cannot succeed
    }
    if errored && attempt < max_one_shot_retries {
        let delay = if expired { std::time::Duration::ZERO } else { DCUTR_RETRY_BACKOFF };
        return DcutrLoopAction::RetryBounded { next_attempt: attempt + 1, delay };
    }
    DcutrLoopAction::Stop
}

/// #24: the shared DCUtR join loop both relay-only variants run — deduplicated
/// from two near-verbatim ~45-line copies whose diverged `label` printed
/// "relay-gate" in the circuit-relay branch. `join` performs ONE dial+admission
/// attempt; its **outer** `Err` is a dial/setup failure and stays terminal
/// (exactly the old `?`-propagation), while the **inner** `Result` is the
/// admission outcome and is routed through [`dcutr_loop_action`]'s policy.
async fn run_dcutr_join_loop<T, F, Fut>(label: &str, serve_loop: bool, join: F) -> Result<T, BoxError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Result<T, BoxError>, BoxError>>,
{
    let mut attempt: u32 = 0;
    let mut consecutive_refusals: u32 = 0;
    loop {
        let result = join().await?;
        match dcutr_loop_action(&result, serve_loop, attempt, ONE_SHOT_DCUTR_ADMISSION_RETRIES, consecutive_refusals) {
            DcutrLoopAction::RetryReset { delay, consecutive_refusals: refusals } => {
                if let Err(e) = &result {
                    eprintln!("ct-agent channel: {label} admission error, re-admitting in {delay:?} (#248/#24): {e}");
                }
                attempt = 0;
                consecutive_refusals = refusals;
                tokio::time::sleep(delay).await;
            }
            DcutrLoopAction::RetryBounded { next_attempt, delay } => {
                attempt = next_attempt;
                if let Err(e) = &result {
                    eprintln!(
                        "ct-agent channel: {label} admission error, retrying ({attempt}/{ONE_SHOT_DCUTR_ADMISSION_RETRIES}) (#248): {e}"
                    );
                }
                tokio::time::sleep(delay).await;
            }
            DcutrLoopAction::Stop => return result,
        }
    }
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
            // #25: name the path -- rung log lines exist only on the ladder above, and
            // their absence here has been misread as a failure during live debugging.
            eprintln!("ct-agent channel: direct-QUIC broker admission (no front-door cert configured -- no ladder)");
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
        ChannelJoinOutcome::Refused { ref category } => {
            // #524: base string frozen, category appended when present.
            Err(AdmissionRefused::boxed_with_category(
                "edge broker refused the channel join",
                category.as_deref(),
            ))
        }
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
                    // #495 slice 2a (v0.4.14): mark the RENDEZVOUS phase on KA-generation
                    // edges (see the relay ladder's twin comment for the why).
                    let phase_marker = crate::channel::phase_marker_for(&stream, crate::channel::PHASE_MARKER_RENDEZVOUS);
                    // #506: a KA-negotiated leg waits for its pairing on the TICK contract
                    // (the edge's 10 s NUL keepalives prove the park alive), so the park may
                    // outlive the fixed 45 s exchange bound once the edge runs a long TTL.
                    // Deliberately gated on the ALPN alone — the v0.4.17 marker switch must
                    // not disable liveness-based waiting.
                    let ka_tick_wait = crate::transport::ka_negotiated(&stream);
                    let (recv, send) = tokio::io::split(stream);
                    // finish_send_after_sig = false (#21 follow-up): on this TCP/TLS leg the
                    // old post-signature shutdown was a close_notify+FIN that half-closed the
                    // whole connection -- the parked member then waited out its park as a
                    // closing flow, and the edge's reap teardown RST'd the in-flight EX away
                    // (packet-capture-proven). The edge needs no EOF; keep the leg fully open.
                    present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT, false, phase_marker, ka_tick_wait)
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

mod errors;
pub(crate) use errors::*;

mod service_calls;
pub use service_calls::*;

#[cfg(test)]
mod tests;
