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
//!
//! ## The session's end is the streams' end (AUF-20260930-005, INC-20260930-101)
//!
//! Both engines treat "my end of the session duplex went EOF" as "every stream I own is over":
//! the `JoinSet` is aborted on the spot, which closes each forwarded TCP connection, and the
//! engine returns, which EOFs its side of the duplex so the session pump finishes too. The
//! session end itself is decided one layer up, by the grant lifetime the peer-grant gate keeps
//! (`super::peer_grant`): an expiring or revoked grant closes this duplex, which is why the
//! engine has to know nothing about grants.
//!
//! ## A session end is not the forward's end (ct-agent#267, AUF-20261004-022)
//!
//! In 0.7.36 the initiate engine stayed alive after its session ended, refusing every new
//! connection, and never closed its side of the duplex -- so the session never returned and the
//! process neither exited nor reconnected: a peer restart or a relay drop killed the forward
//! until a manual restart. Now the listener belongs to [`run_forward_initiate_reconnect_loop`],
//! which hands it to one fresh engine per session. When a session ends for any reason other than
//! a grant end (recorded as state by the gate, [`super::peer_grant::GrantEndRecord`], or this
//! member's own grant past its expiry), the loop admits a new session after a backoff of
//! [`FORWARD_RECONNECT_MIN`] doubling up to [`FORWARD_RECONNECT_MAX`]; connections made in the
//! meantime wait in the listen backlog and are served by the next session. After a grant end the
//! listener stays open but refuses every connection with a log line (#264), without reconnecting.
//
// trace: AUF-20260930-005 (INC-20260930-101)
// trace: AUF-20261004-022 (ct-agent#267)
// trace: AUF-20261005-016 (DEC-0061)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
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

/// Cancel-safe wrapper around [`Frame::read`] for a `select!` loop (AUF-20261005-016): takes
/// the mux's read half by value and hands it back alongside the result, so the caller can feed
/// the SAME half into the next read once this one actually resolved. Reconstructing
/// `Frame::read(&mut mux_read)` in place every `select!` iteration instead is not cancel-safe —
/// a losing iteration (another branch, e.g. `listener.accept()`, ready first) drops a read
/// that may already have consumed some of its bytes (an `Open`'s target string alone can span
/// several `.await` points), desyncing every frame parsed after it.
async fn read_one_frame<R: AsyncRead + Unpin>(mut r: R) -> (R, io::Result<Frame>) {
    let frame = Frame::read(&mut r).await;
    (r, frame)
}

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
    let (listener, bound) = bind_forward_listener(spec.listen)?;
    let local = forward_initiate_on(listener, spec.target.clone(), max_streams, idle);
    Ok((local, bound))
}

/// Bind the initiate side's loopback listener (synchronously, see [`forward_initiate_local`]),
/// shareable so it can outlive any one session (ct-agent#267).
pub(crate) fn bind_forward_listener(
    listen: SocketAddr,
) -> io::Result<(Arc<TcpListener>, SocketAddr)> {
    let std_listener = std::net::TcpListener::bind(listen)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let bound = listener.local_addr()?;
    Ok((Arc::new(listener), bound))
}

/// One session's initiate-side local app duplex over an already-bound, shared `listener`
/// (ct-agent#267): the engine accepts on it only while its session runs.
pub(crate) fn forward_initiate_on(
    listener: Arc<TcpListener>,
    target: String,
    max_streams: usize,
    idle: Duration,
) -> LocalDuplex {
    forward_initiate_on_with(listener, target, max_streams, idle, flow_control_from_env())
}

/// [`forward_initiate_on`] with credit flow control switched explicitly (tests of mixed versions).
pub(crate) fn forward_initiate_on_with(
    listener: Arc<TcpListener>,
    target: String,
    max_streams: usize,
    idle: Duration,
    fc_enabled: bool,
) -> LocalDuplex {
    let (session_side, engine_side) = tokio::io::duplex(ENGINE_DUPLEX_BUF);
    let pump = TaskGuard::spawn(async move {
        run_forward_initiate_engine(engine_side, listener, target, max_streams, idle, fc_enabled)
            .await;
    });
    LocalDuplex::with_pump(session_side, pump)
}

/// [`FORWARD_MAX_STREAMS_ENV`] and [`FORWARD_IDLE_SECS_ENV`] from the process environment.
pub(crate) fn forward_limits_from_env() -> (usize, Duration) {
    (
        max_streams_from_env(std::env::var(FORWARD_MAX_STREAMS_ENV).ok().as_deref()),
        idle_timeout_from_env(std::env::var(FORWARD_IDLE_SECS_ENV).ok().as_deref()),
    )
}

/// The first wait before re-admitting a forward session that ended without a grant end.
pub const FORWARD_RECONNECT_MIN: Duration = Duration::from_secs(1);
/// The cap the wait doubles up to; a session that ran at least this long counts as healthy and
/// resets the wait to [`FORWARD_RECONNECT_MIN`].
pub const FORWARD_RECONNECT_MAX: Duration = Duration::from_secs(30);

/// The wait before the next admission (ct-agent#267): `prev` is the wait used before the session
/// that just ended (`None` for the first), `lasted` how long that session ran.
pub(crate) fn next_forward_reconnect_delay(prev: Option<Duration>, lasted: Duration) -> Duration {
    match prev {
        Some(p) if lasted < FORWARD_RECONNECT_MAX => (p * 2).min(FORWARD_RECONNECT_MAX),
        _ => FORWARD_RECONNECT_MIN,
    }
}

/// Why the session that just ended must not be replaced, decided from state only
/// (ct-agent#267): the gate's recorded grant end, or this member's own grant past its expiry
/// (`now >= expires_at`, the rule `verify_stateless` applies) -- the latter also covers a member
/// running without the peer-grant check, whose gate records nothing. `None`: reconnect.
pub(crate) fn forward_grant_end(
    recorded: Option<String>,
    own_expires_at: u64,
    now: u64,
) -> Option<String> {
    recorded.or_else(|| {
        (now >= own_expires_at)
            .then(|| format!("this member's channel grant expired (expires_at {own_expires_at})"))
    })
}

/// The #264 end state after a grant end: the listener stays bound and every connection is
/// closed at once, each with one log line naming why. Never returns.
async fn refuse_forward_connections(listener: &TcpListener, why: &str) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer_addr)) => {
                drop(tcp);
                eprintln!("ct-agent channel: forward listener refused {peer_addr}: {why}");
            }
            Err(e) => {
                eprintln!("ct-agent channel: forward listener accept error: {e}");
                // An accept error (e.g. EMFILE) can repeat immediately; do not spin on it.
                tokio::time::sleep(FORWARD_RECONNECT_MIN).await;
            }
        }
    }
}

/// The initiate side's session loop (ct-agent#267, see the module doc): one shared `listener`,
/// one fresh engine and one `admit` call per session, reconnecting with backoff until a grant
/// end, after which it refuses connections for good. `admit` runs one whole session (admission
/// included) over the duplex it is given and returns when that session ends; it is the seam the
/// tests drive without a broker. Returns only if the listener's refusing loop ever could.
pub(crate) async fn run_forward_initiate_reconnect_loop<A, Fut, E>(
    listener: Arc<TcpListener>,
    target: String,
    max_streams: usize,
    idle: Duration,
    own_expires_at: u64,
    mut admit: A,
) where
    A: FnMut(LocalDuplex) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let mut delay: Option<Duration> = None;
    loop {
        let record = super::peer_grant::GrantEndRecord::default();
        let local = forward_initiate_on(listener.clone(), target.clone(), max_streams, idle);
        let started = std::time::Instant::now();
        let outcome = super::peer_grant::with_grant_end_record(record.clone(), admit(local)).await;
        let lasted = started.elapsed();
        if let Some(why) =
            forward_grant_end(record.ended(), own_expires_at, crate::codec::now_unix())
        {
            eprintln!(
                "ct-agent channel: forward session ended after {lasted:?}: {why} -- not reconnecting, \
                 the forward listener refuses every new connection (#264, #267)"
            );
            refuse_forward_connections(&listener, &why).await;
            return;
        }
        let wait = next_forward_reconnect_delay(delay, lasted);
        delay = Some(wait);
        match outcome {
            Ok(()) => eprintln!(
                "ct-agent channel: forward session ended after {lasted:?} without a grant end \
                 (peer restart or relay/network drop) -- reconnecting in {wait:?} (#267)"
            ),
            Err(e) => eprintln!(
                "ct-agent channel: forward session failed after {lasted:?}: {e} -- reconnecting \
                 in {wait:?} (#267)"
            ),
        }
        tokio::time::sleep(wait).await;
    }
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
    forward_accept_local_with(
        allow_raw,
        non_loopback_raw,
        max_streams,
        idle,
        flow_control_from_env(),
    )
}

/// [`forward_accept_local`] with credit flow control switched explicitly (tests of mixed versions).
pub(crate) fn forward_accept_local_with(
    allow_raw: Option<String>,
    non_loopback_raw: Option<String>,
    max_streams: usize,
    idle: Duration,
    fc_enabled: bool,
) -> LocalDuplex {
    let (session_side, engine_side) = tokio::io::duplex(ENGINE_DUPLEX_BUF);
    let pump = TaskGuard::spawn(async move {
        run_forward_accept_engine(
            engine_side,
            allow_raw,
            non_loopback_raw,
            max_streams,
            idle,
            fc_enabled,
        )
        .await;
    });
    LocalDuplex::with_pump(session_side, pump)
}

/// What the demuxer hands a stream's pump for its own inbound side: either bytes the peer sent
/// for this stream, or "the peer says this stream is done" (a received [`Frame::Close`]).
enum StreamIn {
    Data(Vec<u8>),
    Closed,
    /// The peer reset the stream ([`super::forward_wire::CLOSE_REASON_ABORT`]): close the local
    /// socket fully and stop, instead of half-closing and draining.
    Aborted,
}

/// The Close that resets a stream (see [`super::forward_wire::CLOSE_REASON_ABORT`]).
fn abort_frame(id: u32) -> Frame {
    Frame::Close {
        id,
        reason: Some(super::forward_wire::CLOSE_REASON_ABORT.to_string()),
    }
}

/// Exact comparison on purpose: only the reset value resets, every other reason half-closes.
fn stream_in_for_close(reason: Option<&str>) -> StreamIn {
    if reason == Some(super::forward_wire::CLOSE_REASON_ABORT) {
        StreamIn::Aborted
    } else {
        StreamIn::Closed
    }
}

// --- Flow control per stream (DEC-0061, spec REP-20261005-entwurf-flusskontrolle-forward, s. 5) ---
//
// Control messages travel as `Data` on the reserved stream id 0 (real streams start at 1): an
// agent without flow control ignores `Data` for an unknown id, so mixed versions keep working.
//   HELLO      [1, b'C', b'F', b'C', 1]  "I speak credit flow control", sent once per session
//   WINDOW     [2, id u32 BE, bytes u32 BE]  the receiver of `id` consumed `bytes`: new credit
//   FC_ON      [3, id u32 BE]  initiate side: stream `id` (opened next) uses credit flow control
// The initiate side sends FC_ON (before the Open) only after it saw the peer's HELLO, so a stream
// runs with credit exactly when BOTH sides know it; everything else keeps the old behaviour.

/// The reserved control stream id.
const CONTROL_ID: u32 = 0;
/// `CT_CHANNEL_FORWARD_FLOW=off` disables credit flow control on this member (it then behaves like
/// an agent before DEC-0061: no HELLO, FC_ON ignored). Default: on.
pub const FORWARD_FLOW_ENV: &str = "CT_CHANNEL_FORWARD_FLOW";

pub(crate) fn flow_control_from_env() -> bool {
    !matches!(
        std::env::var(FORWARD_FLOW_ENV).ok().as_deref(),
        Some("off" | "0" | "false")
    )
}
/// Initial credit per stream and direction: covers bandwidth x delay of a desktop stream
/// (~10 Mbit/s x 100 ms ~ 125 KB) with headroom; 72 streams x 256 KiB = 18 MiB worst case.
pub(crate) const FC_WINDOW: usize = 256 * 1024;
const CTL_HELLO: u8 = 1;
const CTL_WINDOW: u8 = 2;
const CTL_FC_ON: u8 = 3;

fn hello_frame() -> Frame {
    Frame::Data {
        id: CONTROL_ID,
        payload: vec![CTL_HELLO, b'C', b'F', b'C', 1],
    }
}

fn window_frame(id: u32, bytes: u32) -> Frame {
    let mut p = vec![CTL_WINDOW];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&bytes.to_be_bytes());
    Frame::Data {
        id: CONTROL_ID,
        payload: p,
    }
}

fn fc_on_frame(id: u32) -> Frame {
    let mut p = vec![CTL_FC_ON];
    p.extend_from_slice(&id.to_be_bytes());
    Frame::Data {
        id: CONTROL_ID,
        payload: p,
    }
}

/// A decoded control message; anything unknown or malformed is ignored (forward-compatible).
enum Control {
    Hello,
    Window { id: u32, bytes: u32 },
    FcOn { id: u32 },
}

fn parse_control(p: &[u8]) -> Option<Control> {
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    match p {
        [CTL_HELLO, b'C', b'F', b'C', ..] => Some(Control::Hello),
        [CTL_WINDOW, rest @ ..] if rest.len() >= 8 => Some(Control::Window {
            id: be(&rest[..4]),
            bytes: be(&rest[4..8]),
        }),
        [CTL_FC_ON, rest @ ..] if rest.len() >= 4 => Some(Control::FcOn { id: be(&rest[..4]) }),
        _ => None,
    }
}

/// Engine side of one stream's inbound queue.
enum InTx {
    /// No flow control (peer without it): bounded, the engine waits on it as before.
    Bounded(mpsc::Sender<StreamIn>),
    /// Flow control: never blocks; the peer may not send more than its credit, so more than
    /// [`FC_WINDOW`] bytes buffered is a protocol violation of this stream.
    Credited {
        tx: mpsc::UnboundedSender<StreamIn>,
        pending: Arc<AtomicUsize>,
    },
}

/// Pump side of one stream's inbound queue.
enum InRx {
    Bounded(mpsc::Receiver<StreamIn>),
    Credited {
        rx: mpsc::UnboundedReceiver<StreamIn>,
        pending: Arc<AtomicUsize>,
    },
}

impl InRx {
    /// Cancel-safe like the receivers it wraps (the count is only touched after a receive).
    async fn recv(&mut self) -> Option<StreamIn> {
        match self {
            InRx::Bounded(rx) => rx.recv().await,
            InRx::Credited { rx, pending } => {
                let msg = rx.recv().await;
                if let Some(StreamIn::Data(p)) = &msg {
                    pending.fetch_sub(p.len(), Ordering::Relaxed);
                }
                msg
            }
        }
    }
}

fn inbound_queue(credited: bool) -> (InTx, InRx) {
    if credited {
        let (tx, rx) = mpsc::unbounded_channel();
        let pending = Arc::new(AtomicUsize::new(0));
        (
            InTx::Credited {
                tx,
                pending: pending.clone(),
            },
            InRx::Credited { rx, pending },
        )
    } else {
        let (tx, rx) = mpsc::channel(CHANNEL_CAP);
        (InTx::Bounded(tx), InRx::Bounded(rx))
    }
}

/// One stream as the engine sees it.
struct StreamEntry {
    tx: InTx,
    /// Send credit of this stream's pump (flow control only); the engine adds WINDOW credit.
    credit: Option<Arc<Semaphore>>,
}

impl StreamEntry {
    /// Hand peer data to the pump. Returns `false` when the stream must be reset because the
    /// peer exceeded its credit. Waits only for a stream WITHOUT flow control (old peer).
    async fn deliver(&self, payload: Vec<u8>) -> bool {
        match &self.tx {
            InTx::Bounded(tx) => {
                let _ = tx.send(StreamIn::Data(payload)).await;
                true
            }
            InTx::Credited { tx, pending } => {
                if pending.load(Ordering::Relaxed) + payload.len() > FC_WINDOW {
                    return false;
                }
                pending.fetch_add(payload.len(), Ordering::Relaxed);
                let _ = tx.send(StreamIn::Data(payload));
                true
            }
        }
    }

    /// Tell the pump the peer closed (half-close) or reset the stream. The entry itself stays
    /// until the pump ends: after a half-close this side may still be sending, and its credit
    /// (WINDOW from the peer) must keep arriving.
    async fn notify(&self, msg: StreamIn) {
        match &self.tx {
            InTx::Bounded(tx) => {
                let _ = tx.send(msg).await;
            }
            InTx::Credited { tx, .. } => {
                let _ = tx.send(msg);
            }
        }
    }

    /// The stream is gone for good (pump ended or reset): stop any send that waits for credit.
    fn finish(&self) {
        if let Some(c) = &self.credit {
            c.close();
        }
    }
}

/// The send side of a credited stream: the pump takes credit before every `Data` and reports
/// what it wrote to the local socket back to the peer, batched at half a window.
struct PumpFlow {
    credit: Arc<Semaphore>,
}

/// Byte-transparent pump for ONE forwarded TCP connection (either side). Ends when both directions
/// are done, on a reset, or after a full `idle` period without a byte in either direction.
/// With `flow` set it never sends more than the peer's credit and returns credit for what it wrote;
/// it waits for credit HERE, in its own task, never in the engine's read loop.
async fn pump_forward_stream(
    id: u32,
    tcp: TcpStream,
    outbound: mpsc::Sender<Frame>,
    mut inbound: InRx,
    idle: Duration,
    flow: Option<PumpFlow>,
) -> (u64, u64) {
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let mut buf = vec![0u8; DATA_CHUNK_LEN];
    let mut bytes_out: u64 = 0;
    let mut bytes_in: u64 = 0;
    let mut tcp_eof = false;
    let mut peer_eof = false;
    let mut unreported: usize = 0;
    loop {
        if tcp_eof && peer_eof {
            break;
        }
        tokio::select! {
            r = tcp_r.read(&mut buf), if !tcp_eof => {
                match r {
                    // A clean EOF is a half-close: the peer may still owe this side a reply.
                    Ok(0) => {
                        tcp_eof = true;
                        let _ = outbound.send(Frame::Close { id, reason: None }).await;
                    }
                    // The local socket itself failed: reset the stream (DEC-0061, 2026-10-05).
                    Err(_) => {
                        let _ = outbound.send(abort_frame(id)).await;
                        break;
                    }
                    Ok(n) => {
                        if let Some(f) = &flow {
                            match f.credit.acquire_many(n as u32).await {
                                Ok(permit) => permit.forget(),
                                Err(_) => break, // the engine closed the stream
                            }
                        }
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
                            // Nobody reads the local side any more: reset, do not drain.
                            let _ = outbound.send(abort_frame(id)).await;
                            break;
                        }
                        if flow.is_some() {
                            unreported += payload.len();
                            if unreported >= FC_WINDOW / 2 {
                                let _ = outbound.send(window_frame(id, unreported as u32)).await;
                                unreported = 0;
                            }
                        }
                    }
                    Some(StreamIn::Closed) | None => {
                        peer_eof = true;
                        let _ = tcp_w.shutdown().await;
                    }
                    // Dropping both socket halves on return closes the connection fully.
                    Some(StreamIn::Aborted) => break,
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

/// The engine's only writer: owns the session duplex's write half and serializes the pumps'
/// bounded queue and the engine's own unbounded control queue onto it. The engine itself never
/// writes, so a peer that does not read can no longer stop the engine's read loop (DEC-0061 (c)).
fn spawn_frame_writer<W>(
    mut mux_write: W,
    mut out_rx: mpsc::Receiver<Frame>,
    mut ctrl_rx: mpsc::UnboundedReceiver<Frame>,
) -> tokio::task::JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                f = ctrl_rx.recv() => f,
                f = out_rx.recv() => f,
            };
            match frame {
                Some(f) => {
                    if f.write(&mut mux_write).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    })
}

/// Handle one control message in either engine. Returns `true` for a HELLO.
fn apply_control(
    payload: &[u8],
    streams: &HashMap<u32, StreamEntry>,
    pending_fc: &mut std::collections::HashSet<u32>,
) -> bool {
    match parse_control(payload) {
        Some(Control::Hello) => true,
        Some(Control::Window { id, bytes }) => {
            if let Some(Some(c)) = streams.get(&id).map(|s| s.credit.as_ref()) {
                c.add_permits(bytes as usize);
            }
            false
        }
        Some(Control::FcOn { id }) => {
            pending_fc.insert(id);
            false
        }
        None => false,
    }
}

/// The initiate side's engine (#255): every accepted local connection becomes one stream.
/// Reads frames cancel-safe (frame_fut), never waits on a credited stream, never writes itself.
async fn run_forward_initiate_engine(
    engine_side: tokio::io::DuplexStream,
    listener: Arc<TcpListener>,
    target: String,
    max_streams: usize,
    idle: Duration,
    fc_enabled: bool,
) {
    let (mux_read, mux_write) = tokio::io::split(engine_side);
    let (out_tx, out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Frame>();
    let writer = spawn_frame_writer(mux_write, out_rx, ctrl_rx);
    tokio::pin!(writer);
    if fc_enabled {
        let _ = ctrl_tx.send(hello_frame());
    }
    let mut peer_speaks_fc = false;
    let mut pending_fc = std::collections::HashSet::new();
    let mut entries: HashMap<u32, StreamEntry> = HashMap::new();
    let mut streams: JoinSet<u32> = JoinSet::new();
    let mut next_id: u32 = 1;
    let frame_fut = read_one_frame(mux_read);
    tokio::pin!(frame_fut);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, _peer_addr)) => {
                        if entries.len() >= max_streams {
                            drop(tcp);
                            continue;
                        }
                        let id = next_id;
                        next_id = next_id.wrapping_add(1).max(1); // 0 is the control stream
                        let credited = peer_speaks_fc;
                        let (tx, rx) = inbound_queue(credited);
                        let credit = credited.then(|| Arc::new(Semaphore::new(FC_WINDOW)));
                        entries.insert(id, StreamEntry { tx, credit: credit.clone() });
                        let out_tx2 = out_tx.clone();
                        let target2 = target.clone();
                        streams.spawn(async move {
                            // FC_ON before the Open: the accept side decides per stream at the Open.
                            if credited && out_tx2.send(fc_on_frame(id)).await.is_err() {
                                return id;
                            }
                            if out_tx2.send(Frame::Open { id, target: target2 }).await.is_ok() {
                                let flow = credit.map(|credit| PumpFlow { credit });
                                pump_forward_stream(id, tcp, out_tx2, rx, idle, flow).await;
                            }
                            id
                        });
                    }
                    Err(e) => eprintln!("ct-agent channel: forward listener accept error: {e}"),
                }
            }
            (reader, frame) = &mut frame_fut => {
                // Re-arm only after a COMPLETE frame (cancel safety, see read_one_frame).
                if frame.is_ok() {
                    frame_fut.set(read_one_frame(reader));
                }
                match frame {
                    Ok(Frame::Data { id: CONTROL_ID, payload }) => {
                        if fc_enabled && apply_control(&payload, &entries, &mut pending_fc) {
                            peer_speaks_fc = true;
                        }
                    }
                    Ok(Frame::Data { id, payload }) => {
                        let ok = match entries.get(&id) {
                            Some(e) => e.deliver(payload).await,
                            None => true,
                        };
                        if !ok {
                            eprintln!("ct-agent channel: forward stream {id} reset -- the peer exceeded its credit");
                            if let Some(e) = entries.remove(&id) {
                                e.finish();
                                e.notify(StreamIn::Aborted).await;
                            }
                            let _ = ctrl_tx.send(abort_frame(id));
                        }
                    }
                    Ok(Frame::Close { id, reason }) => {
                        let msg = stream_in_for_close(reason.as_deref());
                        if matches!(msg, StreamIn::Aborted) {
                            if let Some(e) = entries.remove(&id) {
                                e.finish();
                                e.notify(msg).await;
                            }
                        } else if let Some(e) = entries.get(&id) {
                            // Half-close: keep the entry (credit for this side's sending).
                            e.notify(msg).await;
                        }
                    }
                    // The initiate side never receives Open -- ignored, not a torn-down session.
                    Ok(Frame::Open { .. }) => {}
                    // Byte sync with the peer's framing is lost, or the transport ended.
                    Err(e) => {
                        streams.abort_all();
                        eprintln!(
                            "ct-agent channel: forward frame read failed ({:?}): {e} -- closed every forwarded stream",
                            e.kind()
                        );
                        break;
                    }
                }
            }
            Some(done) = streams.join_next(), if !streams.is_empty() => {
                if let Ok(id) = done {
                    if let Some(e) = entries.remove(&id) {
                        e.finish();
                    }
                }
            }
            _ = &mut writer => {
                streams.abort_all();
                eprintln!("ct-agent channel: forward session write side ended -- closed every forwarded stream");
                break;
            }
        }
    }
}

/// The accept side's engine (#255 slice 2): for every `Frame::Open` the peer sends, re-check the
/// policy gate and, if allowed, dial `target` and pump it. A stream uses credit flow control when
/// the initiate side announced it with FC_ON before the Open.
async fn run_forward_accept_engine(
    engine_side: tokio::io::DuplexStream,
    allow_raw: Option<String>,
    non_loopback_raw: Option<String>,
    max_streams: usize,
    idle: Duration,
    fc_enabled: bool,
) {
    let (mux_read, mux_write) = tokio::io::split(engine_side);
    let (out_tx, out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Frame>();
    let writer = spawn_frame_writer(mux_write, out_rx, ctrl_rx);
    tokio::pin!(writer);
    if fc_enabled {
        let _ = ctrl_tx.send(hello_frame());
    }
    let mut pending_fc = std::collections::HashSet::new();
    let mut entries: HashMap<u32, StreamEntry> = HashMap::new();
    let mut streams: JoinSet<(u32, u64, u64)> = JoinSet::new();
    let frame_fut = read_one_frame(mux_read);
    tokio::pin!(frame_fut);

    loop {
        tokio::select! {
            (reader, frame) = &mut frame_fut => {
                if frame.is_ok() {
                    frame_fut.set(read_one_frame(reader));
                }
                match frame {
                    Ok(Frame::Open { id, target }) => {
                        let credited = pending_fc.remove(&id);
                        if entries.len() >= max_streams {
                            let _ = ctrl_tx.send(Frame::Close { id, reason: Some(format!("{FORWARD_MAX_STREAMS_ENV} reached")) });
                            continue;
                        }
                        match accept_forward_request_with(&target, allow_raw.as_deref(), non_loopback_raw.as_deref()) {
                            Err(reason) => {
                                // accept_forward_request_with already emitted forward_refused.
                                let _ = ctrl_tx.send(Frame::Close { id, reason: Some(reason) });
                            }
                            Ok(()) => {
                                let (tx, rx) = inbound_queue(credited);
                                let credit = credited.then(|| Arc::new(Semaphore::new(FC_WINDOW)));
                                entries.insert(id, StreamEntry { tx, credit: credit.clone() });
                                let flow = credit.map(|credit| PumpFlow { credit });
                                streams.spawn(dial_and_pump_forward_target(id, target, out_tx.clone(), rx, idle, flow));
                            }
                        }
                    }
                    Ok(Frame::Data { id: CONTROL_ID, payload }) => {
                        if fc_enabled {
                            apply_control(&payload, &entries, &mut pending_fc);
                        }
                    }
                    Ok(Frame::Data { id, payload }) => {
                        let ok = match entries.get(&id) {
                            Some(e) => e.deliver(payload).await,
                            None => true,
                        };
                        if !ok {
                            eprintln!("ct-agent channel: forward stream {id} reset -- the peer exceeded its credit");
                            if let Some(e) = entries.remove(&id) {
                                e.finish();
                                e.notify(StreamIn::Aborted).await;
                            }
                            let _ = ctrl_tx.send(abort_frame(id));
                        }
                    }
                    Ok(Frame::Close { id, reason }) => {
                        let msg = stream_in_for_close(reason.as_deref());
                        if matches!(msg, StreamIn::Aborted) {
                            if let Some(e) = entries.remove(&id) {
                                e.finish();
                                e.notify(msg).await;
                            }
                        } else if let Some(e) = entries.get(&id) {
                            // Half-close: keep the entry (credit for this side's sending).
                            e.notify(msg).await;
                        }
                    }
                    // AUF-20260930-005: the session ended -- every target socket this side dialed
                    // is closed with the JoinSet ("auf beiden Seiten binnen 5 s").
                    Err(e) => {
                        streams.abort_all();
                        eprintln!(
                            "ct-agent channel: forward frame read failed ({:?}): {e} -- closed every forwarded stream to its target",
                            e.kind()
                        );
                        break;
                    }
                }
            }
            Some(done) = streams.join_next(), if !streams.is_empty() => {
                if let Ok((id, ..)) = done {
                    if let Some(e) = entries.remove(&id) {
                        e.finish();
                    }
                }
            }
            _ = &mut writer => {
                streams.abort_all();
                eprintln!("ct-agent channel: forward session write side ended -- closed every forwarded stream to its target");
                break;
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
    inbound: InRx,
    idle: Duration,
    flow: Option<PumpFlow>,
) -> (u32, u64, u64) {
    match TcpStream::connect(&target).await {
        Ok(tcp) => {
            events::emit(
                events::FORWARD_OPEN,
                serde_json::json!({ "target": target }),
            );
            let (bytes_out, bytes_in) =
                pump_forward_stream(id, tcp, outbound, inbound, idle, flow).await;
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

    // T4 (DEC-0061): a peer that sends more than its credit resets only that stream -- the
    // engine sees `deliver` refuse instead of waiting (no session end, no stall).
    #[tokio::test]
    async fn credited_stream_refuses_more_than_its_window() {
        let (tx, mut rx) = inbound_queue(true);
        let entry = StreamEntry {
            tx,
            credit: Some(Arc::new(Semaphore::new(FC_WINDOW))),
        };
        assert!(
            entry.deliver(vec![0u8; FC_WINDOW]).await,
            "a full window is allowed"
        );
        assert!(
            !entry.deliver(vec![0u8; 1]).await,
            "one byte over the window is a violation"
        );
        assert!(matches!(rx.recv().await, Some(StreamIn::Data(d)) if d.len() == FC_WINDOW));
        assert!(
            entry.deliver(vec![0u8; 1]).await,
            "credit returns once the pump took the data"
        );
        entry.finish();
        assert!(
            entry.credit.as_ref().unwrap().acquire().await.is_err(),
            "finish stops waiting senders"
        );
    }

    #[test]
    fn control_messages_round_trip_and_unknown_is_ignored() {
        let Frame::Data { id, payload } = window_frame(7, 4096) else {
            panic!()
        };
        assert_eq!(id, CONTROL_ID);
        assert!(matches!(
            parse_control(&payload),
            Some(Control::Window { id: 7, bytes: 4096 })
        ));
        let Frame::Data { payload, .. } = fc_on_frame(9) else {
            panic!()
        };
        assert!(matches!(
            parse_control(&payload),
            Some(Control::FcOn { id: 9 })
        ));
        let Frame::Data { payload, .. } = hello_frame() else {
            panic!()
        };
        assert!(matches!(parse_control(&payload), Some(Control::Hello)));
        assert!(parse_control(&[99, 1, 2]).is_none());
        assert!(
            parse_control(&[CTL_WINDOW, 1]).is_none(),
            "short WINDOW is ignored, not a panic"
        );
    }

    fn in_tx_bounded(tx: &InTx) -> &mpsc::Sender<StreamIn> {
        match tx {
            InTx::Bounded(t) => t,
            InTx::Credited { .. } => panic!("test expects a bounded inbound queue"),
        }
    }

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

    // trace: AUF-20261004-022 (ct-agent#267)
    #[test]
    fn reconnect_backoff_doubles_from_one_second_to_thirty_and_resets_after_a_healthy_session() {
        let short = Duration::from_millis(10);
        let mut prev = None;
        let mut seen = Vec::new();
        for _ in 0..7 {
            let d = next_forward_reconnect_delay(prev, short);
            seen.push(d.as_secs());
            prev = Some(d);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(
            next_forward_reconnect_delay(Some(FORWARD_RECONNECT_MAX), FORWARD_RECONNECT_MAX),
            FORWARD_RECONNECT_MIN,
            "a session that ran for the cap counts as healthy"
        );
    }

    // trace: AUF-20261004-022 (ct-agent#267)
    #[test]
    fn only_a_recorded_grant_end_or_an_expired_own_grant_stops_the_reconnect() {
        assert_eq!(
            forward_grant_end(None, 1_000, 999),
            None,
            "a valid grant reconnects"
        );
        assert!(
            forward_grant_end(None, 1_000, 1_000).is_some(),
            "now == expires_at is expired"
        );
        assert_eq!(
            forward_grant_end(Some("revoked".into()), 1_000, 0).as_deref(),
            Some("revoked"),
            "a recorded end wins even while the own grant is still valid"
        );
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
        let (in_tx, in_rx) = inbound_queue(false);
        let pump = tokio::spawn(pump_forward_stream(
            1,
            client,
            out_tx,
            in_rx,
            Duration::from_secs(30),
            None,
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
        in_tx_bounded(&in_tx)
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
        in_tx_bounded(&in_tx).send(StreamIn::Closed).await.unwrap();
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
        let (_in_tx, in_rx) = inbound_queue(false);
        let idle = Duration::from_millis(50);
        let pump = tokio::spawn(pump_forward_stream(1, client, out_tx, in_rx, idle, None));

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
        let (in_tx, in_rx) = inbound_queue(false);
        let task = tokio::spawn(dial_and_pump_forward_target(
            1,
            addr.to_string(),
            out_tx,
            in_rx,
            Duration::from_secs(30),
            None,
        ));

        in_tx_bounded(&in_tx)
            .send(StreamIn::Data(b"hello".to_vec()))
            .await
            .unwrap();
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
        in_tx_bounded(&in_tx).send(StreamIn::Closed).await.unwrap();

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
        let (_in_tx, in_rx) = inbound_queue(false);
        let (id, bytes_out, bytes_in) = dial_and_pump_forward_target(
            9,
            dead_addr.to_string(),
            out_tx,
            in_rx,
            Duration::from_secs(30),
            None,
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
