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
// trace: AUF-20261006-070 (DEC-0061)

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

/// Bound on waiting to hand a stream's control/close frame to the shared outbound queue
/// (AUF-20261006-070, Befund a of the #274 review): a peer that stopped reading must not be
/// able to wedge a pump -- including its idle branch -- by leaving the queue full forever.
const CLOSE_SEND_GRACE: Duration = Duration::from_secs(2);

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
    let (up_tx, session_up) = tokio::sync::oneshot::channel();
    let pump = TaskGuard::spawn(async move {
        run_forward_initiate_engine(
            engine_side,
            listener,
            target,
            max_streams,
            idle,
            fc_enabled,
            session_up,
        )
        .await;
    });
    LocalDuplex::with_pump_and_first_read(session_side, pump, up_tx)
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

/// Hand a stream's control/close frame to the shared outbound queue without ever waiting on it
/// forever (AUF-20261006-070, Befund a of the #274 review): try immediately, then wait up to
/// [`CLOSE_SEND_GRACE`], then give up. `false` means the frame was dropped (queue still full
/// after the grace) or the queue is already closed -- either way the caller must end the
/// stream's pump on the spot instead of staying half-open.
///
/// AUF-20261007-005 (merge review of #276, finding 1): the grace is not an absolute deadline. A
/// peer that reads slowly still reads -- as long as the session's writer wrote at least one frame
/// during a grace, the wait goes on. Only a writer that stood still for a whole grace drops the
/// frame. Outside an engine's stream task (no [`WRITTEN`]) the grace counts once, as before.
async fn send_or_drop(out: &mpsc::Sender<Frame>, frame: Frame) -> bool {
    let frame = match out.try_send(frame) {
        Ok(()) => return true,
        Err(mpsc::error::TrySendError::Closed(_)) => return false,
        Err(mpsc::error::TrySendError::Full(frame)) => frame,
    };
    let written = WRITTEN.try_with(|w| w.clone()).ok();
    loop {
        let before = written.as_ref().map(|w| w.load(Ordering::Relaxed));
        match tokio::time::timeout(CLOSE_SEND_GRACE, out.reserve()).await {
            Ok(Ok(permit)) => {
                permit.send(frame);
                return true;
            }
            Ok(Err(_)) => return false,
            Err(_) => match (&written, before) {
                (Some(w), Some(before)) if w.load(Ordering::Relaxed) != before => {}
                _ => return false,
            },
        }
    }
}

tokio::task_local! {
    /// Frames the session's writer has written so far; set for every stream task of an engine.
    static WRITTEN: Arc<std::sync::atomic::AtomicU64>;
}

/// The Close that resets a stream (see [`super::forward_wire::CLOSE_REASON_ABORT`]).
fn abort_frame(id: u32) -> Frame {
    Frame::Close {
        id,
        reason: Some(super::forward_wire::CLOSE_REASON_ABORT.to_string()),
    }
}

/// Close WITHOUT a reason is the half-close a pump sends on a clean local EOF; Close WITH any
/// reason (abort, refused, dial failed, max_streams, idle timeout) ends the stream fully, so a
/// refused or idle client is closed at once instead of half-open until the idle limit
/// (second adversarial review of #274). An agent before DEC-0061 treats all of them as half-close.
fn stream_in_for_close(reason: Option<&str>) -> StreamIn {
    if reason.is_some() {
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
//   SWINDOW    [4, bytes u32 BE]  the receiver's engine took `bytes` of stream data off the session
//
// Session window (HELLO version 2, AUF-20261007-005): the HELLO carries a fifth field, the window
// in bytes its sender grants the peer for ALL streams together (0: none):
//   HELLO v2   [1, b'C', b'F', b'C', 2, window u32 BE]
// A sender with a window from the peer never has more stream data unacknowledged than that window.
// The receiver acknowledges every `Data` byte for a stream id != 0 when its engine READS the frame
// -- also bytes it then drops (reset stream, unknown id) -- so one slow target cannot hold the
// session's window; that is what the credit per stream is for. It acknowledges at a quarter of
// its window and at the latest SESSION_ACK_DELAY after the first unacknowledged byte, so no byte
// stays unacknowledged for good and a sender waiting for the window always gets it back. SWINDOW
// is sent only to a peer whose HELLO said version >= 2; a version-1 peer sees none and the
// session behaves as before.
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
/// (~10 Mbit/s x 100 ms ~ 125 KB) with headroom; 72 streams x 256 KiB = 18 MiB with an honest
/// peer. A peer ignoring its credit can make a stream hold up to 2 x the window (a full queue plus
/// one frame of at most the window inside the pump) before the reset (third review of #274).
pub(crate) const FC_WINDOW: usize = 256 * 1024;
const CTL_HELLO: u8 = 1;
const CTL_WINDOW: u8 = 2;
const CTL_FC_ON: u8 = 3;
const CTL_SWINDOW: u8 = 4;
/// The HELLO version that carries a session window.
const HELLO_V2: u8 = 2;
/// The session window this member grants a peer: how much stream data may be on its way to this
/// engine without an acknowledgement. It bounds what waits ahead of a new stream's Open and first
/// bytes on a slow path (AUF-20261006-078/-081: 3.8 MiB ahead of an Open at 62 500 B/s, 64 s).
pub(crate) const SESSION_WINDOW: usize = 256 * 1024;
/// Smallest window a peer may grant (other than 0): four chunks.
const SESSION_WINDOW_MIN: usize = 4 * DATA_CHUNK_LEN;
/// Largest window this member uses, whatever the peer grants.
const SESSION_WINDOW_MAX: usize = 16 * 1024 * 1024;
/// The receiver acknowledges at the latest this long after the first unacknowledged byte.
const SESSION_ACK_DELAY: Duration = Duration::from_millis(100);
/// Dead-peer detection of a session with a session window (AUF-20261007-005): stream data is
/// unacknowledged and NO frame came from the peer for this long. Any frame counts, not only an
/// acknowledgement: on a slow path the acknowledgement waits behind up to a window of the peer's
/// own data, and a peer that still sends is not dead. A peer that reads acknowledges within
/// [`SESSION_ACK_DELAY`] of every Data frame it takes, so only a peer (or a path) that passes
/// less than one frame in this time is taken for dead. What ends is the SESSION, with every
/// stream on it; the reconnect loop dials a new one.
const SESSION_DEAD_AFTER: Duration = Duration::from_secs(if cfg!(test) { 3 } else { 30 });

/// One step of the dead-peer check (every quarter of [`SESSION_DEAD_AFTER`]): `true` when stream
/// data has been unacknowledged since `since` for the whole time. `since` is cleared by every
/// frame from the peer (see the engines) and whenever nothing is unacknowledged.
fn session_is_dead(
    send: Option<&Arc<SessionSend>>,
    since: &mut Option<tokio::time::Instant>,
) -> bool {
    match send {
        Some(s) if s.unacknowledged() > 0 => {
            let from = *since.get_or_insert_with(tokio::time::Instant::now);
            from.elapsed() >= SESSION_DEAD_AFTER
        }
        _ => {
            *since = None;
            false
        }
    }
}

/// `window`: what this member grants the peer for the session (0: none, the peer sends as before).
fn hello_frame(window: u32) -> Frame {
    let mut p = vec![CTL_HELLO, b'C', b'F', b'C', HELLO_V2];
    p.extend_from_slice(&window.to_be_bytes());
    Frame::Data {
        id: CONTROL_ID,
        payload: p,
    }
}

fn swindow_frame(bytes: u32) -> Frame {
    let mut p = vec![CTL_SWINDOW];
    p.extend_from_slice(&bytes.to_be_bytes());
    Frame::Data {
        id: CONTROL_ID,
        payload: p,
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
    /// `window`: `None` from a version-1 peer (no session window, send it no SWINDOW).
    Hello {
        window: Option<u32>,
    },
    Window {
        id: u32,
        bytes: u32,
    },
    FcOn {
        id: u32,
    },
    SWindow {
        bytes: u32,
    },
}

fn parse_control(p: &[u8]) -> Option<Control> {
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    match p {
        [CTL_HELLO, b'C', b'F', b'C', v, rest @ ..] if *v >= HELLO_V2 && rest.len() >= 4 => {
            Some(Control::Hello {
                window: Some(be(&rest[..4])),
            })
        }
        [CTL_HELLO, b'C', b'F', b'C', ..] => Some(Control::Hello { window: None }),
        [CTL_WINDOW, rest @ ..] if rest.len() >= 8 => Some(Control::Window {
            id: be(&rest[..4]),
            bytes: be(&rest[4..8]),
        }),
        [CTL_FC_ON, rest @ ..] if rest.len() >= 4 => Some(Control::FcOn { id: be(&rest[..4]) }),
        [CTL_SWINDOW, rest @ ..] if rest.len() >= 4 => Some(Control::SWindow {
            bytes: be(&rest[..4]),
        }),
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

/// The send side of a stream under flow control. With `credit` (the peer sent FC_ON for it) the
/// pump takes credit before every `Data` and reports what it wrote to the local socket back to
/// the peer, batched at half a window. The session window does not depend on that: the peer
/// acknowledges every Data byte it reads, so every stream of the session counts against it.
struct PumpFlow {
    credit: Option<Arc<Semaphore>>,
    /// The session window of the peer, shared by every stream of the session (HELLO v2).
    session: Option<Arc<SessionSend>>,
}

/// Receive side of the session window: counts the stream data the engine reads and says when to
/// acknowledge it. Off (nothing counted, no SWINDOW) until the peer's HELLO says version 2 -- the
/// HELLO is the first frame either side sends, so both ends count from the same byte.
#[derive(Default)]
struct SessionRecv {
    on: bool,
    unacked: usize,
    flush_at: Option<tokio::time::Instant>,
}

impl SessionRecv {
    /// The engine read `bytes` of stream data; the SWINDOW to send now, if one is due.
    fn received(&mut self, bytes: usize) -> Option<Frame> {
        if !self.on || bytes == 0 {
            return None;
        }
        self.unacked += bytes;
        if self.unacked >= SESSION_WINDOW / 4 {
            return self.flush();
        }
        if self.flush_at.is_none() {
            self.flush_at = Some(tokio::time::Instant::now() + SESSION_ACK_DELAY);
        }
        None
    }

    /// Acknowledge whatever is unacknowledged (the delay passed, or the threshold is reached).
    fn flush(&mut self) -> Option<Frame> {
        self.flush_at = None;
        let bytes = std::mem::take(&mut self.unacked);
        (bytes > 0).then(|| swindow_frame(bytes as u32))
    }
}

/// Send side of the session window. The window the peer granted is split in two: `first` pays the
/// first chunk of every stream, `budget` every later one. A new stream's first bytes therefore do
/// not queue behind the streams already waiting for the window, and still no more than the window
/// is ever unacknowledged. An acknowledgement refills `first` before `budget`.
///
/// What the peer owes is counted, not derived from the permits: a pump that only WAITS (for the
/// window, or for room in the engine's queue) owes nothing yet. Per part, at any time:
/// free permits + permits a waiting pump holds + `owed` = the part's size.
struct SessionSend {
    budget: Semaphore,
    first: Semaphore,
    budget_cap: usize,
    first_cap: usize,
    owed: std::sync::Mutex<SessionOwed>,
}

/// Bytes taken from the window and not acknowledged, per part; `sending` of them belong to a
/// frame that is not in the engine's queue yet (see [`SessionSending`]).
#[derive(Default)]
struct SessionOwed {
    first: usize,
    budget: usize,
    sending: usize,
}

/// One chunk's bytes of the session window, from the moment the pump has them until its frame is
/// in the engine's queue. Dropped before [`SessionSending::queued`] (the stream was reset while it
/// waited for room in the queue), it gives the bytes back instead of shrinking the window.
struct SessionSending<'a> {
    session: &'a SessionSend,
    from_first: bool,
    bytes: usize,
}

impl SessionSending<'_> {
    /// The frame is in the engine's queue: from now on only an acknowledgement frees the bytes.
    fn queued(mut self) {
        let mut owed = self.session.owed();
        owed.sending -= std::mem::take(&mut self.bytes);
    }
}

impl Drop for SessionSending<'_> {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let s = self.session;
        let mut owed = s.owed();
        owed.sending -= self.bytes;
        // An acknowledgement pays `first` before `budget`, whichever part a byte came from: give
        // back to this chunk's part what it still owes, the rest to the other part.
        let (own, other) = if self.from_first {
            let own = self.bytes.min(owed.first);
            let other = (self.bytes - own).min(owed.budget);
            owed.first -= own;
            owed.budget -= other;
            (own, other)
        } else {
            let own = self.bytes.min(owed.budget);
            let other = (self.bytes - own).min(owed.first);
            owed.budget -= own;
            owed.first -= other;
            (own, other)
        };
        let (to_first, to_budget) = if self.from_first {
            (own, other)
        } else {
            (other, own)
        };
        s.first.add_permits(to_first);
        s.budget.add_permits(to_budget);
    }
}

impl SessionSend {
    /// `None`: the peer granted no window (0). `Err`: a window below the minimum (violation).
    fn from_hello(window: u32) -> Result<Option<Arc<Self>>, ()> {
        let window = (window as usize).min(SESSION_WINDOW_MAX);
        if window == 0 {
            return Ok(None);
        }
        if window < SESSION_WINDOW_MIN {
            return Err(());
        }
        let first_cap = (window / 4).min(4 * DATA_CHUNK_LEN);
        let budget_cap = window - first_cap;
        Ok(Some(Arc::new(Self {
            budget: Semaphore::new(budget_cap),
            first: Semaphore::new(first_cap),
            budget_cap,
            first_cap,
            owed: std::sync::Mutex::new(SessionOwed::default()),
        })))
    }

    /// The counters. A panic while they were held cannot leave them half-written (plain sums).
    fn owed(&self) -> std::sync::MutexGuard<'_, SessionOwed> {
        self.owed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait for `bytes` of the window. A stream's first chunk takes the reserve for first chunks
    /// and, while that is used up, the rest of the window like every later chunk. `None`: the
    /// session is over.
    async fn take(&self, first_chunk: bool, bytes: usize) -> Option<SessionSending<'_>> {
        let (permit, from_first) = if first_chunk {
            tokio::select! {
                biased;
                p = self.first.acquire_many(bytes as u32) => (p.ok()?, true),
                p = self.budget.acquire_many(bytes as u32) => (p.ok()?, false),
            }
        } else {
            (self.budget.acquire_many(bytes as u32).await.ok()?, false)
        };
        let mut owed = self.owed();
        permit.forget();
        if from_first {
            owed.first += bytes;
        } else {
            owed.budget += bytes;
        }
        owed.sending += bytes;
        Some(SessionSending {
            session: self,
            from_first,
            bytes,
        })
    }

    /// Bytes in the engine's queue or beyond that the peer has not acknowledged. What a pump still
    /// holds back does not count: the peer cannot have it.
    fn unacknowledged(&self) -> usize {
        let owed = self.owed();
        owed.first + owed.budget - owed.sending
    }

    /// The peer acknowledged `bytes`. `false`: more than is unacknowledged -- a peer cannot write
    /// itself a larger window (protocol violation of the session).
    fn acknowledge(&self, bytes: usize) -> bool {
        let mut owed = self.owed();
        if bytes > owed.first + owed.budget - owed.sending {
            return false;
        }
        let pay = bytes.min(owed.first);
        owed.first -= pay;
        owed.budget -= bytes - pay;
        self.first.add_permits(pay);
        self.budget.add_permits(bytes - pay);
        true
    }
}

/// Byte-transparent pump for ONE forwarded TCP connection (either side). Two halves run
/// concurrently in this task: "local -> peer" (read the socket, take credit, send `Data`) and
/// "peer -> local" (write what the peer sent, return credit). Waiting for credit therefore never
/// stops the half that returns credit (adversarial review of #274: with one combined loop, bulk in
/// both directions deadlocked each stream on credit). Ends when both halves are done, on a reset,
/// or after a full `idle` period without a byte in either direction.
async fn pump_forward_stream(
    id: u32,
    tcp: TcpStream,
    outbound: mpsc::Sender<Frame>,
    mut inbound: InRx,
    idle: Duration,
    flow: Option<PumpFlow>,
) -> (u64, u64) {
    enum Half {
        /// This direction finished cleanly (half-close).
        Done,
        /// Stop the whole stream now (reset sent or received, or the engine is gone).
        Stop,
    }
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    use std::sync::atomic::AtomicU64;
    let bytes_out = AtomicU64::new(0);
    let bytes_in = AtomicU64::new(0);
    // Last activity as milliseconds since `start` (shared by both halves and the idle timer).
    let start = tokio::time::Instant::now();
    let last_ms = AtomicU64::new(0);
    let touch = || last_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    let last = || start + Duration::from_millis(last_ms.load(Ordering::Relaxed));
    let out_up = outbound.clone();
    let credit = flow.as_ref().and_then(|f| f.credit.clone());
    let session = flow.as_ref().and_then(|f| f.session.clone());

    let up = async {
        let mut buf = vec![0u8; DATA_CHUNK_LEN];
        let mut first_chunk = true;
        loop {
            match tcp_r.read(&mut buf).await {
                // A clean EOF is a half-close: the peer may still owe this side a reply. But a
                // dropped Close (the peer stopped reading) must not half-open the stream either
                // -- end it fully (AUF-20261006-070, Befund a).
                Ok(0) => {
                    return if send_or_drop(&out_up, Frame::Close { id, reason: None }).await {
                        Half::Done
                    } else {
                        Half::Stop
                    };
                }
                // The local socket itself failed: reset the stream (DEC-0061, 2026-10-05).
                Err(_) => {
                    let _ = send_or_drop(&out_up, abort_frame(id)).await;
                    return Half::Stop;
                }
                Ok(n) => {
                    if let Some(c) = &credit {
                        match c.acquire_many(n as u32).await {
                            Ok(permit) => permit.forget(),
                            Err(_) => return Half::Stop, // the engine closed the stream
                        }
                    }
                    // Session window: held until the frame is queued, so a stream that is reset
                    // while it waits here gives the bytes back instead of shrinking the window.
                    let held = match &session {
                        Some(s) => match s.take(first_chunk, n).await {
                            Some(sending) => Some(sending),
                            None => return Half::Stop,
                        },
                        None => None,
                    };
                    first_chunk = false;
                    touch();
                    bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    if out_up
                        .send(Frame::Data {
                            id,
                            payload: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return Half::Stop; // the engine loop ended
                    }
                    if let Some(sending) = held {
                        sending.queued();
                    }
                }
            }
        }
    };
    let down = async {
        let mut unreported: usize = 0;
        loop {
            match inbound.recv().await {
                Some(StreamIn::Data(payload)) => {
                    if tcp_w.write_all(&payload).await.is_err() {
                        // Nobody reads the local side any more: reset, do not drain.
                        let _ = send_or_drop(&outbound, abort_frame(id)).await;
                        return Half::Stop;
                    }
                    touch();
                    bytes_in.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    if credit.is_some() {
                        unreported += payload.len();
                        if unreported >= FC_WINDOW / 2 {
                            // Without credit the peer could never make progress again, so a
                            // dropped WINDOW ends the stream too (AUF-20261006-070).
                            if !send_or_drop(&outbound, window_frame(id, unreported as u32)).await {
                                return Half::Stop;
                            }
                            unreported = 0;
                        }
                    }
                }
                Some(StreamIn::Closed) | None => {
                    let _ = tcp_w.shutdown().await;
                    return Half::Done;
                }
                // Dropping both socket halves on return closes the connection fully.
                Some(StreamIn::Aborted) => return Half::Stop,
            }
        }
    };
    tokio::pin!(up);
    tokio::pin!(down);
    let (mut up_done, mut down_done) = (false, false);
    while !(up_done && down_done) {
        let deadline = last()
            .checked_add(idle)
            .unwrap_or_else(|| last() + Duration::from_secs(86_400 * 365));
        tokio::select! {
            r = &mut up, if !up_done => match r {
                Half::Done => up_done = true,
                Half::Stop => break,
            },
            r = &mut down, if !down_done => match r {
                Half::Done => down_done = true,
                Half::Stop => break,
            },
            _ = tokio::time::sleep_until(deadline) => {
                // Idle: no byte in either direction for a full `idle` (also while waiting for
                // credit or for a slow local reader -- the timer is outside both halves).
                if last().checked_add(idle).is_some_and(|d| d <= tokio::time::Instant::now()) {
                    let _ = send_or_drop(
                        &outbound,
                        Frame::Close {
                            id,
                            reason: Some("idle timeout".to_string()),
                        },
                    )
                    .await;
                    break;
                }
            }
        }
    }
    (
        bytes_out.load(Ordering::Relaxed),
        bytes_in.load(Ordering::Relaxed),
    )
}

/// Upper bound for the engine's own control backlog (frames not yet written). A peer that floods
/// Opens or violations while not reading would otherwise grow it without limit: session violation.
const CTRL_BACKLOG_CAP: usize = 4096;

/// The engine's unbounded control queue with a backlog count (decremented by the writer).
#[derive(Clone)]
struct CtrlTx {
    tx: mpsc::UnboundedSender<Frame>,
    backlog: Arc<AtomicUsize>,
}

impl CtrlTx {
    /// Queue a control frame; `false` when the backlog is over its cap (end the session).
    fn send(&self, f: Frame) -> bool {
        if self.backlog.fetch_add(1, Ordering::Relaxed) >= CTRL_BACKLOG_CAP {
            return false;
        }
        self.tx.send(f).is_ok()
    }
}

fn ctrl_channel() -> (CtrlTx, mpsc::UnboundedReceiver<Frame>, Arc<AtomicUsize>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let backlog = Arc::new(AtomicUsize::new(0));
    (
        CtrlTx {
            tx,
            backlog: backlog.clone(),
        },
        rx,
        backlog,
    )
}

/// The engine's only writer: owns the session duplex's write half and serializes the pumps'
/// bounded queue and the engine's own unbounded control queue onto it. The engine itself never
/// writes, so a peer that does not read can no longer stop the engine's read loop (DEC-0061 (c)).
fn spawn_frame_writer<W>(
    mut mux_write: W,
    mut out_rx: mpsc::Receiver<Frame>,
    mut ctrl_rx: mpsc::UnboundedReceiver<Frame>,
    ctrl_backlog: Arc<AtomicUsize>,
    written: Arc<std::sync::atomic::AtomicU64>,
) -> tokio::task::JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                f = ctrl_rx.recv() => {
                    ctrl_backlog.fetch_sub(1, Ordering::Relaxed);
                    f
                }
                f = out_rx.recv() => f,
            };
            match frame {
                Some(f) => {
                    if f.write(&mut mux_write).await.is_err() {
                        break;
                    }
                    written.fetch_add(1, Ordering::Relaxed);
                }
                None => break,
            }
        }
    })
}

/// What a control message asks the engine to do.
enum ControlOutcome {
    None,
    /// The peer speaks flow control; with the session window it grants (`None`: version 1).
    Hello(Option<u32>),
    /// The peer's engine took this many bytes of stream data off the session.
    SWindow(u32),
    /// Protocol violation of one stream (credit beyond the window): reset that stream.
    ResetStream(u32),
    /// Protocol violation of the session (FC_ON flood): end the session.
    EndSession,
}

/// How long the initiate side holds back new connections at session start until the peer's HELLO
/// arrives. With a peer that speaks flow control the HELLO comes after about one round trip
/// (~100 ms via the edge relay), so every stream -- also connections already waiting in the
/// listen backlog after a reconnect (#267) -- runs with credit. With an older peer the first accept
/// of a session waits once for this long, then the session runs in the old mode
/// (second adversarial review of #274: streams accepted before the HELLO ran without credit).
const HELLO_WAIT: Duration = Duration::from_millis(500);

/// The stream id of a finished pump task, removed from `running` -- also for a task that panicked,
/// so its slot under the stream limit is freed either way.
fn finished_stream_id(
    running: &mut HashMap<u32, tokio::task::Id>,
    done: Result<(tokio::task::Id, u32), tokio::task::JoinError>,
) -> Option<u32> {
    let task = match &done {
        Ok((task, _)) => *task,
        Err(e) => e.id(),
    };
    let id = running.iter().find(|(_, t)| **t == task).map(|(id, _)| *id)?;
    running.remove(&id);
    Some(id)
}

/// The accept side's mode line for a session: on with the peer's HELLO (or an FC_ON before the
/// first Open), off when the first stream opens without either (older agent).
fn accept_mode_line(peer_speaks_fc: bool) -> String {
    if peer_speaks_fc {
        format!(
            "ct-agent channel: forward flow control on for this session (credit window {} KiB per stream, accept side)",
            FC_WINDOW / 1024
        )
    } else {
        "ct-agent channel: forward flow control off for this session -- the first stream opened without HELLO (older agent, accept side)".to_string()
    }
}

/// Sleep until `deadline`; pending forever without one (its select! branch is disabled then).
async fn sleep_until_some(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Upper bound for announced-but-not-yet-opened streams (FC_ON before Open).
const MAX_PENDING_FC: usize = 1024;

/// Handle one control message in either engine.
fn apply_control(
    payload: &[u8],
    streams: &HashMap<u32, StreamEntry>,
    pending_fc: &mut std::collections::HashSet<u32>,
) -> ControlOutcome {
    match parse_control(payload) {
        Some(Control::Hello { window }) => ControlOutcome::Hello(window),
        Some(Control::SWindow { bytes }) => ControlOutcome::SWindow(bytes),
        Some(Control::Window { id, bytes }) => {
            if let Some(Some(c)) = streams.get(&id).map(|s| s.credit.as_ref()) {
                // Never more than the window in total: a peer cannot write itself unlimited credit,
                // and the semaphore can never overflow (adversarial review of #274). More than the
                // room is a protocol violation of this stream -> reset it (rule in the spec, s. 5).
                let room = FC_WINDOW.saturating_sub(c.available_permits());
                if bytes as usize > room {
                    return ControlOutcome::ResetStream(id);
                }
                c.add_permits(bytes as usize);
            }
            ControlOutcome::None
        }
        Some(Control::FcOn { id }) => {
            if pending_fc.len() >= MAX_PENDING_FC {
                return ControlOutcome::EndSession;
            }
            pending_fc.insert(id);
            ControlOutcome::None
        }
        None => ControlOutcome::None,
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
    session_up: tokio::sync::oneshot::Receiver<()>,
) {
    let (mux_read, mux_write) = tokio::io::split(engine_side);
    let (out_tx, out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
    let (ctrl_tx, ctrl_rx, ctrl_backlog) = ctrl_channel();
    let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let writer = TaskGuard::from_handle(spawn_frame_writer(
        mux_write,
        out_rx,
        ctrl_rx,
        ctrl_backlog,
        written.clone(),
    ));
    tokio::pin!(writer);
    if fc_enabled {
        let _ = ctrl_tx.send(hello_frame(SESSION_WINDOW as u32));
    }
    let mut session_recv = SessionRecv::default();
    let mut unacked_since: Option<tokio::time::Instant> = None;
    let mut dead_check = tokio::time::interval(SESSION_DEAD_AFTER / 4);
    let mut peer_speaks_fc = false;
    // The peer's session window; set only by a HELLO that arrives before the first stream, so
    // both ends count the same bytes from the first one on.
    let mut session_send: Option<Arc<SessionSend>> = None;
    // Accept new connections only once the mode is known (HELLO seen, or HELLO_WAIT passed).
    let mut accepting = !fc_enabled;
    // HELLO_WAIT counts from the moment the session is up (its first read of our duplex), not from
    // the engine's start: dial and Noise handshake take seconds in production, and a deadline
    // running during them would let the backlog after a reconnect start without credit.
    tokio::pin!(session_up);
    let mut hello_deadline: Option<tokio::time::Instant> = None;
    if !fc_enabled {
        eprintln!("ct-agent channel: forward flow control off on this member ({FORWARD_FLOW_ENV})");
    }
    let mut pending_fc = std::collections::HashSet::new();
    let mut entries: HashMap<u32, StreamEntry> = HashMap::new();
    let mut streams: JoinSet<u32> = JoinSet::new();
    // Ids whose pump task still runs -- also after an abort removed their entry. The stream limit
    // counts these, and an id is never handed out again while its task runs (third review of #274:
    // abort-close let tasks pile up past max_streams, and a reused id lost its new entry).
    let mut running: HashMap<u32, tokio::task::Id> = HashMap::new();
    let mut next_id: u32 = 1;
    let frame_fut = read_one_frame(mux_read);
    tokio::pin!(frame_fut);

    loop {
        tokio::select! {
            _ = &mut session_up, if !accepting && hello_deadline.is_none() => {
                hello_deadline = Some(tokio::time::Instant::now() + HELLO_WAIT);
            }
            _ = sleep_until_some(hello_deadline), if !accepting && hello_deadline.is_some() => {
                accepting = true;
                eprintln!("ct-agent channel: forward flow control off for this session -- the peer sent no HELLO within {} ms (older agent)", HELLO_WAIT.as_millis());
            }
            accepted = listener.accept(), if accepting => {
                match accepted {
                    Ok((tcp, _peer_addr)) => {
                        if running.len() >= max_streams {
                            drop(tcp);
                            continue;
                        }
                        let mut id = next_id;
                        while running.contains_key(&id) {
                            id = id.wrapping_add(1).max(1);
                        }
                        next_id = id.wrapping_add(1).max(1); // 0 is the control stream
                        let credited = peer_speaks_fc;
                        let (tx, rx) = inbound_queue(credited);
                        let credit = credited.then(|| Arc::new(Semaphore::new(FC_WINDOW)));
                        entries.insert(id, StreamEntry { tx, credit: credit.clone() });
                        let out_tx2 = out_tx.clone();
                        let target2 = target.clone();
                        // A credited stream announces itself on the control queue: FC_ON and its
                        // Open are queued together or not at all (never an FC_ON without its Open
                        // on the wire), ahead of the data already queued, and before this stream's
                        // own first Data, which the pump queues only after this point.
                        if credited
                            && !(ctrl_tx.send(fc_on_frame(id))
                                && ctrl_tx.send(Frame::Open { id, target: target2.clone() }))
                        {
                            streams.abort_all();
                            eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (the peer does not read)");
                            break;
                        }
                        let session = session_send.clone();
                        let task = streams.spawn(WRITTEN.scope(written.clone(), async move {
                            // Without flow control the Open takes the pumps' queue and never waits
                            // forever on a peer that stopped reading (AUF-20261006-070).
                            if credited
                                || send_or_drop(&out_tx2, Frame::Open { id, target: target2 }).await
                            {
                                let flow = credit.map(|credit| PumpFlow { credit: Some(credit), session });
                                pump_forward_stream(id, tcp, out_tx2, rx, idle, flow).await;
                            }
                            id
                        }));
                        running.insert(id, task.id());
                    }
                    Err(e) => eprintln!("ct-agent channel: forward listener accept error: {e}"),
                }
            }
            (reader, frame) = &mut frame_fut => {
                // Any frame shows a peer that lives (see SESSION_DEAD_AFTER).
                if frame.is_ok() {
                    unacked_since = None;
                }
                // Re-arm only after a COMPLETE frame (cancel safety, see read_one_frame).
                if frame.is_ok() {
                    frame_fut.set(read_one_frame(reader));
                }
                match frame {
                    Ok(Frame::Data { id: CONTROL_ID, payload }) => {
                        if fc_enabled {
                            match apply_control(&payload, &entries, &mut pending_fc) {
                                ControlOutcome::Hello(window) => {
                                    if !accepting {
                                        match SessionSend::from_hello(window.unwrap_or(0)) {
                                            Ok(s) => session_send = s,
                                            Err(()) => {
                                                streams.abort_all();
                                                eprintln!("ct-agent channel: forward session ended -- protocol violation (session window below its minimum)");
                                                break;
                                            }
                                        }
                                    }
                                    if !peer_speaks_fc {
                                        eprintln!("ct-agent channel: forward flow control on for this session (credit window {} KiB per stream)", FC_WINDOW / 1024);
                                        match &session_send {
                                            Some(s) => eprintln!("ct-agent channel: forward session window {} KiB for this session", (s.budget_cap + s.first_cap) / 1024),
                                            None => eprintln!("ct-agent channel: forward session window off for this session -- the peer granted none"),
                                        }
                                    }
                                    // The peer's HELLO is the first frame it writes, so no Data
                                    // precedes it: both ends count from the same byte, however
                                    // late the HELLO arrives.
                                    session_recv.on = window.is_some();
                                    peer_speaks_fc = true;
                                    accepting = true;
                                }
                                ControlOutcome::SWindow(bytes) => {
                                    // Without a window in force (HELLO came late) there is nothing to refill.
                                    if session_send.as_ref().is_some_and(|s| !s.acknowledge(bytes as usize)) {
                                        streams.abort_all();
                                        eprintln!("ct-agent channel: forward session ended -- protocol violation (acknowledged more than was sent)");
                                        break;
                                    }
                                }
                                ControlOutcome::ResetStream(id) => {
                                    eprintln!("ct-agent channel: forward stream {id} reset -- the peer granted credit beyond the window");
                                    if let Some(e) = entries.remove(&id) {
                                        e.finish();
                                        e.notify(StreamIn::Aborted).await;
                                    }
                                    if !ctrl_tx.send(abort_frame(id)) {
                                        streams.abort_all();
                                        eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                        break;
                                    }
                                }
                                ControlOutcome::EndSession => {
                                    streams.abort_all();
                                    eprintln!("ct-agent channel: forward session ended -- protocol violation (control flood)");
                                    break;
                                }
                                ControlOutcome::None => {}
                            }
                        }
                    }
                    Ok(Frame::Data { id, payload }) => {
                        // Acknowledge on receipt, whatever happens to the bytes next.
                        if let Some(ack) = session_recv.received(payload.len()) {
                            if !ctrl_tx.send(ack) {
                                streams.abort_all();
                                eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                break;
                            }
                        }
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
                            if !ctrl_tx.send(abort_frame(id)) {
                                streams.abort_all();
                                eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                break;
                            }
                        }
                    }
                    Ok(Frame::Close { id, reason }) => {
                        // An FC_ON whose stream is closed before its Open is over (pair floods).
                        pending_fc.remove(&id);
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
            Some(done) = streams.join_next_with_id(), if !streams.is_empty() => {
                if let Some(id) = finished_stream_id(&mut running, done) {
                    if let Some(e) = entries.remove(&id) {
                        e.finish();
                    }
                }
            }
            _ = sleep_until_some(session_recv.flush_at), if session_recv.flush_at.is_some() => {
                if let Some(ack) = session_recv.flush() {
                    if !ctrl_tx.send(ack) {
                        streams.abort_all();
                        eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                        break;
                    }
                }
            }
            _ = dead_check.tick(), if session_send.is_some() => {
                if session_is_dead(session_send.as_ref(), &mut unacked_since) {
                    streams.abort_all();
                    eprintln!("ct-agent channel: forward session ended -- unacknowledged data and no frame from the peer for {} s (dead peer) -- closed every forwarded stream", SESSION_DEAD_AFTER.as_secs());
                    break;
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
    let (ctrl_tx, ctrl_rx, ctrl_backlog) = ctrl_channel();
    let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let writer = TaskGuard::from_handle(spawn_frame_writer(
        mux_write,
        out_rx,
        ctrl_rx,
        ctrl_backlog,
        written.clone(),
    ));
    tokio::pin!(writer);
    if fc_enabled {
        let _ = ctrl_tx.send(hello_frame(SESSION_WINDOW as u32));
    } else {
        eprintln!("ct-agent channel: forward flow control off on this member ({FORWARD_FLOW_ENV})");
    }
    let mut session_recv = SessionRecv::default();
    // The peer's session window; set only by a HELLO that arrives before the first Open, so both
    // ends count the same bytes from the first one on.
    let mut session_send: Option<Arc<SessionSend>> = None;
    let mut opened = false;
    let mut unacked_since: Option<tokio::time::Instant> = None;
    let mut dead_check = tokio::time::interval(SESSION_DEAD_AFTER / 4);
    // The accept side logs the session's mode too (live run of #274: in operation either node must
    // show whether a session runs with credit): "on" when the peer's HELLO arrives, "off" when the
    // first stream opens without it (older agent).
    let mut mode_logged = !fc_enabled;
    let mut pending_fc = std::collections::HashSet::new();
    let mut entries: HashMap<u32, StreamEntry> = HashMap::new();
    let mut streams: JoinSet<(u32, u64, u64)> = JoinSet::new();
    // Ids whose dial/pump task still runs, also after an abort removed the entry (see the
    // initiate engine): the limit counts them, and an Open for one of them is a violation.
    let mut running: HashMap<u32, tokio::task::Id> = HashMap::new();
    let frame_fut = read_one_frame(mux_read);
    tokio::pin!(frame_fut);

    loop {
        tokio::select! {
            (reader, frame) = &mut frame_fut => {
                // Any frame shows a peer that lives (see SESSION_DEAD_AFTER).
                if frame.is_ok() {
                    unacked_since = None;
                }
                if frame.is_ok() {
                    frame_fut.set(read_one_frame(reader));
                }
                match frame {
                    Ok(Frame::Open { id, target }) => {
                        // An Open for an id in use (or for the control id) is a session violation:
                        // it would overwrite the entry and bypass max_streams (adversarial review).
                        if id == CONTROL_ID || entries.contains_key(&id) || running.contains_key(&id) {
                            streams.abort_all();
                            eprintln!("ct-agent channel: forward session ended -- protocol violation (Open for stream {id} already in use) -- closed every forwarded stream to its target");
                            break;
                        }
                        let credited = pending_fc.remove(&id);
                        opened = true;
                        if !mode_logged {
                            mode_logged = true;
                            eprintln!("{}", accept_mode_line(credited));
                        }
                        if running.len() >= max_streams {
                            if !ctrl_tx.send(Frame::Close { id, reason: Some(format!("{FORWARD_MAX_STREAMS_ENV} reached")) }) {
                                streams.abort_all();
                                eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                break;
                            }
                            continue;
                        }
                        match accept_forward_request_with(&target, allow_raw.as_deref(), non_loopback_raw.as_deref()) {
                            Err(reason) => {
                                // accept_forward_request_with already emitted forward_refused.
                                if !ctrl_tx.send(Frame::Close { id, reason: Some(reason) }) {
                                    streams.abort_all();
                                    eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                    break;
                                }
                            }
                            Ok(()) => {
                                let (tx, rx) = inbound_queue(credited);
                                let credit = credited.then(|| Arc::new(Semaphore::new(FC_WINDOW)));
                                entries.insert(id, StreamEntry { tx, credit: credit.clone() });
                                // Also a stream without credit (the initiate side opened it
                                // before our HELLO reached it) sends under the session window:
                                // the peer acknowledges its bytes like any other.
                                let session = session_send.clone();
                                let flow = (credit.is_some() || session.is_some()).then_some(PumpFlow { credit, session });
                                let task = streams.spawn(WRITTEN.scope(written.clone(), dial_and_pump_forward_target(id, target, out_tx.clone(), rx, idle, flow)));
                                running.insert(id, task.id());
                            }
                        }
                    }
                    Ok(Frame::Data { id: CONTROL_ID, payload }) => {
                        if fc_enabled {
                            match apply_control(&payload, &entries, &mut pending_fc) {
                                ControlOutcome::ResetStream(id) => {
                                    eprintln!("ct-agent channel: forward stream {id} reset -- the peer granted credit beyond the window");
                                    if let Some(e) = entries.remove(&id) {
                                        e.finish();
                                        e.notify(StreamIn::Aborted).await;
                                    }
                                    if !ctrl_tx.send(abort_frame(id)) {
                                        streams.abort_all();
                                        eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                        break;
                                    }
                                }
                                ControlOutcome::EndSession => {
                                    streams.abort_all();
                                    eprintln!("ct-agent channel: forward session ended -- protocol violation (control flood) -- closed every forwarded stream to its target");
                                    break;
                                }
                                ControlOutcome::Hello(window) => {
                                    session_recv.on = window.is_some();
                                    if !opened {
                                        match SessionSend::from_hello(window.unwrap_or(0)) {
                                            Ok(s) => session_send = s,
                                            Err(()) => {
                                                streams.abort_all();
                                                eprintln!("ct-agent channel: forward session ended -- protocol violation (session window below its minimum) -- closed every forwarded stream to its target");
                                                break;
                                            }
                                        }
                                    }
                                    if !mode_logged {
                                        mode_logged = true;
                                        eprintln!("{}", accept_mode_line(true));
                                        match &session_send {
                                            Some(s) => eprintln!("ct-agent channel: forward session window {} KiB for this session (accept side)", (s.budget_cap + s.first_cap) / 1024),
                                            None => eprintln!("ct-agent channel: forward session window off for this session -- the peer granted none (accept side)"),
                                        }
                                    }
                                }
                                ControlOutcome::SWindow(bytes) => {
                                    if session_send.as_ref().is_some_and(|s| !s.acknowledge(bytes as usize)) {
                                        streams.abort_all();
                                        eprintln!("ct-agent channel: forward session ended -- protocol violation (acknowledged more than was sent) -- closed every forwarded stream to its target");
                                        break;
                                    }
                                }
                                ControlOutcome::None => {}
                            }
                        }
                    }
                    Ok(Frame::Data { id, payload }) => {
                        // Acknowledge on receipt, whatever happens to the bytes next.
                        if let Some(ack) = session_recv.received(payload.len()) {
                            if !ctrl_tx.send(ack) {
                                streams.abort_all();
                                eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                break;
                            }
                        }
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
                            if !ctrl_tx.send(abort_frame(id)) {
                                streams.abort_all();
                                eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                                break;
                            }
                        }
                    }
                    Ok(Frame::Close { id, reason }) => {
                        // An FC_ON whose stream is closed before its Open is over (pair floods).
                        pending_fc.remove(&id);
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
            Some(done) = streams.join_next_with_id(), if !streams.is_empty() => {
                if let Some(id) = finished_stream_id(&mut running, done.map(|(task, (id, ..))| (task, id))) {
                    if let Some(e) = entries.remove(&id) {
                        e.finish();
                    }
                }
            }
            _ = sleep_until_some(session_recv.flush_at), if session_recv.flush_at.is_some() => {
                if let Some(ack) = session_recv.flush() {
                    if !ctrl_tx.send(ack) {
                        streams.abort_all();
                        eprintln!("ct-agent channel: forward session ended -- control backlog over its cap (protocol violation)");
                        break;
                    }
                }
            }
            _ = dead_check.tick(), if session_send.is_some() => {
                if session_is_dead(session_send.as_ref(), &mut unacked_since) {
                    streams.abort_all();
                    eprintln!("ct-agent channel: forward session ended -- unacknowledged data and no frame from the peer for {} s (dead peer) -- closed every forwarded stream to its target", SESSION_DEAD_AFTER.as_secs());
                    break;
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
            let _ = send_or_drop(
                &outbound,
                Frame::Close {
                    id,
                    reason: Some(format!("dial failed: {e}")),
                },
            )
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

    // Spec s. 5: credit beyond the window is a stream violation; an FC_ON flood and a control
    // backlog over its cap are session violations.
    #[tokio::test]
    async fn credit_beyond_the_window_resets_only_that_stream() {
        let mut streams = HashMap::new();
        let credit = Arc::new(Semaphore::new(FC_WINDOW));
        let (tx, _rx) = inbound_queue(true);
        streams.insert(
            5u32,
            StreamEntry {
                tx,
                credit: Some(credit.clone()),
            },
        );
        let mut pending = std::collections::HashSet::new();
        // The full window is still available: any further credit is beyond it.
        let Frame::Data { payload, .. } = window_frame(5, 1) else {
            panic!()
        };
        assert!(matches!(
            apply_control(&payload, &streams, &mut pending),
            ControlOutcome::ResetStream(5)
        ));
        // After the pump took 64 KiB, exactly that much may come back.
        credit.acquire_many(65536).await.unwrap().forget();
        let Frame::Data { payload, .. } = window_frame(5, 65536) else {
            panic!()
        };
        assert!(matches!(
            apply_control(&payload, &streams, &mut pending),
            ControlOutcome::None
        ));
        assert_eq!(credit.available_permits(), FC_WINDOW);
    }

    #[test]
    fn fc_on_flood_ends_the_session() {
        let streams = HashMap::new();
        let mut pending = std::collections::HashSet::new();
        for id in 1..=MAX_PENDING_FC as u32 {
            let Frame::Data { payload, .. } = fc_on_frame(id) else {
                panic!()
            };
            assert!(matches!(
                apply_control(&payload, &streams, &mut pending),
                ControlOutcome::None
            ));
        }
        let Frame::Data { payload, .. } = fc_on_frame(u32::MAX) else {
            panic!()
        };
        assert!(matches!(
            apply_control(&payload, &streams, &mut pending),
            ControlOutcome::EndSession
        ));
    }

    #[test]
    fn control_backlog_over_its_cap_refuses() {
        let (ctrl, _rx, _backlog) = ctrl_channel();
        for _ in 0..CTRL_BACKLOG_CAP {
            assert!(ctrl.send(hello_frame(0)));
        }
        assert!(
            !ctrl.send(hello_frame(0)),
            "nobody drains: the cap must hold"
        );
    }

    // Second adversarial review of #274: an Open for an id in use (or for the control id) ends the
    // session instead of overwriting the entry and bypassing max_streams.
    #[tokio::test]
    async fn duplicate_open_ends_the_accept_session() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let _ = target.accept().await;
            }
        });
        for dup in [7u32, CONTROL_ID] {
            let (session_side, engine_side) = tokio::io::duplex(1 << 16);
            let engine = tokio::spawn(run_forward_accept_engine(
                engine_side,
                Some(addr.clone()),
                None,
                2,
                Duration::from_secs(30),
                true,
            ));
            let (_r, mut w) = tokio::io::split(session_side);
            Frame::Open {
                id: dup,
                target: addr.clone(),
            }
            .write(&mut w)
            .await
            .unwrap();
            if dup != CONTROL_ID {
                Frame::Open {
                    id: dup,
                    target: addr.clone(),
                }
                .write(&mut w)
                .await
                .unwrap();
            }
            tokio::time::timeout(Duration::from_secs(10), engine)
                .await
                .unwrap_or_else(|_| panic!("engine kept running after Open id {dup}"))
                .unwrap();
        }
    }

    /// A target that accepts and keeps every connection open (the pump stays busy).
    async fn holding_target() -> String {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = target.accept().await {
                held.push(s);
            }
        });
        addr
    }

    // Third adversarial review of #274: after an abort-close the id's task may still run; an Open
    // for that id must not create an entry the old task's end would remove -- it ends the session.
    #[tokio::test]
    async fn open_for_an_id_whose_task_still_runs_ends_the_accept_session() {
        let addr = holding_target().await;
        let (session_side, engine_side) = tokio::io::duplex(1 << 16);
        let engine = tokio::spawn(run_forward_accept_engine(
            engine_side,
            Some(addr.clone()),
            None,
            8,
            Duration::from_secs(30),
            true,
        ));
        let (_r, mut w) = tokio::io::split(session_side);
        for f in [
            Frame::Open { id: 5, target: addr.clone() },
            abort_frame(5),
            Frame::Open { id: 5, target: addr.clone() },
        ] {
            f.write(&mut w).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), engine)
            .await
            .expect("engine kept running after an Open for a still running id")
            .unwrap();
    }

    // Third adversarial review of #274: the stream limit counts running tasks, not entries --
    // Open + abort-close in a loop must not pile up tasks past max_streams.
    #[tokio::test]
    async fn abort_close_does_not_free_a_slot_before_the_task_ends() {
        let addr = holding_target().await;
        let (session_side, engine_side) = tokio::io::duplex(1 << 16);
        let _engine = tokio::spawn(run_forward_accept_engine(
            engine_side,
            Some(addr.clone()),
            None,
            2,
            Duration::from_secs(30),
            true,
        ));
        let (r, mut w) = tokio::io::split(session_side);
        for id in 1..=3u32 {
            Frame::Open { id, target: addr.clone() }.write(&mut w).await.unwrap();
            abort_frame(id).write(&mut w).await.unwrap();
        }
        // The third Open arrives while the first two tasks still run: refused with the limit.
        let mut r = r;
        let refused = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match Frame::read(&mut r).await.unwrap() {
                    Frame::Close { id: 3, reason: Some(reason) } => break reason,
                    _ => continue,
                }
            }
        })
        .await
        .expect("no Close for the third stream");
        assert!(refused.contains(FORWARD_MAX_STREAMS_ENV), "unexpected reason {refused}");
    }

    // Live run of #274: the accept side names the session's mode like the initiate side does.
    #[test]
    fn accept_mode_line_names_on_and_off() {
        assert!(accept_mode_line(true).contains("forward flow control on for this session"));
        assert!(accept_mode_line(true).contains("accept side"));
        assert!(accept_mode_line(false).contains("forward flow control off for this session"));
        assert!(accept_mode_line(false).contains("older agent"));
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
        let Frame::Data { payload, .. } = hello_frame(0) else {
            panic!()
        };
        assert!(matches!(
            parse_control(&payload),
            Some(Control::Hello { window: Some(0) })
        ));
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

        // `>` rather than `== +1`: EVENT_COUNTS is one process-wide static, and the engine tests of
        // this module open streams at the same time (the tolerance tests.rs and forward.rs use).
        assert!(events::EVENT_COUNTS.get(events::FORWARD_OPEN) > open_before);
        assert!(events::EVENT_COUNTS.get(events::FORWARD_CLOSE) > close_before);

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

        // FORWARD_OPEN is counted per process and other tests open streams meanwhile (measured:
        // red once in seven full runs with `==` on one attempt). A failed dial that opened would
        // move the counter on EVERY attempt, a neighbour only on some.
        let mut never_opened = false;
        for _ in 0..8 {
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
            if events::EVENT_COUNTS.get(events::FORWARD_OPEN) == open_before {
                never_opened = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(never_opened, "a failed dial never opens");
    }

    // AUF-20261006-070 (Befund a): a stream's control/close frames must never wait forever on a
    // full shared queue -- a peer that stopped reading used to wedge the pump (also its idle
    // branch), holding the local socket and its max_streams slot open indefinitely.

    #[tokio::test]
    async fn gegenstelle_liest_nicht_idle_gibt_stream_frei() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let local = TcpStream::connect(addr).await.unwrap();
        let mut peer = accept.await.unwrap();

        let (out_tx, _out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        for _ in 0..CHANNEL_CAP {
            out_tx
                .try_send(Frame::Close {
                    id: 0,
                    reason: None,
                })
                .unwrap();
        }
        let (_in_tx, in_rx) = inbound_queue(false);
        let pump = tokio::spawn(pump_forward_stream(
            1,
            local,
            out_tx,
            in_rx,
            Duration::from_millis(100),
            None,
        ));

        match tokio::time::timeout(Duration::from_millis(3100), pump).await {
            Ok(join) => join.unwrap(),
            Err(_) => panic!(
                "idle pump did not end within idle + grace + margin although the gegenstelle never reads (AUF-20261006-070)"
            ),
        };

        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(1000), peer.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            other => panic!("expected the local socket to be closed (EOF), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gegenstelle_liest_nicht_eof_gibt_stream_frei() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let local = TcpStream::connect(addr).await.unwrap();
        let mut peer = accept.await.unwrap();

        let (out_tx, _out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        for _ in 0..CHANNEL_CAP {
            out_tx
                .try_send(Frame::Close {
                    id: 0,
                    reason: None,
                })
                .unwrap();
        }
        let (_in_tx, in_rx) = inbound_queue(false);
        // Idle at 60 s so only the EOF path (not the idle branch) can end this pump.
        let pump = tokio::spawn(pump_forward_stream(
            1,
            local,
            out_tx,
            in_rx,
            Duration::from_secs(60),
            None,
        ));

        peer.shutdown().await.unwrap(); // local's read side now sees a clean EOF

        match tokio::time::timeout(Duration::from_millis(3000), pump).await {
            Ok(join) => join.unwrap(),
            Err(_) => panic!(
                "pump on a clean local EOF did not end within grace + margin although the gegenstelle never reads (AUF-20261006-070)"
            ),
        };

        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(1000), peer.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            other => panic!("expected the local socket to be closed (EOF), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gegenstelle_liest_nicht_schreibfehler_gibt_stream_frei() {
        // No independent witness for the write-error send at F:684 here: a closed socket delivers
        // EOF to the read side at the same time, so this may end via either path
        // (AUF-20261006-070).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let local = TcpStream::connect(addr).await.unwrap();
        let peer = accept.await.unwrap();

        let (out_tx, _out_rx) = mpsc::channel::<Frame>(CHANNEL_CAP);
        for _ in 0..CHANNEL_CAP {
            out_tx
                .try_send(Frame::Close {
                    id: 0,
                    reason: None,
                })
                .unwrap();
        }
        let (in_tx, in_rx) = inbound_queue(false);
        // Idle at 60 s so only the write/read-error path (not the idle branch) can end this pump.
        let pump = tokio::spawn(pump_forward_stream(
            1,
            local,
            out_tx,
            in_rx,
            Duration::from_secs(60),
            None,
        ));

        in_tx_bounded(&in_tx)
            .send(StreamIn::Data(b"to-local".to_vec()))
            .await
            .unwrap();
        drop(peer); // local's write (and read) now fail

        match tokio::time::timeout(Duration::from_millis(3000), pump).await {
            Ok(join) => join.unwrap(),
            Err(_) => panic!(
                "pump on a local write/read error did not end within grace + margin although the gegenstelle never reads (AUF-20261006-070)"
            ),
        };
    }

    #[tokio::test(start_paused = true)]
    async fn schreiber_endet_mit_der_engine() {
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0,
            "nothing spawned yet"
        );

        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let (session_side, engine_side) = tokio::io::duplex(4);
        let (_session_up_tx, session_up) = tokio::sync::oneshot::channel();
        let engine = tokio::spawn(run_forward_initiate_engine(
            engine_side,
            listener,
            "127.0.0.1:1".to_string(),
            8,
            Duration::from_secs(30),
            true, // fc_enabled: queues a HELLO frame right away, no stream needed to wedge the writer
            session_up,
        ));

        let mut alive = 0;
        for _ in 0..200 {
            tokio::task::yield_now().await;
            alive = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks();
            if alive == 2 {
                break;
            }
        }
        assert_eq!(
            alive, 2,
            "engine task and its frame writer task should both be alive before the abort"
        );

        engine.abort();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks()
                    == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the frame writer task must end with the engine (AUF-20261006-070)");

        drop(session_side); // held, unread, until here -- reading it would free the writer itself
    }

    #[tokio::test]
    async fn gegenstelle_liest_nicht_neue_verbindung_haengt_nicht_laenger_als_die_frist() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = Arc::new(listener);
        let (session_side, engine_side) = tokio::io::duplex(4);
        let (_session_up_tx, session_up) = tokio::sync::oneshot::channel();
        let _engine = tokio::spawn(run_forward_initiate_engine(
            engine_side,
            listener,
            "127.0.0.1:1".to_string(),
            100,
            Duration::from_secs(60),
            false, // fc_enabled off: no HELLO/FC_ON, only Open fills the queue
            session_up,
        ));

        // CHANNEL_CAP+1, not CHANNEL_CAP: the writer dequeues one frame before it blocks on the
        // tiny duplex, which frees one extra queue slot beyond CHANNEL_CAP itself.
        let mut held = Vec::with_capacity(CHANNEL_CAP + 1);
        for _ in 0..CHANNEL_CAP + 1 {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        // Settle time for the engine to accept and queue all CHANNEL_CAP+1 Open frames; the
        // gegenstelle (session_side) never reads, so the writer is already stuck on the first one.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut extra = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(3100), extra.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Err(_)) => {} // a reset also signals the connection was closed, not left hanging
            Ok(Ok(n)) => panic!(
                "expected the connection whose Open could not be queued to see EOF, got {n} bytes"
            ),
            Err(_) => panic!(
                "a new connection waited longer than the grace + margin for its Open (AUF-20261006-070)"
            ),
        }

        drop(session_side); // held, unread, for the whole test
        drop(held);
    }

    // Merge review of #276, finding 1, at the engine: the peer takes one frame every 1.5 s. Two
    // new connections wait for a place in the full queue; the second gets it after 3 s, later
    // than the grace -- its Open must still go out, because the writer wrote in between.
    #[tokio::test]
    async fn langsam_lesende_gegenstelle_bekommt_jedes_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut session_side, engine_side) = tokio::io::duplex(4);
        let (_session_up_tx, session_up) = tokio::sync::oneshot::channel();
        let _engine = tokio::spawn(run_forward_initiate_engine(
            engine_side,
            Arc::new(listener),
            "127.0.0.1:1".to_string(),
            100,
            Duration::from_secs(60),
            false, // fc_enabled off: only Open frames, all through send_or_drop
            session_up,
        ));
        let mut held = Vec::new();
        for _ in 0..CHANNEL_CAP + 3 {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        for _ in 0..2 {
            tokio::time::sleep(CLOSE_SEND_GRACE * 3 / 4).await;
            assert!(matches!(
                Frame::read(&mut session_side).await,
                Ok(Frame::Open { .. })
            ));
        }
        let mut frames = frames_of(session_side);
        let mut opens = 2;
        while let Ok(Some(f)) = tokio::time::timeout(Duration::from_secs(1), frames.recv()).await {
            assert!(
                matches!(f, Frame::Open { .. }),
                "a stream was given up: {f:?}"
            );
            opens += 1;
        }
        assert_eq!(
            opens,
            CHANNEL_CAP + 3,
            "Open frames that reached a peer that was reading"
        );
    }

    // --- Session window (AUF-20261007-005, replaces AUF-20261006-078 and -081) ---

    /// The frames an engine writes, read by a task of their own: `Frame::read` is not cancel-safe,
    /// so a test must not put a timeout around it.
    fn frames_of<R>(mut r: R) -> mpsc::UnboundedReceiver<Frame>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(f) = Frame::read(&mut r).await {
                if tx.send(f).is_err() {
                    break;
                }
            }
        });
        rx
    }

    type Wire = (
        mpsc::UnboundedReceiver<Frame>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    );

    /// An initiate engine whose peer is the test. `hello` is on the wire before the session is up;
    /// `None` leaves the engine to its HELLO_WAIT.
    async fn initiate_at_the_wire(hello: Option<Frame>) -> (SocketAddr, Wire) {
        let (addr, r, w, engine) = initiate_raw(hello).await;
        (addr, (frames_of(r), w, engine))
    }

    /// The same with the read half in the test's hands: a peer that does not read jams the path.
    async fn initiate_raw(
        hello: Option<Frame>,
    ) -> (
        SocketAddr,
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (session_side, engine_side) = tokio::io::duplex(1 << 16);
        let (r, mut w) = tokio::io::split(session_side);
        if let Some(hello) = hello {
            hello.write(&mut w).await.unwrap();
        }
        let (session_up_tx, session_up) = tokio::sync::oneshot::channel();
        let engine = tokio::spawn(run_forward_initiate_engine(
            engine_side,
            Arc::new(listener),
            "127.0.0.1:1".to_string(),
            64,
            Duration::from_secs(60),
            true,
            session_up,
        ));
        let _ = session_up_tx.send(());
        (addr, r, w, engine)
    }

    /// An accept engine whose peer is the test; it may dial `target`.
    fn accept_at_the_wire(target: &str) -> Wire {
        let (session_side, engine_side) = tokio::io::duplex(1 << 16);
        let engine = tokio::spawn(run_forward_accept_engine(
            engine_side,
            Some(target.to_string()),
            None,
            64,
            Duration::from_secs(60),
            true,
        ));
        let (r, w) = tokio::io::split(session_side);
        (frames_of(r), w, engine)
    }

    /// A local client that writes until its connection ends.
    async fn blast(addr: SocketAddr) {
        let mut c = TcpStream::connect(addr).await.unwrap();
        let chunk = vec![7u8; 64 * 1024];
        while c.write_all(&chunk).await.is_ok() {}
    }

    /// The HELLO of an agent before the session window (v0.7.39-rc.2 sends exactly these bytes).
    fn hello_v1() -> Frame {
        Frame::Data {
            id: CONTROL_ID,
            payload: vec![CTL_HELLO, b'C', b'F', b'C', 1],
        }
    }

    fn swindow_bytes(f: &Frame) -> Option<u32> {
        match f {
            Frame::Data {
                id: CONTROL_ID,
                payload,
            } => match parse_control(payload) {
                Some(Control::SWindow { bytes }) => Some(bytes),
                _ => None,
            },
            _ => None,
        }
    }

    #[test]
    fn hello_v2_carries_the_window_and_v1_is_told_apart() {
        let Frame::Data { payload, .. } = hello_frame(SESSION_WINDOW as u32) else {
            unreachable!()
        };
        assert_eq!(&payload[..5], &[CTL_HELLO, b'C', b'F', b'C', 2]);
        assert!(matches!(
            parse_control(&payload),
            Some(Control::Hello { window: Some(w) }) if w as usize == SESSION_WINDOW
        ));
        let Frame::Data { payload, .. } = hello_v1() else {
            unreachable!()
        };
        assert!(matches!(
            parse_control(&payload),
            Some(Control::Hello { window: None })
        ));
        // Version 2 without its window field is no grant either.
        assert!(matches!(
            parse_control(&[CTL_HELLO, b'C', b'F', b'C', 2, 0, 4]),
            Some(Control::Hello { window: None })
        ));
        let Frame::Data { payload, .. } = swindow_frame(70_000) else {
            unreachable!()
        };
        assert!(matches!(
            parse_control(&payload),
            Some(Control::SWindow { bytes: 70_000 })
        ));
        assert!(parse_control(&[CTL_SWINDOW, 1, 2]).is_none());
    }

    #[tokio::test]
    async fn session_send_never_holds_more_than_the_window_and_refuses_over_acknowledgement() {
        assert!(SessionSend::from_hello(0).unwrap().is_none());
        assert!(SessionSend::from_hello(SESSION_WINDOW_MIN as u32 - 1).is_err());
        let s = SessionSend::from_hello(SESSION_WINDOW as u32)
            .unwrap()
            .unwrap();
        assert_eq!(s.budget_cap + s.first_cap, SESSION_WINDOW);
        assert!(s.first_cap >= DATA_CHUNK_LEN && s.budget_cap >= DATA_CHUNK_LEN);
        let huge = SessionSend::from_hello(u32::MAX).unwrap().unwrap();
        assert_eq!(huge.budget_cap + huge.first_cap, SESSION_WINDOW_MAX);
        assert!(!s.acknowledge(1), "nothing is unacknowledged yet");
        s.take(true, 1000).await.unwrap().queued();
        s.take(false, 5000).await.unwrap().queued();
        assert_eq!(s.unacknowledged(), 6000);
        assert!(!s.acknowledge(6001));
        // An acknowledgement refills the first-chunk part before the rest.
        assert!(s.acknowledge(1500));
        assert_eq!(s.first.available_permits(), s.first_cap);
        assert_eq!(s.budget.available_permits(), s.budget_cap - 4500);
        assert!(s.acknowledge(4500));
        assert_eq!(s.unacknowledged(), 0);
    }

    /// Free permits of both parts: never more than the window, whatever a peer or a reset does.
    fn session_permits(s: &SessionSend) -> usize {
        s.first.available_permits() + s.budget.available_permits()
    }

    // Review of AUF-20261007-005 (W1, W2): bytes a pump only holds are not owed. The peer cannot
    // acknowledge them, the dead-peer check does not see them, and giving them back after an
    // acknowledgement never leaves more permits than the window (measured before: 278528 of
    // 262144).
    #[tokio::test]
    async fn session_send_does_not_count_what_a_pump_only_holds() {
        let s = SessionSend::from_hello(SESSION_WINDOW as u32)
            .unwrap()
            .unwrap();
        let window = s.first_cap + s.budget_cap;
        s.take(false, 5000).await.unwrap().queued();
        // Two chunks wait for room in the engine's queue: taken from the window, not owed.
        let waiting_first = s.take(true, 1000).await.unwrap();
        let waiting_later = s.take(false, 3000).await.unwrap();
        assert_eq!(s.unacknowledged(), 5000);
        assert_eq!(session_permits(&s), window - 9000);
        assert!(!s.acknowledge(5001), "held bytes cannot be acknowledged");
        // The acknowledgement pays the first-chunk part first -- also what the waiting chunk took.
        assert!(s.acknowledge(5000));
        assert_eq!(s.unacknowledged(), 0, "nothing queued is unacknowledged");
        assert_eq!(session_permits(&s), window - 4000);
        // Both streams are reset while they wait: every byte comes back, and not one more.
        drop(waiting_first);
        assert!(session_permits(&s) <= window);
        drop(waiting_later);
        assert_eq!(session_permits(&s), window);
        assert_eq!(s.first.available_permits(), s.first_cap);
        assert_eq!(s.budget.available_permits(), s.budget_cap);
        assert_eq!(s.unacknowledged(), 0);
        assert!(!s.acknowledge(1));
    }

    // A stream's first chunk uses the rest of the window while the reserve for first chunks is
    // used up (review of AUF-20261007-005: 100 new streams left 192 KiB of the window unused).
    #[tokio::test]
    async fn a_first_chunk_takes_the_rest_of_the_window_when_the_reserve_is_used_up() {
        let s = SessionSend::from_hello(SESSION_WINDOW as u32)
            .unwrap()
            .unwrap();
        let mut taken = 0;
        while taken + DATA_CHUNK_LEN <= s.first_cap + s.budget_cap {
            let chunk = tokio::time::timeout(Duration::from_secs(1), s.take(true, DATA_CHUNK_LEN))
                .await
                .expect("a first chunk waits although the window has room");
            chunk.unwrap().queued();
            taken += DATA_CHUNK_LEN;
        }
        assert_eq!(s.unacknowledged(), taken);
        assert_eq!(session_permits(&s), s.first_cap + s.budget_cap - taken);
        // The window is used up: the next first chunk waits.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), s.take(true, DATA_CHUNK_LEN))
                .await
                .is_err()
        );
        // A later chunk never takes the reserve: with only the reserve free it waits.
        assert!(s.acknowledge(taken));
        let later = s.take(false, s.budget_cap).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), s.take(false, 1))
                .await
                .is_err()
        );
        assert!(s.take(true, 1).await.unwrap().from_first);
        drop(later);
    }

    // The sender at the wire: with a window from the peer it never has more stream data
    // unacknowledged than that window (not: window plus a chunk per stream), it needs SWINDOW to
    // go on, and every FC_ON is followed directly by its Open (finding 1 of the -078 review: an
    // FC_ON without its Open cannot reach the wire any more).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sitzungsfenster_nie_mehr_als_das_fenster_unbestaetigt() {
        const W: usize = SESSION_WINDOW_MIN;
        let (addr, (mut frames, mut w, _engine)) =
            initiate_at_the_wire(Some(hello_frame(W as u32))).await;
        for _ in 0..6 {
            tokio::spawn(blast(addr));
        }
        let (mut unacked, mut most, mut total, mut acks) = (0usize, 0usize, 0usize, 0usize);
        let mut announced: Option<u32> = None;
        while total < 2 << 20 {
            match tokio::time::timeout(Duration::from_millis(150), frames.recv()).await {
                Ok(Some(Frame::Data {
                    id: CONTROL_ID,
                    payload,
                })) => {
                    if let Some(Control::FcOn { id }) = parse_control(&payload) {
                        assert!(announced.replace(id).is_none(), "two FC_ON in a row");
                    }
                }
                Ok(Some(Frame::Open { id, .. })) => {
                    assert_eq!(
                        announced.take(),
                        Some(id),
                        "Open without its FC_ON directly before it"
                    );
                }
                Ok(Some(Frame::Data { id, payload })) => {
                    assert!(announced.is_none(), "Data between an FC_ON and its Open");
                    unacked += payload.len();
                    total += payload.len();
                    most = most.max(unacked);
                    assert!(
                        unacked <= W,
                        "{unacked} bytes unacknowledged with a window of {W}"
                    );
                    window_frame(id, payload.len() as u32)
                        .write(&mut w)
                        .await
                        .unwrap();
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the engine ended after {total} bytes"),
                // Nothing comes: the sender waits for the window. Acknowledge everything.
                Err(_) => {
                    if unacked > 0 {
                        swindow_frame(unacked as u32).write(&mut w).await.unwrap();
                        unacked = 0;
                        acks += 1;
                    }
                }
            }
        }
        assert!(
            most > W / 2,
            "the window was not used: at most {most} of {W} bytes on their way"
        );
        assert!(
            acks >= (2 << 20) / W - 1,
            "{acks} acknowledgements for {total} bytes"
        );
    }

    #[tokio::test]
    async fn swindow_ueber_das_unbestaetigte_hinaus_beendet_die_sitzung() {
        let (_addr, (_frames, mut w, engine)) =
            initiate_at_the_wire(Some(hello_frame(SESSION_WINDOW as u32))).await;
        swindow_frame(1).write(&mut w).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("the engine kept running after an acknowledgement for bytes it never sent")
            .unwrap();
    }

    #[tokio::test]
    async fn fenster_unter_dem_minimum_beendet_die_sitzung() {
        let (_addr, (_frames, _w, engine)) =
            initiate_at_the_wire(Some(hello_frame(SESSION_WINDOW_MIN as u32 - 1))).await;
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("the engine kept running with a session window below the minimum")
            .unwrap();
    }

    // Fallback: against a version-1 HELLO, and against a HELLO that comes after HELLO_WAIT (the
    // first stream may already run), no session window is in force -- data flows without any
    // SWINDOW, and an SWINDOW from the peer is ignored instead of ending the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ohne_fenster_wie_bisher_gegen_v1_und_bei_spaetem_hello() {
        for late in [false, true] {
            let (addr, (mut frames, mut w, _engine)) =
                initiate_at_the_wire((!late).then(hello_v1)).await;
            assert_eq!(
                frames.recv().await,
                Some(hello_frame(SESSION_WINDOW as u32)),
                "the engine's own HELLO is its first frame"
            );
            if late {
                tokio::time::sleep(HELLO_WAIT + Duration::from_millis(300)).await;
            }
            for _ in 0..2 {
                tokio::spawn(blast(addr));
            }
            if late {
                hello_frame(SESSION_WINDOW_MIN as u32)
                    .write(&mut w)
                    .await
                    .unwrap();
            }
            swindow_frame(1).write(&mut w).await.unwrap();
            let mut total = 0usize;
            tokio::time::timeout(Duration::from_secs(20), async {
                while total < 1 << 20 {
                    match frames.recv().await.expect("the engine ended") {
                        Frame::Data { id, payload } if id != CONTROL_ID => {
                            total += payload.len();
                            // Credit per stream; ignored for a stream that runs without.
                            window_frame(id, payload.len() as u32)
                                .write(&mut w)
                                .await
                                .unwrap();
                        }
                        _ => {}
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("late={late}: only {total} bytes without SWINDOW"));
        }
    }

    // The receiver at the wire: it acknowledges what its engine reads -- also bytes for an unknown
    // id and for a stream that was reset -- at a quarter of the window, and a rest below that
    // after SESSION_ACK_DELAY.
    #[tokio::test]
    async fn empfaenger_quittiert_auch_verworfene_bytes() {
        let target = holding_target().await;
        let (mut frames, mut w, _engine) = accept_at_the_wire(&target);
        hello_frame(0).write(&mut w).await.unwrap();
        async fn acknowledged(frames: &mut mpsc::UnboundedReceiver<Frame>, want: u32) {
            let mut got = 0u32;
            tokio::time::timeout(Duration::from_secs(5), async {
                while got < want {
                    got +=
                        swindow_bytes(&frames.recv().await.expect("the engine ended")).unwrap_or(0);
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{got} of {want} bytes acknowledged"));
            assert_eq!(got, want);
        }
        // Unknown id, below the threshold: acknowledged by the delay.
        Frame::Data {
            id: 99,
            payload: vec![0; 1000],
        }
        .write(&mut w)
        .await
        .unwrap();
        acknowledged(&mut frames, 1000).await;
        // A stream that was reset: its bytes are dropped, and acknowledged at the threshold.
        Frame::Open {
            id: 5,
            target: target.clone(),
        }
        .write(&mut w)
        .await
        .unwrap();
        abort_frame(5).write(&mut w).await.unwrap();
        for _ in 0..SESSION_WINDOW / 4 / DATA_CHUNK_LEN {
            Frame::Data {
                id: 5,
                payload: vec![0; DATA_CHUNK_LEN],
            }
            .write(&mut w)
            .await
            .unwrap();
        }
        acknowledged(&mut frames, (SESSION_WINDOW / 4) as u32).await;
    }

    // Review of AUF-20261007-005 (W3, open since AUF-20261006-078): an FC_ON whose stream is
    // closed before its Open is over. Pairs of FC_ON and Close do not add up to the control flood
    // that ends the session (measured before: session ended at pair 1025); FC_ONs alone still do.
    #[tokio::test]
    async fn fc_on_und_close_paare_beenden_die_sitzung_nicht() {
        let target = holding_target().await;
        let (mut frames, mut w, engine) = accept_at_the_wire(&target);
        hello_frame(0).write(&mut w).await.unwrap();
        for id in 1..=3 * MAX_PENDING_FC as u32 {
            fc_on_frame(id).write(&mut w).await.unwrap();
            let closed = if id % 2 == 0 {
                abort_frame(id)
            } else {
                Frame::Close { id, reason: None }
            };
            closed.write(&mut w).await.unwrap();
        }
        // The session lives: the engine still reads and acknowledges.
        Frame::Data {
            id: 99,
            payload: vec![0; 1000],
        }
        .write(&mut w)
        .await
        .unwrap();
        let acknowledged = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match frames.recv().await {
                    Some(f) if swindow_bytes(&f) == Some(1000) => break true,
                    Some(_) => {}
                    None => break false,
                }
            }
        })
        .await;
        assert_eq!(
            acknowledged,
            Ok(true),
            "the session ended on FC_ON+Close pairs"
        );
        assert!(!engine.is_finished());
        // Without the Close the same number of FC_ONs is the flood.
        for id in 1..=MAX_PENDING_FC as u32 + 1 {
            fc_on_frame(100_000 + id).write(&mut w).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("an FC_ON flood must end the session")
            .unwrap();
    }

    // Against a version-1 peer the receiver sends no SWINDOW at all, and its HELLO still starts
    // with the bytes a version-1 agent recognises.
    #[tokio::test]
    async fn empfaenger_sendet_v1_kein_swindow() {
        let target = holding_target().await;
        let (mut frames, mut w, _engine) = accept_at_the_wire(&target);
        hello_v1().write(&mut w).await.unwrap();
        for _ in 0..SESSION_WINDOW / DATA_CHUNK_LEN {
            Frame::Data {
                id: 99,
                payload: vec![0; DATA_CHUNK_LEN],
            }
            .write(&mut w)
            .await
            .unwrap();
        }
        let hello = frames.recv().await.unwrap();
        let Frame::Data {
            id: CONTROL_ID,
            payload,
        } = &hello
        else {
            panic!("first frame is not the HELLO: {hello:?}")
        };
        assert_eq!(&payload[..4], &[CTL_HELLO, b'C', b'F', b'C']);
        while let Ok(Some(f)) = tokio::time::timeout(SESSION_ACK_DELAY * 4, frames.recv()).await {
            assert!(
                swindow_bytes(&f).is_none(),
                "SWINDOW to a version-1 peer: {f:?}"
            );
        }
    }

    /// Both engines back to back on one duplex, and a target that counts what arrives. A
    /// connection whose first byte is `R` is read for a little and then dropped (reset); one
    /// whose first byte is `E` gets everything back (echo).
    async fn engine_pair() -> (SocketAddr, Arc<AtomicUsize>) {
        engine_pair_on_a_path(None).await
    }

    /// The same; with `accept_side_late` everything the accept side writes -- its HELLO first --
    /// reaches the initiate side only after that time.
    async fn engine_pair_on_a_path(
        accept_side_late: Option<Duration>,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap().to_string();
        let arrived = Arc::new(AtomicUsize::new(0));
        let count = arrived.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = target.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut seen = 0usize;
                    let mut echo = false;
                    loop {
                        match s.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                let reset = seen == 0 && buf[0] == b'R';
                                echo |= seen == 0 && buf[0] == b'E';
                                seen += n;
                                if reset || (echo && s.write_all(&buf[..n]).await.is_err()) {
                                    return;
                                }
                                count.fetch_add(n, Ordering::Relaxed);
                            }
                            _ => return,
                        }
                    }
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = match accept_side_late {
            None => tokio::io::duplex(1 << 16),
            Some(late) => {
                let (a, path_a) = tokio::io::duplex(1 << 16);
                let (path_b, b) = tokio::io::duplex(1 << 16);
                let (mut from_a, mut to_a) = tokio::io::split(path_a);
                let (mut from_b, mut to_b) = tokio::io::split(path_b);
                tokio::spawn(async move { tokio::io::copy(&mut from_a, &mut to_b).await });
                tokio::spawn(async move {
                    tokio::time::sleep(late).await;
                    tokio::io::copy(&mut from_b, &mut to_a).await
                });
                (a, b)
            }
        };
        let (session_up_tx, session_up) = tokio::sync::oneshot::channel();
        tokio::spawn(run_forward_initiate_engine(
            a,
            Arc::new(listener),
            target_addr.clone(),
            256,
            Duration::from_secs(60),
            true,
            session_up,
        ));
        tokio::spawn(run_forward_accept_engine(
            b,
            Some(target_addr),
            None,
            256,
            Duration::from_secs(60),
            true,
        ));
        let _ = session_up_tx.send(());
        (addr, arrived)
    }

    async fn arrives(arrived: &AtomicUsize, want: usize, within: Duration) {
        let t = tokio::time::Instant::now();
        while arrived.load(Ordering::Relaxed) < want {
            assert!(
                t.elapsed() < within,
                "stalled: {} of {want} bytes arrived after {within:?}",
                arrived.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // Many short streams that together stay below the acknowledgement threshold, each kept open:
    // without the acknowledgement by delay the first-chunk part of the window runs dry (64 KiB) while
    // the receiver still waits for its threshold (64 KiB), and the 22nd stream waits for good.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn viele_kurze_streams_unter_der_schwelle_verklemmen_nicht() {
        let (addr, arrived) = engine_pair().await;
        let mut held = Vec::new();
        for _ in 0..40 {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[7u8; 3000]).await.unwrap();
            held.push(c);
        }
        arrives(&arrived, 40 * 3000, Duration::from_secs(10)).await;
    }

    // No deadlock with resets in mid-stream, a silent source, short streams and bulk at once:
    // everything that is not reset arrives. The bytes of the reset streams are dropped by the
    // receiver; if it did not acknowledge them, the window would be gone after the third reset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sitzungsfenster_verklemmt_nicht_bei_resets_stiller_quelle_und_kurzen_streams() {
        let (addr, arrived) = engine_pair().await;
        let _silent = TcpStream::connect(addr).await.unwrap();
        for _ in 0..6 {
            tokio::spawn(async move {
                let mut c = TcpStream::connect(addr).await.unwrap();
                let chunk = vec![b'R'; 64 * 1024];
                for _ in 0..8 {
                    if c.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            });
        }
        let mut want = 0usize;
        let mut seed = 0x2026_1007u32;
        let mut clients = Vec::new();
        for i in 0..42 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = if i % 20 == 0 {
                1 << 20
            } else {
                1 + (seed >> 8) as usize % 3000
            };
            want += len;
            clients.push(tokio::spawn(async move {
                let mut c = TcpStream::connect(addr).await.unwrap();
                c.write_all(&vec![7u8; len]).await.unwrap();
                c
            }));
        }
        arrives(&arrived, want, Duration::from_secs(30)).await;
    }
    // ---- AUF-20261007-005, slice (ii): the other direction, the dead peer, the coupled grace ----

    /// A target that writes until its connection ends.
    async fn blasting_target() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let chunk = vec![7u8; 64 * 1024];
                    while s.write_all(&chunk).await.is_ok() {}
                });
            }
        });
        addr
    }

    /// An accept engine at the wire with one credited stream to a blasting target; the test is
    /// the initiate side and granted `window`.
    async fn accept_sending_at_the_wire(window: u32) -> Wire {
        let target = blasting_target().await;
        let (frames, mut w, engine) = accept_at_the_wire(&target);
        hello_frame(window).write(&mut w).await.unwrap();
        fc_on_frame(1).write(&mut w).await.unwrap();
        Frame::Open { id: 1, target }.write(&mut w).await.unwrap();
        (frames, w, engine)
    }

    // The accept side as sender at the wire: never more stream data unacknowledged than the
    // window the initiate side granted, and it needs SWINDOW to go on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_seite_nie_mehr_als_das_fenster_unbestaetigt() {
        const W: usize = SESSION_WINDOW_MIN;
        let (mut frames, mut w, _engine) = accept_sending_at_the_wire(W as u32).await;
        let (mut unacked, mut most, mut total, mut acks) = (0usize, 0usize, 0usize, 0usize);
        while total < 1 << 20 {
            match tokio::time::timeout(Duration::from_millis(150), frames.recv()).await {
                Ok(Some(Frame::Data { id: CONTROL_ID, .. })) => {}
                Ok(Some(Frame::Data { id, payload })) => {
                    unacked += payload.len();
                    total += payload.len();
                    most = most.max(unacked);
                    assert!(
                        unacked <= W,
                        "{unacked} bytes unacknowledged with a window of {W}"
                    );
                    window_frame(id, payload.len() as u32)
                        .write(&mut w)
                        .await
                        .unwrap();
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the engine ended after {total} bytes"),
                Err(_) => {
                    assert!(
                        unacked > 0,
                        "the sender stands still with nothing unacknowledged"
                    );
                    swindow_frame(unacked as u32).write(&mut w).await.unwrap();
                    unacked = 0;
                    acks += 1;
                }
            }
        }
        assert!(
            most > W / 2,
            "the window was not used: at most {most} of {W} bytes on their way"
        );
        assert!(
            acks >= (1 << 20) / W - 1,
            "{acks} acknowledgements for {total} bytes"
        );
    }

    // The initiate side as receiver at the wire: its HELLO grants the session window, and it
    // acknowledges every byte it reads -- to a version-2 peer only.
    #[tokio::test]
    async fn initiate_seite_gewaehrt_das_fenster_und_quittiert_was_sie_liest() {
        for v2 in [true, false] {
            let hello = if v2 {
                hello_frame(SESSION_WINDOW as u32)
            } else {
                hello_v1()
            };
            let (addr, (mut frames, mut w, _engine)) = initiate_at_the_wire(Some(hello)).await;
            let _client = TcpStream::connect(addr).await.unwrap();
            let mut id = None;
            let mut granted = None;
            while id.is_none() {
                match tokio::time::timeout(Duration::from_secs(5), frames.recv()).await {
                    Ok(Some(Frame::Open { id: i, .. })) => id = Some(i),
                    Ok(Some(Frame::Data {
                        id: CONTROL_ID,
                        payload,
                    })) => {
                        if let Some(Control::Hello { window }) = parse_control(&payload) {
                            granted = window;
                        }
                    }
                    other => panic!("no Open: {other:?}"),
                }
            }
            assert_eq!(
                granted,
                Some(SESSION_WINDOW as u32),
                "the HELLO of the initiate side"
            );
            let sent = 3 * 10_000 + 5 * DATA_CHUNK_LEN;
            for len in [10_000, 10_000, 10_000]
                .into_iter()
                .chain([DATA_CHUNK_LEN; 5])
            {
                Frame::Data {
                    id: id.unwrap(),
                    payload: vec![1u8; len],
                }
                .write(&mut w)
                .await
                .unwrap();
            }
            let mut acked = 0usize;
            let until = tokio::time::Instant::now() + Duration::from_secs(2);
            while acked < sent {
                match tokio::time::timeout_at(until, frames.recv()).await {
                    Ok(Some(f)) => acked += swindow_bytes(&f).unwrap_or(0) as usize,
                    _ => break,
                }
            }
            assert_eq!(
                acked,
                if v2 { sent } else { 0 },
                "acknowledged to a peer with v2 = {v2}"
            );
        }
    }

    /// Read what a sending engine puts on the wire and acknowledge `ack` bytes every
    /// `every` (never, with `None`); returns when the engine ended, with the bytes read.
    async fn read_and_acknowledge(
        (mut frames, mut w, engine): Wire,
        ack: Option<(usize, Duration)>,
        for_at_most: Duration,
    ) -> (bool, usize, Duration) {
        let t0 = tokio::time::Instant::now();
        let (mut total, mut unacked) = (0usize, 0usize);
        let mut next_ack = t0 + ack.map_or(for_at_most * 2, |(_, every)| every);
        loop {
            if engine.is_finished() || t0.elapsed() >= for_at_most {
                return (engine.is_finished(), total, t0.elapsed());
            }
            match tokio::time::timeout(Duration::from_millis(50), frames.recv()).await {
                Ok(Some(Frame::Data { id, payload })) if id != CONTROL_ID => {
                    total += payload.len();
                    unacked += payload.len();
                    // Stream credit is always returned: only the session window is under test.
                    let _ = window_frame(id, payload.len() as u32).write(&mut w).await;
                }
                _ => {}
            }
            if let Some((bytes, every)) = ack {
                if tokio::time::Instant::now() >= next_ack && unacked > 0 {
                    let n = bytes.min(unacked);
                    let _ = swindow_frame(n as u32).write(&mut w).await;
                    unacked -= n;
                    next_ack += every;
                }
            }
        }
    }

    // A peer that acknowledges nothing is dead after SESSION_DEAD_AFTER: the SESSION ends (the
    // engine returns, every stream with it) -- not before the time is up, and on either side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tote_gegenstelle_beendet_die_sitzung_nach_der_frist() {
        const W: u32 = SESSION_WINDOW_MIN as u32;
        let (addr, wire) = initiate_at_the_wire(Some(hello_frame(W))).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&vec![7u8; 4 * SESSION_WINDOW_MIN])
            .await
            .unwrap();
        let (initiate, accept) = tokio::join!(
            read_and_acknowledge(wire, None, SESSION_DEAD_AFTER * 3),
            read_and_acknowledge(
                accept_sending_at_the_wire(W).await,
                None,
                SESSION_DEAD_AFTER * 3
            ),
        );
        for (side, (ended, total, took)) in [("initiate", initiate), ("accept", accept)] {
            assert!(
                ended,
                "{side}: the session still runs {took:?} after the peer went silent"
            );
            // Not `== W`: a chunk that does not fit whole into what is left of the window waits.
            assert!(
                total <= W as usize && total + DATA_CHUNK_LEN > W as usize,
                "{side}: {total} bytes on the wire without an acknowledgement"
            );
            assert!(
                took >= SESSION_DEAD_AFTER,
                "{side}: ended after {took:?}, before the time was up"
            );
        }
        // What ends is the session: the local connection of the initiate side is closed with it.
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "the local connection outlived its session"
        );
    }

    // Review of AUF-20261007-005 (W1): a healthy peer that falls silent is not a dead one. The
    // path is jammed, chunks wait for room in the engine's queue holding a part of the window;
    // the peer acknowledges exactly what it read and resets the waiting streams, then reads and
    // acknowledges the rest and says nothing more. Nothing it could have is unacknowledged, so
    // the session stays (measured before: ended as "dead peer", the held bytes counted as sent).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stille_gesunde_gegenstelle_ist_nicht_tot() {
        let (addr, mut r, mut w, engine) = initiate_raw(Some(hello_frame(u32::MAX))).await;
        // More than the path holds (queue, duplex), each stream up to its credit: the path jams.
        for _ in 0..12 {
            tokio::spawn(blast(addr));
        }
        let pause = |ms| tokio::time::sleep(Duration::from_millis(ms));
        let mut read = 0usize;
        while read < SESSION_WINDOW / 2 {
            if let Frame::Data { id, payload } = Frame::read(&mut r).await.unwrap() {
                if id != CONTROL_ID {
                    read += payload.len();
                }
            }
        }
        pause(300).await;
        // Four more streams: their first chunks wait.
        let mut waiting = Vec::new();
        for _ in 0..4 {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&vec![9u8; DATA_CHUNK_LEN]).await.unwrap();
            waiting.push(c);
        }
        pause(300).await;
        // Acknowledge what was read, in two parts, the path still jammed in between.
        let half = (read / 2) as u32;
        swindow_frame(half).write(&mut w).await.unwrap();
        pause(300).await;
        swindow_frame(read as u32 - half)
            .write(&mut w)
            .await
            .unwrap();
        pause(100).await;
        for id in 1..=16 {
            abort_frame(id).write(&mut w).await.unwrap();
        }
        // The peer reads on and acknowledges every byte, until nothing more comes.
        let mut frames = frames_of(r);
        let mut acknowledged = read;
        while let Ok(Some(f)) =
            tokio::time::timeout(Duration::from_millis(500), frames.recv()).await
        {
            if let Frame::Data { id, payload } = f {
                if id != CONTROL_ID {
                    read += payload.len();
                }
            }
            if read - acknowledged >= SESSION_WINDOW / 4 {
                swindow_frame((read - acknowledged) as u32)
                    .write(&mut w)
                    .await
                    .unwrap();
                acknowledged = read;
            }
        }
        if read > acknowledged {
            swindow_frame((read - acknowledged) as u32)
                .write(&mut w)
                .await
                .unwrap();
        }
        // Silence, but the peer still reads. The session must outlive it.
        let t0 = tokio::time::Instant::now();
        while t0.elapsed() < SESSION_DEAD_AFTER * 2 {
            assert!(
                !engine.is_finished(),
                "the session ended {:?} after a healthy peer fell silent (all {read} bytes acknowledged)",
                t0.elapsed()
            );
            let _ = tokio::time::timeout(Duration::from_millis(100), frames.recv()).await;
        }
        drop(waiting);
    }

    // Review of AUF-20261007-005 (W2): the HELLO of the accept side reaches the initiate side
    // after HELLO_WAIT, both ends with the session window. The initiate side then opens its
    // streams without credit; what the accept side sends on them still counts against the window,
    // because the initiate side acknowledges it (measured before: "acknowledged more than was
    // sent", 217408 of 327680 bytes at the client).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spaetes_hello_zwischen_zwei_neuen_seiten_beendet_die_sitzung_nicht() {
        const BYTES: usize = SESSION_WINDOW + SESSION_WINDOW / 4;
        let (addr, _arrived) = engine_pair_on_a_path(Some(HELLO_WAIT + HELLO_WAIT / 2)).await;
        let (mut from_target, mut to_target) = TcpStream::connect(addr).await.unwrap().into_split();
        let writer = tokio::spawn(async move {
            let mut data = vec![7u8; BYTES];
            data[0] = b'E';
            to_target
                .write_all(&data)
                .await
                .is_ok()
                .then_some(to_target)
        });
        let mut back = vec![0u8; BYTES];
        let mut got = 0;
        let all = tokio::time::timeout(Duration::from_secs(10), async {
            while got < BYTES {
                match from_target.read(&mut back[got..]).await {
                    Ok(n) if n > 0 => got += n,
                    _ => break,
                }
            }
        })
        .await;
        assert!(
            all.is_ok() && got == BYTES,
            "the echo came back with {got} of {BYTES} bytes"
        );
        assert!(writer.await.unwrap().is_some());
        // The session is still there for the next connection.
        let mut next = TcpStream::connect(addr).await.unwrap();
        next.write_all(b"E-next").await.unwrap();
        let mut buf = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), next.read_exact(&mut buf))
            .await
            .expect("no echo on a second connection")
            .unwrap();
        assert_eq!(&buf, b"E-next");
    }

    // A slow reader is not a dead one: one chunk acknowledged every half SESSION_DEAD_AFTER keeps
    // the session, and the data keeps flowing, for three times SESSION_DEAD_AFTER. The bound: the
    // first acknowledgement refills the first-chunk share (no use to a running stream), each later
    // one frees a chunk; two chunks beyond the window need the acknowledgement at 1.5 times
    // SESSION_DEAD_AFTER, and a chunk that does not fit whole waits (so not `4 *`: measured red).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn langsam_fliessender_leser_behaelt_die_sitzung() {
        const W: u32 = SESSION_WINDOW_MIN as u32;
        let (addr, wire) = initiate_at_the_wire(Some(hello_frame(W))).await;
        tokio::spawn(blast(addr));
        let slow = Some((DATA_CHUNK_LEN, SESSION_DEAD_AFTER / 2));
        let (ended, total, took) = read_and_acknowledge(wire, slow, SESSION_DEAD_AFTER * 3).await;
        assert!(
            !ended,
            "the session ended after {took:?} although the peer acknowledged"
        );
        assert!(
            total >= W as usize + 2 * DATA_CHUNK_LEN,
            "only {total} bytes in {took:?}: the data did not keep flowing"
        );
    }

    /// A full queue of one frame, a competitor waiting in front, and a writer that takes one
    /// frame every `step` (never, with `None`) and counts it.
    async fn close_behind_a_full_queue(step: Option<Duration>) -> (bool, Duration) {
        let (tx, mut rx) = mpsc::channel::<Frame>(1);
        tx.send(abort_frame(1)).await.unwrap();
        let ahead = tx.clone();
        tokio::spawn(async move { ahead.send(abort_frame(2)).await });
        tokio::task::yield_now().await;
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let count = written.clone();
        tokio::spawn(async move {
            let Some(step) = step else {
                return std::future::pending().await;
            };
            loop {
                tokio::time::sleep(step).await;
                if rx.recv().await.is_none() {
                    return;
                }
                count.fetch_add(1, Ordering::Relaxed);
            }
        });
        let t0 = tokio::time::Instant::now();
        let sent = WRITTEN
            .scope(
                written,
                send_or_drop(
                    &tx,
                    Frame::Close {
                        id: 3,
                        reason: None,
                    },
                ),
            )
            .await;
        (sent, t0.elapsed())
    }

    // Merge review of #276, finding 1: a peer that reads slowly must not lose a Close. The
    // writer takes a frame every 1.5 s; the Close needs two of them, more than the grace.
    #[tokio::test]
    async fn langsam_lesende_gegenstelle_verliert_kein_close() {
        let (sent, took) = close_behind_a_full_queue(Some(CLOSE_SEND_GRACE * 3 / 4)).await;
        assert!(
            sent,
            "the Close was dropped after {took:?} although the writer made progress"
        );
        assert!(
            took > CLOSE_SEND_GRACE,
            "sent after {took:?}: the case did not outlast the grace"
        );
    }

    #[tokio::test]
    async fn stehender_schreiber_verwirft_nach_einer_frist() {
        let (sent, took) = close_behind_a_full_queue(None).await;
        assert!(!sent, "a Close went into a queue nobody takes from");
        assert!(
            took >= CLOSE_SEND_GRACE && took < CLOSE_SEND_GRACE * 2,
            "dropped after {took:?}, expected after one grace"
        );
    }

    // No deadlock with bulk in BOTH directions under both session windows: eight connections
    // send 512 KiB each and read the same back, next to resets in mid-stream and a connection
    // whose client never reads what comes back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sitzungsfenster_verklemmt_nicht_bei_last_in_beiden_richtungen() {
        let (addr, _arrived) = engine_pair().await;
        for _ in 0..3 {
            tokio::spawn(async move {
                let mut c = TcpStream::connect(addr).await.unwrap();
                let chunk = vec![b'R'; 64 * 1024];
                while c.write_all(&chunk).await.is_ok() {}
            });
        }
        let mut deaf = TcpStream::connect(addr).await.unwrap();
        deaf.write_all(&vec![b'E'; 256 * 1024]).await.unwrap();
        const LEN: usize = 512 * 1024;
        let mut clients = Vec::new();
        for _ in 0..8 {
            clients.push(tokio::spawn(async move {
                let c = TcpStream::connect(addr).await.unwrap();
                let (mut r, mut w) = c.into_split();
                let up = tokio::spawn(async move {
                    w.write_all(&vec![b'E'; LEN]).await.unwrap();
                    w
                });
                let mut back = vec![0u8; LEN];
                r.read_exact(&mut back).await.unwrap();
                drop(up.await);
                back.iter().all(|b| *b == b'E')
            }));
        }
        for c in clients {
            let ok = tokio::time::timeout(Duration::from_secs(30), c)
                .await
                .expect("stalled: a connection did not get its bytes back within 30 s")
                .unwrap();
            assert!(ok, "the bytes that came back are not the bytes sent");
        }
    }

    // Review of AUF-20261007-005 (W2, mirror gaps): what was tested on one engine only, on the
    // other one too, and a HELLO of a later version.

    #[test]
    fn hello_of_a_later_version_still_carries_the_window() {
        for payload in [
            vec![CTL_HELLO, b'C', b'F', b'C', 3, 0, 4, 0, 0],
            vec![CTL_HELLO, b'C', b'F', b'C', 3, 0, 4, 0, 0, 9, 9],
            vec![CTL_HELLO, b'C', b'F', b'C', 255, 0, 4, 0, 0],
        ] {
            assert!(
                matches!(
                    parse_control(&payload),
                    Some(Control::Hello { window: Some(w) }) if w == 0x0004_0000
                ),
                "{payload:?}"
            );
        }
    }

    #[tokio::test]
    async fn accept_seite_swindow_ueber_das_unbestaetigte_hinaus_beendet_die_sitzung() {
        let target = holding_target().await;
        let (_frames, mut w, engine) = accept_at_the_wire(&target);
        hello_frame(SESSION_WINDOW as u32)
            .write(&mut w)
            .await
            .unwrap();
        swindow_frame(1).write(&mut w).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("the engine kept running after an acknowledgement for bytes it never sent")
            .unwrap();
    }

    #[tokio::test]
    async fn accept_seite_fenster_unter_dem_minimum_beendet_die_sitzung() {
        let target = holding_target().await;
        let (_frames, mut w, engine) = accept_at_the_wire(&target);
        hello_frame(SESSION_WINDOW_MIN as u32 - 1)
            .write(&mut w)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("the engine kept running with a session window below the minimum")
            .unwrap();
    }

    /// Stream data of stream `of` an engine puts on the wire within `within`, while the test
    /// returns stream credit and never acknowledges for the session; stops at `enough`.
    async fn flows_without_swindow(
        frames: &mut mpsc::UnboundedReceiver<Frame>,
        w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        of: u32,
        enough: usize,
        within: Duration,
    ) -> usize {
        let mut total = 0usize;
        let until = tokio::time::Instant::now() + within;
        while total < enough {
            match tokio::time::timeout_at(until, frames.recv()).await {
                Ok(Some(Frame::Data { id, payload })) if id != CONTROL_ID => {
                    if id == of {
                        total += payload.len();
                    }
                    window_frame(id, payload.len() as u32)
                        .write(&mut *w)
                        .await
                        .unwrap();
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the engine ended after {total} bytes"),
                Err(_) => break,
            }
        }
        total
    }

    // The accept side as sender against a version-1 HELLO: no session window, the data flows
    // without any SWINDOW, and an SWINDOW from the peer is ignored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_seite_ohne_fenster_gegen_v1() {
        let target = blasting_target().await;
        let (mut frames, mut w, engine) = accept_at_the_wire(&target);
        hello_v1().write(&mut w).await.unwrap();
        fc_on_frame(1).write(&mut w).await.unwrap();
        Frame::Open { id: 1, target }.write(&mut w).await.unwrap();
        swindow_frame(1).write(&mut w).await.unwrap();
        let total =
            flows_without_swindow(&mut frames, &mut w, 1, 1 << 20, Duration::from_secs(20)).await;
        assert!(total >= 1 << 20, "only {total} bytes without SWINDOW");
        assert!(!engine.is_finished());
    }

    // A HELLO that reaches the accept side after the first Open sets no session window there
    // (both ends count from the same byte or not at all): a later stream flows without SWINDOW.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_seite_ohne_fenster_bei_hello_nach_dem_ersten_open() {
        let target = blasting_target().await;
        let (mut frames, mut w, engine) = accept_at_the_wire(&target);
        Frame::Open {
            id: 1,
            target: target.clone(),
        }
        .write(&mut w)
        .await
        .unwrap();
        hello_frame(SESSION_WINDOW_MIN as u32)
            .write(&mut w)
            .await
            .unwrap();
        fc_on_frame(2).write(&mut w).await.unwrap();
        Frame::Open { id: 2, target }.write(&mut w).await.unwrap();
        swindow_frame(1).write(&mut w).await.unwrap();
        let total =
            flows_without_swindow(&mut frames, &mut w, 2, 1 << 20, Duration::from_secs(20)).await;
        assert!(total >= 1 << 20, "only {total} bytes without SWINDOW");
        assert!(!engine.is_finished());
    }

    // Also a stream WITHOUT credit counts against the session window on the accept side (the
    // initiate side acknowledges its bytes like any other): no more than the window is on its
    // way, and an acknowledgement lets it go on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accept_seite_zaehlt_auch_streams_ohne_kredit() {
        const W: usize = SESSION_WINDOW_MIN;
        let target = blasting_target().await;
        let (mut frames, mut w, _engine) = accept_at_the_wire(&target);
        hello_frame(W as u32).write(&mut w).await.unwrap();
        Frame::Open { id: 1, target }.write(&mut w).await.unwrap();
        let first =
            flows_without_swindow(&mut frames, &mut w, 1, 2 * W, Duration::from_secs(2)).await;
        assert!(
            first <= W && first + DATA_CHUNK_LEN > W,
            "{first} bytes on the wire without an acknowledgement, window {W}"
        );
        swindow_frame(first as u32).write(&mut w).await.unwrap();
        let more =
            flows_without_swindow(&mut frames, &mut w, 1, 2 * W, Duration::from_secs(2)).await;
        assert!(
            more > 0 && more <= W,
            "{more} bytes after the acknowledgement, window {W}"
        );
    }

    // The initiate side as receiver: it acknowledges bytes for an unknown id and for a stream
    // that was reset, like the accept side.
    #[tokio::test]
    async fn initiate_seite_quittiert_auch_verworfene_bytes() {
        let (addr, (mut frames, mut w, _engine)) =
            initiate_at_the_wire(Some(hello_frame(SESSION_WINDOW as u32))).await;
        async fn acknowledged(frames: &mut mpsc::UnboundedReceiver<Frame>, want: u32) {
            let mut got = 0u32;
            tokio::time::timeout(Duration::from_secs(5), async {
                while got < want {
                    got +=
                        swindow_bytes(&frames.recv().await.expect("the engine ended")).unwrap_or(0);
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{got} of {want} bytes acknowledged"));
            assert_eq!(got, want);
        }
        Frame::Data {
            id: 99,
            payload: vec![0; 1000],
        }
        .write(&mut w)
        .await
        .unwrap();
        acknowledged(&mut frames, 1000).await;
        let _client = TcpStream::connect(addr).await.unwrap();
        let id = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Frame::Open { id, .. } = frames.recv().await.expect("the engine ended") {
                    break id;
                }
            }
        })
        .await
        .expect("no Open");
        abort_frame(id).write(&mut w).await.unwrap();
        for _ in 0..SESSION_WINDOW / 4 / DATA_CHUNK_LEN {
            Frame::Data {
                id,
                payload: vec![0; DATA_CHUNK_LEN],
            }
            .write(&mut w)
            .await
            .unwrap();
        }
        acknowledged(&mut frames, (SESSION_WINDOW / 4) as u32).await;
    }

    // FC_ON+Close pairs at the initiate side: no control flood there either; FC_ONs alone are.
    #[tokio::test]
    async fn initiate_seite_fc_on_und_close_paare_beenden_die_sitzung_nicht() {
        let (_addr, (mut frames, mut w, engine)) =
            initiate_at_the_wire(Some(hello_frame(SESSION_WINDOW as u32))).await;
        for id in 1..=3 * MAX_PENDING_FC as u32 {
            fc_on_frame(id).write(&mut w).await.unwrap();
            let closed = if id % 2 == 0 {
                abort_frame(id)
            } else {
                Frame::Close { id, reason: None }
            };
            closed.write(&mut w).await.unwrap();
        }
        Frame::Data {
            id: 99,
            payload: vec![0; 1000],
        }
        .write(&mut w)
        .await
        .unwrap();
        let acknowledged = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match frames.recv().await {
                    Some(f) if swindow_bytes(&f) == Some(1000) => break true,
                    Some(_) => {}
                    None => break false,
                }
            }
        })
        .await;
        assert_eq!(
            acknowledged,
            Ok(true),
            "the session ended on FC_ON+Close pairs"
        );
        assert!(!engine.is_finished());
        for id in 1..=MAX_PENDING_FC as u32 + 1 {
            fc_on_frame(100_000 + id).write(&mut w).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), engine)
            .await
            .expect("an FC_ON flood must end the session")
            .unwrap();
    }
}
