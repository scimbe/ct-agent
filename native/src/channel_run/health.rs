//! Health of a running `ct-agent channel` process: what a probe asks (`CT_CHANNEL_HEALTH_LISTEN`,
//! opt-in) and what the shutdown drain waits for ([`super::shutdown`]).
//!
//! Channel mode had no health signal at all: `/healthz` and `/status` exist only on the tunnel
//! agent's metrics listener (`CT_AGENT_METRICS_LISTEN`, ct-agent#178), which the `channel` branch
//! never starts. A pod running `ct-agent channel` could therefore get neither a liveness nor a
//! readiness probe. This module adds two routes and nothing else:
//!
//! * `GET /healthz` -- 200 while the process runs its channel loop. The answer itself is the
//!   check (the runtime still serves requests); it never depends on the edge or on the peer, so a
//!   liveness probe on it cannot restart-loop a pod whose peer is simply away.
//! * `GET /readyz` -- 200 while a session is established, while an accept member's admission is
//!   parked at the edge waiting for a peer, and for [`READY_GRACE_SECS`] after either ended (a
//!   re-park after a park expiry or a forward's reconnect is not an outage); 503 with the reason
//!   otherwise, and from the moment a shutdown started. An initiator's own park does not count:
//!   it waits for an acceptor that may never come, and its forward does not work meanwhile.
//!
//! The listener reuses the observability listener's bounds (connection cap, header and connection
//! timeouts) and, on a loopback bind, its DNS-rebinding guard. `ct-agent channel health
//! [readyz|healthz]` asks it from inside the container and exits 0 or 1, so an exec probe needs
//! neither curl nor python and the port can stay on loopback.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::channel::ChannelJoinOutcome;
use crate::codec::now_unix;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// `CT_CHANNEL_HEALTH_LISTEN=<ip:port>`: serve `/healthz` and `/readyz` there. Unset or empty: no
/// listener (the default).
pub const HEALTH_LISTEN_ENV: &str = "CT_CHANNEL_HEALTH_LISTEN";

/// How long after its last session (or, on the accept side, its last park the edge held) a member
/// still answers ready. Covers a re-park (200 ms after a park expiry) and a forward initiator's
/// reconnect after a dropped session (its first backoff step is 1 s), not an outage.
pub const READY_GRACE_SECS: u64 = 15;

/// Bound on one probe's connect and on reading its answer (`ct-agent channel health`). A
/// Kubernetes exec probe has its own `timeoutSeconds` on top.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the probes and the shutdown drain read. The process-wide instance is [`HEALTH`]; tests
/// build their own (leaked, the routes want `'static`), as `status::AgentStatus` does.
#[derive(Debug)]
pub(crate) struct ChannelHealth {
    /// Sessions past the Noise handshake, until they end (every mode).
    established: AtomicUsize,
    /// Admissions presented on a connected leg and waiting for the edge's answer.
    parked: AtomicUsize,
    /// Persistent-serve sessions from their pairing to their end: unlike `established` this also
    /// covers a paired session that is still setting up its legs.
    serving: AtomicUsize,
    /// Forwarded TCP streams on either side, from the accepted connection or the peer's `Open`.
    forward_streams: AtomicUsize,
    /// Unix time the last session ended (0: none yet).
    session_ended_at: AtomicU64,
    /// Unix time the last park the edge held ended -- paired or expired (0: none yet).
    park_ended_at: AtomicU64,
    /// A shutdown started: not ready any more.
    stopping: AtomicBool,
}

/// The process-wide health every production call site counts in.
pub(crate) static HEALTH: ChannelHealth = ChannelHealth::new();

/// Counts one unit until dropped; with a stamp, it also records when it ended (stamp first, so a
/// reader that sees the count drop also sees the time).
pub(crate) struct Ticket {
    count: &'static AtomicUsize,
    stamp: Option<&'static AtomicU64>,
}

impl Ticket {
    fn new(count: &'static AtomicUsize, stamp: Option<&'static AtomicU64>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self { count, stamp }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(at) = self.stamp {
            at.store(now_unix(), Ordering::SeqCst);
        }
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ChannelHealth {
    pub(crate) const fn new() -> Self {
        Self {
            established: AtomicUsize::new(0),
            parked: AtomicUsize::new(0),
            serving: AtomicUsize::new(0),
            forward_streams: AtomicUsize::new(0),
            session_ended_at: AtomicU64::new(0),
            park_ended_at: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        }
    }

    /// A session completed its Noise handshake: counted until the ticket drops, and its end is
    /// time-stamped for the readiness grace.
    pub(crate) fn session_established(&'static self) -> Ticket {
        Ticket::new(&self.established, Some(&self.session_ended_at))
    }

    /// Run `present` -- an admission on a leg that is already connected -- counted as parked. An
    /// answer showing that the edge held the park (a pairing, or a park expiry the member re-parks
    /// after) time-stamps its end; a refusal or a failed leg does not, so a member the edge keeps
    /// refusing never looks ready.
    pub(crate) async fn parked<E, F>(&'static self, present: F) -> Result<ChannelJoinOutcome, E>
    where
        F: Future<Output = Result<ChannelJoinOutcome, E>>,
    {
        let mut ticket = Ticket::new(&self.parked, None);
        let outcome = present.await;
        if matches!(outcome, Ok(ChannelJoinOutcome::Admitted { .. } | ChannelJoinOutcome::ParkExpired)) {
            ticket.stamp = Some(&self.park_ended_at);
        }
        outcome
    }

    /// `session` counted as a persistent-serve session from NOW -- synchronously, before the
    /// caller spawns it -- until it ends or is dropped.
    pub(crate) fn serving<F: Future>(&'static self, session: F) -> impl Future<Output = F::Output> {
        let ticket = Ticket::new(&self.serving, None);
        async move {
            let _ticket = ticket;
            session.await
        }
    }

    /// `stream` counted as one forwarded TCP stream from now until it ends or is aborted (an
    /// aborted task drops its future, and the ticket with it).
    pub(crate) fn forward_stream<F: Future>(&'static self, stream: F) -> impl Future<Output = F::Output> {
        let ticket = Ticket::new(&self.forward_streams, None);
        async move {
            let _ticket = ticket;
            stream.await
        }
    }

    /// A shutdown started: `/readyz` answers 503 from now on.
    pub(crate) fn set_stopping(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Forwarded streams open right now (both sides).
    pub(crate) fn forward_streams(&self) -> usize {
        self.forward_streams.load(Ordering::SeqCst)
    }

    /// What the shutdown drain waits for. A forward member's sessions live as long as its peer
    /// does, so only the streams on them are work in flight; for any other member a session is
    /// (`serving` covers a persistent-serve session from its pairing on, `established` every other
    /// mode, and the larger of the two counts each session once).
    pub(crate) fn in_flight(&self, forward: bool) -> usize {
        if forward {
            self.forward_streams()
        } else {
            self.serving.load(Ordering::SeqCst).max(self.established.load(Ordering::SeqCst))
        }
    }

    /// `/healthz`: the process runs its channel loop. Never depends on the edge or the peer.
    pub(crate) fn liveness(&self) -> &'static str {
        if self.stopping.load(Ordering::SeqCst) {
            "ok (shutting down)"
        } else {
            "ok"
        }
    }

    /// `/readyz` at unix time `now`: `Ok(why)` or `Err(why not)`. `accept`: this member parks for
    /// its peers (the accept role), so a park counts as ready.
    pub(crate) fn readiness_at(&self, now: u64, accept: bool) -> Result<String, String> {
        if self.stopping.load(Ordering::SeqCst) {
            return Err("shutting down".to_string());
        }
        let established = self.established.load(Ordering::SeqCst);
        if established > 0 {
            return Ok(format!("{established} session(s) established"));
        }
        if accept && self.parked.load(Ordering::SeqCst) > 0 {
            return Ok("parked at the edge, waiting for a peer".to_string());
        }
        let park_ended = if accept { self.park_ended_at.load(Ordering::SeqCst) } else { 0 };
        let last = self.session_ended_at.load(Ordering::SeqCst).max(park_ended);
        let waiting = if accept { "no session established and not parked" } else { "no session established" };
        if last == 0 {
            return Err(format!("{waiting} yet"));
        }
        let ago = now.saturating_sub(last);
        if ago < READY_GRACE_SECS {
            Ok(format!("between sessions (the last one ended {ago}s ago, grace {READY_GRACE_SECS}s)"))
        } else {
            Err(format!("{waiting} for {ago}s"))
        }
    }
}

impl Default for ChannelHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `CT_CHANNEL_ROLE` names the accept side -- the same spellings the config parsers take.
pub(crate) fn accept_role(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|r| r.trim().to_ascii_lowercase()).as_deref(),
        Some("accept" | "responder" | "listen")
    )
}

/// [`HEALTH_LISTEN_ENV`] parsed: unset or empty is off (compose passes an unset variable as
/// empty); anything else must be an `ip:port`, or the start fails -- a probe pointed at a
/// listener that silently never came up would only ever say "not ready".
pub(crate) fn health_listen_from(raw: Option<&str>) -> Result<Option<SocketAddr>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => s
            .parse::<SocketAddr>()
            .map(Some)
            .map_err(|e| format!("{HEALTH_LISTEN_ENV}={s:?} is not an ip:port ({e})")),
    }
}

#[derive(Clone, Copy)]
struct HealthState {
    health: &'static ChannelHealth,
    accept: bool,
}

fn health_router(health: &'static ChannelHealth, accept: bool) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(HealthState { health, accept })
}

async fn healthz(State(s): State<HealthState>) -> (StatusCode, String) {
    (StatusCode::OK, format!("{}\n", s.health.liveness()))
}

async fn readyz(State(s): State<HealthState>) -> (StatusCode, String) {
    match s.health.readiness_at(now_unix(), s.accept) {
        Ok(why) => (StatusCode::OK, format!("ready: {why}\n")),
        Err(why) => (StatusCode::SERVICE_UNAVAILABLE, format!("not ready: {why}\n")),
    }
}

/// Serve `/healthz` and `/readyz` on an already-bound `listener` until the process exits, with the
/// observability listener's bounds and, on loopback, its DNS-rebinding guard.
pub(crate) async fn serve_health(
    listener: tokio::net::TcpListener,
    health: &'static ChannelHealth,
    accept: bool,
) -> Result<(), BoxError> {
    let loopback = listener.local_addr()?.ip().is_loopback();
    let app = crate::observe::guarded(health_router(health, accept), loopback);
    crate::observe::serve_bounded(listener, app, crate::observe::ListenerLimits::DEFAULT).await
}

/// `ct-agent channel health [readyz|healthz]`: ask this container's own health listener
/// ([`HEALTH_LISTEN_ENV`], read from the same environment the member runs with), print the
/// answer, and return the exit status -- 0 for a 200, 1 for anything else or no answer, 2 for a
/// usage or configuration error. That is the shape a Kubernetes exec probe wants.
pub async fn run_health_probe(which: Option<&str>) -> i32 {
    let path = match which {
        None | Some("readyz") => "/readyz",
        Some("healthz") => "/healthz",
        Some(other) => {
            eprintln!("ct-agent channel health: unknown check '{other}' (expected readyz or healthz)");
            return 2;
        }
    };
    let listen = match health_listen_from(std::env::var(HEALTH_LISTEN_ENV).ok().as_deref()) {
        Ok(Some(listen)) => listen,
        Ok(None) => {
            eprintln!(
                "ct-agent channel health: {HEALTH_LISTEN_ENV} is not set -- the probe asks the listener \
                 the running member serves there"
            );
            return 2;
        }
        Err(e) => {
            eprintln!("ct-agent channel health: {e}");
            return 2;
        }
    };
    let target = probe_target(listen);
    let code = match probe(target, path, PROBE_TIMEOUT).await {
        Ok((200, body)) => {
            print!("{body}");
            0
        }
        Ok((code, body)) => {
            print!("{body}");
            eprintln!("ct-agent channel health: {path} on {target} answered {code}");
            1
        }
        Err(e) => {
            eprintln!("ct-agent channel health: {path} on {target}: {e}");
            1
        }
    };
    // The caller exits with `process::exit` on a failure, which flushes nothing.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    code
}

/// Where a probe connects for a listener bound to `listen`: an unspecified address (`0.0.0.0`,
/// `::`) is reached on the loopback address of its family.
pub(crate) fn probe_target(listen: SocketAddr) -> SocketAddr {
    match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), listen.port()),
        _ => listen,
    }
}

/// One `GET path` over HTTP/1.0 to `addr`: the status code and the body. The `Host` is the
/// address itself, which the loopback DNS-rebinding guard accepts. Bounded by `timeout` for the
/// connect and again for the answer; the answer is read up to 16 KiB.
pub(crate) async fn probe(addr: SocketAddr, path: &str, timeout: Duration) -> Result<(u16, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| format!("no connection within {timeout:?}"))?
        .map_err(|e| format!("cannot connect: {e}"))?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let mut answer = Vec::new();
    let exchange = async {
        stream.write_all(request.as_bytes()).await?;
        (&mut stream).take(16 * 1024).read_to_end(&mut answer).await
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("no answer within {timeout:?}"))?
        .map_err(|e| format!("reading the answer: {e}"))?;
    let text = String::from_utf8_lossy(&answer);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("not an HTTP answer: {:?}", head.lines().next().unwrap_or("")))?;
    Ok((code, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A private instance (the routes and tickets want `'static`; a test process can leak a few
    /// dozen bytes), so the counts are this test's alone.
    fn private() -> &'static ChannelHealth {
        Box::leak(Box::new(ChannelHealth::new()))
    }

    #[test]
    fn an_initiator_is_ready_only_with_a_session_and_for_the_grace_after_it() {
        let h = private();
        let now = now_unix();
        let err = h.readiness_at(now, false).unwrap_err();
        assert!(err.contains("no session established yet"), "{err}");
        let session = h.session_established();
        assert!(h.readiness_at(now, false).unwrap().contains("1 session(s) established"));
        drop(session);
        // Just ended: ready for the grace, then not.
        let why = h.readiness_at(now_unix(), false).unwrap();
        assert!(why.contains("between sessions"), "{why}");
        let err = h.readiness_at(now_unix() + READY_GRACE_SECS + 1, false).unwrap_err();
        assert!(err.contains("no session established for"), "{err}");
    }

    #[tokio::test]
    async fn an_accept_member_is_ready_while_parked_and_an_initiators_park_does_not_count() {
        let h = private();
        let (tx, rx) = tokio::sync::oneshot::channel::<ChannelJoinOutcome>();
        let park = tokio::spawn(h.parked(async move { rx.await.map_err(|_| "dropped") }));
        for _ in 0..200 {
            if h.parked.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let why = h.readiness_at(now_unix(), true).unwrap();
        assert!(why.contains("parked at the edge"), "{why}");
        assert!(h.readiness_at(now_unix(), false).is_err(), "an initiator waiting at the edge is not ready");
        // A park expiry: the member re-parks at once, the grace bridges the gap.
        tx.send(ChannelJoinOutcome::ParkExpired).unwrap();
        assert!(matches!(park.await.unwrap(), Ok(ChannelJoinOutcome::ParkExpired)));
        assert_eq!(h.parked.load(Ordering::SeqCst), 0);
        let why = h.readiness_at(now_unix(), true).unwrap();
        assert!(why.contains("between sessions"), "{why}");
        assert!(h.readiness_at(now_unix() + READY_GRACE_SECS + 1, true).is_err());
    }

    #[tokio::test]
    async fn a_refused_park_never_makes_a_member_ready() {
        let h = private();
        let refused = h
            .parked(async { Ok::<_, ()>(ChannelJoinOutcome::Refused { category: None }) })
            .await;
        assert!(matches!(refused, Ok(ChannelJoinOutcome::Refused { .. })));
        let failed = h.parked(async { Err::<ChannelJoinOutcome, _>("leg dropped") }).await;
        assert!(failed.is_err());
        let err = h.readiness_at(now_unix(), true).unwrap_err();
        assert!(err.contains("not parked yet"), "a refusal or a failed leg is no park: {err}");
    }

    #[test]
    fn a_stopping_member_is_unready_but_still_live() {
        let h = private();
        let _session = h.session_established();
        assert!(h.readiness_at(now_unix(), true).is_ok());
        h.set_stopping();
        assert_eq!(h.readiness_at(now_unix(), true).unwrap_err(), "shutting down");
        assert_eq!(h.liveness(), "ok (shutting down)");
    }

    #[tokio::test]
    async fn in_flight_counts_a_forward_members_streams_and_any_other_members_sessions() {
        let h = private();
        let session = h.session_established();
        assert_eq!(h.in_flight(false), 1);
        assert_eq!(h.in_flight(true), 0, "an idle forward session is nothing to wait for");
        // The ticket is taken when the future is BUILT, before anything polls it.
        let stream = h.forward_stream(std::future::pending::<()>());
        assert_eq!(h.in_flight(true), 1);
        drop(stream);
        assert_eq!(h.in_flight(true), 0, "a dropped (aborted) stream is gone");
        // A serve session counts from its pairing; once established it is not counted twice.
        let serve = h.serving(std::future::pending::<()>());
        assert_eq!(h.in_flight(false), 1);
        drop(session);
        assert_eq!(h.in_flight(false), 1, "still setting up or running");
        drop(serve);
        assert_eq!(h.in_flight(false), 0);
    }

    #[test]
    fn the_role_and_the_listen_address_parse_like_the_rest_of_the_config() {
        for accept in ["accept", " Accept ", "responder", "listen"] {
            assert!(accept_role(Some(accept)), "{accept}");
        }
        for not in [None, Some("initiate"), Some(""), Some("acceptor")] {
            assert!(!accept_role(not), "{not:?}");
        }
        assert_eq!(health_listen_from(None), Ok(None));
        assert_eq!(health_listen_from(Some("  ")), Ok(None), "compose passes an unset variable as empty");
        assert_eq!(health_listen_from(Some("127.0.0.1:9480")), Ok(Some("127.0.0.1:9480".parse().unwrap())));
        assert_eq!(health_listen_from(Some("[::]:9480")), Ok(Some("[::]:9480".parse().unwrap())));
        for bad in ["9480", "localhost:9480", "127.0.0.1", "127.0.0.1:x"] {
            let err = health_listen_from(Some(bad)).unwrap_err();
            assert!(err.contains(HEALTH_LISTEN_ENV), "{bad}: {err}");
        }
        assert_eq!(probe_target("0.0.0.0:9480".parse().unwrap()), "127.0.0.1:9480".parse().unwrap());
        assert_eq!(probe_target("[::]:9480".parse().unwrap()), "[::1]:9480".parse().unwrap());
        assert_eq!(probe_target("10.1.2.3:9480".parse().unwrap()), "10.1.2.3:9480".parse().unwrap());
    }

    async fn fetch(app: Router, uri: &str) -> (StatusCode, String) {
        let resp = app.oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let code = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (code, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn the_routes_answer_200_or_503_with_the_reason() {
        let h = private();
        let (code, body) = fetch(health_router(h, true), "/healthz").await;
        assert_eq!((code, body.as_str()), (StatusCode::OK, "ok\n"));
        let (code, body) = fetch(health_router(h, true), "/readyz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.starts_with("not ready: "), "{body}");
        let _session = h.session_established();
        let (code, body) = fetch(health_router(h, true), "/readyz").await;
        assert_eq!((code, body.as_str()), (StatusCode::OK, "ready: 1 session(s) established\n"));
        let (code, _) = fetch(health_router(h, true), "/metrics").await;
        assert_eq!(code, StatusCode::NOT_FOUND, "two routes, nothing else");
    }

    #[tokio::test]
    async fn the_probe_reads_a_real_listener_and_the_exit_status_follows_the_answer() {
        let h = private();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_health(listener, h, false));
        let (code, body) = probe(addr, "/readyz", PROBE_TIMEOUT).await.unwrap();
        assert_eq!(code, 503);
        assert_eq!(body, "not ready: no session established yet\n");
        let _session = h.session_established();
        assert_eq!(probe(addr, "/readyz", PROBE_TIMEOUT).await.unwrap(), (200, "ready: 1 session(s) established\n".to_string()));
        assert_eq!(probe(addr, "/healthz", PROBE_TIMEOUT).await.unwrap(), (200, "ok\n".to_string()));
        server.abort();
        // Nobody listening: an error, which the subcommand turns into status 1.
        let _ = server.await;
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gone = closed.local_addr().unwrap();
        drop(closed);
        assert!(probe(gone, "/healthz", PROBE_TIMEOUT).await.is_err());
    }
}
