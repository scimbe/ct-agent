//! Agent observability endpoint (M14.2, ADR-0016; ct-agent#178).
//!
//! Serves the Agent's [`TunnelMetrics`] over HTTP in the Prometheus text
//! exposition format so a scraper (compose target) can read `/metrics`. The
//! metrics themselves are populated on the data path (M14.1b); this module only
//! exposes the already-shared `Arc<TunnelMetrics>`.
//!
//! ct-agent#178 adds three operator routes on the same listener
//! (`CT_AGENT_METRICS_LISTEN`):
//!
//! * `GET /status` -- the [`crate::status`] snapshot as JSON (what
//!   `ct-agent status` prints).
//! * `GET /healthz` -- `200 ok` when registered and the edge was heard from
//!   within `HEALTHZ_MAX_SILENCE_SECS`, else `503` with the reason as the body;
//!   the shape a container/systemd/load-balancer probe wants.
//! * `GET /events?n=100` -- the last `n` (1..=1000) lines of the
//!   [`crate::events`] ring as `application/x-ndjson`.
//!
//! Every route reads through an [`ObserveState`] so a test can serve a private
//! status/counter/ring instance instead of the process-wide ones.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use ct_common::metrics::TunnelMetrics;

use crate::events::{EventCounters, Ring, EVENT_COUNTS};
use crate::status::{AgentStatus, ProcessFacts, STATUS};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Default and upper bound for `GET /events?n=`.
pub const EVENTS_DEFAULT_N: usize = 100;
pub const EVENTS_MAX_N: usize = 1000;

/// What the routes read. [`ObserveState::live`] wires the process-wide
/// instances; tests build one from their own.
#[derive(Clone)]
pub struct ObserveState {
    metrics: Arc<TunnelMetrics>,
    status: &'static AgentStatus,
    events: &'static EventCounters,
    /// `None` = the process-wide ring (resolved from the environment).
    ring: Option<Arc<Ring>>,
    /// `None` = [`ProcessFacts::live`] at request time.
    facts: Option<ProcessFacts>,
}

impl ObserveState {
    /// The production wiring: `metrics` plus the process-wide status, counters
    /// and ring.
    pub fn live(metrics: Arc<TunnelMetrics>) -> Self {
        Self { metrics, status: &STATUS, events: &EVENT_COUNTS, ring: None, facts: None }
    }

    /// Per-instance wiring (tests): a private status, counters, ring and facts.
    pub fn with_parts(
        metrics: Arc<TunnelMetrics>,
        status: &'static AgentStatus,
        events: &'static EventCounters,
        ring: Arc<Ring>,
        facts: ProcessFacts,
    ) -> Self {
        Self { metrics, status, events, ring: Some(ring), facts: Some(facts) }
    }

    fn facts(&self) -> ProcessFacts {
        self.facts.clone().unwrap_or_else(ProcessFacts::live)
    }

    fn recent_events(&self, n: usize) -> Vec<String> {
        match &self.ring {
            Some(r) => r.recent(n),
            None => crate::events::recent(n),
        }
    }
}

/// Build the metrics router over the process-wide status/events: `GET /metrics`
/// renders the current counters, plus `/status`, `/healthz` and `/events`.
pub fn metrics_router(metrics: Arc<TunnelMetrics>) -> Router {
    observe_router(ObserveState::live(metrics))
}

/// [`metrics_router`] over an explicit [`ObserveState`].
pub fn observe_router(state: ObserveState) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .route("/status", get(status_json))
        .route("/healthz", get(healthz))
        .route("/events", get(events_ndjson))
        .with_state(state)
}

/// Render the counters in the Prometheus text exposition format, with the
/// content type Prometheus expects (`text/plain; version=0.0.4`). The shared
/// [`TunnelMetrics`] block is followed by this crate's own process-wide series:
/// the status gauges and event counters (ct-agent#178), the MASQUE pump drop
/// counter (ct-agent#177) and the live-task gauge (ct-agent#180).
async fn render(State(state): State<ObserveState>) -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], render_text_with(&state.metrics, state.status, state.events))
}

/// The full `/metrics` body over the process-wide status and event counters
/// (the handler goes through [`render_text_with`]; this shape is what the tail-order test pins).
#[cfg(test)]
fn render_text(metrics: &TunnelMetrics) -> String {
    render_text_with(metrics, &STATUS, &EVENT_COUNTS)
}

/// The full `/metrics` body: ct_common's tunnel counters, then ct-agent's own
/// series. Order: status gauges, event counters, MASQUE drops, live tasks -- the
/// last two keep their pre-#178 tail position (a test pins it).
fn render_text_with(metrics: &TunnelMetrics, status: &AgentStatus, events: &EventCounters) -> String {
    let mut text = metrics.render_prometheus();
    text.push_str(&status.render_prometheus());
    text.push_str(&events.render_prometheus());
    text.push_str(&crate::masque::render_dropped_datagrams_prometheus());
    text.push_str(&crate::task_guard::render_prometheus());
    text
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn status_json(State(state): State<ObserveState>) -> impl IntoResponse {
    let body = state.status.snapshot_at(now_unix(), &state.facts()).to_string();
    ([(CONTENT_TYPE, "application/json")], body)
}

async fn healthz(State(state): State<ObserveState>) -> impl IntoResponse {
    match state.status.healthz_at(now_unix()) {
        Ok(()) => (StatusCode::OK, "ok".to_string()),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, reason),
    }
}

/// `n` from a raw query string like `n=50&x=y`: default [`EVENTS_DEFAULT_N`],
/// clamped to `1..=EVENTS_MAX_N`; an unparsable value is the default.
fn events_n(query: Option<&str>) -> usize {
    query
        .into_iter()
        .flat_map(|q| q.split('&'))
        .find_map(|kv| kv.strip_prefix("n=").and_then(|v| v.trim().parse::<usize>().ok()))
        .unwrap_or(EVENTS_DEFAULT_N)
        .clamp(1, EVENTS_MAX_N)
}

async fn events_ndjson(State(state): State<ObserveState>, RawQuery(query): RawQuery) -> impl IntoResponse {
    let lines = state.recent_events(events_n(query.as_deref()));
    let mut body = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for l in lines {
        body.push_str(&l);
        body.push('\n');
    }
    ([(CONTENT_TYPE, "application/x-ndjson")], body)
}

/// Bind `listen` and serve the metrics endpoint until the process exits.
pub async fn serve_metrics(listen: SocketAddr, metrics: Arc<TunnelMetrics>) -> Result<(), BoxError> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    serve_metrics_on(listener, metrics).await
}

/// Serve the metrics scrape on an ALREADY-bound listener. Lets a caller (e.g. a test) bind the port
/// itself and keep the binding, avoiding the bind-`:0` → drop → re-bind TOCTOU race that made the
/// scrape test flaky under parallel load.
pub async fn serve_metrics_on(
    listener: tokio::net::TcpListener,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    axum::serve(listener, metrics_router(metrics)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn metrics_endpoint_renders_current_counters() {
        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.inc();
        metrics.bytes_to_origin.add(2048);
        metrics.observe_handshake(std::time::Duration::from_millis(9));

        let app = metrics_router(Arc::clone(&metrics));
        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/plain"), "Prometheus content type, got {ct}");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE ct_tunnels_opened_total counter"), "exposition header present");
        assert!(text.contains("\nct_tunnels_opened_total 1\n"), "counter value exposed");
        assert!(text.contains("\nct_bytes_to_origin_total 2048\n"));
        assert!(text.contains("\nct_handshake_millis_total 9\n"));
        // ct-agent#177: the MASQUE drop counter rides on the same scrape. The values
        // are process-wide statics other tests may have bumped, so only the series'
        // presence and shape are asserted here.
        assert!(text.contains("# TYPE ct_agent_masque_dropped_datagrams_total counter"), "masque drop counter header");
        assert!(text.contains("\nct_agent_masque_dropped_datagrams_total{direction=\"outbound\"} "));
        assert!(text.contains("\nct_agent_masque_dropped_datagrams_total{direction=\"inbound\"} "));
        // ct-agent#180: the live-task gauge follows the masque block. Same caveat:
        // other tests spawn guarded tasks in parallel, so only the shape is pinned.
        assert!(text.contains("# TYPE ct_agent_tasks_live gauge"), "live-task gauge header");
        assert!(text.contains("\nct_agent_tasks_live "), "live-task gauge value line");
        // ct-agent#178: the status gauges and the per-kind event counters. Process-wide
        // statics again, so shape only.
        assert!(text.contains("# TYPE ct_agent_registered gauge\nct_agent_registered "), "registered gauge");
        assert!(text.contains("# TYPE ct_agent_reconnects_total counter\nct_agent_reconnects_total "));
        assert!(text.contains("\nct_agent_transport{transport=\"quic\"} "));
        assert!(text.contains("\nct_agent_transport{transport=\"none\"} "));
        assert!(text.contains("# TYPE ct_agent_events_total counter\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"registered\"} "));
        assert!(text.contains("\nct_agent_events_total{kind=\"credential_degraded\"} "));
    }

    #[test]
    fn render_text_ends_with_the_masque_drop_series_then_the_task_gauge() {
        // The masque tests bump the same process-wide statics in parallel, so the
        // rendered values are bracketed by a before/after read rather than pinned.
        let before = crate::masque::dropped_datagrams_total();
        let text = render_text(&TunnelMetrics::new());
        let after = crate::masque::dropped_datagrams_total();
        // HELP/TYPE comment lines precede each series; walk only value lines backwards.
        let mut tail = text.lines().rev().filter(|l| !l.starts_with('#'));
        // ct-agent#180: the very last series is the live-task gauge (a parseable u64).
        let gauge = tail.next().unwrap();
        let _live: u64 = gauge
            .strip_prefix("ct_agent_tasks_live ")
            .unwrap_or_else(|| panic!("unexpected last line {gauge:?}"))
            .parse()
            .unwrap();
        let inbound = tail.next().unwrap();
        let outbound = tail.next().unwrap();
        let value = |line: &str, prefix: &str| -> u64 {
            line.strip_prefix(prefix).unwrap_or_else(|| panic!("unexpected line {line:?}")).parse().unwrap()
        };
        let out = value(outbound, "ct_agent_masque_dropped_datagrams_total{direction=\"outbound\"} ");
        let inb = value(inbound, "ct_agent_masque_dropped_datagrams_total{direction=\"inbound\"} ");
        assert!(before.0 <= out && out <= after.0, "outbound {out} within [{}, {}]", before.0, after.0);
        assert!(before.1 <= inb && inb <= after.1, "inbound {inb} within [{}, {}]", before.1, after.1);
        assert!(text.ends_with('\n'));
    }

    #[tokio::test]
    async fn serve_metrics_is_scrapable_over_a_real_socket() {
        // Bind on an ephemeral port and scrape it over TCP with a raw HTTP/1.0
        // request — proves the endpoint serves off a real listener (no reqwest
        // dependency needed for a bare GET).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.add(3);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = metrics_router(Arc::clone(&metrics));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        sock.read_to_string(&mut resp).await.unwrap();

        assert!(resp.starts_with("HTTP/1.0 200") || resp.starts_with("HTTP/1.1 200"), "200 OK: {resp:.40}");
        assert!(resp.contains("ct_tunnels_opened_total 3"), "scraped counter value");
    }

    #[tokio::test]
    async fn serve_metrics_binds_its_own_listener_and_serves() {
        // Exercises serve_metrics() itself (the bind + serve wrapper), not just
        // metrics_router: reserve an ephemeral port, hand it to serve_metrics,
        // scrape once, then stop the (otherwise endless) server.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.add(5);
        // Bind the listener ONCE and hand it to serve_metrics_on — no drop-then-rebind, so there's no
        // TOCTOU window for another process to grab the port (the source of this test's flakiness).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let m = Arc::clone(&metrics);
        let server = tokio::spawn(async move { serve_metrics_on(listener, m).await });

        // serve_metrics binds asynchronously; retry briefly until it answers.
        let mut resp = String::new();
        for _ in 0..50 {
            if let Ok(mut sock) = tokio::net::TcpStream::connect(addr).await {
                sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n")
                    .await
                    .unwrap();
                let _ = sock.read_to_string(&mut resp).await;
                if !resp.is_empty() {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        server.abort();
        assert!(
            resp.contains("ct_tunnels_opened_total 5"),
            "serve_metrics served the scrape: {resp:.60}"
        );
    }

    // ---- ct-agent#178: /status, /healthz, /events over a PRIVATE state ----------------

    /// A per-test [`ObserveState`]: leaked status/counters (the router wants
    /// `'static`, and a test process is fine with a few dozen bytes leaking) plus
    /// a ring in a tempdir the test keeps alive.
    struct Private {
        state: ObserveState,
        status: &'static AgentStatus,
        events: &'static EventCounters,
        ring: Arc<Ring>,
        _dir: tempfile::TempDir,
    }

    fn private_state() -> Private {
        let dir = tempfile::tempdir().unwrap();
        let status: &'static AgentStatus = Box::leak(Box::new(AgentStatus::new()));
        let events: &'static EventCounters = Box::leak(Box::new(EventCounters::new()));
        let ring = Arc::new(Ring::new(dir.path()));
        let facts = ProcessFacts {
            uptime_secs: 7,
            session: "feedfacefeedface".to_string(),
            conn: Some(2),
            tasks_live: 0,
            oidc_credential: "none",
            masque_dropped_datagrams: (0, 0),
            events_ring_write_errors: 0,
        };
        let state = ObserveState::with_parts(Arc::new(TunnelMetrics::new()), status, events, Arc::clone(&ring), facts);
        Private { state, status, events, ring, _dir: dir }
    }

    async fn fetch(app: Router, uri: &str) -> (StatusCode, String, String) {
        let resp = app.oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, ct, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn status_route_serves_the_json_snapshot_with_the_version() {
        let p = private_state();
        p.status.set_transport("quic");
        let (code, ct, body) = fetch(observe_router(p.state.clone()), "/status").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["version"], serde_json::json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(v["transport"], serde_json::json!("quic"));
        assert_eq!(v["session"], serde_json::json!("feedfacefeedface"));
        assert_eq!(v["uptime_secs"], serde_json::json!(7));
        assert_eq!(v["registered"], serde_json::json!(false));
        assert_eq!(v["oidc_credential"], serde_json::json!("none"));
    }

    #[tokio::test]
    async fn healthz_is_503_before_registration_and_200_after_registered_and_seen() {
        let p = private_state();
        let (code, _, body) = fetch(observe_router(p.state.clone()), "/healthz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("not registered"), "{body}");

        p.status.set_registered(Some(now_unix()));
        p.status.note_keepalive();
        let (code, _, body) = fetch(observe_router(p.state.clone()), "/healthz").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "ok");

        // A registration whose edge went silent for longer than the limit is unhealthy again.
        p.status.note_keepalive_at(now_unix().saturating_sub(crate::status::HEALTHZ_MAX_SILENCE_SECS + 5));
        let (code, _, body) = fetch(observe_router(p.state.clone()), "/healthz").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("nothing heard"), "{body}");
    }

    #[tokio::test]
    async fn events_route_serves_the_last_n_ring_lines_as_ndjson() {
        let p = private_state();
        let (code, ct, body) = fetch(observe_router(p.state.clone()), "/events").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(ct, "application/x-ndjson");
        assert_eq!(body, "", "empty ring -> empty body");

        for i in 0..5 {
            p.ring.append(&format!("{{\"kind\":\"registered\",\"n\":{i}}}"));
        }
        let (_, _, body) = fetch(observe_router(p.state.clone()), "/events?n=2").await;
        assert_eq!(body, "{\"kind\":\"registered\",\"n\":3}\n{\"kind\":\"registered\",\"n\":4}\n");
        let (_, _, body) = fetch(observe_router(p.state.clone()), "/events").await;
        assert_eq!(body.lines().count(), 5, "default n covers everything here");
        // Out-of-range / garbage n is clamped or defaulted, never an error.
        let (code, _, body) = fetch(observe_router(p.state.clone()), "/events?n=0").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.lines().count(), 1, "n=0 clamps to 1");
        let (code, _, body) = fetch(observe_router(p.state.clone()), "/events?n=zebra&x=1").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.lines().count(), 5);
    }

    #[test]
    fn events_n_parses_defaults_and_clamps() {
        assert_eq!(events_n(None), EVENTS_DEFAULT_N);
        assert_eq!(events_n(Some("n=7")), 7);
        assert_eq!(events_n(Some("a=b&n=7")), 7);
        assert_eq!(events_n(Some("n=0")), 1);
        assert_eq!(events_n(Some("n=99999")), EVENTS_MAX_N);
        assert_eq!(events_n(Some("n=")), EVENTS_DEFAULT_N);
        assert_eq!(events_n(Some("n=-1")), EVENTS_DEFAULT_N);
    }

    #[tokio::test]
    async fn metrics_route_carries_the_private_status_and_event_series() {
        let p = private_state();
        p.status.set_transport("tcp-fallback");
        p.status.set_registered(Some(1));
        p.status.note_reconnect();
        p.status.note_reconnect();
        p.status.note_reconnect();
        p.events.bump(crate::events::REGISTERED);
        p.events.bump(crate::events::DISCONNECTED);
        p.events.bump(crate::events::DISCONNECTED);
        let (code, _, text) = fetch(observe_router(p.state.clone()), "/metrics").await;
        assert_eq!(code, StatusCode::OK);
        assert!(text.contains("\nct_agent_registered 1\n"), "{text}");
        assert!(text.contains("\nct_agent_reconnects_total 3\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"tcp-fallback\"} 1\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"quic\"} 0\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"registered\"} 1\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"disconnected\"} 2\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"update_applied\"} 0\n"));
        // The pre-#178 tail order is unchanged: masque drops, then the live-task gauge last.
        let last_value_line = text.lines().rev().find(|l| !l.starts_with('#')).unwrap();
        assert!(last_value_line.starts_with("ct_agent_tasks_live "), "{last_value_line}");
    }
}
