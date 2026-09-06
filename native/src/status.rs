//! Live agent status (ct-agent#178): one process-wide [`AgentStatus`] the serve
//! loop updates at the same sites that emit `events`, read back by `GET /status`
//! (JSON), `GET /healthz` (200/503), `/metrics` (`ct_agent_registered`,
//! `ct_agent_reconnects_total`, `ct_agent_transport`) and `ct-agent status`.
//!
//! Only the connection-level facts live here; the process-level ones (uptime,
//! live tasks, the OIDC credential state, MASQUE drop counters) are gathered at
//! snapshot time from the modules that own them, through [`ProcessFacts`] -- so a
//! test builds its own [`AgentStatus`] and its own facts and never touches the
//! process-wide instance.

use std::sync::RwLock;

use ct_common::sync::RwLockExt;
use serde_json::{json, Value};

/// `/healthz` is `503` once the agent has seen no keepalive, ping, ACK or relayed
/// stream from the edge for this long -- three missed 30 s reprobe/ping cadences.
pub const HEALTHZ_MAX_SILENCE_SECS: u64 = 90;

/// The serving transport names `set_transport` accepts and `/metrics` labels.
pub const TRANSPORTS: [&str; 4] = ["quic", "masque", "tcp-fallback", "none"];

#[derive(Debug, Clone)]
struct StatusInner {
    transport: &'static str,
    registered_since: Option<u64>,
    last_seen: Option<u64>,
    reconnects: u64,
    last_error: Option<String>,
    update_state: String,
}

/// The connection-level status. The process-wide instance is [`STATUS`]; tests
/// build their own with [`AgentStatus::new`] (the same per-instance pattern as
/// `task_guard::LiveGauge`, ct-agent#180).
#[derive(Debug)]
pub struct AgentStatus {
    inner: RwLock<StatusInner>,
}

/// The process-wide status every setter below writes to.
pub static STATUS: AgentStatus = AgentStatus::new();

/// Everything `/status` reports that is NOT connection state, gathered by the
/// caller ([`ProcessFacts::live`] in production, literals in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFacts {
    pub uptime_secs: u64,
    pub session: String,
    pub conn: Option<u64>,
    pub tasks_live: u64,
    pub oidc_credential: &'static str,
    /// `(outbound, inbound)` datagrams dropped on a full MASQUE pump (#177).
    pub masque_dropped_datagrams: (u64, u64),
    pub events_ring_write_errors: u64,
}

impl ProcessFacts {
    /// The facts from the running process. Reads the stored login's expiry from
    /// disk (no refresh, no network) for `oidc_credential`.
    pub fn live() -> Self {
        Self {
            uptime_secs: crate::channel_run::process_uptime_secs(),
            session: crate::events::session_id().to_string(),
            conn: crate::events::current_conn_id(),
            tasks_live: crate::task_guard::tasks_live(),
            oidc_credential: crate::login::oidc_credential_state().as_str(),
            masque_dropped_datagrams: crate::masque::dropped_datagrams_total(),
            events_ring_write_errors: crate::events::ring_write_errors(),
        }
    }
}

impl AgentStatus {
    /// A fresh status: transport `none`, not registered, nothing seen, no
    /// reconnects, no error, update state `off` (rendered from the empty string,
    /// since a `const fn` cannot allocate the literal).
    pub const fn new() -> Self {
        Self {
            inner: RwLock::new(StatusInner {
                transport: "none",
                registered_since: None,
                last_seen: None,
                reconnects: 0,
                last_error: None,
                update_state: String::new(),
            }),
        }
    }

    /// Record the serving transport; returns the previous one so the caller can
    /// emit a `transport_switch` event when it actually changed.
    pub fn set_transport(&self, transport: &'static str) -> &'static str {
        let mut s = self.inner.write_safe();
        std::mem::replace(&mut s.transport, transport)
    }

    /// `Some(unix_secs)` once a registration is accepted, `None` when the
    /// connection it rode on is gone or the attempt failed.
    pub fn set_registered(&self, since: Option<u64>) {
        self.inner.write_safe().registered_since = since;
    }

    /// One more reconnect attempt after a failure or a dropped connection.
    pub fn note_reconnect(&self) {
        self.inner.write_safe().reconnects += 1;
    }

    /// The most recent failure, verbatim; cleared by nothing (an operator wants
    /// to see the last thing that went wrong even after recovery).
    pub fn set_last_error(&self, error: impl Into<String>) {
        self.inner.write_safe().last_error = Some(error.into());
    }

    /// The edge was observed alive just now (a keepalive, ping, ACK, relayed
    /// stream, or an accepted registration).
    pub fn note_keepalive(&self) {
        self.note_keepalive_at(now_unix());
    }

    /// [`AgentStatus::note_keepalive`] with an injected clock.
    pub fn note_keepalive_at(&self, now: u64) {
        self.inner.write_safe().last_seen = Some(now);
    }

    /// What the auto-update loop is doing (`off`, `checking`, `up-to-date (v)`,
    /// `downloading v`, `applied v`, `check failed: ..`).
    pub fn set_update_state(&self, state: impl Into<String>) {
        self.inner.write_safe().update_state = state.into();
    }

    /// The current transport name.
    pub fn transport(&self) -> &'static str {
        self.inner.read_safe().transport
    }

    /// Whether a registration is currently accepted.
    pub fn registered(&self) -> bool {
        self.inner.read_safe().registered_since.is_some()
    }

    /// Reconnect attempts so far.
    pub fn reconnects(&self) -> u64 {
        self.inner.read_safe().reconnects
    }

    /// Seconds since the last liveness observation, `None` before the first.
    pub fn last_seen_secs_ago_at(&self, now: u64) -> Option<u64> {
        self.inner.read_safe().last_seen.map(|t| now.saturating_sub(t))
    }

    /// The `/status` document at `now` with the given process facts.
    pub fn snapshot_at(&self, now: u64, facts: &ProcessFacts) -> Value {
        let s = self.inner.read_safe().clone();
        let update_state = if s.update_state.is_empty() { "off" } else { s.update_state.as_str() };
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "session": facts.session,
            "conn": facts.conn,
            "uptime_secs": facts.uptime_secs,
            "transport": s.transport,
            "registered": s.registered_since.is_some(),
            "registered_since": s.registered_since,
            "last_seen_secs_ago": s.last_seen.map(|t| now.saturating_sub(t)),
            "reconnects": s.reconnects,
            "last_error": s.last_error,
            "tasks_live": facts.tasks_live,
            "update_state": update_state,
            "oidc_credential": facts.oidc_credential,
            "masque_dropped_datagrams": {
                "outbound": facts.masque_dropped_datagrams.0,
                "inbound": facts.masque_dropped_datagrams.1,
            },
            "events_ring_write_errors": facts.events_ring_write_errors,
            "healthy": self.healthz_at(now).is_ok(),
        })
    }

    /// `Ok` when registered and the edge was seen within
    /// [`HEALTHZ_MAX_SILENCE_SECS`]; `Err(reason)` otherwise.
    pub fn healthz_at(&self, now: u64) -> Result<(), String> {
        let s = self.inner.read_safe();
        if s.registered_since.is_none() {
            return Err(match &s.last_error {
                Some(e) => format!("not registered with an edge (transport={}, last error: {e})", s.transport),
                None => format!("not registered with an edge (transport={})", s.transport),
            });
        }
        match s.last_seen {
            None => Err("registered but the edge has not been observed alive yet".to_string()),
            Some(seen) => {
                let silence = now.saturating_sub(seen);
                if silence < HEALTHZ_MAX_SILENCE_SECS {
                    Ok(())
                } else {
                    Err(format!(
                        "registered over {} but nothing heard from the edge for {silence}s \
                         (limit {HEALTHZ_MAX_SILENCE_SECS}s)",
                        s.transport
                    ))
                }
            }
        }
    }

    /// `ct_agent_registered`, `ct_agent_reconnects_total` and
    /// `ct_agent_transport{transport}` in the Prometheus text exposition format.
    /// All four transport labels are rendered (the current one `1`, the rest
    /// `0`) so the series set a scraper sees is stable.
    pub fn render_prometheus(&self) -> String {
        let s = self.inner.read_safe().clone();
        let mut text = format!(
            "# HELP ct_agent_registered Whether a registration with the edge is currently accepted \
             (ct-agent#178).\n# TYPE ct_agent_registered gauge\nct_agent_registered {}\n\
             # HELP ct_agent_reconnects_total Reconnect attempts after a failed registration or a dropped \
             edge connection (ct-agent#178).\n# TYPE ct_agent_reconnects_total counter\n\
             ct_agent_reconnects_total {}\n\
             # HELP ct_agent_transport The transport the agent is serving over (1 for the current one).\n\
             # TYPE ct_agent_transport gauge\n",
            u8::from(s.registered_since.is_some()),
            s.reconnects
        );
        for t in TRANSPORTS {
            text.push_str(&format!(
                "ct_agent_transport{{transport=\"{t}\"}} {}\n",
                u8::from(t == s.transport)
            ));
        }
        text
    }
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::new()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- process-wide convenience wrappers ------------------------------------------------

/// [`AgentStatus::set_transport`] on [`STATUS`].
pub fn set_transport(transport: &'static str) -> &'static str {
    STATUS.set_transport(transport)
}

/// [`AgentStatus::set_registered`] on [`STATUS`].
pub fn set_registered(since: Option<u64>) {
    STATUS.set_registered(since)
}

/// `set_registered(Some(now))` on [`STATUS`], plus a keepalive note: an accepted
/// registration is the strongest liveness signal there is.
pub fn set_registered_now() {
    let now = now_unix();
    STATUS.set_registered(Some(now));
    STATUS.note_keepalive_at(now);
}

/// [`AgentStatus::note_reconnect`] on [`STATUS`].
pub fn note_reconnect() {
    STATUS.note_reconnect()
}

/// [`AgentStatus::set_last_error`] on [`STATUS`].
pub fn set_last_error(error: impl Into<String>) {
    STATUS.set_last_error(error)
}

/// [`AgentStatus::note_keepalive`] on [`STATUS`].
pub fn note_keepalive() {
    STATUS.note_keepalive()
}

/// [`AgentStatus::set_update_state`] on [`STATUS`].
pub fn set_update_state(state: impl Into<String>) {
    STATUS.set_update_state(state)
}

/// The `/status` document for the running process.
pub fn snapshot() -> Value {
    STATUS.snapshot_at(now_unix(), &ProcessFacts::live())
}

/// The `/healthz` verdict for the running process.
pub fn healthz() -> Result<(), String> {
    STATUS.healthz_at(now_unix())
}

/// [`AgentStatus::render_prometheus`] on [`STATUS`].
pub fn render_prometheus() -> String {
    STATUS.render_prometheus()
}

// ---- `ct-agent status` ---------------------------------------------------------------

/// The URL `ct-agent status` fetches for a metrics listener at `listen`
/// (`CT_AGENT_METRICS_LISTEN`'s value, e.g. `127.0.0.1:9100`).
pub fn status_url(listen: &str) -> String {
    format!("http://{}/status", listen.trim())
}

/// What `ct-agent status` prints when no metrics listener is configured: the
/// last ring lines (oldest first) and a note on how to get the live view.
pub fn offline_status_text(ring_path: Option<&std::path::Path>, lines: &[String]) -> String {
    let mut out = String::new();
    match ring_path {
        Some(p) => out.push_str(&format!("ct-agent: last {} event(s) from {}:\n", lines.len(), p.display())),
        None => out.push_str(
            "ct-agent: no event ring: neither CT_AGENT_STATE_DIR nor HOME is set, so no events were recorded\n",
        ),
    }
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(
        "ct-agent: live status needs the metrics listener: start the agent with CT_AGENT_METRICS_LISTEN=<addr:port> \
         and run `ct-agent status` with the same variable set (it then fetches http://<addr:port>/status)\n",
    );
    out
}

/// How many ring lines `ct-agent status` shows offline.
pub const OFFLINE_STATUS_LINES: usize = 20;

/// Fetch `/status` from a running agent's metrics listener (5 s timeout) and
/// pretty-print it, or -- with no `CT_AGENT_METRICS_LISTEN` -- print the last
/// [`OFFLINE_STATUS_LINES`] ring lines from the state dir.
pub async fn run_status_command() -> Result<(), String> {
    let listen = std::env::var("CT_AGENT_METRICS_LISTEN").ok().filter(|s| !s.trim().is_empty());
    let Some(listen) = listen else {
        let lines = crate::events::recent(OFFLINE_STATUS_LINES);
        print!("{}", offline_status_text(crate::events::ring_path().as_deref(), &lines));
        return Ok(());
    };
    let url = status_url(&listen);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp = client.get(&url).send().await.map_err(|e| format!("GET {url}: {e}"))?;
    let http_status = resp.status();
    let body = resp.text().await.map_err(|e| format!("GET {url}: reading the body: {e}"))?;
    if !http_status.is_success() {
        return Err(format!("GET {url}: HTTP {http_status}: {}", body.trim()));
    }
    let pretty = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| body.trim_end().to_string());
    println!("{pretty}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> ProcessFacts {
        ProcessFacts {
            uptime_secs: 42,
            session: "0123456789abcdef".to_string(),
            conn: Some(3),
            tasks_live: 2,
            oidc_credential: "stored",
            masque_dropped_datagrams: (1, 2),
            events_ring_write_errors: 0,
        }
    }

    #[test]
    fn snapshot_has_every_documented_key_and_defaults() {
        let st = AgentStatus::new();
        let v = st.snapshot_at(1_000, &facts());
        for key in [
            "version",
            "session",
            "conn",
            "uptime_secs",
            "transport",
            "registered",
            "registered_since",
            "last_seen_secs_ago",
            "reconnects",
            "last_error",
            "tasks_live",
            "update_state",
            "oidc_credential",
            "masque_dropped_datagrams",
            "events_ring_write_errors",
            "healthy",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}: {v}");
        }
        assert_eq!(v["version"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(v["transport"], json!("none"));
        assert_eq!(v["registered"], json!(false));
        assert_eq!(v["registered_since"], Value::Null);
        assert_eq!(v["last_seen_secs_ago"], Value::Null);
        assert_eq!(v["reconnects"], json!(0));
        assert_eq!(v["last_error"], Value::Null);
        assert_eq!(v["update_state"], json!("off"));
        assert_eq!(v["uptime_secs"], json!(42));
        assert_eq!(v["tasks_live"], json!(2));
        assert_eq!(v["oidc_credential"], json!("stored"));
        assert_eq!(v["masque_dropped_datagrams"], json!({"outbound": 1, "inbound": 2}));
        assert_eq!(v["healthy"], json!(false));
    }

    #[test]
    fn snapshot_reflects_the_setters() {
        let st = AgentStatus::new();
        assert_eq!(st.set_transport("quic"), "none");
        assert_eq!(st.set_transport("tcp-fallback"), "quic");
        st.set_registered(Some(900));
        st.note_keepalive_at(980);
        st.note_reconnect();
        st.note_reconnect();
        st.set_last_error("registration failed (NO)");
        st.set_update_state("up-to-date (0.7.27)");
        let v = st.snapshot_at(1_000, &facts());
        assert_eq!(v["transport"], json!("tcp-fallback"));
        assert_eq!(v["registered"], json!(true));
        assert_eq!(v["registered_since"], json!(900));
        assert_eq!(v["last_seen_secs_ago"], json!(20));
        assert_eq!(v["reconnects"], json!(2));
        assert_eq!(v["last_error"], json!("registration failed (NO)"));
        assert_eq!(v["update_state"], json!("up-to-date (0.7.27)"));
        assert_eq!(v["healthy"], json!(true));
    }

    #[test]
    fn healthz_is_err_until_registered_and_recently_seen() {
        let st = AgentStatus::new();
        let err = st.healthz_at(1_000).unwrap_err();
        assert!(err.contains("not registered"), "{err}");
        st.set_last_error("edge dial failed: timeout");
        let err = st.healthz_at(1_000).unwrap_err();
        assert!(err.contains("edge dial failed: timeout"), "the last error is named: {err}");

        st.set_registered(Some(1_000));
        let err = st.healthz_at(1_000).unwrap_err();
        assert!(err.contains("not been observed"), "{err}");

        st.note_keepalive_at(1_000);
        assert_eq!(st.healthz_at(1_000), Ok(()));
        assert_eq!(st.healthz_at(1_000 + HEALTHZ_MAX_SILENCE_SECS - 1), Ok(()));
        let err = st.healthz_at(1_000 + HEALTHZ_MAX_SILENCE_SECS).unwrap_err();
        assert!(err.contains("nothing heard from the edge for 90s"), "{err}");

        st.set_registered(None);
        assert!(st.healthz_at(1_001).is_err(), "a dropped registration is unhealthy even if recently seen");
    }

    #[test]
    fn prometheus_block_renders_registered_reconnects_and_all_transport_labels() {
        let st = AgentStatus::new();
        st.set_transport("masque");
        st.set_registered(Some(1));
        st.note_reconnect();
        let text = st.render_prometheus();
        assert!(text.contains("# TYPE ct_agent_registered gauge\nct_agent_registered 1\n"));
        assert!(text.contains("# TYPE ct_agent_reconnects_total counter\nct_agent_reconnects_total 1\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"masque\"} 1\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"quic\"} 0\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"tcp-fallback\"} 0\n"));
        assert!(text.contains("\nct_agent_transport{transport=\"none\"} 0\n"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn status_url_and_offline_text() {
        assert_eq!(status_url(" 127.0.0.1:9100 "), "http://127.0.0.1:9100/status");
        let lines = vec!["{\"kind\":\"registered\"}".to_string()];
        let text = offline_status_text(Some(std::path::Path::new("/state/events.jsonl")), &lines);
        assert!(text.starts_with("ct-agent: last 1 event(s) from /state/events.jsonl:\n{\"kind\":\"registered\"}\n"));
        assert!(text.contains("CT_AGENT_METRICS_LISTEN"));
        let text = offline_status_text(None, &[]);
        assert!(text.contains("no event ring"));
    }
}
