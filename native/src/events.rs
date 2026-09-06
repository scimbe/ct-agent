//! Structured operator events (ct-agent#178).
//!
//! The agent logs a few hundred distinct `eprintln!` lines; the ones an operator
//! actually pages on (registered / dropped / fell back / refused / updated) are
//! now ALSO emitted as one structured [`Event`] each, through [`emit`]. Every
//! event goes to two places:
//!
//! * **stderr**, next to the existing human line (which stays): one compact
//!   `ct-agent event: <kind> k=v k=v` line by default, or the whole event as one
//!   JSON object when `CT_AGENT_LOG_FORMAT=json`.
//! * **the ring file** `<state_dir>/events.jsonl`, always as JSON lines, so a
//!   `ct-agent status` run after the fact (or `GET /events` while it runs) can
//!   show the last few hundred events without a log aggregator. The state dir
//!   resolves exactly like `login.rs`'s token store: `CT_AGENT_STATE_DIR`, else
//!   `$HOME/.ct-agent`; with neither there is no file and events only reach
//!   stderr. The ring is capped at [`EVENTS_RING_MAX_BYTES`]: when the current
//!   file would exceed it, it is renamed to `events.jsonl.1` (replacing the
//!   previous `.1`) and a fresh file starts, so the disk cost is bounded at
//!   ~2 MiB forever. A ring write that fails never fails the caller -- it is
//!   counted and logged once.
//!
//! Every event carries `ts` (unix seconds), `session` (a random 16-hex id minted
//! once per process, so lines from one process can be grouped after a restart),
//! `conn` (the per-connection counter, see [`next_conn_id`] -- absent before the
//! first registration attempt) and `kind` (one of the taxonomy constants below),
//! plus the kind's own fields. `serde_json` is the only dependency; `tracing` is
//! deliberately not pulled in for this.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ct_common::sync::MutexExt;
use serde_json::{Map, Value};

/// Environment variable selecting the stderr rendering: `json` for one JSON
/// object per event line, anything else (or unset) for the compact `k=v` line.
pub const LOG_FORMAT_ENV: &str = "CT_AGENT_LOG_FORMAT";

/// The ring file's name inside the state dir; the rotated predecessor is
/// `events.jsonl.1`.
pub const EVENTS_RING_FILE: &str = "events.jsonl";

/// Cap on one ring file; exceeding it rotates (see the module doc). 1 MiB.
pub const EVENTS_RING_MAX_BYTES: u64 = 1024 * 1024;

// ---- taxonomy ---------------------------------------------------------------

/// `{edge, transport}`: a registration with the edge was accepted.
pub const REGISTERED: &str = "registered";
/// `{error}`: a dial or registration attempt failed; the loop will retry.
pub const REGISTRATION_FAILED: &str = "registration_failed";
/// `{reason}`: an established edge connection ended.
pub const DISCONNECTED: &str = "disconnected";
/// `{from, to}`: the serving transport changed (`quic`, `masque`, `tcp-fallback`, `none`).
pub const TRANSPORT_SWITCH: &str = "transport_switch";
/// `{}`: every TLS-TCP fallback worker exhausted its reconnect budget.
pub const FALLBACK_EXHAUSTED: &str = "fallback_exhausted";
/// `{reason}`: a direct-connect client was refused at the routing-token check (#45).
pub const DIRECT_REFUSED: &str = "direct_refused";
/// `{state: open|close, peer}`: an A2A channel session started or ended.
pub const CHANNEL_SESSION: &str = "channel_session";
/// `{tool, ok}`: a `bridge/*` tool was invoked (refusals count as `ok=false`).
pub const BRIDGE_CALL: &str = "bridge_call";
/// `{status}`: a manifest activation finished (`ok`, `rejected`, `failed`).
pub const MANIFEST_INSTALL: &str = "manifest_install";
/// `{result}`: a release check ran (`up-to-date`, `available: <v>`, `error: ..`).
pub const UPDATE_CHECK: &str = "update_check";
/// `{version}`: a downloaded release replaced the on-disk binary.
pub const UPDATE_APPLIED: &str = "update_applied";
/// `{}`: the stored OIDC credential is expired and cannot be refreshed (#181).
pub const CREDENTIAL_DEGRADED: &str = "credential_degraded";

/// Every event kind, in the order `/metrics` renders `ct_agent_events_total{kind}`.
pub const KINDS: [&str; 12] = [
    REGISTERED,
    REGISTRATION_FAILED,
    DISCONNECTED,
    TRANSPORT_SWITCH,
    FALLBACK_EXHAUSTED,
    DIRECT_REFUSED,
    CHANNEL_SESSION,
    BRIDGE_CALL,
    MANIFEST_INSTALL,
    UPDATE_CHECK,
    UPDATE_APPLIED,
    CREDENTIAL_DEGRADED,
];

// ---- the event ----------------------------------------------------------------

/// One structured event. Built by [`emit`]; public so tests (and `format_line`)
/// can construct one without touching the process-wide sinks.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Unix seconds at emission.
    pub ts: u64,
    /// The process session id ([`session_id`]).
    pub session: String,
    /// The per-connection counter at emission ([`current_conn_id`]).
    pub conn: Option<u64>,
    /// One of the taxonomy constants (or a caller-supplied literal).
    pub kind: &'static str,
    /// The kind's own fields. Sorted by key (serde_json's default map), so the
    /// rendering is deterministic.
    pub fields: Map<String, Value>,
}

impl Event {
    /// An event stamped with the current time, session and connection id.
    /// `fields` must be a JSON object; anything else is wrapped as `{"value": ..}`
    /// rather than rejected -- an emit site never fails.
    pub fn new(kind: &'static str, fields: Value) -> Self {
        Self::at(now_unix(), session_id().to_string(), current_conn_id(), kind, fields)
    }

    /// [`Event::new`] with every stamp injected (tests).
    pub fn at(ts: u64, session: String, conn: Option<u64>, kind: &'static str, fields: Value) -> Self {
        let fields = match fields {
            Value::Object(map) => map,
            other => {
                let mut map = Map::new();
                map.insert("value".to_string(), other);
                map
            }
        };
        Self { ts, session, conn, kind, fields }
    }

    /// The event as one flat JSON object: the four stamps plus the fields. The
    /// stamps win over a same-named field (a field called `kind` is dropped, not
    /// allowed to impersonate the event kind).
    pub fn to_json(&self) -> Value {
        let mut map = self.fields.clone();
        map.insert("ts".to_string(), Value::from(self.ts));
        map.insert("session".to_string(), Value::from(self.session.as_str()));
        match self.conn {
            Some(c) => map.insert("conn".to_string(), Value::from(c)),
            None => map.remove("conn"),
        };
        map.insert("kind".to_string(), Value::from(self.kind));
        Value::Object(map)
    }
}

/// Render `ev` for stderr: the JSON object on one line when `json`, else the
/// compact `ct-agent event: <kind> [conn=N] k=v k=v` line, where a string value
/// is printed bare and any other value as its JSON. Pure, so the two shapes are
/// unit-testable without a sink.
pub fn format_line(ev: &Event, json: bool) -> String {
    if json {
        return ev.to_json().to_string();
    }
    let mut line = format!("ct-agent event: {}", ev.kind);
    if let Some(c) = ev.conn {
        line.push_str(&format!(" conn={c}"));
    }
    for (k, v) in &ev.fields {
        line.push(' ');
        line.push_str(k);
        line.push('=');
        match v {
            Value::String(s) => line.push_str(s),
            other => line.push_str(&other.to_string()),
        }
    }
    line
}

/// Emit one event: count it, print it to stderr in the configured format, and
/// append its JSON line to the ring file (when a state dir resolves). Never
/// fails and never panics; see the module doc.
pub fn emit(kind: &'static str, fields: Value) {
    let ev = Event::new(kind, fields);
    EVENT_COUNTS.bump(kind);
    eprintln!("{}", format_line(&ev, stderr_json()));
    if let Some(ring) = ring() {
        ring.append(&ev.to_json().to_string());
    }
}

/// Whether `CT_AGENT_LOG_FORMAT` asks for JSON on stderr. Read per emit (events
/// are rare) so a test or a re-exec sees the current environment.
fn stderr_json() -> bool {
    std::env::var(LOG_FORMAT_ENV).map(|v| v.trim().eq_ignore_ascii_case("json")).unwrap_or(false)
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---- process session + connection ids ---------------------------------------------

static SESSION_ID: OnceLock<String> = OnceLock::new();

/// This process's session id: 16 lowercase hex chars from the OS RNG, minted on
/// first use and constant for the life of the process.
pub fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    })
}

/// Per-connection counter: bumped once per registration attempt (see
/// `serve.rs`'s reconnect loop and the TLS-TCP fallback worker). `0` = none yet.
static CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Start a new connection attempt: bump the counter and return the new id, which
/// every event emitted from now on carries as `conn` until the next bump. With a
/// TLS-TCP fallback pool larger than one, the id names the most recent attempt
/// process-wide, not the worker an event came from.
pub fn next_conn_id() -> u64 {
    CONN_ID.fetch_add(1, Ordering::SeqCst) + 1
}

/// The current connection id, `None` before the first attempt.
pub fn current_conn_id() -> Option<u64> {
    match CONN_ID.load(Ordering::SeqCst) {
        0 => None,
        n => Some(n),
    }
}

// ---- per-kind counters (ct_agent_events_total) --------------------------------------

/// A fixed table of one counter per taxonomy kind. The process-wide instance is
/// [`EVENT_COUNTS`]; tests build their own (the same per-test-instance pattern as
/// `task_guard::LiveGauge`, ct-agent#180). A kind outside [`KINDS`] is not counted.
#[derive(Debug)]
pub struct EventCounters([AtomicU64; KINDS.len()]);

/// The process-wide event counters, rendered on `/metrics`.
pub static EVENT_COUNTS: EventCounters = EventCounters::new();

impl EventCounters {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; KINDS.len()])
    }

    fn slot(kind: &str) -> Option<usize> {
        KINDS.iter().position(|k| *k == kind)
    }

    /// Count one event of `kind`.
    pub fn bump(&self, kind: &str) {
        if let Some(i) = Self::slot(kind) {
            self.0[i].fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Events of `kind` counted so far (`0` for a kind outside the taxonomy).
    pub fn get(&self, kind: &str) -> u64 {
        Self::slot(kind).map(|i| self.0[i].load(Ordering::SeqCst)).unwrap_or(0)
    }

    /// `ct_agent_events_total{kind="..."}` for every taxonomy kind, zero-valued
    /// ones included so the series set a scraper sees never changes.
    pub fn render_prometheus(&self) -> String {
        let mut text = String::from(
            "# HELP ct_agent_events_total Structured operator events emitted since process start, by kind \
             (ct-agent#178).\n# TYPE ct_agent_events_total counter\n",
        );
        for (i, kind) in KINDS.iter().enumerate() {
            text.push_str(&format!(
                "ct_agent_events_total{{kind=\"{kind}\"}} {}\n",
                self.0[i].load(Ordering::SeqCst)
            ));
        }
        text
    }
}

impl Default for EventCounters {
    fn default() -> Self {
        Self::new()
    }
}

// ---- the ring file -------------------------------------------------------------------

/// The bounded on-disk event log: `<dir>/events.jsonl` plus at most one rotated
/// predecessor `<dir>/events.jsonl.1`. Appends serialize on an internal mutex so
/// a rotation can never interleave with another thread's write.
#[derive(Debug)]
pub struct Ring {
    path: PathBuf,
    cap: u64,
    lock: Mutex<()>,
    write_errors: AtomicU64,
    error_logged: AtomicBool,
}

impl Ring {
    /// A ring in `dir` with the production cap.
    pub fn new(dir: &Path) -> Self {
        Self::with_cap(dir, EVENTS_RING_MAX_BYTES)
    }

    /// A ring in `dir` rotating once the current file would exceed `cap` bytes.
    pub fn with_cap(dir: &Path, cap: u64) -> Self {
        Self {
            path: dir.join(EVENTS_RING_FILE),
            cap,
            lock: Mutex::new(()),
            write_errors: AtomicU64::new(0),
            error_logged: AtomicBool::new(false),
        }
    }

    /// The current file's path (`<dir>/events.jsonl`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The rotated predecessor's path (`<dir>/events.jsonl.1`).
    pub fn rotated_path(&self) -> PathBuf {
        let mut p = self.path.as_os_str().to_owned();
        p.push(".1");
        PathBuf::from(p)
    }

    /// Appends that failed since this ring was built.
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::SeqCst)
    }

    /// Append one line (a newline is added). Never fails: an I/O error is counted
    /// in [`Ring::write_errors`] and logged the first time only.
    pub fn append(&self, line: &str) {
        let _guard = self.lock.lock_safe();
        if let Err(e) = self.append_locked(line) {
            self.write_errors.fetch_add(1, Ordering::SeqCst);
            if !self.error_logged.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "ct-agent: events ring {}: {e} (further ring write errors are counted on /status, not logged)",
                    self.path.display()
                );
            }
        }
    }

    fn append_locked(&self, line: &str) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let incoming = line.len() as u64 + 1;
        let current = match std::fs::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e),
        };
        if current > 0 && current + incoming > self.cap {
            std::fs::rename(&self.path, self.rotated_path())?;
        }
        let mut f = open_append_private(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }

    /// The last `n` lines across the rotated file and the current one, oldest
    /// first. Unreadable or absent files contribute nothing.
    pub fn recent(&self, n: usize) -> Vec<String> {
        let _guard = self.lock.lock_safe();
        let mut lines = read_lines(&self.rotated_path());
        lines.extend(read_lines(&self.path));
        let skip = lines.len().saturating_sub(n);
        lines.split_off(skip)
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    match std::fs::File::open(path) {
        Ok(f) => BufReader::new(f).lines().map_while(Result::ok).filter(|l| !l.is_empty()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Open the ring file for appending, created at `0600` and never wider (the
/// same discipline as `secret_file::write_private`: mode at CREATE time, then a
/// correction for a pre-existing wider file; `O_NOFOLLOW` refuses a pre-planted
/// symlink). The ring holds edge addresses and peer ids, not secrets, but it sits
/// next to the identity key and the login token and gets the same treatment.
#[cfg(unix)]
fn open_append_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mode = f.metadata()?.permissions().mode() & 0o777;
    if mode != 0o600 {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

#[cfg(not(unix))]
fn open_append_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().append(true).create(true).open(path)
}

// ---- the process-wide ring --------------------------------------------------------------

static RING: OnceLock<Option<Ring>> = OnceLock::new();

/// The process-wide ring, resolved once from the environment; `None` when no
/// state dir resolves (then events reach stderr only). Inert under `cfg(test)`:
/// the crate's e2e tests drive the real reconnect loop, and its events must not
/// land in the developer's `$HOME/.ct-agent/events.jsonl` -- the ring itself is
/// tested through per-test [`Ring`] instances.
fn ring() -> Option<&'static Ring> {
    if cfg!(test) {
        return None;
    }
    RING.get_or_init(|| state_dir().map(|dir| Ring::new(&dir))).as_ref()
}

/// Where this agent keeps persistent state: `CT_AGENT_STATE_DIR`, else
/// `$HOME/.ct-agent` -- the same precedence `login.rs` applies for the token
/// store. `None` when neither is set.
pub fn state_dir() -> Option<PathBuf> {
    state_dir_from(|k| std::env::var(k).ok())
}

/// Pure core of [`state_dir`]: `f` is the env lookup.
pub fn state_dir_from(f: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(dir) = f("CT_AGENT_STATE_DIR").filter(|s| !s.trim().is_empty()) {
        return Some(PathBuf::from(dir.trim()));
    }
    f("HOME")
        .filter(|s| !s.trim().is_empty())
        .map(|home| PathBuf::from(home.trim()).join(".ct-agent"))
}

/// The last `n` lines of the process-wide ring, oldest first; empty when no
/// state dir resolves.
pub fn recent(n: usize) -> Vec<String> {
    ring().map(|r| r.recent(n)).unwrap_or_default()
}

/// The process-wide ring's path, if one resolved (shown by `ct-agent status`).
pub fn ring_path() -> Option<PathBuf> {
    ring().map(|r| r.path().to_path_buf())
}

/// Failed ring appends so far (surfaced on `/status` as `events_ring_write_errors`).
pub fn ring_write_errors() -> u64 {
    ring().map(Ring::write_errors).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample(conn: Option<u64>) -> Event {
        Event::at(
            1_700_000_000,
            "0123456789abcdef".to_string(),
            conn,
            REGISTERED,
            json!({"edge": "edge.example:4433", "transport": "quic"}),
        )
    }

    #[test]
    fn compact_line_lists_kind_conn_and_fields_with_bare_strings() {
        let line = format_line(&sample(Some(3)), false);
        assert_eq!(line, "ct-agent event: registered conn=3 edge=edge.example:4433 transport=quic");
        let line = format_line(&sample(None), false);
        assert_eq!(line, "ct-agent event: registered edge=edge.example:4433 transport=quic");
    }

    #[test]
    fn compact_line_renders_non_string_values_as_json() {
        let ev = Event::at(1, "s".to_string(), None, BRIDGE_CALL, json!({"tool": "bridge/status", "ok": true}));
        assert_eq!(format_line(&ev, false), "ct-agent event: bridge_call ok=true tool=bridge/status");
    }

    #[test]
    fn json_line_is_one_flat_object_with_the_stamps_and_the_fields() {
        let line = format_line(&sample(Some(7)), true);
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["ts"], json!(1_700_000_000));
        assert_eq!(v["session"], json!("0123456789abcdef"));
        assert_eq!(v["conn"], json!(7));
        assert_eq!(v["kind"], json!("registered"));
        assert_eq!(v["edge"], json!("edge.example:4433"));
        assert_eq!(v["transport"], json!("quic"));
        // No conn yet -> the key is absent, not null.
        let v: Value = serde_json::from_str(&format_line(&sample(None), true)).unwrap();
        assert!(v.get("conn").is_none());
    }

    #[test]
    fn stamps_win_over_same_named_fields() {
        let fields = json!({"kind": "spoof", "conn": 99, "reason": "x"});
        let ev = Event::at(5, "s".to_string(), Some(1), DISCONNECTED, fields);
        let v = ev.to_json();
        assert_eq!(v["kind"], json!("disconnected"));
        assert_eq!(v["conn"], json!(1));
        assert_eq!(v["reason"], json!("x"));
    }

    #[test]
    fn non_object_fields_are_wrapped_as_value() {
        let ev = Event::at(1, "s".to_string(), None, UPDATE_CHECK, json!("up-to-date"));
        assert_eq!(ev.fields.get("value"), Some(&json!("up-to-date")));
        assert_eq!(format_line(&ev, false), "ct-agent event: update_check value=up-to-date");
        let ev = Event::at(1, "s".to_string(), None, FALLBACK_EXHAUSTED, json!(null));
        assert_eq!(ev.fields.get("value"), Some(&Value::Null));
        let ev = Event::at(1, "s".to_string(), None, FALLBACK_EXHAUSTED, json!({}));
        assert!(ev.fields.is_empty());
        assert_eq!(format_line(&ev, false), "ct-agent event: fallback_exhausted");
    }

    #[test]
    fn session_id_is_16_hex_and_stable() {
        let a = session_id();
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(a, session_id());
    }

    #[test]
    fn state_dir_prefers_the_explicit_dir_then_home() {
        let explicit = |k: &str| match k {
            "CT_AGENT_STATE_DIR" => Some("/state".to_string()),
            "HOME" => Some("/home/x".to_string()),
            _ => None,
        };
        assert_eq!(state_dir_from(explicit), Some(PathBuf::from("/state")));
        let home_only = |k: &str| match k {
            "CT_AGENT_STATE_DIR" => Some("  ".to_string()),
            "HOME" => Some("/home/x".to_string()),
            _ => None,
        };
        assert_eq!(state_dir_from(home_only), Some(PathBuf::from("/home/x/.ct-agent")));
        assert_eq!(state_dir_from(|_| None), None);
    }

    #[test]
    fn ring_rotates_at_the_cap_and_recent_spans_the_rotation() {
        let dir = tempfile::tempdir().unwrap();
        // Each line is 10 bytes + newline = 11; a cap of 30 holds two lines.
        let ring = Ring::with_cap(dir.path(), 30);
        for i in 0..5 {
            ring.append(&format!("{{\"n\":{i:5}}}"));
        }
        assert_eq!(ring.write_errors(), 0);
        let rotated = std::fs::read_to_string(ring.rotated_path()).unwrap();
        let current = std::fs::read_to_string(ring.path()).unwrap();
        // Lines 0,1 filled the first file; 2 rotated it; 2,3 filled the second;
        // 4 rotated again (replacing .1 with {2,3}) and started the third.
        assert_eq!(rotated, "{\"n\":    2}\n{\"n\":    3}\n");
        assert_eq!(current, "{\"n\":    4}\n");
        assert_eq!(
            ring.recent(10),
            vec!["{\"n\":    2}", "{\"n\":    3}", "{\"n\":    4}"],
            "recent() reads .1 then the current file, oldest first"
        );
        assert_eq!(ring.recent(2), vec!["{\"n\":    3}", "{\"n\":    4}"]);
        assert_eq!(ring.recent(0), Vec::<String>::new());
    }

    #[test]
    fn ring_creates_the_state_dir_and_recent_is_empty_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deeper").join("state");
        let ring = Ring::new(&nested);
        assert!(ring.recent(5).is_empty());
        ring.append("{\"kind\":\"x\"}");
        assert!(nested.join(EVENTS_RING_FILE).is_file());
        assert_eq!(ring.recent(5), vec!["{\"kind\":\"x\"}"]);
    }

    #[cfg(unix)]
    #[test]
    fn ring_file_is_created_0600_and_a_wider_existing_file_is_narrowed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ring = Ring::new(dir.path());
        ring.append("a");
        let mode = std::fs::metadata(ring.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::set_permissions(ring.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        ring.append("b");
        let mode = std::fs::metadata(ring.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a pre-existing wider ring file is corrected on the next append");
    }

    #[test]
    fn ring_write_failure_is_counted_not_propagated() {
        let dir = tempfile::tempdir().unwrap();
        // A regular FILE where the state dir should be: create_dir_all fails.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let ring = Ring::new(&blocker);
        ring.append("one");
        ring.append("two");
        assert_eq!(ring.write_errors(), 2);
        assert!(ring.recent(5).is_empty());
    }

    #[test]
    fn counters_count_only_taxonomy_kinds_and_render_every_series() {
        let c = EventCounters::new();
        c.bump(REGISTERED);
        c.bump(REGISTERED);
        c.bump(DIRECT_REFUSED);
        c.bump("not_a_kind");
        assert_eq!(c.get(REGISTERED), 2);
        assert_eq!(c.get(DIRECT_REFUSED), 1);
        assert_eq!(c.get("not_a_kind"), 0);
        let text = c.render_prometheus();
        assert!(text.contains("# TYPE ct_agent_events_total counter\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"registered\"} 2\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"direct_refused\"} 1\n"));
        assert!(text.contains("\nct_agent_events_total{kind=\"update_applied\"} 0\n"));
        for kind in KINDS {
            assert!(text.contains(&format!("{{kind=\"{kind}\"}} ")), "series for {kind}");
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn conn_ids_are_monotonic_and_visible_to_new_events() {
        let first = next_conn_id();
        let second = next_conn_id();
        // `>` not `+ 1`: the serve e2e tests in this binary bump the same counter in parallel.
        assert!(second > first);
        assert!(current_conn_id().unwrap() >= second);
        let ev = Event::new(DISCONNECTED, json!({"reason": "test"}));
        assert!(ev.conn.unwrap() >= second);
        assert_eq!(ev.session, session_id());
    }
}
