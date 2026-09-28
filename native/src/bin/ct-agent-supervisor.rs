//! `ct-agent-supervisor` (#331): a thin external wrapper that spawns the real `ct-agent`
//! binary as a child, classifies WHY it exits, restarts it with backoff on crash loops, and
//! keeps a short crash history for live debugging -- with zero changes to `ct-agent` itself.
//! Per the issue's own feasibility note: a panic prints via Rust's default panic hook (no
//! source change needed to capture it), `std::process::exit(1)` call sites exit with whatever
//! was just logged, and an OS-level kill (OOM, `docker stop`, `kill -9`) shows up as a signal
//! on the child's wait status -- all externally observable from a supervising parent.
//!
//! Usage: identical to `ct-agent` itself -- `ct-agent-supervisor <subcommand> [args...]`, same
//! env config, so it drops in wherever `ct-agent` is invoked today (a systemd unit, a launch
//! script, `watchdog-serve-roles.sh`'s `serve-role.sh`).
//!
//! Env:
//! - `CT_AGENT_SUPERVISOR_BIN` (default `ct-agent`, resolved via `PATH`): the real binary to
//!   supervise.
//! - `CT_AGENT_SUPERVISOR_STATUS_LISTEN` (optional `host:port`): serves `GET /crashes` with
//!   the crash history as JSON, for live debugging.
//! - `CT_AGENT_SUPERVISOR_STATUS_TOKEN` (64-hex, required whenever `..._STATUS_LISTEN` is
//!   set): bearer token gating `/crashes` (#99 -- the endpoint discloses internal crash
//!   state, including source `path:line:col` from panic locations, so it must not be
//!   servable unauthenticated). Fail-closed: if `..._STATUS_LISTEN` is set but this isn't a
//!   valid 64-hex token, the status endpoint does not start at all rather than falling back
//!   to serving unauthenticated.
//!
//! Deliberately deferred (open design questions the issue itself flags as needing a decision
//! before coding, not attempted here): Prometheus metrics alongside `ct-agent`'s own
//! `/metrics`, and pushing crash events into the control-plane's `/status` operator view. This
//! ships the core supervision mechanism first; either integration is a follow-on that only
//! needs to read the same [`CrashHistory`] this binary already maintains.

// ct-agent#176: the data plane is panic-free by construction. Every `unwrap`/`expect`/
// `panic!`/`unreachable!`/`todo!`/`unimplemented!` in NON-test code is a build error
// (CI runs clippy with -D warnings); a provably-infallible site may carry a scoped
// `#[allow(clippy::expect_used)]` with a one-line proof. Tests keep their unwraps.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ct_agent::reconnect::Backoff;
use ct_common::sync::MutexExt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Why a supervised child exited -- the whole point of this binary: turn "it died" into
/// "here is why," using only externally observable signals (exit status, captured stderr).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", content = "detail")]
enum CrashReason {
    /// Killed by a signal (OOM killer, `docker stop`, `kill -9`, a native crash like SIGSEGV).
    Signal(i32),
    /// A Rust panic — the ring buffer contained a `panicked at` line from the default panic
    /// hook. Carries that line (truncated) as the detail.
    Panic(String),
    /// Exited on its own with a non-zero code and no panic line captured (e.g. one of
    /// `main.rs`/`channel_run.rs`'s `std::process::exit(1)` call sites).
    CleanExit(i32),
    /// Exited 0 — not a crash, but still recorded so "why did it stop" has an answer even for
    /// a deliberate clean shutdown (e.g. a one-shot `--call-service` invocation finishing).
    CleanExitOk,
}

impl std::fmt::Display for CrashReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrashReason::Signal(n) => write!(f, "killed by signal {n}"),
            CrashReason::Panic(msg) => write!(f, "panic: {msg}"),
            CrashReason::CleanExit(code) => write!(f, "clean exit code {code}"),
            CrashReason::CleanExitOk => write!(f, "exited 0"),
        }
    }
}

/// One record in the crash history: the reason, when it happened (unix seconds), and how long
/// the child had been running before it exited (so a supervisor operator can distinguish "died
/// instantly on every restart" from "ran fine for hours, then died once").
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct CrashRecord {
    reason: String,
    at_unix: u64,
    uptime_secs: u64,
}

/// Bounded history the `/crashes` endpoint (when configured) serves, plus the running restart
/// count -- the shared state a status server reads while the supervisor loop writes.
#[derive(Default)]
struct CrashHistory {
    records: VecDeque<CrashRecord>,
    restart_count: u64,
}

/// How many crash records to retain — enough to see a pattern (a tight loop vs. an isolated
/// event) without unbounded memory growth over a long-lived supervisor's lifetime.
const HISTORY_LEN: usize = 10;
/// How many trailing stderr lines to keep in the ring buffer used to detect a panic line —
/// generous enough to catch a multi-line panic message (location + payload) even if other
/// diagnostic output interleaves, without buffering the child's entire (potentially unbounded)
/// stderr history.
const STDERR_RING_LINES: usize = 50;
/// A child that ran at least this long before exiting is treated as "was healthy, then died"
/// rather than "part of a crash loop" — its exit resets the backoff to `BASE_DELAY` so a
/// single isolated crash after hours of healthy operation doesn't inherit whatever backoff a
/// PRIOR crash loop had built up.
const HEALTHY_UPTIME_THRESHOLD: Duration = Duration::from_secs(60);
const BASE_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(60);
/// A stderr "line" longer than this is forwarded and kept in pieces; nothing buffers
/// an unterminated line without bound.
const STDERR_MAX_LINE: usize = 16 * 1024;
/// How long the child gets to exit on its own after a forwarded SIGTERM/SIGINT.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// How one supervised run ended.
enum RunEnd {
    Exited(CrashReason),
    /// The supervisor itself was asked to stop; the child was stopped with it.
    Stopped,
}

/// Resolves when this process receives SIGTERM or SIGINT (Ctrl-C on Windows).
async fn shutdown_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() {
    let child_bin = std::env::var("CT_AGENT_SUPERVISOR_BIN").unwrap_or_else(|_| "ct-agent".to_string());
    let child_args: Vec<String> = std::env::args().skip(1).collect();
    let history = Arc::new(Mutex::new(CrashHistory::default()));

    if let Ok(listen) = std::env::var("CT_AGENT_SUPERVISOR_STATUS_LISTEN") {
        match std::env::var("CT_AGENT_SUPERVISOR_STATUS_TOKEN") {
            Ok(token) if is_valid_status_token(&token) => {
                let history = history.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_status(&listen, history, token).await {
                        eprintln!("ct-agent-supervisor: status endpoint failed to bind {listen}: {e}");
                    }
                });
            }
            Ok(_) => {
                eprintln!(
                    "ct-agent-supervisor: CT_AGENT_SUPERVISOR_STATUS_LISTEN is set but \
                     CT_AGENT_SUPERVISOR_STATUS_TOKEN is not a valid 64-hex token -- refusing \
                     to start the status endpoint (fail-closed, #99)"
                );
            }
            Err(_) => {
                eprintln!(
                    "ct-agent-supervisor: CT_AGENT_SUPERVISOR_STATUS_LISTEN is set but \
                     CT_AGENT_SUPERVISOR_STATUS_TOKEN is not -- refusing to start the status \
                     endpoint unauthenticated (fail-closed, #99); set a 64-hex \
                     CT_AGENT_SUPERVISOR_STATUS_TOKEN to enable it"
                );
            }
        }
    }

    // Never gives up (a supervisor's whole job is to keep trying) -- max_attempts is
    // effectively unbounded; only the exponential-growth cap (`MAX_DELAY`) and the
    // healthy-uptime reset actually shape behavior.
    let mut backoff = Backoff::new(BASE_DELAY, MAX_DELAY, u32::MAX);

    loop {
        let started = Instant::now();
        eprintln!("ct-agent-supervisor: starting {child_bin} {}", child_args.join(" "));
        let outcome = run_once(&child_bin, &child_args, tokio::io::stderr(), shutdown_requested()).await;
        let uptime = started.elapsed();

        let reason = match outcome {
            Ok(RunEnd::Exited(reason)) => reason,
            Ok(RunEnd::Stopped) => {
                eprintln!("ct-agent-supervisor: stopped by signal, {child_bin} stopped with it");
                return;
            }
            Err(e) => {
                // The child binary itself couldn't be spawned (not found, not executable) --
                // not a crash of a running process, but still worth recording + backing off
                // on, since retrying an unspawnable binary in a tight loop is exactly the
                // failure mode this binary exists to avoid.
                eprintln!("ct-agent-supervisor: failed to spawn {child_bin}: {e}");
                CrashReason::CleanExit(-1)
            }
        };

        eprintln!("ct-agent-supervisor: {child_bin} exited after {uptime:?} -- {reason}");
        {
            // Poison-tolerant (ct-agent#176): the crash history is diagnostic state --
            // a panic while it was held must not stop the supervisor from restarting
            // the child, which is its one job.
            let mut h = history.lock_safe();
            h.restart_count += 1;
            if h.records.len() >= HISTORY_LEN {
                h.records.pop_front();
            }
            h.records.push_back(CrashRecord {
                reason: reason.to_string(),
                at_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                uptime_secs: uptime.as_secs(),
            });
        }

        if uptime >= HEALTHY_UPTIME_THRESHOLD {
            backoff.reset();
        }
        // Backoff::next_delay only returns None once max_attempts is exhausted, which never
        // happens with u32::MAX -- unwrap_or is defensive, not expected to fire.
        let delay = backoff.next_delay().unwrap_or(MAX_DELAY);
        eprintln!("ct-agent-supervisor: restarting in {delay:?}");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown_requested() => {
                eprintln!("ct-agent-supervisor: stopped by signal while waiting to restart");
                return;
            }
        }
    }
}

/// Spawn `bin args...` once, stream its stderr through to our own stderr while also keeping a
/// bounded ring buffer of the trailing lines (to detect a panic line), pass its stdout through
/// unchanged (existing log pipelines that read a supervised `ct-agent`'s stdout keep working
/// unmodified), and classify why it exited once it does.
async fn run_once<W>(
    bin: &str,
    args: &[String],
    stderr_out: W,
    stop: impl std::future::Future<Output = ()>,
) -> std::io::Result<RunEnd>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        // If the supervisor ever unwinds out of here, the child must not live on as an
        // orphan that a restarted supervisor would then run a second copy next to.
        .kill_on_drop(true)
        .spawn()?;

    // `.stderr(Stdio::piped())` above guarantees the handle; an absent one is
    // reported as a spawn error rather than panicking the supervisor (ct-agent#176).
    let stderr = child.stderr.take().ok_or_else(|| std::io::Error::other("child stderr was not piped"))?;
    let pump = tokio::spawn(pump_stderr(stderr, stderr_out));

    tokio::pin!(stop);
    let status = tokio::select! {
        status = child.wait() => status?,
        _ = &mut stop => {
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                // Forward the stop as a graceful SIGTERM; the agent gets SHUTDOWN_GRACE.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
            if tokio::time::timeout(SHUTDOWN_GRACE, child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
            pump.abort();
            return Ok(RunEnd::Stopped);
        }
    };
    // The pump ends at EOF, i.e. once every writer of the pipe is gone; a grandchild that
    // inherited it must not keep the supervisor from restarting.
    let ring = match tokio::time::timeout(Duration::from_secs(2), pump).await {
        Ok(Ok(ring)) => ring,
        _ => VecDeque::new(),
    };
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    Ok(RunEnd::Exited(classify_exit(signal, status.code(), &ring)))
}

/// Tee the child's stderr: forward every byte unchanged to `out` (so a caller tailing the
/// supervisor's stderr sees exactly what the child printed) while keeping the trailing
/// [`STDERR_RING_LINES`] lines for post-mortem classification. Reads raw bytes, so non-UTF-8
/// output cannot end the drain -- a stopped drain lets the pipe fill and blocks the child on
/// its next write to stderr, forever.
async fn pump_stderr<R, W>(stderr: R, mut out: W) -> VecDeque<String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut ring: VecDeque<String> = VecDeque::with_capacity(STDERR_RING_LINES);
    let mut reader = BufReader::new(stderr);
    let mut line = Vec::with_capacity(256);
    loop {
        line.clear();
        match (&mut reader).take(STDERR_MAX_LINE as u64).read_until(b'\n', &mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                // Keep the pipe drained even if line framing fails.
                let _ = tokio::io::copy(&mut reader, &mut out).await;
                break;
            }
        }
        let _ = out.write_all(&line).await;
        if ring.len() >= STDERR_RING_LINES {
            ring.pop_front();
        }
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        ring.push_back(String::from_utf8_lossy(text).into_owned());
    }
    let _ = out.flush().await;
    ring
}

/// Pure classification core (no process I/O), so the exit-status logic is unit-testable
/// without actually spawning a child. `signal`/`code` mirror
/// `std::process::ExitStatus::signal()`/`code()`'s Unix semantics (exactly one of them is
/// meaningfully `Some` for a real exit status; a signal takes priority when both could be read,
/// matching the OS's own "this process did not choose its exit" semantics).
fn classify_exit(signal: Option<i32>, code: Option<i32>, stderr_ring: &VecDeque<String>) -> CrashReason {
    if let Some(sig) = signal {
        return CrashReason::Signal(sig);
    }
    let code = code.unwrap_or(-1);
    if code == 0 {
        return CrashReason::CleanExitOk;
    }
    if let Some(panic_line) = stderr_ring.iter().rev().find(|l| l.contains("panicked at")) {
        const MAX_LEN: usize = 300;
        // A byte-index slice on a &str panics unless the index falls on a UTF-8
        // character boundary -- and a panic payload is arbitrary program output
        // (a path, a Display impl, anything), so it can easily contain a
        // multi-byte character straddling MAX_LEN. Walking back to the nearest
        // valid boundary avoids the supervisor itself panicking while trying to
        // report a panic -- exactly the failure mode this binary exists to survive.
        let mut end = MAX_LEN.min(panic_line.len());
        while end > 0 && !panic_line.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &panic_line[..end];
        return CrashReason::Panic(truncated.to_string());
    }
    CrashReason::CleanExit(code)
}

/// #99: the status token must be a real 64-hex secret, not e.g. an accidentally-empty env
/// var that would make `CT_AGENT_SUPERVISOR_STATUS_TOKEN` "set" but trivially guessable --
/// same shape as this codebase's other bearer/routing tokens (cf. `capability::
/// parse_routing_token_hex`), though this one stays a string since it's only ever compared,
/// never decoded into bytes for cryptographic use.
fn is_valid_status_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Constant-time equality -- avoids a timing oracle that could let a remote caller learn the
/// status token byte-by-byte from response-time differences (#99). Both inputs are expected
/// to already be the same fixed length in the real call path (`is_valid_status_token` pins
/// the configured side to exactly 64 bytes); the length check here is a safe fallback for a
/// caller-supplied value of any length, not a timing-sensitive comparison itself since token
/// length isn't secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Checks the `Authorization: Bearer <token>` header against the configured status token
/// (#99). Anything else -- header absent, malformed, wrong scheme, wrong token -- is treated
/// identically (`false`) so there's no oracle distinguishing failure reasons.
fn bearer_token_matches(headers: &axum::http::HeaderMap, expected: &str) -> bool {
    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(auth) = auth.to_str() else {
        return false;
    };
    let Some(provided) = auth.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

#[derive(serde::Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct StatusResp {
    restart_count: u64,
    crashes: Vec<CrashRecord>,
}

#[derive(Clone)]
struct StatusState {
    history: Arc<Mutex<CrashHistory>>,
    token: Arc<String>,
}

async fn crashes_handler(
    axum::extract::State(state): axum::extract::State<StatusState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<StatusResp>, axum::http::StatusCode> {
    if !bearer_token_matches(&headers, &state.token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let h = state.history.lock_safe();
    Ok(axum::Json(StatusResp { restart_count: h.restart_count, crashes: h.records.iter().cloned().collect() }))
}

/// Builds the `/crashes` router gated behind `expected_token` (#99), separated from
/// `serve_status`'s socket-binding so it's exercisable in tests via `tower::ServiceExt::
/// oneshot` without a real listener.
fn status_router(history: Arc<Mutex<CrashHistory>>, expected_token: String) -> axum::Router {
    use axum::routing::get;
    let state = StatusState { history, token: Arc::new(expected_token) };
    axum::Router::new().route("/crashes", get(crashes_handler)).with_state(state)
}

/// Serve `GET /crashes` (the restart count + the bounded crash history as JSON) on `listen`
/// (`host:port`) until the process exits, gated behind `expected_token` (#99 -- see the
/// module doc comment; the caller is responsible for only invoking this with a validated
/// 64-hex token, never an empty/missing one). A deliberately minimal,
/// dependency-free-beyond-axum status surface -- see the module doc comment for why this
/// isn't Prometheus/control-plane integrated yet.
async fn serve_status(listen: &str, history: Arc<Mutex<CrashHistory>>, expected_token: String) -> std::io::Result<()> {
    let app = status_router(history, expected_token);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_utf8_stderr_does_not_stop_the_drain_or_wedge_the_child() {
        // An invalid byte, then far more than a pipe buffer: a drain that stops at the first
        // invalid line leaves the child blocked on its stderr write forever.
        let args = vec![
            "-c".to_string(),
            "printf '\\377\\n' >&2; head -c 300000 /dev/zero | tr '\\0' e >&2; echo >&2; echo 'panicked at x' >&2; exit 3"
                .to_string(),
        ];
        let end = tokio::time::timeout(
            Duration::from_secs(10),
            run_once("sh", &args, tokio::io::sink(), std::future::pending()),
        )
        .await
        .expect("the child finished: its stderr was drained to the end")
        .unwrap();
        match end {
            RunEnd::Exited(CrashReason::Panic(p)) => assert!(p.contains("panicked at x"), "{p}"),
            RunEnd::Exited(other) => panic!("expected the trailing panic line to classify, got {other}"),
            RunEnd::Stopped => panic!("not stopped"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_is_forwarded_to_the_child_and_ends_the_run() {
        let args = vec!["-c".to_string(), "trap 'exit 7' TERM; sleep 30 & wait".to_string()];
        let stop = tokio::time::sleep(Duration::from_millis(200));
        let start = Instant::now();
        let end = run_once("sh", &args, tokio::io::sink(), stop).await.unwrap();
        assert!(matches!(end, RunEnd::Stopped));
        assert!(start.elapsed() < SHUTDOWN_GRACE, "the child exited on the forwarded SIGTERM");
    }

    fn ring(lines: &[&str]) -> VecDeque<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_signal_takes_priority_and_is_classified_regardless_of_stderr_content() {
        let r = classify_exit(Some(9), None, &ring(&["some unrelated log line"]));
        assert!(matches!(r, CrashReason::Signal(9)));
        assert_eq!(r.to_string(), "killed by signal 9");
    }

    #[test]
    fn exit_zero_is_a_clean_exit_ok_even_with_no_stderr() {
        let r = classify_exit(None, Some(0), &ring(&[]));
        assert!(matches!(r, CrashReason::CleanExitOk));
    }

    #[test]
    fn a_nonzero_exit_with_a_panic_line_is_classified_as_a_panic() {
        let r = classify_exit(
            None,
            Some(101), // Rust's standard panic exit code
            &ring(&[
                "ct-agent channel: normal log line",
                "thread 'main' panicked at src/channel_run.rs:123:45:\nindex out of bounds",
            ]),
        );
        match r {
            CrashReason::Panic(msg) => assert!(msg.contains("panicked at"), "got {msg:?}"),
            other => panic!("expected Panic, got {other:?}"),
        }
    }

    #[test]
    fn the_most_recent_panic_line_wins_when_multiple_are_in_the_ring() {
        // A crash-looping process's ring could plausibly contain more than one panic line
        // (from a PRIOR run's tail, if the ring wasn't fully cleared) -- the most recent one
        // is the one that actually explains THIS exit.
        let r = classify_exit(
            None,
            Some(101),
            &ring(&["thread 'main' panicked at old.rs:1:1: stale", "thread 'main' panicked at new.rs:2:2: current"]),
        );
        match r {
            CrashReason::Panic(msg) => assert!(msg.contains("new.rs"), "expected the most recent panic, got {msg:?}"),
            other => panic!("expected Panic, got {other:?}"),
        }
    }

    #[test]
    fn a_nonzero_exit_with_no_panic_line_is_a_clean_exit_code() {
        let r = classify_exit(None, Some(1), &ring(&["ct-agent: some other error, not a panic"]));
        assert!(matches!(r, CrashReason::CleanExit(1)));
    }

    #[test]
    fn a_long_panic_line_is_truncated_not_unbounded() {
        let long_line = format!("thread 'main' panicked at {}", "x".repeat(1000));
        let r = classify_exit(None, Some(101), &ring(&[&long_line]));
        match r {
            CrashReason::Panic(msg) => assert!(msg.len() <= 300, "expected truncation, got len {}", msg.len()),
            other => panic!("expected Panic, got {other:?}"),
        }
    }

    /// A panic payload is arbitrary program output -- a path, a Display impl, anything
    /// -- and can contain multi-byte UTF-8 characters. `MAX_LEN` (300) must never land
    /// mid-character: a byte-index slice on a &str panics unless the index falls on a
    /// character boundary. Constructs a line where byte offset 300 falls INSIDE a 3-byte
    /// '中' character (299 ASCII bytes, then '中' spans bytes 299..302) -- the classifier
    /// itself must not panic while classifying a crash.
    #[test]
    fn truncation_never_lands_mid_character_even_when_max_len_would_split_one() {
        let head = "thread 'main' panicked at ".to_string();
        // Pad so '中' (a 3-byte character) starts exactly one byte before MAX_LEN
        // (300) -- its middle byte then sits AT byte 300, which is provably not a
        // char boundary, regardless of how long the fixed head text is.
        let pad_len = 299 - head.len();
        let long_line = format!("{head}{}中{}", "x".repeat(pad_len), "y".repeat(50));
        assert!(!long_line.is_char_boundary(300), "test setup: byte 300 must NOT be a char boundary");
        let r = classify_exit(None, Some(101), &ring(&[&long_line]));
        match r {
            CrashReason::Panic(msg) => {
                assert!(msg.len() <= 300, "expected truncation at or before 300 bytes, got len {}", msg.len());
            }
            other => panic!("expected Panic, got {other:?}"),
        }
    }

    #[test]
    fn no_code_and_no_signal_degrades_to_clean_exit_negative_one_not_a_panic() {
        // Defensive: on a platform/edge-case where neither is populated, this must not panic
        // the SUPERVISOR itself -- degrade to a sentinel rather than unwrap.
        let r = classify_exit(None, None, &ring(&[]));
        assert!(matches!(r, CrashReason::CleanExit(-1)));
    }

    // #99: the /crashes status endpoint must be gated behind a bearer token, fail-closed.

    // Exactly 64 hex chars (32 repeated "a1" pairs) -- deliberately not hand-typed hex noise,
    // so its length is trivially verifiable by inspection rather than by counting characters.
    const TEST_TOKEN: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

    #[test]
    fn a_real_64_hex_token_validates() {
        assert!(is_valid_status_token(TEST_TOKEN));
    }

    #[test]
    fn wrong_length_or_non_hex_tokens_are_rejected() {
        assert!(!is_valid_status_token(""));
        assert!(!is_valid_status_token(&TEST_TOKEN[..63]));
        assert!(!is_valid_status_token(&format!("{TEST_TOKEN}0")));
        let mut bad = TEST_TOKEN.to_string();
        bad.replace_range(0..1, "g"); // 'g' is not a hex digit
        assert!(!is_valid_status_token(&bad));
    }

    #[test]
    fn constant_time_eq_matches_equal_byte_strings_and_rejects_everything_else() {
        assert!(constant_time_eq(b"same-value", b"same-value"));
        assert!(!constant_time_eq(b"same-value", b"different"));
        assert!(!constant_time_eq(b"short", b"much-longer-value"));
        assert!(!constant_time_eq(b"", b"nonempty"));
        assert!(constant_time_eq(b"", b""));
    }

    fn ring_history() -> Arc<Mutex<CrashHistory>> {
        Arc::new(Mutex::new(CrashHistory {
            records: ring(&["init"])
                .into_iter()
                .map(|reason| CrashRecord { reason, at_unix: 0, uptime_secs: 0 })
                .collect(),
            restart_count: 3,
        }))
    }

    #[tokio::test]
    async fn crashes_endpoint_with_no_authorization_header_is_401_not_the_real_data() {
        use tower::ServiceExt;
        let app = status_router(ring_history(), TEST_TOKEN.to_string());
        let req = axum::http::Request::builder().uri("/crashes").body(axum::body::Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn crashes_endpoint_with_the_wrong_token_is_401() {
        use tower::ServiceExt;
        let app = status_router(ring_history(), TEST_TOKEN.to_string());
        let wrong = "0".repeat(64);
        let req = axum::http::Request::builder()
            .uri("/crashes")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {wrong}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn crashes_endpoint_with_a_non_bearer_scheme_is_401_even_with_the_right_token() {
        use tower::ServiceExt;
        let app = status_router(ring_history(), TEST_TOKEN.to_string());
        let req = axum::http::Request::builder()
            .uri("/crashes")
            .header(axum::http::header::AUTHORIZATION, format!("Token {TEST_TOKEN}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn crashes_endpoint_with_the_correct_token_returns_the_real_crash_history() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let app = status_router(ring_history(), TEST_TOKEN.to_string());
        let req = axum::http::Request::builder()
            .uri("/crashes")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: StatusResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.restart_count, 3);
        assert_eq!(parsed.crashes.len(), 1);
        assert_eq!(parsed.crashes[0].reason, "init");
    }
}
