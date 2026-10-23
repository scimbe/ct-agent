//! `ct-agent channel` as a process: SIGTERM and SIGINT end a running member with status 0 after
//! its drain, the opt-in health listener answers, `ct-agent channel health` turns the answer into
//! an exit status, and a bad lifecycle setting fails the start.
//!
//! Lives under `tests/` because only an integration test gets the built binary
//! (`CARGO_BIN_EXE_<name>`), and a signal has to reach a real process. The member under test runs
//! the direct-address accept mode on an ephemeral port: it binds and then waits for a peer that
//! never comes, so it is long-running without any edge.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ct-agent");

/// The member: a direct-address acceptor that waits for a peer, with a private state dir and
/// nothing inherited from the caller's environment.
fn member(state: &std::path::Path, extra: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.arg("channel")
        .env_clear()
        .env("CT_AGENT_STATE_DIR", state)
        .env("CT_CHANNEL_ROLE", "accept")
        .env("CT_CHANNEL_ADDR", "127.0.0.1:0")
        .env("CT_CHANNEL_NOISE_KEY", "11".repeat(32))
        .env("CT_CHANNEL_PEER_NOISE_KEY", "22".repeat(32));
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd
}

/// A running child with its stderr lines arriving on a channel.
struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Running {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines, seen: Vec::new() }
    }

    /// The first stderr line containing `needle`, within `within`.
    fn line_with(&mut self, needle: &str, within: Duration) -> String {
        let until = Instant::now() + within;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        panic!("no stderr line with {needle:?} within {within:?}; got: {:#?}", self.seen);
    }

    /// The exit status within `within` (killed and failed otherwise).
    fn exit_within(&mut self, within: Duration) -> std::process::ExitStatus {
        let until = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= until {
                let _ = self.child.kill();
                panic!("still running after {within:?}; stderr: {:#?}", self.seen);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[cfg(unix)]
fn send(child: &Child, signal: libc::c_int) {
    // SAFETY: a plain kill(2) to our own child's pid.
    let rc = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    assert_eq!(rc, 0, "kill({signal})");
}

// Without a handler, SIGTERM ended the process by the signal (and as a container's PID 1 it did
// nothing at all until SIGKILL). With one, the member stops taking work, drains and exits 0.
#[cfg(unix)]
#[test]
fn sigterm_and_sigint_end_a_running_channel_member_with_status_0() {
    for (signal, name) in [(libc::SIGTERM, "SIGTERM"), (libc::SIGINT, "SIGINT")] {
        let state = tempfile::tempdir().unwrap();
        let mut run = Running::spawn(member(state.path(), &[]));
        run.line_with("listening on", Duration::from_secs(20));
        let sent = Instant::now();
        send(&run.child, signal);
        let status = run.exit_within(Duration::from_secs(10));
        let took = sent.elapsed();
        assert!(status.success(), "{name}: {status:?}; stderr: {:#?}", run.seen);
        run.line_with(&format!("{name} -- shutting down"), Duration::from_secs(1));
        // Nothing was in flight: no reason to wait out the 5 s drain.
        assert!(took < Duration::from_secs(3), "{name}: exited after {took:?}");
    }
}

#[cfg(unix)]
#[test]
fn the_health_listener_and_the_exec_probe_answer_for_a_running_member() {
    let state = tempfile::tempdir().unwrap();
    let mut run = Running::spawn(member(state.path(), &[("CT_CHANNEL_HEALTH_LISTEN", "127.0.0.1:0")]));
    let line = run.line_with("health endpoint on ", Duration::from_secs(20));
    let addr = line
        .split("health endpoint on ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap()
        .to_string();
    run.line_with("listening on", Duration::from_secs(20));
    let probe = |args: &[&str], listen: Option<&str>| {
        let mut cmd = Command::new(BIN);
        cmd.arg("channel").arg("health").args(args).env_clear().env("CT_AGENT_STATE_DIR", state.path());
        if let Some(listen) = listen {
            cmd.env("CT_CHANNEL_HEALTH_LISTEN", listen);
        }
        let out = cmd.output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    assert_eq!(probe(&["healthz"], Some(&addr)), (Some(0), "ok\n".to_string()));
    // A direct-address acceptor that waits for its peer has no session: not ready, status 1.
    for args in [&["readyz"][..], &[][..]] {
        let (code, out) = probe(args, Some(&addr));
        assert_eq!(code, Some(1), "{args:?}: {out}");
        assert!(out.starts_with("not ready: "), "{args:?}: {out}");
    }
    assert_eq!(probe(&["bogus"], Some(&addr)).0, Some(2), "a usage error");
    assert_eq!(probe(&["readyz"], None).0, Some(2), "no listener configured");
    send(&run.child, libc::SIGTERM);
    assert!(run.exit_within(Duration::from_secs(10)).success());
}

// A lifecycle setting the process cannot honour fails the start, naming the variable -- not a
// silent default, and not a listener that never comes up.
#[test]
fn a_bad_lifecycle_setting_fails_the_start_with_status_1() {
    for (var, value) in [
        ("CT_CHANNEL_SHUTDOWN_DRAIN_SECS", "5s"),
        ("CT_CHANNEL_HEALTH_LISTEN", "localhost:9480"),
        ("CT_CHANNEL_FORWARD_SESSION_WINDOW_KIB", "32"),
    ] {
        let state = tempfile::tempdir().unwrap();
        let mut run = Running::spawn(member(state.path(), &[(var, value)]));
        // Bounded: a member that ignored the setting would wait for its peer for good.
        let status = run.exit_within(Duration::from_secs(20));
        let named = run.line_with(var, Duration::from_secs(1));
        assert_eq!(status.code(), Some(1), "{var}={value}: {named}");
    }
}
