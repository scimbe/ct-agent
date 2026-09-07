//! `ct-agent doctor sandbox` (scimbe/ct-agent#183, decision C1, 2026-09-07).
//!
//! Since v0.7.29 a Binary-manifest activation is FAIL-CLOSED: it refuses to run unless a
//! sandbox backend (bwrap) is usable on this host, or the agent's own environment sets
//! `CT_ALLOW_UNSANDBOXED=1`. The refusal names the probe's failure, but an operator standing up
//! a new host wants that answer BEFORE the first activation, together with what to fix. This
//! module is that per-host check: it runs the very same `installer_engine::sandbox::select()`
//! the activation runs, then -- on Linux -- inspects the three kernel knobs that are known to
//! break unprivileged user namespaces (the thing bwrap needs), and says which one is off and how
//! to turn it on.
//!
//! Everything that decides (sysctl evaluation, the bwrap `--version` verdict, the exit-code
//! mapping, the JSON shape) is a pure function of its inputs so it is unit-tested on every OS
//! without spawning bwrap; only the thin collectors at the bottom touch `/proc` and `PATH`.

use std::time::Duration;

use installer_engine::sandbox::{select, Selection};
use serde_json::{json, Value};

/// The doctor's own usage text, printed (to stderr, exit 2) on any argument it does not know --
/// the #239 discipline: a typo must fail loudly, never silently run something else.
pub const DOCTOR_USAGE: &str = "\
usage: ct-agent doctor sandbox [--json]

  Report whether THIS host can run sandboxed Binary-manifest activations (bwrap) and, if not,
  exactly what to fix. Exit 0: sandbox available; 1: unavailable (see the FAIL lines); 2: OS not
  supported for Binary manifests, or unrecognized arguments. --json prints one JSON object instead
  of the human report.
";

/// Exit status when a sandbox backend is usable on this host.
pub const EXIT_AVAILABLE: i32 = 0;
/// Exit status when the OS is supported but no backend passed its probe.
pub const EXIT_UNAVAILABLE: i32 = 1;
/// Exit status when this OS has no Binary-manifest sandbox at all (decision B3: compose manifests
/// and `manifest plan` only), and for bad arguments -- both mean "this invocation cannot answer".
pub const EXIT_UNSUPPORTED: i32 = 2;

/// How long `bwrap --version` may take before the check gives up. A hung `--version` (seen with a
/// broken setuid install or an LSM that stalls the exec) would otherwise hang the doctor forever;
/// 5 s is generous for a binary that prints one line and exits.
pub const BWRAP_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The single-line message printed on an OS with no Binary-manifest sandbox (B3).
pub const UNSUPPORTED_OS_LINE: &str = "sandbox: not supported on this OS for binary manifests; compose manifests and \
                                       `manifest plan` only (scimbe/ct-agent#183 decision B3)";

/// The kernel knobs the Linux diagnostics read. Each one, in the listed `bad_value` state, makes
/// bwrap's user-namespace creation fail while `bwrap --version` still succeeds -- exactly the
/// "probe passed, first real use failed" gap the activation probe closes at runtime, made visible
/// here up front with the remediation attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysctlCheck {
    /// The `/proc/sys` path; also the finding's `check` name, so an operator can `cat` it.
    pub path: &'static str,
    /// The value that means "unprivileged user namespaces are denied".
    pub bad_value: &'static str,
    /// What the bad value means, in the finding's `detail`.
    pub meaning: &'static str,
    /// The remediation, verbatim in the finding's `fix`.
    pub fix: &'static str,
}

/// Ubuntu 24.04+: `1` denies unprivileged user namespaces unless the caller runs under an AppArmor
/// profile granting `userns`. Handled by [`evaluate_apparmor_restriction`], which also knows about
/// the profile, rather than by the generic [`evaluate_sysctl`].
pub const APPARMOR_USERNS: SysctlCheck = SysctlCheck {
    path: "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    bad_value: "1",
    meaning: "unprivileged user namespaces are denied unless bwrap runs under an AppArmor profile that grants userns",
    fix: "either install the bwrap AppArmor profile (`apt install bubblewrap` ships /etc/apparmor.d/bwrap on Ubuntu \
          24.04) or set `sysctl kernel.apparmor_restrict_unprivileged_userns=0` (throwaway hosts only)",
};

/// Older Debian kernels: `0` disables unprivileged user namespaces outright.
pub const USERNS_CLONE: SysctlCheck = SysctlCheck {
    path: "/proc/sys/kernel/unprivileged_userns_clone",
    bad_value: "0",
    meaning: "unprivileged user namespaces are disabled",
    fix: "sysctl kernel.unprivileged_userns_clone=1",
};

/// Any kernel: `0` means no user namespace can be created at all, by anyone.
pub const MAX_USER_NAMESPACES: SysctlCheck = SysctlCheck {
    path: "/proc/sys/user/max_user_namespaces",
    bad_value: "0",
    meaning: "the user-namespace limit is zero, so none can be created",
    fix: "sysctl user.max_user_namespaces=<N> (e.g. 15000, the kernel default)",
};

/// Where a distro's AppArmor profile for bwrap lands; the presence of either turns the
/// `apparmor_restrict_unprivileged_userns=1` finding from FAIL into ok, because the restriction
/// exempts profile-confined callers -- the probe above the findings is still the authority.
pub const BWRAP_APPARMOR_PROFILES: [&str; 2] = ["/etc/apparmor.d/bwrap", "/etc/apparmor.d/bwrap-userns-restrict"];

/// The check name under which the `bwrap --version` verdict is reported.
pub const BWRAP_ON_PATH_CHECK: &str = "bwrap on PATH";

/// One diagnostic line: what was checked, whether it passed, what was seen, and -- on a failure
/// -- the one thing to do about it. `fix` is `None` on ok findings and on failures this crate has
/// no remediation for (a wrong hint is worse than none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// What was checked: a `/proc/sys` path, or [`BWRAP_ON_PATH_CHECK`].
    pub check: &'static str,
    /// Passed (`ok` line) or not (`FAIL` line).
    pub ok: bool,
    /// What was observed, for the operator's eyes: the value, the version, the error.
    pub detail: String,
    /// The remediation, when this crate knows one.
    pub fix: Option<&'static str>,
}

impl Finding {
    /// The `findings[]` element of the `--json` report: every field, `fix` as `null` when absent,
    /// so a consumer never has to test for a missing key.
    pub fn to_json(&self) -> Value {
        json!({ "check": self.check, "ok": self.ok, "detail": self.detail, "fix": self.fix })
    }

    /// The human line(s): `ok`/`FAIL`, the check, the detail, and the fix indented below a FAIL.
    /// Fixed-width verdict column so a screen of findings scans by eye.
    pub fn render(&self) -> String {
        let verdict = if self.ok { "ok  " } else { "FAIL" };
        let mut line = format!("{verdict}  {}: {}", self.check, self.detail);
        if let Some(fix) = self.fix {
            line.push_str("\n      fix: ");
            line.push_str(fix);
        }
        line
    }
}

/// The outcome of running `bwrap --version`, separated from the spawn so
/// [`evaluate_bwrap_version`] is a pure function a test can drive through every variant without a
/// bwrap binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BwrapVersion {
    /// Exit 0; the trimmed stdout (normally `bubblewrap <version>`).
    Ok(String),
    /// The binary ran but exited non-zero.
    NonZero { code: Option<i32>, stderr: String },
    /// It could not be spawned or waited on (most often: not on PATH).
    NotRunnable(String),
    /// It did not exit within [`BWRAP_VERSION_TIMEOUT`] and was killed.
    TimedOut,
}

/// The `bwrap on PATH` finding. A missing binary is the most common reason a fresh host cannot
/// sandbox, and the only one whose fix is a package install rather than a sysctl.
pub fn evaluate_bwrap_version(outcome: &BwrapVersion) -> Finding {
    const INSTALL: &str =
        "install bubblewrap (Debian/Ubuntu: `apt install bubblewrap`; Fedora: `dnf install bubblewrap`)";
    match outcome {
        BwrapVersion::Ok(version) => {
            let detail = if version.is_empty() { "bwrap --version exited 0".to_string() } else { version.clone() };
            Finding { check: BWRAP_ON_PATH_CHECK, ok: true, detail, fix: None }
        }
        BwrapVersion::NonZero { code, stderr } => Finding {
            check: BWRAP_ON_PATH_CHECK,
            ok: false,
            detail: format!("bwrap --version exited non-zero: exit={code:?} stderr={stderr}"),
            fix: Some(INSTALL),
        },
        BwrapVersion::NotRunnable(err) => Finding {
            check: BWRAP_ON_PATH_CHECK,
            ok: false,
            detail: format!("bwrap not runnable on PATH: {err}"),
            fix: Some(INSTALL),
        },
        BwrapVersion::TimedOut => Finding {
            check: BWRAP_ON_PATH_CHECK,
            ok: false,
            detail: format!("bwrap --version did not exit within {} s (killed)", BWRAP_VERSION_TIMEOUT.as_secs()),
            fix: Some(INSTALL),
        },
    }
}

/// The finding for one kernel knob, given the file's contents (`None` when the file does not
/// exist). Absent is ok, not unknown: each of these files exists exactly on the kernels where the
/// restriction it controls exists, so "no file" means "this kernel has no such restriction".
pub fn evaluate_sysctl(check: &SysctlCheck, contents: Option<&str>) -> Finding {
    match contents.map(str::trim) {
        None => Finding {
            check: check.path,
            ok: true,
            detail: "absent (not applicable on this kernel)".into(),
            fix: None,
        },
        Some(value) if value == check.bad_value => Finding {
            check: check.path,
            ok: false,
            detail: format!("value {value}: {}", check.meaning),
            fix: Some(check.fix),
        },
        Some(value) => Finding { check: check.path, ok: true, detail: format!("value {value}"), fix: None },
    }
}

/// [`evaluate_sysctl`] for [`APPARMOR_USERNS`], with one refinement: when the knob is `1` but a
/// bwrap AppArmor profile is installed (`profile` names it), the restriction does not apply to
/// bwrap, so the finding is ok and says why. Without this a correctly hardened Ubuntu 24.04 host
/// -- profile installed, probe passing -- would show a FAIL line under an `available` verdict.
pub fn evaluate_apparmor_restriction(contents: Option<&str>, profile: Option<&str>) -> Finding {
    let finding = evaluate_sysctl(&APPARMOR_USERNS, contents);
    match (finding.ok, profile) {
        (false, Some(path)) => Finding {
            check: APPARMOR_USERNS.path,
            ok: true,
            detail: format!(
                "value 1, but a bwrap AppArmor profile is installed at {path} (the restriction exempts it)"
            ),
            fix: None,
        },
        _ => finding,
    }
}

/// Whether an activation in an environment where `var` answers lookups would run UNSANDBOXED.
/// Delegates to the engine's own decision (`CT_ALLOW_UNSANDBOXED=1`, unless the legacy
/// `CT_REQUIRE_BINARY_SANDBOX=1` overrides it) rather than re-implementing the string test, so the
/// warning can never disagree with what `manifest activate` actually does.
pub fn would_run_unsandboxed(var: impl Fn(&str) -> Option<String>) -> bool {
    !installer_engine::require_binary_sandbox_from_env(var)
}

/// The warning line printed (never a FAIL) when [`would_run_unsandboxed`] is true. Visible on
/// purpose: an operator who set the opt-out on a throwaway host and forgot should see it every
/// time they check the host.
pub const ALLOW_UNSANDBOXED_WARNING: &str =
    "WARNING: activation would run UNSANDBOXED on this host (CT_ALLOW_UNSANDBOXED=1)";

/// What `installer_engine::sandbox::select()` said, reduced to plain data: the trait object it
/// returns is neither `Debug` nor `Clone`, and the report only needs the backend's name, its
/// isolation summary, and the per-candidate failure reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxVerdict {
    /// `Some("bwrap")` when a backend passed its probe.
    pub backend: Option<&'static str>,
    /// The backend's own one-line description of what it does and does not isolate.
    pub isolation_summary: Option<&'static str>,
    /// `(candidate, reason)` per backend that failed its probe; empty on an OS with no candidate.
    pub tried: Vec<(&'static str, String)>,
}

impl SandboxVerdict {
    /// True when a backend is usable -- the whole point of the command.
    pub fn available(&self) -> bool {
        self.backend.is_some()
    }
}

impl From<Selection> for SandboxVerdict {
    fn from(selection: Selection) -> Self {
        match selection {
            Selection::Sandboxed(backend) => Self {
                backend: Some(backend.name()),
                isolation_summary: Some(backend.isolation_summary()),
                tried: Vec::new(),
            },
            Selection::Unsandboxed { tried } => Self { backend: None, isolation_summary: None, tried },
        }
    }
}

/// The whole answer for one host. Built once by [`run_doctor`] (or by a test from literals), then
/// rendered as text or JSON and mapped to an exit code -- so the three outputs cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// `std::env::consts::OS`; the report's `os` field and the basis of [`DoctorReport::supported`].
    pub os: &'static str,
    /// What the activation-time probe said, reduced to data.
    pub sandbox: SandboxVerdict,
    /// The Linux diagnostics; empty on other OSes.
    pub findings: Vec<Finding>,
    /// [`would_run_unsandboxed`] for the doctor's own environment.
    pub allow_unsandboxed: bool,
}

impl DoctorReport {
    /// Whether this OS has a Binary-manifest sandbox at all. Only Linux does today (bwrap);
    /// macOS's `sandbox_exec` backend is not implemented (installer-engine Milestone 2).
    pub fn supported(&self) -> bool {
        self.os == "linux"
    }

    /// The process exit status: 0 available, 1 unavailable, 2 unsupported OS -- so a provisioning
    /// script can `ct-agent doctor sandbox && ct-agent manifest activate`.
    pub fn exit_code(&self) -> i32 {
        if !self.supported() {
            EXIT_UNSUPPORTED
        } else if self.sandbox.available() {
            EXIT_AVAILABLE
        } else {
            EXIT_UNAVAILABLE
        }
    }

    /// The `--json` object. Fixed keys, every one always present, so a consumer can rely on the
    /// shape regardless of verdict or OS.
    pub fn to_json(&self) -> Value {
        json!({
            "sandbox_available": self.sandbox.available(),
            "backend": self.sandbox.backend,
            "tried": self.sandbox.tried.iter()
                .map(|(candidate, reason)| json!({ "candidate": candidate, "reason": reason }))
                .collect::<Vec<_>>(),
            "findings": self.findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
            "allow_unsandboxed": self.allow_unsandboxed,
            "os": self.os,
        })
    }

    /// The human report: the verdict first, then the findings, then the opt-out warning -- the
    /// order in which an operator needs them (is it fine? if not, what do I fix? and am I about
    /// to run something unconfined?).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if !self.supported() {
            out.push_str(UNSUPPORTED_OS_LINE);
            out.push('\n');
        } else if let Some(backend) = self.sandbox.backend {
            out.push_str(&format!("sandbox: available ({backend})\n"));
            if let Some(summary) = self.sandbox.isolation_summary {
                out.push_str(&format!("  {summary}\n"));
            }
        } else {
            out.push_str("sandbox: UNAVAILABLE\n");
            for (candidate, reason) in &self.sandbox.tried {
                out.push_str(&format!("  {candidate}: {reason}\n"));
            }
        }
        for finding in &self.findings {
            out.push_str(&finding.render());
            out.push('\n');
        }
        if self.allow_unsandboxed {
            out.push_str(ALLOW_UNSANDBOXED_WARNING);
            out.push('\n');
        }
        out
    }
}

/// The arguments `doctor` accepts, parsed from everything after the word `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DoctorArgs {
    /// `--json`: one JSON object on stdout instead of the human report.
    pub json: bool,
}

/// Parse `doctor`'s arguments: exactly the subcommand `sandbox`, optionally followed by `--json`.
/// Anything else is an error carrying the message to print above the usage -- a mistyped
/// `sandbx` or `--jsno` must not be ignored (#239).
pub fn parse_args(args: &[String]) -> Result<DoctorArgs, String> {
    let mut iter = args.iter();
    match iter.next().map(String::as_str) {
        Some("sandbox") => {}
        Some(other) => return Err(format!("unrecognized doctor subcommand '{other}' (only `sandbox` exists)")),
        None => return Err("`doctor` requires a subcommand (sandbox)".to_string()),
    }
    let mut parsed = DoctorArgs::default();
    for arg in iter {
        match arg.as_str() {
            "--json" => parsed.json = true,
            other => return Err(format!("unrecognized `doctor sandbox` argument '{other}' (only --json is accepted)")),
        }
    }
    Ok(parsed)
}

/// `ct-agent doctor ...`: parse, probe, diagnose, print, and return the exit status (never
/// exiting itself, so `main` stays the only place that calls `process::exit`). Blocking: the
/// probe spawns bwrap twice and the version check once; call it from a blocking context.
pub fn run_doctor(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("ct-agent: {message}\n");
            eprint!("{DOCTOR_USAGE}");
            return EXIT_UNSUPPORTED;
        }
    };
    let report = DoctorReport {
        os: std::env::consts::OS,
        sandbox: SandboxVerdict::from(select()),
        findings: platform_findings(),
        allow_unsandboxed: would_run_unsandboxed(|name| std::env::var(name).ok()),
    };
    // ct-agent#178: one structured line per doctor run, like `manifest_plan` per plan, so a
    // host's history shows when its sandbox capability was last checked and what it said.
    crate::events::emit(
        crate::events::DOCTOR_SANDBOX,
        json!({ "available": report.sandbox.available(), "os": report.os }),
    );
    if parsed.json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render_text());
    }
    report.exit_code()
}

/// The Linux diagnostics, in the order an operator fixes them: the binary first (nothing else
/// matters without it), then the kernel knobs from most to least common.
#[cfg(target_os = "linux")]
fn platform_findings() -> Vec<Finding> {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let profile = BWRAP_APPARMOR_PROFILES.into_iter().find(|path| std::path::Path::new(path).is_file());
    vec![
        evaluate_bwrap_version(&bwrap_version_outcome(BWRAP_VERSION_TIMEOUT)),
        evaluate_apparmor_restriction(read(APPARMOR_USERNS.path).as_deref(), profile),
        evaluate_sysctl(&USERNS_CLONE, read(USERNS_CLONE.path).as_deref()),
        evaluate_sysctl(&MAX_USER_NAMESPACES, read(MAX_USER_NAMESPACES.path).as_deref()),
    ]
}

/// No diagnostics off Linux: the knobs are Linux kernel interfaces and bwrap is Linux-only, so
/// every finding would be "absent" -- noise under a verdict that already says "unsupported".
#[cfg(not(target_os = "linux"))]
fn platform_findings() -> Vec<Finding> {
    Vec::new()
}

/// Run `bwrap --version` with a hard deadline. A poll loop over `try_wait` plus `Child::kill`
/// rather than a wait thread: the crate has no shared bounded-process helper, this keeps the
/// kill in safe std, and `--version` writes one short line, so the piped stdout can never fill
/// and stall the child before it exits.
#[cfg(target_os = "linux")]
fn bwrap_version_outcome(timeout: Duration) -> BwrapVersion {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let spawned = Command::new("bwrap")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return BwrapVersion::NotRunnable(e.to_string()),
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return BwrapVersion::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return BwrapVersion::NotRunnable(format!("waiting on bwrap: {e}")),
        }
    }
    match child.wait_with_output() {
        Ok(output) if output.status.success() => {
            BwrapVersion::Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        Ok(output) => BwrapVersion::NonZero {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(e) => BwrapVersion::NotRunnable(format!("reading bwrap output: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available() -> SandboxVerdict {
        SandboxVerdict { backend: Some("bwrap"), isolation_summary: Some("bwrap: isolates things"), tried: vec![] }
    }

    fn unavailable() -> SandboxVerdict {
        SandboxVerdict {
            backend: None,
            isolation_summary: None,
            tried: vec![("bwrap", "bwrap not runnable on PATH: No such file or directory".to_string())],
        }
    }

    fn report(os: &'static str, sandbox: SandboxVerdict, allow: bool) -> DoctorReport {
        DoctorReport { os, sandbox, findings: vec![], allow_unsandboxed: allow }
    }

    #[test]
    fn apparmor_restriction_is_fail_only_when_set_to_one() {
        let bad = evaluate_apparmor_restriction(Some("1\n"), None);
        assert!(!bad.ok);
        assert_eq!(bad.check, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
        assert!(bad.detail.starts_with("value 1"), "{}", bad.detail);
        let fix = bad.fix.unwrap();
        assert!(fix.contains("/etc/apparmor.d/bwrap"), "{fix}");
        assert!(fix.contains("kernel.apparmor_restrict_unprivileged_userns=0"), "{fix}");

        let good = evaluate_apparmor_restriction(Some("0\n"), None);
        assert!(good.ok);
        assert_eq!(good.detail, "value 0");
        assert_eq!(good.fix, None);

        let absent = evaluate_apparmor_restriction(None, None);
        assert!(absent.ok);
        assert!(absent.detail.contains("absent"), "{}", absent.detail);
        assert_eq!(absent.fix, None);
    }

    #[test]
    fn an_installed_bwrap_apparmor_profile_lifts_the_restriction_finding() {
        let lifted = evaluate_apparmor_restriction(Some("1"), Some("/etc/apparmor.d/bwrap"));
        assert!(lifted.ok);
        assert!(lifted.detail.contains("/etc/apparmor.d/bwrap"), "{}", lifted.detail);
        assert_eq!(lifted.fix, None);
        // The profile is irrelevant when the knob is not restricting anything.
        assert_eq!(
            evaluate_apparmor_restriction(Some("0"), Some("/etc/apparmor.d/bwrap")),
            evaluate_apparmor_restriction(Some("0"), None)
        );
    }

    #[test]
    fn userns_clone_is_fail_only_when_zero() {
        let bad = evaluate_sysctl(&USERNS_CLONE, Some("0\n"));
        assert!(!bad.ok);
        assert_eq!(bad.check, "/proc/sys/kernel/unprivileged_userns_clone");
        assert_eq!(bad.fix, Some("sysctl kernel.unprivileged_userns_clone=1"));

        let good = evaluate_sysctl(&USERNS_CLONE, Some("1\n"));
        assert!(good.ok);
        assert_eq!(good.fix, None);

        let absent = evaluate_sysctl(&USERNS_CLONE, None);
        assert!(absent.ok);
        assert_eq!(absent.fix, None);
    }

    #[test]
    fn max_user_namespaces_is_fail_only_when_zero() {
        let bad = evaluate_sysctl(&MAX_USER_NAMESPACES, Some("0"));
        assert!(!bad.ok);
        assert_eq!(bad.check, "/proc/sys/user/max_user_namespaces");
        assert!(bad.fix.unwrap().starts_with("sysctl user.max_user_namespaces="));

        let good = evaluate_sysctl(&MAX_USER_NAMESPACES, Some("15000\n"));
        assert!(good.ok);
        assert_eq!(good.detail, "value 15000");

        let absent = evaluate_sysctl(&MAX_USER_NAMESPACES, None);
        assert!(absent.ok);
    }

    #[test]
    fn bwrap_version_verdicts_cover_every_outcome_without_spawning() {
        let ok = evaluate_bwrap_version(&BwrapVersion::Ok("bubblewrap 0.9.0".into()));
        assert!(ok.ok);
        assert_eq!(ok.check, BWRAP_ON_PATH_CHECK);
        assert_eq!(ok.detail, "bubblewrap 0.9.0");
        assert_eq!(ok.fix, None);

        let missing = evaluate_bwrap_version(&BwrapVersion::NotRunnable("No such file or directory".into()));
        assert!(!missing.ok);
        assert!(missing.detail.contains("not runnable on PATH"), "{}", missing.detail);
        assert!(missing.fix.unwrap().contains("apt install bubblewrap"));

        let broken = evaluate_bwrap_version(&BwrapVersion::NonZero { code: Some(1), stderr: "boom".into() });
        assert!(!broken.ok);
        assert!(broken.detail.contains("exit=Some(1)") && broken.detail.contains("boom"), "{}", broken.detail);

        let hung = evaluate_bwrap_version(&BwrapVersion::TimedOut);
        assert!(!hung.ok);
        assert!(hung.detail.contains("5 s"), "{}", hung.detail);
    }

    #[test]
    fn finding_render_marks_verdict_and_indents_the_fix() {
        let ok = Finding { check: "x", ok: true, detail: "fine".into(), fix: None };
        assert_eq!(ok.render(), "ok    x: fine");
        let bad = Finding { check: "y", ok: false, detail: "broken".into(), fix: Some("do this") };
        assert_eq!(bad.render(), "FAIL  y: broken\n      fix: do this");
    }

    #[test]
    fn exit_codes_map_available_unavailable_unsupported() {
        assert_eq!(report("linux", available(), false).exit_code(), EXIT_AVAILABLE);
        assert_eq!(report("linux", unavailable(), false).exit_code(), EXIT_UNAVAILABLE);
        // Off Linux the verdict is "unsupported" whatever select() said (it says Unsandboxed).
        let empty = SandboxVerdict { backend: None, isolation_summary: None, tried: vec![] };
        assert_eq!(report("macos", empty, false).exit_code(), EXIT_UNSUPPORTED);
        // The opt-out never changes the exit code: it is a warning, not a verdict.
        assert_eq!(report("linux", unavailable(), true).exit_code(), EXIT_UNAVAILABLE);
        assert_eq!((EXIT_AVAILABLE, EXIT_UNAVAILABLE, EXIT_UNSUPPORTED), (0, 1, 2));
    }

    #[test]
    fn json_has_the_fixed_shape_in_both_verdicts() {
        let mut ok = report("linux", available(), false);
        ok.findings.push(Finding { check: "bwrap on PATH", ok: true, detail: "bubblewrap 0.9.0".into(), fix: None });
        let v = ok.to_json();
        assert_eq!(v["sandbox_available"], json!(true));
        assert_eq!(v["backend"], json!("bwrap"));
        assert_eq!(v["tried"], json!([]));
        assert_eq!(
            v["findings"],
            json!([{ "check": "bwrap on PATH", "ok": true, "detail": "bubblewrap 0.9.0", "fix": null }])
        );
        assert_eq!(v["allow_unsandboxed"], json!(false));
        assert_eq!(v["os"], json!("linux"));
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["allow_unsandboxed", "backend", "findings", "os", "sandbox_available", "tried"]);

        let mut bad = report("linux", unavailable(), true);
        bad.findings.push(Finding { check: "c", ok: false, detail: "d".into(), fix: Some("f") });
        let v = bad.to_json();
        assert_eq!(v["sandbox_available"], json!(false));
        assert_eq!(v["backend"], Value::Null);
        assert_eq!(
            v["tried"],
            json!([{ "candidate": "bwrap", "reason": "bwrap not runnable on PATH: No such file or directory" }])
        );
        assert_eq!(v["findings"][0]["fix"], json!("f"));
        assert_eq!(v["allow_unsandboxed"], json!(true));
    }

    #[test]
    fn text_report_leads_with_the_verdict_then_findings_then_the_warning() {
        let mut ok = report("linux", available(), false);
        ok.findings.push(Finding { check: "bwrap on PATH", ok: true, detail: "bubblewrap 0.9.0".into(), fix: None });
        let text = ok.render_text();
        assert!(text.starts_with("sandbox: available (bwrap)\n  bwrap: isolates things\n"), "{text}");
        assert!(text.contains("ok    bwrap on PATH: bubblewrap 0.9.0\n"), "{text}");
        assert!(!text.contains("WARNING"), "{text}");

        let bad = report("linux", unavailable(), false);
        let text = bad.render_text();
        assert!(text.starts_with("sandbox: UNAVAILABLE\n  bwrap: bwrap not runnable on PATH"), "{text}");

        let empty = SandboxVerdict { backend: None, isolation_summary: None, tried: vec![] };
        let text = report("macos", empty, false).render_text();
        assert_eq!(text, format!("{UNSUPPORTED_OS_LINE}\n"));
        assert!(text.contains("decision B3"), "{text}");
    }

    #[test]
    fn the_opt_out_is_a_visible_warning_not_a_failure() {
        let env = |vars: &[(&str, &str)]| {
            let owned: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            move |name: &str| owned.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
        };
        assert!(!would_run_unsandboxed(env(&[])));
        assert!(!would_run_unsandboxed(env(&[("CT_ALLOW_UNSANDBOXED", "0")])));
        assert!(would_run_unsandboxed(env(&[("CT_ALLOW_UNSANDBOXED", "1")])));
        assert!(would_run_unsandboxed(env(&[("CT_ALLOW_UNSANDBOXED", " 1 ")])));
        // The legacy flag wins over the opt-out, exactly as it does in `manifest activate`.
        assert!(!would_run_unsandboxed(env(&[("CT_ALLOW_UNSANDBOXED", "1"), ("CT_REQUIRE_BINARY_SANDBOX", "1")])));

        let warned = report("linux", available(), true);
        let text = warned.render_text();
        assert!(text.ends_with(&format!("{ALLOW_UNSANDBOXED_WARNING}\n")), "{text}");
        assert!(text.contains("CT_ALLOW_UNSANDBOXED=1"), "{text}");
        assert_eq!(warned.exit_code(), EXIT_AVAILABLE);
        assert_eq!(warned.to_json()["allow_unsandboxed"], json!(true));
    }

    #[test]
    fn arguments_are_exactly_sandbox_with_optional_json() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_args(&args(&["sandbox"])), Ok(DoctorArgs { json: false }));
        assert_eq!(parse_args(&args(&["sandbox", "--json"])), Ok(DoctorArgs { json: true }));
        assert!(parse_args(&args(&[])).unwrap_err().contains("requires a subcommand"));
        assert!(parse_args(&args(&["sandbx"])).unwrap_err().contains("'sandbx'"));
        assert!(parse_args(&args(&["sandbox", "--jsno"])).unwrap_err().contains("'--jsno'"));
        assert!(parse_args(&args(&["sandbox", "--json", "extra"])).unwrap_err().contains("'extra'"));
    }

    #[test]
    fn the_sysctl_table_names_the_documented_paths_and_bad_values() {
        assert_eq!(APPARMOR_USERNS.path, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
        assert_eq!(APPARMOR_USERNS.bad_value, "1");
        assert_eq!(USERNS_CLONE.path, "/proc/sys/kernel/unprivileged_userns_clone");
        assert_eq!(USERNS_CLONE.bad_value, "0");
        assert_eq!(MAX_USER_NAMESPACES.path, "/proc/sys/user/max_user_namespaces");
        assert_eq!(MAX_USER_NAMESPACES.bad_value, "0");
    }
}
