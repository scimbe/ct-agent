//! `ct-agent update` (operator-directed hardening pass): check GitHub's
//! releases API for a newer tagged release than this binary's own
//! `CARGO_PKG_VERSION`, and if one exists, download the matching platform
//! asset and replace the running binary with it.
//!
//! Deliberately does NOT touch how `install_docker()` (`scripts/setup.sh`)
//! resolves what to build -- that already pins to the latest release tag
//! independently. This is the other half: an already-running, host-native
//! (non-Docker) install updating itself in place, without the operator
//! having to re-run the installer.
//!
//! **Auto-update** (`CT_AGENT_AUTO_UPDATE`, 2026-09-01 operator ask): the
//! manual `update` subcommand above has a real gap it can't close on its
//! own -- an operator has to already know it exists AND remember to run it,
//! and a binary old enough to predate this whole module has no way to
//! discover either (a live incident: a peer maintainer's install had sat so
//! far behind that `update` itself wasn't in that binary's `--help` output).
//! [`run_auto_update_loop`] closes that gap for anyone who opts in: it
//! periodically re-checks and, on finding a newer release, swaps the binary
//! then exits(0) cleanly -- it does NOT re-exec itself. That exit is only
//! useful paired with a process supervisor that restarts on any exit
//! (`ct-agent-supervisor`, systemd `Restart=always`, Docker
//! `--restart=always`); without one, enabling this trades "silently stale
//! forever" for "silently stopped after the next update" -- also bad, just
//! differently. Off by default, and its own startup notice says so.

use std::path::PathBuf;
use std::time::Duration;

/// The GitHub API endpoint this checks against. A plain, unauthenticated GET
/// -- no token needed, same rate limits any anonymous release-checker has.
const RELEASES_API: &str = "https://api.github.com/repos/scimbe/ct-agent/releases/latest";

/// Where a released asset is downloaded from once its exact name is known
/// (same convention `docker/Dockerfile` already uses for its own download).
fn download_url(asset_name: &str) -> String {
    format!("https://github.com/scimbe/ct-agent/releases/latest/download/{asset_name}")
}

/// The result of checking for an update: what's running, what's latest, and
/// whether they differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub asset_name: String,
}

/// Extract `tag_name` from the GitHub releases API's JSON body -- the same
/// plain-`sed`-style extraction idiom `scripts/setup.sh` already uses for
/// other GitHub/control-plane API responses (no `serde_json` dependency
/// pulled in just for one field; this crate already parses JSON manually
/// elsewhere, e.g. `acme_client.rs`, for the same reason: avoid a full
/// deserializer for a single scalar).
fn extract_tag_name(body: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let idx = body.find(key)?;
    let after_key = &body[idx + key.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let after_colon = after_colon.strip_prefix('"')?;
    let end = after_colon.find('"')?;
    Some(after_colon[..end].to_string())
}

/// Map this process's own platform to the exact asset-name suffix
/// `.github/workflows/release.yml` publishes (`ct-agent-<os>-<arch>[.exe]`).
/// `std::env::consts` doesn't speak this vocabulary directly -- `"macos"` vs.
/// the release asset's `"darwin"`, `"x86"` vs. `"i686"` -- so this is the one
/// translation table both sides need to agree on.
fn asset_name_for_platform(os: &str, arch: &str) -> Result<String, String> {
    let os_name = match os {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => return Err(format!("unsupported OS for self-update: {other}")),
    };
    let arch_name = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "x86" => "i686",
        other => return Err(format!("unsupported architecture for self-update: {other}")),
    };
    let ext = if os_name == "windows" { ".exe" } else { "" };
    Ok(format!("ct-agent-{os_name}-{arch_name}{ext}"))
}

/// Strip a `v` prefix (release tags are `v0.7.12`; `CARGO_PKG_VERSION` is
/// `0.7.12`) and compare as dotted numeric components -- not a string
/// compare, which would sort "0.7.9" ahead of "0.7.12" lexicographically.
fn version_is_newer(current: &str, candidate: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }
    parts(candidate) > parts(current)
}

/// Check the releases API and decide whether an update is available. Pure
/// I/O in one place (the HTTP GET); everything else ([`extract_tag_name`],
/// [`version_is_newer`], [`asset_name_for_platform`]) is a separately-tested
/// pure function.
pub async fn check_latest(current_version: &str) -> Result<UpdateCheck, String> {
    let client = reqwest::Client::builder()
        .user_agent(format!("ct-agent/{current_version}"))
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))?;
    let resp = client
        .get(RELEASES_API)
        .send()
        .await
        .map_err(|e| format!("GET {RELEASES_API}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {RELEASES_API}: HTTP {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| format!("reading response body: {e}"))?;
    let latest_version =
        extract_tag_name(&body).ok_or_else(|| "no tag_name in the releases API response".to_string())?;
    let asset_name = asset_name_for_platform(std::env::consts::OS, std::env::consts::ARCH)?;
    Ok(UpdateCheck {
        update_available: version_is_newer(current_version, &latest_version),
        current_version: current_version.to_string(),
        latest_version,
        asset_name,
    })
}

/// Download `check.asset_name` and atomically replace the currently running
/// binary with it.
///
/// **Unix**: download to a temp file in the SAME directory as the running
/// exe (guarantees the same filesystem, so the final `rename` is atomic),
/// `chmod +x`, then `rename` over the original path. Safe even while the old
/// binary is still executing -- the running process holds its already-open
/// inode; the rename only affects what a FUTURE exec resolves the path to.
///
/// **Windows**: cannot overwrite/delete a running executable's file directly
/// (the OS holds an exclusive lock on it), but CAN rename it -- so the
/// current exe is renamed aside first (`.old` suffix, best-effort cleanup on
/// the *next* successful update), then the new binary takes its place.
pub async fn perform_update(check: &UpdateCheck) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = current_exe.parent().ok_or("current exe has no parent directory")?;
    let tmp_path = dir.join(format!(".{}.new", check.asset_name));

    let url = download_url(&check.asset_name);
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("reading download body: {e}"))?;
    std::fs::write(&tmp_path, &bytes).map_err(|e| format!("writing {tmp_path:?}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {tmp_path:?}: {e}"))?;
        std::fs::rename(&tmp_path, &current_exe)
            .map_err(|e| format!("replacing {current_exe:?}: {e}"))?;
    }
    #[cfg(windows)]
    {
        let old_path = dir.join(format!("{}.old", check.asset_name));
        let _ = std::fs::remove_file(&old_path); // best-effort cleanup of a PRIOR update's leftover
        std::fs::rename(&current_exe, &old_path)
            .map_err(|e| format!("renaming the running exe aside ({current_exe:?} -> {old_path:?}): {e}"))?;
        std::fs::rename(&tmp_path, &current_exe)
            .map_err(|e| format!("installing the new exe at {current_exe:?}: {e}"))?;
    }

    Ok(current_exe)
}

/// Helper for `main.rs`'s `update` subcommand -- ties [`check_latest`] and
/// [`perform_update`] together with the user-facing messages, so the CLI
/// dispatch stays a thin call like every other subcommand there.
pub async fn run_update(current_version: &str) -> Result<(), String> {
    let check = check_latest(current_version).await?;
    if !check.update_available {
        eprintln!(
            "ct-agent: already on the latest release ({} == {})",
            check.current_version, check.latest_version
        );
        return Ok(());
    }
    eprintln!(
        "ct-agent: updating {} -> {} ({})",
        check.current_version, check.latest_version, check.asset_name
    );
    let path = perform_update(&check).await?;
    eprintln!(
        "ct-agent: updated to {} at {path:?} -- restart the agent to run the new build",
        check.latest_version
    );
    Ok(())
}

/// Default check interval when `CT_AGENT_AUTO_UPDATE` is on but
/// `CT_AGENT_AUTO_UPDATE_INTERVAL_SECS` isn't set: once a day. Frequent enough that a
/// release doesn't sit unnoticed for weeks, infrequent enough that a fleet of agents
/// checking in never looks like anything but background noise to GitHub's API.
const DEFAULT_AUTO_UPDATE_INTERVAL_SECS: u64 = 86_400;

/// Floor on the configured interval -- protects the (unauthenticated, rate-limited)
/// releases API from a misconfigured near-zero value (a typo'd "5" meaning hours, taken
/// as seconds) turning into every deployed agent hammering it in a tight loop.
const MIN_AUTO_UPDATE_INTERVAL_SECS: u64 = 300;

/// Opt-in periodic auto-update config -- `None` (the default) means the feature is
/// entirely off; nothing here runs unless `CT_AGENT_AUTO_UPDATE` is explicitly truthy.
pub struct AutoUpdateConfig {
    pub interval: Duration,
}

impl AutoUpdateConfig {
    /// Read from the process environment. `None` when `CT_AGENT_AUTO_UPDATE` is unset
    /// or falsy -- the caller simply doesn't spawn [`run_auto_update_loop`] in that case.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let enabled = f("CT_AGENT_AUTO_UPDATE")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let interval_secs = f("CT_AGENT_AUTO_UPDATE_INTERVAL_SECS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_AUTO_UPDATE_INTERVAL_SECS)
            .max(MIN_AUTO_UPDATE_INTERVAL_SECS);
        Some(Self { interval: Duration::from_secs(interval_secs) })
    }
}

/// Run forever: sleep [`AutoUpdateConfig::interval`], check for a newer release, and on
/// finding one, download+swap the binary ([`perform_update`]) then `exit(0)` so a
/// supervising process restarts into it -- see this module's doc comment for why a
/// supervisor is required for that exit to actually mean anything. A failed check or
/// swap is logged and retried next interval, never fatal on its own (auto-update must
/// never be the reason a working tunnel goes down). Spawn as a background task
/// (`tokio::spawn`) alongside the real serve loop -- this never returns on its own.
pub async fn run_auto_update_loop(config: AutoUpdateConfig, current_version: String) -> ! {
    loop {
        tokio::time::sleep(config.interval).await;
        let check = match check_latest(&current_version).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ct-agent: auto-update check failed, will retry next interval: {e}");
                continue;
            }
        };
        if !check.update_available {
            continue;
        }
        eprintln!(
            "ct-agent: auto-update found {} -> {} ({}) -- downloading",
            check.current_version, check.latest_version, check.asset_name
        );
        match perform_update(&check).await {
            Ok(path) => {
                eprintln!(
                    "ct-agent: auto-updated to {} at {path:?} -- exiting so a process \
                     supervisor restarts into the new build (this exit is only useful \
                     paired with one -- see CT_AGENT_AUTO_UPDATE's own docs)",
                    check.latest_version
                );
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ct-agent: auto-update download/swap failed, will retry next interval: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tag_name_finds_the_field_in_a_real_shaped_response() {
        let body = r#"{"url":"...","tag_name":"v0.7.12","name":"v0.7.12","draft":false}"#;
        assert_eq!(extract_tag_name(body), Some("v0.7.12".to_string()));
    }

    #[test]
    fn extract_tag_name_handles_whitespace_after_the_colon() {
        let body = r#"{ "tag_name" :  "v1.2.3" }"#;
        assert_eq!(extract_tag_name(body), Some("v1.2.3".to_string()));
    }

    #[test]
    fn extract_tag_name_returns_none_when_absent() {
        assert_eq!(extract_tag_name(r#"{"message":"Not Found"}"#), None);
    }

    #[test]
    fn version_is_newer_compares_numerically_not_lexicographically() {
        // The exact bug a naive string compare would have: "0.7.9" > "0.7.12"
        // lexicographically, which is wrong.
        assert!(version_is_newer("0.7.9", "v0.7.12"));
        assert!(version_is_newer("0.7.9", "0.7.12"));
        assert!(!version_is_newer("0.7.12", "v0.7.9"));
        assert!(!version_is_newer("0.7.12", "v0.7.12"), "equal versions are not \"newer\"");
        assert!(version_is_newer("0.6.9", "v0.7.0"));
    }

    #[test]
    fn asset_name_for_platform_matches_the_release_workflow_matrix() {
        // Every combination `.github/workflows/release.yml` actually builds.
        assert_eq!(asset_name_for_platform("linux", "x86_64").unwrap(), "ct-agent-linux-x86_64");
        assert_eq!(asset_name_for_platform("linux", "x86").unwrap(), "ct-agent-linux-i686");
        assert_eq!(asset_name_for_platform("linux", "aarch64").unwrap(), "ct-agent-linux-aarch64");
        assert_eq!(asset_name_for_platform("macos", "x86_64").unwrap(), "ct-agent-darwin-x86_64");
        assert_eq!(asset_name_for_platform("macos", "aarch64").unwrap(), "ct-agent-darwin-aarch64");
        assert_eq!(
            asset_name_for_platform("windows", "x86_64").unwrap(),
            "ct-agent-windows-x86_64.exe"
        );
        assert_eq!(asset_name_for_platform("windows", "x86").unwrap(), "ct-agent-windows-i686.exe");
        assert_eq!(
            asset_name_for_platform("windows", "aarch64").unwrap(),
            "ct-agent-windows-aarch64.exe"
        );
    }

    #[test]
    fn asset_name_for_platform_rejects_unknown_platforms() {
        assert!(asset_name_for_platform("freebsd", "x86_64").is_err());
        assert!(asset_name_for_platform("linux", "mips").is_err());
    }

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn auto_update_config_is_off_unless_explicitly_enabled() {
        assert!(AutoUpdateConfig::from_lookup(lookup(&[])).is_none());
        assert!(AutoUpdateConfig::from_lookup(lookup(&[("CT_AGENT_AUTO_UPDATE", "0")])).is_none());
        assert!(AutoUpdateConfig::from_lookup(lookup(&[("CT_AGENT_AUTO_UPDATE", "false")])).is_none());
        assert!(AutoUpdateConfig::from_lookup(lookup(&[("CT_AGENT_AUTO_UPDATE", "garbage")])).is_none());
    }

    #[test]
    fn auto_update_config_enabled_defaults_to_daily() {
        let cfg = AutoUpdateConfig::from_lookup(lookup(&[("CT_AGENT_AUTO_UPDATE", "1")]))
            .expect("explicitly enabled");
        assert_eq!(cfg.interval, Duration::from_secs(DEFAULT_AUTO_UPDATE_INTERVAL_SECS));
        let cfg = AutoUpdateConfig::from_lookup(lookup(&[("CT_AGENT_AUTO_UPDATE", "true")]))
            .expect("\"true\" also enables it");
        assert_eq!(cfg.interval, Duration::from_secs(DEFAULT_AUTO_UPDATE_INTERVAL_SECS));
    }

    #[test]
    fn auto_update_config_respects_a_custom_interval_above_the_floor() {
        let cfg = AutoUpdateConfig::from_lookup(lookup(&[
            ("CT_AGENT_AUTO_UPDATE", "1"),
            ("CT_AGENT_AUTO_UPDATE_INTERVAL_SECS", "3600"),
        ]))
        .unwrap();
        assert_eq!(cfg.interval, Duration::from_secs(3600));
    }

    #[test]
    fn auto_update_config_floors_a_dangerously_small_interval() {
        // A typo'd "5" (meant as hours) taken literally as seconds must not turn into
        // every deployed agent hammering the releases API in a tight loop.
        let cfg = AutoUpdateConfig::from_lookup(lookup(&[
            ("CT_AGENT_AUTO_UPDATE", "1"),
            ("CT_AGENT_AUTO_UPDATE_INTERVAL_SECS", "5"),
        ]))
        .unwrap();
        assert_eq!(cfg.interval, Duration::from_secs(MIN_AUTO_UPDATE_INTERVAL_SECS));
    }

    #[cfg(unix)]
    #[test]
    fn perform_update_atomically_replaces_a_fake_running_binary() {
        // Exercises the file-replacement half of perform_update without a real
        // network download: writes the "downloaded" bytes directly to the temp
        // path perform_update expects, then lets it do the chmod+rename.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join(format!("ct-selfupdate-test-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let current_exe = dir.join("ct-agent");
        std::fs::write(&current_exe, b"old binary bytes").unwrap();

        let asset_name = "ct-agent-linux-x86_64".to_string();
        let tmp_path = dir.join(format!(".{asset_name}.new"));
        std::fs::write(&tmp_path, b"new binary bytes").unwrap();

        // Mirror perform_update's own replace step directly (no network call).
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp_path, &current_exe).unwrap();

        assert_eq!(std::fs::read(&current_exe).unwrap(), b"new binary bytes");
        let mode = std::fs::metadata(&current_exe).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o111, 0o111, "the replaced binary must be executable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
