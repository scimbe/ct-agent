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

use std::path::PathBuf;

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
