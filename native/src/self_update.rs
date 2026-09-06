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
//! **Download safety** (#168): every downloaded asset is checked against the
//! detached `<asset>.sha256` the release pipeline publishes next to it
//! (`.github/workflows/release.yml`, `sha256sum "$asset" > "$asset.sha256"`),
//! BEFORE anything is written to disk -- a mismatch, a missing checksum file
//! or an unparsable one all refuse the update. The download itself is bounded
//! (60 s whole-request timeout, 20 s connect timeout, [`MAX_UPDATE_BYTES`]
//! size cap) so a stalled or runaway transfer can never wedge the auto-update
//! task or fill the disk. `CT_AGENT_UPDATE_SKIP_VERIFY=1` disables only the
//! checksum check (for a private build whose release has no `.sha256`), and
//! says so loudly on stderr every time it is used.
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

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The GitHub API endpoint this checks against. A plain, unauthenticated GET
/// -- no token needed, same rate limits any anonymous release-checker has.
const RELEASES_API: &str = "https://api.github.com/repos/scimbe/ct-agent/releases/latest";

/// Where released assets are downloaded from once their exact name is known
/// (same convention `docker/Dockerfile` already uses for its own download).
/// `<base>/<asset>` is the binary, `<base>/<asset>.sha256` its checksum.
const RELEASE_DOWNLOAD_BASE: &str = "https://github.com/scimbe/ct-agent/releases/latest/download";

/// Hard ceiling on a downloaded release asset (256 MiB). A real `ct-agent`
/// binary is a few tens of MiB; anything past this is not a release we
/// published, and refusing it keeps a spoofed or broken download from
/// exhausting memory/disk on an unattended host.
pub(crate) const MAX_UPDATE_BYTES: u64 = 256 * 1024 * 1024;

/// Ceiling on the `.sha256` file itself -- a real one is a single line.
const MAX_CHECKSUM_FILE_BYTES: u64 = 64 * 1024;

/// Whole-request timeout for each download (connect + headers + the full
/// body). reqwest's client-level timeout covers body streaming too, so a
/// transfer that stalls mid-body fails instead of hanging forever.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Connect-phase timeout, separate from (and shorter than) the whole-request
/// one so an unreachable host is reported quickly.
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Env var that disables checksum verification (`1`/`true`). Only for a
/// private build whose release has no `.sha256`; never set it on a fleet.
pub(crate) const SKIP_VERIFY_ENV: &str = "CT_AGENT_UPDATE_SKIP_VERIFY";

/// Join the release download base and an asset name into the asset's URL.
fn download_url(base_url: &str, asset_name: &str) -> String {
    format!("{}/{asset_name}", base_url.trim_end_matches('/'))
}

/// `1` / `true` (case-insensitive, whitespace-trimmed) -- the one truthiness
/// rule every boolean env var in this module shares.
fn env_truthy(v: &str) -> bool {
    let v = v.trim();
    v == "1" || v.eq_ignore_ascii_case("true")
}

/// Whether a download must match its published `.sha256` before it is
/// installed. [`ChecksumPolicy::Require`] is the default and the only safe
/// setting for an unattended install; `Skip` exists solely for private builds
/// (see [`SKIP_VERIFY_ENV`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChecksumPolicy {
    Require,
    Skip,
}

impl ChecksumPolicy {
    /// Read [`SKIP_VERIFY_ENV`] from the process environment.
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (testable without touching the real env).
    pub(crate) fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Self {
        match f(SKIP_VERIFY_ENV) {
            Some(v) if env_truthy(&v) => Self::Skip,
            _ => Self::Require,
        }
    }
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
    let client = http_client(current_version)?;
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode exactly 64 hex chars into a SHA-256 digest, naming what's wrong
/// otherwise. Only a short prefix of the offending token is echoed back --
/// the "digest" may be anything a misbehaving server returned.
fn decode_sha256_hex(digest: &str) -> Result<[u8; 32], String> {
    let shown: String = digest.chars().take(16).collect();
    if digest.len() != 64 {
        return Err(format!(
            "digest {shown:?}.. is {} chars long, a SHA-256 is exactly 64 hex chars",
            digest.len()
        ));
    }
    if let Some(bad) = digest.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("digest {shown:?}.. is not hex (contains {bad:?})"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Parse the published `.sha256` file and return the digest for `asset_name`.
///
/// Accepts every shape the release pipeline (or an operator's hand-made
/// file) can produce: a bare 64-hex line, coreutils' `hex  name` (text mode)
/// and `hex *name` (binary mode) forms, and a combined multi-entry file, from
/// which the entry whose file name matches `asset_name` is picked (a
/// directory prefix on the name is tolerated). Refuses -- with the reason --
/// anything else: no digest at all, a wrong-length or non-hex digest, an
/// entry naming a DIFFERENT asset (e.g. the supervisor binary's checksum
/// served for the agent's), or several unnamed digests it can't choose
/// between. Blank lines and `#` comments are ignored.
pub(crate) fn parse_sha256_file(text: &str, asset_name: &str) -> Result<[u8; 32], String> {
    let mut unnamed: Vec<&str> = Vec::new();
    let mut named: Option<&str> = None;
    let mut other_names: Vec<&str> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (digest, name) = match line.find(|c: char| c.is_ascii_whitespace()) {
            Some(i) => (&line[..i], line[i..].trim_start()),
            None => (line, ""),
        };
        // coreutils marks a binary-mode entry with `*` in front of the name.
        let name = name.strip_prefix('*').unwrap_or(name);
        if name.is_empty() {
            unnamed.push(digest);
            continue;
        }
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if base == asset_name {
            if named.is_some() {
                return Err(format!("checksum file lists {asset_name} more than once"));
            }
            named = Some(digest);
        } else {
            other_names.push(name);
        }
    }
    let digest = match (named, unnamed.as_slice()) {
        (Some(d), _) => d,
        (None, [d]) => d,
        (None, []) if other_names.is_empty() => {
            return Err("checksum file contains no digest line".to_string());
        }
        (None, []) => {
            return Err(format!(
                "checksum file has no entry for {asset_name} (it lists: {})",
                other_names.join(", ")
            ));
        }
        (None, many) => {
            return Err(format!(
                "checksum file has {} unnamed digests, cannot tell which one is {asset_name}'s",
                many.len()
            ));
        }
    };
    decode_sha256_hex(digest)
}

/// Compare `bytes`' SHA-256 against `expected`; on mismatch the error names
/// both digests (short prefixes) so a log line is enough to tell "wrong
/// file" from "corrupted transfer".
pub(crate) fn verify_sha256(bytes: &[u8], expected: &[u8; 32]) -> Result<(), String> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual == *expected {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 mismatch: expected {}.., got {}.. over {} bytes",
            hex_encode(&expected[..8]),
            hex_encode(&actual[..8]),
            bytes.len()
        ))
    }
}

/// The one HTTP client this module builds -- for the releases-API check and
/// the downloads alike: bounded end-to-end (whole-request and connect
/// timeouts), unlike the bare `reqwest::Client::new()` the download used to
/// be made with, which could hang the auto-update task forever on a stalled
/// transfer.
fn http_client(current_version: &str) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(format!("ct-agent/{current_version}"))
        .timeout(DOWNLOAD_TIMEOUT)
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

/// Read a response body in chunks, refusing as soon as it would exceed
/// `max_bytes` -- first via `Content-Length` when the server sends one, then
/// again while streaming, since a header is only a claim.
async fn read_body_capped(mut resp: reqwest::Response, url: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            return Err(format!("GET {url}: Content-Length {len} exceeds the {max_bytes}-byte download cap"));
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("GET {url}: reading body: {e}"))? {
        if body.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(format!("GET {url}: body exceeds the {max_bytes}-byte download cap"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Fetch `<base_url>/<asset_name>.sha256` and parse the expected digest out
/// of it. Any non-2xx (a 404 above all) is a hard error: the release
/// pipeline publishes that file for every asset, so its absence means the
/// download cannot be verified -- the error says how to override for a
/// private build that genuinely has none.
pub(crate) async fn fetch_expected_sha256(
    client: &reqwest::Client,
    base_url: &str,
    asset_name: &str,
) -> Result<[u8; 32], String> {
    let url = format!("{}.sha256", download_url(base_url, asset_name));
    let resp = client.get(&url).send().await.map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!(
            "GET {url}: HTTP {status} -- the release pipeline publishes {asset_name}.sha256 next to \
             every asset, so without it the download cannot be verified and is refused; for a \
             private build that has no checksum file set {SKIP_VERIFY_ENV}=1 to install unverified \
             (not recommended)"
        ));
    }
    let body = read_body_capped(resp, &url, MAX_CHECKSUM_FILE_BYTES).await?;
    let text = String::from_utf8(body).map_err(|_| format!("GET {url}: checksum file is not UTF-8"))?;
    parse_sha256_file(&text, asset_name).map_err(|e| format!("{url}: {e}"))
}

/// Download `<base_url>/<asset_name>` and return its bytes only once they
/// have been verified. Order matters: the checksum is fetched FIRST, so a
/// missing/unparsable one fails fast before the (much larger) binary is
/// pulled; the binary is then read under `max_bytes` and compared against
/// the expected digest. Nothing here touches the filesystem.
pub(crate) async fn download_verified(
    client: &reqwest::Client,
    base_url: &str,
    asset_name: &str,
    policy: ChecksumPolicy,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let expected = match policy {
        ChecksumPolicy::Require => Some(fetch_expected_sha256(client, base_url, asset_name).await?),
        ChecksumPolicy::Skip => {
            eprintln!(
                "ct-agent: WARNING: {SKIP_VERIFY_ENV} is set -- installing {asset_name} WITHOUT \
                 verifying it against its published .sha256; only ever do this for a private build"
            );
            None
        }
    };
    let url = download_url(base_url, asset_name);
    let resp = client.get(&url).send().await.map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    let body = read_body_capped(resp, &url, max_bytes).await?;
    if let Some(expected) = &expected {
        verify_sha256(&body, expected).map_err(|e| format!("{url}: {e} -- refusing to install it"))?;
    }
    Ok(body)
}

/// Download `check.asset_name` and atomically replace the currently running
/// binary with it.
///
/// **Verification** (#168): the asset's published `.sha256` is fetched and
/// parsed first, then the binary is downloaded under [`MAX_UPDATE_BYTES`]
/// with a 60 s whole-request / 20 s connect timeout and its SHA-256 compared
/// against the published digest. A mismatch, a missing or unparsable
/// checksum file, or an oversize/stalled download returns `Err` before a
/// single byte is written to disk. `CT_AGENT_UPDATE_SKIP_VERIFY=1` skips only
/// the checksum comparison (private builds), loudly.
///
/// **Unix**: download to a temp file in the SAME directory as the running
/// exe (guarantees the same filesystem, so the final `rename` is atomic),
/// `chmod +x`, then `rename` over the original path. Safe even while the old
/// binary is still executing -- the running process holds its already-open
/// inode; the rename only affects what a FUTURE exec resolves the path to.
/// A `.<asset>.new` left behind by an earlier interrupted update is removed
/// (and logged) right before the fresh one is written.
///
/// **Windows**: cannot overwrite/delete a running executable's file directly
/// (the OS holds an exclusive lock on it), but CAN rename it -- so the
/// current exe is renamed aside first (`.old` suffix, best-effort cleanup on
/// the *next* successful update), then the new binary takes its place.
pub async fn perform_update(check: &UpdateCheck) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    perform_update_into(check, &current_exe, RELEASE_DOWNLOAD_BASE, ChecksumPolicy::from_env(), MAX_UPDATE_BYTES)
        .await
}

/// The whole of [`perform_update`] with its environment made explicit -- the
/// path to replace, the release base URL, the checksum policy and the size
/// cap -- so tests can drive it against a local HTTP server and a temp file
/// instead of the real binary and GitHub.
pub(crate) async fn perform_update_into(
    check: &UpdateCheck,
    current_exe: &Path,
    base_url: &str,
    policy: ChecksumPolicy,
    max_bytes: u64,
) -> Result<PathBuf, String> {
    let dir = current_exe.parent().ok_or("current exe has no parent directory")?;
    let tmp_path = dir.join(format!(".{}.new", check.asset_name));

    let client = http_client(&check.current_version)?;
    let bytes = download_verified(&client, base_url, &check.asset_name, policy, max_bytes).await?;

    // Only a verified download gets this far; nothing above touched the disk.
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => eprintln!("ct-agent: removed stale {tmp_path:?} left behind by an earlier interrupted update"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing stale {tmp_path:?}: {e}")),
    }
    std::fs::write(&tmp_path, &bytes).map_err(|e| format!("writing {tmp_path:?}: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {tmp_path:?}: {e}"))?;
        std::fs::rename(&tmp_path, current_exe).map_err(|e| format!("replacing {current_exe:?}: {e}"))?;
    }
    #[cfg(windows)]
    {
        let old_path = dir.join(format!("{}.old", check.asset_name));
        let _ = std::fs::remove_file(&old_path); // best-effort cleanup of a PRIOR update's leftover
        std::fs::rename(current_exe, &old_path)
            .map_err(|e| format!("renaming the running exe aside ({current_exe:?} -> {old_path:?}): {e}"))?;
        std::fs::rename(&tmp_path, current_exe)
            .map_err(|e| format!("installing the new exe at {current_exe:?}: {e}"))?;
    }

    Ok(current_exe.to_path_buf())
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
        let enabled = f("CT_AGENT_AUTO_UPDATE").map(|v| env_truthy(&v)).unwrap_or(false);
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
/// supervisor is required for that exit to actually mean anything. This is the
/// unattended fleet path, so every download goes through the same guards as the manual
/// subcommand: verified against its published `.sha256` before it touches disk, bounded
/// by a 60 s timeout and the [`MAX_UPDATE_BYTES`] cap, so neither a spoofed release nor
/// a stalled transfer can install anything or wedge this task. A failed check or swap is
/// logged and retried next interval, never fatal on its own (auto-update must never be
/// the reason a working tunnel goes down). Spawn as a background task (`tokio::spawn`)
/// alongside the real serve loop -- this never returns on its own.
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

    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::extract::State as AxState;
    use axum::http::{StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::Router;

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

    #[test]
    fn download_url_joins_base_and_asset_regardless_of_trailing_slash() {
        assert_eq!(download_url("http://h/base", "a"), "http://h/base/a");
        assert_eq!(download_url("http://h/base/", "a"), "http://h/base/a");
    }

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
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

    #[test]
    fn checksum_policy_requires_verification_unless_explicitly_skipped() {
        assert_eq!(ChecksumPolicy::from_lookup(lookup(&[])), ChecksumPolicy::Require);
        assert_eq!(ChecksumPolicy::from_lookup(lookup(&[(SKIP_VERIFY_ENV, "0")])), ChecksumPolicy::Require);
        assert_eq!(ChecksumPolicy::from_lookup(lookup(&[(SKIP_VERIFY_ENV, "yes")])), ChecksumPolicy::Require);
        assert_eq!(ChecksumPolicy::from_lookup(lookup(&[(SKIP_VERIFY_ENV, "1")])), ChecksumPolicy::Skip);
        assert_eq!(ChecksumPolicy::from_lookup(lookup(&[(SKIP_VERIFY_ENV, " TRUE ")])), ChecksumPolicy::Skip);
    }

    // ---- checksum parsing / verification -------------------------------------------

    const ASSET: &str = "ct-agent-linux-x86_64";
    const OTHER_ASSET: &str = "ct-agent-supervisor-linux-x86_64";
    const NEW_BINARY: &[u8] = b"new binary bytes";
    const OLD_BINARY: &[u8] = b"old binary bytes";

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(&sha256_of(bytes))
    }

    #[test]
    fn parse_sha256_file_accepts_a_bare_digest_line() {
        let hex = sha256_hex(NEW_BINARY);
        assert_eq!(parse_sha256_file(&hex, ASSET).unwrap(), sha256_of(NEW_BINARY));
        assert_eq!(parse_sha256_file(&format!("  {hex}\n"), ASSET).unwrap(), sha256_of(NEW_BINARY));
        // Upper-case hex (`shasum` on macOS prints lower-case, but be lenient).
        assert_eq!(parse_sha256_file(&hex.to_uppercase(), ASSET).unwrap(), sha256_of(NEW_BINARY));
    }

    #[test]
    fn parse_sha256_file_accepts_coreutils_text_and_binary_mode_lines() {
        let hex = sha256_hex(NEW_BINARY);
        // Exactly what release.yml's `sha256sum "$asset" > "$asset.sha256"` writes.
        assert_eq!(parse_sha256_file(&format!("{hex}  {ASSET}\n"), ASSET).unwrap(), sha256_of(NEW_BINARY));
        // `sha256sum -b` / `shasum -b`: binary-mode marker.
        assert_eq!(parse_sha256_file(&format!("{hex} *{ASSET}\n"), ASSET).unwrap(), sha256_of(NEW_BINARY));
        // A directory prefix on the name (checksum taken from a staging dir).
        assert_eq!(
            parse_sha256_file(&format!("{hex}  dist/{ASSET}\n"), ASSET).unwrap(),
            sha256_of(NEW_BINARY)
        );
    }

    #[test]
    fn parse_sha256_file_picks_the_matching_entry_from_a_combined_file() {
        let text = format!(
            "# SHA256SUMS\n{}  {OTHER_ASSET}\n{}  {ASSET}\n\n{} *ct-agent-darwin-aarch64\n",
            sha256_hex(b"supervisor"),
            sha256_hex(NEW_BINARY),
            sha256_hex(b"darwin"),
        );
        assert_eq!(parse_sha256_file(&text, ASSET).unwrap(), sha256_of(NEW_BINARY));
        assert_eq!(parse_sha256_file(&text, OTHER_ASSET).unwrap(), sha256_of(b"supervisor"));
    }

    #[test]
    fn parse_sha256_file_rejects_a_short_digest() {
        let err = parse_sha256_file("abcdef0123  ct-agent-linux-x86_64", ASSET).unwrap_err();
        assert!(err.contains("64 hex chars"), "{err}");
        let err = parse_sha256_file(&format!("{}00", sha256_hex(NEW_BINARY)), ASSET).unwrap_err();
        assert!(err.contains("64 hex chars"), "{err}");
    }

    #[test]
    fn parse_sha256_file_rejects_a_non_hex_digest() {
        let bad = format!("{}zz", &sha256_hex(NEW_BINARY)[..62]);
        let err = parse_sha256_file(&bad, ASSET).unwrap_err();
        assert!(err.contains("not hex"), "{err}");
        // Right length in bytes, but not ASCII -- must not panic on slicing.
        let bad = format!("{}é", &sha256_hex(NEW_BINARY)[..62]);
        assert_eq!(bad.len(), 64);
        let err = parse_sha256_file(&bad, ASSET).unwrap_err();
        assert!(err.contains("not hex"), "{err}");
    }

    #[test]
    fn parse_sha256_file_rejects_a_digest_for_a_different_asset() {
        // The supervisor's checksum served where the agent's should be: the
        // digest is perfectly well-formed and must STILL be refused.
        let text = format!("{}  {OTHER_ASSET}\n", sha256_hex(NEW_BINARY));
        let err = parse_sha256_file(&text, ASSET).unwrap_err();
        assert!(err.contains("no entry for ct-agent-linux-x86_64"), "{err}");
        assert!(err.contains(OTHER_ASSET), "{err}");
    }

    #[test]
    fn parse_sha256_file_rejects_empty_and_ambiguous_files() {
        let err = parse_sha256_file("", ASSET).unwrap_err();
        assert!(err.contains("no digest"), "{err}");
        let err = parse_sha256_file("# just a comment\n\n", ASSET).unwrap_err();
        assert!(err.contains("no digest"), "{err}");
        let two_unnamed = format!("{}\n{}\n", sha256_hex(b"a"), sha256_hex(b"b"));
        let err = parse_sha256_file(&two_unnamed, ASSET).unwrap_err();
        assert!(err.contains("2 unnamed digests"), "{err}");
    }

    #[test]
    fn verify_sha256_accepts_a_match_and_names_both_digests_on_mismatch() {
        assert_eq!(verify_sha256(NEW_BINARY, &sha256_of(NEW_BINARY)), Ok(()));
        let err = verify_sha256(NEW_BINARY, &sha256_of(OLD_BINARY)).unwrap_err();
        assert!(err.contains("SHA-256 mismatch"), "{err}");
        assert!(err.contains(&sha256_hex(OLD_BINARY)[..16]), "expected prefix missing: {err}");
        assert!(err.contains(&sha256_hex(NEW_BINARY)[..16]), "actual prefix missing: {err}");
    }

    // ---- end-to-end against a local release server ---------------------------------

    /// A stand-in for `https://github.com/.../releases/latest/download/`: serves the
    /// files it was given by exact path, 404 for anything else. `chunked` streams the
    /// body without a Content-Length so the streaming half of the size cap is hit.
    struct MockRelease {
        files: HashMap<String, Vec<u8>>,
        chunked: bool,
    }

    async fn serve_release_file(AxState(s): AxState<Arc<MockRelease>>, uri: Uri) -> axum::response::Response {
        let name = uri.path().trim_start_matches('/');
        match s.files.get(name) {
            Some(content) if s.chunked => {
                let chunks: Vec<Result<bytes::Bytes, std::io::Error>> =
                    content.chunks(1024).map(|c| Ok(bytes::Bytes::copy_from_slice(c))).collect();
                axum::body::Body::from_stream(tokio_stream::iter(chunks)).into_response()
            }
            Some(content) => content.clone().into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn spawn_mock_release(files: Vec<(String, Vec<u8>)>, chunked: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(MockRelease { files: files.into_iter().collect(), chunked });
        let app = Router::new().fallback(serve_release_file).with_state(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn checksum_file_for(bytes: &[u8], name: &str) -> Vec<u8> {
        format!("{}  {name}\n", sha256_hex(bytes)).into_bytes()
    }

    fn check_for(asset: &str) -> UpdateCheck {
        UpdateCheck {
            current_version: "0.0.1".to_string(),
            latest_version: "v9.9.9".to_string(),
            update_available: true,
            asset_name: asset.to_string(),
        }
    }

    /// A fake "running binary" in a temp dir; the test never goes near the real exe.
    fn fake_install() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("ct-agent");
        std::fs::write(&exe, OLD_BINARY).unwrap();
        (dir, exe)
    }

    fn assert_untouched(dir: &Path, exe: &Path) {
        assert_eq!(std::fs::read(exe).unwrap(), OLD_BINARY, "the running binary must not change");
        assert!(!dir.join(format!(".{ASSET}.new")).exists(), "no .new file may be left behind");
    }

    #[tokio::test]
    async fn perform_update_into_installs_a_verified_download_and_cleans_a_stale_new_file() {
        let base = spawn_mock_release(
            vec![
                (ASSET.to_string(), NEW_BINARY.to_vec()),
                (format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, ASSET)),
            ],
            false,
        )
        .await;
        let (dir, exe) = fake_install();
        // Leftover from an earlier interrupted swap.
        let stale = dir.path().join(format!(".{ASSET}.new"));
        std::fs::write(&stale, b"half-written junk").unwrap();

        let installed =
            perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES)
                .await
                .unwrap();

        assert_eq!(installed, exe);
        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
        assert!(!stale.exists(), "the stale .new must be gone after a successful swap");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & 0o111, 0o111, "the replaced binary must be executable");
        }
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_checksum_mismatch_without_touching_disk() {
        let base = spawn_mock_release(
            vec![
                (ASSET.to_string(), NEW_BINARY.to_vec()),
                // A well-formed checksum -- of some OTHER bytes.
                (format!("{ASSET}.sha256"), checksum_file_for(b"what the release was supposed to be", ASSET)),
            ],
            false,
        )
        .await;
        let (dir, exe) = fake_install();

        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES)
            .await
            .unwrap_err();

        assert!(err.contains("SHA-256 mismatch"), "{err}");
        assert!(err.contains("refusing to install"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_checksum_published_for_a_different_asset() {
        let base = spawn_mock_release(
            vec![
                (ASSET.to_string(), NEW_BINARY.to_vec()),
                (format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, OTHER_ASSET)),
            ],
            false,
        )
        .await;
        let (dir, exe) = fake_install();

        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES)
            .await
            .unwrap_err();

        assert!(err.contains("no entry for"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_when_the_checksum_file_is_missing() {
        // Binary present, .sha256 absent (HTTP 404): a hard error naming the override.
        let base = spawn_mock_release(vec![(ASSET.to_string(), NEW_BINARY.to_vec())], false).await;
        let (dir, exe) = fake_install();

        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES)
            .await
            .unwrap_err();

        assert!(err.contains("HTTP 404"), "{err}");
        assert!(err.contains(".sha256"), "{err}");
        assert!(err.contains(SKIP_VERIFY_ENV), "the error must say how to override: {err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_skip_verify_installs_without_a_checksum_file() {
        let base = spawn_mock_release(vec![(ASSET.to_string(), NEW_BINARY.to_vec())], false).await;
        let (_dir, exe) = fake_install();

        perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Skip, MAX_UPDATE_BYTES)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_an_oversize_body_announced_by_content_length() {
        let big = vec![0xAAu8; 4096];
        let base = spawn_mock_release(
            vec![(ASSET.to_string(), big.clone()), (format!("{ASSET}.sha256"), checksum_file_for(&big, ASSET))],
            false,
        )
        .await;
        let (dir, exe) = fake_install();

        // The checksum is CORRECT -- the size cap alone must refuse this.
        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, 512)
            .await
            .unwrap_err();

        assert!(err.contains("Content-Length 4096 exceeds the 512-byte download cap"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_an_oversize_chunked_body() {
        // No Content-Length (chunked transfer): the cap must trip while streaming.
        let big = vec![0xAAu8; 4096];
        let base = spawn_mock_release(
            vec![(ASSET.to_string(), big.clone()), (format!("{ASSET}.sha256"), checksum_file_for(&big, ASSET))],
            true,
        )
        .await;
        let (dir, exe) = fake_install();

        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, 2048)
            .await
            .unwrap_err();

        assert!(err.contains("body exceeds the 2048-byte download cap"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_missing_asset() {
        let base = spawn_mock_release(vec![(format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, ASSET))], false)
            .await;
        let (dir, exe) = fake_install();

        let err = perform_update_into(&check_for(ASSET), &exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES)
            .await
            .unwrap_err();

        assert!(err.contains("HTTP 404"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn fetch_expected_sha256_parses_what_the_release_pipeline_publishes() {
        let base = spawn_mock_release(
            vec![(format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, ASSET))],
            false,
        )
        .await;
        let client = http_client("0.0.1").unwrap();
        assert_eq!(fetch_expected_sha256(&client, &base, ASSET).await.unwrap(), sha256_of(NEW_BINARY));
    }
}
