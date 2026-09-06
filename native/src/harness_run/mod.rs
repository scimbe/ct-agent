//! `ct-agent harness run` (CADS-agent-marketplace Phase 2): run a signed
//! [`manifest_core::SignedTask`] against `harness_core`'s bounded agent loop, scoped to exactly
//! one already-activated manifest's own bundle directory.
//!
//! Thin CLI glue only -- the whole agent loop, tool set, and containment logic lives in
//! `harness_core`, exactly the same layering as `manifest_run` keeping its logic in
//! `installer_engine`. What stays here is env parsing (same fail-loudly, no-silent-default style
//! as `manifest_run::ActivateCliConfig`) and the one defense-in-depth check that's specific to
//! this CLI: confirming `CT_HARNESS_BUNDLE_DIR` really was installed from the manifest the task
//! claims to be scoped to -- its compose file is where the manifest says, and its
//! `.ct-agent-activation.json` marker (written by `manifest activate`, #165) names that same
//! manifest -- before handing control to the agent loop.

use crate::manifest_run::{read_activation_marker, ACTIVATION_MARKER_FILE};
use installer_engine::allowlist::TrustAllowlist;
use manifest_core::SignedTask;
use std::path::{Path, PathBuf};

fn req<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<String, String> {
    match f(key).map(|v| v.trim().to_string()) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} required ({what})")),
    }
}

fn opt<F: Fn(&str) -> Option<String>>(f: &F, key: &str) -> Option<String> {
    f(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|t| !t.is_empty()).map(str::to_string).collect()
}

/// `ct-agent harness run`: env config.
#[derive(Debug)]
pub struct HarnessCliConfig {
    /// `CT_HARNESS_TASK_URL_OR_PATH` -- an https:// URL or local path to the signed `SignedTask` JSON.
    pub task_location: String,
    /// `CT_HARNESS_MANIFEST_URL_OR_PATH` -- the same manifest reference used at `manifest activate`
    /// time, re-fetched here to confirm it matches the task's `manifest_id` and that `bundle_dir`
    /// really looks installed from it, before any file the harness touches is trusted.
    pub manifest_location: String,
    pub allowlist: TrustAllowlist,
    pub bundle_dir: PathBuf,
    pub litellm_base_url: String,
    /// `CT_HARNESS_LITELLM_KEY_FILE` -- a file, never an inline env var (mirrors `capability.rs`'s
    /// own file-based-secret discipline, #31) so the key never lands in `ps`/process-env dumps.
    pub litellm_key_file: PathBuf,
    /// `CT_HARNESS_ALLOWED_MODELS` -- comma-separated harness-side model allowlist, separate from
    /// the publisher trust allowlist: even a trusted task naming an unexpected model is refused.
    pub allowed_models: Vec<String>,
    /// `CT_HARNESS_ALLOW_UNMARKED_BUNDLE=1` (exactly `1`) -- accept a `bundle_dir` that carries no
    /// activation marker (activated by a ct-agent older than #165, or assembled by hand) with a
    /// stderr warning instead of refusing it. A marker that IS present must still match; this
    /// only relaxes the "must exist" half, never the "must name this manifest" half.
    pub allow_unmarked_bundle: bool,
}

impl HarnessCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let inline = opt(&f, "CT_HARNESS_TRUST_ALLOWLIST");
        let file = opt(&f, "CT_HARNESS_TRUST_ALLOWLIST_FILE");
        let allowlist = match (inline, file) {
            (Some(_), Some(_)) => {
                return Err("set exactly one of CT_HARNESS_TRUST_ALLOWLIST or \
                            CT_HARNESS_TRUST_ALLOWLIST_FILE, not both"
                    .to_string())
            }
            (Some(csv), None) => TrustAllowlist::parse(&csv)?,
            (None, Some(path)) => TrustAllowlist::load_file(std::path::Path::new(&path))?,
            (None, None) => {
                return Err("CT_HARNESS_TRUST_ALLOWLIST (comma-separated 64-hex publisher pubkeys) \
                            or CT_HARNESS_TRUST_ALLOWLIST_FILE (one per line) required -- the \
                            harness runs no task unless you name its publisher explicitly"
                    .to_string())
            }
        };
        if allowlist.is_empty() {
            return Err("the configured publisher trust allowlist is empty -- it would reject \
                        every task; name at least one 64-hex publisher pubkey"
                .to_string());
        }
        let allowed_models = split_csv(&req(
            &f,
            "CT_HARNESS_ALLOWED_MODELS",
            "comma-separated model_name values the harness may call -- no default, ever: this is \
             the ceiling on what a signed task can actually spend against",
        )?);
        if allowed_models.is_empty() {
            return Err("CT_HARNESS_ALLOWED_MODELS resolved to an empty list -- name at least one model".to_string());
        }
        Ok(Self {
            task_location: req(&f, "CT_HARNESS_TASK_URL_OR_PATH", "https:// URL or local path of the signed SignedTask JSON")?,
            manifest_location: req(
                &f,
                "CT_HARNESS_MANIFEST_URL_OR_PATH",
                "the same manifest reference used at `manifest activate` time for this bundle",
            )?,
            allowlist,
            bundle_dir: PathBuf::from(req(
                &f,
                "CT_HARNESS_BUNDLE_DIR",
                "the manifest's own activation directory, <CT_MANIFEST_WORK_DIR>/<project_name>",
            )?),
            litellm_base_url: req(&f, "CT_HARNESS_LITELLM_URL", "base URL of the operator's own LiteLLM proxy")?,
            litellm_key_file: PathBuf::from(req(
                &f,
                "CT_HARNESS_LITELLM_KEY_FILE",
                "path to a file holding a budget-capped LiteLLM virtual key -- never inline",
            )?),
            allowed_models,
            allow_unmarked_bundle: opt(&f, "CT_HARNESS_ALLOW_UNMARKED_BUNDLE").as_deref() == Some("1"),
        })
    }
}

/// Runs the full flow: fetch the task, fetch the manifest it claims to be scoped to, validate that
/// fetched manifest exactly the way `installer_engine::activate` does (signature/expiry via
/// `is_valid`, then the publisher trust allowlist -- `fetch_manifest` alone is unauthenticated JSON
/// parsing, so both checks are required before any of the manifest's fields are trusted), cross-check
/// `manifest_id` and that `bundle_dir` really contains that manifest's `compose_file` (containment-
/// checked against `bundle_dir` the same way the harness's own file tools are, then fail closed on
/// any mismatch -- a task pointed at the wrong bundle must never reach the agent loop), read the
/// LiteLLM key file, then hand off to `harness_core::run_task`.
///
/// `installer_engine`/`harness_core` are entirely synchronous (blocking HTTP, `docker`
/// subprocesses), so the whole flow runs on the blocking pool -- same shape as
/// `manifest_run::run_activate`'s own `tokio::task::spawn_blocking` wrapping, not stalling a
/// runtime worker for the length of an agent-loop run that can legitimately take minutes.
pub async fn run_harness(cfg: HarnessCliConfig) -> Result<harness_core::HarnessReport, String> {
    tokio::task::spawn_blocking(move || run_harness_blocking(cfg))
        .await
        .map_err(|e| format!("harness task failed: {e}"))?
}

fn run_harness_blocking(cfg: HarnessCliConfig) -> Result<harness_core::HarnessReport, String> {
    let task_bytes = installer_engine::fetch::fetch_bytes(&cfg.task_location)
        .map_err(|e| format!("fetch task: {e}"))?;
    let task: SignedTask =
        serde_json::from_slice(&task_bytes).map_err(|e| format!("task at {} is not valid JSON: {e}", cfg.task_location))?;

    let manifest = installer_engine::fetch::fetch_manifest(&cfg.manifest_location)
        .map_err(|e| format!("fetch manifest: {e}"))?;

    let now = crate::manifest_run::unix_now()?;

    // Same two checks `installer_engine::activate` performs immediately after its own
    // `fetch_manifest` call (steps 2-3 of the activate flow) -- `fetch_manifest` is plain JSON
    // parsing with no cryptographic check, so without these, anything served at
    // CT_HARNESS_MANIFEST_URL_OR_PATH with a matching manifest_id (not secret -- observable from
    // the SignedTask itself) would be trusted to say where `rebuild()` runs `docker compose build`.
    if !manifest.is_valid(now) {
        return Err(
            "manifest fetched from CT_HARNESS_MANIFEST_URL_OR_PATH failed signature/expiry validation -- \
             refusing to trust its bundle.compose_file"
                .to_string(),
        );
    }
    if !cfg.allowlist.contains(&manifest.publisher_pubkey) {
        return Err(
            "the manifest fetched from CT_HARNESS_MANIFEST_URL_OR_PATH is signed by a publisher not on \
             CT_HARNESS_TRUST_ALLOWLIST -- refusing to trust its bundle.compose_file"
                .to_string(),
        );
    }

    if manifest.manifest_id != task.manifest_id {
        return Err(format!(
            "task.manifest_id ({}) does not match the manifest fetched from CT_HARNESS_MANIFEST_URL_OR_PATH ({}) -- \
             refusing to run a task against a bundle it wasn't scoped to",
            hex32(&task.manifest_id),
            hex32(&manifest.manifest_id)
        ));
    }

    // Containment-check compose_file against bundle_dir the same way `harness_core`'s own
    // read_file/write_file tools do (symlinks resolved, `..`/absolute paths rejected) -- a bare
    // `bundle_dir.join(..)` would silently discard bundle_dir entirely for an absolute
    // compose_file, letting `rebuild()` build a compose file outside the trusted bundle.
    let expected_compose = harness_core::containment::resolve_in_bundle(&cfg.bundle_dir, &manifest.bundle.compose_file)
        .map_err(|e| format!("manifest bundle.compose_file '{}' is invalid: {e}", manifest.bundle.compose_file))?;
    if !expected_compose.is_file() {
        return Err(format!(
            "{} does not exist -- CT_HARNESS_BUNDLE_DIR does not look like it was actually \
             activated from this manifest",
            expected_compose.display()
        ));
    }

    // The compose file merely EXISTING says nothing about which bundle put it there (#165): the
    // manifest's sha256 is of the tarball, so an unpacked directory cannot be re-hashed against
    // it. The activation marker `manifest activate` leaves behind is the binding instead.
    check_activation_marker(&cfg.bundle_dir, &hex32(&manifest.manifest_id), cfg.allow_unmarked_bundle)?;

    let api_key = std::fs::read_to_string(&cfg.litellm_key_file)
        .map_err(|e| format!("read CT_HARNESS_LITELLM_KEY_FILE {}: {e}", cfg.litellm_key_file.display()))?
        .trim()
        .to_string();
    if api_key.is_empty() {
        return Err(format!("{} is empty -- no LiteLLM key to use", cfg.litellm_key_file.display()));
    }

    let opts = harness_core::RunOptions {
        bundle_dir: cfg.bundle_dir,
        compose_file: manifest.bundle.compose_file,
        litellm_base_url: cfg.litellm_base_url,
        api_key,
        allowed_models: cfg.allowed_models,
        now,
    };
    Ok(harness_core::run_task(&task, &cfg.allowlist, opts))
}

/// The #165 pre-flight: `bundle_dir`'s activation marker must name `expected_manifest_id_hex`.
///
/// - Marker present, same id: ok.
/// - Marker present, different id: refused, both ids named -- the directory holds some OTHER
///   manifest's hash-verified bytes, and a task is only ever scoped to one manifest.
/// - Marker absent: refused unless `allow_unmarked` (`CT_HARNESS_ALLOW_UNMARKED_BUNDLE=1`), in
///   which case a one-line stderr warning is printed and the directory is accepted as-is.
/// - Marker unreadable or not valid JSON: refused, always -- a corrupt marker is not "no marker".
pub(crate) fn check_activation_marker(
    bundle_dir: &Path,
    expected_manifest_id_hex: &str,
    allow_unmarked: bool,
) -> Result<(), String> {
    match read_activation_marker(bundle_dir) {
        Ok(Some(marker)) if marker.manifest_id == expected_manifest_id_hex => Ok(()),
        Ok(Some(marker)) => Err(format!(
            "CT_HARNESS_BUNDLE_DIR {} was activated from manifest {}, not {} (its {ACTIVATION_MARKER_FILE} says \
             so) -- refusing to run a task against a bundle installed from a different manifest (#165)",
            bundle_dir.display(),
            marker.manifest_id,
            expected_manifest_id_hex
        )),
        Ok(None) if allow_unmarked => {
            eprintln!(
                "warning: CT_HARNESS_BUNDLE_DIR {} carries no {ACTIVATION_MARKER_FILE} activation marker -- accepting \
                 it unverified because CT_HARNESS_ALLOW_UNMARKED_BUNDLE=1 (#165)",
                bundle_dir.display()
            );
            Ok(())
        }
        Ok(None) => Err(format!(
            "CT_HARNESS_BUNDLE_DIR {} carries no {ACTIVATION_MARKER_FILE} activation marker -- it was activated by \
             an older ct-agent, or is not an activation directory at all, so nothing binds its contents to \
             manifest {expected_manifest_id_hex}; re-activate it, or set CT_HARNESS_ALLOW_UNMARKED_BUNDLE=1 to \
             accept it explicitly (#165)",
            bundle_dir.display()
        )),
        Err(e) => Err(format!(
            "CT_HARNESS_BUNDLE_DIR {}: {e} -- refusing to trust a bundle directory whose activation marker cannot \
             be read (#165)",
            bundle_dir.display()
        )),
    }
}

fn hex32(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use manifest_core::{BundleRef, EnvVarSpec, InstallerKind, ServiceManifest, VerifySpec};
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    const SHA: &str = "9999999999999999999999999999999999999999999999999999999999999999";

    /// Builds and signs a `ServiceManifest` with `compose_file` pointing at a file that actually
    /// exists inside `bundle_dir` -- so that a test exercising the manifest-trust checks (not the
    /// containment/existence checks) never trips over those instead.
    fn signed_manifest(key: &SigningKey, manifest_id: [u8; 32], issued_at: u64, expires_at: u64) -> ServiceManifest {
        ServiceManifest::sign_new(
            key,
            manifest_id,
            "harness-proof".to_string(),
            "0.1.0".to_string(),
            InstallerKind::Compose,
            BundleRef {
                url: "https://example.invalid/bundle.tar.gz".to_string(),
                sha256: [0u8; 32],
                compose_file: "docker-compose.yml".to_string(),
            },
            Vec::<EnvVarSpec>::new(),
            VerifySpec { script: "verify.sh".to_string(), timeout_secs: 60 },
            issued_at,
            expires_at,
        )
    }

    fn signed_task(key: &SigningKey, task_id: [u8; 32], manifest_id: [u8; 32], issued_at: u64, expires_at: u64) -> SignedTask {
        SignedTask::sign_new(
            key,
            task_id,
            manifest_id,
            "do nothing".to_string(),
            "local-devstral-small2".to_string(),
            1,
            1,
            issued_at,
            expires_at,
        )
    }

    /// Builds a `HarnessCliConfig` pointing at real local files for the task/manifest, with a
    /// bundle_dir that already contains the manifest's `compose_file` -- so a test can isolate the
    /// manifest-trust checks (`is_valid`/allowlist) from the later containment/existence checks.
    fn cfg_for(dir: &std::path::Path, allowlist: TrustAllowlist) -> HarnessCliConfig {
        HarnessCliConfig {
            task_location: dir.join("task.json").to_string_lossy().to_string(),
            manifest_location: dir.join("manifest.json").to_string_lossy().to_string(),
            allowlist,
            bundle_dir: dir.to_path_buf(),
            litellm_base_url: "http://127.0.0.1:1".to_string(),
            litellm_key_file: dir.join("key"),
            allowed_models: vec!["local-devstral-small2".to_string()],
            // Strict, as in production: the existing tests below all fail on an EARLIER check
            // (signature/expiry, allowlist, containment), so they never reach the marker
            // pre-flight; the #165 tests write a marker explicitly where they need one.
            allow_unmarked_bundle: false,
        }
    }

    /// Writes the activation marker `manifest activate` would leave in `dir` for `manifest_id`.
    fn write_marker(dir: &std::path::Path, manifest_id: [u8; 32]) {
        let marker = crate::manifest_run::ActivationMarker {
            manifest_id: hex32(&manifest_id),
            publisher_pubkey: "cd".repeat(32),
            project_name: "harness-proof".to_string(),
            activated_at: 1_700_000_000,
            ct_agent_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        crate::manifest_run::write_activation_marker(dir, &marker).unwrap();
    }

    #[test]
    fn check_activation_marker_refuses_a_marker_naming_a_different_manifest_165() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path(), [7u8; 32]);
        let err = check_activation_marker(dir.path(), &hex32(&[8u8; 32]), false).unwrap_err();
        assert!(err.contains("was activated from manifest"), "{err}");
        assert!(err.contains(&hex32(&[7u8; 32])) && err.contains(&hex32(&[8u8; 32])), "both ids named: {err}");
        // The allow flag only relaxes "must exist", never "must match".
        assert!(check_activation_marker(dir.path(), &hex32(&[8u8; 32]), true).is_err());
    }

    #[test]
    fn check_activation_marker_refuses_a_missing_marker_unless_explicitly_allowed_165() {
        let dir = tempfile::tempdir().unwrap();
        let err = check_activation_marker(dir.path(), &hex32(&[7u8; 32]), false).unwrap_err();
        assert!(err.contains("no ") && err.contains("activation marker"), "{err}");
        assert!(err.contains("CT_HARNESS_ALLOW_UNMARKED_BUNDLE=1"), "the way out must be named: {err}");
        check_activation_marker(dir.path(), &hex32(&[7u8; 32]), true).unwrap();
    }

    #[test]
    fn check_activation_marker_accepts_a_matching_marker_and_refuses_a_corrupt_one_165() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path(), [7u8; 32]);
        check_activation_marker(dir.path(), &hex32(&[7u8; 32]), false).unwrap();

        std::fs::write(dir.path().join(ACTIVATION_MARKER_FILE), b"{ not json").unwrap();
        // Corrupt is not "unmarked": even the allow flag does not wave it through.
        assert!(check_activation_marker(dir.path(), &hex32(&[7u8; 32]), false).is_err());
        assert!(check_activation_marker(dir.path(), &hex32(&[7u8; 32]), true).is_err());
    }

    #[test]
    fn run_harness_blocking_refuses_a_bundle_dir_activated_from_a_different_manifest_165() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest_id = [7u8; 32];
        let now = crate::manifest_run::unix_now().unwrap();
        // Fully trusted manifest (valid, on the allowlist, compose file present and contained)
        // -- only the marker can be the reason for refusal.
        let manifest = signed_manifest(&key, manifest_id, now, now + 7_200);
        let task = signed_task(&key, [9u8; 32], manifest_id, now, now + 7_200);
        std::fs::write(dir.path().join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join("task.json"), serde_json::to_vec(&task).unwrap()).unwrap();
        // The compose file on disk came from some OTHER activation (#165's exact scenario).
        write_marker(dir.path(), [8u8; 32]);

        let allowlist = TrustAllowlist::parse(&hex32(&key.verifying_key().to_bytes())).unwrap();
        let err = run_harness_blocking(cfg_for(dir.path(), allowlist)).unwrap_err();
        assert!(err.contains("was activated from manifest"), "{err}");
        assert!(err.contains(&hex32(&[8u8; 32])) && err.contains(&hex32(&manifest_id)), "{err}");
    }

    #[test]
    fn run_harness_blocking_passes_the_marker_pre_flight_with_a_matching_marker_165() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest_id = [7u8; 32];
        let now = crate::manifest_run::unix_now().unwrap();
        let manifest = signed_manifest(&key, manifest_id, now, now + 7_200);
        let task = signed_task(&key, [9u8; 32], manifest_id, now, now + 7_200);
        std::fs::write(dir.path().join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join("task.json"), serde_json::to_vec(&task).unwrap()).unwrap();
        write_marker(dir.path(), manifest_id);

        // No LiteLLM key file on purpose: the very next step after the marker pre-flight is the
        // key-file read, so failing THERE proves the marker check passed without needing docker.
        let allowlist = TrustAllowlist::parse(&hex32(&key.verifying_key().to_bytes())).unwrap();
        let err = run_harness_blocking(cfg_for(dir.path(), allowlist)).unwrap_err();
        assert!(err.contains("CT_HARNESS_LITELLM_KEY_FILE"), "{err}");
        assert!(!err.contains("activation marker"), "{err}");
    }

    #[test]
    fn run_harness_blocking_rejects_a_manifest_that_fails_signature_expiry_validation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest_id = [7u8; 32];
        // issued/expired deep in the past relative to real wall-clock time -- `is_valid(now)`
        // must fail on expiry regardless of the (otherwise-correct) signature.
        let manifest = signed_manifest(&key, manifest_id, 1_000, 1_001);
        let task = signed_task(&key, [9u8; 32], manifest_id, 1_000, 1_001);
        std::fs::write(dir.path().join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join("task.json"), serde_json::to_vec(&task).unwrap()).unwrap();

        // Publisher IS on the allowlist -- isolates this test to the is_valid/expiry check, not
        // the separate allowlist check.
        let allowlist = TrustAllowlist::parse(&hex32(&key.verifying_key().to_bytes())).unwrap();
        let err = run_harness_blocking(cfg_for(dir.path(), allowlist)).unwrap_err();
        assert!(err.contains("signature/expiry"), "{err}");
    }

    #[test]
    fn run_harness_blocking_rejects_a_validly_signed_manifest_from_a_publisher_not_on_the_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}").unwrap();

        let publisher_key = SigningKey::from_bytes(&[3u8; 32]);
        let untrusted_other_key = SigningKey::from_bytes(&[4u8; 32]);
        let manifest_id = [7u8; 32];
        let now = crate::manifest_run::unix_now().unwrap();
        // Valid signature, not expired -- isolates this test to the allowlist check.
        let manifest = signed_manifest(&publisher_key, manifest_id, now, now + 7_200);
        let task = signed_task(&publisher_key, [9u8; 32], manifest_id, now, now + 7_200);
        std::fs::write(dir.path().join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join("task.json"), serde_json::to_vec(&task).unwrap()).unwrap();

        // Allowlist names a DIFFERENT publisher than the one that actually signed the manifest.
        let allowlist = TrustAllowlist::parse(&hex32(&untrusted_other_key.verifying_key().to_bytes())).unwrap();
        let err = run_harness_blocking(cfg_for(dir.path(), allowlist)).unwrap_err();
        assert!(err.contains("CT_HARNESS_TRUST_ALLOWLIST"), "{err}");
    }

    #[test]
    fn run_harness_blocking_rejects_a_trusted_manifest_whose_compose_file_escapes_the_bundle_dir() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("evil-compose.yml"), "services: {}").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest_id = [7u8; 32];
        let now = crate::manifest_run::unix_now().unwrap();
        let mut manifest = signed_manifest(&key, manifest_id, now, now + 7_200);
        // An absolute path: std::path::Path::join() discards the base for an absolute joined
        // component, so a naive `bundle_dir.join(compose_file)` would silently point outside
        // bundle_dir entirely -- this manifest is otherwise perfectly trusted (valid signature,
        // on the allowlist), so only the containment check can catch this.
        manifest.bundle.compose_file = outside.path().join("evil-compose.yml").to_string_lossy().to_string();
        let task = signed_task(&key, [9u8; 32], manifest_id, now, now + 7_200);
        std::fs::write(dir.path().join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(dir.path().join("task.json"), serde_json::to_vec(&task).unwrap()).unwrap();

        let allowlist = TrustAllowlist::parse(&hex32(&key.verifying_key().to_bytes())).unwrap();
        let err = run_harness_blocking(cfg_for(dir.path(), allowlist)).unwrap_err();
        assert!(err.contains("bundle.compose_file"), "{err}");
    }

    fn full_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CT_HARNESS_TASK_URL_OR_PATH", "/local/task.json"),
            ("CT_HARNESS_MANIFEST_URL_OR_PATH", "/local/manifest.json"),
            ("CT_HARNESS_TRUST_ALLOWLIST", SHA),
            ("CT_HARNESS_BUNDLE_DIR", "/local/bundle"),
            ("CT_HARNESS_LITELLM_URL", "http://172.22.0.1:4103"),
            ("CT_HARNESS_LITELLM_KEY_FILE", "/local/key"),
            ("CT_HARNESS_ALLOWED_MODELS", "local-devstral-small2"),
        ]
    }

    #[test]
    fn parses_a_full_config() {
        let cfg = HarnessCliConfig::from_lookup(lookup(&full_env())).unwrap();
        assert_eq!(cfg.allowed_models, vec!["local-devstral-small2"]);
        assert!(cfg.allowlist.contains(&[0x99; 32]));
        assert!(!cfg.allow_unmarked_bundle, "unmarked bundles are refused unless explicitly allowed (#165)");
    }

    #[test]
    fn allow_unmarked_bundle_is_only_exactly_1_165() {
        for (value, expected) in [("1", true), (" 1 ", true), ("true", false), ("yes", false), ("0", false), ("", false)] {
            let mut env = full_env();
            env.push(("CT_HARNESS_ALLOW_UNMARKED_BUNDLE", value));
            let cfg = HarnessCliConfig::from_lookup(lookup(&env)).unwrap();
            assert_eq!(cfg.allow_unmarked_bundle, expected, "CT_HARNESS_ALLOW_UNMARKED_BUNDLE={value:?}");
        }
    }

    #[test]
    fn refuses_an_empty_allowed_models_list() {
        let mut env = full_env();
        env.retain(|(k, _)| *k != "CT_HARNESS_ALLOWED_MODELS");
        env.push(("CT_HARNESS_ALLOWED_MODELS", " "));
        let err = HarnessCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_HARNESS_ALLOWED_MODELS"), "{err}");
    }

    #[test]
    fn refuses_without_an_explicit_trust_allowlist() {
        let mut env = full_env();
        env.retain(|(k, _)| *k != "CT_HARNESS_TRUST_ALLOWLIST");
        let err = HarnessCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_HARNESS_TRUST_ALLOWLIST"), "{err}");
    }
}
