//! `ct-agent harness run` (CADS-agent-marketplace Phase 2): run a signed
//! [`manifest_core::SignedTask`] against `harness_core`'s bounded agent loop, scoped to exactly
//! one already-activated manifest's own bundle directory.
//!
//! Thin CLI glue only -- the whole agent loop, tool set, and containment logic lives in
//! `harness_core`, exactly the same layering as `manifest_run` keeping its logic in
//! `installer_engine`. What stays here is env parsing (same fail-loudly, no-silent-default style
//! as `manifest_run::ActivateCliConfig`) and the one defense-in-depth check that's specific to
//! this CLI: confirming `CT_HARNESS_BUNDLE_DIR` really looks like it was installed from the
//! manifest the task claims to be scoped to, before handing control to the agent loop.

use installer_engine::allowlist::TrustAllowlist;
use manifest_core::SignedTask;
use std::path::PathBuf;

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
            bundle_dir: PathBuf::from(req(&f, "CT_HARNESS_BUNDLE_DIR", "the manifest's own already-activated work_dir")?),
            litellm_base_url: req(&f, "CT_HARNESS_LITELLM_URL", "base URL of the operator's own LiteLLM proxy")?,
            litellm_key_file: PathBuf::from(req(
                &f,
                "CT_HARNESS_LITELLM_KEY_FILE",
                "path to a file holding a budget-capped LiteLLM virtual key -- never inline",
            )?),
            allowed_models,
        })
    }
}

/// Runs the full flow: fetch the task, fetch the manifest it claims to be scoped to, cross-check
/// `manifest_id` and that `bundle_dir` really contains that manifest's `compose_file` (fail closed
/// on any mismatch -- a task pointed at the wrong bundle must never reach the agent loop), read
/// the LiteLLM key file, then hand off to `harness_core::run_task`.
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

    if manifest.manifest_id != task.manifest_id {
        return Err(format!(
            "task.manifest_id ({}) does not match the manifest fetched from CT_HARNESS_MANIFEST_URL_OR_PATH ({}) -- \
             refusing to run a task against a bundle it wasn't scoped to",
            hex32(&task.manifest_id),
            hex32(&manifest.manifest_id)
        ));
    }
    let expected_compose = cfg.bundle_dir.join(&manifest.bundle.compose_file);
    if !expected_compose.is_file() {
        return Err(format!(
            "{} does not exist -- CT_HARNESS_BUNDLE_DIR does not look like it was actually \
             activated from this manifest",
            expected_compose.display()
        ));
    }

    let api_key = std::fs::read_to_string(&cfg.litellm_key_file)
        .map_err(|e| format!("read CT_HARNESS_LITELLM_KEY_FILE {}: {e}", cfg.litellm_key_file.display()))?
        .trim()
        .to_string();
    if api_key.is_empty() {
        return Err(format!("{} is empty -- no LiteLLM key to use", cfg.litellm_key_file.display()));
    }

    let now = crate::manifest_run::unix_now()?;
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
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    const SHA: &str = "9999999999999999999999999999999999999999999999999999999999999999";

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
