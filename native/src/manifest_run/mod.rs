//! `ct-agent manifest {create,sign,publish,activate}`: author, sign, publish and install a
//! CADS-agent-marketplace [`ServiceManifest`].
//!
//! Thin CLI glue only -- the schema/crypto live in `manifest-core` and the whole
//! fetch/verify/guardrail/compose/verify pipeline lives in `installer-engine`, exactly as the
//! `channel` subcommands keep their protocol logic in `ct_common`/`ct_control_plane`. What stays
//! here is env parsing, and every parser fails LOUDLY: a missing or malformed value is an error
//! with the variable's name in it, never a guessed default. Nothing security-relevant (a key, a
//! trust allowlist, a compose project name) has a default at all.
//!
//! The three-step split exists so the key is needed exactly once: `create` needs no key and no
//! network, `sign` needs the holder key but no network, `publish` needs the network but no key.
//! An operator can therefore review (and diff) the unsigned skeleton before anything signs it.

use ed25519_dalek::SigningKey;
use installer_engine::allowlist::TrustAllowlist;
use installer_engine::{ActivateOptions, InstallReport};
use manifest_core::{BundleRef, EnvVarSpec, InstallerKind, ServiceManifest, VerifySpec};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default manifest lifetime when `CT_MANIFEST_EXPIRES_IN_SECS` is unset: one year.
const DEFAULT_EXPIRES_IN_SECS: u64 = 31_536_000;

/// Seconds since the Unix epoch.
pub fn unix_now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
}

/// Decode exactly 64 ASCII hex characters into 32 bytes.
///
/// The ASCII-hex check comes BEFORE any indexed slicing. `&s[i..i + 2]` on unchecked input can
/// land mid multi-byte-UTF-8-char and panic instead of returning an error -- the #417 /
/// `grant/src/main.rs::from_hex32` bug class this codebase has already hit twice, and these
/// values (env vars, JSON) are attacker-influenceable. `manifest-core::hex` and
/// `installer-engine::allowlist` apply the same discipline on their side of the boundary.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let digits = s.trim().as_bytes();
    if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (digits[2 * i] as char).to_digit(16)?;
        let lo = (digits[2 * i + 1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// A required env value: present and non-blank, or the `X required (…)` error.
fn req<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<String, String> {
    match f(key).map(|v| v.trim().to_string()) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} required ({what})")),
    }
}

/// An optional env value, normalized to `None` when blank.
fn opt<F: Fn(&str) -> Option<String>>(f: &F, key: &str) -> Option<String> {
    f(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn req_u64<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<u64, String> {
    req(f, key, what)?.parse::<u64>().map_err(|e| format!("{key} invalid: {e}"))
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|t| !t.is_empty()).map(str::to_string).collect()
}

/// A manifest before it is signed: every field [`ServiceManifest::sign_new`] needs except the ones
/// only the key can produce (`publisher_pubkey`, `signature`) and the `manifest_id` `sign` mints.
///
/// `deny_unknown_fields` on purpose: a typo'd field in a hand-edited skeleton, or a fully SIGNED
/// manifest piped into `sign` by mistake, must fail loudly rather than be silently dropped and
/// signed as something the author did not write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedManifest {
    pub name: String,
    pub version: String,
    pub installer_kind: InstallerKind,
    pub bundle: BundleRef,
    pub env_template: Vec<EnvVarSpec>,
    pub verify: VerifySpec,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl UnsignedManifest {
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize unsigned manifest: {e}"))
    }
}

/// `ct-agent manifest create`: the env config for an unsigned skeleton. No key, no network.
#[derive(Debug)]
pub struct CreateConfig {
    pub name: String,
    pub version: String,
    pub installer_kind: InstallerKind,
    pub bundle: BundleRef,
    pub env_template: Vec<EnvVarSpec>,
    pub verify: VerifySpec,
    pub expires_in_secs: u64,
}

impl CreateConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let sha256_hex = req(&f, "CT_MANIFEST_BUNDLE_SHA256", "64 hex; sha256 of the bundle tarball")?;
        let sha256 = hex32(&sha256_hex)
            .ok_or("CT_MANIFEST_BUNDLE_SHA256 must be exactly 64 ASCII hex characters")?;
        let expires_in_secs = match opt(&f, "CT_MANIFEST_EXPIRES_IN_SECS") {
            Some(s) => s.parse::<u64>().map_err(|e| format!("CT_MANIFEST_EXPIRES_IN_SECS invalid: {e}"))?,
            None => DEFAULT_EXPIRES_IN_SECS,
        };
        if expires_in_secs == 0 {
            return Err("CT_MANIFEST_EXPIRES_IN_SECS must be greater than 0".to_string());
        }
        // Absent defaults to Compose (Phase 1's only kind, and still the common case) --
        // Binary (Phase 5) is opt-in via an explicit value, never inferred. K8s is accepted here
        // too (the schema slot exists) but `installer-engine::activate` still hard-rejects it;
        // `create` doesn't second-guess that, it just builds the skeleton the operator asked for.
        let installer_kind = match opt(&f, "CT_MANIFEST_KIND").as_deref() {
            None | Some("compose") => InstallerKind::Compose,
            Some("binary") => InstallerKind::Binary,
            Some("k8s") => InstallerKind::K8s,
            Some(other) => return Err(format!("CT_MANIFEST_KIND '{other}' is not one of compose|binary|k8s")),
        };
        Ok(Self {
            name: req(&f, "CT_MANIFEST_NAME", "the service's name")?,
            version: req(&f, "CT_MANIFEST_VERSION", "the service's version")?,
            installer_kind,
            bundle: BundleRef {
                url: req(&f, "CT_MANIFEST_BUNDLE_URL", "https:// URL of the bundle tarball")?,
                sha256,
                compose_file: req(
                    &f,
                    "CT_MANIFEST_COMPOSE_FILE",
                    "path INSIDE the bundle to the compose file (Compose kind) or the executable (Binary kind)",
                )?,
            },
            // Absent/blank is legitimate: a service that needs no operator-supplied secret has an
            // empty env_template. Present-but-malformed is not, and fails loudly below.
            env_template: parse_env_vars(&opt(&f, "CT_MANIFEST_ENV_VARS").unwrap_or_default())?,
            verify: VerifySpec {
                script: req(&f, "CT_MANIFEST_VERIFY_SCRIPT", "path to verify.sh INSIDE the bundle")?,
                timeout_secs: req_u64(
                    &f,
                    "CT_MANIFEST_VERIFY_TIMEOUT_SECS",
                    "seconds the verify script may run",
                )?,
            },
            expires_in_secs,
        })
    }

    /// Build the unsigned skeleton, `installer_kind` as resolved in `from_lookup` above (Compose
    /// unless `CT_MANIFEST_KIND` says otherwise).
    pub fn unsigned(self, now: u64) -> UnsignedManifest {
        UnsignedManifest {
            name: self.name,
            version: self.version,
            installer_kind: self.installer_kind,
            bundle: self.bundle,
            env_template: self.env_template,
            verify: self.verify,
            issued_at: now,
            expires_at: now.saturating_add(self.expires_in_secs),
        }
    }
}

/// Parse `CT_MANIFEST_ENV_VARS`: `;`-separated `NAME:required:description` entries, e.g.
/// `LITELLM_MASTER_KEY:true:proxy admin key;REDIS_PASSWORD:true:redis auth`.
///
/// NAMES only -- a manifest never carries a secret VALUE (see `manifest-core`'s module doc).
/// Split into at most three parts so a description may itself contain `:`.
fn parse_env_vars(s: &str) -> Result<Vec<EnvVarSpec>, String> {
    let shape = "expected NAME:required:description (required = true|false)";
    let mut out = Vec::new();
    for entry in s.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let mut parts = entry.splitn(3, ':');
        let name = parts.next().unwrap_or_default().trim();
        let (Some(required), Some(description)) = (parts.next(), parts.next()) else {
            return Err(format!("CT_MANIFEST_ENV_VARS entry '{entry}': {shape}"));
        };
        if name.is_empty() {
            return Err(format!("CT_MANIFEST_ENV_VARS entry '{entry}': empty variable name, {shape}"));
        }
        let required = match required.trim().to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            other => {
                return Err(format!(
                    "CT_MANIFEST_ENV_VARS entry '{entry}': required flag is '{other}', {shape}"
                ))
            }
        };
        out.push(EnvVarSpec {
            name: name.to_string(),
            required,
            description: description.trim().to_string(),
        });
    }
    Ok(out)
}

/// Read the manifest JSON `sign`/`publish` operate on: `CT_MANIFEST_IN` if set, else stdin.
pub fn read_manifest_input() -> Result<String, String> {
    read_manifest_input_from(&|k| std::env::var(k).ok(), &mut std::io::stdin())
}

fn read_manifest_input_from<F: Fn(&str) -> Option<String>>(
    f: &F,
    stdin: &mut impl std::io::Read,
) -> Result<String, String> {
    let raw = match opt(f, "CT_MANIFEST_IN") {
        Some(path) => std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?,
        None => {
            let mut buf = String::new();
            std::io::Read::read_to_string(stdin, &mut buf)
                .map_err(|e| format!("read manifest JSON from stdin: {e}"))?;
            buf
        }
    };
    if raw.trim().is_empty() {
        return Err("no manifest JSON on stdin (pipe it in, or set CT_MANIFEST_IN to a file)".into());
    }
    Ok(raw)
}

/// Sign `unsigned_json` with `holder`. `manifest_id` is injected so the caller owns the randomness
/// (and tests stay deterministic); `publisher_pubkey` is always derived from the key by `sign_new`,
/// so a caller can never mint a manifest claiming a key it does not hold.
pub fn sign_manifest(
    unsigned_json: &str,
    holder: &SigningKey,
    manifest_id: [u8; 32],
) -> Result<ServiceManifest, String> {
    let unsigned: UnsignedManifest = serde_json::from_str(unsigned_json)
        .map_err(|e| format!("input is not a valid unsigned manifest: {e}"))?;
    if unsigned.expires_at <= unsigned.issued_at {
        return Err(format!(
            "refusing to sign: expires_at ({}) is not after issued_at ({}) -- the manifest would \
             never be valid",
            unsigned.expires_at, unsigned.issued_at
        ));
    }
    Ok(ServiceManifest::sign_new(
        holder,
        manifest_id,
        unsigned.name,
        unsigned.version,
        unsigned.installer_kind,
        unsigned.bundle,
        unsigned.env_template,
        unsigned.verify,
        unsigned.issued_at,
        unsigned.expires_at,
    ))
}

/// `ct-agent manifest sign`: read the unsigned JSON, sign it with `CT_MANIFEST_HOLDER_KEY`, return
/// the signed manifest JSON.
pub fn run_sign() -> Result<String, String> {
    let f = |k: &str| std::env::var(k).ok();
    let seed = hex32(&req(
        &f,
        "CT_MANIFEST_HOLDER_KEY",
        "64 hex; the publisher's ed25519 holder PRIVATE key, same format as CT_CHANNEL_HOLDER_KEY",
    )?)
    .ok_or("CT_MANIFEST_HOLDER_KEY must be exactly 64 ASCII hex characters")?;
    let holder = SigningKey::from_bytes(&seed);
    let input = read_manifest_input()?;
    let mut manifest_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut manifest_id);
    let signed = sign_manifest(&input, &holder, manifest_id)?;
    serde_json::to_string_pretty(&signed).map_err(|e| format!("serialize signed manifest: {e}"))
}

/// `ct-agent manifest publish`: PUT a signed manifest where the operator points us.
///
/// Phase 1 has no registry service -- this is deliberately a dumb PUT to an operator-supplied
/// object-storage URL. The manifest's own signature, not the transport, is what makes it
/// trustworthy at activation time; HTTPS is still required because `installer-engine` refuses to
/// fetch over plain HTTP, so a manifest published to an `http://` URL would be unusable.
pub async fn run_publish() -> Result<(), String> {
    let f = |k: &str| std::env::var(k).ok();
    let url = req(&f, "CT_MANIFEST_PUBLISH_URL", "https:// URL to PUT the signed manifest to")?;
    if !url.starts_with("https://") {
        return Err(format!(
            "CT_MANIFEST_PUBLISH_URL must be https:// (got '{url}') -- installer-engine refuses to \
             fetch a manifest over plain HTTP, so this one could never be activated"
        ));
    }
    let body = read_manifest_input()?;
    // Parse + verify before uploading: publishing a manifest that no one could ever activate is a
    // silent failure that only surfaces on someone else's machine.
    let manifest: ServiceManifest = serde_json::from_str(&body)
        .map_err(|e| format!("input is not a valid signed manifest: {e}"))?;
    let now = unix_now()?;
    if manifest.expires_at <= now {
        return Err(format!(
            "refusing to publish: manifest expired at {} (now {now})",
            manifest.expires_at
        ));
    }
    if !manifest.is_valid(now) {
        return Err(
            "refusing to publish: the signature does not verify against publisher_pubkey -- sign \
             it with `ct-agent manifest sign` and do not edit the JSON afterwards"
                .to_string(),
        );
    }

    // A bare `reqwest::Client::new()` has no request timeout -- a stalled
    // publish endpoint would hang `ct-agent manifest publish` indefinitely
    // rather than surfacing a clear error. Same bug class as #54.
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
        .put(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("PUT {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let detail: String = resp.text().await.unwrap_or_default().trim().chars().take(200).collect();
        return Err(format!("PUT {url}: HTTP {status}{}", if detail.is_empty() {
            String::new()
        } else {
            format!(" -- {detail}")
        }));
    }
    eprintln!("published manifest {} to {url}", hex_encode(&manifest.manifest_id));
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `ct-agent manifest activate`: env config for [`installer_engine::activate`].
#[derive(Debug)]
pub struct ActivateCliConfig {
    /// `CT_MANIFEST_URL` -- an https:// URL or a local file path (installer-engine handles both).
    pub manifest_location: String,
    pub allowlist: TrustAllowlist,
    pub env_file: Option<PathBuf>,
    pub project_name: String,
    pub protected_name_substrings: Vec<String>,
    pub work_dir: PathBuf,
}

impl ActivateCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let inline = opt(&f, "CT_MANIFEST_TRUST_ALLOWLIST");
        let file = opt(&f, "CT_MANIFEST_TRUST_ALLOWLIST_FILE");
        // An empty allowlist trusts NOTHING (installer-engine's deliberate choice), so an absent
        // one would reject every manifest with a confusing "publisher_not_on_trust_allowlist".
        // Say what is actually missing instead. Both set is ambiguous about which one is in
        // force -- for the one input that decides whether foreign code runs on this host, refuse
        // to guess.
        let allowlist = match (inline, file) {
            (Some(_), Some(_)) => {
                return Err("set exactly one of CT_MANIFEST_TRUST_ALLOWLIST or \
                            CT_MANIFEST_TRUST_ALLOWLIST_FILE, not both"
                    .to_string())
            }
            (Some(csv), None) => TrustAllowlist::parse(&csv)?,
            (None, Some(path)) => TrustAllowlist::load_file(std::path::Path::new(&path))?,
            (None, None) => {
                return Err("CT_MANIFEST_TRUST_ALLOWLIST (comma-separated 64-hex publisher \
                            pubkeys) or CT_MANIFEST_TRUST_ALLOWLIST_FILE (one per line) required \
                            -- activation trusts no publisher unless you name it explicitly"
                    .to_string())
            }
        };
        if allowlist.is_empty() {
            return Err("the configured publisher trust allowlist is empty -- it would reject \
                        every manifest; name at least one 64-hex publisher pubkey"
                .to_string());
        }
        Ok(Self {
            manifest_location: req(
                &f,
                "CT_MANIFEST_URL",
                "https:// URL or local path of the signed manifest JSON",
            )?,
            allowlist,
            env_file: opt(&f, "CT_MANIFEST_ENV_FILE").map(PathBuf::from),
            // No default, ever: the compose project name is what keeps this install from
            // colliding with real infrastructure, so it must be an explicit operator choice.
            project_name: req(
                &f,
                "CT_MANIFEST_PROJECT_NAME",
                "the isolated docker compose project name for this install",
            )?,
            protected_name_substrings: split_csv(
                &opt(&f, "CT_MANIFEST_PROTECTED_NAMES").unwrap_or_default(),
            ),
            work_dir: PathBuf::from(req(
                &f,
                "CT_MANIFEST_WORK_DIR",
                "a scratch directory to unpack the bundle into",
            )?),
        })
    }
}

/// Run the activation. `installer-engine` is entirely synchronous (blocking HTTP, `docker`
/// subprocesses, `verify.sh`), so it goes on the blocking pool rather than stalling a runtime
/// worker for the length of a `docker compose up --build`.
pub async fn run_activate(cfg: ActivateCliConfig) -> Result<InstallReport, String> {
    let now = unix_now()?;
    std::fs::create_dir_all(&cfg.work_dir)
        .map_err(|e| format!("create CT_MANIFEST_WORK_DIR {}: {e}", cfg.work_dir.display()))?;
    let opts = ActivateOptions {
        manifest_location: cfg.manifest_location,
        allowlist: cfg.allowlist,
        env_file: cfg.env_file,
        project_name: cfg.project_name,
        protected_name_substrings: cfg.protected_name_substrings,
        work_dir: cfg.work_dir,
        now,
    };
    tokio::task::spawn_blocking(move || installer_engine::activate(opts))
        .await
        .map_err(|e| format!("activation task failed: {e}"))
}

/// Whether the install actually succeeded -- the caller exits non-zero when it did not, so that
/// `ct-agent manifest activate && …` means what it looks like it means.
pub fn report_is_ok(report: &InstallReport) -> bool {
    matches!(report, InstallReport::Ok { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    fn create_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CT_MANIFEST_NAME", "litellm-proof"),
            ("CT_MANIFEST_VERSION", "0.1.0"),
            ("CT_MANIFEST_BUNDLE_URL", "https://example.invalid/bundle.tar.gz"),
            ("CT_MANIFEST_BUNDLE_SHA256", "aa"),
            ("CT_MANIFEST_COMPOSE_FILE", "docker-compose.yml"),
            ("CT_MANIFEST_VERIFY_SCRIPT", "verify.sh"),
            ("CT_MANIFEST_VERIFY_TIMEOUT_SECS", "60"),
        ]
    }

    fn with_sha(mut env: Vec<(&'static str, &'static str)>, sha: &'static str) -> Vec<(&'static str, &'static str)> {
        for pair in env.iter_mut() {
            if pair.0 == "CT_MANIFEST_BUNDLE_SHA256" {
                pair.1 = sha;
            }
        }
        env
    }

    const SHA: &str = "9999999999999999999999999999999999999999999999999999999999999999";

    #[test]
    fn hex32_rejects_non_ascii_instead_of_panicking() {
        // 32 * 2-byte chars = 64 bytes: passes a naive length check, and a naive `&s[i..i+2]`
        // slice would panic mid-char (#417 / from_hex32).
        assert_eq!(hex32(&"é".repeat(32)), None);
        assert_eq!(hex32("aa"), None, "short input is not 32 bytes");
        assert_eq!(hex32(SHA), Some([0x99; 32]));
    }

    #[test]
    fn create_requires_every_security_relevant_field() {
        for missing in [
            "CT_MANIFEST_NAME",
            "CT_MANIFEST_VERSION",
            "CT_MANIFEST_BUNDLE_URL",
            "CT_MANIFEST_BUNDLE_SHA256",
            "CT_MANIFEST_COMPOSE_FILE",
            "CT_MANIFEST_VERIFY_SCRIPT",
            "CT_MANIFEST_VERIFY_TIMEOUT_SECS",
        ] {
            let env: Vec<_> =
                with_sha(create_env(), SHA).into_iter().filter(|(k, _)| *k != missing).collect();
            let err = CreateConfig::from_lookup(lookup(&env)).unwrap_err();
            assert!(err.contains(missing), "missing {missing} must be named in: {err}");
        }
    }

    #[test]
    fn create_rejects_a_short_bundle_hash_rather_than_padding_it() {
        let err = CreateConfig::from_lookup(lookup(&create_env())).unwrap_err();
        assert!(err.contains("CT_MANIFEST_BUNDLE_SHA256"), "{err}");
    }

    #[test]
    fn create_defaults_only_the_expiry_and_produces_a_signable_skeleton() {
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        assert_eq!(cfg.expires_in_secs, DEFAULT_EXPIRES_IN_SECS);
        let unsigned = cfg.unsigned(1_000);
        assert_eq!(unsigned.installer_kind, InstallerKind::Compose);
        assert_eq!(unsigned.issued_at, 1_000);
        assert_eq!(unsigned.expires_at, 1_000 + DEFAULT_EXPIRES_IN_SECS);
        assert!(unsigned.env_template.is_empty(), "no CT_MANIFEST_ENV_VARS -> no declared vars");
        let json = unsigned.to_json().unwrap();
        assert_eq!(serde_json::from_str::<UnsignedManifest>(&json).unwrap(), unsigned);
    }

    #[test]
    fn create_kind_binary_produces_an_installer_kind_binary_skeleton() {
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_KIND", "binary"));
        let cfg = CreateConfig::from_lookup(lookup(&env)).unwrap();
        assert_eq!(cfg.unsigned(1_000).installer_kind, InstallerKind::Binary);
    }

    #[test]
    fn create_kind_rejects_an_unknown_value_rather_than_defaulting() {
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_KIND", "docker-swarm"));
        let err = CreateConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_KIND"), "{err}");
        assert!(err.contains("docker-swarm"), "{err}");
    }

    #[test]
    fn env_vars_parse_a_semicolon_list_and_keep_colons_in_the_description() {
        let specs =
            parse_env_vars("LITELLM_MASTER_KEY:true:proxy admin key;PORT:false:host:port to bind")
                .unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "LITELLM_MASTER_KEY");
        assert!(specs[0].required);
        assert!(!specs[1].required);
        assert_eq!(specs[1].description, "host:port to bind");
    }

    #[test]
    fn env_vars_reject_a_malformed_entry_rather_than_dropping_it() {
        // Silently dropping a malformed entry would omit a REQUIRED variable from the signed
        // manifest, so activation would happily start the service without it.
        assert!(parse_env_vars("LITELLM_MASTER_KEY").is_err());
        assert!(parse_env_vars("LITELLM_MASTER_KEY:true").is_err());
        assert!(parse_env_vars("LITELLM_MASTER_KEY:yes:desc").is_err());
        assert!(parse_env_vars(":true:desc").is_err());
    }

    #[test]
    fn sign_round_trips_and_binds_to_the_signing_key() {
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        let json = cfg.unsigned(1_000).to_json().unwrap();
        let holder = SigningKey::from_bytes(&[3u8; 32]);
        let signed = sign_manifest(&json, &holder, [7u8; 32]).unwrap();
        assert!(signed.is_valid(1_500));
        assert_eq!(signed.publisher_pubkey, holder.verifying_key().to_bytes());
        assert_eq!(signed.manifest_id, [7u8; 32]);
    }

    #[test]
    fn sign_refuses_input_that_is_not_an_unsigned_manifest() {
        let holder = SigningKey::from_bytes(&[3u8; 32]);
        assert!(sign_manifest("not json", &holder, [0u8; 32]).is_err());
        // An already-signed manifest carries fields `UnsignedManifest` denies -- re-signing one
        // would silently drop the original publisher_pubkey/signature.
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        let json = cfg.unsigned(1_000).to_json().unwrap();
        let signed = sign_manifest(&json, &holder, [7u8; 32]).unwrap();
        let signed_json = serde_json::to_string(&signed).unwrap();
        assert!(sign_manifest(&signed_json, &holder, [8u8; 32]).is_err());
    }

    #[test]
    fn sign_refuses_a_window_that_could_never_be_valid() {
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        let mut unsigned = cfg.unsigned(1_000);
        unsigned.expires_at = unsigned.issued_at;
        let holder = SigningKey::from_bytes(&[3u8; 32]);
        let err = sign_manifest(&unsigned.to_json().unwrap(), &holder, [7u8; 32]).unwrap_err();
        assert!(err.contains("expires_at"), "{err}");
    }

    #[test]
    fn activate_refuses_to_run_without_an_explicit_trust_allowlist() {
        let base = [
            ("CT_MANIFEST_URL", "https://example.invalid/m.json"),
            ("CT_MANIFEST_PROJECT_NAME", "proof-run"),
            ("CT_MANIFEST_WORK_DIR", "/tmp/does-not-matter"),
        ];
        let err = ActivateCliConfig::from_lookup(lookup(&base)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_TRUST_ALLOWLIST"), "{err}");

        let mut both = base.to_vec();
        both.push(("CT_MANIFEST_TRUST_ALLOWLIST", SHA));
        both.push(("CT_MANIFEST_TRUST_ALLOWLIST_FILE", "/tmp/list"));
        let err = ActivateCliConfig::from_lookup(lookup(&both)).unwrap_err();
        assert!(err.contains("not both"), "{err}");

        let mut empty = base.to_vec();
        empty.push(("CT_MANIFEST_TRUST_ALLOWLIST", " "));
        let err = ActivateCliConfig::from_lookup(lookup(&empty)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_TRUST_ALLOWLIST"), "{err}");
    }

    #[test]
    fn activate_requires_an_operator_chosen_project_name() {
        let env = [
            ("CT_MANIFEST_URL", "https://example.invalid/m.json"),
            ("CT_MANIFEST_WORK_DIR", "/tmp/does-not-matter"),
            ("CT_MANIFEST_TRUST_ALLOWLIST", SHA),
        ];
        let err = ActivateCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_PROJECT_NAME"), "{err}");
    }

    #[test]
    fn activate_parses_a_full_config() {
        let env = [
            ("CT_MANIFEST_URL", "/local/path/manifest.json"),
            ("CT_MANIFEST_PROJECT_NAME", "proof-run"),
            ("CT_MANIFEST_WORK_DIR", "/tmp/work"),
            ("CT_MANIFEST_TRUST_ALLOWLIST", SHA),
            ("CT_MANIFEST_ENV_FILE", "/local/secrets.env"),
            ("CT_MANIFEST_PROTECTED_NAMES", "litellm-proxy, cads-tunnel"),
        ];
        let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
        assert!(cfg.allowlist.contains(&[0x99; 32]));
        assert_eq!(cfg.env_file, Some(PathBuf::from("/local/secrets.env")));
        assert_eq!(cfg.protected_name_substrings, vec!["litellm-proxy", "cads-tunnel"]);
    }

    #[test]
    fn manifest_input_comes_from_stdin_when_no_file_is_configured() {
        let f = lookup(&[]);
        let mut stdin = std::io::Cursor::new(b"{\"a\":1}".to_vec());
        assert_eq!(read_manifest_input_from(&f, &mut stdin).unwrap(), "{\"a\":1}");
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(read_manifest_input_from(&f, &mut empty).is_err(), "empty stdin must fail loudly");
    }
}
