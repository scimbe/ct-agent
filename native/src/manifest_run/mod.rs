//! `ct-agent manifest {create,sign,publish,activate,plan}`: author, sign, publish, install -- or
//! dry-run -- a CADS-agent-marketplace [`ServiceManifest`].
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
//!
//! `activate` never unpacks a bundle over existing files (#165). `CT_MANIFEST_WORK_DIR` is only
//! the PARENT: each activation gets its own `<CT_MANIFEST_WORK_DIR>/<CT_MANIFEST_PROJECT_NAME>`,
//! which must not exist yet or must be empty -- `installer-engine` writes tar entries without
//! checking what is already there, so reusing one fixed directory would let a later bundle
//! silently overwrite an earlier, hash-verified one. A successful activation then leaves an
//! [`ActivationMarker`] (`.ct-agent-activation.json`) in that directory recording which manifest
//! the bytes on disk came from; `harness run` refuses a bundle directory whose marker names a
//! different manifest, so the fetch -> hash -> signature -> activate chain stays bound to the
//! directory the harness later rebuilds from.
//!
//! Sandbox phase 1 (scimbe/ct-agent#183): a manifest may carry an [`EnvironmentContract`]
//! (`CT_MANIFEST_ENVIRONMENT_JSON` at `create`, signed at `sign`); a Binary activation is refused
//! when no sandbox backend is usable unless the operator opts out with `CT_ALLOW_UNSANDBOXED=1`
//! (read through `installer_engine::require_binary_sandbox_from_env`, the one place that
//! semantics lives); and `plan` computes what `activate` WOULD do on this host -- backend, argv
//! preview, compose hardening, every refusal -- without fetching a bundle or running anything.

use ed25519_dalek::SigningKey;
use installer_engine::allowlist::TrustAllowlist;
use installer_engine::{ActivateOptions, GuardrailPolicy, InstallReport, Plan, PlanOptions};
use manifest_core::{BundleRef, EnvVarSpec, EnvironmentContract, InstallerKind, ServiceManifest, VerifySpec};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default manifest lifetime when `CT_MANIFEST_EXPIRES_IN_SECS` is unset: one year.
const DEFAULT_EXPIRES_IN_SECS: u64 = 31_536_000;

/// Seconds since the Unix epoch.
pub fn unix_now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
}

/// `CT_MANIFEST_REGISTRY_URL` carries `CT_MANIFEST_REGISTRY_WRITE_TOKEN` as a Bearer header on
/// every request -- both the publish POST (which also carries the full signed manifest and bundle
/// bytes) and the activation-ledger POST -- so it gets the same https:// discipline this file
/// already applies to `CT_MANIFEST_PUBLISH_URL`/`CT_MANIFEST_BUNDLE_URL`/`CT_MANIFEST_URL`. Unlike
/// those (which only ever point at real object storage), a registry is realistically also run
/// locally during development, so plain `http://` is allowed for loopback and nowhere else: a
/// typo'd or misconfigured non-loopback `http://` endpoint would otherwise silently leak the write
/// token and the manifest/bundle bytes in cleartext to anyone on path, with no warning from the
/// tool -- exactly the class of bug the https:// checks elsewhere in this file exist to prevent.
fn require_registry_url_scheme(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        // Strip userinfo (`user:pass@host`) before host extraction (#97): without this, an
        // authority like `127.0.0.1:8787@evil.invalid` string-splits on `:` to `127.0.0.1`
        // here (loopback exception granted) while reqwest/the `url` crate parse
        // `127.0.0.1:8787` as userinfo and actually connect to `evil.invalid` -- the two
        // parsers disagreeing lets the real request leak the write token and manifest/bundle
        // bytes in cleartext to whatever host is named after the `@`. `rsplit` (not `split`)
        // keeps the LAST `@`-separated segment, matching how userinfo parsing works even if
        // the (URL-illegal but not rejected by this string-split guard) userinfo itself
        // contains an `@`.
        let host = authority.rsplit('@').next().unwrap_or(authority);
        // Bracketed IPv6 (`[::1]:8787`) needs its own split -- a bare `:` split would chop it
        // apart at every colon inside the address itself.
        let host = match host.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next().unwrap_or(""),
            None => host.split(':').next().unwrap_or(""),
        };
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Ok(());
        }
    }
    Err(format!(
        "CT_MANIFEST_REGISTRY_URL must be https:// (got '{url}') -- it carries \
         CT_MANIFEST_REGISTRY_WRITE_TOKEN plus the manifest/bundle bytes on every request, so a \
         non-loopback http:// endpoint would leak all of it in cleartext to anyone on path; \
         http://127.0.0.1, http://localhost or http://[::1] is allowed for local development"
    ))
}

/// ct-agent#170: the one place `CT_MANIFEST_URL` (and, through `bridge/manifest-install`, a
/// caller-supplied `manifest_location`) is checked before `installer-engine` fetches it.
/// `https://` is the only location accepted by default. A local path is accepted only when the
/// AGENT sets `CT_MANIFEST_ALLOW_LOCAL_PATH=1` (`allow_local_path`) -- never the caller: the
/// bridge peer chooses WHICH manifest, and without this gate it could probe this host's
/// filesystem (an existence oracle) or reach internal `http://` services from the agent's own
/// network position. `http://`, `file://` and every other scheme are refused with the reason
/// named, whatever the flag says.
fn require_manifest_location(location: &str, allow_local_path: bool) -> Result<(), String> {
    if location.starts_with("https://") {
        return Ok(());
    }
    if location.starts_with("http://") {
        return Err(format!(
            "CT_MANIFEST_URL must be https:// (got '{location}') -- a manifest fetched over \
             cleartext http:// could be swapped on path, and via bridge/manifest-install a \
             caller could aim this agent at internal HTTP services (ct-agent#170)"
        ));
    }
    if location.starts_with("file://") {
        return Err(format!(
            "CT_MANIFEST_URL does not accept file:// (got '{location}') -- to activate a manifest \
             from a local file, pass its bare path and set CT_MANIFEST_ALLOW_LOCAL_PATH=1 on this \
             agent (ct-agent#170)"
        ));
    }
    if let Some(scheme) = location.split_once("://").map(|(scheme, _)| scheme) {
        return Err(format!(
            "CT_MANIFEST_URL must be https:// (got unsupported scheme '{scheme}://') (ct-agent#170)"
        ));
    }
    if allow_local_path {
        return Ok(());
    }
    Err(format!(
        "CT_MANIFEST_URL must be an https:// URL (got a local path '{location}') -- set \
         CT_MANIFEST_ALLOW_LOCAL_PATH=1 on this agent to activate manifests from local files; \
         the flag is read from the agent's own environment only, never from a caller \
         (ct-agent#170)"
    ))
}

/// `1`/`true`/`yes` (case-insensitive, trimmed) is set; anything else -- including unset -- is not.
fn flag_set(v: Option<String>) -> bool {
    matches!(
        v.as_deref().map(str::trim),
        Some(s) if s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes")
    )
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
    /// Optional environment contract (scimbe/ct-agent#183). Absent means the strictest profile
    /// (`EnvironmentContract::default`), never "unrestricted" -- so a skeleton written before
    /// this field existed still parses, signs, and means exactly what it meant then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentContract>,
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
    /// `CT_MANIFEST_ENVIRONMENT_JSON`, parsed and validated; `None` when unset.
    pub environment: Option<EnvironmentContract>,
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
        let environment = opt(&f, "CT_MANIFEST_ENVIRONMENT_JSON").map(|json| parse_environment_json(&json)).transpose()?;
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
            environment,
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
            environment: self.environment,
        }
    }
}

/// Parse `CT_MANIFEST_ENVIRONMENT_JSON`: an [`EnvironmentContract`] as JSON (every field optional,
/// `{}` is the strictest default profile). Parsed AND validated here, so a contract that
/// `installer-engine` would refuse at activation never gets as far as being signed; both error
/// paths name the variable, and a validation error additionally names the offending field
/// (`environment.resources.wall_secs must be > 0`, ...).
fn parse_environment_json(json: &str) -> Result<EnvironmentContract, String> {
    let env: EnvironmentContract =
        serde_json::from_str(json).map_err(|e| format!("CT_MANIFEST_ENVIRONMENT_JSON invalid: {e}"))?;
    env.validate().map_err(|e| format!("CT_MANIFEST_ENVIRONMENT_JSON invalid: {e}"))?;
    Ok(env)
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
    // A hand-edited skeleton can carry a contract `create` never validated; refuse to put a
    // signature on one `installer-engine` would refuse anyway (environment_contract_invalid).
    if let Some(env) = &unsigned.environment {
        env.validate().map_err(|e| format!("refusing to sign: environment contract invalid: {e}"))?;
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
        None,
        unsigned.environment,
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

/// `ct-agent manifest publish`: either PUT a signed manifest where the operator points us (Phase
/// 1's dumb object-storage mode), or, if `CT_MANIFEST_REGISTRY_URL` is set, POST it + its bundle
/// to a Phase 3 registry instead. Exactly one of `CT_MANIFEST_PUBLISH_URL` /
/// `CT_MANIFEST_REGISTRY_URL` must be set -- same "for the one input that decides X, refuse to
/// guess" discipline as `ActivateCliConfig`'s trust-allowlist parsing above.
///
/// The manifest's own signature, not the transport, is what makes it trustworthy at activation
/// time; HTTPS is still required because `installer-engine` refuses to fetch over plain HTTP, so a
/// manifest published to an `http://` URL would be unusable either way.
pub async fn run_publish() -> Result<(), String> {
    let f = |k: &str| std::env::var(k).ok();
    let dumb_put_url = opt(&f, "CT_MANIFEST_PUBLISH_URL");
    let registry_url = opt(&f, "CT_MANIFEST_REGISTRY_URL");
    match (dumb_put_url, registry_url) {
        (Some(_), Some(_)) => Err("set exactly one of CT_MANIFEST_PUBLISH_URL or \
                                    CT_MANIFEST_REGISTRY_URL, not both"
            .to_string()),
        (None, None) => Err("CT_MANIFEST_PUBLISH_URL (https:// object-storage URL) or \
                              CT_MANIFEST_REGISTRY_URL (Phase 3 registry base URL) required"
            .to_string()),
        (Some(url), None) => run_publish_dumb_put(url).await,
        (None, Some(registry_url)) => run_publish_to_registry(&f, registry_url).await,
    }
}

/// Load + parse + verify the manifest to publish -- the one step both publish modes share, so a
/// manifest that no one could ever activate is caught before either transport ever runs.
fn load_and_verify_manifest_to_publish() -> Result<(String, ServiceManifest), String> {
    let body = read_manifest_input()?;
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
    Ok((body, manifest))
}

async fn run_publish_dumb_put(url: String) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!(
            "CT_MANIFEST_PUBLISH_URL must be https:// (got '{url}') -- installer-engine refuses to \
             fetch a manifest over plain HTTP, so this one could never be activated"
        ));
    }
    let (body, manifest) = load_and_verify_manifest_to_publish()?;

    // The shared client's 30 s whole-request timeout applies: a stalled publish
    // endpoint must not hang `ct-agent manifest publish` indefinitely rather
    // than surfacing a clear error. Same bug class as #54.
    let resp = crate::http::shared()
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

/// `CT_MANIFEST_REGISTRY_URL` mode: POST the manifest JSON + the bundle tarball
/// (`CT_MANIFEST_BUNDLE_PATH`) as multipart to `{registry_url}/manifests`, authenticated with
/// `CT_MANIFEST_REGISTRY_WRITE_TOKEN`. The registry re-verifies the signature and the bundle's
/// hash itself (never trust a client-side check alone for something a network peer asserts), but
/// checking here first still avoids uploading a multi-megabyte bundle for a manifest that was
/// always going to be rejected.
async fn run_publish_to_registry<F: Fn(&str) -> Option<String>>(f: &F, registry_url: String) -> Result<(), String> {
    let registry_url = registry_url.trim_end_matches('/').to_string();
    require_registry_url_scheme(&registry_url)?;
    let bundle_path = req(f, "CT_MANIFEST_BUNDLE_PATH", "local path to the bundle tarball this manifest's bundle.sha256 commits to")?;
    let token = req(f, "CT_MANIFEST_REGISTRY_WRITE_TOKEN", "the registry's REGISTRY_WRITE_TOKEN")?;

    let (body, manifest) = load_and_verify_manifest_to_publish()?;
    let bundle_bytes = std::fs::read(&bundle_path).map_err(|e| format!("read CT_MANIFEST_BUNDLE_PATH {bundle_path}: {e}"))?;

    let manifest_part = reqwest::multipart::Part::text(body).mime_str("application/json").map_err(|e| e.to_string())?;
    let bundle_part = reqwest::multipart::Part::bytes(bundle_bytes)
        .file_name("bundle.tar.gz")
        .mime_str("application/gzip")
        .map_err(|e| e.to_string())?;
    let form = reqwest::multipart::Form::new().part("manifest", manifest_part).part("bundle", bundle_part);

    // 60 s rather than the shared client's 30 s: this request carries the
    // multi-megabyte bundle tarball.
    let resp = crate::http::shared()
        .post(format!("{registry_url}/manifests"))
        .timeout(std::time::Duration::from_secs(60))
        .header("authorization", format!("Bearer {token}"))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("POST {registry_url}/manifests: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("POST {registry_url}/manifests: HTTP {status} -- {}", text.trim().chars().take(200).collect::<String>()));
    }
    eprintln!("published manifest {} to registry {registry_url}: {}", hex_encode(&manifest.manifest_id), text.trim());
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
    /// `CT_MANIFEST_URL` -- an https:// URL, or (only with `CT_MANIFEST_ALLOW_LOCAL_PATH=1` set on
    /// this agent, ct-agent#170) a local file path; installer-engine handles both shapes.
    pub manifest_location: String,
    pub allowlist: TrustAllowlist,
    pub env_file: Option<PathBuf>,
    pub project_name: String,
    pub protected_name_substrings: Vec<String>,
    pub work_dir: PathBuf,
    /// Phase 3, opt-in: when set, a successful activation additionally POSTs a ledger-only
    /// activation event to `{registry_url}/manifests/:id/activations`. All three of
    /// `registry_url`/`registry_write_token`/`activator_pubkey` are required together (checked in
    /// `from_lookup`) -- a partially-configured registry mode would silently skip the ledger write
    /// instead of failing loudly.
    pub registry: Option<RegistryActivationConfig>,
    /// Binary kind only (scimbe/ct-agent#183, phase 1): `true` -- the default -- refuses a Binary
    /// activation when no sandbox backend is usable on this host; `false` only when the operator
    /// set `CT_ALLOW_UNSANDBOXED=1`. Always derived through
    /// [`installer_engine::require_binary_sandbox_from_env`] (which also honours the legacy
    /// `CT_REQUIRE_BINARY_SANDBOX=1` as a no-op), never set by hand, so ct-agent cannot drift
    /// from the marketplace's own semantics.
    pub require_binary_sandbox: bool,
}

#[derive(Debug)]
pub struct RegistryActivationConfig {
    pub registry_url: String,
    pub registry_write_token: String,
    /// This agent's own holder pubkey, reported (not cryptographically proven) as the activator --
    /// Phase 3's ledger is honest bookkeeping, not a payment-grade attestation (see
    /// `registry::post_activation`'s own doc comment for the full rationale).
    pub activator_pubkey: String,
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
        let registry_url = opt(&f, "CT_MANIFEST_REGISTRY_URL");
        let registry = match registry_url {
            None => None,
            Some(registry_url) => {
                let registry_url = registry_url.trim_end_matches('/').to_string();
                require_registry_url_scheme(&registry_url)?;
                Some(RegistryActivationConfig {
                    registry_url,
                    registry_write_token: req(&f, "CT_MANIFEST_REGISTRY_WRITE_TOKEN", "the registry's REGISTRY_WRITE_TOKEN")?,
                    activator_pubkey: {
                        let hex = req(&f, "CT_MANIFEST_ACTIVATOR_PUBKEY", "this agent's own 64-hex holder pubkey, reported on the activation ledger")?;
                        if hex32(&hex).is_none() {
                            return Err("CT_MANIFEST_ACTIVATOR_PUBKEY must be exactly 64 ASCII hex characters".to_string());
                        }
                        hex
                    },
                })
            }
        };
        // ct-agent#170: https:// only, unless THIS agent opted into local paths. When the lookup
        // is `bridge/manifest-install`'s, `CT_MANIFEST_URL` is the caller's `manifest_location`
        // but the flag still comes from the process environment (that closure falls through to
        // `std::env::var` for every other key) -- the caller can never grant itself local paths.
        let manifest_location = req(
            &f,
            "CT_MANIFEST_URL",
            "https:// URL of the signed manifest JSON (a local path only with \
             CT_MANIFEST_ALLOW_LOCAL_PATH=1 set on this agent)",
        )?;
        require_manifest_location(&manifest_location, flag_set(opt(&f, "CT_MANIFEST_ALLOW_LOCAL_PATH")))?;
        Ok(Self {
            manifest_location,
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
                "the parent directory of per-activation bundle directories; this activation unpacks \
                 into <CT_MANIFEST_WORK_DIR>/<CT_MANIFEST_PROJECT_NAME>, which must not exist yet or \
                 must be empty",
            )?),
            registry,
            require_binary_sandbox: installer_engine::require_binary_sandbox_from_env(&f),
        })
    }
}

/// File `run_activate` writes into the per-activation directory once `installer_engine::activate`
/// reports `Ok` (#165): the [`ActivationMarker`] `harness run` later checks the directory against.
pub const ACTIVATION_MARKER_FILE: &str = ".ct-agent-activation.json";

/// What a successful activation leaves behind in its install directory: which manifest (and
/// publisher) the bytes on disk were fetched, hash-verified and signature-checked from. The bundle
/// sha256 in the manifest is of the TARBALL, so an unpacked directory can never be re-hashed
/// against it -- this marker is what binds the directory to the manifest instead. It is built from
/// the `InstallReport` alone (`installer-engine` fetches and parses the manifest internally and
/// only hands back these string fields), which is exactly the set `harness run` needs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationMarker {
    /// 64-hex `manifest_id`, as `installer-engine` reports it.
    pub manifest_id: String,
    /// 64-hex publisher pubkey the manifest's signature verified against.
    pub publisher_pubkey: String,
    /// The compose project name -- also the install directory's own name under
    /// `CT_MANIFEST_WORK_DIR`.
    pub project_name: String,
    /// Seconds since the Unix epoch when `installer_engine::activate` returned `Ok`.
    pub activated_at: u64,
    /// `CARGO_PKG_VERSION` of the ct-agent that wrote the marker.
    pub ct_agent_version: String,
}

/// The product of [`run_activate`]: `installer-engine`'s own report plus the directory the bundle
/// was unpacked into, so both the CLI and `bridge/manifest-install` can tell the operator where
/// the install lives (it is what `CT_HARNESS_BUNDLE_DIR` must later point at).
#[derive(Debug)]
pub struct Activation {
    pub report: InstallReport,
    pub install_dir: PathBuf,
}

/// The `InstallReport` as JSON with `install_dir` added next to its own fields -- one object, so
/// a caller reading `status` keeps working and additionally learns where the bundle lives. The
/// fallback object mirrors `InstallReport::to_json`'s own shape.
pub fn report_json_with_install_dir(a: &Activation) -> serde_json::Value {
    let mut value = serde_json::to_value(&a.report).unwrap_or_else(|e| {
        serde_json::json!({ "status": "report_serialize_error", "detail": e.to_string() })
    });
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "install_dir".to_string(),
            serde_json::Value::String(a.install_dir.to_string_lossy().into_owned()),
        );
    }
    value
}

/// The project name doubles as a path component under `CT_MANIFEST_WORK_DIR` (#165), so only a
/// plain single-segment name is accepted: 1..=64 characters of `[A-Za-z0-9._-]`, not starting
/// with `-` (an option-lookalike to every tool that later receives the path) or `.` (hidden, and
/// what rules out `.`/`..`). Anything else -- a separator, whitespace, non-ASCII -- is refused
/// with the offending rule named, never normalised into some other name the operator did not
/// choose. Returns the name unchanged when it is acceptable.
pub(crate) fn activation_dir_name(project_name: &str) -> Result<String, String> {
    let bad = |why: &str| {
        format!("CT_MANIFEST_PROJECT_NAME '{project_name}' is not usable as a directory name: {why}")
    };
    if project_name.is_empty() {
        return Err(bad("it is empty"));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if let Some(c) = project_name.chars().find(|&c| !allowed(c)) {
        return Err(bad(&format!("character {c:?} is not one of [A-Za-z0-9._-]")));
    }
    if project_name.len() > 64 {
        return Err(bad("it is longer than 64 characters"));
    }
    if project_name.starts_with('-') {
        return Err(bad("it must not start with '-'"));
    }
    if project_name.starts_with('.') {
        return Err(bad("it must not start with '.' (which also rules out '.' and '..')"));
    }
    Ok(project_name.to_string())
}

/// Resolve and claim `<work_dir>/<project_name>` for one activation (#165): create `work_dir`
/// itself if needed, then create the per-activation directory if it is absent, or accept it only
/// if it is an EMPTY real directory. A non-empty directory (a previous activation, or anything
/// else) is refused with the path named -- nothing is ever deleted on the operator's behalf. A
/// symlink at that path is refused outright (`symlink_metadata`, so it is never followed): it
/// would let a stale link redirect a hash-verified bundle into some other directory entirely.
pub(crate) fn prepare_activation_dir(work_dir: &Path, project_name: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(work_dir)
        .map_err(|e| format!("create CT_MANIFEST_WORK_DIR {}: {e}", work_dir.display()))?;
    let install_dir = work_dir.join(activation_dir_name(project_name)?);
    let meta = match std::fs::symlink_metadata(&install_dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // `create_dir`, not `create_dir_all`: if something races us into existence between
            // the lookup and here, fail closed rather than adopt a directory we did not inspect.
            std::fs::create_dir(&install_dir)
                .map_err(|e| format!("create activation directory {}: {e}", install_dir.display()))?;
            return Ok(install_dir);
        }
        Err(e) => return Err(format!("inspect activation directory {}: {e}", install_dir.display())),
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink -- refusing to unpack a bundle through it (#165); remove it, or choose a new \
             CT_MANIFEST_PROJECT_NAME",
            install_dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "{} exists and is not a directory -- refusing to unpack a bundle there (#165); remove it, or \
             choose a new CT_MANIFEST_PROJECT_NAME",
            install_dir.display()
        ));
    }
    let mut entries = std::fs::read_dir(&install_dir)
        .map_err(|e| format!("read activation directory {}: {e}", install_dir.display()))?;
    if let Some(entry) = entries.next() {
        let occupant = match entry {
            Ok(entry) => entry.file_name().to_string_lossy().into_owned(),
            Err(e) => format!("<unreadable entry: {e}>"),
        };
        // Name the earlier activation when there is one -- the operator most likely wants to
        // know WHICH install they are about to tread on, not just that the directory is busy.
        let prior = match read_activation_marker(&install_dir) {
            Ok(Some(marker)) => format!(
                " -- a previous activation (manifest {}, project '{}', at {}) already occupies it",
                marker.manifest_id, marker.project_name, marker.activated_at
            ),
            _ => " -- a previous activation or unrelated files already occupy it".to_string(),
        };
        return Err(format!(
            "{} is not empty (contains '{occupant}'){prior}; ct-agent never unpacks a bundle over existing \
             files (#165). Remove that directory yourself, or choose a new CT_MANIFEST_PROJECT_NAME",
            install_dir.display()
        ));
    }
    Ok(install_dir)
}

/// Write `marker` as pretty JSON to `<install_dir>/ACTIVATION_MARKER_FILE`.
pub(crate) fn write_activation_marker(install_dir: &Path, marker: &ActivationMarker) -> Result<(), String> {
    let path = install_dir.join(ACTIVATION_MARKER_FILE);
    let json = serde_json::to_string_pretty(marker).map_err(|e| format!("serialize activation marker: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("write activation marker {}: {e}", path.display()))
}

/// Read `<dir>/ACTIVATION_MARKER_FILE`: `Ok(None)` when there is no marker at all, `Err` when
/// there is one that cannot be read or parsed -- a corrupt marker is a reason to stop, not to
/// treat the directory as unmarked.
pub(crate) fn read_activation_marker(dir: &Path) -> Result<Option<ActivationMarker>, String> {
    let path = dir.join(ACTIVATION_MARKER_FILE);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read activation marker {}: {e}", path.display())),
    };
    serde_json::from_slice::<ActivationMarker>(&raw)
        .map(Some)
        .map_err(|e| format!("activation marker {} is not valid: {e}", path.display()))
}

/// Run the activation. `installer-engine` is entirely synchronous (blocking HTTP, `docker`
/// subprocesses, `verify.sh`), so it goes on the blocking pool rather than stalling a runtime
/// worker for the length of a `docker compose up --build`.
///
/// The per-activation directory is claimed FIRST (#165): a directory that is already occupied is
/// an error before any manifest or bundle is fetched, so a refused activation has no side effect
/// beyond (possibly) creating the empty parent.
pub async fn run_activate(cfg: ActivateCliConfig) -> Result<Activation, String> {
    let now = unix_now()?;
    let install_dir = prepare_activation_dir(&cfg.work_dir, &cfg.project_name)?;
    let registry = cfg.registry;
    let opts = ActivateOptions {
        manifest_location: cfg.manifest_location,
        allowlist: cfg.allowlist,
        env_file: cfg.env_file,
        project_name: cfg.project_name,
        protected_name_substrings: cfg.protected_name_substrings,
        work_dir: install_dir.clone(),
        now,
        require_binary_sandbox: cfg.require_binary_sandbox,
    };
    let report = tokio::task::spawn_blocking(move || installer_engine::activate(opts))
        .await
        .map_err(|e| format!("activation task failed: {e}"))?;
    // ct-agent#178: one structured line per activation, whatever its verdict.
    crate::events::emit(
        crate::events::MANIFEST_INSTALL,
        serde_json::json!({ "status": report_status_str(&report) }),
    );

    // The marker is part of the activation, not an afterthought: it is the only thing that binds
    // the unpacked bytes to the manifest they were verified against (the tarball hash cannot be
    // re-checked on a directory), and `harness run` refuses an unmarked directory. So a marker
    // that cannot be written is a failed activation, even though the service itself is up -- the
    // operator gets the path and the reason, and decides.
    if let InstallReport::Ok { manifest_id, publisher_pubkey, project_name, .. } = &report {
        let marker = ActivationMarker {
            manifest_id: manifest_id.clone(),
            publisher_pubkey: publisher_pubkey.clone(),
            project_name: project_name.clone(),
            activated_at: unix_now().unwrap_or(now),
            ct_agent_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        write_activation_marker(&install_dir, &marker).map_err(|e| {
            format!(
                "activation of manifest {manifest_id} into {} succeeded but its activation marker could not be \
                 written: {e} -- the directory is not usable by `harness run` until it carries one",
                install_dir.display()
            )
        })?;
    }

    // Phase 3, opt-in: a ledger write only, and only after a REAL successful install -- a
    // Rejected/Failed activation must never be recorded as if it happened. A failure posting the
    // ledger event does not undo (or fail) the activation itself: the service is already up, and
    // the ledger is bookkeeping, not the source of truth for whether activation succeeded -- but
    // it IS surfaced loudly on stderr so it doesn't silently go missing.
    if let (Some(registry), InstallReport::Ok { manifest_id, .. }) = (&registry, &report) {
        if let Err(e) = post_activation_ledger_event(registry, manifest_id).await {
            eprintln!("warning: activation succeeded but the registry ledger event failed: {e}");
        }
    }
    Ok(Activation { report, install_dir })
}

async fn post_activation_ledger_event(registry: &RegistryActivationConfig, manifest_id: &str) -> Result<(), String> {
    let resp = crate::http::shared()
        .post(format!("{}/manifests/{manifest_id}/activations", registry.registry_url))
        .header("authorization", format!("Bearer {}", registry.registry_write_token))
        .json(&serde_json::json!({ "activator_pubkey": registry.activator_pubkey, "status": "ok" }))
        .send()
        .await
        .map_err(|e| format!("POST activation ledger event: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let detail: String = resp.text().await.unwrap_or_default().trim().chars().take(200).collect();
        return Err(format!("HTTP {status}{}", if detail.is_empty() { String::new() } else { format!(" -- {detail}") }));
    }
    Ok(())
}

/// The report's verdict as the same lowercase word its JSON `status` field carries.
pub fn report_status_str(report: &InstallReport) -> &'static str {
    match report {
        InstallReport::Ok { .. } => "ok",
        InstallReport::Rejected { .. } => "rejected",
        InstallReport::Failed { .. } => "failed",
    }
}

/// Whether the install actually succeeded -- the caller exits non-zero when it did not, so that
/// `ct-agent manifest activate && …` means what it looks like it means.
pub fn report_is_ok(report: &InstallReport) -> bool {
    matches!(report, InstallReport::Ok { .. })
}

/// `ct-agent manifest plan` (scimbe/ct-agent#183, phase 1): the same env as `activate` -- it IS an
/// [`ActivateCliConfig`] -- plus an optional local compose file to scan. Nothing here is a new
/// trust decision: a plan reads exactly the configuration the real activation would.
#[derive(Debug)]
pub struct PlanCliConfig {
    pub activate: ActivateCliConfig,
    /// `CT_MANIFEST_COMPOSE_FILE` -- for `plan` (unlike `create`, where the same variable names a
    /// path INSIDE the bundle) a LOCAL path to the compose file's text, so the static guardrail
    /// scan can run without fetching or unpacking the bundle. Absent: the plan says the scan was
    /// skipped, and lists the hardening rules the file must satisfy anyway.
    pub compose_file: Option<PathBuf>,
}

impl PlanCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let compose_file = opt(&f, "CT_MANIFEST_COMPOSE_FILE").map(PathBuf::from);
        Ok(Self { activate: ActivateCliConfig::from_lookup(f)?, compose_file })
    }
}

/// The product of [`run_plan`]: `installer-engine`'s own [`Plan`] plus the directory the real
/// activation would unpack into (never created by a plan) and the manifest it was computed for.
#[derive(Debug)]
pub struct Planned {
    pub plan: Plan,
    pub install_dir: PathBuf,
    /// 64-hex `manifest_id`.
    pub manifest_id: String,
}

/// The [`Plan`] as JSON with `would_refuse`, `install_dir` and `manifest_id` added next to its
/// own fields -- one object, so `bridge/manifest-plan`'s caller (the portal) gets the verdict
/// without re-deriving it from `refusals`. Same shape discipline as
/// [`report_json_with_install_dir`]; the fallback object mirrors `Plan::to_json`'s own.
pub fn plan_json_with_install_dir(p: &Planned) -> serde_json::Value {
    let mut value = serde_json::to_value(&p.plan).unwrap_or_else(|e| {
        serde_json::json!({ "status": "plan_serialize_error", "detail": e.to_string() })
    });
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("would_refuse".to_string(), serde_json::Value::Bool(p.plan.would_refuse()));
        map.insert(
            "install_dir".to_string(),
            serde_json::Value::String(p.install_dir.to_string_lossy().into_owned()),
        );
        map.insert("manifest_id".to_string(), serde_json::Value::String(p.manifest_id.clone()));
    }
    value
}

/// The exit status `ct-agent manifest plan` / `harness run --plan` end with: 1 when the real run
/// would be refused for at least one reason, 0 otherwise -- so `manifest plan && manifest
/// activate` means what it looks like it means. Pure; `main` performs the actual exit.
pub fn plan_exit_code(plan: &Plan) -> i32 {
    i32::from(plan.would_refuse())
}

/// The checks `run_activate`/`installer_engine::activate` perform on the manifest BEFORE the
/// engine's own plan starts (its steps 2-3: signature/expiry, then the publisher trust
/// allowlist), rendered as refusals in that order. A plan reports EVERY reason the activation
/// would be rejected, so an untrusted publisher is a refusal in the plan, not an error that hides
/// the rest of it. The `reason` wording matches the engine's `InstallReport::Rejected` reasons.
pub fn pre_activation_refusals(allowlist: &TrustAllowlist, manifest: &ServiceManifest, now: u64) -> Vec<String> {
    let mut refusals = Vec::new();
    if !manifest.is_valid(now) {
        refusals.push(
            "manifest_invalid_or_expired: the signature does not verify or the manifest has expired".to_string(),
        );
    }
    if !allowlist.contains(&manifest.publisher_pubkey) {
        refusals.push(format!("publisher_not_on_trust_allowlist: {}", hex_encode(&manifest.publisher_pubkey)));
    }
    refusals
}

/// What a plan is computed FOR, independent of where the manifest came from: the trust
/// allowlist the activation would check, the directory it would unpack into (or, for `harness
/// run --plan`, the already-activated bundle directory), the compose project name, and the
/// sandbox requirement. [`plan_target_for`] derives one from an [`ActivateCliConfig`].
#[derive(Debug)]
pub struct PlanTarget<'a> {
    pub allowlist: &'a TrustAllowlist,
    pub install_dir: PathBuf,
    pub project_name: String,
    pub require_binary_sandbox: bool,
}

/// The [`PlanTarget`] of a `manifest activate` under `cfg`: `install_dir` is
/// `<CT_MANIFEST_WORK_DIR>/<CT_MANIFEST_PROJECT_NAME>` exactly as `prepare_activation_dir` would
/// claim it (the same name rules, #165), but only RENDERED -- a plan never creates it.
pub fn plan_target_for(cfg: &ActivateCliConfig) -> Result<PlanTarget<'_>, String> {
    Ok(PlanTarget {
        allowlist: &cfg.allowlist,
        install_dir: cfg.work_dir.join(activation_dir_name(&cfg.project_name)?),
        project_name: cfg.project_name.clone(),
        require_binary_sandbox: cfg.require_binary_sandbox,
    })
}

/// Pure builder: the [`PlanOptions`] the real activation of `manifest` at `target` corresponds
/// to. `compose_yaml` is the compose file's text when the caller has it locally (Compose kind
/// only; ignored by the engine otherwise). The guardrail policy is the strict default
/// `installer_engine::activate` itself scans with. Env-var NAMES only reach the plan; values are
/// previewed as `<redacted>` by the engine.
pub fn build_plan_options(target: &PlanTarget<'_>, manifest: &ServiceManifest, compose_yaml: Option<String>) -> PlanOptions {
    PlanOptions {
        installer_kind: manifest.installer_kind,
        environment: manifest.environment.clone(),
        entrypoint: manifest.bundle.compose_file.clone(),
        work_dir: target.install_dir.clone(),
        env_names: manifest.env_template.iter().map(|e| e.name.clone()).collect(),
        require_binary_sandbox: target.require_binary_sandbox,
        project_name: target.project_name.clone(),
        compose_yaml,
        guardrail_policy: GuardrailPolicy::default(),
    }
}

/// Blocking core of [`run_plan`]: fetch the manifest (https:// or a local path, the engine's own
/// size-capped/timeout-bounded fetch), compute the plan, prepend the pre-activation refusals,
/// emit one `manifest_plan` event. No bundle fetch, no unpack, no docker, no model call -- the
/// only thing that runs is the sandbox backend probe for a Binary manifest.
pub fn run_plan_blocking(cfg: PlanCliConfig) -> Result<Planned, String> {
    let now = unix_now()?;
    let manifest = installer_engine::fetch::fetch_manifest(&cfg.activate.manifest_location)
        .map_err(|e| format!("fetch manifest: {e}"))?;
    let compose_yaml = cfg
        .compose_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).map_err(|e| format!("read CT_MANIFEST_COMPOSE_FILE {}: {e}", path.display()))
        })
        .transpose()?;
    let target = plan_target_for(&cfg.activate)?;
    Ok(plan_for_manifest(target, &manifest, compose_yaml, now))
}

/// [`run_plan_blocking`] minus the fetch: the plan for an already-held manifest at `target`, the
/// pre-activation refusals first, one `manifest_plan` event emitted. Shared with
/// `harness run --plan`, which holds the manifest it verified for its bundle.
pub fn plan_for_manifest(target: PlanTarget<'_>, manifest: &ServiceManifest, compose_yaml: Option<String>, now: u64) -> Planned {
    let opts = build_plan_options(&target, manifest, compose_yaml);
    let mut plan = installer_engine::plan(opts);
    let pre = pre_activation_refusals(target.allowlist, manifest, now);
    if !pre.is_empty() {
        plan.refusals.splice(0..0, pre);
    }
    // ct-agent#183: one structured line per plan, like `manifest_install` per activation.
    crate::events::emit(
        crate::events::MANIFEST_PLAN,
        serde_json::json!({ "would_refuse": plan.would_refuse(), "backend": plan.backend }),
    );
    Planned { plan, install_dir: target.install_dir, manifest_id: hex_encode(&manifest.manifest_id) }
}

/// `ct-agent manifest plan`. Blocking HTTP and the backend probe go on the blocking pool, same as
/// [`run_activate`].
pub async fn run_plan(cfg: PlanCliConfig) -> Result<Planned, String> {
    tokio::task::spawn_blocking(move || run_plan_blocking(cfg))
        .await
        .map_err(|e| format!("plan task failed: {e}"))?
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
            // ct-agent#170: a local path needs the agent-side opt-in.
            ("CT_MANIFEST_ALLOW_LOCAL_PATH", "1"),
            ("CT_MANIFEST_PROJECT_NAME", "proof-run"),
            ("CT_MANIFEST_WORK_DIR", "/tmp/work"),
            ("CT_MANIFEST_TRUST_ALLOWLIST", SHA),
            ("CT_MANIFEST_ENV_FILE", "/local/secrets.env"),
            ("CT_MANIFEST_PROTECTED_NAMES", "litellm-proxy, cads-tunnel"),
        ];
        let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
        assert_eq!(cfg.manifest_location, "/local/path/manifest.json");
        assert!(cfg.allowlist.contains(&[0x99; 32]));
        assert_eq!(cfg.env_file, Some(PathBuf::from("/local/secrets.env")));
        assert_eq!(cfg.protected_name_substrings, vec!["litellm-proxy", "cads-tunnel"]);
        assert!(cfg.registry.is_none(), "CT_MANIFEST_REGISTRY_URL unset -> registry mode is off, not silently defaulted on");
    }

    fn activate_base_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CT_MANIFEST_URL", "https://example.invalid/m.json"),
            ("CT_MANIFEST_PROJECT_NAME", "proof-run"),
            ("CT_MANIFEST_WORK_DIR", "/tmp/work"),
            ("CT_MANIFEST_TRUST_ALLOWLIST", SHA),
        ]
    }

    #[test]
    fn activate_refuses_a_local_manifest_path_unless_the_agent_allows_it_170() {
        // ct-agent#170: via bridge/manifest-install the bridge peer supplies CT_MANIFEST_URL, so
        // a bare path used to be a filesystem existence oracle. Refused by default, with the
        // opt-in named; accepted once THIS agent sets the flag.
        let mut env = activate_base_env();
        env[0] = ("CT_MANIFEST_URL", "/etc/passwd");
        let err = ActivateCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("local path") && err.contains("CT_MANIFEST_ALLOW_LOCAL_PATH"), "{err}");

        env.push(("CT_MANIFEST_ALLOW_LOCAL_PATH", "1"));
        let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
        assert_eq!(cfg.manifest_location, "/etc/passwd");

        // Only an explicit affirmative value opts in.
        let mut off = activate_base_env();
        off[0] = ("CT_MANIFEST_URL", "relative/manifest.json");
        off.push(("CT_MANIFEST_ALLOW_LOCAL_PATH", "0"));
        assert!(ActivateCliConfig::from_lookup(lookup(&off)).is_err(), "'0' must not opt in");
    }

    #[test]
    fn activate_refuses_http_and_file_manifest_locations_even_with_local_paths_allowed_170() {
        for (bad, reason) in [
            ("http://registry.internal:8787/manifests/x", "https://"),
            ("http://127.0.0.1:8787/manifests/x", "https://"),
            ("file:///etc/passwd", "file://"),
            ("ftp://example.invalid/m.json", "ftp://"),
        ] {
            for flag in [None, Some(("CT_MANIFEST_ALLOW_LOCAL_PATH", "1"))] {
                let mut env = activate_base_env();
                env[0] = ("CT_MANIFEST_URL", bad);
                env.extend(flag);
                let err = ActivateCliConfig::from_lookup(lookup(&env))
                    .expect_err(&format!("{bad} must be refused (flag: {flag:?})"));
                assert!(err.contains(reason) && err.contains("170"), "{bad}: {err}");
            }
        }
        // And https:// stays accepted, flag or not.
        let cfg = ActivateCliConfig::from_lookup(lookup(&activate_base_env())).unwrap();
        assert_eq!(cfg.manifest_location, "https://example.invalid/m.json");
    }

    #[test]
    fn manifest_location_policy_names_each_refusal_reason_170() {
        assert!(require_manifest_location("https://example.invalid/m.json", false).is_ok());
        assert!(require_manifest_location("/srv/m.json", true).is_ok());
        let path_err = require_manifest_location("/srv/m.json", false).unwrap_err();
        assert!(path_err.contains("local path"), "{path_err}");
        let http_err = require_manifest_location("http://example.invalid/m.json", true).unwrap_err();
        assert!(http_err.contains("must be https://"), "{http_err}");
        let file_err = require_manifest_location("file:///srv/m.json", true).unwrap_err();
        assert!(file_err.contains("file://"), "{file_err}");
        let scheme_err = require_manifest_location("gopher://x/m.json", true).unwrap_err();
        assert!(scheme_err.contains("gopher://"), "{scheme_err}");
        assert!(flag_set(Some("1".into())) && flag_set(Some(" true ".into())) && flag_set(Some("YES".into())));
        assert!(!flag_set(None) && !flag_set(Some("0".into())) && !flag_set(Some("".into())));
    }

    #[test]
    fn activate_parses_registry_mode_when_all_three_registry_vars_are_set() {
        let mut env = activate_base_env();
        env.push(("CT_MANIFEST_REGISTRY_URL", "http://127.0.0.1:8787/"));
        env.push(("CT_MANIFEST_REGISTRY_WRITE_TOKEN", "secret-token"));
        env.push(("CT_MANIFEST_ACTIVATOR_PUBKEY", SHA));
        let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
        let registry = cfg.registry.expect("registry mode should be parsed");
        // Trailing slash stripped so `{registry_url}/manifests/...` never double-slashes.
        assert_eq!(registry.registry_url, "http://127.0.0.1:8787");
        assert_eq!(registry.registry_write_token, "secret-token");
        assert_eq!(registry.activator_pubkey, SHA);
    }

    #[test]
    fn activate_registry_mode_requires_a_write_token() {
        let mut env = activate_base_env();
        env.push(("CT_MANIFEST_REGISTRY_URL", "http://127.0.0.1:8787"));
        env.push(("CT_MANIFEST_ACTIVATOR_PUBKEY", SHA));
        let err = ActivateCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_REGISTRY_WRITE_TOKEN"), "{err}");
    }

    #[test]
    fn activate_registry_mode_requires_a_well_formed_activator_pubkey() {
        let mut env = activate_base_env();
        env.push(("CT_MANIFEST_REGISTRY_URL", "http://127.0.0.1:8787"));
        env.push(("CT_MANIFEST_REGISTRY_WRITE_TOKEN", "secret-token"));
        env.push(("CT_MANIFEST_ACTIVATOR_PUBKEY", "not-hex"));
        let err = ActivateCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_ACTIVATOR_PUBKEY"), "{err}");
    }

    #[test]
    fn registry_url_scheme_accepts_https_and_loopback_http_only() {
        for ok in [
            "https://registry.example.invalid",
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://[::1]:8787",
        ] {
            assert!(require_registry_url_scheme(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [
            "http://registry.example.invalid",
            "http://evil.invalid",
            "http://127.0.0.1.evil.invalid",
            "ftp://127.0.0.1:8787",
            // #97: userinfo-bypass -- a "looks-loopback" authority that reqwest/the `url`
            // crate actually parse as userinfo, connecting to the host AFTER the `@` instead.
            "http://127.0.0.1:8787@evil.invalid",
            "http://localhost:1@evil.invalid/",
            "http://[::1]:8787@evil.invalid",
        ] {
            let err = require_registry_url_scheme(bad)
                .expect_err(&format!("{bad} must be rejected -- it would leak the registry write token and manifest/bundle bytes in cleartext"));
            assert!(err.contains("https://"), "{err}");
        }
    }

    #[test]
    fn activate_rejects_a_non_loopback_http_registry_url() {
        // #70-follow: CT_MANIFEST_REGISTRY_URL carries CT_MANIFEST_REGISTRY_WRITE_TOKEN as a
        // Bearer header on every request, exactly like the other network-facing manifest URLs in
        // this file that already require https://. A typo'd or misconfigured non-loopback
        // http:// endpoint must be refused loudly, not silently accepted and leaked in cleartext.
        let mut env = activate_base_env();
        env.push(("CT_MANIFEST_REGISTRY_URL", "http://registry.example.invalid"));
        env.push(("CT_MANIFEST_REGISTRY_WRITE_TOKEN", "secret-token"));
        env.push(("CT_MANIFEST_ACTIVATOR_PUBKEY", SHA));
        let err = ActivateCliConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_REGISTRY_URL") && err.contains("https://"), "{err}");
    }

    #[tokio::test]
    async fn publish_to_registry_rejects_a_non_loopback_http_registry_url_before_touching_the_network() {
        let env = [("CT_MANIFEST_REGISTRY_WRITE_TOKEN", "secret-token")];
        let err = run_publish_to_registry(&lookup(&env), "http://registry.example.invalid".to_string())
            .await
            .unwrap_err();
        assert!(err.contains("CT_MANIFEST_REGISTRY_URL") && err.contains("https://"), "{err}");
    }

    #[test]
    fn manifest_input_comes_from_stdin_when_no_file_is_configured() {
        let f = lookup(&[]);
        let mut stdin = std::io::Cursor::new(b"{\"a\":1}".to_vec());
        assert_eq!(read_manifest_input_from(&f, &mut stdin).unwrap(), "{\"a\":1}");
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(read_manifest_input_from(&f, &mut empty).is_err(), "empty stdin must fail loudly");
    }

    #[test]
    fn activation_dir_name_accepts_plain_names_and_rejects_path_tricks_165() {
        assert_eq!(activation_dir_name("my-agent-tool").unwrap(), "my-agent-tool");
        assert_eq!(activation_dir_name("svc_1.2").unwrap(), "svc_1.2");
        let too_long = "a".repeat(65);
        for bad in ["", ".", "..", "a/b", "a\\b", "-x", ".hidden", too_long.as_str(), "a b", "ü"] {
            let err = activation_dir_name(bad)
                .expect_err(&format!("{bad:?} must not become a path component under CT_MANIFEST_WORK_DIR"));
            assert!(err.contains("CT_MANIFEST_PROJECT_NAME"), "{err}");
        }
    }

    #[test]
    fn prepare_activation_dir_creates_a_fresh_subdir_and_refuses_a_non_empty_one_165() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path().join("work");

        // Fresh: the parent is created too, and the install dir is a new empty directory.
        let install_dir = prepare_activation_dir(&work_dir, "proj").unwrap();
        assert_eq!(install_dir, work_dir.join("proj"));
        assert!(install_dir.is_dir());
        assert_eq!(std::fs::read_dir(&install_dir).unwrap().count(), 0);

        // Existing but still empty is fine -- nothing to overwrite.
        assert_eq!(prepare_activation_dir(&work_dir, "proj").unwrap(), install_dir);

        // Anything inside (here: a previous activation's marker plus a compose file) is refused,
        // with the path and the way out named, and nothing is deleted.
        let marker = ActivationMarker {
            manifest_id: "ab".repeat(32),
            publisher_pubkey: "cd".repeat(32),
            project_name: "proj".to_string(),
            activated_at: 1_000,
            ct_agent_version: "0.0.0".to_string(),
        };
        write_activation_marker(&install_dir, &marker).unwrap();
        std::fs::write(install_dir.join("docker-compose.yml"), "services: {}").unwrap();
        let err = prepare_activation_dir(&work_dir, "proj").unwrap_err();
        assert!(err.contains(&install_dir.display().to_string()), "{err}");
        assert!(err.contains("CT_MANIFEST_PROJECT_NAME"), "{err}");
        assert!(err.contains(&"ab".repeat(32)), "the earlier activation's manifest must be named: {err}");
        assert!(install_dir.join("docker-compose.yml").is_file(), "refusing must never delete anything");

        // A regular file where the directory should be is refused too.
        std::fs::write(work_dir.join("as-file"), b"x").unwrap();
        let err = prepare_activation_dir(&work_dir, "as-file").unwrap_err();
        assert!(err.contains("not a directory"), "{err}");

        // Two project names -> two distinct directories.
        let other = prepare_activation_dir(&work_dir, "other").unwrap();
        assert_ne!(other, install_dir);
        assert!(other.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prepare_activation_dir_refuses_a_symlink_at_the_install_path_165() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path().join("work");
        std::fs::create_dir_all(&work_dir).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        // An empty target directory: only the symlink itself can be the reason for refusal.
        std::os::unix::fs::symlink(&elsewhere, work_dir.join("proj")).unwrap();
        let err = prepare_activation_dir(&work_dir, "proj").unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(err.contains("CT_MANIFEST_PROJECT_NAME"), "{err}");
    }

    #[test]
    fn activation_marker_round_trips_and_is_absent_on_a_fresh_dir_165() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_activation_marker(tmp.path()).unwrap(), None);

        let marker = ActivationMarker {
            manifest_id: "ab".repeat(32),
            publisher_pubkey: "cd".repeat(32),
            project_name: "proj".to_string(),
            activated_at: 1_700_000_000,
            ct_agent_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        write_activation_marker(tmp.path(), &marker).unwrap();
        assert!(tmp.path().join(ACTIVATION_MARKER_FILE).is_file());
        assert_eq!(read_activation_marker(tmp.path()).unwrap(), Some(marker));

        // A marker that exists but is not valid JSON is an error, never "unmarked".
        std::fs::write(tmp.path().join(ACTIVATION_MARKER_FILE), b"{ not json").unwrap();
        assert!(read_activation_marker(tmp.path()).is_err());
    }

    #[test]
    fn report_json_with_install_dir_adds_the_path_next_to_the_report_fields_165() {
        let activation = Activation {
            report: InstallReport::Rejected { reason: "fetch_manifest: nope".to_string(), manifest_id: None },
            install_dir: PathBuf::from("/var/lib/ct-agent/work/proj"),
        };
        let json = report_json_with_install_dir(&activation);
        assert_eq!(json["status"], serde_json::json!("rejected"));
        assert_eq!(json["reason"], serde_json::json!("fetch_manifest: nope"));
        assert_eq!(json["install_dir"], serde_json::json!("/var/lib/ct-agent/work/proj"));
    }

    // --- sandbox phase 1 (scimbe/ct-agent#183) -----------------------------------------------

    fn sample_environment_json() -> &'static str {
        r#"{"network":{"mode":"none"},"resources":{"memory_mb":256,"wall_secs":120},"hooks":{"rollback":"rollback.sh"}}"#
    }

    #[test]
    fn unsigned_manifest_round_trips_with_and_without_environment_183() {
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        let without = cfg.unsigned(1_000);
        assert_eq!(without.environment, None);
        let json = without.to_json().unwrap();
        assert!(!json.contains("\"environment\""), "None must be omitted, not written as null: {json}");
        assert_eq!(serde_json::from_str::<UnsignedManifest>(&json).unwrap(), without);

        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_ENVIRONMENT_JSON", sample_environment_json()));
        let with = CreateConfig::from_lookup(lookup(&env)).unwrap().unsigned(1_000);
        let contract = with.environment.clone().expect("environment parsed");
        assert_eq!(contract.network.mode, manifest_core::NetworkMode::None);
        assert_eq!(contract.resources.memory_mb, 256);
        assert_eq!(contract.hooks.rollback.as_deref(), Some("rollback.sh"));
        let json = with.to_json().unwrap();
        assert!(json.contains("\"environment\""), "{json}");
        assert_eq!(serde_json::from_str::<UnsignedManifest>(&json).unwrap(), with);
    }

    #[test]
    fn unsigned_manifest_still_denies_unknown_fields_183() {
        let cfg = CreateConfig::from_lookup(lookup(&with_sha(create_env(), SHA))).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&cfg.unsigned(1_000).to_json().unwrap()).unwrap();
        // A typo'd contract key must fail loudly, not be dropped and signed as "no contract".
        value["enviroment"] = serde_json::json!({ "network": { "mode": "none" } });
        let err = serde_json::from_value::<UnsignedManifest>(value).unwrap_err().to_string();
        assert!(err.contains("enviroment"), "{err}");
    }

    #[test]
    fn create_rejects_invalid_environment_json_naming_the_variable_183() {
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_ENVIRONMENT_JSON", "{ not json"));
        let err = CreateConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_ENVIRONMENT_JSON"), "{err}");

        // Parses, but fails the contract's own validation: the offending field is named too.
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_ENVIRONMENT_JSON", r#"{"resources":{"wall_secs":0}}"#));
        let err = CreateConfig::from_lookup(lookup(&env)).unwrap_err();
        assert!(err.contains("CT_MANIFEST_ENVIRONMENT_JSON"), "{err}");
        assert!(err.contains("environment.resources.wall_secs"), "{err}");

        // `{}` is the strictest default profile and is valid.
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_ENVIRONMENT_JSON", "{}"));
        let cfg = CreateConfig::from_lookup(lookup(&env)).unwrap();
        assert_eq!(cfg.environment, Some(EnvironmentContract::default()));
    }

    #[test]
    fn sign_carries_the_environment_contract_into_the_signature_183() {
        let mut env = with_sha(create_env(), SHA);
        env.push(("CT_MANIFEST_ENVIRONMENT_JSON", sample_environment_json()));
        let json = CreateConfig::from_lookup(lookup(&env)).unwrap().unsigned(1_000).to_json().unwrap();
        let holder = SigningKey::from_bytes(&[3u8; 32]);
        let signed = sign_manifest(&json, &holder, [7u8; 32]).unwrap();
        assert!(signed.is_valid(1_500));
        let contract = signed.environment.clone().expect("contract signed in");
        assert_eq!(contract.network.mode, manifest_core::NetworkMode::None);

        // Grafting the contract off after signing invalidates the signature: it IS signed.
        let mut stripped = signed.clone();
        stripped.environment = None;
        assert!(!stripped.is_valid(1_500));

        // A hand-edited skeleton with an invalid contract is refused before any signing.
        let mut unsigned: UnsignedManifest = serde_json::from_str(&json).unwrap();
        unsigned.environment.as_mut().unwrap().resources.memory_mb = 0;
        let err = sign_manifest(&unsigned.to_json().unwrap(), &holder, [7u8; 32]).unwrap_err();
        assert!(err.contains("environment.resources.memory_mb"), "{err}");
    }

    #[test]
    fn activate_requires_the_binary_sandbox_unless_the_opt_out_is_set_183() {
        let cfg = ActivateCliConfig::from_lookup(lookup(&activate_base_env())).unwrap();
        assert!(cfg.require_binary_sandbox, "nothing set: fail closed");

        let mut env = activate_base_env();
        env.push(("CT_ALLOW_UNSANDBOXED", "1"));
        let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
        assert!(!cfg.require_binary_sandbox, "CT_ALLOW_UNSANDBOXED=1 is the opt-out");

        // Anything but exactly `1` is not an opt-out, and the legacy flag is a no-op.
        for (k, v) in [("CT_ALLOW_UNSANDBOXED", "true"), ("CT_ALLOW_UNSANDBOXED", "0"), ("CT_REQUIRE_BINARY_SANDBOX", "1")] {
            let mut env = activate_base_env();
            env.push((k, v));
            let cfg = ActivateCliConfig::from_lookup(lookup(&env)).unwrap();
            assert!(cfg.require_binary_sandbox, "{k}={v} must keep the default");
        }
    }

    /// A signed Compose manifest whose publisher is `key`, for the plan tests (Compose: the
    /// engine's plan never probes a sandbox backend, so these tests need no bwrap).
    fn compose_manifest(key: &SigningKey, environment: Option<EnvironmentContract>) -> ServiceManifest {
        ServiceManifest::sign_new(
            key,
            [7u8; 32],
            "plan-proof".to_string(),
            "0.1.0".to_string(),
            InstallerKind::Compose,
            BundleRef {
                url: "https://example.invalid/bundle.tar.gz".to_string(),
                sha256: [0u8; 32],
                compose_file: "docker-compose.yml".to_string(),
            },
            vec![EnvVarSpec { name: "API_KEY".to_string(), required: true, description: "key".to_string() }],
            VerifySpec { script: "verify.sh".to_string(), timeout_secs: 60 },
            1_000,
            u64::MAX / 2,
            None,
            environment,
        )
    }

    fn plan_env_for(key: &SigningKey) -> Vec<(&'static str, String)> {
        vec![
            ("CT_MANIFEST_URL", "/local/path/manifest.json".to_string()),
            ("CT_MANIFEST_PROJECT_NAME", "plan-proof".to_string()),
            ("CT_MANIFEST_WORK_DIR", "/tmp/work".to_string()),
            ("CT_MANIFEST_TRUST_ALLOWLIST", hex_encode(&key.verifying_key().to_bytes())),
            // The plan tests read the manifest from a local file; that is an agent-side opt-in
            // since ct-agent#170, exactly as it is for activation.
            ("CT_MANIFEST_ALLOW_LOCAL_PATH", "1".to_string()),
        ]
    }

    fn lookup_owned(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn build_plan_options_mirrors_the_activation_config_183() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let mut contract = EnvironmentContract::default();
        contract.processes.max_pids = 8;
        let manifest = compose_manifest(&key, Some(contract.clone()));
        let mut env = plan_env_for(&key);
        env.push(("CT_ALLOW_UNSANDBOXED", "1".to_string()));
        let cfg = ActivateCliConfig::from_lookup(lookup_owned(&env)).unwrap();

        let target = plan_target_for(&cfg).unwrap();
        assert_eq!(target.install_dir, PathBuf::from("/tmp/work/plan-proof"), "rendered, never created");
        assert!(!target.install_dir.exists());
        let opts = build_plan_options(&target, &manifest, Some("services: {}".to_string()));
        assert_eq!(opts.installer_kind, InstallerKind::Compose);
        assert_eq!(opts.environment, Some(contract));
        assert_eq!(opts.entrypoint, "docker-compose.yml");
        assert_eq!(opts.work_dir, target.install_dir);
        assert_eq!(opts.env_names, vec!["API_KEY"], "names only -- never a value");
        assert!(!opts.require_binary_sandbox, "the opt-out flows through to the plan");
        assert_eq!(opts.project_name, "plan-proof");
        assert_eq!(opts.compose_yaml.as_deref(), Some("services: {}"));
        assert!(opts.guardrail_policy.require_image_digest, "the strict default activate scans with");

        // The #165 directory-name rules apply to a plan exactly as to an activation.
        let mut bad = plan_env_for(&key);
        bad[1].1 = "../escape".to_string();
        let cfg = ActivateCliConfig::from_lookup(lookup_owned(&bad)).unwrap();
        let err = plan_target_for(&cfg).unwrap_err();
        assert!(err.contains("CT_MANIFEST_PROJECT_NAME"), "{err}");
    }

    #[test]
    fn plan_exit_code_maps_would_refuse_to_1_183() {
        let clean = Plan { backend: None, argv_preview: Vec::new(), compose_overrides: Vec::new(), refusals: Vec::new() };
        assert_eq!(plan_exit_code(&clean), 0);
        let refused = Plan { refusals: vec!["guardrail_violations: web[F.16-missing-read-only]: x".to_string()], ..clean };
        assert!(refused.would_refuse());
        assert_eq!(plan_exit_code(&refused), 1);
    }

    #[test]
    fn plan_for_manifest_lists_pre_activation_refusals_first_183() {
        let publisher = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let manifest = compose_manifest(&publisher, None);

        // Trusted publisher, no compose text: no refusal at all -- exit 0.
        let cfg = ActivateCliConfig::from_lookup(lookup_owned(&plan_env_for(&publisher))).unwrap();
        let planned = plan_for_manifest(plan_target_for(&cfg).unwrap(), &manifest, None, 2_000);
        assert!(!planned.plan.would_refuse(), "{:?}", planned.plan);
        assert_eq!(plan_exit_code(&planned.plan), 0);
        assert_eq!(planned.plan.argv_preview[..4], ["docker", "compose", "-p", "plan-proof"]);
        assert!(planned.plan.compose_overrides.iter().any(|o| o == "pids_limit: 64"), "{:?}", planned.plan);
        assert_eq!(planned.manifest_id, "07".repeat(32));
        assert_eq!(planned.install_dir, PathBuf::from("/tmp/work/plan-proof"));

        // Publisher not on the allowlist: the very first refusal, before anything the engine finds.
        let cfg = ActivateCliConfig::from_lookup(lookup_owned(&plan_env_for(&other))).unwrap();
        let yaml = "services:\n  web:\n    image: ghcr.io/example/svc:latest\n";
        let planned = plan_for_manifest(plan_target_for(&cfg).unwrap(), &manifest, Some(yaml.to_string()), 2_000);
        assert!(planned.plan.would_refuse());
        assert_eq!(plan_exit_code(&planned.plan), 1);
        assert!(planned.plan.refusals[0].starts_with("publisher_not_on_trust_allowlist:"), "{:?}", planned.plan.refusals);
        assert!(planned.plan.refusals[0].contains(&hex_encode(&publisher.verifying_key().to_bytes())));
        assert!(
            planned.plan.refusals.iter().any(|r| r.starts_with("guardrail_violations:")),
            "the engine's own scan findings still follow: {:?}",
            planned.plan.refusals
        );

        // Expired: signature/expiry refusal, named as such.
        let cfg = ActivateCliConfig::from_lookup(lookup_owned(&plan_env_for(&publisher))).unwrap();
        let planned = plan_for_manifest(plan_target_for(&cfg).unwrap(), &manifest, None, u64::MAX);
        assert!(planned.plan.refusals[0].starts_with("manifest_invalid_or_expired"), "{:?}", planned.plan.refusals);

        let json = plan_json_with_install_dir(&planned);
        assert_eq!(json["would_refuse"], serde_json::json!(true));
        assert_eq!(json["install_dir"], serde_json::json!("/tmp/work/plan-proof"));
        assert_eq!(json["manifest_id"], serde_json::json!("07".repeat(32)));
        assert_eq!(json["refusals"].as_array().unwrap().len(), 1, "{json}");
    }

    #[test]
    fn run_plan_blocking_plans_a_local_manifest_without_creating_the_install_dir_183() {
        let tmp = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest = compose_manifest(&key, None);
        let manifest_path = tmp.path().join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let compose_path = tmp.path().join("docker-compose.yml");
        std::fs::write(&compose_path, "services:\n  web:\n    image: ghcr.io/example/svc:latest\n").unwrap();
        let work_dir = tmp.path().join("work");

        let mut env = plan_env_for(&key);
        env[0].1 = manifest_path.to_string_lossy().into_owned();
        env[2].1 = work_dir.to_string_lossy().into_owned();
        env.push(("CT_MANIFEST_COMPOSE_FILE", compose_path.to_string_lossy().into_owned()));
        let cfg = PlanCliConfig::from_lookup(lookup_owned(&env)).unwrap();
        assert_eq!(cfg.compose_file.as_deref(), Some(compose_path.as_path()));

        let planned = run_plan_blocking(cfg).unwrap();
        assert!(planned.plan.would_refuse(), "the unpinned image must be a refusal: {:?}", planned.plan);
        assert!(planned.plan.refusals.iter().any(|r| r.contains("F.15-image-not-digest-pinned")), "{:?}", planned.plan);
        assert_eq!(planned.install_dir, work_dir.join("plan-proof"));
        assert!(!work_dir.exists(), "a plan creates nothing on disk");

        // A compose path that does not exist is an error naming the variable, not a silent skip.
        let mut missing = plan_env_for(&key);
        missing[0].1 = manifest_path.to_string_lossy().into_owned();
        missing.push(("CT_MANIFEST_COMPOSE_FILE", tmp.path().join("nope.yml").to_string_lossy().into_owned()));
        let err = run_plan_blocking(PlanCliConfig::from_lookup(lookup_owned(&missing)).unwrap()).unwrap_err();
        assert!(err.contains("CT_MANIFEST_COMPOSE_FILE"), "{err}");
    }
}
