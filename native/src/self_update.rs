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
//! **Release provenance** (#184): a per-asset `.sha256` proves integrity of
//! the transfer, not origin -- whoever can write the release can write the
//! checksum next to it. The pipeline therefore also publishes ONE
//! `release-manifest.json` (`{ schema, tag, created_at, assets: { name: sha256 } }`)
//! and, once the operator has created the signing key, a detached
//! `release-manifest.sig` (base64 of an ed25519 signature over the exact
//! manifest bytes). This build pins the release public key(s) in
//! [`RELEASE_SIGNING_PUBKEYS`] (or [`RELEASE_PUBKEY_ENV`] for a private
//! build). **With a key pinned**, a release MUST carry a manifest, the
//! manifest MUST verify against a pinned key, and the downloaded asset MUST
//! hash to the manifest's entry (the per-asset `.sha256` is cross-checked
//! against the same entry -- a disagreement refuses the update). **Without a
//! key pinned** (the state until the operator generates one), behaviour is
//! exactly the #168 per-asset check, and a manifest that is present is only
//! logged as "unverified: no release key pinned". [`ProvenanceOutcome`]
//! reports which of these happened.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
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

/// The release manifest the pipeline publishes once per release (#184), next
/// to the per-asset files: `<base>/release-manifest.json`.
pub(crate) const RELEASE_MANIFEST_NAME: &str = "release-manifest.json";

/// Its detached signature: base64 (standard alphabet, padding, trailing
/// newline tolerated) of a 64-byte ed25519 signature over the EXACT bytes of
/// [`RELEASE_MANIFEST_NAME`]. Only present once the operator has created the
/// signing key -- see `.github/workflows/release.yml`'s `manifest` job.
pub(crate) const RELEASE_MANIFEST_SIG_NAME: &str = "release-manifest.sig";

/// The one manifest schema this build understands.
const RELEASE_MANIFEST_SCHEMA: u64 = 1;

/// Ceiling on the manifest and on its signature file -- a real manifest for
/// the whole matrix is under 2 KiB, the signature under 100 bytes.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Pinned release-signing public keys: ed25519, 32 bytes, lower-case hex.
/// Two slots so a key rotation can ship a build that trusts BOTH the outgoing
/// and the incoming key before the first release signed only by the new one.
///
/// Key 1 was generated 2026-09-07 (scimbe's go on #184): `openssl genpkey
/// -algorithm ed25519`, public key hex via `openssl pkey -pubout -outform DER
/// | tail -c 32 | xxd -p -c 64`, the PEM stored ONLY as the
/// `CT_RELEASE_SIGNING_KEY` repository secret (never on a developer machine).
/// From the first release after this build, every self-update refuses a
/// release whose manifest is missing, unsigned, signed by another key, or
/// disagrees with the asset -- see the module doc's "Release provenance"
/// paragraph. Rotation: add the successor as the second slot, ship one release
/// signed by the OLD key, then drop the old slot.
pub(crate) const RELEASE_SIGNING_PUBKEYS: &[&str] = &[
    "73706122db4e9186743ab3aabdf55d80ecf7f08ddc6c5243c9887f7d9bcc9a78",
    // "<64 hex chars: the next key, only during a rotation>",
];

/// Env override for a private build that signs its own releases: one ed25519
/// public key as 64 hex chars. When set (non-empty) it REPLACES
/// [`RELEASE_SIGNING_PUBKEYS`] -- a private release stream cannot be signed by
/// the upstream key, so trusting both would be meaningless.
pub(crate) const RELEASE_PUBKEY_ENV: &str = "CT_AGENT_RELEASE_PUBKEY";

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

/// Decode exactly 64 hex chars into 32 bytes, naming what's wrong otherwise
/// (`what` says which kind of value it was: a digest, a public key). Only a
/// short prefix of the offending token is echoed back -- it may be anything a
/// misbehaving server returned.
fn decode_hex_32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let shown: String = s.chars().take(16).collect();
    if s.len() != 64 {
        return Err(format!(
            "{what} {shown:?}.. is {} chars long, expected exactly 64 hex chars",
            s.len()
        ));
    }
    if let Some(bad) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("{what} {shown:?}.. is not hex (contains {bad:?})"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Decode exactly 64 hex chars into a SHA-256 digest.
fn decode_sha256_hex(digest: &str) -> Result<[u8; 32], String> {
    decode_hex_32(digest, "digest")
}

/// Decode a 64-hex-char ed25519 public key into a [`VerifyingKey`], refusing
/// a non-canonical / off-curve encoding as well as a malformed string.
pub(crate) fn decode_release_pubkey_hex(hex: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_hex_32(hex.trim(), "release public key")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("release public key is not a valid ed25519 key: {e}"))
}

/// What the provenance check concluded for one download -- surfaced to the
/// operator in the update log line so "verified" and "checksum only" are
/// never confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceOutcome {
    /// A pinned key exists, the release manifest's signature verified against
    /// it, and the asset hashed to the manifest's entry.
    Verified,
    /// The release publishes a manifest but this build pins no key, so only
    /// the per-asset `.sha256` was checked.
    UnverifiedNoKey,
    /// The release publishes no manifest (it predates #184): per-asset
    /// `.sha256` only.
    NotProvided,
    /// `CT_AGENT_UPDATE_SKIP_VERIFY=1`: nothing was checked at all.
    Skipped,
}

impl ProvenanceOutcome {
    /// One phrase for the update log line.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Verified => "provenance verified (signed release manifest, pinned key)",
            Self::UnverifiedNoKey => "checksum only (release manifest present but no release key pinned)",
            Self::NotProvided => "checksum only (release publishes no manifest)",
            Self::Skipped => "UNVERIFIED (CT_AGENT_UPDATE_SKIP_VERIFY)",
        }
    }
}

/// `release-manifest.json` as the pipeline writes it (#184):
/// `{ "schema": 1, "tag": "vX.Y.Z", "created_at": <unix secs>, "assets": { "<name>": "<sha256 hex>" } }`.
/// `assets` is a `BTreeMap` so a re-serialised manifest is byte-stable, but
/// verification is always over the ORIGINAL bytes as served, never a
/// re-serialisation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReleaseManifest {
    pub schema: u64,
    pub tag: String,
    pub created_at: u64,
    pub assets: BTreeMap<String, String>,
}

impl ReleaseManifest {
    /// Parse and shape-check: schema 1, a non-empty tag, at least one asset,
    /// every digest exactly 64 hex chars. Structure only -- says nothing
    /// about who wrote it (that is [`verify_manifest_signature`]'s job).
    pub(crate) fn parse(bytes: &[u8]) -> Result<ReleaseManifest, String> {
        let m: ReleaseManifest = serde_json::from_slice(bytes)
            .map_err(|e| format!("{RELEASE_MANIFEST_NAME} is not JSON of the expected shape: {e}"))?;
        if m.schema != RELEASE_MANIFEST_SCHEMA {
            return Err(format!(
                "{RELEASE_MANIFEST_NAME} has schema {}, this build understands only {RELEASE_MANIFEST_SCHEMA}",
                m.schema
            ));
        }
        if m.tag.trim().is_empty() {
            return Err(format!("{RELEASE_MANIFEST_NAME} has an empty tag"));
        }
        if m.assets.is_empty() {
            return Err(format!("{RELEASE_MANIFEST_NAME} lists no assets"));
        }
        for (name, digest) in &m.assets {
            decode_sha256_hex(digest).map_err(|e| format!("{RELEASE_MANIFEST_NAME} entry for {name}: {e}"))?;
        }
        Ok(m)
    }

    /// The manifest's digest for `asset_name`, or an error naming what it
    /// does list.
    pub(crate) fn digest_for(&self, asset_name: &str) -> Result<[u8; 32], String> {
        match self.assets.get(asset_name) {
            Some(d) => decode_sha256_hex(d),
            None => Err(format!(
                "{RELEASE_MANIFEST_NAME} has no entry for {asset_name} (it lists: {})",
                self.assets.keys().cloned().collect::<Vec<_>>().join(", ")
            )),
        }
    }

    /// Release tags are `v0.7.12`; compare leniently on the `v` so a manifest
    /// written as `0.7.12` by hand still matches.
    fn is_for_tag(&self, tag: &str) -> bool {
        self.tag.trim().trim_start_matches('v') == tag.trim().trim_start_matches('v')
    }
}

/// Which release-signing keys this process trusts -- the pinned constants,
/// or the env override, or (today) nothing.
#[derive(Debug, Clone)]
pub(crate) struct ProvenancePolicy {
    keys: Vec<VerifyingKey>,
}

impl ProvenancePolicy {
    /// No key pinned: per-asset checksum behaviour only.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self::with_keys(Vec::new())
    }

    /// Trust exactly these keys.
    pub(crate) fn with_keys(keys: Vec<VerifyingKey>) -> Self {
        Self { keys }
    }

    /// [`RELEASE_SIGNING_PUBKEYS`] unless [`RELEASE_PUBKEY_ENV`] overrides it.
    pub(crate) fn from_env() -> Result<Self, String> {
        Self::from_lookup(RELEASE_SIGNING_PUBKEYS, |k| std::env::var(k).ok())
    }

    /// Resolve from an explicit constant slice and a variable lookup (testable
    /// without touching the real env). A malformed key -- compiled-in or from
    /// the env -- is an error, never silently "no key" (that would quietly
    /// downgrade a fleet to checksum-only).
    pub(crate) fn from_lookup(pinned: &[&str], f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        if let Some(v) = f(RELEASE_PUBKEY_ENV) {
            if !v.trim().is_empty() {
                let key = decode_release_pubkey_hex(&v).map_err(|e| format!("{RELEASE_PUBKEY_ENV}: {e}"))?;
                return Ok(Self::with_keys(vec![key]));
            }
        }
        let keys = pinned
            .iter()
            .map(|h| decode_release_pubkey_hex(h).map_err(|e| format!("compiled-in RELEASE_SIGNING_PUBKEYS: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::with_keys(keys))
    }

    pub(crate) fn has_pinned_key(&self) -> bool {
        !self.keys.is_empty()
    }
}

/// Check `release-manifest.sig` (base64 of a 64-byte ed25519 signature) over
/// the exact `manifest` bytes against any one of `keys`. `verify_strict`
/// rejects the malleable / small-order encodings plain `verify` tolerates.
pub(crate) fn verify_manifest_signature(manifest: &[u8], sig_file: &[u8], keys: &[VerifyingKey]) -> Result<(), String> {
    let text = std::str::from_utf8(sig_file).map_err(|_| format!("{RELEASE_MANIFEST_SIG_NAME} is not UTF-8"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| format!("{RELEASE_MANIFEST_SIG_NAME} is not base64: {e}"))?;
    let sig = Signature::from_slice(&raw).map_err(|_| {
        format!(
            "{RELEASE_MANIFEST_SIG_NAME} decodes to {} bytes, an ed25519 signature is exactly 64",
            raw.len()
        )
    })?;
    if keys.iter().any(|k| k.verify_strict(manifest, &sig).is_ok()) {
        Ok(())
    } else {
        Err(format!(
            "{RELEASE_MANIFEST_SIG_NAME} does not verify against any of the {} pinned release key(s)",
            keys.len()
        ))
    }
}

/// Fetch `<base_url>/release-manifest.json` and, if it exists, its `.sig`.
/// `Ok(None)`: the manifest is absent (HTTP 404) -- the release predates
/// manifests. `Ok(Some((manifest, None)))`: a manifest but no signature (the
/// pipeline had no signing key yet). Any other non-2xx, or an oversize body,
/// is an error. Both bodies are returned as the exact bytes served: the
/// signature is over those, never over a re-serialisation.
pub(crate) async fn fetch_release_manifest(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<Option<(Vec<u8>, Option<Vec<u8>>)>, String> {
    let url = download_url(base_url, RELEASE_MANIFEST_NAME);
    let resp = client.get(&url).send().await.map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    let manifest = read_body_capped(resp, &url, MAX_MANIFEST_BYTES).await?;

    let sig_url = download_url(base_url, RELEASE_MANIFEST_SIG_NAME);
    let resp = client.get(&sig_url).send().await.map_err(|e| format!("GET {sig_url}: {e}"))?;
    let status = resp.status();
    let sig = if status == reqwest::StatusCode::NOT_FOUND {
        None
    } else if !status.is_success() {
        return Err(format!("GET {sig_url}: HTTP {status}"));
    } else {
        Some(read_body_capped(resp, &sig_url, MAX_MANIFEST_BYTES).await?)
    };
    Ok(Some((manifest, sig)))
}

/// Decide what the download must hash to, given what the release publishes
/// and what this build trusts -- the whole #184 policy in one pure function.
///
/// * No key pinned: the per-asset digest is authoritative, exactly as before
///   #184. A manifest that is present is logged as unverified.
/// * A key pinned: the manifest MUST be present AND signed AND verify, MUST
///   be for `expected_tag`, MUST list `asset_name`, and the per-asset
///   `.sha256` MUST agree with it. Any deviation refuses the update -- the
///   per-asset file alone can no longer authorise an install.
pub(crate) fn evaluate_provenance(
    policy: &ProvenancePolicy,
    fetched: Option<(&[u8], Option<&[u8]>)>,
    expected_tag: &str,
    asset_name: &str,
    per_asset_digest: &[u8; 32],
) -> Result<(ProvenanceOutcome, [u8; 32]), String> {
    if !policy.has_pinned_key() {
        return Ok(match fetched {
            None => (ProvenanceOutcome::NotProvided, *per_asset_digest),
            Some((_, sig)) => {
                eprintln!(
                    "ct-agent: release {expected_tag} publishes {RELEASE_MANIFEST_NAME}{} -- unverified: no \
                     release key pinned in this build (RELEASE_SIGNING_PUBKEYS is empty and \
                     {RELEASE_PUBKEY_ENV} is unset); installing on the per-asset .sha256 alone",
                    if sig.is_some() { " with a signature" } else { " without a signature" }
                );
                (ProvenanceOutcome::UnverifiedNoKey, *per_asset_digest)
            }
        });
    }
    let (manifest_bytes, sig) = fetched.ok_or_else(|| {
        format!(
            "a release signing key is pinned but release {expected_tag} publishes no {RELEASE_MANIFEST_NAME} \
             -- refusing to install on the per-asset .sha256 alone (either the release predates signed \
             manifests or the manifest was stripped); {SKIP_VERIFY_ENV}=1 installs unverified (not recommended)"
        )
    })?;
    let sig = sig.ok_or_else(|| {
        format!(
            "a release signing key is pinned but release {expected_tag} publishes {RELEASE_MANIFEST_NAME} \
             without {RELEASE_MANIFEST_SIG_NAME} -- refusing"
        )
    })?;
    verify_manifest_signature(manifest_bytes, sig, &policy.keys).map_err(|e| format!("{e} -- refusing"))?;
    let manifest = ReleaseManifest::parse(manifest_bytes)?;
    if !manifest.is_for_tag(expected_tag) {
        return Err(format!(
            "{RELEASE_MANIFEST_NAME} is for tag {} but the release being installed is {expected_tag} -- refusing",
            manifest.tag
        ));
    }
    let digest = manifest.digest_for(asset_name)?;
    if digest != *per_asset_digest {
        return Err(format!(
            "{asset_name}.sha256 ({}..) disagrees with the signed {RELEASE_MANIFEST_NAME} entry ({}..) -- refusing",
            hex_encode(&per_asset_digest[..8]),
            hex_encode(&digest[..8])
        ));
    }
    Ok((ProvenanceOutcome::Verified, digest))
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
/// have been verified, plus what the provenance check concluded. Order
/// matters: the checksum and the release manifest are fetched FIRST, so a
/// missing/unparsable one -- or a manifest that fails its signature under a
/// pinned key -- fails fast before the (much larger) binary is pulled; the
/// binary is then read under `max_bytes` and compared against the digest
/// [`evaluate_provenance`] settled on. Nothing here touches the filesystem.
pub(crate) async fn download_verified(
    client: &reqwest::Client,
    base_url: &str,
    asset_name: &str,
    expected_tag: &str,
    policy: ChecksumPolicy,
    provenance: &ProvenancePolicy,
    max_bytes: u64,
) -> Result<(Vec<u8>, ProvenanceOutcome), String> {
    let (expected, outcome) = match policy {
        ChecksumPolicy::Require => {
            let per_asset = fetch_expected_sha256(client, base_url, asset_name).await?;
            let fetched = fetch_release_manifest(client, base_url).await?;
            let fetched_ref = fetched.as_ref().map(|(m, s)| (m.as_slice(), s.as_deref()));
            let (outcome, digest) =
                evaluate_provenance(provenance, fetched_ref, expected_tag, asset_name, &per_asset)?;
            (Some(digest), outcome)
        }
        ChecksumPolicy::Skip => {
            eprintln!(
                "ct-agent: WARNING: {SKIP_VERIFY_ENV} is set -- installing {asset_name} WITHOUT \
                 verifying it against its published .sha256 or the signed release manifest; only \
                 ever do this for a private build"
            );
            (None, ProvenanceOutcome::Skipped)
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
    Ok((body, outcome))
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
/// **Provenance** (#184): with a release key pinned ([`RELEASE_SIGNING_PUBKEYS`]
/// / [`RELEASE_PUBKEY_ENV`]) the signed `release-manifest.json` is required
/// and authoritative -- see [`evaluate_provenance`]. The returned
/// [`ProvenanceOutcome`] says which check actually happened.
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
pub async fn perform_update(check: &UpdateCheck) -> Result<(PathBuf, ProvenanceOutcome), String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let provenance = ProvenancePolicy::from_env()?;
    perform_update_into(
        check,
        &current_exe,
        RELEASE_DOWNLOAD_BASE,
        ChecksumPolicy::from_env(),
        &provenance,
        MAX_UPDATE_BYTES,
    )
    .await
}

/// The whole of [`perform_update`] with its environment made explicit -- the
/// path to replace, the release base URL, the checksum policy, the pinned
/// release keys and the size cap -- so tests can drive it against a local
/// HTTP server and a temp file instead of the real binary and GitHub.
pub(crate) async fn perform_update_into(
    check: &UpdateCheck,
    current_exe: &Path,
    base_url: &str,
    policy: ChecksumPolicy,
    provenance: &ProvenancePolicy,
    max_bytes: u64,
) -> Result<(PathBuf, ProvenanceOutcome), String> {
    let dir = current_exe.parent().ok_or("current exe has no parent directory")?;
    let tmp_path = dir.join(format!(".{}.new", check.asset_name));

    let client = http_client(&check.current_version)?;
    let (bytes, outcome) = download_verified(
        &client,
        base_url,
        &check.asset_name,
        &check.latest_version,
        policy,
        provenance,
        max_bytes,
    )
    .await?;

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

    Ok((current_exe.to_path_buf(), outcome))
}

/// Helper for `main.rs`'s `update` subcommand -- ties [`check_latest`] and
/// [`perform_update`] together with the user-facing messages, so the CLI
/// dispatch stays a thin call like every other subcommand there.
pub async fn run_update(current_version: &str) -> Result<(), String> {
    let check = match check_latest(current_version).await {
        Ok(c) => c,
        Err(e) => {
            emit_update_check(&format!("error: {e}"));
            return Err(e);
        }
    };
    if !check.update_available {
        eprintln!(
            "ct-agent: already on the latest release ({} == {})",
            check.current_version, check.latest_version
        );
        emit_update_check("up-to-date");
        return Ok(());
    }
    emit_update_check(&format!("available: {}", check.latest_version));
    eprintln!(
        "ct-agent: updating {} -> {} ({})",
        check.current_version, check.latest_version, check.asset_name
    );
    let (path, outcome) = perform_update(&check).await?;
    eprintln!(
        "ct-agent: updated to {} at {path:?} [{}] -- restart the agent to run the new build",
        check.latest_version,
        outcome.describe()
    );
    crate::events::emit(crate::events::UPDATE_APPLIED, serde_json::json!({ "version": check.latest_version }));
    Ok(())
}

/// ct-agent#178: one `update_check {result}` event per release check, from both
/// the manual subcommand and the background loop.
fn emit_update_check(result: &str) {
    crate::events::emit(crate::events::UPDATE_CHECK, serde_json::json!({ "result": result }));
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
        // ct-agent#178: every step of the loop is visible on /status as `update_state`.
        crate::status::set_update_state(format!("scheduled: next check in {}s", config.interval.as_secs()));
        tokio::time::sleep(config.interval).await;
        crate::status::set_update_state("checking");
        let check = match check_latest(&current_version).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ct-agent: auto-update check failed, will retry next interval: {e}");
                crate::status::set_update_state(format!("check failed: {e}"));
                emit_update_check(&format!("error: {e}"));
                continue;
            }
        };
        if !check.update_available {
            crate::status::set_update_state(format!("up-to-date ({})", check.current_version));
            emit_update_check("up-to-date");
            continue;
        }
        eprintln!(
            "ct-agent: auto-update found {} -> {} ({}) -- downloading",
            check.current_version, check.latest_version, check.asset_name
        );
        emit_update_check(&format!("available: {}", check.latest_version));
        crate::status::set_update_state(format!("downloading {}", check.latest_version));
        match perform_update(&check).await {
            Ok((path, outcome)) => {
                eprintln!(
                    "ct-agent: auto-updated to {} at {path:?} [{}] -- exiting so a process \
                     supervisor restarts into the new build (this exit is only useful \
                     paired with one -- see CT_AGENT_AUTO_UPDATE's own docs)",
                    check.latest_version,
                    outcome.describe()
                );
                crate::status::set_update_state(format!(
                    "applied {}, exiting for the supervisor",
                    check.latest_version
                ));
                crate::events::emit(
                    crate::events::UPDATE_APPLIED,
                    serde_json::json!({ "version": check.latest_version }),
                );
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ct-agent: auto-update download/swap failed, will retry next interval: {e}");
                crate::status::set_update_state(format!("apply failed: {e}"));
                emit_update_check(&format!("apply failed: {e}"));
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

    /// [`perform_update_into`] for [`ASSET`] with no release key pinned -- the
    /// pre-#184 shape every checksum test below drives.
    async fn update_into(
        exe: &Path,
        base: &str,
        policy: ChecksumPolicy,
        max_bytes: u64,
    ) -> Result<(PathBuf, ProvenanceOutcome), String> {
        perform_update_into(&check_for(ASSET), exe, base, policy, &ProvenancePolicy::none(), max_bytes).await
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

        let (installed, outcome) = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap();

        assert_eq!(installed, exe);
        assert_eq!(outcome, ProvenanceOutcome::NotProvided, "no manifest served, no key pinned");
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

        let err = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap_err();

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

        let err = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap_err();

        assert!(err.contains("no entry for"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_when_the_checksum_file_is_missing() {
        // Binary present, .sha256 absent (HTTP 404): a hard error naming the override.
        let base = spawn_mock_release(vec![(ASSET.to_string(), NEW_BINARY.to_vec())], false).await;
        let (dir, exe) = fake_install();

        let err = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap_err();

        assert!(err.contains("HTTP 404"), "{err}");
        assert!(err.contains(".sha256"), "{err}");
        assert!(err.contains(SKIP_VERIFY_ENV), "the error must say how to override: {err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_skip_verify_installs_without_a_checksum_file() {
        let base = spawn_mock_release(vec![(ASSET.to_string(), NEW_BINARY.to_vec())], false).await;
        let (_dir, exe) = fake_install();

        let (_, outcome) = update_into(&exe, &base, ChecksumPolicy::Skip, MAX_UPDATE_BYTES).await.unwrap();

        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
        assert_eq!(outcome, ProvenanceOutcome::Skipped);
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
        let err = update_into(&exe, &base, ChecksumPolicy::Require, 512).await.unwrap_err();

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

        let err = update_into(&exe, &base, ChecksumPolicy::Require, 2048).await.unwrap_err();

        assert!(err.contains("body exceeds the 2048-byte download cap"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_missing_asset() {
        let base = spawn_mock_release(vec![(format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, ASSET))], false)
            .await;
        let (dir, exe) = fake_install();

        let err = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap_err();

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

    // ---- release provenance (#184) ---------------------------------------------------

    use ed25519_dalek::{Signer, SigningKey};

    /// The tag every mock release in this module is for (`check_for` says v9.9.9).
    const TAG: &str = "v9.9.9";

    /// A deterministic release key -- fixed seed, so a failure reproduces exactly.
    fn release_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A different key -- a manifest signed by this one must be refused.
    fn wrong_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn pubkey_hex(key: &SigningKey) -> String {
        hex_encode(key.verifying_key().as_bytes())
    }

    fn policy_for(key: &SigningKey) -> ProvenancePolicy {
        ProvenancePolicy::with_keys(vec![key.verifying_key()])
    }

    /// What [`fetch_release_manifest`] returns for a signed release.
    fn signed<'a>(manifest: &'a [u8], sig: &'a [u8]) -> Option<(&'a [u8], Option<&'a [u8]>)> {
        Some((manifest, Some(sig)))
    }

    /// ... and for a release whose pipeline had no signing key.
    fn unsigned(manifest: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
        Some((manifest, None))
    }

    /// [`perform_update_into`] for [`ASSET`] with `key` pinned as the release key.
    async fn update_with_key(
        exe: &Path,
        base: &str,
        policy: ChecksumPolicy,
        key: &SigningKey,
    ) -> Result<(PathBuf, ProvenanceOutcome), String> {
        perform_update_into(&check_for(ASSET), exe, base, policy, &policy_for(key), MAX_UPDATE_BYTES).await
    }

    /// The manifest bytes exactly as release.yml's `manifest` job writes them
    /// (sorted keys, compact JSON).
    fn manifest_bytes(tag: &str, assets: &[(&str, &[u8])]) -> Vec<u8> {
        let m = ReleaseManifest {
            schema: 1,
            tag: tag.to_string(),
            created_at: 1_757_000_000,
            assets: assets.iter().map(|(n, b)| (n.to_string(), sha256_hex(b))).collect(),
        };
        serde_json::to_vec(&m).unwrap()
    }

    /// `release-manifest.sig` as the pipeline writes it: base64 of the raw
    /// 64-byte signature, with the trailing newline `base64` emits.
    fn sig_file(key: &SigningKey, manifest: &[u8]) -> Vec<u8> {
        let sig = key.sign(manifest);
        let mut out = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()).into_bytes();
        out.push(b'\n');
        out
    }

    /// A full mock release: asset, its `.sha256`, the manifest and its signature.
    fn signed_release(key: &SigningKey, asset_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let manifest = manifest_bytes(TAG, &[(ASSET, asset_bytes), (OTHER_ASSET, b"supervisor")]);
        vec![
            (ASSET.to_string(), asset_bytes.to_vec()),
            (format!("{ASSET}.sha256"), checksum_file_for(asset_bytes, ASSET)),
            (RELEASE_MANIFEST_SIG_NAME.to_string(), sig_file(key, &manifest)),
            (RELEASE_MANIFEST_NAME.to_string(), manifest),
        ]
    }

    #[test]
    fn release_manifest_parses_the_pipeline_shape() {
        let bytes = manifest_bytes(TAG, &[(ASSET, NEW_BINARY), (OTHER_ASSET, b"supervisor")]);
        let m = ReleaseManifest::parse(&bytes).unwrap();
        assert_eq!(m.schema, 1);
        assert_eq!(m.tag, TAG);
        assert_eq!(m.created_at, 1_757_000_000);
        assert_eq!(m.assets.len(), 2);
        assert_eq!(m.digest_for(ASSET).unwrap(), sha256_of(NEW_BINARY));
        assert!(m.is_for_tag("9.9.9"), "the v prefix is not significant");
        assert!(!m.is_for_tag("v9.9.8"));
        // Hand-written with whitespace and a v-less tag: still the same shape.
        let loose = format!(
            "{{\n  \"schema\": 1,\n  \"tag\": \"9.9.9\",\n  \"created_at\": 1,\n  \
             \"assets\": {{ \"{ASSET}\": \"{}\" }}\n}}\n",
            sha256_hex(NEW_BINARY)
        );
        assert!(ReleaseManifest::parse(loose.as_bytes()).unwrap().is_for_tag(TAG));
    }

    #[test]
    fn release_manifest_rejects_malformed_shapes() {
        let err = ReleaseManifest::parse(b"not json").unwrap_err();
        assert!(err.contains("not JSON"), "{err}");
        let err = ReleaseManifest::parse(br#"{"schema":2,"tag":"v1","created_at":1,"assets":{"a":"00"}}"#).unwrap_err();
        assert!(err.contains("schema 2"), "{err}");
        let err = ReleaseManifest::parse(br#"{"schema":1,"tag":"","created_at":1,"assets":{"a":"00"}}"#).unwrap_err();
        assert!(err.contains("empty tag"), "{err}");
        let err = ReleaseManifest::parse(br#"{"schema":1,"tag":"v1","created_at":1,"assets":{}}"#).unwrap_err();
        assert!(err.contains("no assets"), "{err}");
        let err = ReleaseManifest::parse(br#"{"schema":1,"tag":"v1","created_at":1,"assets":{"a":"zz"}}"#).unwrap_err();
        assert!(err.contains("entry for a"), "{err}");
        assert!(err.contains("64 hex chars"), "{err}");
        // Missing field.
        let err = ReleaseManifest::parse(br#"{"schema":1,"tag":"v1","assets":{}}"#).unwrap_err();
        assert!(err.contains("created_at"), "{err}");
        // The right shape but no entry for the asset being installed.
        let m = ReleaseManifest::parse(&manifest_bytes(TAG, &[(OTHER_ASSET, b"supervisor")])).unwrap();
        let err = m.digest_for(ASSET).unwrap_err();
        assert!(err.contains("no entry for ct-agent-linux-x86_64"), "{err}");
        assert!(err.contains(OTHER_ASSET), "{err}");
    }

    #[test]
    fn verify_manifest_signature_accepts_the_signing_key_and_refuses_others() {
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&release_key(), &manifest);
        let good = release_key().verifying_key();
        let other = wrong_key().verifying_key();

        assert_eq!(verify_manifest_signature(&manifest, &sig, &[good]), Ok(()));
        // Two-slot rotation: either key may be the one that signed.
        assert_eq!(verify_manifest_signature(&manifest, &sig, &[other, good]), Ok(()));

        let err = verify_manifest_signature(&manifest, &sig, &[other]).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        // Signature over DIFFERENT bytes than the ones served.
        let mut tampered = manifest.clone();
        tampered.push(b'\n');
        let err = verify_manifest_signature(&tampered, &sig, &[good]).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        // Malformed signature files.
        let err = verify_manifest_signature(&manifest, b"***", &[good]).unwrap_err();
        assert!(err.contains("not base64"), "{err}");
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        let err = verify_manifest_signature(&manifest, short.as_bytes(), &[good]).unwrap_err();
        assert!(err.contains("10 bytes"), "{err}");
    }

    #[test]
    fn evaluate_provenance_verified_when_a_pinned_key_signs_a_matching_manifest() {
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&release_key(), &manifest);
        let per_asset = sha256_of(NEW_BINARY);
        let (outcome, digest) = evaluate_provenance(
            &policy_for(&release_key()),
            signed(&manifest, &sig),
            TAG,
            ASSET,
            &per_asset,
        )
        .unwrap();
        assert_eq!(outcome, ProvenanceOutcome::Verified);
        assert_eq!(digest, per_asset);
    }

    #[test]
    fn evaluate_provenance_refuses_the_wrong_key() {
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&wrong_key(), &manifest);
        let err = evaluate_provenance(
            &policy_for(&release_key()),
            signed(&manifest, &sig),
            TAG,
            ASSET,
            &sha256_of(NEW_BINARY),
        )
        .unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn evaluate_provenance_refuses_a_manifest_asset_hash_mismatch() {
        // Properly signed manifest, but its entry for the asset is for OTHER bytes
        // than the per-asset .sha256 says -- the two sources disagree, refuse.
        let manifest = manifest_bytes(TAG, &[(ASSET, b"what the release was supposed to be")]);
        let sig = sig_file(&release_key(), &manifest);
        let err = evaluate_provenance(
            &policy_for(&release_key()),
            signed(&manifest, &sig),
            TAG,
            ASSET,
            &sha256_of(NEW_BINARY),
        )
        .unwrap_err();
        assert!(err.contains("disagrees with the signed"), "{err}");
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn evaluate_provenance_with_a_pinned_key_requires_manifest_signature_tag_and_entry() {
        let policy = policy_for(&release_key());
        let per_asset = sha256_of(NEW_BINARY);

        // No manifest at all.
        let err = evaluate_provenance(&policy, None, TAG, ASSET, &per_asset).unwrap_err();
        assert!(err.contains("publishes no release-manifest.json"), "{err}");
        assert!(err.contains(SKIP_VERIFY_ENV), "the error must say how to override: {err}");

        // Manifest but no signature.
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let err = evaluate_provenance(&policy, unsigned(&manifest), TAG, ASSET, &per_asset).unwrap_err();
        assert!(err.contains("without release-manifest.sig"), "{err}");

        // Signed, but for another release (a replayed older manifest).
        let old = manifest_bytes("v9.9.8", &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&release_key(), &old);
        let err = evaluate_provenance(&policy, signed(&old, &sig), TAG, ASSET, &per_asset).unwrap_err();
        assert!(err.contains("is for tag v9.9.8"), "{err}");

        // Signed, right tag, but no entry for this platform's asset.
        let partial = manifest_bytes(TAG, &[(OTHER_ASSET, b"supervisor")]);
        let sig = sig_file(&release_key(), &partial);
        let err = evaluate_provenance(&policy, signed(&partial, &sig), TAG, ASSET, &per_asset).unwrap_err();
        assert!(err.contains("no entry for"), "{err}");
    }

    #[test]
    fn evaluate_provenance_without_a_pinned_key_proceeds_on_the_per_asset_check() {
        let per_asset = sha256_of(NEW_BINARY);
        let none = ProvenancePolicy::none();

        // No manifest published: the pre-#184 world.
        let (outcome, digest) = evaluate_provenance(&none, None, TAG, ASSET, &per_asset).unwrap();
        assert_eq!(outcome, ProvenanceOutcome::NotProvided);
        assert_eq!(digest, per_asset);

        // A signed manifest is published, but nothing to verify it against: the
        // per-asset digest stays authoritative and the outcome says so (the
        // "unverified: no release key pinned" note goes to stderr).
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&release_key(), &manifest);
        let (outcome, digest) = evaluate_provenance(&none, signed(&manifest, &sig), TAG, ASSET, &per_asset).unwrap();
        assert_eq!(outcome, ProvenanceOutcome::UnverifiedNoKey);
        assert_eq!(digest, per_asset);

        // Even a manifest that would NOT verify, or that disagrees with the
        // per-asset file, changes nothing without a key: it is not consulted.
        let bogus = manifest_bytes(TAG, &[(ASSET, b"something else")]);
        let bad_sig = sig_file(&wrong_key(), &bogus);
        let (outcome, digest) = evaluate_provenance(&none, signed(&bogus, &bad_sig), TAG, ASSET, &per_asset).unwrap();
        assert_eq!(outcome, ProvenanceOutcome::UnverifiedNoKey);
        assert_eq!(digest, per_asset);
    }

    #[test]
    fn provenance_policy_resolves_pinned_constants_and_the_env_override() {
        // The shipped constant carries the production key since 2026-09-07 (#184): it
        // must parse as a valid ed25519 point and count as pinned, so every release
        // from here on is verified against the manifest.
        let shipped = ProvenancePolicy::from_lookup(RELEASE_SIGNING_PUBKEYS, lookup(&[])).unwrap();
        assert!(shipped.has_pinned_key());
        assert_eq!(shipped.keys.len(), 1);
        // An empty slice plus a blank env override is the only way to get "no key".
        assert!(!ProvenancePolicy::from_lookup(&[], lookup(&[(RELEASE_PUBKEY_ENV, "  ")])).unwrap().has_pinned_key());

        // Two compiled-in slots.
        let a = pubkey_hex(&release_key());
        let b = pubkey_hex(&wrong_key());
        let both = ProvenancePolicy::from_lookup(&[a.as_str(), b.as_str()], lookup(&[])).unwrap();
        assert_eq!(both.keys.len(), 2);
        assert!(both.keys.contains(&release_key().verifying_key()));
        assert!(both.keys.contains(&wrong_key().verifying_key()));

        // The env override REPLACES the constants (a private build's own key).
        let padded = format!(" {b} \n");
        let env_only =
            ProvenancePolicy::from_lookup(&[a.as_str()], lookup(&[(RELEASE_PUBKEY_ENV, padded.as_str())])).unwrap();
        assert_eq!(env_only.keys, vec![wrong_key().verifying_key()]);

        // A malformed key -- compiled-in or from the env -- is an error, never
        // a silent downgrade to "no key".
        let err = ProvenancePolicy::from_lookup(&["abc"], lookup(&[])).unwrap_err();
        assert!(err.contains("RELEASE_SIGNING_PUBKEYS"), "{err}");
        assert!(err.contains("64 hex chars"), "{err}");
        let err = ProvenancePolicy::from_lookup(&[], lookup(&[(RELEASE_PUBKEY_ENV, "zz")])).unwrap_err();
        assert!(err.contains(RELEASE_PUBKEY_ENV), "{err}");
        // 64 hex chars that are not a valid curve point: y = 2 has no square
        // root for x on ed25519 (checked with a Legendre-symbol computation),
        // so decompression must fail.
        let off_curve = format!("02{}", "00".repeat(31));
        let err = ProvenancePolicy::from_lookup(&[], lookup(&[(RELEASE_PUBKEY_ENV, off_curve.as_str())])).unwrap_err();
        assert!(err.contains("not a valid ed25519 key"), "{err}");
    }

    #[test]
    fn env_override_key_verifies_a_manifest_end_to_end_in_memory() {
        // The operator of a private build pins their own key via the env var and
        // signs their own manifest with it.
        let private_key_hex = pubkey_hex(&wrong_key());
        let policy =
            ProvenancePolicy::from_lookup(&[], lookup(&[(RELEASE_PUBKEY_ENV, private_key_hex.as_str())])).unwrap();
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&wrong_key(), &manifest);
        let (outcome, _) =
            evaluate_provenance(&policy, signed(&manifest, &sig), TAG, ASSET, &sha256_of(NEW_BINARY)).unwrap();
        assert_eq!(outcome, ProvenanceOutcome::Verified);
    }

    #[tokio::test]
    async fn fetch_release_manifest_distinguishes_absent_unsigned_and_signed() {
        let client = http_client("0.0.1").unwrap();
        let manifest = manifest_bytes(TAG, &[(ASSET, NEW_BINARY)]);
        let sig = sig_file(&release_key(), &manifest);

        // Release predates manifests: 404 -> None.
        let base = spawn_mock_release(vec![], false).await;
        assert_eq!(fetch_release_manifest(&client, &base).await.unwrap(), None);

        // Manifest, no signature (pipeline ran without the secret).
        let base = spawn_mock_release(vec![(RELEASE_MANIFEST_NAME.to_string(), manifest.clone())], false).await;
        assert_eq!(fetch_release_manifest(&client, &base).await.unwrap(), Some((manifest.clone(), None)));

        // Both, byte-exact.
        let base = spawn_mock_release(
            vec![
                (RELEASE_MANIFEST_NAME.to_string(), manifest.clone()),
                (RELEASE_MANIFEST_SIG_NAME.to_string(), sig.clone()),
            ],
            false,
        )
        .await;
        assert_eq!(fetch_release_manifest(&client, &base).await.unwrap(), Some((manifest, Some(sig))));
    }

    #[tokio::test]
    async fn perform_update_into_verifies_a_signed_manifest_end_to_end() {
        let base = spawn_mock_release(signed_release(&release_key(), NEW_BINARY), false).await;
        let (_dir, exe) = fake_install();

        let (installed, outcome) = update_with_key(&exe, &base, ChecksumPolicy::Require, &release_key()).await.unwrap();

        assert_eq!(installed, exe);
        assert_eq!(outcome, ProvenanceOutcome::Verified);
        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_manifest_signed_by_the_wrong_key_end_to_end() {
        // The asset and its .sha256 are perfectly consistent; only the manifest's
        // signer is wrong. With a key pinned that alone must refuse the install.
        let base = spawn_mock_release(signed_release(&wrong_key(), NEW_BINARY), false).await;
        let (dir, exe) = fake_install();

        let err = update_with_key(&exe, &base, ChecksumPolicy::Require, &release_key()).await.unwrap_err();

        assert!(err.contains("does not verify"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_when_a_key_is_pinned_but_the_release_has_no_manifest() {
        let base = spawn_mock_release(
            vec![
                (ASSET.to_string(), NEW_BINARY.to_vec()),
                (format!("{ASSET}.sha256"), checksum_file_for(NEW_BINARY, ASSET)),
            ],
            false,
        )
        .await;
        let (dir, exe) = fake_install();

        let err = update_with_key(&exe, &base, ChecksumPolicy::Require, &release_key()).await.unwrap_err();

        assert!(err.contains("publishes no release-manifest.json"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_refuses_a_manifest_that_disagrees_with_the_asset_end_to_end() {
        // Signed manifest says the asset should be OTHER bytes; the served asset
        // and its .sha256 agree with each other but not with the manifest.
        let mut files = signed_release(&release_key(), b"what the release was supposed to be");
        for (name, content) in files.iter_mut() {
            if name == ASSET {
                *content = NEW_BINARY.to_vec();
            } else if name == &format!("{ASSET}.sha256") {
                *content = checksum_file_for(NEW_BINARY, ASSET);
            }
        }
        let base = spawn_mock_release(files, false).await;
        let (dir, exe) = fake_install();

        let err = update_with_key(&exe, &base, ChecksumPolicy::Require, &release_key()).await.unwrap_err();

        assert!(err.contains("disagrees with the signed"), "{err}");
        assert_untouched(dir.path(), &exe);
    }

    #[tokio::test]
    async fn perform_update_into_without_a_pinned_key_installs_a_signed_release_as_unverified() {
        // Today's shipped state: the release is signed, the build pins nothing.
        // The per-asset check still gates the install; the outcome records that
        // the manifest went unverified.
        let base = spawn_mock_release(signed_release(&release_key(), NEW_BINARY), false).await;
        let (_dir, exe) = fake_install();

        let (_, outcome) = update_into(&exe, &base, ChecksumPolicy::Require, MAX_UPDATE_BYTES).await.unwrap();

        assert_eq!(outcome, ProvenanceOutcome::UnverifiedNoKey);
        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
    }

    #[tokio::test]
    async fn perform_update_into_skip_verify_bypasses_the_manifest_too() {
        // A wrong-key manifest AND a wrong .sha256 -- SKIP_VERIFY installs anyway,
        // loudly, and reports Skipped rather than any flavour of "checked".
        let mut files = signed_release(&wrong_key(), b"something else entirely");
        for (name, content) in files.iter_mut() {
            if name == ASSET {
                *content = NEW_BINARY.to_vec();
            }
        }
        let base = spawn_mock_release(files, false).await;
        let (_dir, exe) = fake_install();

        let (_, outcome) = update_with_key(&exe, &base, ChecksumPolicy::Skip, &release_key()).await.unwrap();

        assert_eq!(outcome, ProvenanceOutcome::Skipped);
        assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
    }
}
