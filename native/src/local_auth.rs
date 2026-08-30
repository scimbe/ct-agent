//! Generic local-service credential gate (operator-directed hardening pass,
//! Kali-inspired: forwarded local services get an Agent-enforced credential
//! check even when they have no auth of their own).
//!
//! **Mesh-Plane only.** The Browser Plane (`CT_AGENT_MODE=browser`) forwards
//! opaque, still-TLS-encrypted bytes to the Origin verbatim -- the Agent never
//! decrypts them, so there is nothing here to parse or challenge. Bringing
//! Browser Plane into scope would need the Agent to terminate TLS itself for
//! the Origin's own hostname; that is a materially different, larger project,
//! out of scope here.
//!
//! **What this protects, and what it does not.** The gate sits at the one
//! choke point every Mesh-Plane relay path through the Agent shares
//! (`serve.rs::connect_origin`). It fires for every connection that reaches
//! the Origin *through the Agent's own relay path* -- the legitimate tunnel
//! path via the Edge, or a direct connection to the Agent's own listener
//! (`serve_direct`). It does **not**, and cannot, protect a client that
//! reaches the Origin's **own listening socket directly**, bypassing the
//! Agent entirely. Binding the Origin to loopback-only, so it is *only*
//! reachable via the Agent, is what makes this gate a real defense rather
//! than cosmetic -- that is the operator's job to arrange, not something this
//! feature provides on its own.
//!
//! **Protocol scope.** Two sub-modes: [`GateMode::Http`] challenges with a
//! real `WWW-Authenticate: Basic` exchange a browser understands natively;
//! [`GateMode::TextChallenge`] writes a plain `Password: ` prompt and reads a
//! line back, which only works for an interactive/text-oriented peer (a human
//! at `nc`/`telnet`, a scripted reverse-shell handler) -- the literal
//! motivating case for this feature. Structured binary protocols (SSH, VNC,
//! RDP, database wire protocols) have clients that emit their own handshake
//! bytes immediately and never read a text prompt at all; those Origins are
//! explicitly **out of scope for v1** and must stay undisguised as such, not
//! silently unprotected-by-implication.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::secret_file::write_private;

/// How (or whether) the gate checks a connection before letting it reach the
/// Origin. Chosen per the Origin's protocol shape -- see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// No gate -- traffic reaches the Origin unchecked (today's behavior).
    Off,
    /// HTTP Basic-Auth challenge/response.
    Http,
    /// A plain `Password: ` prompt for interactive/text-oriented Origins.
    TextChallenge,
}

impl GateMode {
    fn parse(s: &str) -> Result<GateMode, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" => Ok(GateMode::Http),
            "text" | "textchallenge" | "text-challenge" => Ok(GateMode::TextChallenge),
            "" | "off" | "0" | "false" => Ok(GateMode::Off),
            other => Err(format!(
                "invalid CT_AGENT_LOCAL_AUTH '{other}' (expected http|text|off)"
            )),
        }
    }
}

/// A stored credential: `username` (only meaningful for [`GateMode::Http`]'s
/// Basic-Auth shape; ignored by [`GateMode::TextChallenge`]) plus a salted
/// SHA-256 hash of the password/token. Plain salted SHA-256 is proportionate
/// here, not argon2/bcrypt: `capability.rs`'s own documented threat model is
/// that anyone who reads the Agent's state dir already holds the capability
/// token and Origin private key sitting beside this hash file -- i.e. full
/// tunnel takeover regardless of hash strength. What this hash actually
/// defends against is *online* LAN-local guessing, which is [`RateLimiter`]'s
/// job, not the hash function's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub username: String,
    salt: [u8; 16],
    hash: [u8; 32],
}

impl StoredCredential {
    /// Generate a fresh, random credential: `username` fixed at `"agent"`
    /// (the generated flow needs no operator input), a random 20-byte token
    /// (shown to the operator once, never stored in plaintext).
    fn generate() -> (StoredCredential, String) {
        let mut token_bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let cred = Self::new("agent".to_string(), token.as_bytes());
        (cred, token)
    }

    fn new(username: String, password: &[u8]) -> StoredCredential {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let hash = hash_credential(&salt, password);
        StoredCredential { username, salt, hash }
    }

    /// Serialize as `username:salt_hex:hash_hex` -- one line, written via
    /// [`write_private`] so it is never on disk wider than `0600`.
    fn serialize(&self) -> String {
        format!("{}:{}:{}", self.username, hex_encode(&self.salt), hex_encode(&self.hash))
    }

    fn parse(line: &str) -> Result<StoredCredential, String> {
        let mut parts = line.trim().splitn(3, ':');
        let username = parts.next().ok_or("missing username field")?.to_string();
        let salt_hex = parts.next().ok_or("missing salt field")?;
        let hash_hex = parts.next().ok_or("missing hash field")?;
        let salt = hex_decode_fixed::<16>(salt_hex).map_err(|e| format!("invalid salt: {e}"))?;
        let hash = hex_decode_fixed::<32>(hash_hex).map_err(|e| format!("invalid hash: {e}"))?;
        Ok(StoredCredential { username, salt, hash })
    }

    /// Constant-time verification of `attempt` against the stored hash.
    /// Username comparison is NOT constant-time (usernames aren't secret;
    /// only the password/token is) -- see the struct doc for why hash
    /// strength itself is not the binding constraint here.
    fn verify(&self, attempt_username: &str, attempt_password: &[u8]) -> bool {
        if self.username != attempt_username {
            return false;
        }
        self.verify_password(attempt_password)
    }

    /// Same check, ignoring the username entirely -- used by
    /// [`GateMode::TextChallenge`], whose prompt is a bare "Password: " with
    /// no username step (see the module doc: the credential's username only
    /// matters for the HTTP Basic-Auth shape).
    fn verify_password(&self, attempt_password: &[u8]) -> bool {
        let candidate = hash_credential(&self.salt, attempt_password);
        constant_time_eq(&self.hash, &candidate)
    }
}

fn hash_credential(salt: &[u8; 16], password: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password);
    hasher.finalize().into()
}

/// Hand-rolled constant-time compare (XOR-accumulate) -- avoids pulling in
/// the `subtle` crate for one function. Both inputs are fixed-size 32-byte
/// hashes so there is no length-leak to guard against separately.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// A per-process, global (not per-source -- the Agent has no reliable
/// visibility into the real Client IP through a relayed connection) failure
/// lockout: after [`MAX_FAILURES`] failed attempts within [`WINDOW`], every
/// attempt (even a correct one) is refused for [`LOCKOUT`] from the *last*
/// failure. Deliberately simple for v1 -- exponential backoff / per-source
/// tracking are plausible follow-ups, not asserted as built here.
pub struct RateLimiter {
    failures: AtomicU32,
    window_start_secs: AtomicU64,
    locked_until_secs: AtomicU64,
}

const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(60);
const LOCKOUT: Duration = Duration::from_secs(30);

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitVerdict {
    /// The attempt may proceed to a credential check.
    Allowed,
    /// Locked out; retry after this many seconds.
    Locked { retry_after_secs: u64 },
}

impl RateLimiter {
    pub fn new() -> RateLimiter {
        RateLimiter {
            failures: AtomicU32::new(0),
            window_start_secs: AtomicU64::new(0),
            locked_until_secs: AtomicU64::new(0),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    /// Call before running a credential check. `Locked` means: reject this
    /// attempt WITHOUT even comparing the credential, and do not count it as
    /// an additional failure (it already isn't one -- the peer never got to
    /// try).
    pub fn check(&self) -> RateLimitVerdict {
        let now = Self::now_secs();
        let locked_until = self.locked_until_secs.load(Ordering::SeqCst);
        if locked_until > now {
            return RateLimitVerdict::Locked { retry_after_secs: locked_until - now };
        }
        RateLimitVerdict::Allowed
    }

    /// Record the outcome of a credential check that [`check`] allowed to
    /// proceed. A success resets the failure window entirely; a failure
    /// counts toward the window and, once [`MAX_FAILURES`] is reached, locks
    /// out for [`LOCKOUT`] from now.
    ///
    /// [`check`]: Self::check
    pub fn record(&self, success: bool) {
        let now = Self::now_secs();
        if success {
            self.failures.store(0, Ordering::SeqCst);
            self.window_start_secs.store(0, Ordering::SeqCst);
            return;
        }
        let window_start = self.window_start_secs.load(Ordering::SeqCst);
        if window_start == 0 || now.saturating_sub(window_start) > WINDOW.as_secs() {
            // Fresh window.
            self.window_start_secs.store(now, Ordering::SeqCst);
            self.failures.store(1, Ordering::SeqCst);
            return;
        }
        let count = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= MAX_FAILURES {
            self.locked_until_secs.store(now + LOCKOUT.as_secs(), Ordering::SeqCst);
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// The full gate: mode + credential + rate limiter, resolved once at startup
/// and shared (via `Arc`) across every relayed connection this Agent serves.
pub struct LocalAuthGate {
    pub mode: GateMode,
    credential: Option<StoredCredential>,
    pub limiter: RateLimiter,
}

/// Filename under `CT_AGENT_STATE_DIR` for the generated-and-hashed
/// credential (provisioning option B -- the default; see `set`/`reset` for
/// the CLI-managed variant, and `CT_AGENT_LOCAL_AUTH_FILE` for an
/// operator-supplied file entirely outside the state dir, option C).
pub const CREDENTIAL_FILENAME: &str = "local-auth.hash";

impl LocalAuthGate {
    /// Resolve the gate from environment + on-disk state, generating and
    /// printing a fresh credential on first run if the mode is enabled and no
    /// credential exists yet anywhere (state dir, or `CT_AGENT_LOCAL_AUTH_FILE`
    /// if set). Returns `(gate, printed_first_boot_notice)` -- the caller
    /// decides where the notice actually goes (stderr in the live binary;
    /// swallowed in tests).
    pub fn from_env(
        state_dir: Option<&Path>,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<(LocalAuthGate, Option<String>), String> {
        let mode = match get("CT_AGENT_LOCAL_AUTH") {
            Some(s) => GateMode::parse(&s)?,
            None => GateMode::Off,
        };
        if mode == GateMode::Off {
            return Ok((
                LocalAuthGate { mode, credential: None, limiter: RateLimiter::new() },
                None,
            ));
        }
        if let Some(file) = get("CT_AGENT_LOCAL_AUTH_FILE") {
            let contents = std::fs::read_to_string(&file)
                .map_err(|e| format!("CT_AGENT_LOCAL_AUTH_FILE '{file}': {e}"))?;
            check_file_not_group_or_world_readable(Path::new(&file))?;
            let credential = StoredCredential::parse(contents.trim())
                .map_err(|e| format!("CT_AGENT_LOCAL_AUTH_FILE '{file}': {e}"))?;
            return Ok((
                LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new() },
                None,
            ));
        }
        let dir = state_dir.ok_or_else(|| {
            "CT_AGENT_LOCAL_AUTH is set but neither CT_AGENT_LOCAL_AUTH_FILE nor \
             CT_AGENT_STATE_DIR is -- nowhere to store the generated credential"
                .to_string()
        })?;
        let path = dir.join(CREDENTIAL_FILENAME);
        if path.exists() {
            let contents = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let credential = StoredCredential::parse(contents.trim())?;
            return Ok((
                LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new() },
                None,
            ));
        }
        let (credential, token) = StoredCredential::generate();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        write_private(&path, credential.serialize().as_bytes()).map_err(|e| e.to_string())?;
        let notice = format!(
            "ct-agent: generated a local-auth credential for this tunnel (mode={mode:?}).\n\
             \n    username: {}\n    password: {token}\n\n\
             This is shown ONCE -- it is not stored in recoverable form. If you lose it, run \
             `ct-agent local-auth reset` to generate a new one.",
            credential.username,
        );
        Ok((
            LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new() },
            Some(notice),
        ))
    }

    /// Verify an attempt, applying the rate limiter first. Returns `Ok(())`
    /// on success; `Err(GateRejection)` otherwise, naming why (so the caller
    /// can choose the right response -- a 401 vs. a lockout message differ).
    pub fn verify(&self, username: &str, password: &[u8]) -> Result<(), GateRejection> {
        match self.limiter.check() {
            RateLimitVerdict::Locked { retry_after_secs } => {
                return Err(GateRejection::RateLimited { retry_after_secs })
            }
            RateLimitVerdict::Allowed => {}
        }
        let ok = self
            .credential
            .as_ref()
            .map(|c| c.verify(username, password))
            .unwrap_or(false);
        self.limiter.record(ok);
        if ok {
            Ok(())
        } else {
            Err(GateRejection::BadCredential)
        }
    }

    /// Same as [`verify`](Self::verify) but for [`GateMode::TextChallenge`],
    /// which never collects a username.
    pub fn verify_password_only(&self, password: &[u8]) -> Result<(), GateRejection> {
        match self.limiter.check() {
            RateLimitVerdict::Locked { retry_after_secs } => {
                return Err(GateRejection::RateLimited { retry_after_secs })
            }
            RateLimitVerdict::Allowed => {}
        }
        let ok = self.credential.as_ref().map(|c| c.verify_password(password)).unwrap_or(false);
        self.limiter.record(ok);
        if ok {
            Ok(())
        } else {
            Err(GateRejection::BadCredential)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRejection {
    BadCredential,
    RateLimited { retry_after_secs: u64 },
}

/// Refuse to load a credential file that is readable by anyone but its
/// owner -- the same posture SSH takes on a loose private key. Unlike the
/// generated flow (which gets the create-time-`0600` guarantee for free via
/// [`write_private`]), an operator-supplied file was written by something
/// else entirely, so this is checked explicitly rather than assumed.
#[cfg(unix)]
fn check_file_not_group_or_world_readable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map_err(|e| e.to_string())?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "CT_AGENT_LOCAL_AUTH_FILE {path:?} is readable by group/other (mode {:o}) -- \
             chmod 600 it before running the Agent",
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_file_not_group_or_world_readable(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Bound on how much of a connection's opening bytes the HTTP sub-mode will
/// buffer looking for the `\r\n\r\n` header terminator, before failing
/// closed. Without this, a peer that opens a connection and never sends the
/// terminator causes unbounded per-connection buffering -- a trivial DoS
/// against the gate itself. This is part of the mechanism, not an add-on
/// hardening pass.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// How long [`find_authorization`]'s caller should wait for the terminator
/// before giving up, on top of the byte bound above.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Find `\r\n\r\n` in `buf` (bounded to [`MAX_HEADER_BYTES`]) and, if present,
/// extract the `Authorization: Basic <base64>` header's decoded
/// `username:password`. Returns `None` if the terminator isn't found within
/// the bound, or no `Authorization: Basic` header is present, or it doesn't
/// decode/split cleanly -- all three collapse to "no credential offered",
/// which the caller treats as a 401, not a parse error to surface.
pub fn parse_basic_auth(buf: &[u8]) -> Option<(String, Vec<u8>)> {
    let scan = &buf[..buf.len().min(MAX_HEADER_BYTES)];
    let end = find_subslice(scan, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&scan[..end]).ok()?;
    for line in head.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("authorization") {
            continue;
        }
        let value = value.trim();
        let b64 = value.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded_str.split_once(':')?;
        return Some((user.to_string(), pass.as_bytes().to_vec()));
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The literal `401 Unauthorized` response this gate writes back (as Noise
/// plaintext) on a failed/missing HTTP credential -- a real browser shows its
/// native Basic-Auth dialog on this, no client-side UX to build.
pub fn http_401_challenge() -> Vec<u8> {
    b"HTTP/1.1 401 Unauthorized\r\n\
      WWW-Authenticate: Basic realm=\"ct-agent\"\r\n\
      Content-Length: 0\r\n\
      Connection: close\r\n\r\n"
        .to_vec()
}

/// The plain-text prompt [`GateMode::TextChallenge`] writes before reading a
/// reply.
pub const TEXT_CHALLENGE_PROMPT: &[u8] = b"Password: ";

/// What [`GateMode::TextChallenge`] writes back on a failed attempt.
pub const TEXT_CHALLENGE_DENIED: &[u8] = b"Access denied.\r\n";

/// Path helper used by `main.rs`'s `local-auth` subcommand and by
/// [`from_env`](LocalAuthGate::from_env).
pub fn credential_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CREDENTIAL_FILENAME)
}

/// `ct-agent local-auth set <user> <password>`: write an operator-chosen
/// credential to the state dir, overwriting any generated one.
pub fn set_credential(state_dir: &Path, username: &str, password: &str) -> io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let credential = StoredCredential::new(username.to_string(), password.as_bytes());
    write_private(&credential_path(state_dir), credential.serialize().as_bytes())
}

/// `ct-agent local-auth reset` / `rotate`: generate a fresh credential and
/// print it once (same shape as first-boot generation).
pub fn reset_credential(state_dir: &Path) -> io::Result<String> {
    std::fs::create_dir_all(state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let (credential, token) = StoredCredential::generate();
    write_private(&credential_path(state_dir), credential.serialize().as_bytes())?;
    Ok(format!("username: {}\npassword: {token}", credential.username))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(what: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ct-local-auth-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn gate_mode_parses_and_rejects_garbage() {
        assert_eq!(GateMode::parse("http").unwrap(), GateMode::Http);
        assert_eq!(GateMode::parse("HTTP").unwrap(), GateMode::Http);
        assert_eq!(GateMode::parse("text").unwrap(), GateMode::TextChallenge);
        assert_eq!(GateMode::parse("").unwrap(), GateMode::Off);
        assert_eq!(GateMode::parse("off").unwrap(), GateMode::Off);
        assert!(GateMode::parse("vnc").is_err(), "binary-protocol modes are not a v1 thing");
    }

    #[test]
    fn stored_credential_round_trips_through_serialize_parse() {
        let cred = StoredCredential::new("agent".to_string(), b"correct-horse");
        let line = cred.serialize();
        let parsed = StoredCredential::parse(&line).unwrap();
        assert_eq!(parsed, cred);
    }

    #[test]
    fn stored_credential_verifies_the_right_password_and_rejects_others() {
        let cred = StoredCredential::new("agent".to_string(), b"correct-horse");
        assert!(cred.verify("agent", b"correct-horse"));
        assert!(!cred.verify("agent", b"wrong"));
        assert!(!cred.verify("someone-else", b"correct-horse"), "username must match too");
    }

    #[test]
    fn parse_basic_auth_extracts_valid_header() {
        // "alice:s3cret" base64-encoded.
        let creds_b64 = base64::engine::general_purpose::STANDARD.encode(b"alice:s3cret");
        let req = format!(
            "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {creds_b64}\r\n\r\n"
        );
        let (user, pass) = parse_basic_auth(req.as_bytes()).expect("header present");
        assert_eq!(user, "alice");
        assert_eq!(pass, b"s3cret");
    }

    #[test]
    fn parse_basic_auth_returns_none_when_header_absent() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(parse_basic_auth(req).is_none());
    }

    #[test]
    fn parse_basic_auth_returns_none_when_terminator_never_arrives_within_bound() {
        // A peer that never sends \r\n\r\n must not be scanned unboundedly --
        // this is the DoS the bounded scan exists to prevent (fail closed,
        // don't hang trying to find a terminator that isn't there).
        let mut req = b"GET / HTTP/1.1\r\nAuthorization: Basic YQ==\r\n".to_vec();
        req.extend(std::iter::repeat(b'x').take(MAX_HEADER_BYTES + 100));
        assert!(parse_basic_auth(&req).is_none());
    }

    #[test]
    fn parse_basic_auth_rejects_malformed_base64_without_panicking() {
        let req = b"GET / HTTP/1.1\r\nAuthorization: Basic ***not-base64***\r\n\r\n";
        assert!(parse_basic_auth(req).is_none());
    }

    #[test]
    fn rate_limiter_allows_until_the_failure_threshold_then_locks_out() {
        let limiter = RateLimiter::new();
        for _ in 0..MAX_FAILURES - 1 {
            assert_eq!(limiter.check(), RateLimitVerdict::Allowed);
            limiter.record(false);
        }
        // One more failure crosses the threshold.
        assert_eq!(limiter.check(), RateLimitVerdict::Allowed);
        limiter.record(false);
        match limiter.check() {
            RateLimitVerdict::Locked { retry_after_secs } => {
                assert!(retry_after_secs > 0 && retry_after_secs <= LOCKOUT.as_secs())
            }
            RateLimitVerdict::Allowed => panic!("must be locked after {MAX_FAILURES} failures"),
        }
    }

    #[test]
    fn rate_limiter_success_resets_the_failure_count() {
        let limiter = RateLimiter::new();
        limiter.record(false);
        limiter.record(false);
        limiter.record(true); // a real success clears the slate
        for _ in 0..MAX_FAILURES - 1 {
            limiter.record(false);
        }
        // Still under threshold since the counter was reset by the success above.
        assert_eq!(limiter.check(), RateLimitVerdict::Allowed);
    }

    #[test]
    fn gate_disabled_by_default_and_needs_no_state_dir() {
        let (gate, notice) = LocalAuthGate::from_env(None, |_| None).unwrap();
        assert_eq!(gate.mode, GateMode::Off);
        assert!(notice.is_none());
        // Off mode always rejects, since there is no credential -- but the
        // caller in serve.rs never calls verify() when mode is Off; this
        // just documents the safe default if it somehow were called.
        assert!(gate.verify("agent", b"anything").is_err());
    }

    #[test]
    fn gate_generates_and_persists_a_credential_on_first_run() {
        let dir = scratch("generate");
        let (gate, notice) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string()))
                .unwrap();
        assert_eq!(gate.mode, GateMode::Http);
        let notice = notice.expect("first boot prints the credential once");
        assert!(notice.contains("username: agent"));
        assert!(credential_path(&dir).exists());

        // A second call reads the SAME persisted credential back, no
        // re-generation and no second notice.
        let (_gate2, notice2) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string()))
                .unwrap();
        assert!(notice2.is_none(), "must not re-print/re-generate on a second boot");
    }

    #[test]
    fn gate_verify_end_to_end_against_a_generated_credential() {
        let dir = scratch("verify-e2e");
        let (gate, notice) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "text".to_string()))
                .unwrap();
        let notice = notice.unwrap();
        let token = notice.lines().find(|l| l.contains("password:")).unwrap();
        let token = token.trim_start_matches("    password: ").trim();
        assert!(gate.verify("agent", token.as_bytes()).is_ok());
        assert!(gate.verify("agent", b"definitely-wrong").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn generated_credential_file_and_state_dir_are_never_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let _ = LocalAuthGate::from_env(Some(&dir), |k| {
            (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string())
        })
        .unwrap();
        let file_mode = std::fs::metadata(credential_path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn set_credential_then_verify_round_trips() {
        let dir = scratch("set");
        set_credential(&dir, "root", "hunter2").unwrap();
        let (gate, notice) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string()))
                .unwrap();
        assert!(notice.is_none(), "an operator-set credential must not trigger generation");
        assert!(gate.verify("root", b"hunter2").is_ok());
        assert!(gate.verify("root", b"wrong").is_err());
    }

    #[test]
    fn verify_password_only_ignores_username_for_text_challenge_mode() {
        let dir = scratch("password-only");
        set_credential(&dir, "root", "hunter2").unwrap();
        let (gate, _) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "text".to_string()))
                .unwrap();
        assert!(gate.verify_password_only(b"hunter2").is_ok(), "username is irrelevant here");
        assert!(gate.verify_password_only(b"wrong").is_err());
    }

    #[test]
    fn reset_credential_replaces_a_prior_one() {
        let dir = scratch("reset");
        set_credential(&dir, "root", "old-pass").unwrap();
        let printed = reset_credential(&dir).unwrap();
        assert!(printed.contains("username: agent"));
        let (gate, _) =
            LocalAuthGate::from_env(Some(&dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string()))
                .unwrap();
        assert!(gate.verify("root", b"old-pass").is_err(), "the old credential must no longer work");
    }
}
