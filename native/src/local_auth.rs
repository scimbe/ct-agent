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

//! **Share links** (#185). A Basic-Auth credential is a poor thing to hand a
//! guest: it is the whole gate, forever, and revoking it means rotating it
//! for everyone. `ct-agent local-auth link --ttl 24h [--once]` mints a
//! time-boxed token instead. Presented as `?ct_link=<token>` on any request
//! target, a valid token answers with a 302 to the same path WITHOUT the
//! parameter plus a `ct_link_session` cookie carrying the token (so it does
//! not stay in the address bar / history / referers); the cookie is then
//! accepted until the link expires. Only SHA-256 hashes of tokens are stored
//! (`local-auth-links.json`, `0600`); the token itself is printed once at
//! mint time. `--once` links redeem a single time via the URL (the first
//! redemption stamps `used_at`), but the cookie that redemption set keeps
//! working until expiry. The store is re-read on every check, so a link
//! minted or revoked by the CLI while the agent serves takes effect
//! immediately. This is Mesh-Plane HTTP-mode only, like the rest of the gate.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ct_common::sync::MutexExt;
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
    /// Share links (#185) -- present whenever the gate is on and a state dir
    /// is known (the links file lives beside the credential hash). `None`
    /// means no link can ever be accepted: mode `Off`, or a
    /// `CT_AGENT_LOCAL_AUTH_FILE`-only setup without `CT_AGENT_STATE_DIR`.
    links: Option<LinkStore>,
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
                LocalAuthGate { mode, credential: None, limiter: RateLimiter::new(), links: None },
                None,
            ));
        }
        // Share links (#185) live in the state dir even when the credential
        // itself comes from CT_AGENT_LOCAL_AUTH_FILE.
        let links = state_dir.map(LinkStore::new);
        if let Some(file) = get("CT_AGENT_LOCAL_AUTH_FILE") {
            let contents = std::fs::read_to_string(&file)
                .map_err(|e| format!("CT_AGENT_LOCAL_AUTH_FILE '{file}': {e}"))?;
            check_file_not_group_or_world_readable(Path::new(&file))?;
            let credential = StoredCredential::parse(contents.trim())
                .map_err(|e| format!("CT_AGENT_LOCAL_AUTH_FILE '{file}': {e}"))?;
            return Ok((
                LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new(), links },
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
                LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new(), links },
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
            LocalAuthGate { mode, credential: Some(credential), limiter: RateLimiter::new(), links },
            Some(notice),
        ))
    }

    /// The share-link store (#185), if this gate can accept links at all.
    pub fn links(&self) -> Option<&LinkStore> {
        self.links.as_ref()
    }

    /// Look for a share link (#185) on an HTTP request head -- `?ct_link=`
    /// on the request target, else a `ct_link_session` cookie -- and judge
    /// it. Only called by the HTTP sub-mode when no `Authorization` header
    /// was offered; the rate limiter covers a presented-but-wrong token the
    /// same way it covers a wrong password, and a request that presents no
    /// token at all costs nothing (a browser's natural first request).
    pub fn check_share_link(&self, request: &[u8]) -> LinkGateVerdict {
        self.check_share_link_at(unix_now(), request)
    }

    /// [`check_share_link`](Self::check_share_link) at an explicit `now`.
    pub fn check_share_link_at(&self, now: u64, request: &[u8]) -> LinkGateVerdict {
        let Some(store) = &self.links else {
            return LinkGateVerdict::NotPresented;
        };
        let Some(head) = parse_request_head(request) else {
            return LinkGateVerdict::NotPresented;
        };
        let (token, via, stripped_target) = match link_token_in_target(head.target) {
            Some((token, stripped)) => (token, LinkPresentation::Query, Some(stripped)),
            None => match link_token_in_cookies(&head) {
                Some(token) => (token, LinkPresentation::Cookie, None),
                None => return LinkGateVerdict::NotPresented,
            },
        };
        if let RateLimitVerdict::Locked { retry_after_secs } = self.limiter.check() {
            return LinkGateVerdict::Rejected(LinkRejection::RateLimited { retry_after_secs });
        }
        let redeemed = match store.redeem_at(now, &token, via) {
            Ok(r) => r,
            Err(e) => {
                self.limiter.record(false);
                return LinkGateVerdict::Rejected(e);
            }
        };
        self.limiter.record(true);
        match stripped_target {
            Some(location) => LinkGateVerdict::Redirect {
                response: http_302_link_redirect(&location, &token, redeemed.remaining_secs),
                id: redeemed.id,
            },
            None => LinkGateVerdict::Authenticated { id: redeemed.id },
        }
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

// ---- share links (#185) ---------------------------------------------------------------

/// Filename under the state dir for the share-link records (#185): a JSON
/// list of [`ShareLink`]s, written `0600` via [`write_private`]. Token
/// HASHES only -- a token itself is printed once at mint time, never stored.
pub const LINKS_FILENAME: &str = "local-auth-links.json";

/// Ceiling on ACTIVE (unexpired, unrevoked) links; `link` refuses past it.
pub const MAX_ACTIVE_LINKS: usize = 50;

/// Expired links stay on file this long past their expiry (so `links` can
/// still show what a guest had), then drop off on the next write.
pub const LINK_PRUNE_AFTER: Duration = Duration::from_secs(7 * 86_400);

/// Longest `--ttl` accepted. A share link is for a guest, not a tenant: past
/// a month the operator should hand out a real credential instead.
pub const MAX_LINK_TTL: Duration = Duration::from_secs(30 * 86_400);

/// Query parameter a share link is presented on: `?ct_link=<token>`.
pub const LINK_QUERY_PARAM: &str = "ct_link";

/// Cookie the 302 sets and later requests are recognised by.
pub const LINK_COOKIE_NAME: &str = "ct_link_session";

/// Labels are printed in log lines and listings: one line, bounded.
const MAX_LABEL_CHARS: usize = 64;

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// One share link as stored on disk. `token_hash` is the lower-case hex
/// SHA-256 of the token string; the token is never on disk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareLink {
    pub id: String,
    pub token_hash: String,
    pub label: String,
    pub expires_at: u64,
    pub single_use: bool,
    /// First successful redemption (URL or cookie) -- stamped once.
    #[serde(default)]
    pub used_at: Option<u64>,
    /// Set by `link-revoke`; the record stays for the listing until pruned.
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

impl ShareLink {
    /// Counts against [`MAX_ACTIVE_LINKS`] and can (still) be redeemed.
    pub fn is_active(&self, now: u64) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    /// One word for the listing.
    pub fn status(&self, now: u64) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if now >= self.expires_at {
            "expired"
        } else if self.single_use && self.used_at.is_some() {
            "used (cookie still valid)"
        } else if self.used_at.is_some() {
            "active (in use)"
        } else {
            "active"
        }
    }
}

/// Parse `--ttl`: `<n>s`, `<n>m`, `<n>h`, `<n>d`, or a bare number of
/// seconds. Positive, at most [`MAX_LINK_TTL`].
pub fn parse_ttl(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = (&s[..split], s[split..].trim());
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid --ttl '{s}' (expected e.g. 1h, 24h, 7d or 3600s)"))?;
    let mult: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(format!("invalid --ttl unit '{unit}' in '{s}' (expected s, m, h or d)")),
    };
    let secs = n.checked_mul(mult).ok_or_else(|| format!("--ttl '{s}' overflows"))?;
    if secs == 0 {
        return Err("--ttl must be positive".to_string());
    }
    if secs > MAX_LINK_TTL.as_secs() {
        return Err(format!("--ttl '{s}' exceeds the {}-day maximum", MAX_LINK_TTL.as_secs() / 86_400));
    }
    Ok(Duration::from_secs(secs))
}

fn hash_link_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// A share-link token is 32 random bytes as base64url without padding: 43
/// chars of `[A-Za-z0-9_-]`. Anything outside that alphabet is refused
/// before it is hashed, which also guarantees a token echoed into a
/// `Set-Cookie` header can never smuggle a `;`, CR or LF.
fn looks_like_link_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// One line, control characters stripped, bounded -- a label is printed in
/// log lines and listings.
fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// What `local-auth link` hands back -- the ONLY time the token exists in
/// plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedLink {
    pub id: String,
    pub token: String,
    pub label: String,
    pub expires_at: u64,
    pub single_use: bool,
}

impl MintedLink {
    /// The URL form, with a placeholder host: the agent does not know the
    /// public hostname its tunnel is served under.
    pub fn url_with_placeholder_host(&self) -> String {
        format!("https://<your-hostname>/?{LINK_QUERY_PARAM}={}", self.token)
    }

    /// What `ct-agent local-auth link` prints -- the one and only time the
    /// token is shown.
    pub fn announcement(&self, ttl: Duration) -> String {
        let label = if self.label.is_empty() { "-".to_string() } else { self.label.clone() };
        format!(
            "ct-agent: local-auth share link minted -- the token is shown ONCE, not recoverable after this:\n\
             \n    id:       {}\n    label:    {label}\n    expires:  {} (unix; in {})\n    once:     {}\n    \
             token:    {}\n    url:      {}\n\n\
             Replace <your-hostname> with the public hostname this tunnel is reached under -- the agent \
             does not know it. The first visit answers with a 302 that drops the token from the URL and \
             sets a {LINK_COOKIE_NAME} cookie for the link's remaining lifetime. Revoke early with \
             `ct-agent local-auth link-revoke {}`.",
            self.id,
            self.expires_at,
            format_ttl(ttl),
            if self.single_use { "yes (the URL redeems once; its cookie lasts until expiry)" } else { "no" },
            self.token,
            self.url_with_placeholder_host(),
            self.id,
        )
    }
}

/// `7d` / `24h` / `15m` / `90s` -- the largest unit that divides evenly.
pub fn format_ttl(ttl: Duration) -> String {
    let s = ttl.as_secs();
    if s > 0 && s % 86_400 == 0 {
        format!("{}d", s / 86_400)
    } else if s > 0 && s % 3_600 == 0 {
        format!("{}h", s / 3_600)
    } else if s > 0 && s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// `ct-agent local-auth link --ttl <duration> [--once] [--label <text>]`,
/// parsed from the arguments after `link`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkArgs {
    pub ttl: Duration,
    pub single_use: bool,
    pub label: String,
}

/// The usage line every `link` argument error ends with.
pub const LINK_USAGE: &str = "usage: ct-agent local-auth link --ttl <1h|24h|7d|<n>s> [--once] [--label <text>]";

pub fn parse_link_args(args: &[String]) -> Result<LinkArgs, String> {
    let mut ttl = None;
    let mut single_use = false;
    let mut label = String::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ttl" => {
                let v = it.next().ok_or_else(|| format!("--ttl needs a value\n{LINK_USAGE}"))?;
                ttl = Some(parse_ttl(v).map_err(|e| format!("{e}\n{LINK_USAGE}"))?);
            }
            "--once" => single_use = true,
            "--label" => {
                let v = it.next().ok_or_else(|| format!("--label needs a value\n{LINK_USAGE}"))?;
                label = v.clone();
            }
            other => {
                if let Some(v) = other.strip_prefix("--ttl=") {
                    ttl = Some(parse_ttl(v).map_err(|e| format!("{e}\n{LINK_USAGE}"))?);
                } else if let Some(v) = other.strip_prefix("--label=") {
                    label = v.to_string();
                } else {
                    return Err(format!("unexpected argument '{other}'\n{LINK_USAGE}"));
                }
            }
        }
    }
    let ttl = ttl.ok_or_else(|| format!("--ttl is required\n{LINK_USAGE}"))?;
    Ok(LinkArgs { ttl, single_use, label })
}

/// How a token reached the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPresentation {
    /// `?ct_link=<token>` on the request target -- answered with the 302.
    Query,
    /// The `ct_link_session` cookie the 302 set.
    Cookie,
}

/// Why a presented token was refused. Every variant is a 401 to the client;
/// the distinction is for the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRejection {
    /// No record hashes to this token (never minted, or pruned).
    Unknown,
    Expired,
    Revoked,
    /// A `--once` link presented via the URL a second time.
    AlreadyUsed,
    /// The gate's failure lockout is in force.
    RateLimited { retry_after_secs: u64 },
    /// The links file could not be read or updated -- fail closed.
    Store(String),
}

impl std::fmt::Display for LinkRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown token"),
            Self::Expired => write!(f, "link expired"),
            Self::Revoked => write!(f, "link revoked"),
            Self::AlreadyUsed => write!(f, "single-use link already redeemed"),
            Self::RateLimited { retry_after_secs } => write!(f, "rate limited, retry in {retry_after_secs}s"),
            Self::Store(e) => write!(f, "links file: {e}"),
        }
    }
}

/// A successful redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedLink {
    pub id: String,
    pub label: String,
    pub single_use: bool,
    /// Seconds until expiry -- the cookie's `Max-Age`.
    pub remaining_secs: u64,
    /// This redemption stamped `used_at`.
    pub first_use: bool,
}

/// The share-link store: `<state_dir>/local-auth-links.json`, re-read on
/// every operation (the CLI mints and revokes while the agent serves, so a
/// cached copy would be stale) and written back `0600`. The in-process mutex
/// serialises the agent's own read-modify-write cycles (concurrent
/// redemptions); a CLI write racing the agent's is not guarded beyond
/// "last writer wins", which for a used_at stamp or a revocation is a
/// tolerable window, never a way to un-revoke a link.
pub struct LinkStore {
    path: PathBuf,
    state_dir: PathBuf,
    lock: Mutex<()>,
}

impl LinkStore {
    pub fn new(state_dir: &Path) -> LinkStore {
        LinkStore {
            path: state_dir.join(LINKS_FILENAME),
            state_dir: state_dir.to_path_buf(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<Vec<ShareLink>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("reading {:?}: {e}", self.path)),
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("parsing {:?}: {e}", self.path))
    }

    /// Prune, then write `0600`. Every write goes through here.
    fn save(&self, links: &mut Vec<ShareLink>, now: u64) -> Result<(), String> {
        links.retain(|l| now < l.expires_at.saturating_add(LINK_PRUNE_AFTER.as_secs()));
        std::fs::create_dir_all(&self.state_dir).map_err(|e| format!("creating {:?}: {e}", self.state_dir))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.state_dir, std::fs::Permissions::from_mode(0o700));
        }
        let json = serde_json::to_vec_pretty(links).map_err(|e| e.to_string())?;
        write_private(&self.path, &json).map_err(|e| format!("writing {:?}: {e}", self.path))
    }

    /// `ct-agent local-auth link`: mint a token, store its hash, return the
    /// token (once).
    pub fn mint(&self, ttl: Duration, single_use: bool, label: &str) -> Result<MintedLink, String> {
        self.mint_at(unix_now(), ttl, single_use, label)
    }

    /// [`mint`](Self::mint) at an explicit `now`.
    pub fn mint_at(&self, now: u64, ttl: Duration, single_use: bool, label: &str) -> Result<MintedLink, String> {
        let _guard = self.lock.lock_safe();
        let mut links = self.load()?;
        let active = links.iter().filter(|l| l.is_active(now)).count();
        if active >= MAX_ACTIVE_LINKS {
            return Err(format!(
                "{active} share links are already active (the cap is {MAX_ACTIVE_LINKS}) -- revoke one \
                 with `ct-agent local-auth link-revoke <id>` first"
            ));
        }
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let mut id_bytes = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let id = hex_encode(&id_bytes);
        let link = ShareLink {
            id: id.clone(),
            token_hash: hex_encode(&hash_link_token(&token)),
            label: sanitize_label(label),
            expires_at: now.saturating_add(ttl.as_secs()),
            single_use,
            used_at: None,
            revoked_at: None,
        };
        links.push(link.clone());
        self.save(&mut links, now)?;
        emit_link_event("minted", &link, "");
        Ok(MintedLink { id, token, label: link.label, expires_at: link.expires_at, single_use })
    }

    /// `ct-agent local-auth links`: every record still on file (no tokens --
    /// there are none to show).
    pub fn list(&self) -> Result<Vec<ShareLink>, String> {
        let _guard = self.lock.lock_safe();
        self.load()
    }

    /// `ct-agent local-auth link-revoke <id>`.
    pub fn revoke(&self, id: &str) -> Result<ShareLink, String> {
        self.revoke_at(unix_now(), id)
    }

    /// [`revoke`](Self::revoke) at an explicit `now`.
    pub fn revoke_at(&self, now: u64, id: &str) -> Result<ShareLink, String> {
        let _guard = self.lock.lock_safe();
        let mut links = self.load()?;
        let link = links.iter_mut().find(|l| l.id == id).ok_or_else(|| format!("no share link with id {id}"))?;
        if link.revoked_at.is_some() {
            return Err(format!("share link {id} is already revoked"));
        }
        link.revoked_at = Some(now);
        let revoked = link.clone();
        self.save(&mut links, now)?;
        emit_link_event("revoked", &revoked, "");
        Ok(revoked)
    }

    /// Judge a presented token. The hash comparison is constant-time per
    /// record; the walk over records is not (their count is not secret).
    /// A `--once` link accepts the URL form exactly once; the cookie form is
    /// accepted for as long as the link is unexpired and unrevoked, since
    /// the cookie IS the session that one redemption opened.
    pub fn redeem(&self, token: &str, via: LinkPresentation) -> Result<RedeemedLink, LinkRejection> {
        self.redeem_at(unix_now(), token, via)
    }

    /// [`redeem`](Self::redeem) at an explicit `now`.
    pub fn redeem_at(&self, now: u64, token: &str, via: LinkPresentation) -> Result<RedeemedLink, LinkRejection> {
        if !looks_like_link_token(token) {
            return Err(LinkRejection::Unknown);
        }
        let presented = hash_link_token(token);
        let _guard = self.lock.lock_safe();
        let mut links = self.load().map_err(LinkRejection::Store)?;
        let link = links
            .iter_mut()
            .find(|l| hex_decode_fixed::<32>(&l.token_hash).map(|h| constant_time_eq(&h, &presented)).unwrap_or(false))
            .ok_or(LinkRejection::Unknown)?;
        if link.revoked_at.is_some() {
            return Err(LinkRejection::Revoked);
        }
        if now >= link.expires_at {
            return Err(LinkRejection::Expired);
        }
        if link.single_use && link.used_at.is_some() && via == LinkPresentation::Query {
            return Err(LinkRejection::AlreadyUsed);
        }
        let first_use = link.used_at.is_none();
        if first_use {
            link.used_at = Some(now);
        }
        let redeemed = RedeemedLink {
            id: link.id.clone(),
            label: link.label.clone(),
            single_use: link.single_use,
            remaining_secs: link.expires_at - now,
            first_use,
        };
        let snapshot = link.clone();
        if first_use {
            self.save(&mut links, now).map_err(LinkRejection::Store)?;
        }
        let via_name = match via {
            LinkPresentation::Query => "query",
            LinkPresentation::Cookie => "cookie",
        };
        emit_link_event("redeemed", &snapshot, &format!(" via={via_name} first_use={first_use}"));
        Ok(redeemed)
    }
}

/// The mint / redeem / revoke audit line. This worktree has no `events`
/// module (an `emit` helper landed on main after this branch forked, if at
/// all), so the line goes to stderr with the wording an events sink would
/// carry -- swap the body for `crate::events::emit` when merging onto it.
fn emit_link_event(what: &str, link: &ShareLink, extra: &str) {
    eprintln!(
        "ct-agent: local-auth link {what} id={} label={:?} expires_at={} single_use={}{extra}",
        link.id, link.label, link.expires_at, link.single_use
    );
}

/// The request line and headers of one HTTP/1.x request head, borrowed from
/// the buffer. Bounded like [`parse_basic_auth`]: no terminator within
/// [`MAX_HEADER_BYTES`] means "not an HTTP request we will look at".
pub struct RequestHead<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
}

/// Parse the head out of `buf` (through the first `\r\n\r\n`, within
/// [`MAX_HEADER_BYTES`]). Header lines without a colon are skipped rather
/// than failing the whole head; names are returned as-is (compare
/// case-insensitively), values trimmed.
pub fn parse_request_head(buf: &[u8]) -> Option<RequestHead<'_>> {
    let scan = &buf[..buf.len().min(MAX_HEADER_BYTES)];
    let end = find_subslice(scan, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&scan[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ').filter(|p| !p.is_empty());
    let method = parts.next()?;
    let target = parts.next()?;
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(n, v)| (n.trim(), v.trim())).collect();
    Some(RequestHead { method, target, headers })
}

/// If `target` carries `?ct_link=<token>`, return the token and the target
/// with that parameter removed (other parameters kept in order; a `?` with
/// nothing left behind it is dropped) -- the `Location` of the 302.
pub fn link_token_in_target(target: &str) -> Option<(String, String)> {
    let (path, query) = target.split_once('?')?;
    let mut token: Option<String> = None;
    let mut rest: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == LINK_QUERY_PARAM {
            if token.is_none() {
                token = Some(v.to_string());
            }
        } else if !pair.is_empty() {
            rest.push(pair);
        }
    }
    let token = token?;
    let stripped = if rest.is_empty() { path.to_string() } else { format!("{path}?{}", rest.join("&")) };
    Some((token, stripped))
}

/// The `ct_link_session` cookie's value, if any `Cookie` header carries it.
pub fn link_token_in_cookies(head: &RequestHead<'_>) -> Option<String> {
    head.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(n, _)| n.trim() == LINK_COOKIE_NAME)
        .map(|(_, v)| v.trim().to_string())
}

/// The 302 that answers a valid `?ct_link=` redemption: back to `location`
/// (the same target minus the parameter) with the session cookie set for
/// exactly the link's remaining lifetime. `HttpOnly` keeps page scripts away
/// from it, `Secure` keeps it off plain-HTTP hops, `SameSite=Lax` keeps a
/// cross-site POST from riding on it. `location` comes from a request line
/// (no whitespace by construction); anything with a control character in it
/// falls back to `/` so no header can be injected through it.
pub fn http_302_link_redirect(location: &str, token: &str, max_age_secs: u64) -> Vec<u8> {
    let safe_location = if location.is_empty() || location.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        "/"
    } else {
        location
    };
    let token = if looks_like_link_token(token) { token } else { "" };
    format!(
        "HTTP/1.1 302 Found\r\n\
         Location: {safe_location}\r\n\
         Set-Cookie: {LINK_COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}\r\n\
         Cache-Control: no-store\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

/// What [`LocalAuthGate::check_share_link`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGateVerdict {
    /// The request carries no `?ct_link=` and no `ct_link_session` cookie.
    NotPresented,
    /// A valid cookie: the request is authenticated, forward it as-is.
    Authenticated { id: String },
    /// A valid URL token: write `response` (the 302 + cookie) and close;
    /// the browser comes back with the cookie on a fresh connection.
    Redirect { response: Vec<u8>, id: String },
    /// A token was presented and refused: answer with the 401 challenge.
    Rejected(LinkRejection),
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
        req.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES + 100));
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

    // ---- share links (#185) -----------------------------------------------------------

    const NOW: u64 = 1_757_000_000;
    const HOUR: Duration = Duration::from_secs(3_600);

    fn http_gate(dir: &Path) -> LocalAuthGate {
        set_credential(dir, "agent", "s3cret").unwrap();
        LocalAuthGate::from_env(Some(dir), |k| (k == "CT_AGENT_LOCAL_AUTH").then(|| "http".to_string()))
            .unwrap()
            .0
    }

    fn get_with_query(token: &str) -> Vec<u8> {
        format!("GET /app/page?x=1&{LINK_QUERY_PARAM}={token}&y=2 HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes()
    }

    fn get_with_cookie(token: &str) -> Vec<u8> {
        format!("GET /app/page HTTP/1.1\r\nHost: x\r\nCookie: a=b; {LINK_COOKIE_NAME}={token}; c=d\r\n\r\n")
            .into_bytes()
    }

    #[test]
    fn parse_ttl_accepts_the_documented_forms_and_rejects_garbage() {
        assert_eq!(parse_ttl("1h").unwrap(), HOUR);
        assert_eq!(parse_ttl("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(7 * 86_400));
        assert_eq!(parse_ttl("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_ttl(" 3600 ").unwrap(), HOUR, "a bare number is seconds");
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("0s").is_err(), "must be positive");
        assert!(parse_ttl("2w").is_err(), "unknown unit");
        assert!(parse_ttl("31d").is_err(), "past the 30-day cap");
        assert!(parse_ttl("99999999999999999999d").is_err(), "overflow, not a panic");
    }

    #[test]
    fn parse_link_args_covers_the_documented_flags() {
        fn args(s: &[&str]) -> Vec<String> {
            s.iter().map(|a| a.to_string()).collect()
        }
        assert_eq!(
            parse_link_args(&args(&["--ttl", "24h"])).unwrap(),
            LinkArgs { ttl: Duration::from_secs(86_400), single_use: false, label: String::new() }
        );
        assert_eq!(
            parse_link_args(&args(&["--once", "--label", "for bob", "--ttl=7d"])).unwrap(),
            LinkArgs { ttl: Duration::from_secs(7 * 86_400), single_use: true, label: "for bob".to_string() }
        );
        assert_eq!(parse_link_args(&args(&["--ttl", "1h", "--label=x"])).unwrap().label, "x");
        let err = parse_link_args(&args(&[])).unwrap_err();
        assert!(err.starts_with("--ttl is required"), "{err}");
        assert!(err.contains(LINK_USAGE), "{err}");
        assert!(parse_link_args(&args(&["--ttl"])).is_err());
        assert!(parse_link_args(&args(&["--ttl", "1h", "--label"])).is_err());
        assert!(parse_link_args(&args(&["--ttl", "1h", "--bogus"])).is_err());
        assert!(parse_link_args(&args(&["--ttl", "40d"])).is_err(), "the TTL cap applies here too");
    }

    #[test]
    fn format_ttl_picks_the_largest_even_unit() {
        assert_eq!(format_ttl(Duration::from_secs(7 * 86_400)), "7d");
        assert_eq!(format_ttl(Duration::from_secs(86_400)), "1d");
        assert_eq!(format_ttl(Duration::from_secs(3_600 * 5)), "5h");
        assert_eq!(format_ttl(Duration::from_secs(900)), "15m");
        assert_eq!(format_ttl(Duration::from_secs(90)), "90s");
        assert_eq!(format_ttl(Duration::from_secs(0)), "0s");
    }

    #[test]
    fn minted_link_announcement_shows_the_token_url_and_revoke_hint() {
        let m = MintedLink {
            id: "abc123".to_string(),
            token: "tok".to_string(),
            label: String::new(),
            expires_at: 42,
            single_use: true,
        };
        let text = m.announcement(Duration::from_secs(3_600));
        assert!(text.contains("token:    tok\n"), "{text}");
        assert!(text.contains("url:      https://<your-hostname>/?ct_link=tok\n"), "{text}");
        assert!(text.contains("label:    -\n"), "an empty label shows as a dash: {text}");
        assert!(text.contains("expires:  42 (unix; in 1h)"), "{text}");
        assert!(text.contains("once:     yes"), "{text}");
        assert!(text.contains("link-revoke abc123"), "{text}");
    }

    #[test]
    fn share_link_mint_list_revoke_round_trip() {
        let dir = scratch("link-round-trip");
        let store = LinkStore::new(&dir);
        assert!(store.list().unwrap().is_empty(), "no file yet reads as no links");

        let minted = store.mint_at(NOW, HOUR, false, "  demo for  bob\n").unwrap();
        assert_eq!(minted.token.len(), 43, "32 bytes base64url-nopad");
        assert!(looks_like_link_token(&minted.token));
        assert_eq!(minted.expires_at, NOW + 3_600);
        assert_eq!(minted.label, "demo for  bob", "label is one trimmed line");
        assert!(!minted.single_use);
        assert!(minted.url_with_placeholder_host().ends_with(&format!("/?{LINK_QUERY_PARAM}={}", minted.token)));

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        let rec = &listed[0];
        assert_eq!(rec.id, minted.id);
        assert_eq!(rec.token_hash, hex_encode(&hash_link_token(&minted.token)));
        assert_ne!(rec.token_hash, minted.token, "the token itself is never stored");
        assert!(!std::fs::read_to_string(store.path()).unwrap().contains(&minted.token));
        assert_eq!(rec.status(NOW), "active");
        assert!(rec.is_active(NOW));

        let revoked = store.revoke_at(NOW + 10, &minted.id).unwrap();
        assert_eq!(revoked.revoked_at, Some(NOW + 10));
        assert_eq!(store.list().unwrap()[0].status(NOW + 10), "revoked");
        assert!(!store.list().unwrap()[0].is_active(NOW + 10));
        let err = store.revoke_at(NOW + 11, &minted.id).unwrap_err();
        assert!(err.contains("already revoked"), "{err}");
        let err = store.revoke_at(NOW, "nope").unwrap_err();
        assert!(err.contains("no share link with id nope"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn share_link_file_is_never_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("link-perms");
        let store = LinkStore::new(&dir);
        store.mint_at(NOW, HOUR, false, "x").unwrap();
        let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn share_link_mint_is_capped_at_fifty_active() {
        let dir = scratch("link-cap");
        let store = LinkStore::new(&dir);
        let mut ids = Vec::new();
        for i in 0..MAX_ACTIVE_LINKS {
            ids.push(store.mint_at(NOW, HOUR, false, &format!("l{i}")).unwrap().id);
        }
        let err = store.mint_at(NOW, HOUR, false, "one too many").unwrap_err();
        assert!(err.contains("50 share links are already active"), "{err}");
        assert!(err.contains("link-revoke"), "{err}");
        // A revoked one no longer counts ...
        store.revoke_at(NOW, &ids[0]).unwrap();
        store.mint_at(NOW, HOUR, false, "fits again").unwrap();
        // ... and neither does an expired one.
        let err = store.mint_at(NOW, HOUR, false, "full again").unwrap_err();
        assert!(err.contains("already active"), "{err}");
        store.mint_at(NOW + 3_601, HOUR, false, "everything above has expired").unwrap();
    }

    #[test]
    fn share_link_expired_records_are_pruned_a_week_after_expiry() {
        let dir = scratch("link-prune");
        let store = LinkStore::new(&dir);
        let old = store.mint_at(NOW, HOUR, false, "old").unwrap();
        // Still listed a day after expiry ...
        store.mint_at(NOW + 86_400 + 3_600, HOUR, false, "newer").unwrap();
        assert!(store.list().unwrap().iter().any(|l| l.id == old.id));
        // ... gone once a write happens more than 7 days past its expiry.
        store.mint_at(NOW + 3_600 + LINK_PRUNE_AFTER.as_secs() + 1, HOUR, false, "much later").unwrap();
        assert!(!store.list().unwrap().iter().any(|l| l.id == old.id));
    }

    #[test]
    fn share_link_redeem_via_query_answers_302_with_the_cookie_and_strips_the_parameter() {
        let dir = scratch("link-query");
        let gate = http_gate(&dir);
        let minted = gate.links().unwrap().mint_at(NOW, HOUR, false, "guest").unwrap();

        let (response, id) = match gate.check_share_link_at(NOW + 60, &get_with_query(&minted.token)) {
            LinkGateVerdict::Redirect { response, id } => (response, id),
            other => panic!("expected a redirect, got {other:?}"),
        };
        assert_eq!(id, minted.id);
        let resp = String::from_utf8(response).unwrap();
        assert!(resp.starts_with("HTTP/1.1 302 Found\r\n"), "{resp}");
        assert!(resp.contains("\r\nLocation: /app/page?x=1&y=2\r\n"), "parameter stripped, others kept: {resp}");
        let cookie = format!(
            "\r\nSet-Cookie: {LINK_COOKIE_NAME}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3540\r\n",
            minted.token
        );
        assert!(resp.contains(&cookie), "{resp}");
        assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");
        assert!(resp.ends_with("\r\n\r\n"));
        // The redemption stamped used_at, even for a multi-use link.
        assert_eq!(gate.links().unwrap().list().unwrap()[0].used_at, Some(NOW + 60));
    }

    #[test]
    fn share_link_cookie_is_accepted_until_expiry() {
        let dir = scratch("link-cookie");
        let gate = http_gate(&dir);
        let minted = gate.links().unwrap().mint_at(NOW, HOUR, false, "guest").unwrap();

        let req = get_with_cookie(&minted.token);
        assert_eq!(
            gate.check_share_link_at(NOW + 1, &req),
            LinkGateVerdict::Authenticated { id: minted.id.clone() },
            "a valid cookie authenticates without a redirect"
        );
        assert_eq!(
            gate.check_share_link_at(NOW + 3_599, &req),
            LinkGateVerdict::Authenticated { id: minted.id.clone() },
            "... right up to expiry"
        );
        assert_eq!(
            gate.check_share_link_at(NOW + 3_600, &req),
            LinkGateVerdict::Rejected(LinkRejection::Expired),
            "... and not one second past it"
        );
    }

    #[test]
    fn share_link_expired_revoked_unknown_and_used_are_refused() {
        let dir = scratch("link-refused");
        let gate = http_gate(&dir);
        let store = gate.links().unwrap();

        // Expired.
        let expired = store.mint_at(NOW - 7_200, HOUR, false, "expired").unwrap();
        assert_eq!(
            gate.check_share_link_at(NOW, &get_with_query(&expired.token)),
            LinkGateVerdict::Rejected(LinkRejection::Expired)
        );
        // Revoked.
        let revoked = store.mint_at(NOW, HOUR, false, "revoked").unwrap();
        store.revoke_at(NOW, &revoked.id).unwrap();
        assert_eq!(
            gate.check_share_link_at(NOW + 1, &get_with_query(&revoked.token)),
            LinkGateVerdict::Rejected(LinkRejection::Revoked)
        );
        assert_eq!(
            gate.check_share_link_at(NOW + 1, &get_with_cookie(&revoked.token)),
            LinkGateVerdict::Rejected(LinkRejection::Revoked),
            "revocation kills the cookie session too"
        );
        // Never minted (a well-formed token that hashes to nothing), and garbage.
        let stranger = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        assert_eq!(
            gate.check_share_link_at(NOW, &get_with_query(&stranger)),
            LinkGateVerdict::Rejected(LinkRejection::Unknown)
        );
        assert_eq!(
            gate.check_share_link_at(NOW, &get_with_query("not%20a%20token;x")),
            LinkGateVerdict::Rejected(LinkRejection::Unknown)
        );
        // No link at all: nothing to judge, and it never touched the limiter.
        assert_eq!(gate.check_share_link_at(NOW, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), LinkGateVerdict::NotPresented);
        assert_eq!(gate.check_share_link_at(NOW, b"not http at all"), LinkGateVerdict::NotPresented);
        // Every rejection above counted as a failure; the lockout must engage.
        assert!(matches!(gate.limiter.check(), RateLimitVerdict::Locked { .. }));
        let good = store.mint_at(NOW, HOUR, false, "good").unwrap();
        assert!(matches!(
            gate.check_share_link_at(NOW, &get_with_query(&good.token)),
            LinkGateVerdict::Rejected(LinkRejection::RateLimited { .. })
        ));
    }

    #[test]
    fn share_link_single_use_redeems_once_by_url_but_its_cookie_keeps_working() {
        let dir = scratch("link-once");
        let gate = http_gate(&dir);
        let minted = gate.links().unwrap().mint_at(NOW, HOUR, true, "once").unwrap();

        // First visit: redirect + cookie, used_at stamped.
        assert!(matches!(
            gate.check_share_link_at(NOW + 1, &get_with_query(&minted.token)),
            LinkGateVerdict::Redirect { .. }
        ));
        let rec = &gate.links().unwrap().list().unwrap()[0];
        assert_eq!(rec.used_at, Some(NOW + 1));
        assert_eq!(rec.status(NOW + 1), "used (cookie still valid)");
        // The same URL again (forwarded, bookmarked, sniffed): refused.
        assert_eq!(
            gate.check_share_link_at(NOW + 2, &get_with_query(&minted.token)),
            LinkGateVerdict::Rejected(LinkRejection::AlreadyUsed)
        );
        // The cookie the first visit set: still the session it opened.
        assert_eq!(
            gate.check_share_link_at(NOW + 3, &get_with_cookie(&minted.token)),
            LinkGateVerdict::Authenticated { id: minted.id.clone() }
        );
        assert_eq!(
            gate.check_share_link_at(NOW + 3_600, &get_with_cookie(&minted.token)),
            LinkGateVerdict::Rejected(LinkRejection::Expired)
        );
    }

    #[test]
    fn share_links_are_never_accepted_when_the_gate_has_no_state_dir() {
        // CT_AGENT_LOCAL_AUTH_FILE without CT_AGENT_STATE_DIR: no links store.
        let dir = scratch("link-no-state");
        set_credential(&dir, "agent", "s3cret").unwrap();
        let file = credential_path(&dir).to_string_lossy().to_string();
        let (gate, _) = LocalAuthGate::from_env(None, move |k| match k {
            "CT_AGENT_LOCAL_AUTH" => Some("http".to_string()),
            "CT_AGENT_LOCAL_AUTH_FILE" => Some(file.clone()),
            _ => None,
        })
        .unwrap();
        assert!(gate.links().is_none());
        assert_eq!(gate.check_share_link_at(NOW, &get_with_cookie("anything")), LinkGateVerdict::NotPresented);
        // Off mode has none either.
        let (off, _) = LocalAuthGate::from_env(Some(&dir), |_| None).unwrap();
        assert!(off.links().is_none());
    }

    #[test]
    fn link_token_in_target_strips_exactly_the_link_parameter() {
        assert_eq!(link_token_in_target("/"), None);
        assert_eq!(link_token_in_target("/a?b=1"), None);
        assert_eq!(link_token_in_target("/?ct_link=T"), Some(("T".to_string(), "/".to_string())));
        assert_eq!(link_token_in_target("/p?ct_link=T&x=1"), Some(("T".to_string(), "/p?x=1".to_string())));
        assert_eq!(link_token_in_target("/p?x=1&ct_link=T"), Some(("T".to_string(), "/p?x=1".to_string())));
        assert_eq!(
            link_token_in_target("/p?x=1&ct_link=T&y=2&ct_link=U"),
            Some(("T".to_string(), "/p?x=1&y=2".to_string())),
            "the first wins, every copy is stripped"
        );
        assert_eq!(link_token_in_target("/p?ct_link="), Some((String::new(), "/p".to_string())));
        assert_eq!(link_token_in_target("/p?ct_linkx=T"), None, "prefix is not a match");
    }

    #[test]
    fn parse_request_head_and_cookie_extraction() {
        let req =
            b"GET /x?y=1 HTTP/1.1\r\nHost: h\r\nbogus line\r\nCOOKIE:  a=1;ct_link_session = tok ; b=2\r\n\r\nbody";
        let head = parse_request_head(req).unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/x?y=1");
        assert_eq!(head.headers, vec![("Host", "h"), ("COOKIE", "a=1;ct_link_session = tok ; b=2")]);
        assert_eq!(link_token_in_cookies(&head), Some("tok".to_string()));

        let no_cookie = parse_request_head(b"GET / HTTP/1.1\r\nCookie: other=1\r\n\r\n").unwrap();
        assert_eq!(link_token_in_cookies(&no_cookie), None);
        assert!(parse_request_head(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none(), "no terminator");
        assert!(parse_request_head(b"\r\n\r\n").is_none(), "no request line");
        let mut unbounded = b"GET / HTTP/1.1\r\n".to_vec();
        unbounded.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES + 100));
        unbounded.extend_from_slice(b"\r\n\r\n");
        assert!(parse_request_head(&unbounded).is_none(), "terminator past the bound is not searched for");
    }

    #[test]
    fn http_302_link_redirect_never_lets_a_location_or_token_inject_headers() {
        let resp = String::from_utf8(http_302_link_redirect("/ok?a=1", "tok_-1", 5)).unwrap();
        assert!(resp.contains("\r\nLocation: /ok?a=1\r\n"), "{resp}");
        let cookie = "ct_link_session=tok_-1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=5\r\n";
        assert!(resp.contains(cookie), "{resp}");
        let resp = String::from_utf8(http_302_link_redirect("/x\r\nX-Injected: 1", "t", 5)).unwrap();
        assert!(resp.contains("\r\nLocation: /\r\n"), "{resp}");
        assert!(!resp.contains("X-Injected"), "{resp}");
        let resp = String::from_utf8(http_302_link_redirect("", "t;Path=/evil\r\n", 5)).unwrap();
        assert!(resp.contains("\r\nLocation: /\r\n"), "{resp}");
        assert!(resp.contains("ct_link_session=; Path=/;"), "a malformed token is blanked: {resp}");
        assert!(!resp.contains("evil"), "{resp}");
    }
}
