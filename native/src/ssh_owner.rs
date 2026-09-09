//! SSH owner authentication (scimbe/ct-agent#214): ON BY DEFAULT for every SSH tunnel.
//!
//! `ct-agent ssh` (#204) pipes ssh's bytes through a TLS session that the Agent terminates
//! (`CT_AGENT_ORIGIN_TLS=terminate`) and forwards to the local sshd. Until #214, sshd's own
//! authentication was the only gate: anyone who could reach the hostname could talk to sshd.
//! The local-auth gate (#185) is Mesh-Plane HTTP/text only and never touches this path.
//!
//! Now the Agent owns a per-agent **owner key** (32 random bytes, generated at the first start in
//! terminate mode, stored 0600 in the state dir, printed once) and runs a **preamble** on every
//! terminated stream, right after the TLS handshake and before the first SSH byte:
//!
//! ```text
//! agent  -> client : "CTSSH1" 0x01 nonce[32]                 (39 bytes)
//! client -> agent  : HMAC-SHA256(key, "ct-agent-ssh-owner-v1" || nonce)   (32 bytes)
//! agent  -> client : 0x01 (ok, sshd follows)  |  0x00 then close (refused)
//! ```
//!
//! The Agent speaks first, which is what makes this transparent for an OLD `ct-agent ssh`
//! talking to a NEW agent (it gets a clear refusal instead of a hang) and for a NEW client
//! talking to an OLD agent (the first bytes are sshd's `SSH-2.0-` banner, not the magic, and the
//! client passes them straight through). Fail closed: an agent in terminate mode without a key
//! generates one; without a state dir it refuses to start; only `CT_AGENT_SSH_OWNER_AUTH=off`
//! turns the preamble off, loudly. Everything that decides is a pure function; the two handshake
//! halves are generic over the stream so the tests run them over an in-memory duplex.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// File name of the owner key inside the agent state dir (hex, 0600).
pub const OWNER_KEY_FILE: &str = "ssh-owner.key";
/// Agent side: `off` / `0` / `false` disables the preamble (loud opt-out). Anything else = on.
pub const OWNER_AUTH_ENV: &str = "CT_AGENT_SSH_OWNER_AUTH";
/// Client side: the owner key as hex (alternative to `--owner-key-file`).
pub const OWNER_KEY_ENV: &str = "CT_AGENT_SSH_OWNER_KEY";

const MAGIC: &[u8; 6] = b"CTSSH1";
const VERSION: u8 = 0x01;
const DOMAIN: &[u8] = b"ct-agent-ssh-owner-v1";
/// Length of the nonce and of the HMAC-SHA256 tag.
pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
/// The challenge frame: magic + version + nonce.
pub const CHALLENGE_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;
/// Bound on each preamble read: a peer that sends nothing must not park a terminated stream.
pub const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The 32-byte owner key. Debug/Display never print it.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerKey([u8; 32]);

impl std::fmt::Debug for OwnerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerKey(<redacted>)")
    }
}

impl OwnerKey {
    /// A fresh random key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self(k)
    }

    /// Parse the hex form (64 hex digits, whitespace around it ignored).
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let t = s.trim();
        if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("owner key must be 64 hex digits".to_string());
        }
        let mut k = [0u8; 32];
        for (i, chunk) in t.as_bytes().chunks(2).enumerate() {
            k[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("zz"), 16).map_err(|e| e.to_string())?;
        }
        Ok(Self(k))
    }

    /// The hex form (what `ct-agent ssh-owner show` prints and `--owner-key` takes).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The tag for `nonce`: HMAC-SHA256(key, DOMAIN || nonce). Domain-separated so the key can
    /// never be turned into a MAC oracle for some other protocol's bytes.
    pub fn tag(&self, nonce: &[u8; NONCE_LEN]) -> [u8; TAG_LEN] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.0);
        let mut msg = Vec::with_capacity(DOMAIN.len() + NONCE_LEN);
        msg.extend_from_slice(DOMAIN);
        msg.extend_from_slice(nonce);
        let t = ring::hmac::sign(&key, &msg);
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(t.as_ref());
        out
    }

    /// Constant-time check of a received tag.
    pub fn verify(&self, nonce: &[u8; NONCE_LEN], tag: &[u8]) -> bool {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.0);
        let mut msg = Vec::with_capacity(DOMAIN.len() + NONCE_LEN);
        msg.extend_from_slice(DOMAIN);
        msg.extend_from_slice(nonce);
        ring::hmac::verify(&key, &msg, tag).is_ok()
    }

    /// The key file path inside `state_dir`.
    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(OWNER_KEY_FILE)
    }

    /// Read the key at `path`; `Ok(None)` when the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_hex(&s).map(Some).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write the key to `path` (dir 0700, file 0600, created atomically via a temp file).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        let dir = path.parent().ok_or_else(|| format!("{}: no parent directory", path.display()))?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension("key.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
            f.write_all(self.to_hex().as_bytes()).and_then(|_| f.write_all(b"\n")).map_err(|e| format!("{}: {e}", tmp.display()))?;
            f.sync_all().map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// The key in `state_dir`, generated and saved if there is none. Returns `(key, generated)`.
    pub fn load_or_generate(state_dir: &Path) -> Result<(Self, bool), String> {
        let path = Self::path_in(state_dir);
        if let Some(k) = Self::load(&path)? {
            return Ok((k, false));
        }
        let k = Self::generate();
        k.save(&path)?;
        Ok((k, true))
    }
}

/// What the agent enforces on terminated (SSH) streams.
#[derive(Debug, Clone)]
pub enum OwnerAuth {
    /// The default: every terminated stream must pass the preamble with this key.
    Required(Arc<OwnerKey>),
    /// `CT_AGENT_SSH_OWNER_AUTH=off`: no preamble (sshd's own auth is the only gate).
    Off,
}

/// Whether `CT_AGENT_SSH_OWNER_AUTH` opts out. Only an explicit off/0/false does.
pub fn owner_auth_disabled(get: &impl Fn(&str) -> Option<String>) -> bool {
    get(OWNER_AUTH_ENV)
        .map(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("no")
        })
        .unwrap_or(false)
}

/// The agent-side policy from the environment and the state dir: `Off` only on the explicit
/// opt-out; otherwise the key in `state_dir` (generated on first use). `Err` when there is no
/// state dir to keep the key in -- fail closed, the operator sets `CT_AGENT_STATE_DIR` (or
/// `HOME`) or opts out explicitly. Returns `(policy, generated)`.
pub fn owner_auth_from_env(
    get: &impl Fn(&str) -> Option<String>,
    state_dir: Option<&Path>,
) -> Result<(OwnerAuth, bool), String> {
    if owner_auth_disabled(get) {
        return Ok((OwnerAuth::Off, false));
    }
    let dir = state_dir.ok_or_else(|| {
        format!(
            "SSH owner authentication is on by default (#214) and needs a state dir for the owner key: \
             set CT_AGENT_STATE_DIR (or HOME), or opt out explicitly with {OWNER_AUTH_ENV}=off"
        )
    })?;
    let (key, generated) = OwnerKey::load_or_generate(dir)?;
    Ok((OwnerAuth::Required(Arc::new(key)), generated))
}

/// Build the challenge frame for `nonce`.
pub fn challenge_frame(nonce: &[u8; NONCE_LEN]) -> [u8; CHALLENGE_LEN] {
    let mut f = [0u8; CHALLENGE_LEN];
    f[..MAGIC.len()].copy_from_slice(MAGIC);
    f[MAGIC.len()] = VERSION;
    f[MAGIC.len() + 1..].copy_from_slice(nonce);
    f
}

/// Whether `head` (the first bytes a client read) starts the preamble.
pub fn starts_with_magic(head: &[u8]) -> bool {
    head.len() >= MAGIC.len() && &head[..MAGIC.len()] == MAGIC
}

/// Parse a full challenge frame.
pub fn parse_challenge(frame: &[u8]) -> Result<[u8; NONCE_LEN], String> {
    if frame.len() != CHALLENGE_LEN || !starts_with_magic(frame) {
        return Err("malformed owner-auth challenge".to_string());
    }
    if frame[MAGIC.len()] != VERSION {
        return Err(format!("unsupported owner-auth version {}", frame[MAGIC.len()]));
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&frame[MAGIC.len() + 1..]);
    Ok(n)
}

async fn read_exact_timeout<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8], what: &str) -> Result<(), String> {
    match tokio::time::timeout(PREAMBLE_TIMEOUT, s.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: no data within {}s", PREAMBLE_TIMEOUT.as_secs())),
    }
}

/// Agent side: challenge, verify, verdict. `Ok(())` means the peer proved the owner key and the
/// stream is positioned at its first SSH byte; `Err` means the stream must be dropped (the
/// verdict byte 0x00 was written when the peer answered at all).
pub async fn server_handshake<S>(stream: &mut S, key: &OwnerKey) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    stream.write_all(&challenge_frame(&nonce)).await.map_err(|e| format!("owner-auth challenge: {e}"))?;
    stream.flush().await.map_err(|e| format!("owner-auth challenge: {e}"))?;
    let mut tag = [0u8; TAG_LEN];
    // A peer that starts with an SSH banner (an old `ct-agent ssh`, or raw ssh pointed at the
    // hostname) fails the tag check below; its bytes are never forwarded to sshd.
    read_exact_timeout(stream, &mut tag, "owner-auth response").await?;
    if key.verify(&nonce, &tag) {
        stream.write_all(&[0x01]).await.map_err(|e| format!("owner-auth verdict: {e}"))?;
        stream.flush().await.map_err(|e| format!("owner-auth verdict: {e}"))?;
        Ok(())
    } else {
        let _ = stream.write_all(&[0x00]).await;
        let _ = stream.flush().await;
        Err("owner authentication failed (wrong or missing owner key)".to_string())
    }
}

/// What the client found on the wire after its TLS handshake.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientPreamble {
    /// The agent required the preamble and accepted our tag; SSH bytes follow.
    Authenticated,
    /// The agent does not run the preamble (pre-#214): these bytes are the start of sshd's own
    /// banner and must reach ssh first.
    Passthrough(Vec<u8>),
}

/// Client side: read the agent's first bytes; answer the challenge with `key` when there is one.
pub async fn client_handshake<S>(stream: &mut S, key: Option<&OwnerKey>) -> Result<ClientPreamble, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; MAGIC.len()];
    read_exact_timeout(stream, &mut head, "waiting for the agent's first bytes").await?;
    if !starts_with_magic(&head) {
        return Ok(ClientPreamble::Passthrough(head.to_vec()));
    }
    let mut rest = [0u8; CHALLENGE_LEN - MAGIC.len()];
    read_exact_timeout(stream, &mut rest, "owner-auth challenge").await?;
    let mut frame = [0u8; CHALLENGE_LEN];
    frame[..MAGIC.len()].copy_from_slice(&head);
    frame[MAGIC.len()..].copy_from_slice(&rest);
    let nonce = parse_challenge(&frame)?;
    let key = key.ok_or_else(|| {
        format!(
            "the agent requires owner authentication (#214): run `ct-agent ssh-owner show` on the agent \
             host and pass the key with --owner-key-file <file> (or {OWNER_KEY_ENV}); see `ct-agent ssh-config --owner-key`"
        )
    })?;
    stream.write_all(&key.tag(&nonce)).await.map_err(|e| format!("owner-auth response: {e}"))?;
    stream.flush().await.map_err(|e| format!("owner-auth response: {e}"))?;
    let mut verdict = [0u8; 1];
    read_exact_timeout(stream, &mut verdict, "owner-auth verdict").await?;
    if verdict[0] == 0x01 {
        Ok(ClientPreamble::Authenticated)
    } else {
        Err("owner authentication refused by the agent (wrong owner key for this hostname?)".to_string())
    }
}

/// Read the key file for the client (`--owner-key-file`).
pub fn read_key_file(path: &Path) -> Result<OwnerKey, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("--owner-key-file {}: {e}", path.display()))?;
    OwnerKey::from_hex(&s).map_err(|e| format!("--owner-key-file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejects_bad_input() {
        let k = OwnerKey::generate();
        let hex = k.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(OwnerKey::from_hex(&format!(" {hex}\n")).unwrap(), k);
        assert!(OwnerKey::from_hex("abc").is_err());
        assert!(OwnerKey::from_hex(&"zz".repeat(32)).is_err());
        assert_eq!(format!("{k:?}"), "OwnerKey(<redacted>)");
    }

    #[test]
    fn tag_is_deterministic_keyed_and_verifies_in_constant_time_api() {
        let k1 = OwnerKey::generate();
        let k2 = OwnerKey::generate();
        let nonce = [7u8; NONCE_LEN];
        assert_eq!(k1.tag(&nonce), k1.tag(&nonce));
        assert_ne!(k1.tag(&nonce), k2.tag(&nonce), "the tag is keyed");
        assert_ne!(k1.tag(&nonce), k1.tag(&[8u8; NONCE_LEN]), "the tag depends on the nonce");
        assert!(k1.verify(&nonce, &k1.tag(&nonce)));
        assert!(!k1.verify(&nonce, &k2.tag(&nonce)));
        assert!(!k1.verify(&nonce, b"short"));
    }

    #[test]
    fn challenge_frame_parses_and_rejects_the_rest() {
        let nonce = [3u8; NONCE_LEN];
        let f = challenge_frame(&nonce);
        assert!(starts_with_magic(&f));
        assert_eq!(parse_challenge(&f).unwrap(), nonce);
        assert!(!starts_with_magic(b"SSH-2.0-OpenSSH_9.6"));
        let mut bad = f;
        bad[MAGIC.len()] = 0x02;
        assert!(parse_challenge(&bad).unwrap_err().contains("version"));
        assert!(parse_challenge(&f[..10]).is_err());
    }

    #[test]
    fn load_or_generate_creates_a_0600_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let (k1, gen1) = OwnerKey::load_or_generate(dir.path()).unwrap();
        let (k2, gen2) = OwnerKey::load_or_generate(dir.path()).unwrap();
        assert!(gen1 && !gen2);
        assert_eq!(k1, k2, "the second start reads the same key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(OwnerKey::path_in(dir.path())).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(read_key_file(&OwnerKey::path_in(dir.path())).unwrap(), k1);
    }

    #[test]
    fn owner_auth_env_is_on_by_default_and_off_only_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let none = |_: &str| None::<String>;
        let (p, generated) = owner_auth_from_env(&none, Some(dir.path())).unwrap();
        assert!(matches!(p, OwnerAuth::Required(_)) && generated);
        let (p, generated) = owner_auth_from_env(&none, Some(dir.path())).unwrap();
        assert!(matches!(p, OwnerAuth::Required(_)) && !generated, "same key, not regenerated");
        for v in ["off", "0", "false", " OFF "] {
            let get = |k: &str| (k == OWNER_AUTH_ENV).then(|| v.to_string());
            assert!(matches!(owner_auth_from_env(&get, Some(dir.path())).unwrap().0, OwnerAuth::Off), "{v}");
        }
        let on = |k: &str| (k == OWNER_AUTH_ENV).then(|| "on".to_string());
        assert!(matches!(owner_auth_from_env(&on, Some(dir.path())).unwrap().0, OwnerAuth::Required(_)));
        let e = owner_auth_from_env(&none, None).unwrap_err();
        assert!(e.contains("CT_AGENT_STATE_DIR") && e.contains("=off"), "fail closed names the way out: {e}");
    }

    #[tokio::test]
    async fn handshake_right_key_ok_wrong_key_refused_missing_key_explained() {
        let key = Arc::new(OwnerKey::generate());
        // right key
        let (mut a, mut c) = tokio::io::duplex(1024);
        let k = Arc::clone(&key);
        let server = tokio::spawn(async move { server_handshake(&mut a, &k).await });
        assert_eq!(client_handshake(&mut c, Some(&key)).await.unwrap(), ClientPreamble::Authenticated);
        server.await.unwrap().unwrap();
        // wrong key: the client sees the refusal, the server returns Err
        let (mut a, mut c) = tokio::io::duplex(1024);
        let k = Arc::clone(&key);
        let server = tokio::spawn(async move { server_handshake(&mut a, &k).await });
        let wrong = OwnerKey::generate();
        let e = client_handshake(&mut c, Some(&wrong)).await.unwrap_err();
        assert!(e.contains("refused"), "{e}");
        assert!(server.await.unwrap().is_err());
        // no key on the client: a clear instruction, and nothing was sent as a tag
        let (mut a, mut c) = tokio::io::duplex(1024);
        let k = Arc::clone(&key);
        let server = tokio::spawn(async move { server_handshake(&mut a, &k).await });
        let e = client_handshake(&mut c, None).await.unwrap_err();
        assert!(e.contains("ssh-owner show") && e.contains("--owner-key-file"), "{e}");
        drop(c);
        assert!(server.await.unwrap().is_err(), "the server never let the stream through");
    }

    #[tokio::test]
    async fn old_agent_without_preamble_passes_the_ssh_banner_through() {
        let (mut a, mut c) = tokio::io::duplex(1024);
        a.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        let key = OwnerKey::generate();
        match client_handshake(&mut c, Some(&key)).await.unwrap() {
            ClientPreamble::Passthrough(head) => assert_eq!(head, b"SSH-2."),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_old_client_that_sends_its_ssh_banner_first_is_refused_not_forwarded() {
        let key = OwnerKey::generate();
        let (mut a, mut c) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move { server_handshake(&mut a, &key).await });
        // A pre-#214 `ct-agent ssh` pumps ssh's banner straight away (32+ bytes, so the read completes).
        c.write_all(b"SSH-2.0-OpenSSH_9.6 some client software\r\n").await.unwrap();
        let e = server.await.unwrap().unwrap_err();
        assert!(e.contains("owner authentication failed"), "{e}");
        // and the verdict byte 0x00 reached the peer
        let mut buf = vec![0u8; CHALLENGE_LEN + 1];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[CHALLENGE_LEN], 0x00);
    }
}
