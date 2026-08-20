//! Capability minting (ADR-0014).
//!
//! The Agent mints a self-contained Capability (Routing Token, Origin Identity,
//! and Edge address) that the customer distributes out of band. P2.2 mints the
//! Capability with a fresh random Routing Token; its token is what the control
//! plane registers in the Tunnel Registry (ADR-0006).

use crate::origin::OriginKey;
use ct_common::{Capability, OriginIdentity, RoutingToken};
use rand::RngCore;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Mint a Capability for an Origin reachable via `edge_addr`, generating a fresh
/// random Routing Token.
pub fn mint_capability(origin: OriginIdentity, edge_addr: String) -> Capability {
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    mint_capability_with_token(RoutingToken(token), origin, edge_addr)
}

/// Mint a Capability with an **explicit** Routing Token — used by key rotation
/// (#12 K4) to re-mint with the *same* token while changing the Origin Identity,
/// so clients holding the old capability keep rendezvousing during the window.
pub fn mint_capability_with_token(
    token: RoutingToken,
    origin: OriginIdentity,
    edge_addr: String,
) -> Capability {
    Capability {
        token,
        origin,
        edge_addr,
    }
}

/// The Agent's serving identity: the Origin static private key (to terminate the
/// Client↔Origin Noise handshake) and the Capability (Routing Token + Origin
/// Identity) that Clients pin.
pub struct ServingIdentity {
    pub cap: Capability,
    /// Origin private keys this Agent terminates handshakes for: the **primary**
    /// (the identity the published `cap` pins) first, then any additional
    /// rotation-window keys loaded from a key directory (#12 K3). During a
    /// rotation the previous key is kept here so old capabilities keep working
    /// until the window closes.
    pub origin_keys: Vec<[u8; 32]>,
}

/// Resolve the Agent's serving identity, writing the Capability to `cap_path`.
///
/// With `key_path = Some(p)`, the Origin key + Capability are **persisted and
/// shared**: the first Agent generates them and writes the key to `p` (owner-only)
/// and the capability to `cap_path`; later Agents pointed at the same paths
/// **load** them and therefore serve the **same Routing Token** — i.e. multiple
/// Agents back one tunnel (redundancy/failover, #8 R4). Start the first Agent
/// before the peers so the shared files exist.
///
/// With `key_path = None`, a fresh single-Agent identity is minted (the default).
pub fn resolve_serving_identity(
    key_path: Option<&str>,
    cap_path: &str,
    edge: &str,
    extra_keys_dir: Option<&str>,
) -> Result<ServingIdentity, BoxError> {
    resolve_serving_identity_with_token(key_path, cap_path, edge, extra_keys_dir, None)
}

/// Like [`resolve_serving_identity`], but when `forced_token` is `Some` a newly
/// minted capability uses that routing token instead of a random one (#27 RB2b).
/// This lets an agent onboarded via the portal register at the edge under the
/// tunnel's known routing token, so a revocation can find and drop it. A reused
/// persisted capability keeps its own token (redundancy/rotation unaffected).
pub fn resolve_serving_identity_with_token(
    key_path: Option<&str>,
    cap_path: &str,
    edge: &str,
    extra_keys_dir: Option<&str>,
    forced_token: Option<RoutingToken>,
) -> Result<ServingIdentity, BoxError> {
    let (cap, primary) = resolve_primary_identity(key_path, cap_path, edge, forced_token)?;
    let mut origin_keys = vec![primary];
    if let Some(dir) = extra_keys_dir {
        origin_keys.extend(load_extra_origin_keys(dir)?);
    }
    Ok(ServingIdentity { cap, origin_keys })
}

/// Parse a 64-hex routing token (e.g. from `CT_AGENT_TOKEN`), if valid.
///
/// #49: `s.len()` is BYTE length -- a string containing a multi-byte UTF-8
/// character can have `len() == 64` while a raw `&s[i*2..i*2+2]` slice lands
/// mid-character and panics. Chunk the bytes instead of slicing the `str`, so
/// a malformed `CT_AGENT_TOKEN` (set by the install one-liner / portal
/// onboarding, not necessarily hand-typed) is rejected -- falling back to a
/// freshly minted token, the documented "unset" behavior -- instead of
/// crashing the agent process at startup.
pub fn parse_routing_token_hex(s: &str) -> Option<RoutingToken> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        t[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(RoutingToken(t))
}

/// Resolve the **primary** identity — the capability and its origin private key.
/// Persists/shares them when `key_path` is set (redundancy, #8 R4a); otherwise
/// mints a fresh unique identity.
fn resolve_primary_identity(
    key_path: Option<&str>,
    cap_path: &str,
    edge: &str,
    forced_token: Option<RoutingToken>,
) -> Result<(Capability, [u8; 32]), BoxError> {
    // Mint a capability for `origin`, honoring a forced routing token if given.
    let mint = |origin: OriginIdentity| match &forced_token {
        Some(t) => mint_capability_with_token(t.clone(), origin, edge.to_string()),
        None => mint_capability(origin, edge.to_string()),
    };
    if let Some(kp) = key_path {
        // Shared identity: reuse the persisted key + capability if both exist.
        if let (Ok(key), Ok(capb)) = (std::fs::read(kp), std::fs::read(cap_path)) {
            if key.len() == 32 {
                let mut origin_private = [0u8; 32];
                origin_private.copy_from_slice(&key);
                return Ok((Capability::decode(&capb)?, origin_private));
            }
        }
        // First agent: generate the identity and persist both for peers to share.
        // Staged the same way as `rotate_origin_key` (#51), for the same reason: a
        // crash between the two writes would leave `kp` holding a key with no
        // matching `cap_path` -- self-healing IS possible here (the load branch
        // above falls through to regenerate when either file is missing, since
        // nothing external has trusted the partial state yet on a genuine first
        // boot), but a peer sharing these paths (#8 R4) that starts up in that
        // exact window would ALSO see "cap_path missing" and race to generate its
        // OWN fresh identity, silently discarding the first agent's key instead of
        // sharing it. Staging removes the window instead of relying on retry luck.
        let origin_key = OriginKey::generate();
        let cap = mint(origin_key.origin_identity());
        let key_tmp = format!("{kp}.new");
        let cap_tmp = format!("{cap_path}.new");
        write_owner_only(&key_tmp, &origin_key.private_bytes())?;
        if let Err(e) = write_owner_only(&cap_tmp, &cap.encode()) {
            let _ = std::fs::remove_file(&key_tmp);
            return Err(e);
        }
        std::fs::rename(&key_tmp, kp)?;
        std::fs::rename(&cap_tmp, cap_path)?;
        return Ok((cap, origin_key.private_bytes()));
    }
    // Default: a fresh, unique single-agent identity.
    let origin_key = OriginKey::generate();
    let cap = mint(origin_key.origin_identity());
    write_owner_only(cap_path, &cap.encode())?;
    Ok((cap, origin_key.private_bytes()))
}

/// Load additional origin private keys (32-byte files) from `dir` — the previous
/// identities still accepted during a rotation window (#12 K3). A missing
/// directory yields no extra keys; files are read in sorted order for
/// determinism, and non-32-byte files are skipped.
fn load_extra_origin_keys(dir: &str) -> Result<Vec<[u8; 32]>, BoxError> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(Vec::new()),
    };
    let mut paths: Vec<_> = read_dir.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    let mut keys = Vec::new();
    for path in paths {
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                keys.push(k);
            }
        }
    }
    Ok(keys)
}

/// Rotate the Agent's Origin key while **keeping the Routing Token** (#12 K4).
/// Origin-key rotation only helps clients holding the old capability if they can
/// still rendezvous, so the token stays the same and only the Origin Identity
/// changes: generate a fresh Origin key, re-mint the capability with the same
/// token + the new identity, persist the new key as the primary (`key_path`) and
/// the new capability (`cap_path`), and move the previous key into
/// `extra_keys_dir` so the Agent keeps serving the old identity during the window
/// (remove it after the window to finish the rotation). Returns the new
/// capability. Restart the Agent (with `CT_AGENT_ORIGIN_KEY_DIR` set) to serve
/// both identities.
pub fn rotate_origin_key(
    key_path: &str,
    cap_path: &str,
    extra_keys_dir: &str,
) -> Result<Capability, BoxError> {
    let old_cap = Capability::decode(&std::fs::read(cap_path)?)?;
    let old_key = std::fs::read(key_path)?;
    if old_key.len() != 32 {
        return Err(format!("current origin key at {key_path} is not 32 bytes").into());
    }
    let new_key = OriginKey::generate();
    let new_cap = mint_capability_with_token(
        old_cap.token.clone(),
        new_key.origin_identity(),
        old_cap.edge_addr.clone(),
    );
    // Retire the previous key into the rotation directory (still served until
    // removed); name it by the old Origin Identity so repeated rotations don't
    // collide.
    std::fs::create_dir_all(extra_keys_dir)?;
    let retired = std::path::Path::new(extra_keys_dir)
        .join(format!("retired-{}.key", hex8(&old_cap.origin.0)));
    write_owner_only(&retired.to_string_lossy(), &old_key)?;
    // Promote the new key + capability as a near-atomic unit, not two independent
    // writes: stage both to `.new` temp paths first, then rename both into place.
    // `resolve_primary_identity`'s shared-identity load reads `key_path`/`cap_path`
    // independently with no cross-check that they name the SAME origin identity --
    // if the old code's two direct writes landed key_path=NEW but cap_path=OLD (a
    // crash or a write error, e.g. disk full, between them), the agent would next
    // boot with a private key that doesn't match its own persisted capability, and
    // silently fail every Noise handshake with no clear signal why. Staging first
    // means the FAR more likely failure (an error mid-write) leaves key_path/
    // cap_path completely untouched -- still a consistent OLD pair -- rather than a
    // mismatched mix; only a crash landing exactly between the two renames (fast,
    // near-instantaneous syscalls) remains a residual window, far smaller than
    // spanning two full-content writes.
    let key_tmp = format!("{key_path}.new");
    let cap_tmp = format!("{cap_path}.new");
    write_owner_only(&key_tmp, &new_key.private_bytes())?;
    if let Err(e) = write_owner_only(&cap_tmp, &new_cap.encode()) {
        // key_tmp already landed -- clean it up so a failed rotation doesn't leave
        // a stray `.new` file (containing key material) sitting next to key_path
        // forever. Best-effort: the real key_path/cap_path pair is what matters
        // for correctness, and is already untouched at this point either way.
        let _ = std::fs::remove_file(&key_tmp);
        return Err(e);
    }
    std::fs::rename(&key_tmp, key_path)?;
    std::fs::rename(&cap_tmp, cap_path)?;
    Ok(new_cap)
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Write `bytes` to `path`, restricting to owner read/write (0600) on Unix.
///
/// Applies to every **bearer** artifact this module persists, not just key material —
/// #31. The capability is the sufficient secret, not the lesser one: CADS-Tunnel#540
/// established that agent registration takes `role='A'(1) | token(32)` and nothing else,
/// that every edge TLS context is `with_no_client_auth()`, and that a capability carries
/// `{token, origin, edge_addr}`. So whoever reads a capability can register as the
/// tunnel's agent, and since `EdgeState::route` hands back `v.last()` they receive ALL of
/// its traffic. The origin private key — already protected here — is not needed for that
/// at all, which is why writing the key 0600 and the capability 0644 protected the wrong
/// file of the two.
///
/// This adds no constraint that sharing an identity did not already impose: `key_path` in
/// the shared-identity branch has always been written 0600, so peer agents that share an
/// identity already had to run as the same user.
fn write_owner_only(path: &str, bytes: &[u8]) -> Result<(), BoxError> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("ct-{}-{}", std::process::id(), name))
            .to_string_lossy()
            .into_owned()
    }

    /// #31: the capability file must be owner-only, on every path that writes one.
    ///
    /// It is not a lesser secret than the origin key beside it — it is the *sufficient*
    /// one. CADS-Tunnel#540: agent registration takes `role='A'(1) | token(32)` and
    /// nothing more, every edge TLS context is `with_no_client_auth()`, and a capability
    /// carries `{token, origin, edge_addr}`. Whoever can read this file can register as an
    /// agent for the tunnel, and `EdgeState::route` returns `v.last()` — so they take ALL
    /// of its traffic, not a share. The private key is not needed for any of that.
    #[cfg(unix)]
    #[test]
    fn a_written_capability_is_not_world_readable_31() {
        use std::os::unix::fs::PermissionsExt;

        let check = |path: &str, what: &str| {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "{what} is mode {mode:o}; anyone who can read it can register as this \
                 tunnel's agent and take all of its traffic (CADS-Tunnel#540)"
            );
        };

        // Path 1: fresh single-agent identity (no shared key path).
        let cap1 = tmp("perm-fresh-cap.bin");
        let _ = std::fs::remove_file(&cap1);
        let _ = resolve_serving_identity_with_token(None, &cap1, "edge:443", None, None).unwrap();
        check(&cap1, "a freshly minted capability");

        // Path 2: shared identity — key and capability persisted side by side. This is the
        // one where the asymmetry was visible in a single directory listing.
        let cap2 = tmp("perm-shared-cap.bin");
        let key2 = tmp("perm-shared.key");
        let _ = std::fs::remove_file(&cap2);
        let _ = std::fs::remove_file(&key2);
        let _ =
            resolve_serving_identity_with_token(Some(&key2), &cap2, "edge:443", None, None).unwrap();
        check(&key2, "the origin key");
        check(&cap2, "the capability written alongside that key");

        // Path 3: rotation promotes a new capability over the old one.
        let dir = tmp("perm-retired-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = rotate_origin_key(&key2, &cap2, &dir).unwrap();
        check(&cap2, "the capability promoted by a key rotation");

        for p in [&cap1, &cap2, &key2] {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forced_routing_token_is_honored_on_a_fresh_identity() {
        // #27 RB2b: a portal-supplied routing token is the token the freshly
        // minted capability registers under.
        let forced = RoutingToken([0x5a; 32]);
        let cap = tmp("forced-cap.bin");
        let _ = std::fs::remove_file(&cap);
        let id = resolve_serving_identity_with_token(
            None,
            &cap,
            "edge:443",
            None,
            Some(forced.clone()),
        )
        .unwrap();
        assert_eq!(id.cap.token, forced, "capability adopts the forced routing token");
        // Without a forced token, the token is random (not the forced value).
        let other = resolve_serving_identity_with_token(None, &tmp("rand-cap.bin"), "edge:443", None, None).unwrap();
        assert_ne!(other.cap.token, forced);
    }

    #[test]
    fn parse_routing_token_hex_validates_length_and_hex() {
        assert_eq!(parse_routing_token_hex(&"5a".repeat(32)), Some(RoutingToken([0x5a; 32])));
        assert!(parse_routing_token_hex("deadbeef").is_none(), "too short");
        assert!(parse_routing_token_hex(&"zz".repeat(32)).is_none(), "non-hex");
    }

    #[test]
    fn parse_routing_token_hex_rejects_rather_than_panics_on_a_multi_byte_char_49() {
        // #49: a multi-byte UTF-8 char (U+FFFD, 3 bytes) plus enough ASCII to reach
        // exactly 64 BYTES -- the old code's `s.len() != 64` guard passes (byte length),
        // then a raw `&s[i*2..i*2+2]` slice lands mid-character and panics.
        let s: String = "\u{FFFD}".to_string() + &"a".repeat(61);
        assert_eq!(s.len(), 64, "byte-length guard alone would let this through");
        assert_eq!(parse_routing_token_hex(&s), None);
    }

    #[test]
    fn shared_identity_lets_multiple_agents_serve_one_token() {
        // #8 R4: with a shared origin-key path, the first agent persists the
        // identity and later agents load it — so they serve the SAME token
        // (redundant registrations for one tunnel). Without it, each agent is a
        // unique single-agent identity.
        let key = tmp("origin.key");
        let cap = tmp("cap.bin");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);

        // "Agent 1" generates + persists; "agent 2" loads the same files.
        let a = resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        let b = resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        assert_eq!(a.cap.token, b.cap.token, "shared routing token → redundancy");
        assert_eq!(a.origin_keys, b.origin_keys, "shared origin key");
        assert_eq!(a.origin_keys.len(), 1, "no rotation dir → just the primary key");
        assert_eq!(a.cap.origin, b.cap.origin, "shared origin identity");

        // Default (no shared key path) mints unique identities.
        let c = resolve_serving_identity(None, &tmp("c.bin"), "edge:443", None).unwrap();
        let d = resolve_serving_identity(None, &tmp("d.bin"), "edge:443", None).unwrap();
        assert_ne!(c.cap.token, d.cap.token, "single-agent identities are unique");

        for f in [&key, &cap, &tmp("c.bin"), &tmp("d.bin")] {
            let _ = std::fs::remove_file(f);
        }
    }

    #[test]
    fn first_boot_leaves_no_partial_state_when_the_capability_write_fails() {
        // The "First agent" branch shares the same crash window `rotate_origin_key`
        // (#51) had: two independent writes for a shared identity's key + capability.
        // Force the failure on the capability's staging write (a directory pre-
        // created at exactly `cap_path.new`, EISDIR -- unconditional, not
        // permission-based, so it isn't bypassed running as root).
        let key = tmp("firstboot-origin.key");
        let cap = tmp("firstboot-cap.bin");
        let cap_tmp = format!("{cap}.new");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&cap_tmp);
        std::fs::create_dir_all(&cap_tmp).unwrap();

        let err = match resolve_serving_identity(Some(&key), &cap, "edge:443", None) {
            Err(e) => e,
            Ok(_) => panic!("staging the capability must fail (EISDIR)"),
        };
        assert!(!err.to_string().contains("not 32 bytes"), "{err}");

        assert!(!std::path::Path::new(&key).exists(), "no partial key file on a failed first boot");
        assert!(!std::path::Path::new(&cap).exists(), "no partial capability file on a failed first boot");
        assert!(!std::path::Path::new(&format!("{key}.new")).exists(), "no leftover key temp file");

        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&cap_tmp);
    }

    #[test]
    fn rotation_dir_adds_old_keys_alongside_the_primary() {
        // #12 K3: keys in the rotation directory are served alongside the primary
        // (the published identity), so old capabilities keep working during a
        // rotation window. The primary is always first.
        let key = tmp("rot-origin.key");
        let cap = tmp("rot-cap.bin");
        let dir = std::env::temp_dir().join(format!("ct-rotdir-{}", std::process::id()));
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Two retired keys in the window.
        std::fs::write(dir.join("old-a.key"), [7u8; 32]).unwrap();
        std::fs::write(dir.join("old-b.key"), [9u8; 32]).unwrap();
        // A stray non-key file is ignored.
        std::fs::write(dir.join("README.txt"), b"not a key").unwrap();

        let dir_s = dir.to_string_lossy().into_owned();
        let id = resolve_serving_identity(Some(&key), &cap, "edge:443", Some(&dir_s)).unwrap();
        assert_eq!(id.origin_keys.len(), 3, "primary + 2 rotation-window keys");
        assert!(
            id.origin_keys[1..].contains(&[7u8; 32]) && id.origin_keys[1..].contains(&[9u8; 32]),
            "old keys are served"
        );

        // The primary stays first and stable regardless of the rotation dir.
        let bare = resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        assert_eq!(bare.origin_keys.len(), 1);
        assert_eq!(id.origin_keys[0], bare.origin_keys[0], "primary is first");

        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_keeps_the_token_and_retires_the_old_key() {
        // #12 K4: rotation preserves the routing token (so old clients still
        // rendezvous) while changing the origin identity, and the old key is
        // retired into the dir so the agent serves BOTH during the window.
        let key = tmp("rk-origin.key");
        let cap = tmp("rk-cap.bin");
        let dir = std::env::temp_dir().join(format!("ct-rk-dir-{}", std::process::id()));
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
        let dir_s = dir.to_string_lossy().into_owned();

        // Establish the initial identity (token T0, origin O0).
        let id0 = resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        let token0 = id0.cap.token.clone();
        let origin0 = id0.cap.origin.clone();

        // Rotate: same token, new origin; old key retired into the dir.
        let new_cap = rotate_origin_key(&key, &cap, &dir_s).unwrap();
        assert_eq!(new_cap.token, token0, "routing token preserved across rotation");
        assert_ne!(new_cap.origin, origin0, "origin identity rotated");

        // The agent now serves the new primary + the retired old identity, still
        // publishing the same token.
        let id1 = resolve_serving_identity(Some(&key), &cap, "edge:443", Some(&dir_s)).unwrap();
        assert_eq!(id1.cap.token, token0, "same token still published");
        assert_eq!(id1.cap.origin, new_cap.origin, "primary is the new origin");
        assert_eq!(id1.origin_keys.len(), 2, "serves new primary + retired old key");

        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_tolerates_a_missing_rotation_dir() {
        // #12 K3 error branch: a nonexistent rotation dir yields no extra keys
        // (load_extra_origin_keys read_dir Err -> empty), just the primary.
        let key = tmp("md-origin.key");
        let cap = tmp("md-cap.bin");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let missing = tmp("does-not-exist-dir");
        let _ = std::fs::remove_dir_all(&missing);
        let id = resolve_serving_identity(Some(&key), &cap, "edge:443", Some(&missing)).unwrap();
        assert_eq!(id.origin_keys.len(), 1, "missing dir -> only the primary key");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
    }

    #[test]
    fn rotate_leaves_key_and_capability_untouched_when_the_capability_write_fails() {
        // A crash-consistency regression test: rotation must not be observable as a
        // half-done state (key_path already the NEW origin while cap_path still
        // names the OLD one) -- that pair would fail every future Noise handshake
        // with no clear signal why. Forces the failure on the capability's staging
        // write by pre-creating a DIRECTORY at exactly `cap_path.new` -- opening a
        // directory for writing fails with EISDIR unconditionally (unlike a
        // permission bit, this isn't bypassed when the test runs as root, which
        // Docker-based CI does).
        let key = tmp("crash-origin.key");
        let cap = tmp("crash-cap.bin");
        let dir = tmp("crash-dir");
        let cap_tmp = format!("{cap}.new");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&cap_tmp);

        resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        let key_before = std::fs::read(&key).unwrap();
        let cap_before = std::fs::read(&cap).unwrap();

        std::fs::create_dir_all(&cap_tmp).unwrap(); // blocks writing cap_path.new, EISDIR

        let err = rotate_origin_key(&key, &cap, &dir)
            .expect_err("writing the new capability's staging file must fail (EISDIR)");
        assert!(!err.to_string().contains("not 32 bytes"), "{err}"); // real failure, not the guard

        assert_eq!(std::fs::read(&key).unwrap(), key_before, "key_path untouched by a failed rotation");
        assert_eq!(std::fs::read(&cap).unwrap(), cap_before, "cap_path untouched by a failed rotation");
        assert!(!std::path::Path::new(&format!("{key}.new")).exists(), "no leftover key temp file");

        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&cap_tmp);
    }

    #[test]
    fn rotate_rejects_a_non_32_byte_current_key() {
        // #12 K4 guard: rotation refuses a corrupt/short current origin key.
        let key = tmp("bk-origin.key");
        let cap = tmp("bk-cap.bin");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
        resolve_serving_identity(Some(&key), &cap, "edge:443", None).unwrap();
        std::fs::write(&key, b"short").unwrap(); // not 32 bytes
        let dir = tmp("bk-dir");
        let err = rotate_origin_key(&key, &cap, &dir)
            .expect_err("a non-32-byte current key must be rejected");
        assert!(err.to_string().contains("not 32 bytes"), "{err}");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&cap);
    }

    #[test]
    fn mints_distinct_tokens() {
        let a = mint_capability(OriginIdentity([1u8; 32]), "edge:443".into());
        let b = mint_capability(OriginIdentity([1u8; 32]), "edge:443".into());
        assert_ne!(a.token, b.token, "each Capability gets a fresh Routing Token");
        assert_eq!(a.origin, OriginIdentity([1u8; 32]));
        assert_eq!(a.edge_addr, "edge:443");
    }

    #[test]
    fn capability_token_registers_in_registry() {
        use ct_common::{AgentId, TenantId};
        use ct_control_plane::registry::{TunnelInfo, TunnelRegistry};

        let cap = mint_capability(OriginIdentity([2u8; 32]), "edge.example:443".into());
        let mut registry = TunnelRegistry::new();
        let info = TunnelInfo {
            tenant: TenantId("tenant-1".into()),
            agent: AgentId("agent-1".into()),
        };
        registry.register(cap.token.clone(), info.clone());
        assert_eq!(registry.lookup(&cap.token), Some(&info));
    }
}
