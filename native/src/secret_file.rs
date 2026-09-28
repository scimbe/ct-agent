//! The one way this agent writes a secret to disk (#36).
//!
//! There were two rules for the same job and they had already drifted apart.
//! [`write_private`] (from #31, for the ACME account/cert keys) opens the file with the
//! restrictive mode so it is never on disk wider than `0600`, then corrects a
//! pre-existing file's mode explicitly. `Identity::save_secret_to` did the opposite: a
//! plain `fs::write` under the umask, narrowed only *afterwards* — so the 32 secret
//! ed25519 bytes sat at whatever the umask allowed (commonly `0644`) until the second
//! call landed, and a crash in between left the agent's identity key world-readable for
//! good. Local disclosure of that key is full agent-identity takeover.
//!
//! Neither copy was wrong when written; the second one simply never learned what the
//! first one had. Hence one function, in one place, that both call.

use std::path::Path;

/// Write `bytes` to `path` so the content is never on disk at a wider mode than `0600`.
///
/// Deliberately **not** `create_new(true)`: re-provisioning legitimately overwrites an
/// existing key (`Onboarded::persist` re-runs, an operator restores a state dir). Refusing
/// a pre-existing file would turn a routine path into a hard failure. What matters is that
/// the fresh secret is never *readable* by anyone else:
///
/// * `mode(0o600)` applies at CREATE time, so the common case (no file yet) has no window
///   at all — this is the part `fs::write` + `set_permissions` could not give.
/// * `set_permissions` afterwards additionally CORRECTS a file that already existed at a
///   wider mode (an older agent's key, a restored backup, an operator's `touch`), which is
///   the case #31 was filed about.
///
/// `sync_all` before returning: a key that the caller believes is persisted, but which a
/// power loss drops, costs a re-enrolment with a single-use token that is already spent.
/// `O_NOFOLLOW` (security-hardening pass, cloudflared-class-defense audit
/// finding B.1): without it, a pre-planted symlink at `path` -- possible only
/// if an attacker already has write access to the containing directory --
/// would be followed and truncated-then-narrowed-to-`0600` by this call
/// instead of refused. Low real-world exploitability here (no default path
/// this crate writes to is world-writable like `/tmp`), but the guard is
/// cheap and closes the class outright rather than relying on that being
/// true forever.
#[cfg(unix)]
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // A symlink at `path` is refused outright (the O_NOFOLLOW contract). A link planted
    // after this check is harmless: `rename` replaces the link itself, never its target.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
    }
    replace_atomically(path, bytes, 0o600)
}

/// Non-Unix fallback: there is no mode to set, so this is a plain atomic replace. Kept as a
/// separate `cfg` rather than a runtime branch so the Unix path carries no dead code.
#[cfg(not(unix))]
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    replace_atomically(path, bytes, 0o600)
}

/// [`write_private`]'s crash safety for a file that is not a secret (a certificate chain a
/// web server under another user must read, an id file): created at `0644` minus the umask.
pub fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    replace_atomically(path, bytes, 0o644)
}

/// Write a temp sibling (created exclusively, `mode`, `O_NOFOLLOW`), `fsync` it, rename it
/// over `path`, then `fsync` the directory. Writing `path` in place with `truncate` left an
/// empty or half-written file behind on a crash -- for a rotated OIDC refresh token or the
/// local-auth credential that is a manual re-login on an unattended host.
/// `create_dir_all`, except that every directory it CREATES is `0700` (Unix): the state dir holds
/// secrets, and whichever writer runs first must not leave it listable at the umask. Existing
/// directories are left exactly as they are.
pub fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn replace_atomically(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = temp_sibling(path);
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let written = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        sync_parent_dir(path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// `.<name>.tmp` next to `path`.
fn temp_sibling(path: &Path) -> std::path::PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.tmp"))
}

/// `fsync` the directory holding `path`, so a completed `rename` into it survives a power
/// loss. A no-op where directories cannot be opened for syncing.
pub fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn created_state_dirs_are_private_and_existing_ones_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b");
        create_private_dir_all(&nested).unwrap();
        for d in [root.path().join("a"), nested.clone()] {
            assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700, "{d:?}");
        }
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir_all(root.path()).unwrap();
        assert_eq!(std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777, 0o755);
    }

    use super::*;

    /// Same idiom as the #31 test this file absorbed: a per-process scratch dir, so no
    /// dev-dependency is added just to hold two files. The `what` suffix keeps the two
    /// tests in this module from sharing a directory when they run concurrently.
    fn scratch(what: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ct-secret-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// #31: an already-existing, world-readable file must come out narrowed.
    #[cfg(unix)]
    #[test]
    fn write_private_hardens_a_file_that_already_exists_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("hardens");
        let path = dir.join("key");
        std::fs::write(&path, b"stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"fresh-private-key-material").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a pre-existing wider file must be corrected, not inherited");
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh-private-key-material");
    }

    /// Security-hardening pass, B.1: a pre-planted symlink at the target path
    /// must be REFUSED, not followed. Fails against the pre-`O_NOFOLLOW` code:
    /// without the flag this call would silently truncate+write through the
    /// symlink into whatever it points at.
    #[cfg(unix)]
    #[test]
    fn write_private_refuses_to_follow_a_pre_planted_symlink() {
        let dir = scratch("symlink");
        let real_target = dir.join("outside-file");
        std::fs::write(&real_target, b"pre-existing, must not be touched").unwrap();
        let link_path = dir.join("key");
        std::os::unix::fs::symlink(&real_target, &link_path).unwrap();

        let err = write_private(&link_path, b"attacker-controlled").unwrap_err();
        // ELOOP (40 on Linux) is what O_NOFOLLOW produces when the target IS a
        // symlink; ErrorKind::FilesystemLoop is still unstable on this
        // toolchain, so match the raw errno instead.
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "must refuse via O_NOFOLLOW (ELOOP), not follow: {err}");
        assert_eq!(
            std::fs::read(&real_target).unwrap(),
            b"pre-existing, must not be touched",
            "the symlink target must be untouched"
        );
    }

    /// #36: the CREATE path ends at `0600`.
    ///
    /// **What this does NOT prove, stated plainly:** the old
    /// `fs::write` + `set_permissions` shape would pass it too, because it also ends at
    /// `0600` — the defect was the *window* between the two calls, and a final-state
    /// assertion cannot see a window. Observing it would mean racing a reader against the
    /// two syscalls, which fails in the useless direction: green by luck.
    ///
    /// The window is therefore closed by CONSTRUCTION, not by this test — `mode()` on the
    /// `OpenOptions` applies when the file is created, so there is no moment at which the
    /// bytes exist at a wider mode. What this test does earn: it fails if someone later
    /// swaps the helper back to a plain `fs::write` with no narrowing at all, and it pins
    /// the post-condition both callers depend on.
    #[cfg(unix)]
    #[test]
    fn a_freshly_created_secret_is_never_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("create");
        let path = dir.join("new-key");
        assert!(!path.exists(), "this test is about the CREATE path");

        write_private(&path, b"secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created at 0600, not narrowed to it afterwards");
    }

    #[test]
    fn write_private_replaces_atomically_and_leaves_no_temp_file() {
        let dir = scratch("atomic");
        let path = dir.join("token.json");
        write_private(&path, b"first").unwrap();
        // A stale temp from an interrupted earlier write, even a symlink, is not followed.
        let tmp = dir.join(".token.json.tmp");
        #[cfg(unix)]
        {
            let decoy = dir.join("decoy");
            std::fs::write(&decoy, b"untouched").unwrap();
            std::os::unix::fs::symlink(&decoy, &tmp).unwrap();
            write_private(&path, b"second").unwrap();
            assert_eq!(std::fs::read(&decoy).unwrap(), b"untouched");
        }
        #[cfg(not(unix))]
        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(std::fs::symlink_metadata(&tmp).is_err(), "no temp file left behind");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn write_durable_is_readable_by_others_but_still_atomic() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("durable");
        let path = dir.join("fullchain.pem");
        write_durable(&path, b"cert").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644 & !process_umask(), "0644 minus the umask, not forced to 0600");
        assert_eq!(std::fs::read(&path).unwrap(), b"cert");
    }

    /// The umask from /proc, read without changing it (it is process-wide, and the
    /// other tests run concurrently).
    #[cfg(target_os = "linux")]
    fn process_umask() -> u32 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("Umask:")).unwrap();
        u32::from_str_radix(line.trim_start_matches("Umask:").trim(), 8).unwrap()
    }
}
