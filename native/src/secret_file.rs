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
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Non-Unix fallback: there is no mode to set, so this is a plain write. Kept as a
/// separate `cfg` rather than a runtime branch so the Unix path carries no dead code.
#[cfg(not(unix))]
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
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
}
