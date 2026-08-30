#!/bin/sh
# Security-hardening pass: this image now runs the Agent as an unprivileged
# uid/gid (65532, this product family's non-root baseline) instead of root.
#
# The container still STARTS as root (see the Dockerfile: no USER directive)
# specifically so this script can migrate an EXISTING deployment's mounted
# state before dropping privileges. Without this step, recreating a container
# from an already-deployed image (bind-mounted CT_AGENT_STATE_DIR/`/shared`
# created by the OLD root-run container) would fail every write with
# Permission denied the moment the new non-root image tried to touch it --
# turning a routine version bump into a breaking change for every existing
# customer. `chown` here is idempotent and a no-op on a fresh install (nothing
# to fix yet), so this never costs a new deployment anything.
set -e

for dir in "${CT_AGENT_STATE_DIR:-}" /shared; do
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        chown -R 65532:65532 "$dir" 2>/dev/null || true
    fi
done

# `--userspec` drops to the target uid:gid without needing a /etc/passwd entry
# (none is created for 65532 -- see the Dockerfile comment) or an extra
# downloaded binary like gosu/su-exec. `--skip-chdir` (coreutils 8.28+, present
# on ubuntu:24.04) means this only changes the process's uid/gid -- it does
# NOT actually chroot the filesystem, so every absolute path the Agent reads
# (CT_AGENT_STATE_DIR, /shared/*) still resolves exactly as before.
exec chroot --userspec=65532:65532 --skip-chdir / "$@"
