#!/usr/bin/env bash
# Regression test for #219: --client-only must install the binary without a
# .env, without the sandbox confirm, and without starting a serving agent.
# Uses a file:// CT_RELEASE_BASE so no network is touched.
#
#   scripts/tests/test-setup-sh-client-only.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SH="$ROOT/scripts/setup.sh"
fail=0

case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  i686|i386)     arch=i686 ;;
  *) echo "SKIP: unsupported test arch $(uname -m)"; exit 0 ;;
esac
os="$(uname -s | tr '[:upper:]' '[:lower:]')"

mirror="$(mktemp -d)"
printf '#!/bin/sh\necho fake-ct-agent\n' > "$mirror/ct-agent-${os}-${arch}"

# --- case 1: piped, no .env, no TTY, no --yes -- must still install the binary.
dir1="$(mktemp -d)"
out1=$(cd "$dir1" && env -i PATH="$PATH" HOME="$dir1" CT_RELEASE_BASE="file://$mirror" \
  bash -s -- --client-only < "$SETUP_SH" 2>&1)
rc1=$?
[ "$rc1" -eq 0 ] && echo "ok: case 1 exited 0" || { echo "FAIL: case 1 rc=$rc1 output: $out1" >&2; fail=1; }
if [ -x "$dir1/ct-agent" ] && [ "$("$dir1/ct-agent")" = "fake-ct-agent" ]; then
  echo "ok: case 1 installed the binary"
else
  echo "FAIL: case 1 did not install an executable ct-agent -- output: $out1" >&2; fail=1
fi
for f in .env.example ct-agent.pid ct-agent.log .ct-agent-state; do
  [ -e "$dir1/$f" ] && { echo "FAIL: case 1 created $f (should not touch agent setup)" >&2; fail=1; }
done
echo "ok: case 1 left no agent-setup files behind"
rm -rf "$dir1"

# --- case 2: --client-only combined with a serving-agent flag is refused.
dir2="$(mktemp -d)"
out2=$(cd "$dir2" && env -i PATH="$PATH" HOME="$dir2" CT_RELEASE_BASE="file://$mirror" \
  bash "$SETUP_SH" --client-only --docker 2>&1)
rc2=$?
if [ "$rc2" -ne 0 ] && [ ! -e "$dir2/ct-agent" ]; then
  echo "ok: case 2 refused --client-only --docker"
else
  echo "FAIL: case 2 rc=$rc2 output: $out2" >&2; fail=1
fi
rm -rf "$dir2" "$mirror"

if [ "$fail" -eq 0 ]; then
  echo "PASS: setup.sh --client-only behaves"
else
  echo "FAIL: setup.sh --client-only regressed"
fi
exit "$fail"
