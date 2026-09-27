#!/usr/bin/env bash
# Regression test for #218: `curl ... | bash` (script on stdin, no backing file)
# must reach main() instead of dying on an unbound BASH_SOURCE[0] under set -u,
# while `source`-ing the file must still NOT run main().
#
#   scripts/tests/test-setup-sh-piped.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SH="$ROOT/scripts/setup.sh"
fail=0

# --- case 1: piped into bash. Without --yes and without a TTY, main() must get
# as far as confirm_mode's non-interactive refusal -- proof that main ran.
dir1="$(mktemp -d)"
out1=$(cd "$dir1" && env -i PATH="$PATH" HOME="$dir1" bash < "$SETUP_SH" 2>&1)
rc1=$?
case "$out1" in
  *"unbound variable"*) echo "FAIL: case 1 hit an unbound variable: $out1" >&2; fail=1 ;;
  *"checking your environment"*) echo "ok: case 1 (piped) reached main()" ;;
  *) echo "FAIL: case 1 (piped) never reached main() -- output: $out1" >&2; fail=1 ;;
esac
case "$out1" in
  *"not an interactive terminal"*) echo "ok: case 1 stopped at the non-interactive confirm gate" ;;
  *) echo "FAIL: case 1 did not stop at the confirm gate -- output: $out1" >&2; fail=1 ;;
esac
[ "$rc1" -ne 0 ] && echo "ok: case 1 exited nonzero ($rc1)" || { echo "FAIL: case 1 exited 0" >&2; fail=1; }
rm -rf "$dir1"

# --- case 2: sourced (the scripts/tests use case) -- main() must NOT run.
dir2="$(mktemp -d)"
out2=$(cd "$dir2" && env -i PATH="$PATH" HOME="$dir2" \
  bash -c "set -uo pipefail; source '$SETUP_SH'; echo SOURCED_OK" 2>&1)
rc2=$?
case "$out2" in
  *"checking your environment"*) echo "FAIL: case 2 (sourced) ran main(): $out2" >&2; fail=1 ;;
  *SOURCED_OK*) echo "ok: case 2 (sourced) defined functions only" ;;
  *) echo "FAIL: case 2 (sourced) did not complete -- rc=$rc2 output: $out2" >&2; fail=1 ;;
esac
rm -rf "$dir2"

if [ "$fail" -eq 0 ]; then
  echo "PASS: setup.sh main() guard behaves for piped and sourced invocation"
else
  echo "FAIL: setup.sh main() guard regressed"
fi
exit "$fail"
