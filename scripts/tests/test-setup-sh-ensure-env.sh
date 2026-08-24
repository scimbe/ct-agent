#!/usr/bin/env bash
# Regression test for scripts/setup.sh's ensure_env() gate.
#
# Real gap this guards against (found live while writing help.bunsenbrenner.org's
# sandbox-instructions section): ensure_env() used to unconditionally require a
# real .env FILE on disk, even when the one secret that actually matters
# (CT_BOOTSTRAP, or CT_AGENT_JOIN_TOKEN+CT_AGENT_TOKEN) was already sitting right
# there in the process environment -- meaning the portal's own advertised
# one-liner (`curl ... | CT_BOOTSTRAP=... sh`, installer.rs's
# install_one_liner_bootstrap) could never actually complete non-interactively.
#
# Sources setup.sh directly (safe: the BASH_SOURCE guard at the bottom of
# setup.sh means `source`-ing it defines functions only, it never calls main()
# or touches the network/filesystem beyond what a test explicitly does).
#
#   scripts/tests/test-setup-sh-ensure-env.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SH="$ROOT/scripts/setup.sh"
fail=0

# Deliberately NOT sourcing setup.sh here at top level: it carries its own
# `set -euo pipefail`, which -- since `source` runs in the CURRENT shell --
# would silently turn on errexit for the rest of THIS test script too (a
# nonzero `out3=$(...)` assignment in case 3 below would then abort the whole
# test right there instead of being asserted on). Each case below sources it
# inside its own isolated `bash -c` subshell instead, where that's contained.

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" != "$actual" ]; then
    echo "FAIL: $desc (expected [$expected], got [$actual])" >&2
    fail=1
  else
    echo "ok: $desc"
  fi
}

run_case() {
  local dir; dir="$(mktemp -d)"
  ( cd "$dir" && "$@" )
  local rc=$?
  echo "$dir:$rc"
}

# --- case 1: no .env file, but the essential secret is already in the environment (the real one-liner shape) ---
dir1="$(mktemp -d)"
out1=$(cd "$dir1" && env -i PATH="$PATH" \
  CT_AGENT_JOIN_TOKEN=dummyjoin CT_AGENT_TOKEN=dummytoken \
  CT_AGENT_CP_URL=https://example.invalid CT_AGENT_HOSTNAME=demo.example \
  CT_AGENT_ORIGIN=127.0.0.1:8080 CT_AGENT_EDGE=example.invalid:4433 \
  bash -c "set -uo pipefail; C_B='' C_G='' C_Y='' C_R='' C_0=''; STATE_DIR='./.ct-agent-state'; source '$SETUP_SH'; ensure_env && echo ENSURE_ENV_OK" 2>&1)
rc1=$?
assert_eq "case 1 (env-only one-liner shape) exits 0" "0" "$rc1"
case "$out1" in
  *ENSURE_ENV_OK*) echo "ok: case 1 reached end of ensure_env" ;;
  *) echo "FAIL: case 1 did not reach end of ensure_env -- output: $out1" >&2; fail=1 ;;
esac
case "$out1" in
  *".env not found"*) echo "FAIL: case 1 should not need a real .env file: $out1" >&2; fail=1 ;;
  *) echo "ok: case 1 did not demand a .env file" ;;
esac
rm -rf "$dir1"

# --- case 2: a real .env file present (the pre-existing, still-supported path) ---
dir2="$(mktemp -d)"
cat > "$dir2/.env" <<'EOF'
CT_AGENT_JOIN_TOKEN=fromfile
CT_AGENT_TOKEN=fromfiletoken
CT_AGENT_CP_URL=https://example.invalid
CT_AGENT_HOSTNAME=demo.example
CT_AGENT_ORIGIN=127.0.0.1:9090
CT_AGENT_EDGE=example.invalid:4433
EOF
out2=$(cd "$dir2" && env -i PATH="$PATH" \
  bash -c "set -uo pipefail; C_B='' C_G='' C_Y='' C_R='' C_0=''; STATE_DIR='./.ct-agent-state'; source '$SETUP_SH'; ensure_env && echo ENSURE_ENV_OK" 2>&1)
rc2=$?
assert_eq "case 2 (.env file present) exits 0" "0" "$rc2"
case "$out2" in
  *ENSURE_ENV_OK*) echo "ok: case 2 reached end of ensure_env" ;;
  *) echo "FAIL: case 2 did not reach end of ensure_env -- output: $out2" >&2; fail=1 ;;
esac
rm -rf "$dir2"

# --- case 3: neither a .env file nor the secret in env -- must still guide the user, not silently proceed ---
dir3="$(mktemp -d)"
out3=$(cd "$dir3" && env -i PATH="$PATH" \
  bash -c "set -uo pipefail; C_B='' C_G='' C_Y='' C_R='' C_0=''; STATE_DIR='./.ct-agent-state'; source '$SETUP_SH'; ensure_env && echo ENSURE_ENV_OK" 2>&1)
rc3=$?
assert_eq "case 3 (nothing provided) exits 1" "1" "$rc3"
if [ -f "$dir3/.env.example" ]; then
  echo "ok: case 3 wrote .env.example so the customer has something to fill in"
else
  echo "FAIL: case 3 did not write .env.example" >&2
  fail=1
fi
rm -rf "$dir3"

if [ "$fail" -eq 0 ]; then
  echo "PASS: all ensure_env() cases behaved correctly"
else
  echo "FAIL: one or more ensure_env() cases regressed"
fi
exit "$fail"
