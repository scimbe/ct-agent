#!/usr/bin/env bash
# Regression test for setup.sh's secret handling and --docker env passthrough:
#  - CT_BOOTSTRAP must never appear in a child process's argv (ps-visible);
#  - install_docker must hand the container every value ensure_env resolved
#    (redeemed tokens, CT_AGENT_ID, CT_AGENT_EDGE, ...) -- with or without a
#    .env file -- and must not put secret values in docker's argv either.
# docker and curl are stubs on PATH that record their argv (and, for
# `docker run`, the -e NAME values they would copy); no network, no daemon.
#
#   scripts/tests/test-setup-sh-secrets-docker.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SH="$ROOT/scripts/setup.sh"
fail=0

stubs="$(mktemp -d)"
cat > "$stubs/curl" <<'STUB'
#!/bin/sh
echo "curl $*" >> "$STUB_LOG"
case "$*" in
  *bootstrap/redeem*) cat >/dev/null; printf '{"secret":"CT_JOIN_TOKEN=redeemedjoin;CT_AGENT_TOKEN=redeemedagent"}' ;;
  *releases/latest*)  printf '{"tag_name": "v9.9.9"}' ;;
  *network-info*)     printf '{"mesh_edge_port":4433}' ;;
esac
STUB
cat > "$stubs/docker" <<'STUB'
#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
if [ "$1" = "run" ]; then
  prev=""
  for a in "$@"; do
    if [ "$prev" = "-e" ]; then
      case "$a" in *=*) echo "ENV $a" ;; *) eval "v=\${$a-__UNSET__}"; echo "ENV $a=$v" ;; esac
    fi
    prev="$a"
  done >> "$STUB_ENV"
fi
exit 0
STUB
chmod +x "$stubs/curl" "$stubs/docker"

run_docker_case() {
  local dir="$1"; shift
  (cd "$dir" && env -i PATH="$stubs:$PATH" HOME="$dir" STUB_LOG="$dir/argv.log" STUB_ENV="$dir/env.log" "$@" \
    bash -c "set -uo pipefail; source '$SETUP_SH'; MODE=docker; ensure_env && install_docker && echo DOCKER_OK" </dev/null 2>&1)
}

expect_env() {
  local desc="$1" file="$2" line="$3"
  if grep -qxF "ENV $line" "$file"; then echo "ok: $desc: $line"; else
    echo "FAIL: $desc: container would not get $line -- got:" >&2; cat "$file" >&2; fail=1; fi
}

# --- case 1: bootstrap one-liner shape, no .env file at all.
d1="$(mktemp -d)"
out1=$(run_docker_case "$d1" CT_BOOTSTRAP=sekritbootstrap CT_AGENT_CP_URL=https://cp.example \
  CT_AGENT_HOSTNAME=demo.example CT_AGENT_ORIGIN=10.0.0.5:8080)
case "$out1" in *DOCKER_OK*) echo "ok: case 1 completed" ;; *) echo "FAIL: case 1: $out1" >&2; fail=1 ;; esac
if grep -q sekritbootstrap "$d1/argv.log"; then
  echo "FAIL: case 1 leaked CT_BOOTSTRAP into a child argv:" >&2; grep sekritbootstrap "$d1/argv.log" >&2; fail=1
else echo "ok: case 1 kept CT_BOOTSTRAP out of every argv"; fi
if grep -qE 'redeemedjoin|redeemedagent' "$d1/argv.log"; then
  echo "FAIL: case 1 put redeemed tokens into docker argv" >&2; fail=1
else echo "ok: case 1 kept redeemed tokens out of docker argv"; fi
if grep -q -- '--env-file' "$d1/argv.log"; then echo "FAIL: case 1 passed --env-file without a .env" >&2; fail=1; fi
expect_env "case 1" "$d1/env.log" "CT_AGENT_JOIN_TOKEN=redeemedjoin"
expect_env "case 1" "$d1/env.log" "CT_AGENT_TOKEN=redeemedagent"
expect_env "case 1" "$d1/env.log" "CT_AGENT_EDGE=cp.example:4433"
expect_env "case 1" "$d1/env.log" "CT_AGENT_EDGE_CERT_URL=https://cp.example"
expect_env "case 1" "$d1/env.log" "CT_AGENT_MODE=browser"
expect_env "case 1" "$d1/env.log" "CT_AGENT_STATE_DIR=/state"
expect_env "case 1" "$d1/env.log" "CT_AGENT_CAPABILITY_OUT=/state/capability.bin"
if grep -qE '^ENV CT_AGENT_ID=agent-[0-9]+-[0-9]+$' "$d1/env.log"; then echo "ok: case 1: CT_AGENT_ID passed"; else
  echo "FAIL: case 1: CT_AGENT_ID not passed" >&2; fail=1; fi
if grep -q -- "-v $d1/.ct-agent-state:/state" "$d1/argv.log"; then echo "ok: case 1 mounted an absolute state dir"; else
  echo "FAIL: case 1 state mount wrong:" >&2; grep '^docker run' "$d1/argv.log" >&2; fail=1; fi
rm -rf "$d1"

# --- case 2: a .env file with explicit tokens -- still passed, plus the resolved values.
d2="$(mktemp -d)"
cat > "$d2/.env" <<'ENV'
CT_AGENT_JOIN_TOKEN=filejoin
CT_AGENT_TOKEN=filetoken
CT_AGENT_CP_URL=https://cp.example
CT_AGENT_HOSTNAME=demo.example
CT_AGENT_ORIGIN=127.0.0.1:8080
ENV
out2=$(run_docker_case "$d2")
case "$out2" in *DOCKER_OK*) echo "ok: case 2 completed" ;; *) echo "FAIL: case 2: $out2" >&2; fail=1 ;; esac
grep -q -- '--env-file .env' "$d2/argv.log" && echo "ok: case 2 kept --env-file .env" || { echo "FAIL: case 2 dropped --env-file" >&2; fail=1; }
expect_env "case 2" "$d2/env.log" "CT_AGENT_TOKEN=filetoken"
expect_env "case 2" "$d2/env.log" "CT_AGENT_EDGE=cp.example:4433"
case "$out2" in *"is loopback"*) echo "ok: case 2 warned about a loopback origin" ;; *) echo "FAIL: case 2 no loopback warning" >&2; fail=1 ;; esac
rm -rf "$d2" "$stubs"

if [ "$fail" -eq 0 ]; then
  echo "PASS: setup.sh keeps secrets out of argv and hands --docker its full config"
else
  echo "FAIL: setup.sh secret/docker handling regressed"
fi
exit "$fail"
