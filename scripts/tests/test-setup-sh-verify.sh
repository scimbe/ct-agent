#!/usr/bin/env bash
# The installer verifies what it downloads, like `ct-agent update`: the binary must match its
# .sha256, and the signed release-manifest.json must verify against the pinned release key and
# list the same digest. Uses a file:// mirror signed with a throwaway key (passed in through
# CT_AGENT_RELEASE_PUBKEY, the same override self_update.rs honours), so no network is touched.
#
#   scripts/tests/test-setup-sh-verify.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SH="$ROOT/scripts/setup.sh"
fail=0

command -v openssl >/dev/null 2>&1 && openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' \
  || { echo "SKIP: needs OpenSSL >= 3"; exit 0; }

case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  i686|i386)     arch=i686 ;;
  *) echo "SKIP: unsupported test arch $(uname -m)"; exit 0 ;;
esac
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
asset="ct-agent-${os}-${arch}"
sha() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }

keys="$(mktemp -d)"
openssl genpkey -algorithm ed25519 -out "$keys/release.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$keys/other.pem" 2>/dev/null
pubhex() { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
RELEASE_KEY="$(pubhex "$keys/release.pem")"

# make_mirror <dir> <binary text> <signing key> [manifest digest override]
make_mirror() {
  local dir="$1" body="$2" key="$3" digest
  mkdir -p "$dir"
  printf '#!/bin/sh\necho %s\n' "$body" > "$dir/$asset"
  (cd "$dir" && { sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset"; } > "$asset.sha256")
  digest="${4:-$(sha "$dir/$asset")}"
  printf '{"assets":{"%s":"%s"},"created_at":1,"schema":1,"tag":"v9.9.9"}' "$asset" "$digest" \
    > "$dir/release-manifest.json"
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$dir/release-manifest.json" -out "$dir/sig.bin"
  openssl base64 -A -in "$dir/sig.bin" > "$dir/release-manifest.sig"
  rm -f "$dir/sig.bin"
}

# run_install <mirror> [extra env...] -> sets $out, $rc, $dir
run_install() {
  local mirror="$1"; shift
  dir="$(mktemp -d)"
  out=$(cd "$dir" && env -i PATH="$PATH" HOME="$dir" CT_RELEASE_BASE="file://$mirror" \
    CT_AGENT_RELEASE_PUBKEY="$RELEASE_KEY" "$@" bash "$SETUP_SH" --client-only 2>&1 </dev/null)
  rc=$?
}

expect_installed() { # <name> <expected output of the binary>
  if [ "$rc" -eq 0 ] && [ -x "$dir/ct-agent" ] && [ "$("$dir/ct-agent")" = "$2" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1 rc=$rc output: $out" >&2; fail=1
  fi
}

expect_refused() { # <name> <text the output must contain>
  if [ "$rc" -ne 0 ] && [ ! -e "$dir/ct-agent" ] && [ ! -e "$dir/ct-agent.download" ] \
     && printf '%s' "$out" | grep -qF -- "$2"; then
    echo "ok: $1"
  else
    echo "FAIL: $1 rc=$rc (expected a refusal naming '$2') output: $out" >&2; fail=1
  fi
}

m="$(mktemp -d)"

make_mirror "$m/good" good "$keys/release.pem"
run_install "$m/good"
expect_installed "a signed, matching release installs" good
printf '%s' "$out" | grep -qF "release signature verified" || { echo "FAIL: no signature line: $out" >&2; fail=1; }

make_mirror "$m/tampered" good "$keys/release.pem"
printf '#!/bin/sh\necho evil\n' > "$m/tampered/$asset"
run_install "$m/tampered"
expect_refused "a binary that does not match its .sha256 is refused" "does not match its .sha256"

make_mirror "$m/swapped" evil "$keys/release.pem" "$(printf '%064d' 0)"
run_install "$m/swapped"
expect_refused "a binary + .sha256 swapped behind the signed manifest is refused" "does not list $asset with this digest"

make_mirror "$m/forged" evil "$keys/other.pem"
run_install "$m/forged"
expect_refused "a manifest signed by another key is refused" "does not verify against the pinned release key"

make_mirror "$m/unsigned" good "$keys/release.pem"
rm -f "$m/unsigned/release-manifest.sig"
run_install "$m/unsigned"
expect_refused "a release without a signature is refused" "no release-manifest.sig"

make_mirror "$m/nosum" good "$keys/release.pem"
rm -f "$m/nosum/$asset.sha256"
run_install "$m/nosum"
expect_refused "a release without a .sha256 is refused" "no $asset.sha256"

run_install "$m/forged" CT_AGENT_UPDATE_SKIP_VERIFY=1
expect_installed "CT_AGENT_UPDATE_SKIP_VERIFY=1 skips only the signature" evil

# docker/verify-release.sh makes the same checks inside the image build.
VERIFY="$ROOT/docker/verify-release.sh"
docker_verify() { # <name> <mirror> <expect 0|1> [text]
  local o r
  o=$(env -i PATH="$PATH" CT_AGENT_RELEASE_PUBKEY="$RELEASE_KEY" \
    bash "$VERIFY" "$2/$asset" "$asset" "file://$2" 2>&1); r=$?
  if { [ "$3" -eq 0 ] && [ "$r" -eq 0 ]; } || { [ "$3" -ne 0 ] && [ "$r" -ne 0 ] && printf '%s' "$o" | grep -qF -- "$4"; }; then
    echo "ok: docker/verify-release.sh: $1"
  else
    echo "FAIL: docker/verify-release.sh: $1 rc=$r output: $o" >&2; fail=1
  fi
}
docker_verify "accepts a signed, matching release" "$m/good" 0
docker_verify "refuses a tampered binary" "$m/tampered" 1 "does not match its .sha256"
docker_verify "refuses a swapped binary + .sha256" "$m/swapped" 1 "does not list $asset with this digest"
docker_verify "refuses another key's signature" "$m/forged" 1 "does not verify against the pinned release key"
docker_verify "refuses a release without a signature" "$m/unsigned" 1 "no release-manifest.sig"

rm -rf "$keys" "$m"
if [ "$fail" -eq 0 ]; then
  echo "PASS: setup.sh verifies what it installs"
else
  echo "FAIL: setup.sh download verification regressed"
fi
exit "$fail"
