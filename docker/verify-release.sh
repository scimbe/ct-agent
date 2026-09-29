#!/bin/bash
# Verify a downloaded ct-agent release asset before the image installs it -- the same two checks
# scripts/setup.sh's verify_release_asset and `ct-agent update` make:
#  1. it hashes to its published <asset>.sha256;
#  2. the signed release-manifest.json verifies against the pinned release key and lists the
#     same digest for this asset.
#
#   verify-release.sh <file> <asset> <release base URL>
#
# CT_AGENT_RELEASE_PUBKEY overrides the pinned key (hex ed25519, space-separated for a rotation);
# CT_AGENT_UPDATE_SKIP_VERIFY=1 skips step 2. Needs curl, sha256sum and OpenSSL >= 3.
set -euo pipefail

file="$1" asset="$2" base="${3%/}"
keys="${CT_AGENT_RELEASE_PUBKEY:-73706122db4e9186743ab3aabdf55d80ecf7f08ddc6c5243c9887f7d9bcc9a78}"
die() { echo "verify-release: $*" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$base/$asset.sha256" -o "$tmp/sum" || die "no $asset.sha256 at $base"
expected="$(tr -d '\r' < "$tmp/sum" | awk 'NF { print tolower($1); exit }')"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "$asset.sha256 holds no SHA-256 digest"
actual="$(sha256sum "$file" | cut -d' ' -f1)"
[ "$actual" = "$expected" ] || die "$asset does not match its .sha256 (got $actual)"
echo "verify-release: checksum verified"

case "${CT_AGENT_UPDATE_SKIP_VERIFY:-}" in
  1|true|yes|on) echo "verify-release: CT_AGENT_UPDATE_SKIP_VERIFY is set: signature NOT verified" >&2; exit 0 ;;
esac
curl -fsSL "$base/release-manifest.json" -o "$tmp/manifest" || die "the release publishes no release-manifest.json"
curl -fsSL "$base/release-manifest.sig" -o "$tmp/sig.b64" || die "the release publishes no release-manifest.sig"
openssl base64 -d -A -in "$tmp/sig.b64" -out "$tmp/sig" 2>/dev/null || die "release-manifest.sig is not base64"
for key in $keys; do
  [[ "$key" =~ ^[0-9a-fA-F]{64}$ ]] || continue
  # SubjectPublicKeyInfo for a raw ed25519 key: the fixed 12-byte DER prefix, then the key.
  printf "$(printf '302a300506032b6570032100%s' "$key" | sed 's/../\\x&/g')" > "$tmp/pub.der"
  openssl pkey -pubin -inform DER -in "$tmp/pub.der" -out "$tmp/pub.pem" 2>/dev/null || continue
  if openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/manifest" -sigfile "$tmp/sig" >/dev/null 2>&1; then
    grep -qF "\"$asset\":\"$expected\"" "$tmp/manifest" \
      || die "the signed release-manifest.json does not list $asset with this digest"
    echo "verify-release: release signature verified"
    exit 0
  fi
done
die "release-manifest.json does not verify against the pinned release key"
