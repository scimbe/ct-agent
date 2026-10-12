#!/usr/bin/env bash
# Keeps internal identifiers, hosts, accounts and secrets out of a public repository.
#
#   check-public-hygiene.sh diff [BASE [HEAD]]   CI mode: lines ADDED between BASE...HEAD,
#                                                commit messages and author/committer emails
#                                                of BASE..HEAD, plus PR_TITLE / PR_BODY /
#                                                PR_HEAD_REF from the environment. Exit 1 on a hit.
#   check-public-hygiene.sh scan                 Report on the tracked tree. Always exits 0.
#
# Matches are reported by location and rule name only, never by value: CI logs of a
# public repository are public. Rules live in scripts/public-hygiene.patterns.
# Optional, kept outside the repository (for example as CI secrets):
#   PUBLIC_HYGIENE_EXTRA_PATTERNS   more rules, same format as the patterns file
#   PUBLIC_HYGIENE_EXTRA_SHA256     whitespace-separated sha256 of lowercased tokens
set -euo pipefail

mode="${1:-}"; [ $# -gt 0 ] && shift
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
patterns_file="$here/public-hygiene.patterns"
tab=$'\t'; us=$'\x1f'
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
stream="$work/stream"; : > "$stream"
rules="$work/rules"
grep -vE '^(#|$)' "$patterns_file" > "$rules"
if [ -n "${PUBLIC_HYGIENE_EXTRA_PATTERNS:-}" ]; then
  printf '%s\n' "$PUBLIC_HYGIENE_EXTRA_PATTERNS" | grep -vE '^(#|$)' >> "$rules" || true
fi
author_allow="$(awk -F'\t' '$1=="@author-allow"{print $2}' "$rules")"
[ -n "$author_allow" ] || { echo "no @author-allow rule in $patterns_file" >&2; exit 2; }
grep -v '^@' "$rules" > "$rules.r" || true

# add_text LOCPREFIX < text   -> "LOCPREFIX:LINE<US>text" per line, marker lines dropped
add_text() { awk -v p="$1" -v us="$us" 'index($0,"public-hygiene: allow")==0 {print p ":" NR us $0}' >> "$stream"; }

hits=0
report() { # loc rule
  hits=$((hits + 1))
  local file="${1%%:*}" line="${1##*:}"
  if [ -n "${GITHUB_ACTIONS:-}" ] && [ -f "$file" ]; then
    echo "::error file=$file,line=$line::public-hygiene rule '$2' matched"
  else
    echo "HYGIENE $1 rule=$2"
  fi
}

run_rules() {
  local name ere allow line loc text tok kept
  while IFS="$tab" read -r name ere allow; do
    [ -n "$ere" ] || continue
    while IFS= read -r line; do
      loc="${line%%$us*}"; text="${line#*$us}"
      kept=0
      while IFS= read -r tok; do
        tok="$(printf '%s' "$tok" | sed -E 's/^[^A-Za-z0-9\/]//; s/[^A-Za-z0-9._@\/+=:-]*$//')"
        [ -n "$tok" ] || continue
        if [ -n "$allow" ] && printf '%s' "$tok" | grep -Eq -- "$allow"; then continue; fi
        kept=1; break
      done < <(printf '%s\n' "$text" | grep -Eo -- "$ere" || true)
      [ "$kept" = 1 ] && report "$loc" "$name"
    done < <(grep -E -- "$ere" "$stream" || true)
  done < "$rules.r"
}

run_hashes() {
  [ -n "${PUBLIC_HYGIENE_EXTRA_SHA256:-}" ] || return 0
  local sum tok h; sum() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
  while IFS= read -r tok; do
    h="$(printf '%s' "$tok" | sum | cut -d' ' -f1)"
    if printf '%s\n' "$PUBLIC_HYGIENE_EXTRA_SHA256" | tr -s ' \t' '\n\n' | grep -qxF "$h"; then
      while IFS= read -r loc; do report "$loc" "listed-token"; done \
        < <(awk -v us="$us" -v t="$tok" '{ i = index($0, us); if (index(tolower(substr($0, i + 1)), t)) print substr($0, 1, i - 1) }' "$stream")
    fi
  done < <(sed "s/^[^${us}]*${us}//" "$stream" | grep -Eo '[A-Za-z0-9][A-Za-z0-9._-]{2,40}' | tr 'A-Z' 'a-z' | sort -u)
}

case "$mode" in
diff)
  base="${1:-origin/main}"; head="${2:-HEAD}"
  # added lines with file:line locations (rename-aware, binary files are skipped by git)
  git diff --unified=0 --no-color --diff-filter=AMR "$base...$head" -- . \
      ':!scripts/check-public-hygiene.sh' ':!scripts/public-hygiene.patterns' \
      ':!scripts/tests/test-public-hygiene.sh' |
    awk -v us="$us" '
      /^\+\+\+ /{f=substr($0,7); next}
      /^@@/{match($0,/\+[0-9]+/); n=substr($0,RSTART+1,RLENGTH-1)+0; next}
      /^\+/{ if (index($0,"public-hygiene: allow")==0) print f ":" n us substr($0,2); n++ }' >> "$stream"
  # commit messages: location is commit:line
  for c in $(git rev-list "$base..$head"); do
    git log -1 --format=%B "$c" | add_text "commit-$(git rev-parse --short "$c")"
    git log -1 --format='%ae%n%ce' "$c" | sort -u | while IFS= read -r e; do
      printf '%s' "$e" | grep -Eq -- "$author_allow" || { echo "HYGIENE commit-$(git rev-parse --short "$c") rule=author-email"; echo x >> "$work/authorhit"; }
    done
  done
  [ -n "${PR_TITLE:-}" ] && printf '%s\n' "$PR_TITLE" | add_text "pr-title"
  [ -n "${PR_BODY:-}" ] && printf '%s\n' "$PR_BODY" | tr -d '\r' | add_text "pr-body"
  [ -n "${PR_HEAD_REF:-}" ] && printf '%s\n' "$PR_HEAD_REF" | add_text "pr-branch"
  run_rules; run_hashes
  [ -f "$work/authorhit" ] && hits=$((hits + $(wc -l < "$work/authorhit")))
  if [ "$hits" -gt 0 ]; then echo "public-hygiene: $hits finding(s); values are not printed. Fix the text, or mark a deliberate line with 'public-hygiene: allow'." >&2; exit 1; fi
  echo "public-hygiene: clean (diff $base...$head)"
  ;;
scan)
  git ls-files -z -- . ':!scripts/check-public-hygiene.sh' ':!scripts/public-hygiene.patterns' \
      ':!scripts/tests/test-public-hygiene.sh' |
    while IFS= read -r -d '' f; do
      grep -Iq . -- "$f" 2>/dev/null || continue
      add_text "$f" < "$f"
    done
  run_rules; run_hashes
  echo "public-hygiene scan: $hits finding(s) (report only)"
  ;;
*) echo "usage: $0 diff [BASE [HEAD]] | scan" >&2; exit 2 ;;
esac
