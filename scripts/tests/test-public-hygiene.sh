#!/usr/bin/env bash
# Regression test for scripts/check-public-hygiene.sh: diff mode must go red on added
# internal-looking text (line, commit message, PR text, author email), stay green on
# clean additions and untouched legacy lines, and never print a matched value.
set -euo pipefail
script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/check-public-hygiene.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main . && git config user.name t && git config user.email scimbe@gmail.com
legacy="see ticket ""ABC-20260101-001 for history"       # pre-existing, must stay untouched
printf '%s\n' "$legacy" > doc.md; git add doc.md; git commit -qm base
base="$(git rev-parse HEAD)"

fail() { echo "FAIL: $*" >&2; exit 1; }
# The plain "HYGIENE loc rule=NAME" form is what the cases below read, so GITHUB_ACTIONS (set on CI
# runners, switches the output to workflow annotations) is removed; case 2b covers the annotation form.
run() { env -u GITHUB_ACTIONS bash "$script" diff "$base" HEAD 2>&1; }

# 1. clean change -> green, legacy line is not re-reported
git checkout -q -b clean; echo "plain text, mail scimbe@gmail.com, see user@example.org" >> doc.md
git commit -qam "Add notes"
out="$(run)" || fail "clean change went red: $out"

# 2. added bad lines -> red, location named, value never printed
git checkout -q -b bad "$base"
{ echo "ref ""XYZ-20261231-042"; echo "path ""/Users/""someone""/work"; echo "mail ""ops""@""corp-internal.example.io"
  echo "key ""ghp""_""abcdefghijklmnopqrstuvwxyz0123456789"; echo "skip ""ABC-20260101-009 public-hygiene: allow"; } >> doc.md
git commit -qam "Add bad lines"
set +e; out="$(run)"; rc=$?; set -e
[ "$rc" = 1 ] || fail "bad lines did not go red (rc=$rc)"
for r in tracker-id mac-home email secret-token; do echo "$out" | grep -q "rule=$r" || fail "missing rule $r"; done
echo "$out" | grep -q "doc.md:1 " && fail "legacy line reported"
echo "$out" | grep -q "20261231\|someone\|corp-internal\|abcdefgh" && fail "a matched value was printed"
# lines 2-5 are the bad ones, line 6 carries the allow marker
for l in 2 3 4 5; do echo "$out" | grep -q "doc.md:$l " || fail "bad line $l not reported"; done
echo "$out" | grep -q "doc.md:6 " && fail "allow-marked line reported"

# 2b. under GITHUB_ACTIONS the same findings come as annotations with file and line, still no value
out="$(GITHUB_ACTIONS=1 bash "$script" diff "$base" HEAD 2>&1)" && fail "annotation run did not go red"
echo "$out" | grep -qF "::error file=doc.md,line=2::public-hygiene rule 'tracker-id' matched" || fail "missing annotation for line 2"
echo "$out" | grep -q "::error file=doc.md,line=6" && fail "allow-marked line annotated"
echo "$out" | grep -q "20261231\|someone\|corp-internal\|abcdefgh" && fail "a matched value was printed in an annotation"

# 3. bad commit message, author email and PR text on an otherwise clean diff -> red
git checkout -q -b meta "$base"; echo more >> doc.md
git -c user.email="bot@host.vps.example.net" commit -qam "Fix thing for XYZ-20261231-042"
set +e; out="$(PR_TITLE='ok' PR_BODY='Cads task task-0123456789ABCDEFGHJKMNPQRS' run)"; rc=$?; set -e
[ "$rc" = 1 ] || fail "meta text did not go red"
for r in author-email tracker-id task-handle; do echo "$out" | grep -q "rule=$r" || fail "missing meta rule $r"; done

# 4. extra hash list (kept outside the repo) is honoured
git checkout -q -b hashed "$base"; echo "host zzinternalhost here" >> doc.md
echo "plain" > zzinternalhost-notes.md; git add zzinternalhost-notes.md; git commit -qam "Add host"
h="$(printf '%s' zzinternalhost | (sha256sum 2>/dev/null || shasum -a 256) | cut -d' ' -f1)"
set +e; out="$(PUBLIC_HYGIENE_EXTRA_SHA256="$h" run)"; rc=$?; set -e
[ "$rc" = 1 ] && echo "$out" | grep -q "rule=listed-token" || fail "hash list not honoured"
echo "$out" | grep -q zzinternalhost && fail "hashed token printed (or matched in a file path)"
echo "$out" | grep -q "doc.md:2 rule=listed-token" || fail "listed token not located in the text line"
echo "ok"
