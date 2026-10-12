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

# A failed check is counted, not fatal, so one run lists every broken case.
failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
# The plain "HYGIENE loc rule=NAME" form is what the cases below read, so GITHUB_ACTIONS (set on CI
# runners, switches the output to workflow annotations) is removed; case 2b covers the annotation form.
run() { env -u GITHUB_ACTIONS bash "$script" diff "$base" HEAD 2>&1; }

# 1. clean change -> green, legacy line is not re-reported
git checkout -q -b clean; echo "plain text, mail scimbe@gmail.com, see user@example.org" >> doc.md
git commit -qam "Add notes"
out="$(run)" || fail "clean change went red: $out"
echo "$out" | grep -q "extra rules: not available" || fail "missing notice that the extra rules were not available"

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

# 5. an added line that starts with "++ " is not taken for a "+++" file header (B1)
git checkout -q -b plusplus "$base"; echo "++ ref ""XYZ-20261231-077" >> doc.md; git commit -qam "Add line"
set +e; out="$(run)"; rc=$?; set -e
[ "$rc" = 1 ] && echo "$out" | grep -q "doc.md:2 rule=tracker-id" || fail "'++ ' line slipped through (rc=$rc)"

# 6. the tracker-id allow list covers only the short number form (B2)
git checkout -q -b allowlist "$base"
{ echo "see RFC-9298 and ADR-0002 and CVE-2024-12345"; echo "bad ""SEC-20261231-042"; echo "bad ""ADR-20261231"; } >> doc.md
git commit -qam "Add refs"
set +e; out="$(run)"; rc=$?; set -e
[ "$rc" = 1 ] || fail "long id behind an allowed prefix passed (rc=$rc)"
echo "$out" | grep -q "doc.md:2 " && fail "short allowed reference was reported"
for l in 3 4; do echo "$out" | grep -q "doc.md:$l rule=tracker-id" || fail "long id on line $l not reported"; done

# 7. file names (added, renamed) and author/committer names are checked (M1)
git checkout -q -b names "$base"; echo plain > "XYZ-20261231-055.md"; git add . ; git commit -qm "Add file"
git mv doc.md "XYZ-20261231-056.md"; git -c user.name="XYZ-20261231-057" commit -qm "Rename"
set +e; out="$(run)"; rc=$?; set -e
[ "$rc" = 1 ] || fail "bad names went green"
[ "$(echo "$out" | grep -c '^HYGIENE path:[0-9]* rule=tracker-id')" = 2 ] || fail "added and renamed file names not both reported: $out"
echo "$out" | grep -q "^HYGIENE commit-[0-9a-f]*:author:[0-9]* rule=tracker-id" || fail "author name not reported"
echo "$out" | grep -q "20261231" && fail "a name was printed"

# 8. rules that do not parse stop the run with exit 2 and name the rule number, never its text (M3)
git checkout -q -b rules "$base"; echo more >> doc.md; git commit -qam "More"
for bad in $'badre\tzzbadre[\t' $'zznotab'; do
  set +e; out="$(PUBLIC_HYGIENE_EXTRA_PATTERNS="$bad" run)"; rc=$?; set -e
  [ "$rc" = 2 ] || fail "broken extra rule did not stop the run (rc=$rc)"
  echo "$out" | grep -q "rule #[0-9]" || fail "broken rule not named by number"
  echo "$out" | grep -q "zzbadre\|zznotab" && fail "rule text printed"
done

# 9. a last rule whose only match is allowed must not end the run silently (M4)
git checkout -q -b lastallowed "$base"; echo "zzq1" >> doc.md; git commit -qam "Add zzq1"
set +e; out="$(PUBLIC_HYGIENE_EXTRA_PATTERNS=$'zzrule\tzzq[0-9]+\t^zzq1$' run)"; rc=$?; set -e
[ "$rc" = 0 ] && echo "$out" | grep -q "public-hygiene: clean" || fail "allowed last match ended the run (rc=$rc): $out"

# 10. many tokens are hashed in one pass, and a listed one is still found (M5)
git checkout -q -b manytokens "$base"
awk 'BEGIN { for (i = 0; i < 250; i++) { l = ""; for (j = 0; j < 20; j++) l = l sprintf("tok%05d ", i * 20 + j); print l }; print "zzlisted here" }' >> doc.md
git commit -qam "Add many tokens"
h="$(printf '%s' zzlisted | (sha256sum 2>/dev/null || shasum -a 256) | cut -d' ' -f1)"
start=$SECONDS; set +e; out="$(PUBLIC_HYGIENE_EXTRA_SHA256="$h" run)"; rc=$?; set -e
[ $((SECONDS - start)) -lt 10 ] || fail "hashing 5000 tokens took $((SECONDS - start)) s"
[ "$rc" = 1 ] && echo "$out" | grep -q "doc.md:252 rule=listed-token" || fail "listed token among many not found (rc=$rc)"

# 11. scp-style git remotes are fine (N1)
git checkout -q -b scp "$base"; echo "git clone git@github.com:owner/repo.git" >> doc.md; git commit -qam "Add clone hint"
out="$(run)" || fail "scp-style remote went red: $out"

# 12. annotations only for plain paths; others fall back to the plain form (N2)
git checkout -q -b oddname "$base"; echo "ref ""XYZ-20261231-088" > "a,b.md"; git add . ; git commit -qm "Add odd name"
set +e; out="$(GITHUB_ACTIONS=1 bash "$script" diff "$base" HEAD 2>&1)"; rc=$?; set -e
[ "$rc" = 1 ] || fail "odd file name went green"
echo "$out" | grep -q "::error file=a,b" && fail "annotation written for an unsafe file name"
echo "$out" | grep -q "^HYGIENE a,b.md:1 rule=tracker-id" || fail "plain form missing for the odd file name"

[ "$failures" = 0 ] || { echo "$failures check(s) failed" >&2; exit 1; }
echo "ok"
