#!/usr/bin/env bash
# Regression test for scripts/quickstart.sh. `ct-agent`, `curl` and `setup.sh` are stubs on PATH
# that record argv (and, for curl, stdin) -- no network, no real login, no daemon.
# Covers: defaults and --yes, resume (keys and grants reused), 409 on member add, a refused
# register, a missing token, secrets never in argv or output, 0600 on secret files, the --clean
# guard, and the pasted-block round trip for the multi-machine form.
#
#   bash scripts/tests/test-quickstart-sh.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
QS="$ROOT/scripts/quickstart.sh"
fail=0
pass() { echo "ok: $1"; }
bad()  { echo "FAIL: $1" >&2; fail=1; }
check() { # description, command...
  local d="$1" neg=0; shift
  [ "$1" != "!" ] || { neg=1; shift; }
  if "$@"; then [ "$neg" -eq 0 ] && pass "$d" || bad "$d"; else [ "$neg" -eq 1 ] && pass "$d" || bad "$d"; fi
}
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"
SECRET_TOKEN="TESTBEARER-s3cr3t-value"
SECRET_BOOT="TESTBOOT-s3cr3t-value"

sha() { shasum -a 256 2>/dev/null || sha256sum; }
export -f sha 2>/dev/null || true

cat > "$BIN/ct-agent" <<'STUB'
#!/usr/bin/env bash
echo "ct-agent $*" >> "$STUB_LOG"
rnd() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
hash() { { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-64; }
case "$1 $2" in
  "channel operator-init")
    echo "# operator"; echo "#   operator_pubkey = $(rnd 32)"; echo "export CT_CHANNEL_OPERATOR_KEY=$(rnd 32)" ;;
  "channel init")
    echo "export CT_CHANNEL_HOLDER_PUBKEY=$(rnd 32)"; echo "export CT_CHANNEL_NOISE_PUBKEY=$(rnd 32)"
    echo "export CT_CHANNEL_HOLDER_KEY=$(rnd 32)"; echo "export CT_CHANNEL_NOISE_KEY=$(rnd 32)" ;;
  "channel member-material")
    own="$(printf '%s' "$CT_CHANNEL_HOLDER_KEY" | hash)"
    # the holder pubkey of the stub is the one recorded by `channel init`; the test passes it in
    pub="${CT_CHANNEL_HOLDER_PUBKEY}"
    ch="$(printf '%s\n%s\n' "$pub" "$CT_CHANNEL_BRIDGE_HOLDER" | sort | hash)"
    echo "holder_pubkey     = $pub"; echo "noise_pubkey      = $CT_CHANNEL_NOISE_PUBKEY"
    echo "channel_id        = $ch"; echo "noise_attestation = $(rnd 64)" ;;
  "channel grant")
    echo "$(rnd 40)" ;;
  "channel register")
    echo "register id=${CT_CHANNEL_ID:-} rekey=${3:-no}" >> "$STUB_LOG"
    if [ -n "${STUB_REGISTER_FAIL:-}" ]; then echo "ct-agent channel register: control plane answered 409: $STUB_REGISTER_FAIL" >&2; exit 1; fi
    echo "registered channel ${CT_CHANNEL_ID:-} with the control plane" >&2 ;;
  "channel "*|"channel ")
    # run: accept waits for the initiator's line on a shared file; initiate drops its stdin there
    echo "run role=${CT_CHANNEL_ROLE:-} serve=${CT_CHANNEL_SERVE:-} allow=${CT_CHANNEL_FORWARD_ALLOW:-} fwd=${CT_CHANNEL_FORWARD:-} front=${CT_CHANNEL_FRONT_DOOR:-}" >> "$STUB_LOG"
    if [ -n "${CT_CHANNEL_FORWARD:-}" ]; then echo "CT_CHANNEL_FORWARD ${CT_CHANNEL_FORWARD%%=*} -> ${CT_CHANNEL_FORWARD#*=}"; sleep 30; exit 0; fi
    if [ "${CT_CHANNEL_SERVE:-}" = 1 ]; then sleep 30; exit 0; fi
    case "${CT_CHANNEL_ROLE:-}" in
      accept)   i=0; while [ ! -s "$STUB_BUS" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; cat "$STUB_BUS"; sleep 30 ;;
      initiate) cat > "$STUB_BUS" ;;
    esac ;;
  "login "*|"login ")
    mkdir -p "$HOME/.ct-agent"; echo "{\"access_token\":\"$STUB_TOKEN\"}" > "$HOME/.ct-agent/oidc-token.json" ;;
  *) echo "stub ct-agent: unexpected: $*" >&2; exit 2 ;;
esac
STUB
# `channel` with only the subcommand: the stub's case sees "channel " -- normalise.
sed -i.bak 's/^case "\$1 \$2" in/case "$1 ${2:-}" in/' "$BIN/ct-agent"; rm -f "$BIN/ct-agent.bak"

cat > "$BIN/curl" <<'STUB'
#!/usr/bin/env bash
echo "curl $*" >> "$STUB_LOG"
out=""; wfmt=""; url=""; cfg=0; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a" ;; -w) wfmt="$a" ;; --config) [ "$a" = "-" ] && cfg=1 ;; esac
  case "$a" in http*://*) url="$a" ;; esac
  prev="$a"
done
[ "$cfg" = 1 ] && cat >> "$STUB_CURL_STDIN"
[ -t 0 ] || [ "$cfg" = 1 ] || cat >> "$STUB_CURL_STDIN"
code=200; body=""
case "$url" in
  */network-info)     body='{"channel_broker_port": 7001, "channel_relay_port": 7002, "channel_relay_gate_port": 443}' ;;
  */pki/ca)           printf '\001\002\003' ;;
  */bootstrap/redeem) body="{\"secret\":\"CT_JOIN_TOKEN=joinsecret123;CT_AGENT_TOKEN=agentsecret456\"}" ;;
  */members)          code="${STUB_MEMBER_CODE:-201}" ;;
  https://*)          code=200 ;;
esac
[ -z "$out" ] || printf '%s' "$body" > "$out"
if [ -n "$wfmt" ]; then printf '%s' "$code"; elif [ -n "$body" ]; then printf '%s' "$body"; fi
exit 0
STUB

cat > "$BIN/setup.sh" <<'STUB'
#!/usr/bin/env bash
echo "setup.sh $*" >> "$STUB_LOG"
. ./.env 2>/dev/null
echo "token is $CT_AGENT_TOKEN"
( sleep 120 ) >/dev/null 2>&1 & echo $! > ct-agent.pid
echo "done — current tier: gelb"
STUB
chmod +x "$BIN"/*

run_qs() { # workdir, then args; env comes from the caller via E=(...)
  local wd="$1"; shift
  env -i PATH="$BIN:$PATH" HOME="$T/home" STUB_LOG="$T/stub.log" STUB_BUS="$T/bus" STUB_CURL_STDIN="$T/curl.stdin" \
    STUB_TOKEN="$SECRET_TOKEN" CT_QS_SETUP_SH="$BIN/setup.sh" CT_QS_WORKDIR="$wd" CT_QS_A_HEAD_START=1 CT_QS_WAIT=20 \
    "${E[@]}" bash "$QS" "$@"
}
reset() { rm -rf "$T/home" "$T/stub.log" "$T/bus" "$T/curl.stdin"; mkdir -p "$T/home"; : > "$T/stub.log"; : > "$T/curl.stdin"; E=(); }

# The stub's member-material needs the holder pubkey from `channel init`; the script sources member.env for it,
# which the stub reads as CT_CHANNEL_HOLDER_PUBKEY (exported by the block) -- nothing to do here.

# ---- 1. channel on one machine: defaults, --yes, permissions, no secret in argv or output -----------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
out1="$(run_qs "$T/w1" channel --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || echo "$out1" | tail -12 >&2
check "channel --yes exits 0" [ "$rc" -eq 0 ]
check "channel reports RESULT: OK" grep -q 'RESULT: OK' <<<"$out1"
check "the test line reached member A" grep -q 'hello from B' "$T/w1/received.txt"
check "default control plane used" grep -q 'CT_AGENT_CP_URL\|bunsenbrenner.org/network-info' "$T/stub.log"
check "edge values were fetched, not asked" grep -q 'network-info' "$T/stub.log"
check "both members were added" [ "$(grep -c '/members' "$T/stub.log")" -eq 2 ]
check "login was found, no new sign-in" ! grep -q '^ct-agent login' "$T/stub.log"
for f in "$T/w1/operator.env" "$T/w1/accept/member.env" "$T/w1/initiate/member.env" "$T/w1/grants/accept.grant"; do
  check "mode 0600: ${f#$T/}" [ "$(mode "$f")" = 600 ]
done
check "bearer token not in any argv" ! grep -q "$SECRET_TOKEN" "$T/stub.log"
check "bearer token not in the output" ! grep -q "$SECRET_TOKEN" <<<"$out1"
check "bearer token travelled through curl's stdin" grep -q "Authorization: Bearer $SECRET_TOKEN" "$T/curl.stdin"
pkill -f "sleep 30" 2>/dev/null || true

# ---- 2. resume: second run reuses keys and grants; 409 on member add is fine ------------------------
n_before="$(grep -c 'channel operator-init' "$T/stub.log")"
g_before="$(grep -c 'channel grant' "$T/stub.log")"
rm -f "$T/bus"
E=(STUB_MEMBER_CODE=409)
out2="$(run_qs "$T/w1" channel --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || echo "$out2" | tail -12 >&2
check "resume exits 0" [ "$rc" -eq 0 ]
check "resume did not mint a second operator key" [ "$(grep -c 'channel operator-init' "$T/stub.log")" -eq "$n_before" ]
check "resume did not sign new grants" [ "$(grep -c 'channel grant' "$T/stub.log")" -eq "$g_before" ]
check "409 on member add is reported as already added" grep -q 'already added (409)' <<<"$out2"
check "resume says it reuses the key" grep -q 'reusing it' <<<"$out2"
pkill -f "sleep 30" 2>/dev/null || true

# ---- 2b. ssh-channel: forward settings, the warning, the finished ssh line ------------------------------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=(CT_QS_SSH_USER=tester)
out2b="$(run_qs "$T/w2b" ssh-channel --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || echo "$out2b" | tail -12 >&2
check "ssh-channel --yes exits 0" [ "$rc" -eq 0 ]
check "the accepting side serves with forward allowed to 127.0.0.1:22" grep -q 'run role=accept serve=1 allow=127.0.0.1:22' "$T/stub.log"
check "the initiating side forwards 2222 to 22" grep -q 'run role=initiate .*fwd=127.0.0.1:2222=127.0.0.1:22' "$T/stub.log"
check "the front door is the :443 door" grep -q 'front=bunsenbrenner.org:443' "$T/stub.log"
check "the forward warning stays visible and points to channel.md" grep -q 'docs/channel.md' <<<"$out2b"
check "the warning does not state a measured duration" ! grep -q 'seconds' <<<"$out2b"
check "the finished ssh line is printed" grep -q 'ssh -p 2222 .*tester@127.0.0.1' <<<"$out2b"
run_qs "$T/w2b" --clean --yes >/dev/null 2>&1
pkill -f "sleep 30" 2>/dev/null || true

# ---- 3. a refused register names the failed stage and the next action ----------------------------------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=(STUB_REGISTER_FAIL=other-operator)
out3="$(run_qs "$T/w3" channel --yes 2>&1)"; rc=$?
check "refused register exits non-zero" [ "$rc" -ne 0 ]
check "failed stage is named" grep -q "FAILED.*register the channel" <<<"$out3"
check "next action mentions --rekey" grep -q -- '--rekey' <<<"$out3"
check "nothing was added after the failed register" ! grep -q '/members' "$T/stub.log"

# ---- 4. tunnel: missing token, then the full path ----------------------------------------------------------
reset
E=(CT_AGENT_HOSTNAME=demo.example.test)
out4="$(run_qs "$T/w4" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "tunnel without a token exits non-zero" [ "$rc" -ne 0 ]
check "the message names CT_BOOTSTRAP" grep -q 'CT_BOOTSTRAP' <<<"$out4"
check "no .env was written without a token" [ ! -e "$T/w4/.env" ]

reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9)
out5="$(run_qs "$T/w5" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "tunnel --yes exits 0" [ "$rc" -eq 0 ]
check "tunnel reports the tier" grep -q 'tier: gelb' <<<"$out5"
check "tunnel .env is mode 0600" [ "$(mode "$T/w5/.env")" = 600 ]
check "setup.sh was called with --yes" grep -q '^setup.sh --yes' "$T/stub.log"
check "bootstrap token not in any argv" ! grep -q "$SECRET_BOOT" "$T/stub.log"
check "bootstrap token not in the output" ! grep -q "$SECRET_BOOT" <<<"$out5"
check "routing token from setup.sh output is redacted" ! grep -q 'agentsecret456' <<<"$out5"
check "routing token is redacted in setup.log too" ! grep -q 'agentsecret456' "$T/w5/logs/setup.log"
pkill -f "sleep 120" 2>/dev/null || true

# rerun reuses .env and does not redeem again
n="$(grep -c 'bootstrap/redeem' "$T/stub.log")"
out6="$(run_qs "$T/w5" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "tunnel rerun exits 0" [ "$rc" -eq 0 ]
check "tunnel rerun reuses .env" grep -q '.env found' <<<"$out6"
check "tunnel rerun did not redeem again" [ "$(grep -c 'bootstrap/redeem' "$T/stub.log")" -eq "$n" ]
pkill -f "sleep 120" 2>/dev/null || true

# ---- 5. --clean only touches the script's own directory ---------------------------------------------------------
reset
mkdir -p "$T/foreign"; echo keep > "$T/foreign/file"
E=()
run_qs "$T/foreign" --clean --yes >/dev/null 2>&1; rc=$?
check "--clean refuses a directory without the marker" [ "$rc" -ne 0 ]
check "the foreign directory is untouched" [ -f "$T/foreign/file" ]
run_qs "$T/w5" --clean --yes >/dev/null 2>&1; rc=$?
check "--clean removes its own directory" [ "$rc" -eq 0 ] && [ ! -e "$T/w5" ]

# a foreign, non-empty directory is refused as a working directory
mkdir -p "$T/foreign2"; echo keep > "$T/foreign2/file"
E=()
outf="$(run_qs "$T/foreign2" channel --yes 2>&1)"; rc=$?
check "a foreign non-empty directory is refused as workdir" [ "$rc" -ne 0 ]
check "the refusal says why" grep -q 'not empty and was not created by this script' <<<"$outf"
check "no marker was written into the foreign directory" [ ! -e "$T/foreign2/.ct-quickstart" ]
check "the foreign file is untouched after the refusal" [ -f "$T/foreign2/file" ]
# --clean removes only known files; a foreign file in the workdir survives and so does the directory
mkdir -p "$T/w7"; E=()
run_qs "$T/w7" tunnel --yes >/dev/null 2>&1 || true   # creates the workdir and marker, fails at the missing token
echo mine > "$T/w7/my-notes.txt"
sleep 100 & spid=$!; echo "$spid" > "$T/w7/run/other.pid"
run_qs "$T/w7" --clean --yes >/dev/null 2>&1; rc=$?
check "--clean succeeds" [ "$rc" -eq 0 ]
check "a foreign file in the workdir survives --clean" [ -f "$T/w7/my-notes.txt" ]
check "the script's own marker is gone" [ ! -e "$T/w7/.ct-quickstart" ]
check "a recycled pid of a foreign process is not killed" kill -0 "$spid"
kill "$spid" 2>/dev/null

# a bootstrap token with odd characters is refused before it is sent
reset
E=(CT_AGENT_HOSTNAME=demo.example.test 'CT_BOOTSTRAP=ab"cd' CT_AGENT_ORIGIN=127.0.0.1:9)
outb="$(run_qs "$T/w8" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "a bootstrap token with a quote is refused" [ "$rc" -ne 0 ]
check "it was not sent to the control plane" ! grep -q 'bootstrap/redeem' "$T/stub.log"

# ---- 6. several machines: the pasted-block round trip -----------------------------------------------------------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=()
blk() { sed -n 's/^\(ctq1 .*\)$/\1/p'; }
op1="$(run_qs "$T/op" channel --role operator --yes 2>&1 || true)"
echo "$op1" | blk > "$T/op-block.txt"
check "operator prints its block" grep -q '^ctq1 operator pubkey ' "$T/op-block.txt"
ha="$(E=(CT_QS_SIDE=accept); run_qs "$T/ma" channel --role member --yes 2>&1 || true)"
hb="$(E=(CT_QS_SIDE=initiate); run_qs "$T/mb" channel --role member --yes 2>&1 || true)"
echo "$ha" | blk > "$T/ha.txt"; echo "$hb" | blk > "$T/hb.txt"
check "accept member prints holder and noise" [ "$(grep -c '^ctq1 accept ' "$T/ha.txt")" -eq 2 ]
cat "$T/op-block.txt" "$T/hb.txt" > "$T/in-a.txt"; cat "$T/op-block.txt" "$T/ha.txt" > "$T/in-b.txt"
ma="$(E=(CT_QS_SIDE=accept); run_qs "$T/ma" channel --role member --yes --inbox "$T/in-a.txt" 2>&1 || true)"
mb="$(E=(CT_QS_SIDE=initiate); run_qs "$T/mb" channel --role member --yes --inbox "$T/in-b.txt" 2>&1 || true)"
echo "$ma" | blk > "$T/ma.txt"; echo "$mb" | blk > "$T/mb.txt"
check "members print a material block with a channel id" grep -q '^ctq1 accept channel ' "$T/ma.txt"
check "both members derived the same channel id" [ "$(grep '^ctq1 accept channel' "$T/ma.txt" | awk '{print $4}')" = "$(grep '^ctq1 initiate channel' "$T/mb.txt" | awk '{print $4}')" ]
cat "$T/ma.txt" "$T/mb.txt" | grep -E ' (channel|holder|noise|attest) ' > "$T/op-in.txt"
op2="$(run_qs "$T/op" channel --role operator --yes --inbox "$T/op-in.txt" 2>&1)"; rc=$?
check "operator finishes once both material blocks are in" [ "$rc" -eq 0 ]
check "operator added both members" [ "$(grep -c '/members' "$T/stub.log")" -eq 2 ]
echo "$op2" | blk | grep ' grant ' > "$T/grants.txt"
check "operator prints one grant per side" [ "$(wc -l < "$T/grants.txt" | tr -d ' ')" -eq 2 ]
check "bearer token not in the multi-machine output" ! grep -q "$SECRET_TOKEN" <<<"$op2$ma$mb"
cat "$T/in-b.txt" "$T/grants.txt" > "$T/in-b2.txt"
rm -f "$T/bus"; echo "from the other machine" > "$T/bus"
mb2="$(E=(CT_QS_SIDE=initiate); run_qs "$T/mb" channel --role member --yes --inbox "$T/in-b2.txt" 2>&1)"; rc=$?
check "initiating member sends its line with the pasted grant" [ "$rc" -eq 0 ]
check "the pasted grant landed in a 0600 file" [ "$(mode "$T/mb/grants/initiate.grant")" = 600 ]
echo "ctq1 accept holder abcd" > "$T/bad.txt"
badout="$(E=(CT_QS_SIDE=accept); run_qs "$T/mbad" channel --role member --yes --inbox "$T/bad.txt" 2>&1 || true)"
check "a pasted line with the wrong hex length is ignored with a warning" grep -q 'expected 64 hex characters' <<<"$badout"

echo
if [ "$fail" -eq 0 ]; then echo "all quickstart.sh checks passed"; else echo "quickstart.sh checks FAILED" >&2; fi
exit "$fail"
