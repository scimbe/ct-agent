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

T="$(mktemp -d)"
# Long-running stub processes record their pid here; the test kills exactly those, never by name.
PIDS="$T/stub.pids"; : > "$PIDS"
killrec() { local p; while read -r p; do [ -z "$p" ] || kill "$p" 2>/dev/null || true; done < "$PIDS"; : > "$PIDS"; }
trap 'killrec; rm -rf "$T"' EXIT
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
    if [ -n "${CT_CHANNEL_FORWARD:-}" ] || [ "${CT_CHANNEL_SERVE:-}" = 1 ]; then
      # a forward session checks the peer's grant against the operator key: without it the real agent refuses
      echo "opk=${CT_CHANNEL_OPERATOR_PUBKEY:-}" >> "$STUB_LOG"
      case "${CT_CHANNEL_OPERATOR_PUBKEY:-}" in
        ""|*[!0-9a-f]*) echo "ct-agent channel: peer's grant must be checked ... CT_CHANNEL_OPERATOR_PUBKEY is not a 64-hex value" >&2; exit 1 ;;
      esac
    fi
    if [ -n "${CT_CHANNEL_FORWARD:-}" ]; then
      echo "CT_CHANNEL_FORWARD ${CT_CHANNEL_FORWARD%%=*} -> ${CT_CHANNEL_FORWARD#*=}"
      fp="${CT_CHANNEL_FORWARD%%=*}"; fp="${fp##*:}"
      if [ -n "${STUB_REJECT_SESSION:-}" ]; then
        echo "ct-agent channel: forward session refused: stub peer rejected the grant" >&2
        python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(5)
while True:
    c,_=s.accept(); c.close()' "$fp" &
      else
        python3 -c 'import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(5)
while True:
    c,_=s.accept(); c.sendall(b"SSH-2.0-stub\r\n"); c.close()' "$fp" &
      fi
      echo $! >> "$STUB_PIDS"; echo $$ >> "$STUB_PIDS"; exec sleep 30
    fi
    if [ "${CT_CHANNEL_SERVE:-}" = 1 ]; then echo $$ >> "$STUB_PIDS"; exec sleep 30; fi
    case "${CT_CHANNEL_ROLE:-}" in
      accept)   i=0; while [ ! -s "$STUB_BUS" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; cat "$STUB_BUS"; echo $$ >> "$STUB_PIDS"; exec sleep 30 ;;
      initiate) cat > "$STUB_BUS" ;;
    esac ;;
  "ssh-owner init") echo "ownerkey-$(rnd 16)" ;;
  "ssh-config "*)   echo "# ct-agent ssh"; echo "Host $2"; echo "  ProxyCommand ct-agent ssh $2 --owner-key-file k"; echo "  User tester" ;;
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
  */bootstrap/redeem) body="{\"secret\":\"CT_JOIN_TOKEN=joinsecret123;CT_AGENT_TOKEN=${STUB_EVIL_TOKEN:-agentsecret456}\"}" ;;
esac
case "$url" in
  */bootstrap/redeem) [ -z "${STUB_EMPTY_SECRET:-}" ] || body='{"secret":""}' ;;
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
# like the real setup.sh: a CT_BOOTSTRAP in the environment is redeemed here (single use)
[ -z "${CT_BOOTSTRAP:-}" ] || echo "setup-redeems-bootstrap" >> "$STUB_LOG"
set -a; . ./.env 2>/dev/null; set +a
echo "token is $CT_AGENT_TOKEN"
echo "cert-dir is ${CT_ACME_CERT_OUT_DIR:-none}" >> "$STUB_LOG"
sleep 120 >/dev/null 2>&1 & echo $! > ct-agent.pid; echo $! >> "$STUB_PIDS"
echo "done — current tier: gelb"
STUB
chmod +x "$BIN"/*

run_qs() { # workdir, then args; env comes from the caller via E=(...)
  local wd="$1"; shift
  env -i PATH="$BIN:$PATH" HOME="$T/home" STUB_LOG="$T/stub.log" STUB_PIDS="$PIDS" STUB_BUS="$T/bus" STUB_CURL_STDIN="$T/curl.stdin" \
    STUB_TOKEN="$SECRET_TOKEN" CT_QS_SETUP_SH="$BIN/setup.sh" CT_QS_WORKDIR="$wd" CT_QS_A_HEAD_START=1 CT_QS_WAIT=20 \
    "${E[@]}" bash "$QS" "$@" </dev/null
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
killrec

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
killrec

# ---- 2b. ssh-channel: forward settings, the warning, the finished ssh line ------------------------------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=(CT_QS_SSH_USER=tester)
out2a="$(run_qs "$T/w2a" ssh-channel --yes 2>&1)"; rc=$?
check "ssh-channel --yes alone does not turn the forward on" [ "$rc" -ne 0 ]
check "the refusal names --enable-forward" grep -q -- '--enable-forward' <<<"$out2a"
check "no forward listener was started without the switch" ! grep -q 'fwd=127' "$T/stub.log"
out2b="$(run_qs "$T/w2b" ssh-channel --yes --enable-forward 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || echo "$out2b" | tail -12 >&2
check "ssh-channel --yes exits 0" [ "$rc" -eq 0 ]
check "the accepting side serves with forward allowed to 127.0.0.1:22" grep -q 'run role=accept serve=1 allow=127.0.0.1:22' "$T/stub.log"
check "the initiating side forwards 2222 to 22" grep -q 'run role=initiate .*fwd=127.0.0.1:2222=127.0.0.1:22' "$T/stub.log"
check "the front door is the :443 door" grep -q 'front=bunsenbrenner.org:443' "$T/stub.log"
check "the forward warning stays visible and points to channel.md" grep -q 'docs/channel.md' <<<"$out2b"
check "the warning does not state a measured duration" ! grep -q 'seconds' <<<"$out2b"
check "the finished ssh line is printed" grep -q 'ssh -p 2222 .*tester@127.0.0.1' <<<"$out2b"
check "the banner through the forward is what makes it OK" grep -q 'sshd answered through the channel: SSH-2.0-stub' <<<"$out2b"
opkw="$(sed -n 's/.*operator_pubkey = \([0-9a-f]\{64\}\).*/\1/p' "$T/w2b/operator.env" | head -1)"
check "both members got the operator pubkey from the script (caller env had none)" [ "$(grep -c "^opk=$opkw\$" "$T/stub.log")" -eq 2 ]
run_qs "$T/w2b" --clean --yes >/dev/null 2>&1
killrec

# ---- 2c. the forward only counts when data comes back; the probe must not silence later warnings --------------
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=(CT_QS_SSH_USER=tester STUB_REJECT_SESSION=1)
out2c="$(run_qs "$T/w2c" ssh-channel --yes --enable-forward 2>&1)"; rc=$?
check "P: a forward without data from the far side ends non-zero" [ "$rc" -ne 0 ]
check "P: the result is FAILED, not OK" grep -q 'RESULT: FAILED' <<<"$out2c"
check "P: no OK result is printed" ! grep -q 'RESULT: OK' <<<"$out2c"
check "P: the reason from the agent log is shown" grep -q 'stub peer rejected the grant' <<<"$out2c"
run_qs "$T/w2c" --clean --yes >/dev/null 2>&1
killrec
# Q: the probe's stderr redirect is limited to the probe -- a later warning still reaches stderr
QSRC="$(cd "$(dirname "$QS")" && pwd)/$(basename "$QS")"
errQ="$(QSRC="$QSRC" CT_QS_WORKDIR="$T/wq" bash -c '
  set -- --yes tunnel; . "$QSRC"
  port=$((30000 + $$ % 20000))
  python3 -c "import socket,sys
s=socket.socket(); s.bind((\"127.0.0.1\",int(sys.argv[1]))); s.listen(5)
c,_=s.accept(); c.sendall(b\"SSH-2.0-x\\r\\n\"); c.close()" "$port" &
  sleep 1
  banner=""
  if port_open 127.0.0.1 "$port" && { exec 4<>"/dev/tcp/127.0.0.1/$port"; } 2>/dev/null; then :; fi
  warn "after-probe-warning"' 2>&1 >/dev/null </dev/null)"
check "Q: the script has no bare exec with a stderr redirect left" ! grep -nE '^[[:space:]]*exec [0-9]*[<>&].*2>' "$QS"
check "Q: a warning after the probe still reaches stderr" grep -q 'after-probe-warning' <<<"$errQ"
# R: without a known operator pubkey the members are not started, with a plain message
errR="$(QSRC="$QSRC" CT_QS_WORKDIR="$T/wq" WORKR="$T/wr" bash -c 'set -- --yes tunnel; . "$QSRC"; WORK="$WORKR"; OPERATOR_PUB=""; run_side accept true; echo STARTED' 2>&1 </dev/null)"; rcR=$?
check "R: an unknown operator pubkey aborts before any member starts" [ "$rcR" -ne 0 ]
check "R: the message is plain text and names the key" grep -q 'operator public key is unknown' <<<"$errR"
check "R: the member command never ran" ! grep -q STARTED <<<"$errR"

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
killrec

# rerun reuses .env and does not redeem again
n="$(grep -c 'bootstrap/redeem' "$T/stub.log")"
out6="$(run_qs "$T/w5" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "tunnel rerun exits 0" [ "$rc" -eq 0 ]
check "tunnel rerun reuses .env" grep -q '.env found' <<<"$out6"
check "tunnel rerun did not redeem again" [ "$(grep -c 'bootstrap/redeem' "$T/stub.log")" -eq "$n" ]
killrec

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
sleep 100 & spid=$!; echo "$spid" >> "$PIDS"; echo "$spid" > "$T/w7/run/other.pid"
run_qs "$T/w7" --clean --yes >/dev/null 2>&1; rc=$?
check "--clean succeeds" [ "$rc" -eq 0 ]
check "a foreign file in the workdir survives --clean" [ -f "$T/w7/my-notes.txt" ]
check "the script's own marker is gone" [ ! -e "$T/w7/.ct-quickstart" ]
check "a recycled pid of a foreign process is not killed" kill -0 "$spid"
killrec

# a bootstrap token with odd characters is refused before it is sent
reset
E=(CT_AGENT_HOSTNAME=demo.example.test 'CT_BOOTSTRAP=ab"cd' CT_AGENT_ORIGIN=127.0.0.1:9)
outb="$(run_qs "$T/w8" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "a bootstrap token with a quote is refused" [ "$rc" -ne 0 ]
check "it was not sent to the control plane" ! grep -q 'bootstrap/redeem' "$T/stub.log"

# ---- 5b. review round 2 ---------------------------------------------------------------------------------------
# A: a workdir with spaces, a server token with a command substitution, a hostname with shell characters
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9)
outA="$(run_qs "$T/w a b" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "A: tunnel works in a workdir with spaces" [ "$rc" -eq 0 ]
killrec
reset
EVIL="$T/pwned"
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 "STUB_EVIL_TOKEN=\$(touch $EVIL)")
outA2="$(run_qs "$T/w5c" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "A: a server token with a command substitution is refused" [ "$rc" -ne 0 ]
check "A: it was never executed" [ ! -e "$EVIL" ]
check "A: no .env was written for it" [ ! -e "$T/w5c/.env" ]
reset
E=(CT_AGENT_HOSTNAME='demo.example.test;touch x' "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9)
outA3="$(run_qs "$T/w5d" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "A: a hostname with shell characters is refused" [ "$rc" -ne 0 ]
check "A: nothing was redeemed for it" ! grep -q 'bootstrap/redeem' "$T/stub.log"

# D: only privkey.pem.new present is not a finished pair
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 CT_QS_CERT_WAIT=4)
mkdir -p "$T/wh/ct-agent-cert"; : > "$T/wh/.ct-quickstart"; : > "$T/wh/ct-agent-cert/privkey.pem.new"
outD="$(run_qs "$T/wh" ssh-tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "D: a half-written pair (privkey.pem.new only) is not counted as done" [ "$rc" -ne 0 ]
check "D: the run did not skip the certificate stage" ! grep -q 'certificate pair already' <<<"$outD"
check "B: setup.sh did not see the one-time token" ! grep -q 'setup-redeems-bootstrap' "$T/stub.log"
killrec

# B/C: resume with a still-exported CT_BOOTSTRAP, then the agent died in terminate mode
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 CT_QS_CERT_WAIT=4)
mkdir -p "$T/w r/ct-agent-cert"; : > "$T/w r/.ct-quickstart"
echo c > "$T/w r/ct-agent-cert/fullchain.pem"; echo k > "$T/w r/ct-agent-cert/privkey.pem"
outR="$(run_qs "$T/w r" ssh-tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "D: a complete pair is accepted" grep -q 'certificate pair already' <<<"$outR"
check "ssh-tunnel host run exits 0 with the pair present" [ "$rc" -eq 0 ]
check "A: CT_ACME_CERT_OUT_DIR reached setup.sh intact" grep -q "cert-dir is $T/w r/ct-agent-cert" "$T/stub.log"
check "B: setup.sh never got the one-time token" ! grep -q 'setup-redeems-bootstrap' "$T/stub.log"
killrec; : > "$T/w r/gone"; unlink "$T/w r/ct-agent.pid" 2>/dev/null; s0="$(grep -c '^setup.sh' "$T/stub.log")"
outC="$(run_qs "$T/w r" ssh-tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "C: re-run in terminate mode with a dead agent exits 0" [ "$rc" -eq 0 ]
check "C: setup.sh ran again to restart the agent" [ "$(grep -c '^setup.sh' "$T/stub.log")" -gt "$s0" ]
check "B: still no token redeemed by setup.sh after the resume" ! grep -q 'setup-redeems-bootstrap' "$T/stub.log"
killrec

# H: a foreign process whose pid file points into the workdir (no recorded signature) is never killed
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9)
run_qs "$T/wf" tunnel --yes --no-demo-origin >/dev/null 2>&1; killrec
sleep 90 & fp=$!; echo "$fp" >> "$PIDS"; echo "$fp" > "$T/wf/ct-agent.pid"; unlink "$T/wf/run/ct-agent.sig" 2>/dev/null
run_qs "$T/wf" --clean --yes >/dev/null 2>&1
check "H: a process with a pid file but no recorded signature survives --clean" kill -0 "$fp"
killrec

# F: grants are bound to the operator key; --rekey discards them
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
run_qs "$T/wg" channel --yes >/dev/null 2>&1; killrec
g1="$(grep -c 'channel grant' "$T/stub.log")"
unlink "$T/bus" 2>/dev/null
run_qs "$T/wg" channel --yes >/dev/null 2>&1; killrec
check "F: same operator key reuses the grants" [ "$(grep -c 'channel grant' "$T/stub.log")" -eq "$g1" ]
unlink "$T/bus" 2>/dev/null
run_qs "$T/wg" channel --yes --rekey >/dev/null 2>&1; killrec
check "F: after --rekey new grants are signed" [ "$(grep -c 'channel grant' "$T/stub.log")" -gt "$g1" ]

# E/G: ssh-tunnel client
reset
printf 'k' > "$T/owner.key"
mkdir -p "$T/home/.ssh"; printf 'old' > "$T/home/.ssh/ct-agent-demo.example.test.owner"
E=(CT_AGENT_HOSTNAME=demo.example.test CT_QS_OWNER_KEY_FILE="$T/owner.key" CT_QS_SSH_USER=tester)
outG="$(run_qs "$T/wc" ssh-tunnel --role client --yes 2>&1)"; rc=$?
check "G: --yes does not overwrite a different owner key" [ "$rc" -ne 0 ] && [ "$(cat "$T/home/.ssh/ct-agent-demo.example.test.owner")" = old ]
check "G: the refusal names the switch" grep -q -- '--allow-ssh-key-overwrite' <<<"$outG"
unlink "$T/home/.ssh/ct-agent-demo.example.test.owner"
outG2="$(run_qs "$T/wc" ssh-tunnel --role client --yes 2>&1)"; rc=$?
check "G: --yes without --append-ssh-config leaves ~/.ssh/config alone" [ "$rc" -eq 0 ] && [ ! -e "$T/home/.ssh/config" ]
outG3="$(run_qs "$T/wc" ssh-tunnel --role client --yes --append-ssh-config 2>&1)"; rc=$?
check "G: --append-ssh-config appends" [ "$rc" -eq 0 ] && grep -q '^Host demo.example.test' "$T/home/.ssh/config"
# E: ct-agent is only in the workdir, not on PATH -> the stanza must carry its absolute path
reset
mkdir -p "$T/we"; : > "$T/we/.ct-quickstart"; cp "$BIN/ct-agent" "$T/we/ct-agent"
env -i PATH=/usr/bin:/bin HOME="$T/home" STUB_LOG="$T/stub.log" CT_QS_WORKDIR="$T/we" CT_AGENT_HOSTNAME=demo.example.test \
  CT_QS_OWNER_KEY_FILE="$T/owner.key" CT_QS_SSH_USER=tester bash "$QS" ssh-tunnel --role client --yes --append-ssh-config >/dev/null 2>&1; rc=$?
check "E: client run without ct-agent on PATH succeeds" [ "$rc" -eq 0 ]
check "E: the stanza calls the CLI by absolute path" grep -q "ProxyCommand $T/we/ct-agent " "$T/home/.ssh/config"

# J: the host path warns that the agent log can hold the owner key; log excerpts mask long hex runs
check "J: the finished host run says the owner key is not printed by the script and warns about ct-agent.log" grep -q 'do not share it' <<<"$outR"
( set -e; cd "$T"; CT_QS_WORKDIR="$T/wj" . "$QS" tunnel >/dev/null 2>&1 || true
  printf 'owner key %s\n' "$(printf 'ab%.0s' $(seq 1 32))" > "$T/j.log"
  tail_log "$T/j.log" 2>&1 | grep -q 'hex-redacted' && ! tail_log "$T/j.log" 2>&1 | grep -q 'abababababababab' )
check "J: tail_log masks a 64-character hex key" [ "$?" -eq 0 ]
# K: the redeem POST does not follow redirects
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9)
run_qs "$T/wk" tunnel --yes --no-demo-origin >/dev/null 2>&1; killrec
check "K: the redeem call has no -L and caps redirects" grep -q 'curl -fsS --max-redirs 0 -X POST' "$T/stub.log"
# L: a bearer token with a quote is refused before it reaches a curl config
reset
E=(CT_OIDC_TOKEN='abc"def' CT_QS_WAIT=5)
outL="$(run_qs "$T/wl" channel --yes 2>&1)"; rc=$?
check "L: a bearer token with a quote is refused" [ "$rc" -ne 0 ]
check "L: the bad token never reached curl's stdin" ! grep -q 'abc"def' "$T/curl.stdin"
# M: a changed forward target restarts the members instead of keeping the old FORWARD_ALLOW
reset
mkdir -p "$T/home/.ct-agent"; echo "{\"access_token\":\"$SECRET_TOKEN\"}" > "$T/home/.ct-agent/oidc-token.json"
E=(CT_QS_SSH_USER=tester)
run_qs "$T/wm" ssh-channel --yes --enable-forward >/dev/null 2>&1
E=(CT_QS_SSH_USER=tester CT_QS_FORWARD_TARGET=127.0.0.1:2200)
outM="$(run_qs "$T/wm" ssh-channel --yes --enable-forward 2>&1)"
check "M: the changed target is announced as a restart" grep -q 'restarting both members' <<<"$outM"
check "M: member A was started again with the new allow list" grep -q 'run role=accept serve=1 allow=127.0.0.1:2200' "$T/stub.log"
killrec
# N: an option without its value ends with a clear message
outN="$(run_qs "$T/wn" tunnel --workdir 2>&1)"; rc=$?
check "N: --workdir without a value fails and says so" [ "$rc" -ne 0 ] && grep -q -- '--workdir needs a value' <<<"$outN"
# O: without pgrep the script stops with a clear message
mkdir -p "$T/nops"; for t in mkdir ls touch cat sed dirname id date cd pwd; do p="$(command -v "$t" 2>/dev/null)"; case "$p" in /*) ln -sf "$p" "$T/nops/$t" ;; esac; done
outO="$(env -i PATH="$T/nops" HOME="$T/home" CT_QS_WORKDIR="$T/wo" "$(command -v bash)" "$QS" --clean --yes 2>&1 </dev/null)"; rc=$?
check "O: missing ps/pgrep stops with a clear message" [ "$rc" -ne 0 ] && grep -q 'ps and pgrep are required' <<<"$outO"

# empty secret from the control plane: "holds no tokens", not "unexpected characters"
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 STUB_EMPTY_SECRET=1)
outE="$(run_qs "$T/wq" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "an answer without tokens fails" [ "$rc" -ne 0 ]
check "it says the answer holds no tokens" grep -q 'holds no tokens' <<<"$outE"
check "it does not blame the characters" ! grep -q 'unexpected characters' <<<"$outE"
# plain http:// to a non-local host warns loudly (no abort); to localhost it stays quiet
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 CT_AGENT_CP_URL=http://cp.example.test)
outH="$(run_qs "$T/wu" tunnel --yes --no-demo-origin 2>&1)"; rc=$?
check "http:// to a non-local host warns about clear text" grep -q 'plain http://' <<<"$outH"
check "the warning is not an abort" [ "$rc" -eq 0 ]
killrec
reset
E=(CT_AGENT_HOSTNAME=demo.example.test "CT_BOOTSTRAP=$SECRET_BOOT" CT_AGENT_ORIGIN=127.0.0.1:9 CT_AGENT_CP_URL=http://127.0.0.1:8080)
outH2="$(run_qs "$T/wv" tunnel --yes --no-demo-origin 2>&1)"
check "http:// to localhost does not warn" ! grep -q 'plain http://' <<<"$outH2"
killrec

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
