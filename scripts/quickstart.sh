#!/usr/bin/env bash
# ct-agent quickstart -- the four paths of docs/quickstarts.md as one guided, repeatable script.
# It asks only what it cannot work out itself, offers a default for everything else (Enter
# accepts it) and runs without questions under --yes or with the matching variables set.
#
#   scripts/quickstart.sh tunnel       [--yes] [--docker]              # 1. a service under a public hostname
#   scripts/quickstart.sh channel      [--yes]                         # 2. two members, one machine, end to end
#   scripts/quickstart.sh channel      --role operator|member [--side accept|initiate]   # several machines
#   scripts/quickstart.sh ssh-tunnel   [--yes] [--role host|client]    # 3. ssh to a machine behind NAT, via a tunnel
#   scripts/quickstart.sh ssh-channel  [--yes] [--role operator|member] # 4. ssh via a channel (TCP forward)
#   scripts/quickstart.sh --clean                                      # remove this script's own working directory
#
# This script never puts a secret on a command line it builds itself: tokens come from the environment
# or a hidden prompt and go to curl through stdin; files that hold secrets are mode 0600. It cannot
# vouch for other programs it starts (setup.sh, ct-agent). Known: the agent writes the ssh owner key to
# ct-agent.log on its first terminate-mode start, so treat that file as secret. Run it again after a failure: keys, the registration, the
# member entries and the grants that already exist are reused. It overwrites only files it created
# itself. With --yes it accepts defaults only: overwriting a different ssh owner key, appending to
# ~/.ssh/config and turning on the TCP forward each need their own switch (see --help).
set -euo pipefail
umask 077

# --- output ----------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B="\033[1m"; C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_0="\033[0m"
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi
log()  { printf "${C_B}==>${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}  ✓${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}  !${C_0} %s\n" "$*" >&2; }
die()  { printf "${C_R}error:${C_0} %s\n" "$*" >&2; exit 1; }

STAGE="start"; HINT="re-run with --help"; DONE_MSG=""; FG_PIDS=""
stage() { STAGE="$1"; HINT="${2:-re-run the same command; finished steps are skipped}"; log "$1"; }

on_exit() {
  local rc=$? p
  trap - EXIT
  for p in $FG_PIDS; do kill_tree "$p"; done
  if [ "$rc" -eq 0 ] && [ -n "$DONE_MSG" ]; then
    printf "\n${C_G}RESULT: OK${C_0} -- %s\n" "$DONE_MSG"
  elif [ "$rc" -ne 0 ]; then
    printf "\n${C_R}RESULT: FAILED${C_0} at stage '%s'.\n  Next: %s\n" "$STAGE" "$HINT" >&2
  fi
  exit "$rc"
}
trap on_exit EXIT

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'
  cat <<'USAGE'

Every question has a variable of the same name; a variable that is set is never asked.

  CT_AGENT_CP_URL          control plane                         (default https://bunsenbrenner.org)
  CT_OIDC_ISSUER           login realm, asked only when a login is needed
                           (default https://auth.bunsenbrenner.org/realms/ct-demo)
  CT_QS_GRANT_HOURS        grant lifetime in hours               (default 24)
  CT_QS_WORKDIR            working directory                     (default ./ct-quickstart)
  CT_QS_SIDE               accept | initiate (several machines: which member this is)
  CT_QS_MESSAGE            test line sent from the initiating side
  CT_QS_SSH_USER           login name on the ssh target          (default: current user)
  CT_QS_FORWARD_TARGET     ssh-channel: what the accepting side allows   (default 127.0.0.1:22)
  CT_QS_LOCAL_PORT         ssh-channel: loopback port on the initiating side (default 2222)
  CT_BOOTSTRAP             tunnel: the token of the Install page (hidden prompt if unset)
  CT_AGENT_HOSTNAME        tunnel: the hostname of the Install page
  CT_AGENT_ORIGIN          tunnel: what to publish               (default 127.0.0.1:8080)
  CT_QS_OWNER_KEY_FILE     ssh-tunnel client: file holding the owner key printed by the host

Switches that --yes does NOT imply (each is a separate, explicit decision):
  --enable-forward           ssh-channel: turn on the opt-in TCP forward
  --allow-ssh-key-overwrite  ssh-tunnel client: replace a different ~/.ssh/ct-agent-<host>.owner
  --append-ssh-config        ssh-tunnel client: append the stanza to ~/.ssh/config
                             (without it, --yes prints the stanza for you to add)

Options: --yes (no questions), --workdir DIR, --inbox FILE (read pasted blocks from a file),
--docker (tunnel only), --no-demo-origin, --rekey (channel register --rekey), --green is implied by
ssh-tunnel. Tuning for slow links: CT_QS_WAIT (seconds to wait for the test line, default 90),
CT_QS_RETRIES (join retries on a refusal, default 6).
USAGE
  exit "${1:-0}"
}

# --- arguments -------------------------------------------------------------------
CMD=""; ROLE="${CT_QS_ROLE:-}"; ASSUME_YES=0; DO_CLEAN=0; DOCKER=0; DEMO_ORIGIN=1; ENABLE_FORWARD=0; ALLOW_KEY_OVERWRITE=0; APPEND_SSH_CONFIG=0; REKEY="${CT_CHANNEL_REKEY:-0}"
INBOX_FILE="${CT_QS_INBOX_FILE:-}"
WORK="${CT_QS_WORKDIR:-./ct-quickstart}"
CT_QS_SIDE="${CT_QS_SIDE:-}"
optval() { # an option that takes a value must have one (not missing, not another option)
  { [ $# -ge 2 ] && [ -n "$2" ] && [ "${2#-}" = "$2" ]; } || die "$1 needs a value (try --help)"
}
while [ $# -gt 0 ]; do
  case "$1" in
    tunnel|channel|ssh-tunnel|ssh-channel) CMD="$1" ;;
    --yes|-y)         ASSUME_YES=1 ;;
    --role)           optval "$@"; shift; ROLE="$1" ;;
    --side)           optval "$@"; shift; CT_QS_SIDE="$1" ;;
    --workdir)        optval "$@"; shift; WORK="$1" ;;
    --inbox)          optval "$@"; shift; INBOX_FILE="$1" ;;
    --docker)         DOCKER=1 ;;
    --no-demo-origin) DEMO_ORIGIN=0 ;;
    --rekey)          REKEY=1 ;;
    --enable-forward) ENABLE_FORWARD=1 ;;
    --allow-ssh-key-overwrite) ALLOW_KEY_OVERWRITE=1 ;;
    --append-ssh-config) APPEND_SSH_CONFIG=1 ;;
    --clean)          DO_CLEAN=1 ;;
    -h|--help)        usage 0 ;;
    *)                die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[ "$DO_CLEAN" -eq 1 ] || [ -n "$CMD" ] || usage 1
case "$ROLE" in ""|operator|member|host|client) ;; *) die "--role must be operator|member (channel) or host|client (ssh-tunnel)" ;; esac
case "$CT_QS_SIDE" in ""|accept|initiate) ;; *) die "--side must be accept or initiate" ;; esac

# --- questions ---------------------------------------------------------------------
# ask VAR "question" [default] [secret]   -- a set variable is taken as is and never asked.
ask() {
  local var="$1" prompt="$2" def="${3:-}" secret="${4:-}" ans=""
  [ -z "${!var:-}" ] || return 0
  if [ "$ASSUME_YES" -eq 1 ]; then
    [ -n "$def" ] || die "$var is required: set it in the environment (it has no default)"
    printf -v "$var" '%s' "$def"; return 0
  fi
  if [ -n "$def" ]; then printf '%s [%s]: ' "$prompt" "$def" >&2; else printf '%s: ' "$prompt" >&2; fi
  if [ -n "$secret" ] && [ -t 0 ]; then
    IFS= read -rs ans || true; echo >&2
  else
    IFS= read -r ans || true
  fi
  ans="${ans:-$def}"
  [ -n "$ans" ] || die "$var is required (or set it in the environment)"
  printf -v "$var" '%s' "$ans"
}

# confirm "question" -- yes under --yes; without a terminal and without --yes it refuses.
confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -t 0 ] || die "not an interactive terminal -- pass --yes to confirm: $1"
  local r; printf '%s [y/N] ' "$1" >&2; read -r r || true
  case "$r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# --- small helpers -----------------------------------------------------------------
DEFAULT_CP="https://bunsenbrenner.org"
DEFAULT_ISSUER="https://auth.bunsenbrenner.org/realms/ct-demo"
CTA=""

if [ "$DO_CLEAN" -eq 1 ]; then
  [ -d "$WORK" ] || die "$WORK does not exist -- nothing to clean"
  WORK="$(cd "$WORK" && pwd)"
else
  if [ -d "$WORK" ] && [ ! -f "$WORK/.ct-quickstart" ] && [ -n "$(ls -A "$WORK" 2>/dev/null)" ]; then
    die "$WORK exists, is not empty and was not created by this script -- use an empty or new directory (--workdir DIR)"
  fi
  mkdir -p "$WORK"; WORK="$(cd "$WORK" && pwd)"
  [ -f "$WORK/.ct-quickstart" ] || : > "$WORK/.ct-quickstart"
  mkdir -p "$WORK/logs" "$WORK/run" "$WORK/grants"
fi
INBOX="$WORK/inbox.txt"
[ "$DO_CLEAN" -eq 1 ] || touch "$INBOX"

host_of() { printf '%s' "$1" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*##'; }
now() { date +%s; }
sha8() { printf '%s' "$1" | cut -c1-8; }
getenv_file() { sed -n "s/^export $2=\(.*\)\$/\1/p" "$1" 2>/dev/null | head -1; }
is_hex() { case "$1" in ""|*[!0-9a-f]*) return 1 ;; *) return 0 ;; esac; }
port_open() { # host port
  (exec 3<>"/dev/tcp/$1/$2") >/dev/null 2>&1
}
pid_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

# Values that end up in the .env (which setup.sh sources) are checked against a narrow pattern first and
# written quoted when they hold anything beyond a plain word.
RE_HOST='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
RE_URL='^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'
RE_ORIGIN='^[A-Za-z0-9.-]+:[0-9]+$'
RE_TOKEN='^[A-Za-z0-9._~+/=-]+$'
need() { # label value regex
  [[ "$2" =~ $3 ]] || die "$1 holds characters it should not (allowed pattern: $3) -- nothing was written"
}
check_cp() { # CP URL: shape, and a loud warning for clear-text http to a non-local host
  need "CT_AGENT_CP_URL" "$1" "$RE_URL"
  case "$1" in
    http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*|"http://[::1]"*) ;;
    http://*) warn "the control plane URL uses plain http:// to a non-local host -- tokens would travel in clear text. Use https://" ;;
  esac
}
env_kv() { # NAME VALUE -> a line safe to source
  if [[ "$2" =~ ^[A-Za-z0-9._~:/+=@%,-]*$ ]]; then printf '%s=%s\n' "$1" "$2"
  else printf "%s='%s'\n" "$1" "${2//\'/\'\\\'\'}"; fi
}

# ours PIDFILE -- alive AND matching the signature recorded at start
ours() {
  local p; p="$(cat "$1" 2>/dev/null || true)"
  pid_alive "$p" && [ -s "$(sigfile_of "$1")" ] && [ "$(proc_sig "$p")" = "$(cat "$(sigfile_of "$1")")" ]
}
# A process is "ours" only if its start time and command line equal what was recorded right after the start
# (a recycled pid or someone else's ct-agent never matches). No record: never killed.
proc_sig() { ps -p "$1" -o lstart=,command= 2>/dev/null | sed 's/  */ /g'; }
sigfile_of() { printf '%s/run/%s.sig' "$WORK" "$(basename "$1" .pid)"; }
record_sig() { # PIDFILE
  local p; p="$(cat "$1" 2>/dev/null || true)"
  if pid_alive "$p"; then proc_sig "$p" > "$(sigfile_of "$1")"; fi
  return 0
}
kill_tree() {
  local p="$1" c
  for c in $(pgrep -P "$p" 2>/dev/null || true); do kill_tree "$c"; done
  kill "$p" 2>/dev/null || true
}
# Show the last lines of a log. Logs can hold keys (the agent prints the ssh owner key to its log on the first
# terminate-mode start), so long hex runs are masked before anything is shown.
tail_log() {
  [ -s "$1" ] || return 0
  echo "  --- last lines of $1" >&2
  tail -n "${2:-8}" "$1" | sed -E 's/[0-9A-Fa-f]{32,}/<hex-redacted>/g; s/^/  | /' >&2
}

# Copy `bash`'s stdin to stdout, hiding every occurrence of the given secrets.
redact() {
  local line s
  while IFS= read -r line || [ -n "$line" ]; do
    for s in "$@"; do [ -z "$s" ] || line="${line//"$s"/<redacted>}"; done
    printf '%s\n' "$line"
  done
}

# --- the CLI ------------------------------------------------------------------------
setup_sh() {
  if [ -n "${CT_QS_SETUP_SH:-}" ]; then printf '%s' "$CT_QS_SETUP_SH"; return; fi
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  if [ -n "$here" ] && [ -f "$here/setup.sh" ]; then printf '%s' "$here/setup.sh"; return; fi
  curl -fsSL "${CT_QS_SETUP_URL:-https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh}" \
    -o "$WORK/setup.sh" || die "could not download setup.sh"
  printf '%s' "$WORK/setup.sh"
}

ensure_cli() {
  if command -v ct-agent >/dev/null 2>&1; then CTA="$(command -v ct-agent)"; ok "ct-agent found: $CTA"; return; fi
  if [ -x "$WORK/ct-agent" ]; then CTA="$WORK/ct-agent"; ok "ct-agent found: $CTA"; return; fi
  command -v curl >/dev/null 2>&1 || die "curl is required but not found"
  local s; s="$(setup_sh)"
  (cd "$WORK" && bash "$s" --client-only) || die "installing the CLI failed"
  CTA="$WORK/ct-agent"
  [ -x "$CTA" ] || die "setup.sh --client-only did not produce $CTA"
  ok "ct-agent installed in $WORK (not on your PATH; nothing outside $WORK was touched)"
}

# --- login and the bearer token -----------------------------------------------------
token_file() {
  if [ -n "${CT_AGENT_LOGIN_TOKEN_FILE:-}" ]; then printf '%s' "$CT_AGENT_LOGIN_TOKEN_FILE"
  elif [ -n "${CT_AGENT_STATE_DIR:-}" ]; then printf '%s' "$CT_AGENT_STATE_DIR/oidc-token.json"
  else printf '%s' "${HOME:-.}/.ct-agent/oidc-token.json"; fi
}
have_login() {
  [ -n "${CT_OIDC_TOKEN:-}" ] && return 0
  [ -n "${CT_OIDC_TOKEN_FILE:-}" ] && [ -s "$CT_OIDC_TOKEN_FILE" ] && return 0
  [ -s "$(token_file)" ]
}
ensure_login() {
  if have_login; then ok "login found -- no new sign-in needed (a stale one is refreshed on use)"; return; fi
  ask CT_OIDC_ISSUER "OIDC issuer (realm URL)" "$DEFAULT_ISSUER"
  log "sign-in: open the URL below in any browser and enter the code"
  CT_OIDC_ISSUER="$CT_OIDC_ISSUER" "$CTA" login || die "login failed"
}
# The bearer token goes to curl through stdin only; this prints it for that single use.
bearer() {
  local f t=""
  if [ -n "${CT_OIDC_TOKEN:-}" ]; then t="$CT_OIDC_TOKEN"
  elif [ -n "${CT_OIDC_TOKEN_FILE:-}" ] && [ -s "$CT_OIDC_TOKEN_FILE" ]; then t="$(tr -d ' \r\n' < "$CT_OIDC_TOKEN_FILE")"
  else
    f="$(token_file)"
    [ -s "$f" ] || return 1
    t="$(tr -d '\n' < "$f" | sed -n 's/.*"access_token" *: *"\([^"]*\)".*/\1/p')"
  fi
  # the value goes into a curl config line: no quote, space or line break may get in
  [[ "$t" =~ $RE_TOKEN ]] || { echo "the bearer token holds characters a token never has (quote, space, line break)" >&2; return 1; }
  printf '%s' "$t"
}

# --- key material ---------------------------------------------------------------------
ensure_operator() {
  local f="$WORK/operator.env"
  if [ -s "$f" ] && grep -q '^export CT_CHANNEL_OPERATOR_KEY=' "$f"; then
    ok "operator key found in $f -- reusing it"
  else
    "$CTA" channel operator-init > "$f" || die "operator-init failed"
    chmod 600 "$f"; ok "operator key created ($f, mode 0600)"
  fi
  OPERATOR_KEY="$(getenv_file "$f" CT_CHANNEL_OPERATOR_KEY)"
  OPERATOR_PUB="$(sed -n 's/.*operator_pubkey = \([0-9a-f]\{64\}\).*/\1/p' "$f" | head -1)"
  is_hex "$OPERATOR_PUB" || die "no operator_pubkey line in $f"
}
ensure_member() { # side
  local d="$WORK/$1"; mkdir -p "$d"
  if [ -s "$d/member.env" ] && grep -q '^export CT_CHANNEL_HOLDER_KEY=' "$d/member.env"; then
    ok "$1 identity found in $d/member.env -- reusing it"
  else
    "$CTA" channel init > "$d/member.env" || die "channel init failed"
    chmod 600 "$d/member.env"; ok "$1 identity created ($d/member.env, mode 0600)"
  fi
}
holder_of() { getenv_file "$WORK/$1/member.env" CT_CHANNEL_HOLDER_PUBKEY; }
noise_of()  { getenv_file "$WORK/$1/member.env" CT_CHANNEL_NOISE_PUBKEY; }
other() { [ "$1" = accept ] && echo initiate || echo accept; }

# material <side> <peer holder>  -> $WORK/<side>/material.txt (public values only)
member_material() {
  local side="$1" peer="$2" d="$WORK/$1"
  ( set -a; . "$d/member.env"; set +a
    CT_CHANNEL_OPERATOR_PUBKEY="$OPERATOR_PUB" CT_CHANNEL_BRIDGE_HOLDER="$peer" "$CTA" channel member-material ) \
    > "$d/material.txt" || die "member-material failed for $side"
}
mat() { sed -n "s/^$2 *= *\([0-9a-f]*\).*/\1/p" "$WORK/$1/material.txt" | head -1; }

# --- control plane: register, add member, grant ----------------------------------------
cp_register() { # channel
  local out rc=0 tries=0
  while :; do
    out="$(CT_AGENT_CP_URL="$CP" CT_CHANNEL_ID="$1" CT_CHANNEL_OPERATOR_KEY="$OPERATOR_KEY" \
           "$CTA" channel register $( [ "$REKEY" = 1 ] && echo --rekey ) 2>&1)" && rc=0 || rc=$?
    if [ "$rc" -eq 0 ]; then ok "channel registered (an existing identical registration is fine)"; return; fi
    printf '%s\n' "$out" >&2
    if printf '%s' "$out" | grep -qiE 'ct-agent login|401|unauthori[sz]ed|not set and no stored login' && [ "$tries" -eq 0 ]; then
      tries=1; warn "the sign-in is missing or stale -- signing in once more"
      CT_OIDC_ISSUER="${CT_OIDC_ISSUER:-$DEFAULT_ISSUER}" "$CTA" login || die "login failed"
      continue
    fi
    if printf '%s' "$out" | grep -q '409'; then
      HINT="this channel is registered under a different operator key. If you lost ${WORK}/operator.env, re-run with --rekey (every grant signed by the old key stops verifying)"
    else
      HINT="read the message above; if it names the sign-in, run: CT_OIDC_ISSUER=<issuer> ct-agent login"
    fi
    die "channel register failed"
  done
}

cp_add_member() { # side channel holder noise attest
  local body code tries=0 tok resp="$WORK/logs/member-add.$1.body"
  body="{\"holder\":\"$3\",\"noise_pubkey\":\"$4\",\"noise_attestation\":\"$5\"}"
  while :; do
    tok="$(bearer)" || tok=""
    [ -n "$tok" ] || die "no bearer token found -- run: CT_OIDC_ISSUER=<issuer> ct-agent login"
    # the header goes through stdin (printf is a builtin): the token never shows up in the process list
    code="$(printf 'header = "Authorization: Bearer %s"\n' "$tok" | curl -sS -o "$resp" -w '%{http_code}' \
            -X POST "$CP/me/channels/$2/members" -H 'content-type: application/json' --config - -d "$body")" || code="000"
    tok=""
    case "$code" in
      200|201|204) ok "member '$1' added"; return ;;
      409)         ok "member '$1' was already added (409) -- continuing"; return ;;
      401)
        if [ "$tries" -eq 0 ]; then
          tries=1; warn "the token was refused (they live only minutes) -- refreshing it"
          CT_AGENT_CP_URL="$CP" CT_CHANNEL_ID="$2" CT_CHANNEL_OPERATOR_KEY="$OPERATOR_KEY" "$CTA" channel register >/dev/null 2>&1 || true
          continue
        fi
        HINT="sign in again and re-run: CT_OIDC_ISSUER=<issuer> ct-agent login"
        die "adding member '$1' was refused with 401" ;;
      *)
        tail_log "$resp" 3
        HINT="the control plane answered $code; check that the channel is registered under your account and the attestation matches"
        die "adding member '$1' failed (HTTP $code)" ;;
    esac
  done
}

issue_grant() { # side channel holder direction
  local side="$1" f="$WORK/grants/$1.grant" m="$WORK/grants/$1.meta" exp g
  if [ -s "$f" ] && [ -s "$m" ]; then
    local mch mexp mop; mch="$(sed -n 's/^channel=//p' "$m")"; mexp="$(sed -n 's/^expires=//p' "$m")"; mop="$(sed -n 's/^operator=//p' "$m")"
    if [ "$mch" = "$2" ] && [ "$mop" = "$OPERATOR_PUB" ] && [ "$REKEY" != 1 ] && [ "${mexp:-0}" -gt $(( $(now) + 600 )) ]; then
      ok "grant for '$side' still valid -- reusing it"; return
    fi
    warn "grant for '$side' is expired, for another channel or operator key, or --rekey was given -- signing a new one"
  fi
  exp=$(( $(now) + ${CT_QS_GRANT_HOURS} * 3600 ))
  g="$(CT_CHANNEL_OPERATOR_KEY="$OPERATOR_KEY" CT_GRANT_CHANNEL="$2" CT_GRANT_MEMBER_HOLDER="$3" \
       CT_GRANT_DIRECTION="$4" CT_GRANT_EXPIRES="$exp" "$CTA" channel grant)" || die "signing the grant for '$side' failed"
  printf '%s\n' "$g" > "$f"; chmod 600 "$f"
  printf 'channel=%s\nexpires=%s\noperator=%s\n' "$2" "$exp" "$OPERATOR_PUB" > "$m"
  ok "grant for '$side' signed (valid ${CT_QS_GRANT_HOURS} h)"
}

# --- edge values from the control plane -------------------------------------------------
edge_values() {
  local ni host bp rp gp ca
  ni="$(curl -fsS "$CP/network-info")" || die "could not read $CP/network-info"
  host="$(host_of "$CP")"
  bp="$(printf '%s' "$ni" | sed -n 's/.*"channel_broker_port": *\([0-9]*\).*/\1/p')"
  rp="$(printf '%s' "$ni" | sed -n 's/.*"channel_relay_port": *\([0-9]*\).*/\1/p')"
  gp="$(printf '%s' "$ni" | sed -n 's/.*"channel_relay_gate_port": *\([0-9]*\).*/\1/p')"
  [ -n "$bp" ] && [ -n "$rp" ] || die "$CP/network-info does not list channel_broker_port / channel_relay_port -- is this a CADS-Tunnel control plane?"
  ca="$(curl -fsS "$CP/pki/ca" | od -An -v -tx1 | tr -d ' \n')" || die "could not read $CP/pki/ca"
  [ -n "$ca" ] || die "$CP/pki/ca returned nothing"
  EDGE_BROKER="$host:$bp"; EDGE_RELAY="$host:$rp"; EDGE_FRONT="$host:${gp:-443}"; EDGE_CA_HEX="$ca"
  ok "edge: $host (broker $bp, relay $rp, front door ${gp:-443}), CA ${#ca} hex chars"
}

# Both members check the peer's grant against the operator public key. The script knows it (operator.env on
# a single machine, the pasted operator block on the member side) and hands it to every member it starts.
need_operator_pub() {
  case "${OPERATOR_PUB:-}" in
    ""|*[!0-9a-f]*) die "the operator public key is unknown here, so the members could not check each other's grant. Single machine: run the operator step first ($WORK/operator.env). Several machines: paste the operator block first" ;;
  esac
  [ "${#OPERATOR_PUB}" -eq 64 ] || die "the operator public key must be 64 hex characters (got ${#OPERATOR_PUB})"
}

# run_side <side> <command...> -- the command runs with that member's keys, its grant and the edge settings
run_side() {
  local side="$1"; shift
  need_operator_pub
  ( set -a; . "$WORK/$side/member.env"; set +a
    export CT_CHANNEL_BROKER="$EDGE_BROKER" CT_CHANNEL_RELAY="$EDGE_RELAY" CT_CHANNEL_FRONT_DOOR="$EDGE_FRONT" \
      CT_CHANNEL_FRONT_DOOR_CERT="$EDGE_CA_HEX" CT_CHANNEL_FRONT_DOOR_ONLY=1 CT_CHANNEL_RELAY_ONLY=1 \
      CT_CHANNEL_GRANT="$(tr -d ' \r\n' < "$WORK/grants/$side.grant")" CT_CHANNEL_OPERATOR_PUBKEY="$OPERATOR_PUB"
    exec "$@" )
}

# --- the pasted blocks (several machines) -----------------------------------------------
# One line per fact:  ctq1 <operator|accept|initiate> <pubkey|holder|noise|channel|attest|grant> <hex>
# Blocks are public values (and the grant); pasting them in any order, any number of times, is fine.
valid_len() { case "$1" in attest) echo 128 ;; grant) echo 0 ;; *) echo 64 ;; esac; }
inbox_add() { # line
  local who key val len
  [[ "$1" =~ ctq1[[:space:]]+(operator|accept|initiate)[[:space:]]+(pubkey|holder|noise|channel|attest|grant)[[:space:]]+([0-9a-fA-F]+) ]] || return 1
  who="${BASH_REMATCH[1]}"; key="${BASH_REMATCH[2]}"; val="$(printf '%s' "${BASH_REMATCH[3]}" | tr 'A-F' 'a-f')"
  len="$(valid_len "$key")"
  if [ "$len" -ne 0 ] && [ "${#val}" -ne "$len" ]; then warn "ignored a '$who $key' line: expected $len hex characters, got ${#val}"; return 0; fi
  [ "$len" -ne 0 ] || [ "${#val}" -ge 64 ] || { warn "ignored a short grant line"; return 0; }
  grep -qxF "ctq1 $who $key $val" "$INBOX" || printf 'ctq1 %s %s %s\n' "$who" "$key" "$val" >> "$INBOX"
  return 0
}
inbox_get() { awk -v w="$1" -v k="$2" '$1=="ctq1" && $2==w && $3==k {v=$4} END{if(v!="")print v}' "$INBOX"; }
inbox_missing() { local p; for p in "$@"; do [ -n "$(inbox_get "${p%%:*}" "${p##*:}")" ] || { echo "$p"; return 0; }; done; return 1; }
# collect "<what to paste>" who:key ...   -- waits until every who:key is known
collect() {
  local what="$1" line; shift
  if [ -n "$INBOX_FILE" ] && [ -f "$INBOX_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do inbox_add "$line" || true; done < "$INBOX_FILE"
  fi
  inbox_missing "$@" >/dev/null || { ok "already have everything from $what (inbox.txt)"; return; }
  [ "$ASSUME_YES" -eq 0 ] || die "missing from $what: $(inbox_missing "$@") -- pass the blocks with --inbox FILE"
  log "paste $what now (all 'ctq1 ...' lines; other text is ignored; it continues by itself once complete)"
  while inbox_missing "$@" >/dev/null; do
    IFS= read -r line || die "input ended but still missing from $what: $(inbox_missing "$@")"
    inbox_add "$line" || true
  done
  ok "received everything from $what"
}
block() { # title, then lines on stdin
  echo; echo "-------- $1 --------"; cat; echo "-------- end --------"
}

# --- common start for channel commands ---------------------------------------------------
channel_common() {
  stage "settings" "set the variable named in the message and re-run"
  ask CT_AGENT_CP_URL "Control plane" "$DEFAULT_CP"
  CP="${CT_AGENT_CP_URL%/}"; check_cp "$CP"
  CT_QS_GRANT_HOURS="${CT_QS_GRANT_HOURS:-24}"
  case "$CT_QS_GRANT_HOURS" in ""|*[!0-9]*) die "CT_QS_GRANT_HOURS must be a whole number of hours" ;; esac
  stage "install the CLI" "install curl, or put ct-agent on PATH, then re-run"
  ensure_cli
}

forward_warning() {
  warn "The TCP forward is opt-in and off by default. Read the current limits of grant revocation for running"
  warn "forwarded streams first (docs/channel.md, section 'TCP forward over a paired channel'; ct-agent#45)."
  warn "Do not enable it in production unless that section says it is safe for your case."
}

# --- stop what this script started --------------------------------------------------------
# stop_pidfile FILE -- kills the process only if it still looks like one this script starts (PIDs get reused).
stop_pidfile() {
  local f="$1" p
  [ -f "$f" ] || return 0
  p="$(cat "$f" 2>/dev/null || true)"
  local sf; sf="$(sigfile_of "$f")"
  if pid_alive "$p" && [ -s "$sf" ] && [ "$(proc_sig "$p")" = "$(cat "$sf")" ]; then
    kill_tree "$p"; ok "stopped pid $p ($(basename "$f"))"
  elif pid_alive "$p"; then
    warn "pid $p ($(basename "$f")) cannot be shown to be this script's process -- left running"
  fi
  rm -f "$f" "$sf"
}
stop_runs() {
  local f
  for f in "$WORK"/run/*.pid "$WORK/ct-agent.pid"; do stop_pidfile "$f"; done
}

do_clean() {
  [ -f "$WORK/.ct-quickstart" ] || die "$WORK was not created by this script (no .ct-quickstart marker) -- refusing to remove it"
  case "$WORK" in /|"$HOME"|"${HOME:-/nonexistent}/") die "refusing to remove $WORK" ;; esac
  confirm "Stop what runs from $WORK and delete the files this script created there (keys, grants, logs)?" || die "aborted"
  stop_runs
  local x
  for x in logs run grants accept initiate site ct-agent-cert .ct-agent-state \
           operator.env inbox.txt received.txt .env .env.bak .env.new ct-agent setup.sh ssh-owner.key ssh-owner.key.new \
           ct-agent.pid ct-agent.log .ct-quickstart; do
    [ -e "$WORK/$x" ] && rm -rf "${WORK:?}/$x"
  done
  if rmdir "$WORK" 2>/dev/null; then
    DONE_MSG="removed $WORK. Not touched: your login (ct-agent login), ~/.ssh, and the channel registration at the control plane."
  else
    DONE_MSG="removed the files this script created in $WORK; the directory stays because it holds other files. Your login, ~/.ssh and the channel registration were not touched."
  fi
}

# =============================================================================================
# channel / ssh-channel
# =============================================================================================
FORWARD=0
channel_target_questions() {
  if [ "$FORWARD" -eq 1 ]; then
    ask CT_QS_FORWARD_TARGET "What may the forward reach (host:port on the accepting machine)" "127.0.0.1:22"
    ask CT_QS_LOCAL_PORT "Local port for ssh on the initiating side" "2222"
    case "$CT_QS_LOCAL_PORT" in ""|*[!0-9]*) die "CT_QS_LOCAL_PORT must be a port number" ;; esac
  fi
}

# --- one machine: operator, A and B -------------------------------------------------------
channel_single() {
  channel_target_questions
  stage "login" "run: CT_OIDC_ISSUER=<issuer> ct-agent login   (then re-run)"
  ensure_login
  stage "operator key" "check that $WORK is writable"
  ensure_operator
  stage "member identities" "check that $WORK is writable"
  ensure_member accept; ensure_member initiate
  local ha hb
  ha="$(holder_of accept)"; hb="$(holder_of initiate)"
  is_hex "$ha" && is_hex "$hb" || die "member.env files hold no holder pubkey -- delete $WORK/accept and $WORK/initiate and re-run"
  member_material accept "$hb"; member_material initiate "$ha"
  CH="$(mat accept channel_id)"
  [ -n "$CH" ] && [ "$CH" = "$(mat initiate channel_id)" ] || die "the two members derived different channel ids"
  ok "channel id $(sha8 "$CH")... (the same for both members)"

  stage "register the channel" "sign in (ct-agent login) and re-run; a 409 means a different operator key owns this id (see --rekey)"
  cp_register "$CH"
  stage "add both members" "a 401 means the token expired: re-run; any other code is printed above"
  cp_add_member accept "$CH" "$ha" "$(mat accept noise_pubkey)" "$(mat accept noise_attestation)"
  cp_add_member initiate "$CH" "$hb" "$(mat initiate noise_pubkey)" "$(mat initiate noise_attestation)"
  stage "sign the grants" "check the operator key in $WORK/operator.env"
  issue_grant accept "$CH" "$ha" accept
  issue_grant initiate "$CH" "$hb" initiate
  stage "edge values" "check that $CP/network-info and $CP/pki/ca answer (curl -fsS $CP/network-info)"
  edge_values

  if [ "$FORWARD" -eq 1 ]; then ssh_channel_run_single; else channel_run_single; fi
}

channel_run_single() {
  local msg="hello from B $(now)-$$" deadline apid=0 bpid=0 recv="$WORK/received.txt" waitfor="${CT_QS_WAIT:-90}"
  : > "$recv"
  need_operator_pub
  stage "start member A (accept)" "see $WORK/logs/accept.log; 'refused the channel join' means the member add did not take effect"
  mkfifo "$WORK/run/accept.in" 2>/dev/null || true
  exec 7<>"$WORK/run/accept.in"     # keeps A's stdin open: at end-of-file A loses the data on an edge before CADS-Tunnel v0.5.0 (#299)
  run_side accept env CT_CHANNEL_ROLE=accept "$CTA" channel <&7 >"$recv" 2>"$WORK/logs/accept.log" &
  apid=$!; echo "$apid" > "$WORK/run/accept.pid"; FG_PIDS="$apid"
  sleep "${CT_QS_A_HEAD_START:-5}"
  pid_alive "$apid" || { tail_log "$WORK/logs/accept.log"; die "member A exited right after start"; }
  record_sig "$WORK/run/accept.pid"
  ok "member A is waiting at the edge"

  stage "send the test line from B (initiate)" "see $WORK/logs/initiate.log; A's log is $WORK/logs/accept.log"
  printf '%s\n' "$msg" | run_side initiate env CT_CHANNEL_ROLE=initiate "$CTA" channel >"$WORK/logs/initiate.out" 2>"$WORK/logs/initiate.log" &
  bpid=$!; FG_PIDS="$apid $bpid"
  deadline=$(( $(now) + waitfor ))
  while [ "$(now)" -lt "$deadline" ]; do
    if grep -qF "$msg" "$recv" 2>/dev/null; then
      DONE_MSG="member B's line arrived at member A, end-to-end encrypted: '$msg' (in $recv)"
      return
    fi
    if ! pid_alive "$apid"; then tail_log "$WORK/logs/accept.log"; die "member A stopped before the line arrived"; fi
    if ! pid_alive "$bpid" && ! grep -qF "$msg" "$recv" 2>/dev/null; then
      sleep 2   # B may have finished a moment before A flushed
      grep -qF "$msg" "$recv" 2>/dev/null && continue
      tail_log "$WORK/logs/initiate.log"; tail_log "$WORK/logs/accept.log"
      die "member B ended without the line arriving at A"
    fi
    sleep 1
  done
  tail_log "$WORK/logs/initiate.log"; tail_log "$WORK/logs/accept.log"
  die "no line arrived within ${waitfor}s"
}

ssh_channel_run_single() {
  local port="$CT_QS_LOCAL_PORT" tgt="$CT_QS_FORWARD_TARGET" waitfor="${CT_QS_WAIT:-90}" deadline pa pb banner="" user
  need_operator_pub
  ask CT_QS_SSH_USER "Login name for ssh on the accepting machine" "$(id -un)"; user="$CT_QS_SSH_USER"
  pa="$(cat "$WORK/run/accept.pid" 2>/dev/null || true)"; pb="$(cat "$WORK/run/initiate.pid" 2>/dev/null || true)"
  stage "start member A (accept, serving, forward allowed to $tgt)" "see $WORK/logs/accept.log"
  local cfg="$WORK/run/forward.cfg" want="$tgt $port"
  if [ -f "$cfg" ] && [ "$(cat "$cfg")" != "$want" ]; then
    warn "the forward target or port changed ($(cat "$cfg") -> $want) -- restarting both members"
    stop_pidfile "$WORK/run/accept.pid"; stop_pidfile "$WORK/run/initiate.pid"; pa=""; pb=""
  fi
  printf '%s\n' "$want" > "$cfg"
  if ours "$WORK/run/accept.pid"; then ok "member A already running (pid $pa)"; else
    pid_alive "$pa" && warn "pid $pa in accept.pid is not this script's process -- starting a new member A"
    run_side accept env CT_CHANNEL_ROLE=accept CT_CHANNEL_SERVE=1 CT_CHANNEL_FORWARD_ALLOW="$tgt" "$CTA" channel \
      </dev/null >"$WORK/logs/accept.out" 2>"$WORK/logs/accept.log" &
    pa=$!; echo "$pa" > "$WORK/run/accept.pid"; disown "$pa" 2>/dev/null || true
    sleep "${CT_QS_A_HEAD_START:-5}"
    pid_alive "$pa" || { tail_log "$WORK/logs/accept.log"; die "member A exited right after start"; }
    record_sig "$WORK/run/accept.pid"
  fi
  stage "start member B (initiate, listener on 127.0.0.1:$port)" "see $WORK/logs/initiate.log; stop everything with: $0 --clean"
  if ours "$WORK/run/initiate.pid"; then ok "member B already running (pid $pb)"; else
    pid_alive "$pb" && warn "pid $pb in initiate.pid is not this script's process -- starting a new member B"
    : > "$WORK/logs/initiate.out"
    run_side initiate env CT_CHANNEL_ROLE=initiate CT_CHANNEL_FORWARD="127.0.0.1:$port=$tgt" "$CTA" channel \
      </dev/null >"$WORK/logs/initiate.out" 2>"$WORK/logs/initiate.log" &
    pb=$!; echo "$pb" > "$WORK/run/initiate.pid"; disown "$pb" 2>/dev/null || true
  fi
  deadline=$(( $(now) + waitfor ))
  until grep -qs "CT_CHANNEL_FORWARD 127.0.0.1:$port" "$WORK/logs/initiate.out" "$WORK/logs/initiate.log"; do
    pid_alive "$pb" || { tail_log "$WORK/logs/initiate.log"; die "member B stopped before the listener came up"; }
    [ "$(now)" -lt "$deadline" ] || { tail_log "$WORK/logs/initiate.log"; die "the listener did not come up within ${waitfor}s"; }
    sleep 1
  done
  record_sig "$WORK/run/initiate.pid"
  ok "listener is up on 127.0.0.1:$port"
  stage "probe the forward" "make sure sshd listens on the target ($tgt) of the accepting side"
  # the redirect belongs to the probe only: a bare `exec ... 2>/dev/null` would silence the whole script
  if port_open 127.0.0.1 "$port" && { exec 4<>"/dev/tcp/127.0.0.1/$port"; } 2>/dev/null; then
    IFS= read -r -t 10 banner <&4 || true
    exec 4>&-
  fi
  case "$banner" in
    SSH-*) ok "sshd answered through the channel: ${banner%$'\r'}" ;;
    *)
      tail_log "$WORK/logs/accept.log"; tail_log "$WORK/logs/initiate.log"
      die "the forward carried no data from the far side (no ssh banner). The local port being open is not enough: see the agent logs above, and check that sshd listens on $tgt of the accepting side" ;;
  esac
  DONE_MSG="the forward is up. Connect with:  ssh -p $port -o HostKeyAlias=ct-channel-$(sha8 "$CH") $user@127.0.0.1
  Stop it with:  $0 --clean   (the first ssh asks to confirm the host key of the accepting machine, not of this one)"
}

# --- several machines -----------------------------------------------------------------------
channel_operator() {
  stage "login" "run: CT_OIDC_ISSUER=<issuer> ct-agent login   (then re-run)"
  ensure_login
  stage "operator key" "check that $WORK is writable"
  ensure_operator
  {
    echo "ctq1 operator pubkey $OPERATOR_PUB"
  } | block "operator block: send this to BOTH members (public value)"
  stage "wait for both members' material" "ask each member to run: $0 ${CMD} --role member and paste back the 'material' block"
  collect "both members (their 'material' blocks)" accept:channel accept:holder accept:noise accept:attest \
    initiate:channel initiate:holder initiate:noise initiate:attest
  CH="$(inbox_get accept channel)"
  [ "$CH" = "$(inbox_get initiate channel)" ] || die "the members report different channel ids -- they used different operator or peer values; delete $INBOX and start over"
  stage "register the channel" "sign in (ct-agent login) and re-run; a 409 means a different operator key owns this id (see --rekey)"
  cp_register "$CH"
  stage "add both members" "a 401 means the token expired: re-run; any other code is printed above"
  cp_add_member accept "$CH" "$(inbox_get accept holder)" "$(inbox_get accept noise)" "$(inbox_get accept attest)"
  cp_add_member initiate "$CH" "$(inbox_get initiate holder)" "$(inbox_get initiate noise)" "$(inbox_get initiate attest)"
  stage "sign the grants" "check the operator key in $WORK/operator.env"
  issue_grant accept "$CH" "$(inbox_get accept holder)" accept
  issue_grant initiate "$CH" "$(inbox_get initiate holder)" initiate
  {
    echo "ctq1 accept grant $(tr -d ' \r\n' < "$WORK/grants/accept.grant")"
    echo "ctq1 initiate grant $(tr -d ' \r\n' < "$WORK/grants/initiate.grant")"
  } | block "grant block: send to the members (each uses its own line; valid ${CT_QS_GRANT_HOURS} h)"
  DONE_MSG="both members are added and have their grants. Tell them to paste the grant block; the accepting side must be started first."
}

channel_member() {
  ask CT_QS_SIDE "Which side is this machine (accept = starts first$([ "$FORWARD" -eq 1 ] && echo ', the one running sshd') / initiate)" ""
  case "$CT_QS_SIDE" in accept|initiate) ;; *) die "CT_QS_SIDE must be accept or initiate" ;; esac
  local side="$CT_QS_SIDE" peer; peer="$(other "$side")"
  channel_target_questions
  stage "member identity" "check that $WORK is writable"
  ensure_member "$side"
  {
    echo "ctq1 $side holder $(holder_of "$side")"
    echo "ctq1 $side noise $(noise_of "$side")"
  } | block "hello block: send to the operator and to the other member (public values)"
  stage "wait for the operator block and the other member's hello" "paste the lines the operator and the $peer member printed"
  collect "the operator and the $peer member" operator:pubkey "$peer:holder"
  OPERATOR_PUB="$(inbox_get operator pubkey)"
  member_material "$side" "$(inbox_get "$peer" holder)"
  CH="$(mat "$side" channel_id)"
  {
    echo "ctq1 $side channel $CH"
    echo "ctq1 $side holder $(mat "$side" holder_pubkey)"
    echo "ctq1 $side noise $(mat "$side" noise_pubkey)"
    echo "ctq1 $side attest $(mat "$side" noise_attestation)"
  } | block "material block: send to the operator (public values)"
  stage "wait for the grant" "the operator prints the grant block when both material blocks arrived"
  collect "the operator (the grant block)" "$side:grant"
  printf '%s\n' "$(inbox_get "$side" grant)" > "$WORK/grants/$side.grant"; chmod 600 "$WORK/grants/$side.grant"
  stage "edge values" "check that $CP/network-info and $CP/pki/ca answer"
  edge_values
  member_start "$side"
}

# join, retrying while the operator may not have finished adding the members
member_start() {
  local side="$1" tries="${CT_QS_RETRIES:-6}" i=1 rc msg
  need_operator_pub
  stage "start the $side side" "see $WORK/logs/$side.log; 'refused the channel join' means the operator has not added you yet or the grant expired"
  if [ "$side" = accept ]; then
    if [ "$FORWARD" -eq 1 ]; then
      ok "accepting side; serves every paired session; the forward may reach ${CT_QS_FORWARD_TARGET}"
      while :; do
        rc=0; run_side accept env CT_CHANNEL_ROLE=accept CT_CHANNEL_SERVE=1 CT_CHANNEL_FORWARD_ALLOW="$CT_QS_FORWARD_TARGET" \
          "$CTA" channel 2>&1 | tee "$WORK/logs/accept.log" || rc=$?
        [ "$rc" -ne 0 ] && grep -q 'refused' "$WORK/logs/accept.log" && [ "$i" -lt "$tries" ] || break
        i=$((i+1)); warn "refused -- retrying in 10 s ($i/$tries)"; sleep 10
      done
      DONE_MSG="the accepting side ran; Ctrl-C stops it."
    else
      ok "accepting side; Ctrl-C stops it. Keep this terminal open (stdin must not be closed)."
      while :; do
        rc=0; run_side accept env CT_CHANNEL_ROLE=accept "$CTA" channel 2>"$WORK/logs/accept.log" | tee "$WORK/received.txt" || rc=$?
        [ "$rc" -ne 0 ] && grep -q 'refused' "$WORK/logs/accept.log" && [ "$i" -lt "$tries" ] || break
        i=$((i+1)); warn "refused -- retrying in 10 s ($i/$tries)"; sleep 10
      done
      DONE_MSG="the accepting side ran; what arrived is in $WORK/received.txt"
    fi
    return
  fi
  if [ "$FORWARD" -eq 1 ]; then
    ok "initiating side; after the listener is up, in a second terminal:"
    echo "    ssh -p ${CT_QS_LOCAL_PORT} -o HostKeyAlias=ct-channel-$(sha8 "$CH") ${CT_QS_SSH_USER:-$(id -un)}@127.0.0.1"
    while :; do
      rc=0; run_side initiate env CT_CHANNEL_ROLE=initiate CT_CHANNEL_FORWARD="127.0.0.1:${CT_QS_LOCAL_PORT}=${CT_QS_FORWARD_TARGET}" \
        "$CTA" channel 2>&1 | tee "$WORK/logs/initiate.log" || rc=$?
      [ "$rc" -ne 0 ] && grep -q 'refused' "$WORK/logs/initiate.log" && [ "$i" -lt "$tries" ] || break
      i=$((i+1)); warn "refused -- retrying in 10 s ($i/$tries)"; sleep 10
    done
    DONE_MSG="the listener ran; Ctrl-C stops it."
    return
  fi
  ask CT_QS_MESSAGE "Test line to send" "hello from $(hostname -s 2>/dev/null || echo B)"
  msg="$CT_QS_MESSAGE"
  while :; do
    rc=0; printf '%s\n' "$msg" | run_side initiate env CT_CHANNEL_ROLE=initiate "$CTA" channel 2>"$WORK/logs/initiate.log" || rc=$?
    [ "$rc" -eq 0 ] && break
    if grep -q 'refused' "$WORK/logs/initiate.log" && [ "$i" -lt "$tries" ]; then
      i=$((i+1)); warn "refused -- the operator may not have finished; retrying in 10 s ($i/$tries)"; sleep 10; continue
    fi
    tail_log "$WORK/logs/initiate.log"; die "the initiating side failed (exit $rc)"
  done
  DONE_MSG="the line was sent. It is a success when the accepting side shows '$msg' (and in its received.txt)."
}

cmd_channel() {
  [ "$CMD" = ssh-channel ] && FORWARD=1
  [ "$FORWARD" -eq 0 ] || forward_warning
  if [ "$FORWARD" -eq 1 ] && [ "$ENABLE_FORWARD" -ne 1 ]; then
    [ "$ASSUME_YES" -eq 0 ] || die "the TCP forward is opt-in: add --enable-forward to turn it on without questions"
    confirm "Enable the TCP forward anyway?" || die "aborted"
  fi
  channel_common
  case "$ROLE" in
    "")       channel_single ;;
    operator) channel_operator ;;
    member)   channel_member ;;
    *)        die "--role $ROLE does not apply to $CMD (use operator|member)" ;;
  esac
}

# =============================================================================================
# tunnel / ssh-tunnel
# =============================================================================================
redeem() { # sets AGENT_JOIN_TOKEN / AGENT_TOKEN from CT_BOOTSTRAP
  local resp bundle
  case "$CT_BOOTSTRAP" in *[!A-Za-z0-9._~-]*) die "the bootstrap token holds characters a token never has -- copy it again from the Install page" ;; esac
  resp="$(printf '{"token":"%s"}' "$CT_BOOTSTRAP" | curl -fsS --max-redirs 0 -X POST -H 'content-type: application/json' \
          --data-binary @- "$CP/bootstrap/redeem")" || die "redeeming the token failed -- it may be expired or already used; create a new one on the Install page (a redirect is treated as an error: the token is not sent anywhere else)"
  bundle="$(printf '%s' "$resp" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')"
  AGENT_JOIN_TOKEN="$(printf '%s' "$bundle" | sed -n 's/.*CT_JOIN_TOKEN=\([^;"]*\).*/\1/p')"
  AGENT_TOKEN="$(printf '%s' "$bundle" | sed -n 's/.*CT_AGENT_TOKEN=\([^;"]*\).*/\1/p')"
  unset CT_BOOTSTRAP
  [ -n "$AGENT_JOIN_TOKEN" ] && [ -n "$AGENT_TOKEN" ] || die "the control plane answered, but the answer holds no tokens"
  [[ "$AGENT_JOIN_TOKEN" =~ $RE_TOKEN && "$AGENT_TOKEN" =~ $RE_TOKEN ]] || { AGENT_JOIN_TOKEN=""; AGENT_TOKEN=""; die "the control plane returned a token with unexpected characters -- nothing was written"; }
  ok "token redeemed"
}

write_tunnel_env() { # origin [NAME=VALUE ...]
  local f="$WORK/.env" tmp="$WORK/.env.new" origin="$1" kv; shift
  {
    env_kv CT_AGENT_JOIN_TOKEN "$AGENT_JOIN_TOKEN"; env_kv CT_AGENT_TOKEN "$AGENT_TOKEN"
    env_kv CT_AGENT_CP_URL "$CP"; env_kv CT_AGENT_HOSTNAME "$HOSTNAME_"
    env_kv CT_AGENT_ORIGIN "$origin"; env_kv CT_AGENT_ORIGIN_PROTO tcp
    for kv in "$@"; do env_kv "${kv%%=*}" "${kv#*=}"; done
  } > "$tmp"
  chmod 600 "$tmp"
  [ ! -f "$f" ] || cp -p "$f" "$WORK/.env.bak"
  mv -f "$tmp" "$f"
}
envval() { sed -n "s/^$1=//p" "$WORK/.env" | head -1; }

run_setup() { # extra args...
  local s out rc=0
  s="$(setup_sh)"
  out="$WORK/logs/setup.log"
  # setup.sh prints the routing token in its Gelb hint; the redaction keeps it out of the terminal and the log
  set +e
  (cd "$WORK" && env -u CT_BOOTSTRAP bash "$s" "$@") 2>&1 | redact "$AGENT_TOKEN" "$AGENT_JOIN_TOKEN" | tee "$out"
  rc=${PIPESTATUS[0]}
  set -e
  [ "$rc" -eq 0 ] || return 1
  TIER="$(sed -n 's/.*current tier: *\([A-Za-zü]*\).*/\1/p' "$out" | tail -1)"
}

demo_origin() { # host:port
  local h="${1%:*}" p="${1##*:}"
  if port_open "$h" "$p"; then ok "something already answers on $1"; return; fi
  if [ "$DEMO_ORIGIN" -ne 1 ] || [ "$1" != "127.0.0.1:8080" ]; then
    warn "nothing listens on $1 yet -- start the service you want to publish there"; return
  fi
  command -v python3 >/dev/null 2>&1 || { warn "nothing listens on $1 and python3 is missing -- start your service there"; return; }
  mkdir -p "$WORK/site"; [ -f "$WORK/site/index.html" ] || echo "<h1>ct-agent quickstart</h1>" > "$WORK/site/index.html"
  (cd "$WORK/site" && nohup python3 -m http.server 8080 --bind 127.0.0.1 >"$WORK/logs/demo-origin.log" 2>&1 & echo $! > "$WORK/run/demo-origin.pid")
  sleep 1; record_sig "$WORK/run/demo-origin.pid"
  ok "started a throw-away web server on 127.0.0.1:8080 (pid $(cat "$WORK/run/demo-origin.pid")); '--clean' stops it"
}

tunnel_questions() {
  ask CT_AGENT_CP_URL "Control plane" "$DEFAULT_CP"
  CP="${CT_AGENT_CP_URL%/}"; check_cp "$CP"
  if [ -f "$WORK/.env" ] && grep -q '^CT_AGENT_TOKEN=' "$WORK/.env"; then
    ok ".env found in $WORK -- reusing hostname and tokens"
    HOSTNAME_="$(envval CT_AGENT_HOSTNAME)"; AGENT_TOKEN="$(envval CT_AGENT_TOKEN)"; AGENT_JOIN_TOKEN="$(envval CT_AGENT_JOIN_TOKEN)"
    ORIGIN="$(envval CT_AGENT_ORIGIN)"
    need "CT_AGENT_HOSTNAME in .env" "$HOSTNAME_" "$RE_HOST"; need "CT_AGENT_ORIGIN in .env" "$ORIGIN" "$RE_ORIGIN"
    need "CT_AGENT_TOKEN in .env" "$AGENT_TOKEN" "$RE_TOKEN"; need "CT_AGENT_JOIN_TOKEN in .env" "$AGENT_JOIN_TOKEN" "$RE_TOKEN"
    if [ -n "${CT_AGENT_HOSTNAME:-}" ] && [ "$CT_AGENT_HOSTNAME" != "$HOSTNAME_" ]; then
      die "$WORK/.env is for $HOSTNAME_, not $CT_AGENT_HOSTNAME. Use --clean first, or another --workdir"
    fi
    return
  fi
  ask CT_AGENT_HOSTNAME "Hostname of the tunnel (as on the Install page)" ""
  HOSTNAME_="$CT_AGENT_HOSTNAME"; need "CT_AGENT_HOSTNAME" "$HOSTNAME_" "$RE_HOST"
  ask CT_BOOTSTRAP "Bootstrap token of the Install page (hidden)" "" secret
  ask CT_AGENT_ORIGIN "What to publish (host:port on this machine)" "127.0.0.1:8080"
  ORIGIN="$CT_AGENT_ORIGIN"; need "CT_AGENT_ORIGIN" "$ORIGIN" "$RE_ORIGIN"
  stage "redeem the token" "create a fresh token on the Install page and re-run (a token works once)"
  redeem
  write_tunnel_env "$ORIGIN"
  ok ".env written ($WORK/.env, mode 0600)"
}

tunnel_up() {
  stage "check the machine" "install curl; for --docker also install docker"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  [ "$DOCKER" -eq 0 ] || command -v docker >/dev/null 2>&1 || die "docker not found"
  if [ "$DOCKER" -eq 0 ]; then
    warn "The agent will run directly on this machine; it is meant for a VM, a container or a dedicated host."
    confirm "Continue with a direct-host install?" || die "aborted (use --docker to run it as a container)"
  fi
  stage "start the agent" "see $WORK/ct-agent.log and $WORK/logs/setup.log"
  demo_origin "$ORIGIN"
  local args=(--yes); [ "$DOCKER" -eq 0 ] || args=(--docker)
  run_setup ${args[@]+"${args[@]}"} || die "setup.sh failed"
  if [ "$DOCKER" -eq 0 ]; then
    pid_alive "$(cat "$WORK/ct-agent.pid" 2>/dev/null || true)" || die "the agent is not running after setup"
    record_sig "$WORK/ct-agent.pid"
    ok "agent running, pid $(cat "$WORK/ct-agent.pid")"
  fi
  case "$TIER" in
    gelb|gruen|Gelb|Grün|Gruen) ok "tier: $TIER" ;;
    *) HINT="the tier is still '${TIER:-unknown}'; read $WORK/ct-agent.log, then re-run (it resumes)"; die "the tunnel did not reach Gelb" ;;
  esac
}

verify_tunnel_url() {
  stage "check the public URL" "the agent is up; check that $ORIGIN answers locally, then: curl -I https://$HOSTNAME_/"
  local i code=""
  for i in 1 2 3 4 5 6; do
    code="$(curl -sS -o /dev/null -m 10 -w '%{http_code}' "https://$HOSTNAME_/" 2>/dev/null || true)"
    case "$code" in 2*|3*|4*) break ;; esac
    sleep 5
  done
  case "$code" in
    2*|3*) ok "https://$HOSTNAME_/ answered $code" ;;
    4*)    warn "https://$HOSTNAME_/ answered $code (reachable, but your service said no to /)"; ok "the tunnel carries traffic" ;;
    *)     HINT="the tunnel is registered but the URL did not answer; check DNS for $HOSTNAME_ and that $ORIGIN serves plain HTTP at tier Gelb"; die "no answer from https://$HOSTNAME_/" ;;
  esac
  PUBLIC_CODE="$code"
}

cmd_tunnel() {
  tunnel_questions
  tunnel_up
  verify_tunnel_url
  DONE_MSG="https://$HOSTNAME_/ answers ($PUBLIC_CODE), tier ${TIER}. Stop: $0 --clean. Own certificate (Grün): see 'ssh-tunnel' or the hint printed by setup.sh."
}

cmd_ssh_tunnel_client() {
  stage "install the CLI" "install curl, or put ct-agent on PATH"
  ensure_cli
  ask CT_AGENT_HOSTNAME "Hostname of the tunnel (the ssh host)" ""
  ask CT_QS_SSH_USER "Your login name on the agent host" "$(id -un)"
  local kf="${CT_QS_OWNER_KEY_FILE:-}" dest ssh_dir="${HOME}/.ssh" stanza
  [ -n "$kf" ] || { [ -s "$WORK/ssh-owner.key" ] && kf="$WORK/ssh-owner.key"; } || true
  if [ -z "$kf" ]; then CT_QS_OWNER_KEY_FILE=""; ask CT_QS_OWNER_KEY_FILE "File with the owner key the agent host printed (ssh-owner.key)" ""; kf="$CT_QS_OWNER_KEY_FILE"; fi
  [ -s "$kf" ] || die "owner key file $kf not found or empty -- copy ssh-owner.key from the agent host's quickstart directory"
  stage "write the ssh config" "check that $ssh_dir is writable"
  mkdir -p "$ssh_dir"; chmod 700 "$ssh_dir"
  dest="$ssh_dir/ct-agent-$CT_AGENT_HOSTNAME.owner"
  if [ -f "$dest" ] && ! cmp -s "$kf" "$dest" && [ "$ALLOW_KEY_OVERWRITE" -ne 1 ]; then
    [ "$ASSUME_YES" -eq 0 ] || die "$dest exists and differs -- add --allow-ssh-key-overwrite to replace it; nothing changed"
    confirm "$dest exists and differs -- overwrite it?" || die "kept the existing key; nothing changed"
  fi
  cp "$kf" "$dest"; chmod 600 "$dest"
  if grep -qs "^Host $CT_AGENT_HOSTNAME\$" "$ssh_dir/config"; then
    ok "$ssh_dir/config already has a stanza for $CT_AGENT_HOSTNAME -- left as it is"
  else
    stanza="$("$CTA" ssh-config "$CT_AGENT_HOSTNAME" --user "$CT_QS_SSH_USER" --owner-key-file "$dest")" || die "ct-agent ssh-config failed"
    # the stanza calls the CLI by name; make it the absolute path when ct-agent is not on PATH
    if ! command -v ct-agent >/dev/null 2>&1; then
      case "$CTA" in *[!A-Za-z0-9._/+-]*) stanza="${stanza//ProxyCommand ct-agent /ProxyCommand \'$CTA\' }" ;; *) stanza="${stanza//ProxyCommand ct-agent /ProxyCommand $CTA }" ;; esac
    fi
    if [ "$APPEND_SSH_CONFIG" -ne 1 ]; then
      if [ "$ASSUME_YES" -eq 1 ]; then
        printf '%s\n' "$stanza" >&2
        DONE_MSG="the stanza above was NOT added to $ssh_dir/config (--yes does not edit it). Add it yourself or re-run with --append-ssh-config."
        return 0
      fi
      confirm "Append the stanza for $CT_AGENT_HOSTNAME to $ssh_dir/config?" || die "not appended; the stanza is: $stanza"
    fi
    printf '\n%s\n' "$stanza" >> "$ssh_dir/config"; chmod 600 "$ssh_dir/config"
    ok "stanza appended to $ssh_dir/config"
  fi
  if ! command -v ct-agent >/dev/null 2>&1; then
    DONE_MSG="ready, using $CTA in the ssh config (ct-agent is not on your PATH). Connect with:  ssh $CT_AGENT_HOSTNAME"; return 0
  fi
  DONE_MSG="ready. Connect with:  ssh $CT_AGENT_HOSTNAME   (you get the shell prompt of the agent host if sshd accepts your login)"
}

cmd_ssh_tunnel() {
  case "$ROLE" in client) cmd_ssh_tunnel_client; return ;; ""|host) ;; *) die "--role $ROLE does not apply to ssh-tunnel (use host|client)" ;; esac
  [ "$DOCKER" -eq 0 ] || die "ssh-tunnel runs the agent directly on the host (it needs the certificate pair and the owner key on disk); drop --docker"
  log "what tier Grün needs (checked below, in this order):"
  echo "    - a tunnel at tier Gelb first: its origin must serve plain HTTP while the certificate is issued (a throw-away web server is started for that)"
  echo "    - this machine reaches the control plane over TLS and the hostname resolves to the edge"
  echo "    - sshd listens on 127.0.0.1:22 of this machine"
  stage "check the machine" "install curl; start sshd; then re-run"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  if port_open 127.0.0.1 22; then ok "sshd answers on 127.0.0.1:22"; else warn "nothing listens on 127.0.0.1:22 -- the tunnel will come up, ssh will be refused until sshd runs"; fi
  tunnel_questions
  stage "install the CLI" "install curl, or put ct-agent on PATH"
  ensure_cli
  if [ "$(envval CT_AGENT_ORIGIN_TLS)" = terminate ]; then
    ok "the agent is already configured for ssh (terminate mode) -- resuming"
    if ! pid_alive "$(cat "$WORK/ct-agent.pid" 2>/dev/null || true)"; then
      stage "restart the agent" "see $WORK/ct-agent.log"
      run_setup --yes || die "setup.sh failed while restarting the agent"
      pid_alive "$(cat "$WORK/ct-agent.pid" 2>/dev/null || true)" && record_sig "$WORK/ct-agent.pid"
    fi
  else
    [ "$ORIGIN" = "127.0.0.1:8080" ] || warn "the first phase needs an origin that serves plain HTTP; $ORIGIN will be replaced by 127.0.0.1:22 afterwards"
    tunnel_up
    stage "get the certificate (tier Grün)" "read $WORK/logs/certificate.log; at tier Rot/Gelb wait and re-run"
    local cdir="$WORK/ct-agent-cert" i=0 cwait="${CT_QS_CERT_WAIT:-180}"
    cert_done() { [ -s "$cdir/fullchain.pem" ] && [ -s "$cdir/privkey.pem" ]; }
    if cert_done; then ok "certificate pair already in $cdir"; else
      mkdir -p "$cdir"
      (cd "$WORK" && CT_AGENT_CP_URL="$CP" CT_AGENT_TOKEN="$AGENT_TOKEN" CT_AGENT_HOSTNAME="$HOSTNAME_" CT_ACME_CERT_OUT_DIR="$cdir" \
        nohup "$CTA" certificate >"$WORK/logs/certificate.log" 2>&1 & echo $! > "$WORK/run/certificate.pid")
      while ! cert_done; do
        pid_alive "$(cat "$WORK/run/certificate.pid")" || { tail_log "$WORK/logs/certificate.log"; die "ct-agent certificate stopped before it wrote the pair"; }
        [ "$i" -lt "$cwait" ] || { tail_log "$WORK/logs/certificate.log"; die "no certificate after ${cwait}s"; }
        i=$((i+2)); sleep 2
      done
      ok "certificate pair written to $cdir (ct-agent certificate keeps running and renews it)"
    fi
    stage "switch the agent to ssh" "see $WORK/ct-agent.log (it may hold the owner key: do not share it); the previous .env is in $WORK/.env.bak"
    stop_pidfile "$WORK/ct-agent.pid"; sleep 1
    write_tunnel_env "127.0.0.1:22" CT_AGENT_MODE=browser CT_AGENT_ORIGIN_TLS=terminate "CT_ACME_CERT_OUT_DIR=$cdir"
    ok ".env switched to 127.0.0.1:22 / terminate (old one kept as .env.bak)"
    run_setup --yes || die "setup.sh failed in the second phase"
  fi
  pid_alive "$(cat "$WORK/ct-agent.pid" 2>/dev/null || true)" || die "the agent is not running"
  stage "owner key" "run in $WORK: CT_AGENT_STATE_DIR=./.ct-agent-state ct-agent ssh-owner init"
  (cd "$WORK" && CT_AGENT_STATE_DIR=./.ct-agent-state "$CTA" ssh-owner init > ssh-owner.key.new 2>"$WORK/logs/ssh-owner.log") \
    || { tail_log "$WORK/logs/ssh-owner.log"; die "ssh-owner init failed"; }
  chmod 600 "$WORK/ssh-owner.key.new"; mv -f "$WORK/ssh-owner.key.new" "$WORK/ssh-owner.key"
  ok "owner key saved to $WORK/ssh-owner.key (mode 0600; this script does not print it)"
  warn "the agent also wrote the owner key to $WORK/ct-agent.log on its first start -- treat that file as secret and do not share it"
  DONE_MSG="the agent host is ready for ssh at $HOSTNAME_.
  On the client: copy $WORK/ssh-owner.key there (scp), then run
    CT_AGENT_HOSTNAME=$HOSTNAME_ CT_QS_OWNER_KEY_FILE=./ssh-owner.key $0 ssh-tunnel --role client
  and connect with:  ssh $HOSTNAME_      (stop the host side with: $0 --clean)"
}

# --- main ----------------------------------------------------------------------------------
main() {
  command -v ps >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 \
    || die "ps and pgrep are required to stop only the processes this script started -- install procps (or run on macOS/Linux)"
  ps -p $$ -o lstart=,command= >/dev/null 2>&1 \
    || die "this system's ps does not support 'ps -p PID -o lstart=,command=' -- the script cannot tell its own processes apart, so it will not run"
  if [ "$DO_CLEAN" -eq 1 ]; then do_clean; return; fi
  case "$CMD" in
    tunnel)      cmd_tunnel ;;
    channel|ssh-channel) cmd_channel ;;
    ssh-tunnel)  cmd_ssh_tunnel ;;
  esac
}
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  main
fi
