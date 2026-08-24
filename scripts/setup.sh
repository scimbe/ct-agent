#!/usr/bin/env bash
# ct-agent guided setup (Linux/macOS) — a richer, optional alternative to the
# portal's thin curl-pipe-sh one-liner (CADS-Tunnel's /install.sh). Checks your
# environment, walks you through a .env file, optionally grabs a starter
# template, installs + onboards the agent (directly on this host, or as a
# Docker container), then reports your tunnel's certificate tier (Rot/Gelb/
# Grün) and the commands you need to stop/reset it or go from Gelb to Grün.
#
#   ./scripts/setup.sh                  # direct-host install (asks to confirm)
#   ./scripts/setup.sh --docker         # run as a Docker container instead
#   ./scripts/setup.sh --yes            # skip the sandbox-warning confirmation
#   ./scripts/setup.sh --template       # also fetch the starter site template
#   ./scripts/setup.sh --green          # push straight through to Grün (own cert)
#   ./scripts/setup.sh --help
#
# Env overrides: CT_RELEASE_BASE (default: this repo's GitHub releases), NO_COLOR.
set -euo pipefail

# --- pretty output (matches CADS-Tunnel's scripts/install.sh convention) ------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B="\033[1m"; C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_0="\033[0m"
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi
log()  { printf "${C_B}==>${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}  ✓${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}  !${C_0} %s\n" "$*" >&2; }
die()  { printf "${C_R}error:${C_0} %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
ct-agent guided setup (Linux/macOS) — a richer, optional alternative to the
portal's thin curl-pipe-sh one-liner (CADS-Tunnel's /install.sh). Checks your
environment, walks you through a .env file, optionally grabs a starter
template, installs + onboards the agent (directly on this host, or as a
Docker container), then reports your tunnel's certificate tier (Rot/Gelb/
Grün) and the commands you need to stop/reset it or go from Gelb to Grün.

  ./scripts/setup.sh                  # direct-host install (asks to confirm)
  ./scripts/setup.sh --docker         # run as a Docker container instead
  ./scripts/setup.sh --yes            # skip the sandbox-warning confirmation
  ./scripts/setup.sh --template       # also fetch the starter site template
  ./scripts/setup.sh --green          # push straight through to Grün (own cert)
  ./scripts/setup.sh --help

Env overrides: CT_RELEASE_BASE (default: this repo's GitHub releases), NO_COLOR.
USAGE
  exit "${1:-0}"
}

RELEASE_BASE="${CT_RELEASE_BASE:-https://github.com/scimbe/ct-agent/releases/latest/download}"
MODE="direct"
ASSUME_YES=0
WANT_TEMPLATE=0
WANT_GREEN=0
STATE_DIR="${CT_AGENT_STATE_DIR:-./.ct-agent-state}"
PID_FILE="./ct-agent.pid"

while [ $# -gt 0 ]; do
  case "$1" in
    --docker)   MODE="docker" ;;
    --yes)      ASSUME_YES=1 ;;
    --template) WANT_TEMPLATE=1 ;;
    --green)    WANT_GREEN=1 ;;
    -h|--help)  usage 0 ;;
    *)          die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# --- 1. environment check ------------------------------------------------------
os=""
arch=""
detect_env() {
  log "checking your environment"
  local u_os u_arch
  u_os=$(uname -s | tr '[:upper:]' '[:lower:]')
  u_arch=$(uname -m)
  case "$u_os" in
    linux|darwin) os="$u_os" ;;
    *) die "unsupported OS '$u_os' — this script covers Linux/macOS only (see scripts/setup.ps1 for Windows)" ;;
  esac
  case "$u_arch" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    i686|i386)     arch=i686 ;;
    *) die "unsupported architecture '$u_arch'" ;;
  esac
  ok "OS/arch: ${os}/${arch}"

  command -v curl >/dev/null 2>&1 || die "curl is required but not found — install it and re-run"
  ok "curl present"

  if [ "$MODE" = "docker" ]; then
    command -v docker >/dev/null 2>&1 || die "docker not found — install it from https://docs.docker.com/get-docker/ and re-run with --docker"
    ok "docker present"
  fi

  if [ "$WANT_TEMPLATE" -eq 1 ]; then
    # maybe_install_template unconditionally shells out to unzip -- found live
    # (this host has curl but no unzip) that without this check it fails with a
    # raw "unzip: command not found" instead of this script's own clear,
    # actionable die messages.
    command -v unzip >/dev/null 2>&1 || die "unzip is required for --template but not found — install it and re-run"
    ok "unzip present"
  fi
}

# --- 2. mode select + sandbox warning ------------------------------------------
confirm_mode() {
  if [ "$MODE" = "docker" ]; then
    log "mode: Docker container (recommended isolation)"
    return
  fi
  log "mode: direct install on this host"
  warn "ct-agent is a network-facing process that will run directly on this machine."
  warn "It's designed to run inside an isolated environment (a VM, a container, or a"
  warn "dedicated host) — not on a machine holding data/credentials you wouldn't want"
  warn "reachable if this agent were ever compromised. Prefer --docker if unsure."
  if [ "$ASSUME_YES" -eq 1 ]; then
    ok "proceeding (--yes)"
    return
  fi
  if [ ! -t 0 ]; then
    die "not an interactive terminal — pass --yes to confirm direct-host install non-interactively"
  fi
  printf "Continue with a direct-host install? [y/N] "
  read -r reply
  case "$reply" in
    y|Y|yes|YES) ok "confirmed" ;;
    *) die "aborted" ;;
  esac
}

# --- 3. .env handling -----------------------------------------------------------
write_env_template() {
  cat > .env.example <<'EOF'
# ct-agent tunnel config -- get these values from your tunnel's page on
# the portal (Install button), then re-run ./scripts/setup.sh.
#
# Preferred: a single short-lived bootstrap token (never touches disk/history
# beyond this file); the script redeems it for real credentials server-side.
CT_BOOTSTRAP=

# Alternative to CT_BOOTSTRAP: the two tokens it would have redeemed into.
#CT_AGENT_JOIN_TOKEN=
#CT_AGENT_TOKEN=

# Your control plane (the portal's own URL).
CT_AGENT_CP_URL=https://bunsenbrenner.org

# The hostname the portal assigned (or you configured) for this tunnel.
CT_AGENT_HOSTNAME=

# Where your own site/service is actually running, and how ct-agent should
# forward to it. tcp+host:port for a plain backend; while your tunnel is
# Gelb, this origin must serve PLAIN HTTP (not TLS) -- see the Gelb->Gruen
# note this script prints after onboarding.
CT_AGENT_ORIGIN=127.0.0.1:8080
CT_AGENT_ORIGIN_PROTO=tcp
EOF
}

ensure_env() {
  log "checking for .env"
  if [ -f .env ]; then
    ok ".env found"
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
  elif [ -n "${CT_BOOTSTRAP:-}" ] || { [ -n "${CT_AGENT_JOIN_TOKEN:-}" ] && [ -n "${CT_AGENT_TOKEN:-}" ]; }; then
    # Real gap found live (help.bunsenbrenner.org sandbox-instructions work): a
    # genuine one-liner (CT_BOOTSTRAP=... curl ... | sh, matching the portal's
    # own rendered command in installer.rs's install_one_liner_bootstrap) could
    # never actually complete non-interactively -- this gate unconditionally
    # demanded a real .env FILE on disk even when the one secret that actually
    # matters was already sitting right there in the process environment.
    # Every other required var (CT_AGENT_CP_URL/CT_AGENT_HOSTNAME/CT_AGENT_ORIGIN)
    # is still validated by the `missing` check below regardless of source.
    ok "no .env file, but a real bootstrap/join token is already set in the environment — proceeding without one"
  else
    warn ".env not found in $(pwd)"
    write_env_template
    warn "wrote .env.example — copy it to .env, fill in the values from your portal"
    warn "tunnel page, then re-run this script. Stopping here."
    exit 1
  fi

  if [ -n "${CT_BOOTSTRAP:-}" ]; then
    log "redeeming CT_BOOTSTRAP server-side"
    : "${CT_AGENT_CP_URL:?set CT_AGENT_CP_URL in .env}"
    local resp bundle
    resp=$(curl -fsSL -X POST -H 'content-type: application/json' \
      --data "{\"token\":\"$CT_BOOTSTRAP\"}" "${CT_AGENT_CP_URL%/}/bootstrap/redeem") \
      || die "bootstrap redeem failed — the token may be expired/already used"
    bundle=$(printf '%s' "$resp" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
    CT_AGENT_JOIN_TOKEN=$(printf '%s' "$bundle" | sed -n 's/.*CT_JOIN_TOKEN=\([^;"]*\).*/\1/p')
    CT_AGENT_TOKEN=$(printf '%s' "$bundle" | sed -n 's/.*CT_AGENT_TOKEN=\([^;"]*\).*/\1/p')
    export CT_AGENT_JOIN_TOKEN CT_AGENT_TOKEN
    ok "bootstrap redeemed"
  fi

  local missing=()
  for v in CT_AGENT_CP_URL CT_AGENT_HOSTNAME CT_AGENT_ORIGIN; do
    [ -n "${!v:-}" ] || missing+=("$v")
  done
  [ -n "${CT_AGENT_JOIN_TOKEN:-}" ] || missing+=("CT_AGENT_JOIN_TOKEN (or CT_BOOTSTRAP)")
  [ -n "${CT_AGENT_TOKEN:-}" ] || missing+=("CT_AGENT_TOKEN (or CT_BOOTSTRAP)")
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "missing/blank in .env: ${missing[*]}"
    die "fill these in and re-run"
  fi
  ok "required variables present"

  # Deployment-wide defaults ct-agent needs but a customer wouldn't usually set
  # by hand -- mirrors CADS-Tunnel's own /install.sh (installer.rs). Missing
  # CT_AGENT_EDGE_CERT_URL in particular makes the agent hang forever, not just
  # error, so this is defaulted rather than left optional.
  : "${CT_AGENT_MODE:=browser}"
  : "${CT_AGENT_EDGE_CERT_URL:=$CT_AGENT_CP_URL}"
  # ct-agent itself defaults CT_AGENT_ORIGIN_PROTO to tcp when unset (config.rs) --
  # this was wrongly required above (pre-dating this default in the .env template),
  # breaking any .env written before this var existed. Match the binary's own default
  # instead of hard-requiring it. Found live: a customer with an older .env (no
  # CT_AGENT_ORIGIN_PROTO line at all) hit "missing/blank in .env" for a value the
  # agent would have happily defaulted itself.
  : "${CT_AGENT_ORIGIN_PROTO:=tcp}"
  # A fresh CT_AGENT_ID every run would break restore: ct-agent's onboard_or_restore
  # only reuses persisted identity/tenant when CT_AGENT_ID matches the "agent" file
  # written at onboard time (src/onboard.rs's OnboardedAgent::restore) -- otherwise
  # it silently falls through to re-onboarding with the (already single-use-spent)
  # join token and the background process dies on a 409, right after this script's
  # own "already onboarded, skipping onboard" line claimed success. Found live: a
  # second run against existing state crashed the backgrounded agent this way.
  if [ -z "${CT_AGENT_ID:-}" ] && [ -f "$STATE_DIR/agent" ]; then
    CT_AGENT_ID="$(cat "$STATE_DIR/agent")"
  fi
  : "${CT_AGENT_ID:=agent-$(date +%s)-$$}"
  # ct-agent defaults this to /shared/capability.bin -- a path from CADS-Tunnel's
  # own docker-compose shared volume that doesn't exist on a customer's machine.
  # Without overriding it, onboarding fails (ENOENT) right after fetching the
  # edge cert.
  : "${CT_AGENT_CAPABILITY_OUT:=$STATE_DIR/capability.bin}"
  : "${CT_AGENT_EDGE:=}"
  if [ -z "$CT_AGENT_EDGE" ]; then
    # /network-info returns just the port ({"mesh_edge_port":4433,...}), not a
    # host:port string -- the host is the same one CT_AGENT_CP_URL points at.
    local ni edge_host edge_port
    ni=$(curl -fsSL "${CT_AGENT_CP_URL%/}/network-info" 2>/dev/null || true)
    edge_port=$(printf '%s' "$ni" | sed -n 's/.*"mesh_edge_port":\([0-9]*\).*/\1/p')
    edge_host=$(printf '%s' "$CT_AGENT_CP_URL" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*##')
    [ -n "$edge_port" ] && [ -n "$edge_host" ] && CT_AGENT_EDGE="${edge_host}:${edge_port}"
    [ -n "$CT_AGENT_EDGE" ] || die "could not determine CT_AGENT_EDGE automatically — set it in .env (host:port of the mesh edge)"
  fi
  # ct-agent reads/writes its bound-identity state here but doesn't create the
  # directory itself -- onboarding fails (ENOENT) on a fresh checkout otherwise.
  mkdir -p "$STATE_DIR"
  export CT_AGENT_MODE CT_AGENT_EDGE_CERT_URL CT_AGENT_ID CT_AGENT_EDGE CT_AGENT_CAPABILITY_OUT \
    CT_AGENT_ORIGIN_PROTO CT_AGENT_STATE_DIR="$STATE_DIR"
}

# --- 4. optional template -------------------------------------------------------
maybe_install_template() {
  [ "$WANT_TEMPLATE" -eq 1 ] || return 0
  log "fetching the starter site template"
  mkdir -p template
  curl -fsSL "${CT_AGENT_CP_URL%/}/downloads/hello-world-pipeline.zip" -o template/hello-world-pipeline.zip \
    || { warn "template download failed — skipping"; return 0; }
  (cd template && unzip -o -q hello-world-pipeline.zip && rm -f hello-world-pipeline.zip)
  ok "template unpacked into ./template"
}

# --- 5. install + onboard -------------------------------------------------------
install_direct() {
  local asset="ct-agent-${os}-${arch}"
  local url="${RELEASE_BASE%/}/${asset}"
  log "downloading $asset"
  curl -fsSL "$url" -o ./ct-agent -w '' || die "download failed: $url"
  chmod +x ./ct-agent
  ok "ct-agent binary ready"

  local fresh=1
  if [ -d "$STATE_DIR" ] && [ -n "$(ls -A "$STATE_DIR" 2>/dev/null || true)" ]; then
    ok "existing state in $STATE_DIR — restoring bound identity"
    fresh=0
  fi

  # `ct-agent onboard` (and the bare invocation with CT_AGENT_JOIN_TOKEN set --
  # they're the same code path) never returns: once onboarding succeeds it
  # falls straight into serving, forever, in the foreground. A prior version
  # of this script called `./ct-agent onboard` synchronously before
  # backgrounding a separate serve process -- on a genuinely fresh install
  # that just hung forever, since onboard never gets to the point of
  # returning. Found live. Fix: always background it up front, then on a
  # fresh install confirm onboarding actually completed by watching for its
  # persisted state file rather than waiting on the process to exit.
  log "starting ct-agent in the background"
  nohup ./ct-agent >./ct-agent.log 2>&1 &
  echo $! > "$PID_FILE"

  sleep 1
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || die "ct-agent exited immediately — see ./ct-agent.log for details"

  if [ "$fresh" -eq 1 ]; then
    log "onboarding (this reads CT_AGENT_JOIN_TOKEN/CT_AGENT_TOKEN from the environment, never the command line)"
    local deadline=$((SECONDS + 45))
    while [ "$SECONDS" -lt "$deadline" ]; do
      [ -f "$STATE_DIR/tenant" ] && break
      kill -0 "$(cat "$PID_FILE")" 2>/dev/null || die "onboarding failed — see ./ct-agent.log for details"
      sleep 1
    done
    if [ ! -f "$STATE_DIR/tenant" ]; then
      kill "$(cat "$PID_FILE")" 2>/dev/null || true
      rm -f "$PID_FILE"
      die "onboarding did not complete within 45s — see ./ct-agent.log for details"
    fi
    ok "onboarded"
  fi

  ok "running, pid $(cat "$PID_FILE") (logs: ./ct-agent.log)"
}

install_docker() {
  log "building the Docker image"
  # Build straight from this repo's git history (docker supports git-URL build
  # contexts natively) rather than a local ../docker path -- this script is
  # commonly run via `curl ... | bash`, where no local checkout exists.
  # buildx (not the classic builder) is required here: the Dockerfile's
  # TARGETOS/TARGETARCH build args are only auto-populated by buildx, and a
  # plain `docker build` leaves them empty, failing with "unsupported
  # TARGETARCH: " on every platform (#3).
  docker buildx build --load -t ct-agent:local "https://github.com/scimbe/ct-agent.git#main:docker" \
    || die "docker build failed"
  log "starting the container"
  docker rm -f ct-agent >/dev/null 2>&1 || true
  docker run -d --name ct-agent --env-file .env -v "$(pwd)/$STATE_DIR:/state" \
    -e CT_AGENT_STATE_DIR=/state ct-agent:local || die "docker run failed"
  ok "container 'ct-agent' running (logs: docker logs -f ct-agent)"
}

# --- 6. bring up to Gelb (default) or Grün --------------------------------------
poll_status() {
  log "checking certificate tier (Rot -> Gelb -> Grün)"
  local deadline=$((SECONDS + 120))
  local status="" last=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    local resp
    resp=$(curl -fsSL "${CT_AGENT_CP_URL%/}/agent/acme-admission/${CT_AGENT_TOKEN}/${CT_AGENT_HOSTNAME}" 2>/dev/null || true)
    status=$(printf '%s' "$resp" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
    if [ -n "$status" ] && [ "$status" != "$last" ]; then
      case "$status" in
        rot)   warn "🔴 Rot — still being set up, waiting..." ;;
        gelb)  ok "🟡 Gelb — live now via the shared certificate" ;;
        gruen) ok "🟢 Grün — your own certificate, fully zero-knowledge"; break ;;
      esac
      last="$status"
    fi
    [ "$status" = "gruen" ] && break
    [ "$status" = "gelb" ] && [ "$WANT_GREEN" -eq 0 ] && break
    sleep 3
  done

  if [ "$status" = "gelb" ] && [ "$WANT_GREEN" -eq 1 ]; then
    warn "Gelb->Grün: your origin (${CT_AGENT_ORIGIN}) must serve PLAIN HTTP right now,"
    warn "not TLS — it only needs its own certificate once Grün is reached."
    if [ "$MODE" = "docker" ]; then
      # There is no ./ct-agent on the host in Docker mode -- only inside the
      # container -- so the direct-mode "run it locally in the background" path
      # below would silently fail (exec: no such file) while still printing a
      # false success message. Found live: reproduced the exact ENOENT/exit-127
      # failure before this fix. Rather than guess at a docker-exec + docker-cp
      # flow that can't be round-trip tested here without a real registered
      # tunnel, tell the customer exactly what to run themselves.
      warn "--green isn't automated in --docker mode yet — run this yourself once you're ready:"
      warn "  docker exec ct-agent sh -c 'CT_ACME_CERT_OUT_DIR=/ct-agent-cert ct-agent certificate' &"
      warn "  # then, once it reports Grün above: docker cp ct-agent:/ct-agent-cert ./ct-agent-cert"
    else
      log "requesting your own certificate (ct-agent certificate)"
      CT_ACME_CERT_OUT_DIR="${CT_ACME_CERT_OUT_DIR:-./ct-agent-cert}" \
        ./ct-agent certificate >>./ct-agent.log 2>&1 &
      ok "certificate issuance running in the background (watch ./ct-agent.log)"
    fi
  fi
  FINAL_STATUS="${status:-unknown}"
}

# --- 7. final report -------------------------------------------------------------
final_report() {
  echo
  log "done — current tier: ${FINAL_STATUS:-unknown}"
  if [ "$MODE" = "docker" ]; then
    echo "  stop:   docker stop ct-agent"
    echo "  reset:  docker rm -f ct-agent && rm -rf ${STATE_DIR} && ./scripts/setup.sh --docker"
  else
    echo "  stop:   kill \$(cat ${PID_FILE}) 2>/dev/null || true"
    echo "  reset:  kill \$(cat ${PID_FILE}) 2>/dev/null; rm -rf ${STATE_DIR} ${PID_FILE}; ./scripts/setup.sh"
    echo "  rotate origin key only (keep the same tunnel): ./ct-agent rotate"
  fi
  echo "  full revoke/delete of the tunnel itself: use the portal UI (${CT_AGENT_CP_URL%/}/portal/tunnels) — not scriptable today."
  if [ "${FINAL_STATUS:-}" = "gelb" ]; then
    echo
    echo "  Still Gelb. To get your own certificate (Grün) once you're ready:"
    echo "    1. Make sure ${CT_AGENT_ORIGIN} serves PLAIN HTTP (not TLS) for now."
    echo "    2. CT_AGENT_CP_URL=${CT_AGENT_CP_URL} CT_AGENT_TOKEN=${CT_AGENT_TOKEN} CT_AGENT_HOSTNAME=${CT_AGENT_HOSTNAME} \\"
    echo "         CT_ACME_CERT_OUT_DIR=./ct-agent-cert ./ct-agent certificate"
    echo "    3. Once Grün, switch ${CT_AGENT_ORIGIN} back to serving its own TLS cert."
  fi
}

main() {
  detect_env
  confirm_mode
  ensure_env
  maybe_install_template
  if [ "$MODE" = "docker" ]; then install_docker; else install_direct; fi
  poll_status
  final_report
}
# Guarded so scripts/tests/*.sh can `source` this file to unit-test individual
# functions (e.g. ensure_env) without it immediately downloading/running a
# real agent -- `main` only fires on a direct invocation, matching `${0}`.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main
fi
