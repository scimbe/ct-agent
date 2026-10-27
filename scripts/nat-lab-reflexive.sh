#!/usr/bin/env bash
# scripts/nat-lab-reflexive.sh -- #248/#238 real-NAT validation for the UDP/QUIC reflexive-
# discovery fix (discover_udp_reflexive / the edge's 'W' echo), plus the #296 punch pair. Two
# hosts behind SEPARATE NATs and a public host, all Linux network namespaces + iptables in one
# privileged container. It tests the SPECIFIC pieces these fixes add -- NOT the full DCUtR punch
# (that needs either the full production stack or real hardware; see the PR/issue for that
# scope boundary).
#
# Topology -- #296: one router namespace per NAT. CADS-Tunnel's scripts/nat-lab.sh (which this
# script started from) runs both NATs in the root namespace and gives root both public
# addresses. A packet from one NAT'd host to the other's public address is then delivered
# locally to root: never SNAT'd, never matched against the other NAT's mapping. Reaching the
# echo works that way; a peer-to-peer punch never can. So here:
#
#   nsA 10.0.1.2 --- natA [10.0.1.1 | 203.0.113.10] ---+
#                                                       br0 (root: a bare L2 switch) --- nsR 203.0.113.1 ('W' echo)
#   nsB 10.0.2.2 --- natB [10.0.2.1 | 203.0.113.20] ---+
#
# Each NAT router SNATs its host (Linux keeps the source port when it is free: an endpoint-
# independent mapping) and drops unsolicited NEW traffic on its public side, like a home router.
# The drop is not decoration: without it conntrack records the peer's early punch as a local
# flow, and the host's own later packet toward that peer then gets ANOTHER source port (a tuple
# clash) -- which side punched first would decide the result, not the code under test.
#
# What this checks, with REAL packets crossing a REAL (synthetic) NAT boundary, not loopback:
#   1. `whoami_lab query` (a thin CLI wrapper around ct-agent's actual, production
#      `discover_udp_reflexive` function) reaches a public echo server through each NAT.
#   2. nsA and nsB each get back their OWN distinct, NAT-correct external address (NAT_A_PUB /
#      NAT_B_PUB) -- i.e. the discovery mechanism genuinely observes each peer's real UDP
#      reflexive mapping, not a proxy's address or a shared/wrong one.
#   3. #296: points 1-2 only check the IP; the punch pair checks the PORT. nsB QUIC-dials the
#      reflexive address nsA advertises, after nsA sent one punch toward nsB. Expected: nsB gets
#      through when nsA learned that address through its listening socket (`punch-listen`). Not
#      expected to get through with `--throwaway` (the address of a separate socket, what main
#      did) nor under `SNAT --random-fully` (endpoint-dependent mapping: the port toward the echo
#      is not the port toward nsB, so no candidate can work -- the boundary of the fix). Those two
#      only run after the shared-socket pair got through in the same run: a NAT that lets nothing
#      through would "pass" them too and prove nothing, so they report INCONCLUSIVE then.
#
# Run:
#   docker run --rm --privileged -v "$PWD":/w -w /w rust:1-slim bash scripts/nat-lab-reflexive.sh
set -euo pipefail

if ! command -v ip >/dev/null || ! command -v iptables >/dev/null || ! command -v ping >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iptables iputils-ping >/dev/null
fi

RELAY_PUB=203.0.113.1
NAT_A_PUB=203.0.113.10
NAT_B_PUB=203.0.113.20

cleanup() {
  set +e
  for ns in nsA nsB natA natB nsR; do ip netns del "$ns" 2>/dev/null; done
  ip link del vRbr 2>/dev/null
  ip link del bnatA 2>/dev/null
  ip link del bnatB 2>/dev/null
  ip link del br0 2>/dev/null
}
trap cleanup EXIT
cleanup

# The public segment: a bridge in root, which itself has no address on it.
ip link add br0 type bridge
ip link set br0 up

ip netns add nsR
ip link add vR type veth peer name vRbr
ip link set vR netns nsR
ip link set vRbr master br0
ip link set vRbr up
ip netns exec nsR ip addr add "${RELAY_PUB}/24" dev vR
ip netns exec nsR ip link set vR up
ip netns exec nsR ip link set lo up

setup_nat() { # $1=host namespace $2=NAT router namespace $3=third octet $4=this NAT's public IP
  local host=$1 nat=$2 net=$3 pub=$4
  ip netns add "$nat"
  ip netns add "$host"
  # public side: the router's wan port on the bridge
  ip link add "w${nat}" type veth peer name "b${nat}"
  ip link set "w${nat}" netns "$nat"
  ip link set "b${nat}" master br0
  ip link set "b${nat}" up
  ip netns exec "$nat" ip addr add "${pub}/24" dev "w${nat}"
  ip netns exec "$nat" ip link set "w${nat}" up
  ip netns exec "$nat" ip link set lo up
  # private side: router <-> host
  ip link add "l${nat}" type veth peer name "h${host}"
  ip link set "l${nat}" netns "$nat"
  ip link set "h${host}" netns "$host"
  ip netns exec "$nat" ip addr add "10.0.${net}.1/24" dev "l${nat}"
  ip netns exec "$nat" ip link set "l${nat}" up
  ip netns exec "$host" ip addr add "10.0.${net}.2/24" dev "h${host}"
  ip netns exec "$host" ip link set "h${host}" up
  ip netns exec "$host" ip link set lo up
  ip netns exec "$host" ip route add default via "10.0.${net}.1"
  ip netns exec "$nat" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  ip netns exec "$nat" iptables -t nat -A POSTROUTING -s "10.0.${net}.0/24" -o "w${nat}" -j SNAT --to-source "$pub"
  ip netns exec "$nat" iptables -A INPUT -i "w${nat}" -m conntrack --ctstate NEW -j DROP
}
setup_nat nsA natA 1 "$NAT_A_PUB"
setup_nat nsB natB 2 "$NAT_B_PUB"

pass=0 fail=0
expect_ok() { local name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS: ${name}"; pass=$((pass+1)); else echo "FAIL: ${name}"; fail=$((fail+1)); fi; }

expect_ok "nsA reaches the public segment" ip netns exec nsA ping -c1 -W1 "$RELAY_PUB"
expect_ok "nsB reaches the public segment" ip netns exec nsB ping -c1 -W1 "$RELAY_PUB"

WHOAMI_LAB="${WHOAMI_LAB:-target/debug/whoami_lab}"
if [ ! -x "$WHOAMI_LAB" ]; then
  echo "SKIP: build the harness first: cargo build --bin whoami_lab && WHOAMI_LAB=target/debug/whoami_lab $0"
  exit 0
fi

echo_out=$(mktemp)
ip netns exec nsR "$WHOAMI_LAB" echo "${RELAY_PUB}:4433" >"$echo_out" 2>&1 &
echo_pid=$!
sleep 0.5

query_ns() { # $1=namespace -> prints the reported address, or "ERR"
  local ns=$1 out; out=$(mktemp)
  if ip netns exec "$ns" timeout 8 "$WHOAMI_LAB" query "${RELAY_PUB}:4433" >"$out" 2>/dev/null; then
    grep -oP 'REFLEXIVE \K.*' "$out" | head -1
  else
    echo "ERR"
  fi
  rm -f "$out"
}

a_reported=$(query_ns nsA)
b_reported=$(query_ns nsB)
echo "nsA's discover_udp_reflexive reported: ${a_reported}"
echo "nsB's discover_udp_reflexive reported: ${b_reported}"
cat "$echo_out" | sed 's/^/  [echo server] /' || true
rm -f "$echo_out"

if [[ "$a_reported" == "${NAT_A_PUB}:"* ]]; then
  echo "PASS: nsA's own real, GENUINELY UDP-observed reflexive address is ${NAT_A_PUB} (its actual SNAT public IP)"
  pass=$((pass+1))
else
  echo "FAIL: nsA reported '${a_reported}', expected an address starting with ${NAT_A_PUB}:"
  fail=$((fail+1))
fi
if [[ "$b_reported" == "${NAT_B_PUB}:"* ]]; then
  echo "PASS: nsB's own real, GENUINELY UDP-observed reflexive address is ${NAT_B_PUB} (its actual SNAT public IP)"
  pass=$((pass+1))
else
  echo "FAIL: nsB reported '${b_reported}', expected an address starting with ${NAT_B_PUB}:"
  fail=$((fail+1))
fi
if [ "$a_reported" != "ERR" ] && [ "$a_reported" != "$b_reported" ]; then
  echo "PASS: nsA and nsB got DISTINCT reflexive addresses (each peer's own real mapping, not a shared/proxy one)"
  pass=$((pass+1))
else
  echo "FAIL: nsA and nsB did not get distinct addresses"
  fail=$((fail+1))
fi

# #296 punch pair: prints "<nsA exit> <nsB exit>"; $1 = extra flag for nsA's punch-listen.
punch_pair() {
  local flag=${1:-} dir a_pid b_pid a_ref="" b_ref="" a_rc=0 b_rc=0 i
  dir=$(mktemp -d)
  # shellcheck disable=SC2086 # $flag is empty or one word
  ip netns exec nsA timeout 40 "$WHOAMI_LAB" punch-listen "${RELAY_PUB}:4433" "$dir/a.peer" $flag >"$dir/a.out" 2>"$dir/a.err" &
  a_pid=$!
  ip netns exec nsB timeout 40 "$WHOAMI_LAB" punch-dial "${RELAY_PUB}:4433" "$dir/b.peer" >"$dir/b.out" 2>"$dir/b.err" &
  b_pid=$!
  for i in $(seq 1 100); do
    a_ref=$(grep -oP 'REFLEXIVE \K\S+' "$dir/a.out" 2>/dev/null || true)
    b_ref=$(grep -oP 'REFLEXIVE \K\S+' "$dir/b.out" 2>/dev/null || true)
    if [ -n "$a_ref" ] && [ -n "$b_ref" ]; then break; fi
    sleep 0.1
  done
  echo "$b_ref" >"$dir/a.peer" # nsA punches toward nsB
  echo "$a_ref" >"$dir/b.peer" # nsB dials what nsA advertises
  wait "$a_pid" || a_rc=$?
  wait "$b_pid" || b_rc=$?
  sed 's/^/  [nsA] /' "$dir/a.out" "$dir/a.err" >&2
  sed 's/^/  [nsB] /' "$dir/b.out" "$dir/b.err" >&2
  rm -rf "$dir"
  echo "$a_rc $b_rc"
}

shared_ok=0
read -r a_rc b_rc < <(punch_pair)
if [ "$a_rc" -eq 0 ] && [ "$b_rc" -eq 0 ]; then
  echo "PASS: nsB reached nsA's listener on the reflexive nsA learned THROUGH that listener (#296)"
  pass=$((pass+1))
  shared_ok=1
else
  echo "FAIL: shared-socket punch pair (nsA exit ${a_rc}, nsB exit ${b_rc})"
  fail=$((fail+1))
fi
if [ "$shared_ok" -eq 1 ]; then
  read -r a_rc b_rc < <(punch_pair --throwaway)
  if [ "$b_rc" -ne 0 ]; then
    echo "PASS: (expected) a throwaway socket's reflexive does not reach the listener -- #296 as on main"
    pass=$((pass+1))
  else
    echo "FAIL: the throwaway-socket reflexive reached the listener -- this NAT cannot show #296"
    fail=$((fail+1))
  fi
  ip netns exec natA iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o wnatA -j SNAT --to-source "$NAT_A_PUB"
  ip netns exec natA iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o wnatA -j SNAT --to-source "$NAT_A_PUB" --random-fully
  read -r a_rc b_rc < <(punch_pair)
  if [ "$b_rc" -ne 0 ]; then
    echo "PASS: (expected) endpoint-dependent mapping (--random-fully) defeats even the shared socket -- the fix's boundary"
    pass=$((pass+1))
  else
    echo "FAIL: the punch crossed a --random-fully NAT -- the EDM boundary in docs/channel.md is wrong"
    fail=$((fail+1))
  fi
else
  echo "INCONCLUSIVE: the --throwaway and --random-fully checks were not run -- they only mean something once the shared-socket pair gets through this NAT"
fi
kill "$echo_pid" 2>/dev/null || true

echo "== nat-lab-reflexive: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
