#!/usr/bin/env bash
# scripts/nat-lab-reflexive.sh -- #248/#238 real-NAT validation for the UDP/QUIC reflexive-
# discovery fix (discover_udp_reflexive / the edge's 'W' echo). Reuses CADS-Tunnel's
# scripts/nat-lab.sh topology (two hosts behind SEPARATE NATs + a public host, all via Linux
# network namespaces + iptables SNAT, in one privileged container) but tests the SPECIFIC new
# piece this fix adds -- NOT the full DCUtR punch (that needs either the full production stack
# or real hardware; see the PR/issue for that scope boundary).
#
# What this proves, with REAL packets crossing a REAL (synthetic) NAT boundary, not loopback:
#   1. `whoami_lab query` (a thin CLI wrapper around ct-agent's actual, production
#      `discover_udp_reflexive` function) reaches a public echo server through each NAT.
#   2. nsA and nsB each get back their OWN distinct, NAT-correct external address (NAT_A_PUB /
#      NAT_B_PUB) -- i.e. the discovery mechanism genuinely observes each peer's real UDP
#      reflexive mapping, not a proxy's address or a shared/wrong one.
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
BACKBONE=203.0.113.254

cleanup() {
  set +e
  ip netns del nsA 2>/dev/null
  ip netns del nsB 2>/dev/null
  ip netns del nsR 2>/dev/null
  ip link del vethnsA 2>/dev/null
  ip link del vethnsB 2>/dev/null
  ip link del pubR 2>/dev/null
  iptables -t nat -F 2>/dev/null
  iptables -F 2>/dev/null
}
trap cleanup EXIT
cleanup

ip netns add nsR
ip link add pubR type veth peer name inR
ip link set inR netns nsR
ip addr add "${BACKBONE}/24" dev pubR
ip addr add "${NAT_A_PUB}/24" dev pubR
ip addr add "${NAT_B_PUB}/24" dev pubR
ip link set pubR up
ip netns exec nsR ip addr add "${RELAY_PUB}/24" dev inR
ip netns exec nsR ip link set inR up
ip netns exec nsR ip link set lo up
ip netns exec nsR ip route add default via "${BACKBONE}"
echo 1 > /proc/sys/net/ipv4/ip_forward

setup_nat() { # $1=namespace $2=third-octet $3=this-NAT's-public-IP
  local ns=$1 net=$2 pub=$3
  ip netns add "$ns"
  ip link add "veth${ns}" type veth peer name "in${ns}"
  ip link set "in${ns}" netns "$ns"
  ip addr add "10.0.${net}.1/24" dev "veth${ns}"
  ip link set "veth${ns}" up
  ip netns exec "$ns" ip addr add "10.0.${net}.2/24" dev "in${ns}"
  ip netns exec "$ns" ip link set "in${ns}" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip route add default via "10.0.${net}.1"
  iptables -t nat -A POSTROUTING -s "10.0.${net}.0/24" -o pubR -j SNAT --to-source "$pub"
}
setup_nat nsA 1 "$NAT_A_PUB"
setup_nat nsB 2 "$NAT_B_PUB"

# NAT isolation -- neither peer can reach the other directly, matching nat-lab.sh's topology.
iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.2.0/24 -j DROP
iptables -A FORWARD -s 10.0.2.0/24 -d 10.0.1.0/24 -j DROP

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
kill "$echo_pid" 2>/dev/null || true
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

echo "== nat-lab-reflexive: ${pass} passed, ${fail} failed =="
[ "$fail" -eq 0 ]
