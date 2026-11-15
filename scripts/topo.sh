#!/usr/bin/env bash
# Three-namespace topology for the v2 benchmark (docs/DESIGN_NOTES.md §Topology):
#
#  ns_w (workers)                root ns (aggregator)               ns_ps (parameter server)
#  10.10.1.2  veth_w1 <------> veth_w0 10.10.1.1
#                              veth_p0 10.10.2.1 <------> veth_p1 10.10.2.2
#
# Workers send gradients to 10.10.1.1:9876. The aggregator (XDP on veth_w0 and
# veth_p0, or bin/agg in the root ns) forwards one aggregate per chunk to the
# PS at 10.10.2.2:9000; results and ACKs come back through the root ns, which
# routes between the two links. No rp_filter or accept_local relaxation.
# Usage: topo.sh up | down   (root, Linux)
set -euo pipefail

down() {
    ip netns del ns_w 2>/dev/null || true
    ip netns del ns_ps 2>/dev/null || true
    ip link del veth_w0 2>/dev/null || true
    ip link del veth_p0 2>/dev/null || true
}

up() {
    down
    ip netns add ns_w
    ip netns add ns_ps
    ip link add veth_w0 type veth peer name veth_w1
    ip link add veth_p0 type veth peer name veth_p1
    ip link set veth_w1 netns ns_w
    ip link set veth_p1 netns ns_ps
    ip addr add 10.10.1.1/24 dev veth_w0
    ip addr add 10.10.2.1/24 dev veth_p0
    ip link set veth_w0 up
    ip link set veth_p0 up
    ip netns exec ns_w ip addr add 10.10.1.2/24 dev veth_w1
    ip netns exec ns_w ip link set veth_w1 up
    ip netns exec ns_w ip link set lo up
    ip netns exec ns_w ip route add default via 10.10.1.1
    ip netns exec ns_ps ip addr add 10.10.2.2/24 dev veth_p1
    ip netns exec ns_ps ip link set veth_p1 up
    ip netns exec ns_ps ip link set lo up
    ip netns exec ns_ps ip route add default via 10.10.2.1
    sysctl -qw net.ipv4.ip_forward=1
    for ns in "" ns_w ns_ps; do
        cmd=(sysctl -qw)
        [ -n "$ns" ] && cmd=(ip netns exec "$ns" sysctl -qw)
        "${cmd[@]}" net.core.rmem_max=8388608 net.core.wmem_max=8388608 >/dev/null 2>&1 || true
    done
    # Let the PS-side veth receive frames redirected by native-mode XDP
    # (veth NAPI via GRO, kernel >= 5.13); harmless otherwise.
    ip netns exec ns_ps ethtool -K veth_p1 gro on >/dev/null 2>&1 || true
}

mac() { # ns ifname
    if [ -n "$1" ]; then ip netns exec "$1" cat "/sys/class/net/$2/address"; else cat "/sys/class/net/$2/address"; fi
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    mac) mac "${2:-}" "$3" ;;
    *) echo "usage: $0 up|down|mac <ns> <ifname>" >&2; exit 1 ;;
esac
