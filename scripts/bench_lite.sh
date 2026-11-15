#!/usr/bin/env bash
# Benchmark-lite: the first measured comparison of noagg, userspace
# aggregation (agg) and XDP aggregation (xdpgeneric) on one Linux host, over
# the two-namespace veth topology of the XDP load test. Open loop (paced
# sender, no result path). Run as root on Linux; CI: .github/workflows/bench-lite.yml.
# Output: $OUT/raw.csv (one row per trial), $OUT/environment.json, $OUT/stats/.
# Methodology: docs/DESIGN_NOTES.md §Benchmark methodology.
set -euo pipefail

OUT=${OUT:-bench-out/lite}
ROUNDS=${ROUNDS:-25000}
TRIALS=${TRIALS:-5}
WORKERS=${WORKERS:-"2 4 8"}
RATES=${RATES:-"100000 200000 400000 0"}
CHUNK=${CHUNK:-16}
CONFIGS=${CONFIGS:-"noagg useragg xdp"}
PIN=/sys/fs/bpf/netsum_lite
mkdir -p "$OUT/stats"

topo_down() {
    pkill -f "bin/paramserver" 2>/dev/null || true
    pkill -f "bin/agg" 2>/dev/null || true
    ./bin/netsum-ctl --pin "$PIN" detach --ifname veth0 --unpin 2>/dev/null || true
    ip netns del ns1 2>/dev/null || true
    ip link del veth0 2>/dev/null || true
}

topo_up() {
    topo_down
    ip link add veth0 type veth peer name veth1
    ip netns add ns1
    ip link set veth1 netns ns1
    ip addr add 10.200.1.1/24 dev veth0
    ip link set veth0 up
    ip netns exec ns1 ip addr add 10.200.1.2/24 dev veth1
    ip netns exec ns1 ip link set veth1 up
    ip netns exec ns1 ip link set lo up
    ip netns exec ns1 sysctl -qw net.ipv4.conf.veth1.accept_local=1
    ip netns exec ns1 sysctl -qw net.ipv4.conf.veth1.rp_filter=0
    ip netns exec ns1 sysctl -qw net.ipv4.conf.all.rp_filter=0
    sysctl -qw net.core.rmem_max=8388608 net.core.wmem_max=8388608
    ip netns exec ns1 sysctl -qw net.core.rmem_max=8388608 || true
    VETH0_MAC=$(ip link show veth0 | awk '/link\/ether/ {print $2}')
    VETH1_MAC=$(ip netns exec ns1 ip link show veth1 | awk '/link\/ether/ {print $2}')
}

CTL="./bin/netsum-ctl --pin $PIN"

xdp_up() {
    $CTL attach --ifname veth0 --mode generic --obj xdp_agg/xdp_agg.o >/dev/null
    $CTL config --ps-mac "$VETH1_MAC" --ps-ip 10.200.1.2 --ps-port 9000 --agg-mac "$VETH0_MAC" --agg-ip 10.200.1.1
}

xdp_down() {
    $CTL detach --ifname veth0 --unpin
}

udp_rcvbuf_errors() { # $1: "" for root ns, "ns1"
    local cmd="cat /proc/net/snmp"
    [ -n "$1" ] && cmd="ip netns exec $1 cat /proc/net/snmp"
    $cmd | awk '/^Udp:/ { if (!h) { for (i = 1; i <= NF; i++) col[$i] = i; h = 1 } else print $col["RcvbufErrors"] }'
}

cpu_ns() { awk '{print $1}' "/proc/$1/schedstat"; }  # on-CPU time, ns

wait_ready() { # $1 log file
    for _ in $(seq 1 100); do grep -q listening "$1" 2>/dev/null && return 0; sleep 0.05; done
    echo "server never became ready: $(cat "$1")" >&2; return 1
}

json_field() { python3 -c "import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], ''))" "$1" "$2"; }

stats_field() { # $1 log, $2 field, from the last [stats-all] line
    python3 - "$1" "$2" <<'PY'
import json, re, sys
line = [l for l in open(sys.argv[1]) if l.startswith("[stats-all]")][-1]
print(json.loads(line.split(" ", 1)[1]).get(sys.argv[2], 0))
PY
}

summary_field() { # $1 log, $2 field
    python3 - "$1" "$2" <<'PY'
import json, sys
line = [l for l in open(sys.argv[1]) if l.startswith("[summary]")][-1]
print(json.loads(line.split(" ", 1)[1])[sys.argv[2]])
PY
}

environment() {
    python3 - "$OUT/environment.json" <<PY
import json, os, platform, subprocess, sys, datetime
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True).strip()
    except Exception as e: return f"unavailable: {e}"
env = {
    "uname": sh("uname -a"), "kernel": platform.release(), "nproc": os.cpu_count(),
    "cpu_model": sh("lscpu | sed -n 's/^Model name:[ ]*//p'"),
    "image_os": os.environ.get("ImageOS", ""), "image_version": os.environ.get("ImageVersion", ""),
    "clang": sh("clang --version | head -1"), "gcc": sh("gcc --version | head -1"),
    "libbpf": sh("dpkg -s libbpf-dev 2>/dev/null | sed -n 's/^Version: //p'"),
    "xdp_attach_mode": "xdpgeneric (read back below)", "xdp_attach_readback": "$XDP_READBACK",
    "git_commit": sh("git rev-parse HEAD"), "utc": datetime.datetime.utcnow().isoformat() + "Z",
    "rounds_per_trial": $ROUNDS, "trials": $TRIALS, "chunk_len": $CHUNK,
    "workers": "$WORKERS", "rates_pps": "$RATES (0 = unpaced)", "cpu_pinning": "none",
    "topology": "two-namespace veth (workers and PS in ns1, aggregator in root ns)",
    "rng_seed": 1234,
}
json.dump(env, open(sys.argv[1], "w"), indent=2)
PY
}

trial() { # config workers rate trial
    local cfg=$1 n=$2 rate=$3 t=$4 tag="$1-w$2-r$3-t$4"
    local pslog="$OUT/stats/ps-$tag.log" agglog="$OUT/stats/agg-$tag.log"
    ip netns exec ns1 ./bin/paramserver --quiet --tombstone-ttl-ms 600000 9000 agg > "$pslog" 2>&1 &
    local ps_pid=$!
    wait_ready "$pslog"
    local agg_pid="" target_ns="ns1" target_ip=10.200.1.1 target_port=9876
    case $cfg in
        noagg) target_ns=""; target_ip=10.200.1.2; target_port=9000 ;;
        useragg)
            ./bin/agg --quiet 9876 10.200.1.2 9000 > "$agglog" 2>&1 &
            agg_pid=$!
            wait_ready "$agglog" ;;
        xdp) xdp_up ;;
    esac
    local ps_err0 agg_err0 ps_cpu0 agg_cpu0=0
    ps_err0=$(udp_rcvbuf_errors ns1); agg_err0=$(udp_rcvbuf_errors "")
    ps_cpu0=$(cpu_ns $ps_pid); [ -n "$agg_pid" ] && agg_cpu0=$(cpu_ns $agg_pid)

    local sender=(./bin/lite_sender "$target_ip" "$target_port" 7 "$n" "$ROUNDS" "$rate" "$CHUNK")
    local sres
    if [ -n "$target_ns" ]; then sres=$(ip netns exec "$target_ns" "${sender[@]}"); else sres=$("${sender[@]}"); fi
    sleep 0.5

    local ps_err1 agg_err1 ps_cpu1 agg_cpu1=0
    ps_err1=$(udp_rcvbuf_errors ns1); agg_err1=$(udp_rcvbuf_errors "")
    ps_cpu1=$(cpu_ns $ps_pid); [ -n "$agg_pid" ] && agg_cpu1=$(cpu_ns $agg_pid)

    local xdp_cnt=0 xdp_ns=0 xdp_rx=0 xdp_acc=0 xdp_tx=0 xdp_done=0 xdp_other=0
    if [ "$cfg" = xdp ]; then
        $CTL --json stats > "$OUT/stats/xdp-$tag.json"
        xdp_cnt=$(json_field "$(cat "$OUT/stats/xdp-$tag.json")" prog_run_cnt)
        xdp_ns=$(json_field "$(cat "$OUT/stats/xdp-$tag.json")" prog_run_time_ns)
        read -r xdp_rx xdp_acc xdp_tx xdp_done xdp_other < <(python3 -c "
import sys; sys.path.insert(0, 'ci'); import netsum_bpf_json as n
s = n.stats('$OUT/stats/xdp-$tag.json')
other = sum(v for k, v in s.items() if k.startswith('rej_') or k in ('duplicate', 'resend_duplicate', 'late_duplicate', 'num_workers_mismatch', 'chunk_len_mismatch', 'pass_control', 'drop_quota', 'drop_map_full', 'drop_job_table_full'))
print(s['rx_total'], s['accepted'], s['tx_aggregate'], s['slot_completed'], other)")
        xdp_down
    fi
    local agg_in=0 agg_out=0
    if [ -n "$agg_pid" ]; then
        kill -TERM "$agg_pid"; wait "$agg_pid" || true
        agg_in=$(stats_field "$agglog" rx_total); agg_out=$(stats_field "$agglog" tx_aggregate)
    fi
    kill -TERM "$ps_pid"; wait "$ps_pid" || true
    local completed first last
    completed=$(summary_field "$pslog" completed)
    first=$(summary_field "$pslog" first_complete_us); last=$(summary_field "$pslog" last_complete_us)
    local ps_rx; ps_rx=$(stats_field "$pslog" rx_total)
    local ps_wrong; ps_wrong=$(grep -c '^\[overflow\]' "$pslog" || true)
    echo "$cfg,$n,$rate,$t,$ROUNDS,$CHUNK,$(json_field "$sres" offered),$(json_field "$sres" sent),$(json_field "$sres" send_retries),$(json_field "$sres" elapsed_us),$(json_field "$sres" achieved_pps),$completed,$first,$last,$ps_rx,$((ps_err1 - ps_err0)),$((agg_err1 - agg_err0)),$((ps_cpu1 - ps_cpu0)),$((agg_cpu1 - agg_cpu0)),$agg_in,$agg_out,$xdp_cnt,$xdp_ns,$xdp_rx,$xdp_acc,$xdp_other,$xdp_tx,$xdp_done,$ps_wrong" >> "$OUT/raw.csv"
    echo "  $tag: completed $completed/$ROUNDS sender $(json_field "$sres" achieved_pps) pps"
}

main() {
    topo_up
    sysctl -qw kernel.bpf_stats_enabled=1
    xdp_up; XDP_READBACK=$($CTL --json attach --ifname veth0 --mode generic | python3 -c "import json,sys; print(json.load(sys.stdin)['attached'])"); xdp_down
    environment
    echo "config,workers,rate_pps,trial,rounds,chunk_len,offered,sent,send_retries,send_elapsed_us,achieved_pps,ps_completed,ps_first_complete_us,ps_last_complete_us,ps_rx_packets,ps_rcvbuf_errors,root_rcvbuf_errors,ps_cpu_ns,agg_cpu_ns,agg_rx_packets,agg_tx_aggregates,xdp_run_cnt,xdp_run_time_ns,xdp_rx_total,xdp_accepted,xdp_other_outcomes,xdp_tx_aggregate,xdp_slot_completed,ps_overflow_lines" > "$OUT/raw.csv"
    for t in $(seq 1 "$TRIALS"); do          # trials outermost: drift spreads across cells
        for n in $WORKERS; do
            for rate in $RATES; do
                for cfg in $CONFIGS; do
                    trial "$cfg" "$n" "$rate" "$t"
                done
            done
        done
    done
    sysctl -qw kernel.bpf_stats_enabled=0
    topo_down
}

main "$@"
