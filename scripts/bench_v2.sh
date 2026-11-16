#!/usr/bin/env bash
# NetSum v2 benchmark: closed-loop noagg vs userspace aggregation vs XDP
# aggregation (generic, native, array mode) on the three-namespace topology
# (scripts/topo.sh), plus a multi-tenant fairness sweep. Root, Linux.
# CI: .github/workflows/bench.yml. Method: docs/DESIGN_NOTES.md §Benchmark methodology.
#
# Outputs under $OUT: throughput.csv, latency.csv, latency_rounds.csv,
# fairness.csv, environment.json, raw/ (per-trial worker JSON, counters).
# Fails (non-zero) only on a functional error: a worker that did not finish,
# or any result that is not the exact expected sum.
set -euo pipefail

OUT=${OUT:-bench-out/v2}
WORKERS=${WORKERS:-"2 4 8"}
TP_TRIALS=${TP_TRIALS:-5}
TP_ROUNDS=${TP_ROUNDS:-1000}
LAT_TRIALS=${LAT_TRIALS:-5}
LAT_ROUNDS=${LAT_ROUNDS:-500}
VECTOR=${VECTOR:-1024}
CHUNK=${CHUNK:-64}
FAIR_TRIALS=${FAIR_TRIALS:-3}
FAIR_ROUNDS=${FAIR_ROUNDS:-1500}
CONFIGS=${CONFIGS:-"noagg useragg xdp-generic xdp-native xdp-array"}
PIN=/sys/fs/bpf/netsum_bench
CTL="./bin/netsum-ctl --pin $PIN"
NCPU=$(nproc)
mkdir -p "$OUT/raw"

# CPU pinning when there are at least 4 CPUs: workers 0-1, agg 2, PS 3.
if [ "$NCPU" -ge 4 ]; then PIN_W="taskset -c 0,1"; PIN_AGG="taskset -c 2"; PIN_PS="taskset -c 3"; else PIN_W=""; PIN_AGG=""; PIN_PS=""; fi

log() { echo "[bench $(date +%H:%M:%S)] $*" >&2; }

native_ok=""
xdp_up() { # mode slot_mode [slots_log2] [quota args...]
    local mode=$1 slot_mode=$2 log2=${3:-16}; shift 3 || true
    $CTL detach --ifname veth_w0 --ifname veth_p0 --unpin >/dev/null 2>&1 || true
    $CTL --json attach --ifname veth_w0 --ifname veth_p0 --mode "$mode" --slots-log2 "$log2" --obj xdp_agg/xdp_agg.o > "$OUT/raw/attach.json"
    ATTACHED=$(python3 -c "import json; print(json.loads(open('$OUT/raw/attach.json').read().splitlines()[0])['attached'])")
    $CTL config --ps-mac "$PS_MAC" --ps-ip 10.10.2.2 --ps-port 9000 --agg-mac "$AGGP_MAC" --agg-ip 10.10.2.1 \
        --egress-ifname veth_p0 --slot-mode "$slot_mode" "$@"
}
xdp_down() { $CTL detach --ifname veth_w0 --ifname veth_p0 --unpin >/dev/null 2>&1 || true; }

ps_start() { # extra args
    ip netns exec ns_ps $PIN_PS ./bin/paramserver --quiet --ack-to 10.10.2.1:9876 "$@" 9000 agg > "$OUT/raw/ps.log" 2>&1 &
    PS_PID=$!
    for _ in $(seq 1 100); do grep -q listening "$OUT/raw/ps.log" && return 0; sleep 0.05; done
    echo "PS did not start" >&2; return 1
}
ps_stop() { kill -TERM "$PS_PID" 2>/dev/null || true; wait "$PS_PID" 2>/dev/null || true; }

agg_start() { # --profile only in latency trials, so throughput carries no timing overhead
    $PIN_AGG ./bin/agg --quiet ${AGG_PROFILE:-} 9876 10.10.2.2 9000 > "$OUT/raw/agg.log" 2>&1 &
    AGG_PID=$!
    for _ in $(seq 1 100); do grep -q listening "$OUT/raw/agg.log" && return 0; sleep 0.05; done
    echo "agg did not start" >&2; return 1
}
agg_stop() { [ -n "${AGG_PID:-}" ] && { kill -TERM "$AGG_PID" 2>/dev/null || true; wait "$AGG_PID" 2>/dev/null || true; }; AGG_PID=""; }

cpu_ns() { awk '{print $1}' "/proc/$1/schedstat" 2>/dev/null || echo 0; }
net_rx() { awk '/NET_RX/ {for (i = 2; i <= NF; i++) printf "%s%s", (i > 2 ? ";" : ""), $i; print ""}' /proc/softirqs; }

setup_config() { # config -> sets TARGET and starts the aggregator
    local cfg=$1
    TARGET=10.10.1.1:9876; AGG_PID=""; ATTACHED=""
    case $cfg in
        noagg) TARGET=10.10.2.2:9000 ;;
        useragg) agg_start ;;
        xdp-generic) xdp_up generic hash 16 ;;
        xdp-native) xdp_up native hash 16 ;;
        xdp-array) xdp_up "${BEST_MODE:-generic}" array 16 ;;
    esac
}
teardown_config() { agg_stop; xdp_down; }

# Runs one job with N reliable workers; JSON per worker in $1-w<k>.json.
run_job() { # prefix job n rounds window [--sync] [extra...]
    local prefix=$1 job=$2 n=$3 rounds=$4 window=$5; shift 5
    local pids=()
    for w in $(seq 0 $((n - 1))); do
        ip netns exec ns_w $PIN_W ./bin/worker --mode reliable --to "$TARGET" --ps 10.10.2.2:9000 --job "$job" \
            --worker "$w" --workers "$n" --rounds "$rounds" --vector-len "$VECTOR" --chunk-len "$CHUNK" \
            --window "$window" --rto-ms 200 --fixed 0.25 "$@" > "$prefix-w$w.json" 2> "$prefix-w$w.err" &
        pids+=($!)
    done
    local rc=0
    for p in "${pids[@]}"; do wait "$p" || rc=1; done
    return $rc
}

check_results() { # prefix n expected_chunks_per_worker
    python3 - "$@" <<'PY'
import json, sys
prefix, n, want = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for w in range(n):
    lines = open(f"{prefix}-w{w}.json").read().strip().splitlines()
    if not lines:
        sys.exit(f"FUNCTIONAL ERROR: {prefix} worker {w} printed nothing: " + open(f"{prefix}-w{w}.err").read())
    r = json.loads(lines[-1])
    if r["results"] != want or r["result_mismatches"] != 0:
        sys.exit(f"FUNCTIONAL ERROR: {prefix} worker {w}: {r}")
PY
}

counters() { # prefix: XDP counters (if attached), agg stats, PS stats
    [ -e "$PIN/stats" ] && $CTL --json stats > "$1-xdp.json" || echo "{}" > "$1-xdp.json"
}

trial() { # mode(tp|lat) config n t
    local mode=$1 cfg=$2 n=$3 t=$4
    local prefix="$OUT/raw/$mode-$cfg-n$n-t$t" job=$((100 + t))
    local rounds=$TP_ROUNDS window=64 sync=()
    AGG_PROFILE=""
    if [ "$mode" = lat ]; then rounds=$LAT_ROUNDS; window=$(( (VECTOR + CHUNK - 1) / CHUNK )); sync=(--sync --emit-rounds); AGG_PROFILE=--profile; fi
    setup_config "$cfg"
    if [ "$cfg" = xdp-native ] && [ "$ATTACHED" != native ]; then
        log "native attach fell back to '$ATTACHED'; skipping xdp-native"; teardown_config; return 0
    fi
    ps_start
    local rx0 ps_cpu0 agg_cpu0=0
    rx0=$(net_rx); ps_cpu0=$(cpu_ns "$PS_PID"); [ -n "$AGG_PID" ] && agg_cpu0=$(cpu_ns "$AGG_PID")
    local t0 t1
    t0=$(date +%s%N)
    run_job "$prefix" "$job" "$n" "$rounds" "$window" "${sync[@]}" || { log "worker failure in $prefix"; }
    t1=$(date +%s%N)
    local rx1 ps_cpu1 agg_cpu1=0
    rx1=$(net_rx); ps_cpu1=$(cpu_ns "$PS_PID"); [ -n "$AGG_PID" ] && agg_cpu1=$(cpu_ns "$AGG_PID")
    check_results "$prefix" "$n" $((rounds * ((VECTOR + CHUNK - 1) / CHUNK)))
    counters "$prefix"
    if [ -n "$AGG_PID" ]; then agg_stop; mv "$OUT/raw/agg.log" "$prefix-agg.log"; fi
    ps_stop
    cp "$OUT/raw/ps.log" "$prefix-ps.log"
    xdp_down
    python3 - "$prefix" "$mode" "$cfg" "$n" "$t" "$rounds" "$window" "$ATTACHED" "$rx0" "$rx1" \
        "$((ps_cpu1 - ps_cpu0))" "$((agg_cpu1 - agg_cpu0))" "$(( (t1 - t0) / 1000 ))" "$VECTOR" >> "$OUT/$( [ "$mode" = tp ] && echo throughput || echo latency ).csv" <<'PY'
import json, re, sys
prefix, mode, cfg, n, t, rounds, window, attached, rx0, rx1, ps_cpu, agg_cpu, wall_us, vector = sys.argv[1:]
n = int(n)
ws = [json.loads(open(f"{prefix}-w{w}.json").read().strip().splitlines()[-1]) for w in range(n)]
elapsed = max(w["elapsed_us"] for w in ws)
def stats_all(path):
    try:
        lines = [l for l in open(path) if l.startswith("[stats-all]")]
        return json.loads(lines[-1].split(" ", 1)[1]) if lines else {}
    except FileNotFoundError:
        return {}
ps, agg = stats_all(f"{prefix}-ps.log"), stats_all(f"{prefix}-agg.log")
xdp = json.load(open(f"{prefix}-xdp.json"))
d0 = [int(x) for x in rx0.split(";")]; d1 = [int(x) for x in rx1.split(";")]
softirq = [b - a for a, b in zip(d0, d1)]
row = {
    "mode": mode, "config": cfg, "workers": n, "trial": t, "rounds": rounds, "window": window,
    "attach_mode": attached or "-", "elapsed_us": elapsed, "wall_us": wall_us,
    "values_per_s": int(rounds) * int(vector) / (elapsed / 1e6) if elapsed else 0,
    "rounds_per_s": int(rounds) / (elapsed / 1e6) if elapsed else 0,
    "round_us_p50": max(w["round_us_p50"] for w in ws), "round_us_p99": max(w["round_us_p99"] for w in ws),
    "sent": sum(w["sent"] for w in ws), "resent": sum(w["resent"] for w in ws),
    "ps_rx_packets": ps.get("rx_total", 0), "ps_cpu_ns": ps_cpu, "agg_cpu_ns": agg_cpu,
    "agg_rx_packets": agg.get("rx_total", 0), "agg_profile_ns": agg.get("profile_ns", 0),
    "agg_profile_pkts": agg.get("profile_pkts", 0),
    "xdp_run_cnt": xdp.get("prog_run_cnt", 0), "xdp_run_time_ns": xdp.get("prog_run_time_ns", 0),
    "xdp_rx_total": xdp.get("rx_total", 0), "xdp_accepted": xdp.get("accepted", 0),
    "xdp_tx_aggregate": xdp.get("tx_aggregate", 0), "xdp_tx_fallback": xdp.get("tx_fallback", 0),
    "xdp_ack_seen": xdp.get("ack_seen", 0),
    "xdp_terminal": sum(xdp.get(k, 0) for k in xdp if k.startswith("rej_") and k != "rej_ttl") + sum(xdp.get(k, 0) for k in (
        "accepted", "duplicate", "resend_duplicate", "late_duplicate", "num_workers_mismatch", "chunk_len_mismatch",
        "tx_fallback", "tx_result_resend", "drop_quota", "drop_map_full", "drop_job_table_full", "pass_control", "ack_seen")),
    "net_rx_softirqs_by_cpu": "|".join(str(x) for x in softirq),
}
import csv, os
path = sys.stdout
w = csv.DictWriter(sys.stdout, fieldnames=list(row.keys()))
if os.fstat(sys.stdout.fileno()).st_size == 0:
    w.writeheader()
w.writerow(row)
PY
    if [ "$mode" = lat ]; then
        python3 - "$prefix" "$cfg" "$n" "$t" "$n" >> "$OUT/latency_rounds.csv" <<'PY'
import json, os, sys
prefix, cfg, n, t, nw = sys.argv[1:]
if os.fstat(sys.stdout.fileno()).st_size == 0:
    print("config,workers,trial,worker,round,round_us")
for w in range(int(nw)):
    line = open(f"{prefix}-w{w}.json").read().strip().splitlines()[0]
    for i, us in enumerate(json.loads(line)["round_us"]):
        print(f"{cfg},{n},{t},{w},{i},{us}")
PY
    fi
    log "$mode $cfg n=$n t=$t: $(tail -1 "$OUT/$( [ "$mode" = tp ] && echo throughput || echo latency ).csv" | cut -d, -f8-13)"
}

# Fairness: three jobs (fan-in 2 each) with demand 4:2:1 (windows 64/32/16)
# run concurrently through one aggregator under each policy.
fair_trial() { # policy t
    local policy=$1 t=$2 prefix="$OUT/raw/fair-$1-t$2"
    TARGET=10.10.1.1:9876
    case $policy in
        none) xdp_up "${BEST_MODE:-generic}" hash 16 ;;
        quota-drop) xdp_up "${BEST_MODE:-generic}" hash 16 --max-slots-per-job 16 --quota-policy drop ;;
        quota-fallback) xdp_up "${BEST_MODE:-generic}" hash 16 --max-slots-per-job 16 --quota-policy fallback ;;
        array-small) xdp_up "${BEST_MODE:-generic}" array 6 ;;
    esac
    ps_start
    local pids=() j=0
    for win in 64 32 16; do
        j=$((j + 1))
        ( run_job "$prefix-job$j" $((200 + j)) 2 "$FAIR_ROUNDS" "$win" --emit-rounds --max-retries 60 ) &
        pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || log "fairness worker failure ($policy t=$t)"; done
    counters "$prefix"
    ps_stop
    xdp_down
    for j in 1 2 3; do check_results "$prefix-job$j" 2 $((FAIR_ROUNDS * ((VECTOR + CHUNK - 1) / CHUNK))); done
    python3 - "$prefix" "$policy" "$t" >> "$OUT/fairness.csv" <<'PY'
import json, os, sys
prefix, policy, t = sys.argv[1:]
jobs = []
for j, demand in ((1, 64), (2, 32), (3, 16)):
    w = [open(f"{prefix}-job{j}-w{k}.json").read().strip().splitlines() for k in range(2)]
    ends = [json.loads(x[0])["round_end_us"] for x in w]
    start = min(json.loads(x[0])["round_end_us"][0] - json.loads(x[0])["round_us"][0] for x in w)
    summary = [json.loads(x[-1]) for x in w]
    jobs.append({"job": j, "demand": demand, "ends": [max(a, b) for a, b in zip(*ends)], "start": start,
                 "resent": sum(s["resent"] for s in summary), "p99": max(s["round_us_p99"] for s in summary)})
t0 = min(j["start"] for j in jobs)
window_end = min(j["ends"][-1] for j in jobs)  # all three jobs active until the first finishes
xdp = json.load(open(f"{prefix}-xdp.json"))
if os.fstat(sys.stdout.fileno()).st_size == 0:
    print("policy,trial,job,demand_window,rounds_in_window,window_s,goodput_rounds_per_s,round_us_p99,resent,"
          "xdp_accepted,xdp_tx_fallback,xdp_fallback_collision,xdp_fallback_quota,xdp_drop_quota")
for j in jobs:
    done = sum(1 for e in j["ends"] if e <= window_end)
    secs = (window_end - t0) / 1e6
    print(f"{policy},{t},{j['job']},{j['demand']},{done},{secs:.4f},{done / secs:.2f},{j['p99']},{j['resent']},"
          f"{xdp.get('accepted', 0)},{xdp.get('tx_fallback', 0)},{xdp.get('fallback_collision', 0)},"
          f"{xdp.get('fallback_quota', 0)},{xdp.get('drop_quota', 0)}")
PY
    log "fairness $policy t=$t done"
}

environment() {
    python3 - "$OUT/environment.json" <<PY
import datetime, json, os, platform, subprocess, sys
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True).strip()
    except Exception as e: return f"unavailable: {e}"
json.dump({
    "uname": sh("uname -a"), "kernel": platform.release(), "nproc": os.cpu_count(),
    "cpu_model": sh("lscpu | sed -n 's/^Model name:[ ]*//p'"),
    "image_os": os.environ.get("ImageOS", ""), "image_version": os.environ.get("ImageVersion", ""),
    "clang": sh("clang --version | head -1"), "gcc": sh("gcc --version | head -1"),
    "libbpf": sh("dpkg -s libbpf-dev 2>/dev/null | sed -n 's/^Version: //p'"),
    "native_attach": "$native_ok", "best_xdp_mode": "${BEST_MODE:-generic}",
    "cpu_pinning": "workers ${PIN_W:-none}, agg ${PIN_AGG:-none}, PS ${PIN_PS:-none}",
    "topology": "three namespaces: ns_w -- veth -- root (aggregator) -- veth -- ns_ps; routed, no rp_filter relaxation",
    "vector_len": $VECTOR, "chunk_len": $CHUNK, "tp_rounds": $TP_ROUNDS, "tp_trials": $TP_TRIALS,
    "lat_rounds": $LAT_ROUNDS, "lat_trials": $LAT_TRIALS, "fair_rounds": $FAIR_ROUNDS, "fair_trials": $FAIR_TRIALS,
    "workers": "$WORKERS", "configs": "$CONFIGS", "rto_ms": 200, "rng_seed": 1234,
    "git_commit": sh("git rev-parse HEAD"), "utc": datetime.datetime.utcnow().isoformat() + "Z",
}, open(sys.argv[1], "w"), indent=2)
PY
}

main() {
    bash scripts/topo.sh up
    trap 'agg_stop; xdp_down; bash scripts/topo.sh down' EXIT
    sysctl -qw kernel.bpf_stats_enabled=1
    PS_MAC=$(bash scripts/topo.sh mac ns_ps veth_p1)
    AGGP_MAC=$(bash scripts/topo.sh mac "" veth_p0)
    xdp_up native hash 16 && [ "$ATTACHED" = native ] && native_ok=yes || native_ok=no
    xdp_down
    BEST_MODE=$([ "$native_ok" = yes ] && echo native || echo generic)
    log "native attach on veth: $native_ok; array and fairness use $BEST_MODE"
    environment
    for t in $(seq 1 "$TP_TRIALS"); do
        for n in $WORKERS; do for cfg in $CONFIGS; do trial tp "$cfg" "$n" "$t"; done; done
    done
    for t in $(seq 1 "$LAT_TRIALS"); do
        for n in $WORKERS; do for cfg in $CONFIGS; do trial lat "$cfg" "$n" "$t"; done; done
    done
    for t in $(seq 1 "$FAIR_TRIALS"); do
        for policy in none quota-drop quota-fallback array-small; do fair_trial "$policy" "$t"; done
    done
    sysctl -qw kernel.bpf_stats_enabled=0
}

main "$@"
