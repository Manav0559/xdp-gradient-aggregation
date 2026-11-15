# Helpers sourced by .github/workflows/xdp-loadtest.yml steps (bash, root via sudo).
# Topology: veth0 (root ns, 10.200.1.1, XDP attached) <-> veth1 (ns1, 10.200.1.2,
# workers and the parameter server).
CTL="sudo ./bin/netsum-ctl --pin /sys/fs/bpf/netsum"
AGG=10.200.1.1
PS=10.200.1.2

ctl_json() { $CTL --json "$@"; }
stats_to() { ctl_json stats > "$1"; }
slots_to() { ctl_json slots > "$1"; }
in_ns1() { sudo ip netns exec ns1 "$@"; }

# oneshot worker: job worker fanin value [rounds] [chunk_len]
send() { in_ns1 ./bin/worker "$AGG" 9876 "$1" "$2" "$3" "${5:-1}" "${6:-1}" 1.0 "$4"; }

# reliable worker in the background; JSON summary to /tmp/rw-<job>-<worker>.json
reliable_bg() { # job worker fanin rounds vector_len extra...
    local job=$1 w=$2 n=$3 rounds=$4 vlen=$5; shift 5
    in_ns1 ./bin/worker --mode reliable --to "$AGG:9876" --ps "$PS:9000" --job "$job" --worker "$w" \
        --workers "$n" --rounds "$rounds" --vector-len "$vlen" --chunk-len 64 --fixed 0.5 "$@" \
        > "/tmp/rw-$job-$w.json" 2> "/tmp/rw-$job-$w.err" &
}

# Asserts every reliable worker of a job exited 0 with all results correct.
check_reliable() { # job fanin expected_results
    python3 - "$@" <<'PY'
import json, sys
job, n, want = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
total_resent = 0
for w in range(n):
    lines = open(f"/tmp/rw-{job}-{w}.json").read().strip().splitlines()
    assert lines, f"worker {w} of job {job} printed nothing: " + open(f"/tmp/rw-{job}-{w}.err").read()
    r = json.loads(lines[-1])
    print(f"job {job} worker {w}: {r}")
    assert r["results"] == want and r["result_mismatches"] == 0, r
    total_resent += r["resent"]
print(f"PASS: job {job}: {n} reliable workers got {want} correct results each; {total_resent} retransmissions")
PY
}
