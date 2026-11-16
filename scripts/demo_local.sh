#!/usr/bin/env bash
# One-command local demo (macOS or Linux, no kernel features needed): a
# parameter server, the userspace aggregator and three reliable workers on
# loopback, with 10% of first transmissions and 10% of results dropped on
# purpose so retransmission and recovery are visible. Run `make` first.
set -euo pipefail
cd "$(dirname "$0")/.."
PS_PORT=39500 AGG_PORT=39501
./bin/paramserver --quiet --ack-to 127.0.0.1:$AGG_PORT $PS_PORT agg 2> /tmp/netsum-demo-ps.log &
PS=$!
./bin/agg --quiet $AGG_PORT 127.0.0.1 $PS_PORT 2> /tmp/netsum-demo-agg.log &
AGG=$!
trap 'kill -USR1 $AGG 2>/dev/null; sleep 0.2; kill $PS $AGG 2>/dev/null || true' EXIT
sleep 0.3
echo "3 workers x 20 rounds x 4096 values (64 chunks per round), 10% simulated loss each way..."
for w in 0 1 2; do
    ./bin/worker --mode reliable --to 127.0.0.1:$AGG_PORT --ps 127.0.0.1:$PS_PORT --job 1 --worker $w \
        --workers 3 --rounds 20 --vector-len 4096 --chunk-len 64 --window 64 --rto-ms 30 --fixed 0.5 \
        --drop-every 10 --drop-result-every 10 > /tmp/netsum-demo-w$w.json &
done
wait $(jobs -p | tail -3)
python3 - <<'PY'
import json
for w in range(3):
    r = json.loads(open(f"/tmp/netsum-demo-w{w}.json").read().strip().splitlines()[-1])
    print(f"worker {w}: {r['results']}/{r['chunks']} chunk results, {r['result_mismatches']} wrong sums, "
          f"{r['resent']} retransmissions, round p50 {r['round_us_p50']} us, total {r['elapsed_us'] / 1000:.0f} ms")
PY
