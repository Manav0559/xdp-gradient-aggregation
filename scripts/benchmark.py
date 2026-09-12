#!/usr/bin/env python3
"""NetSum benchmark harness: runs the no-aggregation baseline (#1) and the
userspace-aggregation baseline (#2) across a sweep of worker counts, and
records real, measured completion latency and aggregator-uplink packet
counts to bench/results.csv -- every number the dashboard charts comes from
this script actually running the real compiled binaries, never a
hand-typed or simulated value.

The XDP baseline (#3) is not included: it needs a real Linux kernel this
development machine doesn't have (see docs/DEV_ENVIRONMENT.md). The CSV
schema below already has a `config` column ready for an `xdp` row once that
becomes runnable -- adding it later is "run this script on a Linux box with
one more baseline wired in," not a schema change.

Run: python3 scripts/benchmark.py [--trials N] [--out bench/results.csv]
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO_ROOT, "bin")
WORKER = os.path.join(BIN, "worker")
PARAMSERVER = os.path.join(BIN, "paramserver")
AGG = os.path.join(BIN, "agg")

sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
from test_correctness import Server, free_port, run_worker, extract_complete_lines  # noqa: E402

WORKER_COUNTS = [2, 4, 8, 16]
CHUNK_LEN = 16  # a modest gradient-chunk size, not the 1-value smoke-test size


def bench_noagg(num_workers, job_id):
    port = free_port()
    srv = Server([PARAMSERVER, str(port), "noagg"])
    try:
        t0 = time.time()
        for wid in range(num_workers):
            run_worker("127.0.0.1", port, job_id=job_id, worker_id=wid, num_workers=num_workers,
                       num_rounds=1, chunk_len=CHUNK_LEN, fixed_value=0.01)
        srv.drain_for(1.0)
        wall_us = (time.time() - t0) * 1e6
    finally:
        srv.stop()
    completes = extract_complete_lines(srv.text())
    if len(completes) != 1:
        raise RuntimeError(f"noagg num_workers={num_workers}: expected 1 completion, got {completes}")
    latency_us = int(completes[0][5])
    return {"uplink_packets": num_workers, "latency_us": latency_us, "wall_us": wall_us}


def bench_useragg(num_workers, job_id):
    ps_port = free_port()
    agg_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg = Server([AGG, str(agg_port), "127.0.0.1", str(ps_port), str(num_workers)])
    try:
        t0 = time.time()
        for wid in range(num_workers):
            run_worker("127.0.0.1", agg_port, job_id=job_id, worker_id=wid, num_workers=num_workers,
                       num_rounds=1, chunk_len=CHUNK_LEN, fixed_value=0.01)
        deadline = time.time() + 2.0
        while agg.proc.poll() is None and time.time() < deadline:
            agg.drain_for(0.1)
        agg.drain_for(0.1)
        ps.drain_for(0.3)
        wall_us = (time.time() - t0) * 1e6
    finally:
        agg.stop()
        ps.stop()
    # Latency comes from the AGGREGATOR's own completion log, not the
    # parameter server's: in "agg" mode the parameter server receives
    # exactly one already-summed packet per slot, so its own
    # first-seen-to-complete gap is a near-zero, meaningless measurement
    # (this was a real bug in an earlier version of this script -- the
    # tell was every useragg latency reading coming back ~0us regardless
    # of worker count). The real multi-contribution accumulation, and the
    # timestamp for how long it took, happens at the aggregator.
    agg_completes = extract_complete_lines(agg.text())
    if len(agg_completes) != 1:
        raise RuntimeError(f"useragg num_workers={num_workers}: expected 1 completion at aggregator, got {agg_completes}")
    latency_us = int(agg_completes[0][5])
    ps_completes = extract_complete_lines(ps.text())
    if len(ps_completes) != 1:
        raise RuntimeError(f"useragg num_workers={num_workers}: expected 1 completion at paramserver, got {ps_completes}")
    m = re.search(r"(\d+) packets in, (\d+) aggregated packets out", agg.text())
    if not m:
        raise RuntimeError(f"useragg num_workers={num_workers}: aggregator summary line not found:\n{agg.text()}")
    uplink_packets = int(m.group(2))  # what actually crosses the aggregator->paramserver hop
    return {"uplink_packets": uplink_packets, "latency_us": latency_us, "wall_us": wall_us}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--out", default=os.path.join(REPO_ROOT, "bench", "results.csv"))
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    job_id = 1000

    for num_workers in WORKER_COUNTS:
        for trial in range(args.trials):
            job_id += 1
            r = bench_noagg(num_workers, job_id)
            rows.append({"config": "noagg", "num_workers": num_workers, "trial": trial,
                        "uplink_packets": r["uplink_packets"], "latency_us": r["latency_us"],
                        "wall_us": round(r["wall_us"], 1)})
            print(f"noagg    num_workers={num_workers:2d} trial={trial:2d} "
                  f"uplink_packets={r['uplink_packets']:3d} latency_us={r['latency_us']:6d}")

            job_id += 1
            r = bench_useragg(num_workers, job_id)
            rows.append({"config": "useragg", "num_workers": num_workers, "trial": trial,
                        "uplink_packets": r["uplink_packets"], "latency_us": r["latency_us"],
                        "wall_us": round(r["wall_us"], 1)})
            print(f"useragg  num_workers={num_workers:2d} trial={trial:2d} "
                  f"uplink_packets={r['uplink_packets']:3d} latency_us={r['latency_us']:6d}")

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["config", "num_workers", "trial", "uplink_packets", "latency_us", "wall_us"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nwrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
