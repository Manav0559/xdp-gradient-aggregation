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

Latency distribution rigor: beyond mean/min/max, this script also computes
p50/p95/p99 per (config, num_workers) cell, a bootstrap 95% confidence
interval on the median, and a permutation test (with Cliff's delta effect
size) comparing the noagg vs. useragg latency distributions at each worker
count -- see the "STATISTICAL RIGOR" section below for why, and why plain
Python rather than NumPy/SciPy (neither is installed in this dev
environment -- see the failed `import numpy`/`import scipy` probe recorded
when this was built; the project's Python scripts have always run on plain
Python 3, so that discipline continues here rather than adding a dependency
this repo has never needed before).

Run: python3 scripts/benchmark.py [--trials N] [--out bench/results.csv]
     [--percentiles-out bench/results_percentiles.csv]
"""
import argparse
import csv
import os
import random
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

# ---------------------------------------------------------------------------
# STATISTICAL RIGOR: percentiles, bootstrap CI, permutation test
#
# The original version of this script reported mean/min/max over 10 trials --
# exactly the setup prone to tail-latency effects (userspace_agg/agg.c is
# explicitly single-threaded, so one slow OS scheduling gap shows up as a
# tail outlier, not a shifted mean) and to noise at low trial counts (a
# single unlucky trial can move a mean-of-10 a lot more than it moves a
# median-of-30). This raises the default trial count to 30 -- "a few dozen,"
# per the task's own guidance -- as a judgment call between statistical
# stability and keeping a local/CI run practical: 30 trials x 4 worker
# counts x 2 configs takes roughly 3 minutes on this dev machine (measured:
# 10 trials took ~66s, so 30 scales to ~200s), vs. 10 trials' ~66s. Going to
# "a few hundred" would buy smoother tails but push a routine local run past
# what's practical to re-run on every change.
DEFAULT_TRIALS = 30
BOOTSTRAP_RESAMPLES = 2000
PERMUTATION_ITERS = 2000
RNG_SEED = 1234  # fixed seed: bootstrap CI / permutation p-value are reproducible run-to-run for the same underlying latency sample


def percentile(sorted_vals, p):
    """Linear-interpolation percentile (matches NumPy's default 'linear'
    method) over an already-sorted list, p in [0, 100]. Plain Python, no
    dependency -- this is the one piece of "statistics" simple enough not
    to need one."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return float(sorted_vals[f])
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def median(vals):
    s = sorted(vals)
    return percentile(s, 50)


def bootstrap_median_ci(vals, rng, num_resamples=BOOTSTRAP_RESAMPLES, alpha=0.05):
    """Plain-Python bootstrap 95% CI on the median: resample `vals` with
    replacement `num_resamples` times, take each resample's median, and
    report the [alpha/2, 1-alpha/2] percentiles of that distribution of
    medians. A simple resampling loop, exactly as much machinery as the
    task calls for -- no SciPy needed."""
    n = len(vals)
    if n == 0:
        return (0.0, 0.0)
    medians = []
    for _ in range(num_resamples):
        sample = [vals[rng.randrange(n)] for _ in range(n)]
        medians.append(median(sample))
    medians.sort()
    lo = percentile(medians, 100 * (alpha / 2))
    hi = percentile(medians, 100 * (1 - alpha / 2))
    return (lo, hi)


def cliffs_delta(a, b):
    """Cliff's delta: (#pairs where a_i > b_j) - (#pairs where a_i < b_j),
    normalized by n_a*n_b. This is the natural effect-size companion to a
    Mann-Whitney U test (delta = 2*U/(n_a*n_b) - 1) -- a rank-based,
    distribution-free measure of "how much bigger is distribution a than
    distribution b," in [-1, 1]. 0 = fully overlapping, +/-1 = fully
    separated."""
    n_a, n_b = len(a), len(b)
    if n_a == 0 or n_b == 0:
        return 0.0
    gt = lt = 0
    for x in a:
        for y in b:
            if x > y:
                gt += 1
            elif x < y:
                lt += 1
    return (gt - lt) / (n_a * n_b)


def permutation_test(a, b, rng, num_iters=PERMUTATION_ITERS):
    """Two-sided permutation test using Cliff's delta as the test
    statistic -- a distribution-free stand-in for a Mann-Whitney U test
    that needs no SciPy: pool the two samples, repeatedly reassign labels
    at random, and see how often a random relabeling produces a delta at
    least as extreme as the one actually observed. Returns
    (observed_cliffs_delta, p_value). Add-one smoothing on both numerator
    and denominator avoids ever reporting an unearned p=0.0 from a finite
    number of permutations."""
    observed = cliffs_delta(a, b)
    pooled = list(a) + list(b)
    n_a = len(a)
    as_extreme = 0
    for _ in range(num_iters):
        rng.shuffle(pooled)
        perm_a = pooled[:n_a]
        perm_b = pooled[n_a:]
        if abs(cliffs_delta(perm_a, perm_b)) >= abs(observed):
            as_extreme += 1
    p_value = (as_extreme + 1) / (num_iters + 1)
    return observed, p_value


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
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--out", default=os.path.join(REPO_ROOT, "bench", "results.csv"))
    parser.add_argument("--percentiles-out", default=os.path.join(REPO_ROOT, "bench", "results_percentiles.csv"),
                         help="companion file for per-cell p50/p95/p99, bootstrap median CI, and the "
                              "noagg-vs-useragg permutation-test result -- a separate file rather than "
                              "changing results.csv's existing per-trial schema, since dashboard/index.html "
                              "already parses that schema directly (one row per trial, latency_us as a "
                              "single value) and this is per-CELL aggregate data, a different shape.")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    job_id = 1000
    # latencies[config][num_workers] -> list of latency_us across trials, kept in
    # memory (not re-read from the CSV) so the percentile/CI/permutation-test
    # pass below has the exact real per-trial values this run just measured.
    latencies = {"noagg": {}, "useragg": {}}

    for num_workers in WORKER_COUNTS:
        for trial in range(args.trials):
            job_id += 1
            r = bench_noagg(num_workers, job_id)
            rows.append({"config": "noagg", "num_workers": num_workers, "trial": trial,
                        "uplink_packets": r["uplink_packets"], "latency_us": r["latency_us"],
                        "wall_us": round(r["wall_us"], 1)})
            latencies["noagg"].setdefault(num_workers, []).append(r["latency_us"])
            print(f"noagg    num_workers={num_workers:2d} trial={trial:2d} "
                  f"uplink_packets={r['uplink_packets']:3d} latency_us={r['latency_us']:6d}")

            job_id += 1
            r = bench_useragg(num_workers, job_id)
            rows.append({"config": "useragg", "num_workers": num_workers, "trial": trial,
                        "uplink_packets": r["uplink_packets"], "latency_us": r["latency_us"],
                        "wall_us": round(r["wall_us"], 1)})
            latencies["useragg"].setdefault(num_workers, []).append(r["latency_us"])
            print(f"useragg  num_workers={num_workers:2d} trial={trial:2d} "
                  f"uplink_packets={r['uplink_packets']:3d} latency_us={r['latency_us']:6d}")

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["config", "num_workers", "trial", "uplink_packets", "latency_us", "wall_us"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nwrote {len(rows)} rows to {args.out}")

    # ---- percentiles / bootstrap CI / permutation test, per (config, num_workers) ----
    rng = random.Random(RNG_SEED)
    perc_rows = []
    print("\nlatency distribution summary (p50/p95/p99, 95% bootstrap CI on median):")
    for num_workers in WORKER_COUNTS:
        noagg_lat = latencies["noagg"].get(num_workers, [])
        useragg_lat = latencies["useragg"].get(num_workers, [])
        # Comparison is always "useragg vs. noagg" at this worker count;
        # both rows carry the same |delta| and p-value, with delta's sign
        # flipped for the noagg row (cliffs_delta(a,b) == -cliffs_delta(b,a)),
        # so a reader looking at either row alone still gets a directional
        # answer without needing to cross-reference the other config's row.
        delta_useragg_vs_noagg, p_value = permutation_test(useragg_lat, noagg_lat, rng)
        per_config = {
            "noagg": (noagg_lat, -delta_useragg_vs_noagg),
            "useragg": (useragg_lat, delta_useragg_vs_noagg),
        }
        for config, (lat, delta) in per_config.items():
            s = sorted(lat)
            ci_lo, ci_hi = bootstrap_median_ci(lat, rng)
            row = {
                "config": config,
                "num_workers": num_workers,
                "n": len(lat),
                "p50": round(percentile(s, 50), 1),
                "p95": round(percentile(s, 95), 1),
                "p99": round(percentile(s, 99), 1),
                "median_ci95_lo": round(ci_lo, 1),
                "median_ci95_hi": round(ci_hi, 1),
                "cliffs_delta_vs_other_config": round(delta, 4),
                "p_value_vs_other_config": round(p_value, 4),
                "significant_at_0.05": p_value < 0.05,
            }
            perc_rows.append(row)
            print(f"  {config:8s} num_workers={num_workers:2d}  n={row['n']:3d}  "
                  f"p50={row['p50']:7.1f}  p95={row['p95']:7.1f}  p99={row['p99']:7.1f}  "
                  f"median_ci95=[{row['median_ci95_lo']:.1f}, {row['median_ci95_hi']:.1f}]  "
                  f"cliffs_delta={row['cliffs_delta_vs_other_config']:+.4f}  p={row['p_value_vs_other_config']:.4f}"
                  f"{'  *significant*' if row['significant_at_0.05'] else ''}")

    with open(args.percentiles_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["config", "num_workers", "n", "p50", "p95", "p99",
                                                "median_ci95_lo", "median_ci95_hi",
                                                "cliffs_delta_vs_other_config", "p_value_vs_other_config",
                                                "significant_at_0.05"])
        writer.writeheader()
        writer.writerows(perc_rows)
    print(f"\nwrote {len(perc_rows)} rows to {args.percentiles_out}")


if __name__ == "__main__":
    main()
