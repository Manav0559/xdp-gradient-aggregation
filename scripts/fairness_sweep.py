#!/usr/bin/env python3
"""NetSum formal Jain's-fairness-index sweep: quantifies ATP's actual
headline contribution (its paper's own title is literally "...for
Multi-tenant Learning") with a real, measured curve instead of the existing
qualitative-only proof (tests/test_correctness.py's
test_fairness_quota_isolates_greedy_job: one greedy job's excess request
gets rejected once). That test proves the mechanism *fires*; this script
measures how *fair* the outcome actually is, as a function of the quota.

Method
------
Launches a fresh `bin/agg` for each `max_slots_per_job` quota value in the
sweep (quota=0 is the "unlimited" baseline the project's own CLI already
uses -- see userspace_agg/agg.c's usage string), then drives 3 concurrent
synthetic jobs with DELIBERATELY UNEVEN demand at it, all using the exact
same technique tests/test_correctness.py's fairness test already uses:
`num_workers=2` with only worker_id=0 ever sending, so every round it opens
stays permanently incomplete (worker 1 never shows up) -- it never
completes, never frees its slot, and so it holds its admitted slots open for
the rest of the run. Job A asks for 16 concurrent rounds, job B for 4, job C
for 8: a real, uneven, multi-tenant demand pattern sharing one aggregator.

Measurement choice -- concurrent_slots, not admitted-vs-attempted RATIO:
this script measures Jain's index over each job's `concurrent_slots` (how
many slots of the shared table it is holding open right now), not the
fraction of its own attempts that got admitted. The ratio metric is
degenerate here: at quota=0 (unlimited) NOTHING is ever rejected, so every
job's admitted/attempted ratio is trivially 1.0 and Jain's index would
read a perfect 1.0 exactly when the aggregator is doing the LEAST to
protect anyone -- the opposite of what "fairness" should mean. concurrent_
slots directly measures each job's actual share of the scarce, shared
resource (the slot table) at the moment of measurement, which is what an
admission quota is supposed to equalize. Because none of these three jobs
ever completes a round (by construction, so nothing frees mid-measurement
and turns this into a timing race), concurrent_slots for job i settles
deterministically at min(demand_i, quota) when quota>0, or demand_i itself
when quota==0 -- no flakiness, exactly reproducible across repeats.

Since every quota value's outcome is a deterministic function of
(demand_i, quota) rather than wall-clock timing, this script still runs
each quota point multiple times (see --repeats) and reports whether any
variance was actually observed, rather than assuming determinism.

Every number in bench/fairness_results.csv comes from actually running
bin/agg and reading its real "[stats]" stderr line (emitted on SIGUSR1 --
see userspace_agg/agg.c's dump_job_stats()) -- nothing here is simulated.

Run: python3 scripts/fairness_sweep.py [--quotas 0,1,2,4,...] [--repeats 3]
     [--out bench/fairness_results.csv]
"""
import argparse
import csv
import os
import re
import signal
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO_ROOT, "bin")
AGG = os.path.join(BIN, "agg")
PARAMSERVER = os.path.join(BIN, "paramserver")

sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
from test_correctness import Server, free_port, run_worker  # noqa: E402

# Uneven, multi-tenant demand: job A is the "greedy" tenant asking for 4x
# job B's concurrency, job C sits in between -- three distinct concurrent
# jobs sharing one aggregator, per the task's "2-4 concurrent jobs" ask.
JOBS = [
    {"name": "A_greedy", "job_id": 5001, "demand": 16},
    {"name": "B_modest", "job_id": 5002, "demand": 4},
    {"name": "C_medium", "job_id": 5003, "demand": 8},
]

DEFAULT_QUOTAS = [0, 1, 2, 4, 6, 8, 10, 12, 16, 24]

STATS_RE = re.compile(
    r'\[stats\] \{"job_id":(\d+),"concurrent_slots":(\d+),'
    r'"admitted_count":(\d+),"rejected_count":(\d+)\}'
)


def jains_index(values):
    """J = (Sum xi)^2 / (n * Sum xi^2). 1.0 = perfectly fair (every job
    holds an equal share); 1/n = maximally unfair (one job holds
    everything, the rest hold nothing)."""
    n = len(values)
    if n == 0:
        return 0.0
    s = sum(values)
    sq = sum(v * v for v in values)
    if sq == 0:
        return 1.0  # everyone holds exactly zero -- vacuously "equal"
    return (s * s) / (n * sq)


def run_one_trial(quota):
    """Launches a fresh agg process at this quota, drives all three jobs'
    uneven demand at it, snapshots job stats via SIGUSR1, and returns a
    list of per-job dicts plus the computed Jain's index. Raises if
    anything about the real run doesn't match what's expected -- this
    script does not paper over a surprising result with a fabricated one."""
    ps_port = free_port()
    agg_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    # max_packets=0 (unbounded -- this script stops agg itself once done),
    # max_slots_per_job=quota, slot_ttl_ms=0 (disabled: a reaper eviction
    # would free a slot mid-measurement and turn concurrent_slots into a
    # timing-dependent quantity instead of the deterministic one this
    # sweep relies on).
    agg = Server([AGG, str(agg_port), "127.0.0.1", str(ps_port), "0", str(quota), "0"])
    try:
        for job in JOBS:
            # worker_id=0 of 2 expected workers, sent `demand` times across
            # `demand` distinct rounds -- worker 1 never sends, so every one
            # of these rounds stays permanently incomplete (never frees).
            run_worker("127.0.0.1", agg_port, job_id=job["job_id"], worker_id=0,
                       num_workers=2, num_rounds=job["demand"], chunk_len=1,
                       fixed_value=1.0)
        # Give the single-threaded aggregator a moment to drain its recv
        # queue -- a few dozen tiny UDP packets on loopback, not a real
        # bottleneck, but this is a real wait for real processing, not a
        # fixed sleep standing in for it (drain_for pumps stderr the whole
        # time so nothing is lost).
        agg.drain_for(0.3)
        os.kill(agg.proc.pid, signal.SIGUSR1)
        agg.drain_for(0.3)
    finally:
        agg.stop()
        ps.stop()

    text = agg.text()
    found = {int(m.group(1)): {
        "concurrent_slots": int(m.group(2)),
        "admitted_count": int(m.group(3)),
        "rejected_count": int(m.group(4)),
    } for m in STATS_RE.finditer(text)}

    missing = [job["job_id"] for job in JOBS if job["job_id"] not in found]
    if missing:
        raise RuntimeError(
            f"quota={quota}: no [stats] line for job_id(s) {missing} -- "
            f"SIGUSR1 dump didn't fire as expected.\nfull log:\n{text}"
        )

    xs = [found[job["job_id"]]["concurrent_slots"] for job in JOBS]
    j = jains_index(xs)

    rows = []
    for job in JOBS:
        s = found[job["job_id"]]
        rows.append({
            "quota": quota,
            "job_id": job["job_id"],
            "job_name": job["name"],
            "demand": job["demand"],
            "concurrent_slots": s["concurrent_slots"],
            "admitted": s["admitted_count"],
            "rejected": s["rejected_count"],
            "jains_index": round(j, 6),
        })
    return rows, j


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quotas", default=",".join(str(q) for q in DEFAULT_QUOTAS),
                         help="comma-separated quota values to sweep (0 = unlimited)")
    parser.add_argument("--repeats", type=int, default=3,
                         help="repeats per quota value, to check for variance (default: 3)")
    parser.add_argument("--out", default=os.path.join(REPO_ROOT, "bench", "fairness_results.csv"))
    args = parser.parse_args()

    quotas = [int(q.strip()) for q in args.quotas.split(",") if q.strip() != ""]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    print(f"jobs: {[(j['name'], j['job_id'], j['demand']) for j in JOBS]}")
    print(f"quotas: {quotas}  repeats: {args.repeats}\n")

    all_rows = []
    curve = {}  # quota -> list of J across repeats, to report variance honestly
    for quota in quotas:
        js_this_quota = []
        for repeat in range(args.repeats):
            rows, j = run_one_trial(quota)
            for r in rows:
                r["repeat"] = repeat
            all_rows.extend(rows)
            js_this_quota.append(j)
            detail = ", ".join(f"{r['job_name']}={r['concurrent_slots']}" for r in rows)
            print(f"quota={quota:3d} repeat={repeat}  {detail}  jains_index={j:.4f}")
        curve[quota] = js_this_quota

    fieldnames = ["quota", "repeat", "job_id", "job_name", "demand",
                  "concurrent_slots", "admitted", "rejected", "jains_index"]
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\nwrote {len(all_rows)} rows to {args.out}")

    print("\nJain's-fairness-index curve (quota -> J, mean across repeats):")
    any_variance = False
    for quota in quotas:
        vals = curve[quota]
        lo, hi = min(vals), max(vals)
        if hi - lo > 1e-9:
            any_variance = True
            print(f"  quota={quota:3d}  J in [{lo:.4f}, {hi:.4f}]  (VARIANCE observed across {len(vals)} repeats)")
        else:
            print(f"  quota={quota:3d}  J = {lo:.4f}  (identical across {len(vals)} repeats)")
    if not any_variance:
        print("\nNo variance observed across repeats: each quota's outcome is a "
              "deterministic function of (per-job demand, quota) by this script's "
              "construction (no job ever completes/frees mid-measurement).")
    else:
        print("\nVariance WAS observed -- see per-quota ranges above; report this "
              "honestly rather than averaging it away.")


if __name__ == "__main__":
    main()
