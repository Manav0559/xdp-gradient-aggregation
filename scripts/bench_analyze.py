#!/usr/bin/env python3
"""Analyses scripts/bench_v2.sh output (docs/DESIGN_NOTES.md §Benchmark
methodology). Plain Python.

Usage: bench_analyze.py <bench-out dir> <output dir>
Reads throughput.csv, latency.csv, latency_rounds.csv, fairness.csv.
Writes summary_throughput.csv, summary_latency.csv, comparisons.csv,
fairness_summary.csv, accounting.csv and results.md. The comparisons are the
ones pre-registered in docs/OVERNIGHT_LOG.md (Phase 6) before the run."""
import csv
import os
import random
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_stats import (RNG_SEED, bootstrap_ci, holm, median, percentile,  # noqa: E402
                          permutation_test, ratio_of_medians_ci)

CONFIG_ORDER = ["noagg", "useragg", "xdp-generic", "xdp-native", "xdp-array"]


def read(path):
    return list(csv.DictReader(open(path))) if os.path.exists(path) else []


def f(x):
    return float(x) if x not in ("", None) else 0.0


def fmt(x, nd=0):
    if x is None or x != x:
        return "-"
    return f"{x:,.{nd}f}"


def jain(xs):
    xs = [x for x in xs]
    s, s2 = sum(xs), sum(x * x for x in xs)
    return (s * s) / (len(xs) * s2) if s2 else float("nan")


def order(cells):
    return sorted(cells, key=lambda k: (int(k[1]), CONFIG_ORDER.index(k[0]) if k[0] in CONFIG_ORDER else 99))


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    rng = random.Random(RNG_SEED)
    tp, lat = read(os.path.join(src, "throughput.csv")), read(os.path.join(src, "latency.csv"))
    if not tp and not lat:
        print("no benchmark rows found (the run failed before the first trial completed)")
        return 1
    rounds_rows, fair = read(os.path.join(src, "latency_rounds.csv")), read(os.path.join(src, "fairness.csv"))
    env = {}
    if os.path.exists(os.path.join(src, "environment.json")):
        import json
        env = json.load(open(os.path.join(src, "environment.json")))
    chunks_per_round = -(-int(env.get("vector_len", 1024)) // int(env.get("chunk_len", 64)))

    # ---- accounting: every packet the XDP program saw has one outcome ----
    acc_rows, bad = [], 0
    for r in tp + lat:
        if r["config"].startswith("xdp"):
            ok = f(r["xdp_rx_total"]) == f(r["xdp_terminal"])
            bad += not ok
            acc_rows.append([r["mode"], r["config"], r["workers"], r["trial"], int(f(r["xdp_rx_total"])),
                             int(f(r["xdp_terminal"])), ok])
    with open(os.path.join(out, "accounting.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["mode", "config", "workers", "trial", "xdp_rx_total", "sum_of_outcomes", "balanced"])
        w.writerows(acc_rows)

    # ---- throughput ----
    cells = defaultdict(list)
    for r in tp:
        cells[(r["config"], r["workers"])].append(r)
    tp_summary = []
    for key in order(cells):
        rs = cells[key]
        vps = [f(r["values_per_s"]) for r in rs]
        lo, hi = bootstrap_ci(vps, rng)
        runs = [f(r["xdp_run_time_ns"]) / f(r["xdp_run_cnt"]) for r in rs if f(r["xdp_run_cnt"])]
        aggc = [f(r["agg_cpu_ns"]) / f(r["agg_rx_packets"]) for r in rs if f(r["agg_rx_packets"])]
        psc = [f(r["ps_cpu_ns"]) / (f(r["rounds"]) * chunks_per_round) for r in rs if f(r["rounds"])]
        fb = sum(f(r["xdp_tx_fallback"]) for r in rs)
        accd = sum(f(r["xdp_accepted"]) for r in rs)
        tp_summary.append({
            "config": key[0], "workers": int(key[1]), "trials": len(rs), "attach_mode": rs[0]["attach_mode"],
            "values_per_s_median": median(vps), "values_per_s_ci_lo": lo, "values_per_s_ci_hi": hi,
            "rounds_per_s_median": median([f(r["rounds_per_s"]) for r in rs]),
            "resent_total": int(sum(f(r["resent"]) for r in rs)),
            "xdp_ns_per_run_median": median(runs) if runs else None,
            "agg_cpu_ns_per_pkt_median": median(aggc) if aggc else None,
            "ps_cpu_ns_per_chunk_median": median(psc) if psc else None,
            "in_network_fraction": accd / (accd + fb) if (accd + fb) else None,
            "net_rx_softirqs_by_cpu_median": "|".join(
                str(int(median([f(r["net_rx_softirqs_by_cpu"].split("|")[i]) for r in rs])))
                for i in range(len(rs[0]["net_rx_softirqs_by_cpu"].split("|")))),
        })
    with open(os.path.join(out, "summary_throughput.csv"), "w", newline="") as fh:
        if not tp_summary:
            tp_summary = [{"config": "-"}]
        w = csv.DictWriter(fh, fieldnames=list(tp_summary[0].keys()))
        w.writeheader()
        for s in tp_summary:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in s.items()})

    # ---- latency: pooled per-round samples; trials are the resampling unit ----
    samples = defaultdict(lambda: defaultdict(list))
    for r in rounds_rows:
        samples[(r["config"], r["workers"])][r["trial"]].append(f(r["round_us"]))
    lcells = defaultdict(list)
    for r in lat:
        lcells[(r["config"], r["workers"])].append(r)
    lat_summary = []
    for key in order(lcells):
        by_trial = samples.get(key, {})
        pooled = sorted(x for v in by_trial.values() for x in v)
        trials = list(by_trial.values())

        def pct_of(p):
            return lambda ts: percentile(sorted(x for t in ts for x in t), p)
        p50_ci = bootstrap_ci(trials, rng, stat=pct_of(50), resamples=500) if trials else (None, None)
        p99_ci = bootstrap_ci(trials, rng, stat=pct_of(99), resamples=500) if trials else (None, None)
        prof = [f(r["agg_profile_ns"]) / f(r["agg_profile_pkts"]) for r in lcells[key] if f(r["agg_profile_pkts"])]
        runs = [f(r["xdp_run_time_ns"]) / f(r["xdp_run_cnt"]) for r in lcells[key] if f(r["xdp_run_cnt"])]
        lat_summary.append({
            "config": key[0], "workers": int(key[1]), "trials": len(trials), "samples": len(pooled),
            "p50_us": percentile(pooled, 50), "p50_ci_lo": p50_ci[0], "p50_ci_hi": p50_ci[1],
            "p95_us": percentile(pooled, 95), "p99_us": percentile(pooled, 99) if len(pooled) >= 1000 else None,
            "p99_ci_lo": p99_ci[0] if len(pooled) >= 1000 else None, "p99_ci_hi": p99_ci[1] if len(pooled) >= 1000 else None,
            "p999_us": percentile(pooled, 99.9) if len(pooled) >= 10000 else None,
            "agg_profile_ns_per_pkt": median(prof) if prof else None,
            "xdp_ns_per_run": median(runs) if runs else None,
        })
    with open(os.path.join(out, "summary_latency.csv"), "w", newline="") as fh:
        if not lat_summary:
            lat_summary = [{"config": "-"}]
        w = csv.DictWriter(fh, fieldnames=list(lat_summary[0].keys()))
        w.writeheader()
        for s in lat_summary:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in s.items()})

    # ---- pre-registered comparisons vs useragg ----
    comps = []
    for fam, metric, data in (("T_throughput", "values_per_s", cells), ("L_round_p50", "round_p50_us", None)):
        for n in sorted({int(k[1]) for k in cells}):
            for cfg in ("xdp-generic", "xdp-native"):
                if fam == "T_throughput":
                    a = [f(r["values_per_s"]) for r in cells.get((cfg, str(n)), [])]
                    b = [f(r["values_per_s"]) for r in cells.get(("useragg", str(n)), [])]
                else:
                    a = [percentile(sorted(v), 50) for v in samples.get((cfg, str(n)), {}).values()]
                    b = [percentile(sorted(v), 50) for v in samples.get(("useragg", str(n)), {}).values()]
                if len(a) < 2 or len(b) < 2:
                    continue
                delta, p = permutation_test(a, b, rng)
                lo, hi = ratio_of_medians_ci(a, b, rng)
                comps.append({"family": fam, "workers": n, "config": cfg, "metric": metric,
                              "config_median": median(a), "useragg_median": median(b),
                              "ratio": median(a) / median(b) if median(b) else None, "ratio_ci_lo": lo,
                              "ratio_ci_hi": hi, "cliffs_delta": delta, "p": p, "n": f"{len(a)} vs {len(b)}"})
    for fam in {c["family"] for c in comps}:
        idx = [i for i, c in enumerate(comps) if c["family"] == fam]
        for i, adj in zip(idx, holm([comps[i]["p"] for i in idx])):
            comps[i]["p_holm"] = adj
    if comps:
        with open(os.path.join(out, "comparisons.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(comps[0].keys()))
            w.writeheader()
            for c in comps:
                w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in c.items()})

    # ---- fairness ----
    fsum = []
    by_policy = defaultdict(lambda: defaultdict(list))
    for r in fair:
        by_policy[r["policy"]][r["trial"]].append(r)
    for policy in ("none", "quota-drop", "quota-fallback", "array-small"):
        trials = by_policy.get(policy)
        if not trials:
            continue
        jr, jn, per_job, resent, inn = [], [], defaultdict(list), [], []
        for t, rows in trials.items():
            g = [f(r["goodput_rounds_per_s"]) for r in sorted(rows, key=lambda r: r["job"])]
            d = [f(r["demand_window"]) for r in sorted(rows, key=lambda r: r["job"])]
            jr.append(jain(g))
            jn.append(jain([x / y for x, y in zip(g, d)]))
            for r in rows:
                per_job[r["job"]].append(f(r["goodput_rounds_per_s"]))
            resent.append(sum(f(r["resent"]) for r in rows))
            a, fb = f(rows[0]["xdp_accepted"]), f(rows[0]["xdp_tx_fallback"])
            inn.append(a / (a + fb) if a + fb else float("nan"))
        fsum.append({"policy": policy, "trials": len(trials),
                     "goodput_job1_demand64": median(per_job["1"]), "goodput_job2_demand32": median(per_job["2"]),
                     "goodput_job3_demand16": median(per_job["3"]), "jain_raw": median(jr),
                     "jain_demand_normalised": median(jn), "retransmissions": median(resent),
                     "in_network_fraction": median(inn)})
    if fsum:
        with open(os.path.join(out, "fairness_summary.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(fsum[0].keys()))
            w.writeheader()
            for s in fsum:
                w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in s.items()})

    # ---- markdown ----
    md = ["### Throughput (window 64, closed loop)\n",
          "| config | workers | attach | values/s median [95% CI] | rounds/s | XDP ns/run | agg CPU ns/pkt | PS CPU ns/chunk | in-network | retransmissions |",
          "|---|---:|---|---|---:|---:|---:|---:|---:|---:|"]
    for s in tp_summary:
        inn = "-" if s["in_network_fraction"] is None else f"{s['in_network_fraction']:.3f}"
        md.append(f"| {s['config']} | {s['workers']} | {s['attach_mode']} | {fmt(s['values_per_s_median'])} "
                  f"[{fmt(s['values_per_s_ci_lo'])}, {fmt(s['values_per_s_ci_hi'])}] | {fmt(s['rounds_per_s_median'])} | "
                  f"{fmt(s['xdp_ns_per_run_median'], 1)} | {fmt(s['agg_cpu_ns_per_pkt_median'])} | "
                  f"{fmt(s['ps_cpu_ns_per_chunk_median'])} | "
                  f"{inn} | "
                  f"{s['resent_total']} |")
    md += ["\n### Round completion time (synchronous rounds, measured at the worker)\n",
           "| config | workers | samples | p50 us [95% CI] | p95 us | p99 us [95% CI] | p99.9 us | agg algorithm ns/pkt | XDP ns/run |",
           "|---|---:|---:|---|---:|---|---:|---:|---:|"]
    for s in lat_summary:
        md.append(f"| {s['config']} | {s['workers']} | {s['samples']} | {fmt(s['p50_us'])} [{fmt(s['p50_ci_lo'])}, "
                  f"{fmt(s['p50_ci_hi'])}] | {fmt(s['p95_us'])} | {fmt(s['p99_us'])} [{fmt(s['p99_ci_lo'])}, "
                  f"{fmt(s['p99_ci_hi'])}] | {fmt(s['p999_us'])} | {fmt(s['agg_profile_ns_per_pkt'])} | "
                  f"{fmt(s['xdp_ns_per_run'], 1)} |")
    if comps:
        md += ["\n### Pre-registered comparisons against userspace aggregation\n",
               "| family | workers | config | config median | useragg median | ratio [95% CI] | Cliff's delta | p | p (Holm) | n |",
               "|---|---:|---|---:|---:|---|---:|---:|---:|---|"]
        for c in comps:
            md.append(f"| {c['family']} | {c['workers']} | {c['config']} | {fmt(c['config_median'])} | "
                      f"{fmt(c['useragg_median'])} | {fmt(c['ratio'], 3)} [{fmt(c['ratio_ci_lo'], 3)}, "
                      f"{fmt(c['ratio_ci_hi'], 3)}] | {c['cliffs_delta']:.3f} | {c['p']:.4f} | {c['p_holm']:.4f} | {c['n']} |")
    if fsum:
        md += ["\n### Fairness: three jobs with demand 4:2:1 sharing one XDP aggregator\n",
               "| policy | goodput job1 (demand 64) | job2 (32) | job3 (16) | Jain raw | Jain / demand | retransmissions | in-network fraction |",
               "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for s in fsum:
            md.append(f"| {s['policy']} | {fmt(s['goodput_job1_demand64'])} | {fmt(s['goodput_job2_demand32'])} | "
                      f"{fmt(s['goodput_job3_demand16'])} | {s['jain_raw']:.3f} | {s['jain_demand_normalised']:.3f} | "
                      f"{fmt(s['retransmissions'])} | {s['in_network_fraction']:.3f} |")
    md.append(f"\nXDP packet accounting balanced in {len(acc_rows) - bad}/{len(acc_rows)} trials.")
    text = "\n".join(md) + "\n"
    open(os.path.join(out, "results.md"), "w").write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
