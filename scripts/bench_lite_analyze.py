#!/usr/bin/env python3
"""Summarises bench_lite.sh output: per-trial derived metrics and packet
accounting, per-cell medians with bootstrap CIs, and Holm-corrected
permutation tests of useragg vs xdp. Plain Python.

Usage: bench_lite_analyze.py <raw.csv> <out_dir>
Writes <out_dir>/summary.csv, comparisons.csv, accounting.csv, results.md.
Comparisons are pre-registered in docs/WORKLOG.md (Phase 3.5)."""
import csv
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_stats import (RNG_SEED, bootstrap_ci, holm, median,  # noqa: E402
                          permutation_test, ratio_of_medians_ci)



def num(row, k):
    v = row.get(k, "")
    return float(v) if v not in ("", None) else 0.0


def derive(row):
    rounds, sent = num(row, "rounds"), num(row, "sent")
    done = num(row, "ps_completed")
    span = (num(row, "ps_last_complete_us") - num(row, "ps_first_complete_us")) / 1e6
    d = {
        "completion_ratio": done / rounds if rounds else 0.0,
        "goodput_rounds_per_s": done / span if span > 0 else 0.0,
        "xdp_ns_per_run": num(row, "xdp_run_time_ns") / num(row, "xdp_run_cnt") if num(row, "xdp_run_cnt") else None,
        "agg_cpu_ns_per_pkt": num(row, "agg_cpu_ns") / num(row, "agg_rx_packets") if num(row, "agg_rx_packets") else None,
        "ps_cpu_ns_per_pkt": num(row, "ps_cpu_ns") / num(row, "ps_rx_packets") if num(row, "ps_rx_packets") else None,
        "ps_rx_per_round": num(row, "ps_rx_packets") / rounds if rounds else 0.0,
    }
    # Packet accounting: every packet sent is either received at the next hop
    # or counted as dropped there (socket RcvbufErrors), and every packet the
    # XDP program sees ends in exactly one outcome counter. Loss is not an
    # imbalance; it shows up as completion_ratio < 1.
    cfg, ps_in = row["config"], num(row, "ps_rx_packets") + num(row, "ps_rcvbuf_errors")
    if cfg == "noagg":
        checks = {"ps_in == sent": (ps_in, sent)}
    elif cfg == "useragg":
        agg_in = num(row, "agg_rx_packets") + num(row, "root_rcvbuf_errors")
        checks = {"agg_in == sent": (agg_in, sent),
                  "ps_in == agg_tx": (ps_in, num(row, "agg_tx_aggregates"))}
    else:
        checks = {"xdp_rx == sent": (num(row, "xdp_rx_total"), sent),
                  "xdp_rx == accepted + other outcomes": (num(row, "xdp_rx_total"), num(row, "xdp_accepted") + num(row, "xdp_other_outcomes")),
                  "xdp_tx == slots completed": (num(row, "xdp_tx_aggregate"), num(row, "xdp_slot_completed")),
                  "ps_in == xdp_tx": (ps_in, num(row, "xdp_tx_aggregate"))}
    d["accounting_ok"] = all(a == b for a, b in checks.values())
    d["accounting_detail"] = "; ".join(f"{k}: {int(a)} vs {int(b)}" for k, (a, b) in checks.items() if a != b)
    return d


def fmt(x, nd=1):
    return "-" if x is None or x != x else f"{x:,.{nd}f}"


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    rows = list(csv.DictReader(open(sys.argv[1])))
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    rng = random.Random(RNG_SEED)
    for r in rows:
        r.update(derive(r))

    with open(os.path.join(out, "accounting.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "workers", "rate_pps", "trial", "accounting_ok", "detail"])
        for r in rows:
            w.writerow([r["config"], r["workers"], r["rate_pps"], r["trial"], r["accounting_ok"], r["accounting_detail"]])

    cells = {}
    for r in rows:
        cells.setdefault((r["config"], int(r["workers"]), int(r["rate_pps"])), []).append(r)

    summary = []
    for (cfg, n, rate), rs in sorted(cells.items()):
        def col(k):
            return [r[k] for r in rs if r[k] is not None]
        cr, gp = col("completion_ratio"), col("goodput_rounds_per_s")
        ach = [num(r, "achieved_pps") for r in rs]
        xdp, aggc, psc = col("xdp_ns_per_run"), col("agg_cpu_ns_per_pkt"), col("ps_cpu_ns_per_pkt")
        summary.append({
            "config": cfg, "workers": n, "rate_pps": rate, "trials": len(rs),
            "sender_achieved_pps_median": median(ach),
            "completion_ratio_median": median(cr), "completion_ratio_ci_lo": bootstrap_ci(cr, rng)[0],
            "completion_ratio_ci_hi": bootstrap_ci(cr, rng)[1],
            "goodput_rounds_per_s_median": median(gp), "goodput_ci_lo": bootstrap_ci(gp, rng)[0],
            "goodput_ci_hi": bootstrap_ci(gp, rng)[1],
            "ps_rx_packets_per_round_median": median(col("ps_rx_per_round")),
            "xdp_ns_per_run_median": median(xdp) if xdp else None,
            "agg_cpu_ns_per_pkt_median": median(aggc) if aggc else None,
            "ps_cpu_ns_per_pkt_median": median(psc) if psc else None,
            "accounting_ok_trials": sum(1 for r in rs if r["accounting_ok"]),
        })
    with open(os.path.join(out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        for s in summary:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in s.items()})

    # Pre-registered (docs/WORKLOG.md, Phase 3.5), per worker count,
    # useragg vs xdp with the sender unpaced: F1 goodput (rounds/s), F2
    # completion ratio. Holm-corrected within each family. Paced cells are
    # descriptive only: in an open loop their goodput equals the offered rate.
    comps = []
    for fam, metric in (("F1_goodput_unpaced", "goodput_rounds_per_s"), ("F2_completion_unpaced", "completion_ratio")):
        for n in sorted({s["workers"] for s in summary}):
            if ("xdp", n, 0) not in cells or ("useragg", n, 0) not in cells:
                continue
            a = [r[metric] for r in cells[("xdp", n, 0)]]
            b = [r[metric] for r in cells[("useragg", n, 0)]]
            delta, p = permutation_test(a, b, rng)
            lo, hi = ratio_of_medians_ci(a, b, rng)
            comps.append({"family": fam, "workers": n, "rate_pps": 0, "metric": metric,
                          "xdp_median": median(a), "useragg_median": median(b),
                          "ratio_xdp_over_useragg": median(a) / median(b) if median(b) else None,
                          "ratio_ci_lo": lo, "ratio_ci_hi": hi, "cliffs_delta": delta, "p": p})
    for fam in {c["family"] for c in comps}:
        idx = [i for i, c in enumerate(comps) if c["family"] == fam]
        for i, adj in zip(idx, holm([comps[i]["p"] for i in idx])):
            comps[i]["p_holm"] = adj
    if comps:
        with open(os.path.join(out, "comparisons.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(comps[0].keys()))
            w.writeheader()
            for c in comps:
                w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in c.items()})

    with open(os.path.join(out, "results.md"), "w") as f:
        f.write("| config | workers | target pps | sender pps | completion (median, 95% CI) | goodput rounds/s (median, 95% CI) | XDP ns/run | agg CPU ns/pkt | PS CPU ns/pkt | accounting ok |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|\n")
        for s in summary:
            f.write(f"| {s['config']} | {s['workers']} | {s['rate_pps'] or 'unpaced'} | {fmt(s['sender_achieved_pps_median'], 0)} | "
                    f"{s['completion_ratio_median']:.4f} [{s['completion_ratio_ci_lo']:.4f}, {s['completion_ratio_ci_hi']:.4f}] | "
                    f"{fmt(s['goodput_rounds_per_s_median'], 0)} [{fmt(s['goodput_ci_lo'], 0)}, {fmt(s['goodput_ci_hi'], 0)}] | "
                    f"{fmt(s['xdp_ns_per_run_median'])} | {fmt(s['agg_cpu_ns_per_pkt_median'], 0)} | {fmt(s['ps_cpu_ns_per_pkt_median'], 0)} | "
                    f"{s['accounting_ok_trials']}/{s['trials']} |\n")
        if comps:
            f.write("\n| family | workers | rate | metric | xdp median | useragg median | ratio xdp/useragg [95% CI] | Cliff's delta | p | p (Holm) |\n")
            f.write("|---|---|---|---|---|---|---|---|---|---|\n")
            for c in comps:
                f.write(f"| {c['family']} | {c['workers']} | {c['rate_pps'] or 'unpaced'} | {c['metric']} | {fmt(c['xdp_median'], 4)} | "
                        f"{fmt(c['useragg_median'], 4)} | {fmt(c['ratio_xdp_over_useragg'], 3)} [{fmt(c['ratio_ci_lo'], 3)}, {fmt(c['ratio_ci_hi'], 3)}] | "
                        f"{c['cliffs_delta']:.3f} | {c['p']:.4f} | {c['p_holm']:.4f} |\n")
    print(open(os.path.join(out, "results.md")).read())
    bad = [r for r in rows if not r["accounting_ok"]]
    print(f"accounting balanced in {len(rows) - len(bad)}/{len(rows)} trials")
    for r in bad[:10]:
        print(f"  {r['config']} w{r['workers']} r{r['rate_pps']} t{r['trial']}: {r['accounting_detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
