#!/usr/bin/env python3
"""Wire format v3: a per-chunk shared exponent (docs/DESIGN_NOTES.md §Fixed
point). A v3 packet carries its values as round(x * 2^e) with e (0..63) in
flags bits 6-11. Every path must sum only contributions with the same e,
keep e on everything it emits, and pass on a worker's saturation (OVERFLOW
on a raw contribution) instead of reporting a wrong sum.
Run: python3 tests/test_scaled.py (after `make`)."""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_packets import grad_packet, send  # noqa: E402
from test_correctness import AGG, PARAMSERVER, Server, free_port  # noqa: E402
from test_protocol_v2 import EXPECTED_FAIL  # noqa: E402
from test_reliability import ACK, OVERFLOW, Endpoint, bitmap, run_reliable, start_agg, stats_all  # noqa: E402

V3 = 3 << 12
TRAIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "train_mlp")


def v3flags(e, bits=0):
    return V3 | (e << 6) | bits


def raw(port, job, w, n, ints, e, bits=0, rnd=0):
    send(grad_packet(job, rnd, 0, w, n, len(ints), ints, v3flags(e, bits), bitmap(w)), port)


def complete_lines(text, job):
    return re.findall(rf"\[complete\] job={job} round=0 chunk=0 contributions=\d+ sum\[0\]=([-0-9.e]+)", text)


def run_ps(steps):
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        for s in steps:
            s(port)
        ps.drain_for(0.3)
        st = stats_all(ps)
    finally:
        ps.stop()
    return ps.text(), st


def test_s1_paramserver_sums_v3_at_a_fine_scale():
    # 3 x 1e-6 at e = 40 is exactly 1099512 each (round(1e-6 * 2^40))
    q = 1099512
    text, st = run_ps([lambda p, w=w: raw(p, 900, w, 3, [q, -q], 40) for w in range(3)])
    sums = complete_lines(text, 900)
    assert len(sums) == 1 and abs(float(sums[0]) - 3 * q / 2**40) < 1e-12, text


def test_s1_scale_disagreement_is_rejected():
    text, st = run_ps([lambda p: raw(p, 901, 0, 2, [1 << 20], 20),
                       lambda p: raw(p, 901, 1, 2, [1 << 24], 24),
                       lambda p: raw(p, 901, 1, 2, [1 << 20], 20)])
    assert st.get("scale_mismatch") == 1, st
    sums = complete_lines(text, 901)
    assert len(sums) == 1 and float(sums[0]) == 2.0, text


def test_s1_worker_saturation_is_reported_not_summed():
    text, st = run_ps([lambda p: raw(p, 902, 0, 2, [2**31 - 1], 30, OVERFLOW),
                       lambda p: raw(p, 902, 1, 2, [5], 30)])
    assert complete_lines(text, 902) == [] and "[overflow] job=902" in text, text


def test_s1_aggregator_and_results_keep_the_exponent():
    ps_port, agg_port = free_port(), free_port()
    agg = Server([AGG, str(agg_port), "127.0.0.1", str(ps_port)])
    ps = Server([PARAMSERVER, "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    w = [Endpoint(), Endpoint()]
    try:
        for i, e in enumerate(w):
            e.register(ps_port, 903, i, 2)
            e.s.sendto(grad_packet(903, 0, 0, i, 2, 2, [1000, -7], v3flags(37), bitmap(i)), ("127.0.0.1", agg_port))
        res = w[0].results()
        agg.drain_for(0.1)
        ast = stats_all(agg)
    finally:
        agg.stop()
        ps.stop()
        for e in w:
            e.close()
    acks = [r for r in res if r["flags"] & ACK]
    assert len(acks) == 1, res
    assert acks[0]["flags"] >> 12 == 3 and (acks[0]["flags"] >> 6) & 63 == 37, hex(acks[0]["flags"])
    assert acks[0]["vals"] == [2000, -14], acks[0]
    assert ast.get("slot_retired_ack") == 1, ast


def test_s1_aggregator_rejects_scale_disagreement():
    ps_port, agg_port = free_port(), free_port()
    agg = Server([AGG, str(agg_port), "127.0.0.1", str(ps_port)])
    try:
        raw(agg_port, 904, 0, 2, [1], 10)
        raw(agg_port, 904, 1, 2, [1], 11)
        agg.drain_for(0.2)
        st = stats_all(agg)
    finally:
        agg.stop()
    assert st.get("scale_mismatch") == 1 and st.get("tx_aggregate") == 0, st


def test_reliable_v3_workers_through_useragg_with_loss():
    # 3e-6 is 0 in Q16.16; at e=40 it is 3298535 per worker, summed exactly
    ps_port = free_port()
    agg, agg_port = start_agg(ps_port, "--quiet")
    ps = Server([PARAMSERVER, "--quiet", "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    try:
        res = run_reliable(agg_port, ps_port, 910, 3, 6, 256,
                           ("--fixed", "3e-6", "--frac-bits", "40", "--drop-every", "5", "--drop-result-every", "7"))
        ast, pst = stats_all(agg), stats_all(ps)
    finally:
        agg.stop()
        ps.stop()
    for r in res:
        assert r["results"] == 6 * 4 and r["result_mismatches"] == 0 and r["overflow_results"] == 0, r
    assert sum(r["resent"] for r in res) > 0, res
    assert ast.get("scale_mismatch") == 0 and pst.get("scale_mismatch") == 0, (ast, pst)
    assert ast.get("slots_accumulating") == 0, ast


def test_reliable_v3_saturation_is_flagged_not_summed():
    # 1.0 at e=31 does not fit in int32: every result must carry OVERFLOW
    ps_port = free_port()
    ps = Server([PARAMSERVER, "--quiet", str(ps_port), "noagg"])
    try:
        res = run_reliable(ps_port, ps_port, 911, 2, 2, 128, ("--fixed", "1.0", "--frac-bits", "31"))
    finally:
        ps.stop()
    for r in res:
        assert r["results"] == 2 * 2 and r["overflow_results"] == r["results"], r


def run_train_spike(train_dir):
    """Trains with a x1000 gradient spike at step 20 through the userspace
    aggregator: every chunk overflows once and must be retried in-step."""
    ps_port, agg_port = free_port(), free_port()
    agg = Server([AGG, "--quiet", str(agg_port), "127.0.0.1", str(ps_port)])
    ps = Server([PARAMSERVER, "--quiet", "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    out = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"netsum_spike_{os.getpid()}.csv")
    try:
        p = subprocess.run([sys.executable, os.path.join(train_dir, "train.py"), "--steps", "40",
                            "--paths", "adapt,net", "--net-format", "v3", "--grad-scale", "1e-4",
                            "--spike-step", "20", "--spike-factor", "1000", "--log-every", "40",
                            "--to", f"127.0.0.1:{agg_port}", "--ps", f"127.0.0.1:{ps_port}",
                            "--label", "useragg-v3", "--job", "920", "--out", out],
                           capture_output=True, text=True, timeout=120)
    finally:
        agg.stop()
        ps.stop()
        if os.path.exists(out):
            os.remove(out)
    return p


def test_overflowed_chunks_are_retried_in_step_at_a_lower_exponent():
    p = run_train_spike(TRAIN_DIR)
    assert p.returncode == 0, p.stdout[-800:] + p.stderr[-800:]
    assert "useragg-v3: chunks retried after OVERFLOW: 3" in p.stdout, p.stdout
    assert "adapt: chunks retried after OVERFLOW: 3" in p.stdout, p.stdout
    assert "differed from the local quantized sum: 0" in p.stdout, p.stdout


def main():
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    bad = 0
    for t in tests:
        bug = EXPECTED_FAIL.get(t.__name__)
        try:
            t()
        except Exception as e:  # noqa: BLE001
            if bug:
                print(f"XFAIL({bug}): {t.__name__}: {str(e).splitlines()[0][:140] if str(e) else type(e).__name__}")
            else:
                bad += 1
                print(f"FAIL: {t.__name__}: {e}")
            continue
        if bug:
            bad += 1
            print(f"XPASS!({bug}): {t.__name__} passed; remove its @expect_fail")
        else:
            print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)} tests, {bad} unexpected")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
