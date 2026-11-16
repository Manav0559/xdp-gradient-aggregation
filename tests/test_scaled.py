#!/usr/bin/env python3
"""Wire format v3: a per-chunk shared exponent (docs/DESIGN_NOTES.md §Fixed
point). A v3 packet carries its values as round(x * 2^e) with e (0..63) in
flags bits 6-11. Every path must sum only contributions with the same e,
keep e on everything it emits, and pass on a worker's saturation (OVERFLOW
on a raw contribution) instead of reporting a wrong sum.
Run: python3 tests/test_scaled.py (after `make`)."""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_packets import grad_packet, send  # noqa: E402
from test_correctness import AGG, PARAMSERVER, Server, free_port  # noqa: E402
from test_protocol_v2 import EXPECTED_FAIL, expect_fail  # noqa: E402
from test_reliability import ACK, OVERFLOW, Endpoint, bitmap, stats_all  # noqa: E402

V3 = 3 << 12


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


@expect_fail("S1")
def test_s1_paramserver_sums_v3_at_a_fine_scale():
    # 3 x 1e-6 at e = 40 is exactly 1099512 each (round(1e-6 * 2^40))
    q = 1099512
    text, st = run_ps([lambda p: raw(p, 900, w, 3, [q, -q], 40) for w in range(3)])
    sums = complete_lines(text, 900)
    assert len(sums) == 1 and abs(float(sums[0]) - 3 * q / 2**40) < 1e-12, text


@expect_fail("S1")
def test_s1_scale_disagreement_is_rejected():
    text, st = run_ps([lambda p: raw(p, 901, 0, 2, [1 << 20], 20),
                       lambda p: raw(p, 901, 1, 2, [1 << 24], 24),
                       lambda p: raw(p, 901, 1, 2, [1 << 20], 20)])
    assert st.get("scale_mismatch") == 1, st
    sums = complete_lines(text, 901)
    assert len(sums) == 1 and float(sums[0]) == 2.0, text


@expect_fail("S1")
def test_s1_worker_saturation_is_reported_not_summed():
    text, st = run_ps([lambda p: raw(p, 902, 0, 2, [2**31 - 1], 30, OVERFLOW),
                       lambda p: raw(p, 902, 1, 2, [5], 30)])
    assert complete_lines(text, 902) == [] and "[overflow] job=902" in text, text


@expect_fail("S1")
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


@expect_fail("S1")
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
