#!/usr/bin/env python3
"""Parameter-server merge rules for mixed in-network and fallback paths
(docs/DESIGN_NOTES.md §Fallback): raw/fallback contributions, partial and
complete aggregates for the same key must never be double counted, and a key
must still complete. Run: python3 tests/test_fallback.py (after `make`)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_packets import fx, grad_packet, send  # noqa: E402
from test_correctness import PARAMSERVER, Server, extract_complete_lines, free_port  # noqa: E402
from test_reliability import ACK, FALLBACK, OVERFLOW, PARTIAL, RESEND, V2, bitmap, stats_all  # noqa: E402

AGG = 0xFFFF


def raw(port, job, w, n, v, flags=FALLBACK):
    send(grad_packet(job, 0, 0, w, n, 2, [fx(v), fx(v)], V2 | flags, bitmap(w)), port)


def agg(port, job, workers, n, total, flags=0):
    send(grad_packet(job, 0, 0, AGG, n, 2, [fx(total), fx(total)], V2 | flags, bitmap(*workers)), port)


def run(steps):
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "agg"])
    try:
        for step in steps:
            step(port)
            ps.drain_for(0.05)
        ps.drain_for(0.2)
        st = stats_all(ps)
    finally:
        ps.stop()
    return extract_complete_lines(ps.text()), st, ps.text()


def test_partial_plus_fallback_completes():
    done, st, log = run([lambda p: agg(p, 700, (0, 1), 3, 3.0, PARTIAL), lambda p: raw(p, 700, 2, 3, 4.0)])
    assert len(done) == 1 and abs(float(done[0][4]) - 7.0) < 1e-3, log


def test_fallback_then_superset_aggregate_is_not_double_counted():
    # worker 1 fell back, then its resend joined a fresh aggregator slot
    done, st, log = run([lambda p: raw(p, 701, 1, 3, 2.0), lambda p: agg(p, 701, (0, 1, 2), 3, 6.0)])
    assert len(done) == 1 and abs(float(done[0][4]) - 6.0) < 1e-3, log
    assert st["overlap_superset"] == 1, st


def test_subset_partial_is_dropped():
    done, st, log = run([lambda p: agg(p, 702, (0, 1, 2), 4, 6.0, PARTIAL), lambda p: agg(p, 702, (0, 1), 4, 3.0, PARTIAL),
                         lambda p: raw(p, 702, 3, 4, 1.0)])
    assert st["overlap_subset"] == 1, st
    assert len(done) == 1 and abs(float(done[0][4]) - 7.0) < 1e-3, log


def test_partial_overlap_is_rejected_then_fallback_finishes():
    done, st, log = run([lambda p: agg(p, 703, (0, 1), 3, 3.0, PARTIAL), lambda p: agg(p, 703, (1, 2), 3, 5.0, PARTIAL),
                         lambda p: raw(p, 703, 2, 3, 3.0, FALLBACK | RESEND)])
    assert st["overlap_rejected"] == 1, st
    assert len(done) == 1 and abs(float(done[0][4]) - 6.0) < 1e-3, log


def test_aggregate_after_completion_is_a_conflict_not_a_second_result():
    done, st, log = run([lambda p: raw(p, 704, 0, 2, 1.0), lambda p: raw(p, 704, 1, 2, 1.0),
                         lambda p: agg(p, 704, (0, 1), 2, 2.0)])
    assert len(done) == 1 and st["aggregate_conflict"] == 1 and st["tx_result_resend"] == 1, (st, log)


def test_overflow_flag_on_a_partial_poisons_the_key():
    done, st, log = run([lambda p: agg(p, 705, (0, 1), 3, 1.0, PARTIAL | OVERFLOW), lambda p: raw(p, 705, 2, 3, 1.0)])
    assert done == [] and "[overflow] job=705" in log, log


def test_aggregate_with_bitmap_beyond_fanin_is_rejected():
    done, st, log = run([lambda p: agg(p, 706, (0, 5), 3, 1.0, PARTIAL)])
    assert st["rej_kind"] == 1 and done == [], st


def main():
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    bad = 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
        except Exception as e:  # noqa: BLE001
            bad += 1
            print(f"FAIL: {t.__name__}: {e}")
    print(f"\n{len(tests)} tests, {bad} failed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
