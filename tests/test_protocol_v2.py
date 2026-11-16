#!/usr/bin/env python3
"""Regression tests for the confirmed protocol bugs C1-C7 (see
docs/DESIGN_NOTES.md §Known issues). Each test drives the real binaries.

A test decorated @expect_fail("Cn") documents an open bug: the runner
reports XFAIL when it fails, and XPASS! (non-zero exit) if it passes
unexpectedly, so the decorator must be removed in the commit that fixes it.

Run: python3 tests/test_protocol_v2.py   (after `make`)
"""
import json
import os
import re
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_packets import contribute, fx, grad_packet, send  # noqa: E402
from test_correctness import (AGG, PARAMSERVER, Server,  # noqa: E402
                              extract_complete_lines, free_port)

EXPECTED_FAIL = {}


def expect_fail(bug_id):
    def wrap(fn):
        EXPECTED_FAIL[fn.__name__] = bug_id
        return fn
    return wrap


# ---- helpers -------------------------------------------------------------

def start_agg(ps_port, *extra, capacity_log2=None):
    agg_port = free_port()
    argv = [AGG]
    if capacity_log2 is not None:
        argv += ["--slot-capacity-log2", str(capacity_log2)]
    argv += [str(agg_port), "127.0.0.1", str(ps_port)] + [str(x) for x in extra]
    return Server(argv), agg_port


def job_stats(agg, job_id, wait=0.3):
    """SIGUSR1 the aggregator and return its latest [stats] dict for job_id
    (None if the job is not tracked)."""
    before = len(agg.lines)
    agg.proc.send_signal(signal.SIGUSR1)
    agg.drain_for(wait)
    found = None
    for line in agg.lines[before:]:
        m = re.search(r"\[stats\] (\{.*\})", line)
        if m:
            d = json.loads(m.group(1))
            if d.get("job_id") == job_id:
                found = d
    return found


def completes_for(text, job_id, round_=None):
    return [c for c in extract_complete_lines(text)
            if c[0] == str(job_id) and (round_ is None or c[1] == str(round_))]


def fnv1a_slot_index(job_id, round_, chunk_id, capacity):
    """Mirror of agg.c slot_key() (FNV-1a over the three uint32 fields in
    little-endian host order). Used only to pick colliding test inputs."""
    h = 1469598103934665603
    for field in (job_id, round_, chunk_id):
        for b in field.to_bytes(4, "little"):
            h ^= b
            h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h & (capacity - 1)


# ---- C1: late duplicate after completion ----------------------------------

def test_c1_late_duplicate_after_completion_leaves_no_slot():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port)
    try:
        for w in range(3):
            contribute(port, 2, 0, w, 3, 1.0)
        agg.drain_for(0.3)
        assert len(completes_for(agg.text(), 2)) == 1, agg.text()
        contribute(port, 2, 0, 1, 3, 1.0)  # late duplicate
        agg.drain_for(0.2)
        st = job_stats(agg, 2)
    finally:
        agg.stop()
        ps.stop()
    held = st["concurrent_slots"] if st else 0
    assert held == 0, f"late duplicate left {held} live slot(s) for job 2: {st}\n{agg.text()}"


def test_c1_late_duplicate_counts_against_quota():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port, 0, 1)  # max_slots_per_job = 1
    try:
        for w in range(3):
            contribute(port, 20, 0, w, 3, 1.0)
        agg.drain_for(0.2)
        contribute(port, 20, 0, 1, 3, 1.0)  # late duplicate of round 0
        agg.drain_for(0.1)
        for w in range(3):
            contribute(port, 20, 1, w, 3, 1.0)
        agg.drain_for(0.3)
    finally:
        agg.stop()
        ps.stop()
    assert len(completes_for(agg.text(), 20, 1)) == 1, (
        f"round 1 was locked out by a late duplicate of round 0:\n{agg.text()}")


# ---- C2: worker_id beyond fan-in -----------------------------------------

def test_c2_worker_id_beyond_fanin_rejected_agg():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port)
    try:
        for w in (10, 11, 12):
            contribute(port, 30, 0, w, 3, 1.0)
        agg.drain_for(0.3)
    finally:
        agg.stop()
        ps.stop()
    assert completes_for(agg.text(), 30) == [], f"worker_ids 10-12 completed a 3-worker round:\n{agg.text()}"


def test_c2_worker_id_beyond_fanin_rejected_paramserver():
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        for w in (10, 11, 12):
            contribute(port, 31, 0, w, 3, 1.0)
        ps.drain_for(0.3)
    finally:
        ps.stop()
    assert completes_for(ps.text(), 31) == [], f"worker_ids 10-12 completed a 3-worker round:\n{ps.text()}"


# ---- C3: fan-in consistency ----------------------------------------------

def _c3_disagreement(text_of, port, job):
    contribute(port, job, 0, 0, 3, 1.0)
    contribute(port, job, 0, 1, 4, 1.0)  # disagrees on the fan-in
    contribute(port, job, 0, 2, 3, 1.0)
    time.sleep(0.2)
    first = completes_for(text_of(), job)
    contribute(port, job, 0, 1, 3, 1.0)  # consistent worker 1
    time.sleep(0.2)
    return first


def test_c3_num_workers_disagreement_rejected_agg():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port)
    try:
        def text():
            agg.drain_for(0.05)
            return agg.text()
        first = _c3_disagreement(text, port, 40)
        agg.drain_for(0.2)
    finally:
        agg.stop()
        ps.stop()
    assert first == [], f"round completed using a contribution that disagreed on fan-in: {first}"
    final = completes_for(agg.text(), 40)
    assert len(final) == 1 and int(final[0][3]) == 3, f"expected one 3-way completion:\n{agg.text()}"


def test_c3_num_workers_disagreement_rejected_paramserver():
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        def text():
            ps.drain_for(0.05)
            return ps.text()
        first = _c3_disagreement(text, port, 41)
        ps.drain_for(0.2)
    finally:
        ps.stop()
    assert first == [], f"round completed using a contribution that disagreed on fan-in: {first}"
    final = completes_for(ps.text(), 41)
    assert len(final) == 1 and int(final[0][3]) == 3, f"expected one 3-way completion:\n{ps.text()}"


def test_c3_single_claim_closes_round_once_without_zombie():
    """Semantics (DESIGN_NOTES §Admission): the first accepted contribution
    fixes the fan-in, so a fan-in-1 claim legitimately completes the round.
    The later fan-in-3 contributions must be absorbed by the completed
    round, not open a second slot that can never complete."""
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port)
    try:
        contribute(port, 42, 0, 0, 1, 1.0)
        agg.drain_for(0.1)
        contribute(port, 42, 0, 1, 3, 1.0)
        contribute(port, 42, 0, 2, 3, 1.0)
        agg.drain_for(0.2)
        st = job_stats(agg, 42)
    finally:
        agg.stop()
        ps.stop()
    assert len(completes_for(agg.text(), 42)) == 1, agg.text()
    held = st["concurrent_slots"] if st else 0
    assert held == 0, f"fan-in disagreement after completion opened a zombie slot: {st}"


# ---- C4: accumulator overflow --------------------------------------------

def _wrong_or_missing_overflow(text, job):
    wrong = [c for c in completes_for(text, job) if abs(float(c[4]) - 60000.0) > 1e-3]
    return wrong, f"[overflow] job={job}" in text


def test_c4_overflow_never_produces_wrong_sum_agg():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port)
    try:
        for w in range(3):
            contribute(port, 50, 0, w, 3, 20000.0)
        agg.drain_for(0.3)
        ps.drain_for(0.2)
    finally:
        agg.stop()
        ps.stop()
    text = agg.text() + ps.text()
    wrong, flagged = _wrong_or_missing_overflow(text, 50)
    assert not wrong, f"overflowed sum reported as a normal result: {wrong}"
    assert flagged, f"overflow was not reported:\n{text}"


def test_c4_overflow_never_produces_wrong_sum_paramserver():
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        for w in range(3):
            contribute(port, 51, 0, w, 3, 20000.0)
        ps.drain_for(0.3)
    finally:
        ps.stop()
    wrong, flagged = _wrong_or_missing_overflow(ps.text(), 51)
    assert not wrong, f"overflowed sum reported as a normal result: {wrong}"
    assert flagged, f"overflow was not reported:\n{ps.text()}"


# ---- C5: paramserver parity ----------------------------------------------

def test_c5_paramserver_truncated_packet_not_summed():
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        send(grad_packet(60, 0, 0, 0, 2, 4, [fx(1.0)] * 4), port)
        time.sleep(0.05)
        send(grad_packet(60, 0, 0, 1, 2, 4, []), port)  # header only, claims 4 values
        ps.drain_for(0.3)
    finally:
        ps.stop()
    assert completes_for(ps.text(), 60) == [], f"truncated packet was summed from stale bytes:\n{ps.text()}"


def test_c5_paramserver_num_workers_zero_rejected():
    port = free_port()
    ps = Server([PARAMSERVER, str(port), "noagg"])
    try:
        send(grad_packet(61, 0, 0, 0, 0, 1, [fx(99.0)]), port)  # num_workers = 0
        time.sleep(0.05)
        contribute(port, 61, 0, 0, 2, 1.0)
        contribute(port, 61, 0, 1, 2, 1.0)
        ps.drain_for(0.3)
    finally:
        ps.stop()
    done = completes_for(ps.text(), 61)
    assert len(done) == 1 and abs(float(done[0][4]) - 2.0) < 1e-3, (
        f"a num_workers=0 packet poisoned the round:\n{ps.text()}")


# ---- C6: probe chains survive deletion -----------------------------------

def _colliding_keys(capacity, job_base):
    seen = {}
    for job in range(job_base, job_base + 10000):
        idx = fnv1a_slot_index(job, 0, 0, capacity)
        if idx in seen:
            return seen[idx], job
        seen[idx] = job
    raise RuntimeError("no collision found")


def test_c6_probe_chain_survives_free():
    cap_log2 = 4
    k1, k2 = _colliding_keys(1 << cap_log2, 70000)
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port, capacity_log2=cap_log2)
    try:
        contribute(port, k1, 0, 0, 2, 1.0)  # K1 takes idx
        contribute(port, k2, 0, 0, 2, 1.0)  # K2 probes to idx+1
        contribute(port, k1, 0, 1, 2, 1.0)  # K1 completes and frees idx
        contribute(port, k2, 0, 1, 2, 1.0)  # K2 must find its own slot
        agg.drain_for(0.3)
    finally:
        agg.stop()
        ps.stop()
    assert len(completes_for(agg.text(), k1)) == 1, agg.text()
    assert len(completes_for(agg.text(), k2)) == 1, (
        f"K2={k2} split across two slots after K1={k1} was freed:\n{agg.text()}")


# ---- C7: quota must not fail open after job-table churn -------------------

def test_c7_quota_survives_job_table_churn():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, port = start_agg(ps_port, 0, 1)  # quota 1
    try:
        for job in range(80000, 80256):  # 256 distinct jobs, each completes
            contribute(port, job, 0, 0, 1, 1.0)
            if job % 32 == 0:
                agg.drain_for(0.02)
        agg.drain_for(0.3)
        greedy = 80300
        for rnd in range(3):  # three concurrent incomplete slots
            contribute(port, greedy, rnd, 0, 2, 1.0)
        agg.drain_for(0.3)
    finally:
        agg.stop()
        ps.stop()
    rejects = re.findall(rf"\[admission-reject\] job={greedy} ", agg.text())
    assert len(rejects) == 2, f"quota failed open after 256 jobs: {len(rejects)} rejects (want 2)"


# ---- runner ----------------------------------------------------------------

def main():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    bad = 0
    for t in tests:
        bug = EXPECTED_FAIL.get(t.__name__)
        try:
            t()
        except Exception as e:  # noqa: BLE001
            if bug:
                print(f"XFAIL({bug}): {t.__name__}: {str(e).splitlines()[0][:160]}")
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
