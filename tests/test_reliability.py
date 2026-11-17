#!/usr/bin/env python3
"""Result path, slot retirement and loss recovery (docs/DESIGN_NOTES.md
§Reliability, §Reclamation), driven against the real binaries.

Uses the @expect_fail mechanism of test_protocol_v2.py: a decorated test
documents behaviour that is not implemented yet (XFAIL), and an unexpected
pass fails the run. Run: python3 tests/test_reliability.py (after `make`)."""
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsum_packets import fx, grad_packet  # noqa: E402
from test_correctness import AGG, PARAMSERVER, WORKER, Server, extract_complete_lines, free_port  # noqa: E402
from test_protocol_v2 import EXPECTED_FAIL, expect_fail  # noqa: E402

V2 = 2 << 12
RESEND, ACK, OVERFLOW, FALLBACK, PARTIAL, REGISTER = 1, 2, 4, 8, 16, 32
AGG_ID = 0xFFFF


def bitmap(*workers):
    b = bytearray(32)
    for w in workers:
        b[w // 8] |= 1 << (w % 8)
    return bytes(b)


class Endpoint:
    """A worker-side UDP socket: sends v2 packets, collects ACKs."""

    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))

    def send(self, port, job, rnd, wid, nw, value, flags=0, chunk_len=1, chunk=0):
        pkt = grad_packet(job, rnd, chunk, wid, nw, chunk_len, [fx(value)] * chunk_len,
                          V2 | flags, bitmap(wid))
        self.s.sendto(pkt, ("127.0.0.1", port))

    def register(self, port, job, wid, nw):
        self.s.sendto(grad_packet(job, 0, 0, wid, nw, 0, [], V2 | REGISTER, bitmap(wid)), ("127.0.0.1", port))

    def results(self, wait=0.3):
        out, deadline = [], time.time() + wait
        while True:
            r, _, _ = select.select([self.s], [], [], max(0.0, deadline - time.time()))
            if not r:
                return out
            data = self.s.recv(2048)
            job, rnd, chunk, wid, nw, cl, flags = struct.unpack(">IIIHHHH", data[:20])
            vals = [struct.unpack(">i", data[20 + 4 * i:24 + 4 * i])[0] for i in range(cl)]
            out.append({"job": job, "round": rnd, "chunk": chunk, "wid": wid, "nw": nw,
                        "flags": flags, "vals": vals, "bitmap": data[20 + 4 * cl:52 + 4 * cl]})

    def close(self):
        self.s.close()


def stats_all(srv, wait=0.3):
    before = len(srv.lines)
    srv.proc.send_signal(signal.SIGUSR1)
    srv.drain_for(wait)
    for line in reversed(srv.lines[before:]):
        m = re.search(r"\[stats-all\] (\{.*\})", line)
        if m:
            return json.loads(m.group(1))
    return {}


def start_ps(*flags):
    port = free_port()
    return Server([PARAMSERVER, *flags, str(port), "noagg"]), port


def start_agg(ps_port, *flags):
    port = free_port()
    return Server([AGG, *flags, str(port), "127.0.0.1", str(ps_port)]), port


# ---- 4a: results and ACK retirement ----------------------------------------

def test_g1_ps_sends_result_to_registered_workers():
    ps, port = start_ps()
    w = [Endpoint(), Endpoint()]
    try:
        for i, e in enumerate(w):
            e.register(port, 500, i, 2)
        for i, e in enumerate(w):
            e.send(port, 500, 0, i, 2, 1.5)
        got = [e.results() for e in w]
    finally:
        ps.stop()
        for e in w:
            e.close()
    for i, res in enumerate(got):
        acks = [r for r in res if r["flags"] & ACK]
        assert len(acks) == 1, f"worker {i} got {len(acks)} results: {res}\n{ps.text()}"
        assert acks[0]["vals"] == [fx(1.5) * 2] and acks[0]["bitmap"] == bitmap(0, 1), acks[0]


def test_g1_ack_retires_aggregator_tombstone():
    ps_port = free_port()
    agg, agg_port = start_agg(ps_port)
    ps = Server([PARAMSERVER, "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    e = Endpoint()
    try:
        for i in range(3):
            e.send(agg_port, 501, 0, i, 3, 1.0)
        agg.drain_for(0.3)
        st = stats_all(agg)
    finally:
        agg.stop()
        ps.stop()
        e.close()
    assert st.get("slot_retired_ack") == 1, f"ACK did not retire the tombstone: {st}"
    assert st.get("slots_completed") == 0, st


# ---- C13: a lost result must be recoverable ---------------------------------

def test_c13_resend_after_completion_gets_the_result_again():
    ps, port = start_ps()
    w = [Endpoint(), Endpoint()]
    try:
        for i, e in enumerate(w):
            e.register(port, 502, i, 2)
            e.send(port, 502, 0, i, 2, 2.0)
        first = [e.results() for e in w]
        w[1].send(port, 502, 0, 1, 2, 2.0, flags=RESEND)  # worker 1 lost its result
        again = w[1].results()
        ps.drain_for(0.1)
    finally:
        ps.stop()
        for e in w:
            e.close()
    assert all(len([r for r in f if r["flags"] & ACK]) == 1 for f in first), first
    acks = [r for r in again if r["flags"] & ACK]
    assert len(acks) == 1 and acks[0]["vals"] == [fx(2.0) * 2], f"no result re-sent: {again}"
    assert len(extract_complete_lines(ps.text())) == 1, ps.text()


# ---- 4d aggregator RESEND table ----------------------------------------------

def test_g2_resend_on_completed_slot_resends_aggregate():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, agg_port = start_agg(ps_port)
    e = Endpoint()
    try:
        for i in range(2):
            e.send(agg_port, 503, 0, i, 2, 1.0)
        agg.drain_for(0.2)
        e.send(agg_port, 503, 0, 1, 2, 1.0, flags=RESEND)
        agg.drain_for(0.2)
        ps.drain_for(0.1)
        st, pst = stats_all(agg), stats_all(ps)
    finally:
        agg.stop()
        ps.stop()
        e.close()
    assert st.get("tx_result_resend") == 1 and st.get("tx_aggregate") == 2, st
    assert pst.get("aggregate_conflict") == 1, pst
    assert len(extract_complete_lines(ps.text())) == 1, ps.text()


def test_g2_resend_duplicate_flushes_partial_then_falls_back():
    ps_port = free_port()
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    agg, agg_port = start_agg(ps_port)
    e = Endpoint()
    try:
        e.send(agg_port, 504, 0, 0, 3, 1.0)
        e.send(agg_port, 504, 0, 1, 3, 2.0)
        agg.drain_for(0.1)
        e.send(agg_port, 504, 0, 1, 3, 2.0, flags=RESEND)  # stuck round: flush
        agg.drain_for(0.1)
        e.send(agg_port, 504, 0, 2, 3, 4.0)                 # after the flush: fallback
        agg.drain_for(0.2)
        ps.drain_for(0.2)
        st, pst = stats_all(agg), stats_all(ps)
    finally:
        agg.stop()
        ps.stop()
        e.close()
    assert st.get("slot_flushed_partial") == 1 and st.get("tx_partial") == 1, st
    assert st.get("tx_fallback") == 1, st
    assert pst.get("rx_partial") == 1 and pst.get("rx_fallback") == 1, pst
    done = extract_complete_lines(ps.text())
    assert len(done) == 1 and abs(float(done[0][4]) - 7.0) < 1e-3, ps.text()


# ---- 4d reliable worker -------------------------------------------------------

def run_reliable(target_port, ps_port, job, n, rounds, vector_len, extra=(), timeout=30):
    procs = []
    for wid in range(n):
        argv = [WORKER, "--mode", "reliable", "--to", f"127.0.0.1:{target_port}",
                "--ps", f"127.0.0.1:{ps_port}", "--job", str(job), "--worker", str(wid),
                "--workers", str(n), "--rounds", str(rounds), "--vector-len", str(vector_len),
                "--chunk-len", "64", "--window", "16", "--rto-ms", "40", "--fixed", "0.25", *extra]
        procs.append(subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    out = []
    for p in procs:
        o, err = p.communicate(timeout=timeout)
        assert p.returncode == 0, f"worker failed ({p.returncode}): {err}"
        out.append(json.loads(o.strip().splitlines()[-1]))
    return out


def test_g2_reliable_workers_noagg_with_drops():
    ps, port = start_ps("--quiet")
    try:
        res = run_reliable(port, port, 600, 3, 8, 1024, ("--drop-every", "3"))
    finally:
        ps.stop()
    for r in res:
        assert r["chunks"] == 8 * 16 and r["results"] == 8 * 16, r
        assert r["result_mismatches"] == 0 and r["resent"] > 0, r


def test_g2_reliable_workers_useragg_with_lost_contributions_and_results():
    ps_port = free_port()
    agg, agg_port = start_agg(ps_port, "--quiet")
    ps = Server([PARAMSERVER, "--quiet", "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    try:
        res = run_reliable(agg_port, ps_port, 601, 3, 8, 1024,
                           ("--drop-every", "5", "--drop-result-every", "7"))
        ast, pst = stats_all(agg), stats_all(ps)
    finally:
        agg.stop()
        ps.stop()
    for r in res:
        assert r["results"] == 8 * 16 and r["result_mismatches"] == 0, r
    assert sum(r["resent"] for r in res) > 0
    assert ast.get("slots_accumulating") == 0, f"stuck slots at the aggregator: {ast}"


# ---- array mode (ATP aggregator pool) in the userspace aggregator ------------

def test_array_mode_collision_falls_back_and_ack_frees_the_aggregator():
    # One aggregator: key A claims it, key B collides and lives at the PS for
    # all of its contributions (sticky), the ACK for A frees the aggregator,
    # and key C then aggregates in-network. Every sum is exact.
    ps_port = free_port()
    agg, agg_port = start_agg(ps_port, "--array-slots-log2", "0")
    ps = Server([PARAMSERVER, "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    e = Endpoint()
    try:
        e.send(agg_port, 710, 0, 0, 3, 1.0)        # A claims the only aggregator
        agg.drain_for(0.05)
        e.send(agg_port, 711, 0, 0, 3, 10.0)       # B collides: fallback
        agg.drain_for(0.05)
        for w in (1, 2):
            e.send(agg_port, 710, 0, w, 3, 1.0)    # A completes in-network
        agg.drain_for(0.1)
        for w in (1, 2):
            e.send(agg_port, 711, 0, w, 3, 10.0)   # B stays at the PS
        agg.drain_for(0.3)
        ps.drain_for(0.1)
        for w in range(3):
            e.send(agg_port, 712, 0, w, 3, 100.0)  # C: aggregator free again after A's ACK
        agg.drain_for(0.3)
        ps.drain_for(0.2)
        st, pst = stats_all(agg), stats_all(ps)
    finally:
        agg.stop()
        ps.stop()
        e.close()
    assert "array mode" in agg.text(), agg.text()
    assert st.get("fallback_collision") == 1 and st.get("tx_fallback") == 3, st
    assert st.get("tx_aggregate") == 2 and st.get("slot_completed") == 2, st
    assert st.get("slot_retired_ack") == 2 and st.get("slots_completed") == 0, st
    assert pst.get("rx_fallback") == 3, pst
    done = {(int(j), int(r)): float(v) for j, r, _c, _n, v, _l in extract_complete_lines(ps.text())}
    assert done == {(710, 0): 3.0, (711, 0): 30.0, (712, 0): 300.0}, ps.text()


def test_array_mode_late_contribution_for_a_fallen_back_key_never_steals_an_aggregator():
    # B falls back on a collision with A; once A's aggregator is freed, a
    # retransmission for B must still go to the PS (the key lives there), or
    # B would be split between the aggregator and the PS.
    ps_port = free_port()
    # No --ack-to: A's aggregator is freed by its 50 ms tombstone instead, so
    # it is EMPTY when B's second contribution arrives. Without the sticky
    # fallback set, B would claim it and never complete (1 of 2 workers).
    agg, agg_port = start_agg(ps_port, "--array-slots-log2", "0", "--tombstone-ttl-ms", "50")
    ps = Server([PARAMSERVER, str(ps_port), "agg"])
    e = Endpoint()
    try:
        e.send(agg_port, 720, 0, 0, 2, 1.0)
        e.send(agg_port, 721, 0, 0, 2, 5.0)        # collision: B -> PS
        e.send(agg_port, 720, 0, 1, 2, 1.0)        # A completes, aggregator COMPLETED
        agg.drain_for(0.4)                         # ... and its tombstone expires
        e.send(agg_port, 721, 0, 1, 2, 5.0)        # B's second worker: still the PS
        agg.drain_for(0.2)
        ps.drain_for(0.2)
        st = stats_all(agg)
    finally:
        agg.stop()
        ps.stop()
        e.close()
    assert st.get("fallback_collision") == 1 and st.get("tx_fallback") == 2, st
    assert st.get("slot_retired_ttl") == 1 and st.get("slots_accumulating") == 0, st
    done = {(int(j), int(r)): float(v) for j, r, _c, _n, v, _l in extract_complete_lines(ps.text())}
    assert done == {(720, 0): 2.0, (721, 0): 10.0}, ps.text()


def test_array_mode_reliable_workers_share_a_tiny_pool_under_loss():
    # Two jobs, 16 chunks per round, 4 aggregators: most keys collide. Lost
    # contributions and lost results on top. Every result must be exact and
    # no aggregator may stay ACCUMULATING.
    ps_port = free_port()
    agg, agg_port = start_agg(ps_port, "--quiet", "--array-slots-log2", "2")
    ps = Server([PARAMSERVER, "--quiet", "--ack-to", f"127.0.0.1:{agg_port}", str(ps_port), "agg"])
    procs, res = [], []
    try:
        for job in (730, 731):
            for wid in range(3):
                argv = [WORKER, "--mode", "reliable", "--to", f"127.0.0.1:{agg_port}",
                        "--ps", f"127.0.0.1:{ps_port}", "--job", str(job), "--worker", str(wid),
                        "--workers", "3", "--rounds", "6", "--vector-len", "1024", "--chunk-len", "64",
                        "--window", "16", "--rto-ms", "40", "--fixed", "0.25",
                        "--drop-every", "5", "--drop-result-every", "7"]
                procs.append(subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        for p in procs:
            o, err = p.communicate(timeout=60)
            assert p.returncode == 0, f"worker failed ({p.returncode}): {err}"
            res.append(json.loads(o.strip().splitlines()[-1]))
        agg.drain_for(0.3)
        ast = stats_all(agg)
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
        agg.stop()
        ps.stop()
    for r in res:
        assert r["results"] == 6 * 16 and r["result_mismatches"] == 0, r
    assert sum(r["dropped_rx"] for r in res) > 0, res
    assert ast.get("fallback_collision", 0) > 0 and ast.get("tx_aggregate", 0) > 0, ast
    assert ast.get("slots_accumulating") == 0, f"stuck aggregators: {ast}"


def main():
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    bad = 0
    for t in tests:
        bug = EXPECTED_FAIL.get(t.__name__)
        try:
            t()
        except Exception as e:  # noqa: BLE001
            if bug:
                print(f"XFAIL({bug}): {t.__name__}: {str(e).splitlines()[0][:150] if str(e) else type(e).__name__}")
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
