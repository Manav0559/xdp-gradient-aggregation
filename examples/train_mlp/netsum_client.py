"""Minimal Python implementation of the NetSum v2/v3 worker protocol
(docs/DESIGN_NOTES.md §Wire format, §Reliability): REGISTER, chunked raw
contributions with a contributor-bitmap trailer, results (ACK) back from the
parameter server, retransmission with RESEND on timeout.

All logical workers of one process are driven together by allreduce(), so a
synchronous training step needs no threads. exchange() also speaks wire v3
(values are round(x * 2^e), e in flags bits 6-11; scale_rule.py chooses e)."""
import select
import socket
import struct
import time

HDR = struct.Struct(">IIIHHHH")
V2 = 2 << 12
V3 = 3 << 12
FRAC_SHIFT, FRAC_MASK = 6, 0x0FC0
RESEND, ACK, OVERFLOW, FALLBACK, PARTIAL, REGISTER = 1, 2, 4, 8, 16, 32
MAX_CHUNK = 64
AGGREGATE_ID = 0xFFFF
RETRY_SHIFT = 24


def retry_chunk_id(chunk, attempt):
    """Wire chunk id of a retry: a fresh key, so no slot, tombstone or stored
    result of an earlier attempt can match it."""
    return chunk | (attempt << RETRY_SHIFT)


def wire_flags(e, bits):
    """v2 (Q16.16) when e is None, else v3 at exponent e."""
    return V2 | bits if e is None else V3 | (e << FRAC_SHIFT) | bits


def pack(job, rnd, chunk, worker, workers, values, flags, e=None):
    """grad_hdr + big-endian int32 values + 32-byte bitmap with this worker's bit."""
    bm = bytearray(32)
    if worker < 256:
        bm[worker // 8] |= 1 << (worker % 8)
    return (HDR.pack(job, rnd, chunk, worker, workers, len(values), wire_flags(e, flags))
            + struct.pack(f">{len(values)}i", *values) + bytes(bm))


def unpack(data):
    job, rnd, chunk, worker, workers, n, flags = HDR.unpack_from(data)
    values = list(struct.unpack_from(f">{n}i", data, HDR.size)) if len(data) >= HDR.size + 4 * n else None
    return job, rnd, chunk, worker, workers, flags, values


class Worker:
    def __init__(self, worker_id, workers, job, to, ps, bind_ip="0.0.0.0"):
        self.id, self.n, self.job, self.to, self.ps = worker_id, workers, job, to, ps
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.sock.bind((bind_ip, 0))
        self.sock.setblocking(False)
        self.resent = 0
        self.register()

    def register(self):
        self.sock.sendto(HDR.pack(self.job, 0, 0, self.id, self.n, 0, V2 | REGISTER) + self._bitmap(), self.ps)

    def _bitmap(self):
        bm = bytearray(32)
        bm[self.id // 8] |= 1 << (self.id % 8)
        return bytes(bm)

    def send_chunk(self, rnd, chunk, values, resend=False, e=None, saturated=False):
        bits = (RESEND if resend else 0) | (OVERFLOW if saturated and e is not None else 0)
        self.sock.sendto(pack(self.job, rnd, chunk, self.id, self.n, values, bits, e), self.to)

    def close(self):
        self.sock.close()


def exchange(workers, rnd, items, rto=0.05, max_retries=30):
    """One all-reduce of round `rnd`. items: [(chunk_id, per-worker int32
    lists, e or None for v2, per-worker saturated flags or None)]. Returns
    {chunk_id: (summed values, OVERFLOW set)}; every worker must receive the
    same. Rejects a result at another version or exponent; raises
    TimeoutError if a chunk never completes."""
    spec = {cid: (vals, e, sat) for cid, vals, e, sat in items}
    results = [dict() for _ in workers]

    def send(i, w, cid, resend=False):
        vals, e, sat = spec[cid]
        w.send_chunk(rnd, cid, vals[i], resend, e, bool(sat and sat[i]))

    for i, w in enumerate(workers):
        for cid in spec:
            send(i, w, cid)
    deadline, retries = time.monotonic() + rto, 0
    while any(len(r) < len(spec) for r in results):
        timeout = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([w.sock for w in workers], [], [], timeout)
        for s in ready:
            i = next(k for k, w in enumerate(workers) if w.sock is s)
            while True:
                try:
                    data = s.recv(4096)
                except BlockingIOError:
                    break
                job, r, cid, _, _, flags, values = unpack(data)
                if not flags & ACK or job != workers[i].job or r != rnd or values is None or cid not in spec:
                    continue
                if flags & 0xFFC0 != wire_flags(spec[cid][1], 0):  # version and exponent
                    raise AssertionError(f"round {rnd} chunk {cid}: result flags {flags:#06x} at another scale")
                results[i][cid] = (values, bool(flags & OVERFLOW))
        if time.monotonic() >= deadline and any(len(r) < len(spec) for r in results):
            retries += 1
            if retries > max_retries:
                raise TimeoutError(f"round {rnd}: no result after {max_retries} retransmissions")
            for i, w in enumerate(workers):
                missing = [cid for cid in spec if cid not in results[i]]
                if missing:
                    w.register()
                for cid in missing:
                    send(i, w, cid, resend=True)
                    w.resent += 1
            deadline = time.monotonic() + min(rto * (2 ** retries), 1.0)
    if any(r != results[0] for r in results):
        raise AssertionError(f"round {rnd}: workers received different sums")
    return results[0]


def allreduce(workers, rnd, vectors, rto=0.05, max_retries=30):
    """v2 (Q16.16) all-reduce of one int32 vector per worker, in 64-value
    chunks; returns the summed vector. Raises OverflowError on OVERFLOW."""
    length = len(vectors[0])
    ids = list(range((length + MAX_CHUNK - 1) // MAX_CHUNK))
    items = [(c, [v[c * MAX_CHUNK:(c + 1) * MAX_CHUNK] for v in vectors], None, None) for c in ids]
    res = exchange(workers, rnd, items, rto, max_retries)
    over = [c for c in ids if res[c][1]]
    if over:
        raise OverflowError(f"round {rnd} chunks {over} overflowed Q16.16")
    return sum((res[c][0] for c in ids), [])
