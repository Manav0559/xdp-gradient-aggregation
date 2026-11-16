"""Minimal Python implementation of the NetSum v2/v3 worker protocol
(docs/DESIGN_NOTES.md §Wire format, §Reliability): REGISTER, chunked raw
contributions with a contributor-bitmap trailer, results (ACK) back from the
parameter server, retransmission with RESEND on timeout.

All logical workers of one process are driven together by allreduce(), so a
synchronous training step needs no threads. With per-chunk exponents
allreduce() speaks wire v3 (values are round(x * 2^e), e in flags bits 6-11;
scale_rule.py chooses e)."""
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


def allreduce(workers, rnd, vectors, exps=None, saturated=None, rto=0.05, max_retries=30):
    """Sends every worker's int32 vector for round `rnd` and returns the summed
    vector each worker received (they must all be identical).

    v2 (Q16.16) when `exps` is None: raises OverflowError on an OVERFLOW
    result. v3 when `exps` gives each chunk's exponent: saturated[w][c] marks
    worker w's chunk c OVERFLOW; returns (sum, overflowed chunk ids) and
    rejects a result at any other version or exponent. Raises TimeoutError
    if a chunk never completes."""
    length = len(vectors[0])
    chunks = [(c, min(MAX_CHUNK, length - c * MAX_CHUNK)) for c in range((length + MAX_CHUNK - 1) // MAX_CHUNK)]
    e_of = (lambda c: None) if exps is None else (lambda c: exps[c])
    sat_of = (lambda w, c: False) if saturated is None else (lambda w, c: saturated[w][c])
    results = [dict() for _ in workers]
    overflowed = set()

    def send(i, w, c, n, resend=False):
        w.send_chunk(rnd, c, vectors[i][c * MAX_CHUNK:c * MAX_CHUNK + n], resend, e_of(c), sat_of(i, c))

    for i, w in enumerate(workers):
        for c, n in chunks:
            send(i, w, c, n)
    deadline, retries = time.monotonic() + rto, 0
    while any(len(r) < len(chunks) for r in results):
        timeout = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([w.sock for w in workers], [], [], timeout)
        for s in ready:
            i = next(k for k, w in enumerate(workers) if w.sock is s)
            while True:
                try:
                    data = s.recv(4096)
                except BlockingIOError:
                    break
                job, r, chunk, _, _, flags, values = unpack(data)
                if not flags & ACK or job != workers[i].job or r != rnd or values is None or chunk >= len(chunks):
                    continue
                if flags & 0xFFC0 != wire_flags(e_of(chunk), 0):  # version and exponent
                    raise AssertionError(f"round {rnd} chunk {chunk}: result flags {flags:#06x} at another scale")
                if flags & OVERFLOW:
                    if exps is None:
                        raise OverflowError(f"round {rnd} chunk {chunk} overflowed Q16.16")
                    overflowed.add(chunk)
                results[i][chunk] = values
        if time.monotonic() >= deadline and any(len(r) < len(chunks) for r in results):
            retries += 1
            if retries > max_retries:
                raise TimeoutError(f"round {rnd}: no result after {max_retries} retransmissions")
            for i, w in enumerate(workers):
                missing = [(c, n) for c, n in chunks if c not in results[i]]
                if missing:
                    w.register()
                for c, n in missing:
                    send(i, w, c, n, resend=True)
                    w.resent += 1
            deadline = time.monotonic() + min(rto * (2 ** retries), 1.0)
    out = [sum((r[c] for c, _ in chunks), []) for r in results]
    if any(o != out[0] for o in out):
        raise AssertionError(f"round {rnd}: workers received different sums")
    return out[0] if exps is None else (out[0], sorted(overflowed))
