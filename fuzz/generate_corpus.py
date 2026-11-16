#!/usr/bin/env python3
"""Writes fuzz/corpus/*.bin seed inputs: well-formed v1 and v2 packets of
every kind plus one seed per rejection rule, so the fuzzer starts past the
header checks. Run: python3 fuzz/generate_corpus.py"""
import os
import struct

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
V2 = 2 << 12
RESEND, ACK, OVERFLOW, FALLBACK, PARTIAL, REGISTER = 1, 2, 4, 8, 16, 32
AGG = 0xFFFF


def pkt(worker_id, num_workers, chunk_len, values=None, flags=0, trailer=None, job=1, rnd=0, chunk=0):
    hdr = struct.pack(">IIIHHHH", job, rnd, chunk, worker_id, num_workers, chunk_len, flags)
    body = b"".join(struct.pack(">i", v) for v in (values if values is not None else [1] * chunk_len))
    if trailer is None:
        trailer = bytes(32) if flags >> 12 == 2 else b""
    return hdr + body + trailer


def bitmap(*workers):
    b = bytearray(32)
    for w in workers:
        b[w // 8] |= 1 << (w % 8)
    return bytes(b)


SEEDS = {
    "valid.bin": pkt(0, 2, 4, [65536, 131072, 196608, 262144]),
    "valid_max_chunk_len.bin": pkt(0, 1, 64),
    "worker_id_at_boundary.bin": pkt(255, 256, 1),
    "v2_raw.bin": pkt(1, 3, 4, flags=V2, trailer=bitmap(1)),
    "v2_resend.bin": pkt(1, 3, 4, flags=V2 | RESEND, trailer=bitmap(1)),
    "v2_fallback.bin": pkt(2, 3, 4, flags=V2 | FALLBACK, trailer=bitmap(2)),
    "v2_aggregate.bin": pkt(AGG, 3, 4, flags=V2, trailer=bitmap(0, 1, 2)),
    "v2_aggregate_overflow.bin": pkt(AGG, 3, 4, flags=V2 | OVERFLOW, trailer=bitmap(0, 1, 2)),
    "v2_partial.bin": pkt(AGG, 3, 4, flags=V2 | PARTIAL, trailer=bitmap(0, 1)),
    "v2_ack.bin": pkt(AGG, 3, 4, flags=V2 | ACK),
    "v2_ack_overflow.bin": pkt(AGG, 3, 4, flags=V2 | ACK | OVERFLOW),
    "v2_register.bin": pkt(1, 3, 0, [], flags=V2 | REGISTER),
    "v3_raw_e40.bin": pkt(1, 3, 4, flags=(3 << 12) | (40 << 6), trailer=bitmap(1)),
    "v3_raw_saturated.bin": pkt(1, 3, 4, flags=(3 << 12) | (30 << 6) | OVERFLOW, trailer=bitmap(1)),
    "v3_aggregate_e63.bin": pkt(AGG, 3, 4, flags=(3 << 12) | (63 << 6), trailer=bitmap(0, 1, 2)),
    "v3_missing_trailer.bin": pkt(1, 2, 4, flags=(3 << 12) | (20 << 6), trailer=b""),
    "v2_raw_overflow.bin": pkt(1, 3, 4, flags=V2 | OVERFLOW, trailer=bitmap(1)),
    "empty.bin": b"",
    "too_short.bin": b"\x00" * 10,
    "one_byte_short_of_header.bin": pkt(0, 2, 4)[:19],
    "truncated.bin": pkt(1, 2, 4, []),
    "truncated_partial.bin": pkt(1, 2, 4, [1, 2]),
    "v2_missing_trailer.bin": pkt(1, 2, 4, flags=V2, trailer=b""),
    "chunk_len_exceeds_max.bin": pkt(0, 1, 100),
    "chunk_len_zero.bin": pkt(0, 1, 0, []),
    "worker_id_out_of_range.bin": pkt(9999, 1, 1),
    "worker_id_beyond_fanin.bin": pkt(10, 3, 1),
    "num_workers_zero.bin": pkt(0, 0, 1),
    "num_workers_out_of_range.bin": pkt(0, 9999, 1),
    "bad_version.bin": pkt(0, 1, 1, flags=4 << 12),
    "v1_with_flags.bin": pkt(0, 1, 1, flags=RESEND),
    "v2_reserved_bit.bin": pkt(0, 1, 1, flags=V2 | 0x0040),
    "v2_ack_from_worker.bin": pkt(0, 1, 1, flags=V2 | ACK),
    "v2_partial_from_worker.bin": pkt(0, 1, 1, flags=V2 | PARTIAL),
    "v2_fallback_partial.bin": pkt(AGG, 1, 1, flags=V2 | FALLBACK | PARTIAL),
    "v1_aggregate_id.bin": pkt(AGG, 1, 1),
}


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(CORPUS_DIR, name), "wb") as f:
            f.write(data)
    print(f"wrote {len(SEEDS)} seeds to {CORPUS_DIR}")


if __name__ == "__main__":
    main()
