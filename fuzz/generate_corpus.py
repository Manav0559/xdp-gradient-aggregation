#!/usr/bin/env python3
"""Generates fuzz/corpus/ seed inputs for fuzz_grad_parse.cpp, byte-for-byte
in the same raw grad_hdr + payload layout as tests/test_correctness.py's
_raw_grad_packet() helper -- that file is the single source of truth for
this hand-crafted-packet wire layout in test code, and this script mirrors
it rather than redefining its own. Real, correctly-shaped (and
occasionally deliberately-broken) grad_hdr packets get the fuzzer past
both extracted admission checks immediately, instead of spending most of
its mutation budget on inputs that die before either function reads a
single header field.

Run: python3 fuzz/generate_corpus.py   (regenerates fuzz/corpus/*.bin)
"""
import os
import struct

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def raw_grad_packet(job_id, round_, chunk_id, worker_id, num_workers,
                     declared_chunk_len, values=None):
    """Byte-for-byte the same layout as tests/test_correctness.py's
    _raw_grad_packet(): a big-endian grad_hdr (job_id, round, chunk_id,
    worker_id, num_workers, chunk_len, flags=0) followed by `values`,
    which may deliberately disagree in count with declared_chunk_len --
    exactly the mismatch the truncated-packet and chunk_len checks exist
    to catch."""
    header = struct.pack(">IIIHHHH", job_id, round_, chunk_id, worker_id,
                          num_workers, declared_chunk_len, 0)
    payload = b"".join(struct.pack(">i", v) for v in (values or []))
    return header + payload


SEEDS = {
    # A well-formed packet -- both agg_parse_stateless() and
    # xdp_parse_stateless() must ACCEPT it.
    "valid.bin": raw_grad_packet(
        job_id=1, round_=0, chunk_id=0, worker_id=0, num_workers=2,
        declared_chunk_len=4, values=[65536, 131072, 196608, 262144]),

    # Boundary: chunk_len exactly at NETSUM_MAX_CHUNK_LEN (64) -- the
    # check is strictly "> MAX", so this must ACCEPT, not reject.
    "valid_max_chunk_len.bin": raw_grad_packet(
        job_id=2, round_=0, chunk_id=0, worker_id=0, num_workers=1,
        declared_chunk_len=64, values=[1] * 64),

    # Regression seed for the critical truncated-packet-stale-read bug
    # (tests/test_correctness.py's
    # test_truncated_packet_not_summed_as_stale_bytes): header claims
    # chunk_len=4 but zero payload bytes actually follow. Both functions
    # must REJECT.
    "truncated.bin": raw_grad_packet(
        job_id=7, round_=0, chunk_id=0, worker_id=1, num_workers=2,
        declared_chunk_len=4, values=[]),

    # Same shape, one value short rather than all of them missing --
    # a partial-payload truncation, not just a header-only one.
    "truncated_partial.bin": raw_grad_packet(
        job_id=7, round_=1, chunk_id=0, worker_id=1, num_workers=2,
        declared_chunk_len=4, values=[1, 2]),

    # chunk_len exceeds NETSUM_MAX_CHUNK_LEN (64). Both functions must
    # REJECT before ever reaching the length-vs-payload check.
    "chunk_len_exceeds_max.bin": raw_grad_packet(
        job_id=3, round_=0, chunk_id=0, worker_id=0, num_workers=1,
        declared_chunk_len=100, values=[1] * 100),

    # worker_id out of the 256-worker tracked range. Both functions must
    # REJECT.
    "worker_id_out_of_range.bin": raw_grad_packet(
        job_id=4, round_=0, chunk_id=0, worker_id=9999, num_workers=1,
        declared_chunk_len=1, values=[1]),

    # worker_id at the boundary (255 is the last valid id, 0-indexed
    # against 256 tracked workers) -- must ACCEPT.
    "worker_id_at_boundary.bin": raw_grad_packet(
        job_id=4, round_=1, chunk_id=0, worker_id=255, num_workers=1,
        declared_chunk_len=1, values=[1]),

    # num_workers == 0: degenerate, would make the real completion
    # equality (contributions_received == num_workers_expected)
    # permanently unreachable. Both functions must REJECT.
    "num_workers_zero.bin": raw_grad_packet(
        job_id=5, round_=0, chunk_id=0, worker_id=0, num_workers=0,
        declared_chunk_len=1, values=[1]),

    # num_workers exceeds the 256 tracked-worker range. Both functions
    # must REJECT.
    "num_workers_out_of_range.bin": raw_grad_packet(
        job_id=6, round_=0, chunk_id=0, worker_id=0, num_workers=9999,
        declared_chunk_len=1, values=[1]),

    # Empty input: zero bytes, not even a partial header. Both functions
    # must REJECT without reading anything.
    "empty.bin": b"",

    # Too-short input: fewer bytes than NETSUM_HDR_SIZE (20), a partial
    # header. Both functions must REJECT without reading past `size`.
    "too_short.bin": b"\x00" * 5,

    # One byte short of a full header -- the sharpest possible edge on
    # the header-fits-at-all check.
    "one_byte_short_of_header.bin": b"\x00" * 19,
}


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)
    for name, blob in SEEDS.items():
        path = os.path.join(CORPUS_DIR, name)
        with open(path, "wb") as f:
            f.write(blob)
        print(f"wrote {path} ({len(blob)} bytes)")


if __name__ == "__main__":
    main()
