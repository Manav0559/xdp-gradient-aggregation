#!/usr/bin/env python3
"""Prints a hexdump of one example of every NetSum v2 packet kind, for
docs/DESIGN_NOTES.md §Wire format. Run: python3 scripts/hexdump_examples.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
from netsum_packets import fx, grad_packet  # noqa: E402

V2 = 2 << 12
RESEND, ACK, OVERFLOW, FALLBACK, PARTIAL, REGISTER = 1, 2, 4, 8, 16, 32
AGG = 0xFFFF


def bitmap(*workers):
    b = bytearray(32)
    for w in workers:
        b[w // 8] |= 1 << (w % 8)
    return bytes(b)


EXAMPLES = [
    ("raw contribution, job 7 round 3 chunk 0, worker 1 of 3, two values 0.5 and -1.0",
     grad_packet(7, 3, 0, 1, 3, 2, [fx(0.5), fx(-1.0)], V2, bitmap(1))),
    ("resent raw contribution (RESEND)",
     grad_packet(7, 3, 0, 1, 3, 2, [fx(0.5), fx(-1.0)], V2 | RESEND, bitmap(1))),
    ("fallback: raw contribution forwarded un-aggregated by an aggregator (FALLBACK)",
     grad_packet(7, 3, 0, 2, 3, 2, [fx(0.25), fx(0.25)], V2 | FALLBACK, bitmap(2))),
    ("complete aggregate of workers 0-2 (worker_id 0xFFFF, num_workers = fan-in)",
     grad_packet(7, 3, 0, AGG, 3, 2, [fx(1.25), fx(-1.5)], V2, bitmap(0, 1, 2))),
    ("partial aggregate of workers 0-1 flushed on resend or TTL (PARTIAL)",
     grad_packet(7, 3, 0, AGG, 3, 2, [fx(1.0), fx(-1.75)], V2 | PARTIAL, bitmap(0, 1))),
    ("result / ACK from the parameter server (ACK)",
     grad_packet(7, 3, 0, AGG, 3, 2, [fx(1.25), fx(-1.5)], V2 | ACK, bytes(32))),
    ("worker registration, no values (REGISTER)",
     grad_packet(7, 0, 0, 1, 3, 0, [], V2 | REGISTER, bitmap(1))),
]


def hexdump(data):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        lines.append(f"{off:04x}  " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(lines)


def main():
    for title, data in EXAMPLES:
        print(f"{title} ({len(data)} bytes):\n")
        print("```")
        print(hexdump(data))
        print("```\n")


if __name__ == "__main__":
    main()
