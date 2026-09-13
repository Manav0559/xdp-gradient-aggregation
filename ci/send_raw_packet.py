#!/usr/bin/env python3
"""CI-only helper: sends one hand-crafted raw grad_hdr(+payload) UDP packet,
using the exact same struct.pack pattern as tests/test_correctness.py's
_raw_grad_packet() helper, so the xdp-loadtest CI workflow can replay the
same adversarial byte-level scenarios against the REAL kernel-loaded
xdp_agg.o that tests/test_correctness.py already replays against the
userspace agg.c binary.

This intentionally does not import tests/test_correctness.py (that module
launches subprocesses and isn't meant to run inside a network namespace as
a one-shot sender) -- it just re-implements the same small, well-understood
packing logic standalone.

Usage:
  send_raw_packet.py <dest_ip> <dest_port> <job_id> <round> <chunk_id> \
      <worker_id> <num_workers> <declared_chunk_len> [value ...]

Each trailing `value` is a real int32 fixed-point value to append to the
payload -- the count of values given is independent of
<declared_chunk_len>, which is exactly the mismatch adversarial tests need
(e.g. declare chunk_len=4 but supply zero values, to build a genuinely
truncated packet).
"""
import socket
import struct
import sys


def main():
    if len(sys.argv) < 9:
        print(__doc__, file=sys.stderr)
        return 1
    dest_ip = sys.argv[1]
    dest_port = int(sys.argv[2])
    job_id = int(sys.argv[3])
    round_ = int(sys.argv[4])
    chunk_id = int(sys.argv[5])
    worker_id = int(sys.argv[6])
    num_workers = int(sys.argv[7])
    declared_chunk_len = int(sys.argv[8])
    values = [int(v) for v in sys.argv[9:]]

    header = struct.pack(">IIIHHHH", job_id, round_, chunk_id, worker_id,
                          num_workers, declared_chunk_len, 0)
    payload = b"".join(struct.pack(">i", v) for v in values)
    packet = header + payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (dest_ip, dest_port))
    sock.close()
    print(f"sent {len(packet)} bytes to {dest_ip}:{dest_port} "
          f"(job={job_id} round={round_} chunk={chunk_id} worker={worker_id} "
          f"num_workers={num_workers} declared_chunk_len={declared_chunk_len} "
          f"actual_values={len(values)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
