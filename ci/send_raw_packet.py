#!/usr/bin/env python3
"""Sends one hand-built grad_hdr packet (v1, flags 0) whose declared chunk_len
may disagree with the values supplied, for adversarial kernel scenarios.

Usage:
  send_raw_packet.py <dest_ip> <dest_port> <job_id> <round> <chunk_id> \
      <worker_id> <num_workers> <declared_chunk_len> [value ...]
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
