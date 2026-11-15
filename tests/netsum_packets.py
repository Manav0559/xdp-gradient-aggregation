"""Builds NetSum wire packets by hand, so tests can send what the worker
binary never would (lying chunk_len, bad fan-in, crafted flags).

Layout mirrors protocol/grad_proto.h: a 20-byte big-endian grad_hdr
followed by int32 big-endian Q16.16 values.
"""
import socket
import struct

HDR_FMT = ">IIIHHHH"
Q = 1 << 16


def fx(v):
    """Python float -> Q16.16 int (truncating, like netsum_to_fixed)."""
    return int(v * Q)


def grad_packet(job_id, round_, chunk_id, worker_id, num_workers, chunk_len,
                values=None, flags=0, trailer=b""):
    """values are already-fixed-point ints; chunk_len is what the header
    claims, independent of len(values)."""
    hdr = struct.pack(HDR_FMT, job_id, round_, chunk_id, worker_id,
                      num_workers, chunk_len, flags)
    payload = b"".join(struct.pack(">i", v) for v in (values or []))
    return hdr + payload + trailer


def send(packet, port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(packet, (host, port))
    finally:
        s.close()


def contribute(port, job_id, round_, worker_id, num_workers, value, chunk_len=1,
               chunk_id=0, flags=0, host="127.0.0.1"):
    """One well-formed raw contribution with every lane = fx(value)."""
    send(grad_packet(job_id, round_, chunk_id, worker_id, num_workers, chunk_len,
                     [fx(value)] * chunk_len, flags), port, host)
