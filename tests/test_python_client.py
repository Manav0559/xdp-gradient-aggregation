#!/usr/bin/env python3
"""The Python v2 client (examples/train_mlp/netsum_client.py) must produce
byte-for-byte the packets the C header defines (tests/unit/hdr_dump.c)."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "examples", "train_mlp"))
import netsum_client as nc  # noqa: E402

CASES = [
    (4242, 0, 0, 0, 4, [65536, -32768, 2147483647], 0),
    (7, 123456, 2, 3, 4, [-2147483648], nc.RESEND),
    (0xFFFFFFFF, 0xFFFFFFFF, 65, 255, 256, [65536, -32768], 0),
]


def main():
    c_lines = subprocess.run([os.path.join(ROOT, "bin", "hdr_dump")], capture_output=True, text=True,
                             check=True).stdout.split()
    bad = 0
    for (job, rnd, chunk, w, n, vals, flags), want in zip(CASES, c_lines):
        got = nc.pack(job, rnd, chunk, w, n, vals, flags).hex()
        if got != want:
            bad += 1
            print(f"FAIL: job {job}: python {got} != C {want}")
    print(f"python client packer vs C header: {len(CASES) - bad}/{len(CASES)} identical")
    sys.exit(1 if bad or len(c_lines) != len(CASES) else 0)


if __name__ == "__main__":
    main()
