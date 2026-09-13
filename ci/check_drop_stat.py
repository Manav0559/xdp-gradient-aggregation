#!/usr/bin/env python3
"""CI-only helper: checks a `bpftool -j map dump pinned <drop_stats path>`
JSON dump for a specific integer key (e.g. STAT_DROPPED_NO_CONFIG=0 from
xdp_agg.c) and asserts its uint64 counter value is > 0 -- proof that the
real, kernel-verifier-approved program actually took that drop path and
counted it, not just that some packet silently vanished.

bpftool renders map dumps two different ways depending on whether the
object carries BTF for the map's key/value types (this repo's clang -g
-target bpf build should emit it, but this script tolerates either form
so it isn't coupled to that): with BTF, keys/values come back as decoded
JSON scalars/objects; without it, as arrays of "0x.." hex byte strings in
map-native (little-endian) order. Both are handled by to_int() below.

Usage: check_drop_stat.py <bpftool -j map dump output as a file> <expected_key_int>
"""
import json
import sys


def to_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, list):
        n = 0
        for i, b in enumerate(v):
            n |= int(b, 16) << (8 * i)
        return n
    raise ValueError(f"unexpected key/value representation: {v!r}")


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, expect_key = sys.argv[1], int(sys.argv[2])

    with open(path, "r") as f:
        data = json.load(f)

    for entry in data:
        key = to_int(entry["key"])
        if key == expect_key:
            val = to_int(entry["value"])
            if val > 0:
                print(f"PASS: drop_stats[{expect_key}] = {val} (> 0, as expected)")
                return 0
            print(f"FAIL: drop_stats[{expect_key}] = {val}, expected > 0", file=sys.stderr)
            return 1

    print(f"FAIL: no drop_stats entry found for key {expect_key}; full dump: {data}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
