#!/usr/bin/env python3
"""CI-only assertion helper for the xdp-loadtest workflow's kernel-side
fairness-quota scenario: checks a `bpftool -j map dump pinned
<job_quota_map path>` JSON dump for a specific job_id key and asserts its
`concurrent_slots` field equals an expected value -- proof that the real,
kernel-verifier-approved xdp_agg.o is actually tracking per-job
concurrent-slot counts in job_quota_map, not just rejecting packets for
some other reason.

Tolerates the same two bpftool JSON renderings check_drop_stat.py already
documents: with BTF, key/value come back as decoded JSON
scalars/objects (key: int, value: {"concurrent_slots": N}); without BTF,
as arrays of "0x.." hex byte strings in map-native (little-endian) order
(key: 4-byte job_id; value: 4-byte concurrent_slots).

Usage: check_job_quota.py <bpftool -j map dump output as a file> <job_id> <expected_concurrent_slots>
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


def concurrent_slots_of(value):
    if isinstance(value, dict):
        return int(value["concurrent_slots"])
    return to_int(value)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    path, expect_job_id, expect_count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

    with open(path, "r") as f:
        data = json.load(f)

    for entry in data:
        key_job_id = to_int(entry["key"]) if not isinstance(entry["key"], dict) else int(entry["key"]["job_id"])
        if key_job_id == expect_job_id:
            got = concurrent_slots_of(entry["value"])
            if got == expect_count:
                print(f"PASS: job_quota_map[job_id={expect_job_id}].concurrent_slots = {got} (as expected)")
                return 0
            print(f"FAIL: job_quota_map[job_id={expect_job_id}].concurrent_slots = {got}, expected {expect_count}",
                  file=sys.stderr)
            return 1

    print(f"FAIL: no job_quota_map entry found for job_id={expect_job_id}; full dump: {data}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
