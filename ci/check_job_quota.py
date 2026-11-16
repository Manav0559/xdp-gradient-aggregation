#!/usr/bin/env python3
"""Asserts a job's charged-slot count in netsum-ctl --json jobs output (or a
bpftool dump of job_quota_map).

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
        if "concurrent_slots" in entry:  # netsum-ctl --json jobs
            entry = {"key": entry["job_id"], "value": entry["concurrent_slots"]}
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
