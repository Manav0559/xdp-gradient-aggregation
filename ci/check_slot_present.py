#!/usr/bin/env python3
"""CI-only assertion helper for the xdp-loadtest workflow's netem sweep
scenario: checks a `bpftool -j map dump pinned <slot_map path>` JSON dump
for the presence (or absence) of ANY entry whose key's job_id matches, to
empirically confirm xdp_agg.c's documented lack of a TTL/reaper -- an
incomplete slot for a job whose last expected worker's packet was
permanently dropped (by netem, simulating real packet loss) must still be
sitting in slot_map, not silently reclaimed.

Tolerates the same two bpftool JSON renderings check_drop_stat.py and
check_job_quota.py already document: with BTF, `key` comes back as a
decoded {"job_id": N, "round": N, "chunk_id": N} object; without BTF, as
one flat array of "0x.." hex byte strings for the whole
struct grad_slot_key (job_id is bytes[0:4], map-native little-endian).

Usage: check_slot_present.py <bpftool -j map dump output as a file> <job_id> present|absent
"""
import json
import sys


def to_int(byte_list):
    n = 0
    for i, b in enumerate(byte_list):
        n |= int(b, 16) << (8 * i)
    return n


def job_id_of_key(key):
    if isinstance(key, dict):
        return int(key["job_id"])
    # Flat byte array for the whole {job_id, round, chunk_id} struct --
    # job_id is the first 4 bytes, map-native little-endian order.
    return to_int(key[0:4])


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    path, expect_job_id, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    if mode not in ("present", "absent"):
        print(f"unknown mode: {mode}", file=sys.stderr)
        return 2

    with open(path, "r") as f:
        data = json.load(f)

    matches = [e for e in data if job_id_of_key(e["key"]) == expect_job_id]

    if mode == "present":
        if matches:
            print(f"PASS: slot_map has {len(matches)} entr{'y' if len(matches)==1 else 'ies'} "
                  f"for job_id={expect_job_id} (confirmed: no TTL, the incomplete slot leaked as expected)")
            return 0
        print(f"FAIL: expected a stuck slot_map entry for job_id={expect_job_id}, found none; full dump: {data}",
              file=sys.stderr)
        return 1

    # mode == "absent"
    if not matches:
        print(f"PASS: slot_map has no entry for job_id={expect_job_id}, as expected")
        return 0
    print(f"FAIL: expected NO slot_map entry for job_id={expect_job_id}, found: {matches}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
