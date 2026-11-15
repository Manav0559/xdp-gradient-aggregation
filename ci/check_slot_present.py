"""Asserts on the slot_map entries of one job in a `bpftool -j map dump`.

Usage: check_slot_present.py <dump.json> <job_id> <mode>
  present              at least one entry, any state
  absent               no entry at all
  completed            at least one entry, and every entry is a COMPLETED tombstone
  accumulating         at least one ACCUMULATING entry
  no-accumulating      no ACCUMULATING entry (absent, or only tombstones)
"""
import sys

from netsum_bpf_json import slots

MODES = ("present", "absent", "completed", "accumulating", "no-accumulating")


def main():
    if len(sys.argv) != 4 or sys.argv[3] not in MODES:
        print(__doc__, file=sys.stderr)
        return 2
    path, job, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    entries = [e for e in slots(path) if e[0] == job]
    states = [e[3] for e in entries]
    ok = {
        "present": bool(entries),
        "absent": not entries,
        "completed": bool(entries) and all(s == "completed" for s in states),
        "accumulating": "accumulating" in states,
        "no-accumulating": "accumulating" not in states,
    }[mode]
    desc = ", ".join(f"({e[0]},{e[1]},{e[2]}) {e[3]} {e[4]} contributors" for e in entries) or "none"
    if ok:
        print(f"PASS: job {job} slot_map entries [{desc}] satisfy '{mode}'")
        return 0
    print(f"FAIL: job {job} slot_map entries [{desc}] do not satisfy '{mode}'", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
