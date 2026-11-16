"""Asserts exact values of named counters in a `bpftool -j map dump` of the
XDP program's per-CPU `stats` map (names as in protocol/netsum_stats.h,
lower case without the NS_ prefix).

Usage: check_stat.py <dump.json> <name>=<value> [<name>=<value> ...]
       check_stat.py <before.json> <after.json> --delta <name>=<value> ...
"""
import sys

from netsum_bpf_json import stats


def main():
    args = sys.argv[1:]
    if "--delta" in args:
        i = args.index("--delta")
        before, after, wants = stats(args[0]), stats(args[1]), args[i + 1:]
        got = {k: after.get(k, 0) - before.get(k, 0) for k in after}
    elif len(args) >= 2:
        got, wants = stats(args[0]), args[1:]
    else:
        print(__doc__, file=sys.stderr)
        return 2
    bad = 0
    for w in wants:
        name, val = w.split("=")
        if name not in got:
            print(f"FAIL: unknown counter {name}", file=sys.stderr)
            bad += 1
        elif got[name] != int(val):
            print(f"FAIL: {name} = {got[name]}, expected {val}", file=sys.stderr)
            bad += 1
        else:
            print(f"PASS: {name} = {val}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
