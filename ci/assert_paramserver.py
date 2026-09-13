#!/usr/bin/env python3
"""CI-only assertion helper for the xdp-loadtest workflow: greps a captured
paramserver stderr log for a `[complete] job=... sum[0]=...` line (the same
regex tests/test_correctness.py uses) for one specific job_id, and either
requires it to be present with a sum within tolerance of an expected value,
or requires it to be absent entirely -- the latter is how every adversarial
case in this workflow proves the real, kernel-verifier-approved xdp_agg.o
actually dropped a malformed/adversarial contribution instead of silently
summing it, exactly mirroring the assertions tests/test_correctness.py
already makes against the userspace agg.c binary.

Usage:
  assert_paramserver.py <logfile> <job_id> require <num_workers> <expected_sum>
  assert_paramserver.py <logfile> <job_id> forbid

Tolerance matches tests/test_correctness.py's sum_tolerance(): num_workers
Q16.16 ULPs (1/65536 each) plus a tiny epsilon, since each contribution's
value was independently quantized before summing.
"""
import re
import sys

Q16_16_ULP = 1.0 / 65536.0

COMPLETE_RE = re.compile(
    r"\[complete\] job=(\d+) round=(\d+) chunk=(\d+) contributions=(\d+) "
    r"sum\[0\]=([\-0-9.]+) latency_us=(\d+)"
)


def sum_tolerance(num_workers):
    return num_workers * Q16_16_ULP + 1e-9


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    logfile = sys.argv[1]
    job_id = sys.argv[2]
    mode = sys.argv[3]

    with open(logfile, "r", errors="replace") as f:
        text = f.read()

    matches = [m for m in COMPLETE_RE.findall(text) if m[0] == job_id]

    if mode == "forbid":
        if matches:
            print(f"FAIL: expected NO [complete] line for job={job_id}, but found: {matches}",
                  file=sys.stderr)
            print("---- full log ----", file=sys.stderr)
            print(text, file=sys.stderr)
            return 1
        print(f"PASS: job={job_id} correctly never completed (adversarial input rejected)")
        return 0

    if mode == "require":
        if len(sys.argv) != 6:
            print("require mode needs <num_workers> <expected_sum>", file=sys.stderr)
            return 2
        num_workers = int(sys.argv[4])
        expected_sum = float(sys.argv[5])
        if len(matches) != 1:
            print(f"FAIL: expected exactly 1 [complete] line for job={job_id}, got {len(matches)}: {matches}",
                  file=sys.stderr)
            print("---- full log ----", file=sys.stderr)
            print(text, file=sys.stderr)
            return 1
        _, _, _, contributions, total, _ = matches[0]
        tol = sum_tolerance(num_workers)
        if abs(float(total) - expected_sum) >= tol:
            print(f"FAIL: job={job_id} sum={total} not within {tol} of expected {expected_sum}",
                  file=sys.stderr)
            return 1
        print(f"PASS: job={job_id} completed with contributions={contributions} "
              f"sum={total} (expected {expected_sum} +/- {tol})")
        return 0

    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
