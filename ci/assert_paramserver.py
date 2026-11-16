#!/usr/bin/env python3
"""Asserts that a captured paramserver log has (require) or lacks (forbid) a
[complete] line for a job, with the sum within the Q16.16 tolerance.

Usage:
  assert_paramserver.py <logfile> <job_id> require <num_workers> <expected_sum>
  assert_paramserver.py <logfile> <job_id> forbid
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
