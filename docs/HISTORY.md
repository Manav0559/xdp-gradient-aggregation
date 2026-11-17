# NetSum history

Git has the full record; this page keeps the few stories worth reading.

## v1 (to October 2026)

NetSum v1 had the wire format, worker, parameter server, a userspace
aggregator and an XDP program that passed the real kernel verifier in CI,
plus a correctness suite, a differential fuzzer, netem loss scenarios and a
fairness sweep. Its benchmark compared no aggregation with userspace
aggregation on macOS loopback; because workers were launched one after
another, its "latency" mostly measured process start-up, and it never
measured the XDP path (`scripts/legacy/benchmark_v1.py`,
`bench/v1-macos-loopback/`).

## v2 (November 2026)

An audit found confirmed correctness bugs (late duplicates re-creating slots
that never complete, unchecked worker ids and fan-in, silent int32 overflow,
a parameter server without the aggregator's checks, a slot-table delete that
broke probe chains, a quota that failed open, a racy kernel quota, a
forwarded aggregate keeping the worker's source address), a benchmark that
did not measure aggregation, and a fuzzer that tested copies of the checks.
v2 added red tests for every bug first, then: protocol v2 with a contributor
bitmap on every packet, one shared parser, a kernel state machine with
tombstones and per-CPU counters, a `BPF_PROG_TEST_RUN` unit harness, the
result/ACK path, resend semantics, best-effort fallback, array-mode
aggregators, a reliable worker, `netsum-ctl`, a closed-loop three-namespace
benchmark, a training demo and a quantization study.
`docs/WORKLOG.md` is the step-by-step record, including what went
wrong.

## Four engineering stories

**The verifier and the loop back-edge.** The first real-kernel run rejected
the accumulate loop with "invalid access to packet ... offset is outside of
the packet". The loop checked `values + chunk_len <= data_end` once before
starting, but the loop does not fully unroll, and the verifier does not carry
a bounds proof across a loop's back-edge. The fix is the standard idiom: re-check
`values + i + 1 <= data_end` on every iteration, directly before the access.
macOS could compile the program all along; only a real kernel can verify it,
which is why every kernel claim in this repo comes from CI.

**The 512-byte stack.** An early version staged the summed values in a
`final_sum[64]` array on the stack and blew BPF's hard 512-byte limit at
compile time; it was fixed by writing sums straight into the packet under
the slot lock. v1 still built new slots from a ~300-byte `struct grad_slot`
on the stack (352 of 512 bytes used). v2 initialises new slots from a zeroed
per-CPU template map instead, bringing the stack to 192-200 bytes.

**`_POSIX_C_SOURCE` and glibc.** `agg.c` used `sigaction` under
`-std=c11`. macOS's libc exposes POSIX regardless of the C standard; glibc
does not unless `_POSIX_C_SOURCE` is defined before the first include. Every
local build passed and the first Linux build in CI failed (commit `896e804`).
Every userspace file that uses POSIX now defines it first.

**Two buffering models on one pipe.** The test harness once read server
output with `select()` on the pipe plus `readline()` on Python's text
wrapper. One `readline()` can pull several lines into Python's buffer, after
which `select()` correctly reports the OS pipe empty and the remaining lines
sit unread until the test times out. The harness now reads raw bytes with
`os.read` and splits lines itself.
