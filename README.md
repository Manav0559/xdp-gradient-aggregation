# NetSum — In-Network Gradient Aggregation on Commodity Linux via XDP/eBPF

A CN + OS + distributed-systems research project: reproducing **ATP**'s
(*"In-network Aggregation for Multi-tenant Learning,"* NSDI 2021 Best Paper)
streaming, multi-tenant, fairness-aware gradient-aggregation mechanism — normally
built on a Barefoot/Intel Tofino programmable switch — on an ordinary Linux box
using XDP/eBPF instead. No specialized hardware.

**Full project specification:** [`docs/PROJECT_SPEC.md`](docs/PROJECT_SPEC.md)
(also available as a formatted PDF: [`docs/NetSum_Project_Spec.pdf`](docs/NetSum_Project_Spec.pdf))
**Live results dashboard:** see the `dashboard/` section below.

## What's built and tested right now

The wire protocol, both non-kernel benchmark baselines, and the XDP/eBPF kernel
program (compiled, not yet load-tested) are all implemented and passing a real
correctness test suite:

```sh
make                              # builds bin/worker, bin/paramserver, bin/agg
make bpf                          # compiles xdp_agg/xdp_agg.c to real eBPF bytecode
python3 tests/test_correctness.py # 8/8 passing
python3 scripts/benchmark.py      # runs the real noagg-vs-useragg benchmark sweep
```

| Component | What it is | Status |
|---|---|---|
| `protocol/grad_proto.h` | The wire format every other piece includes verbatim — Q16.16 fixed-point (no floats, since the BPF verifier forbids them), network byte order | Done, tested |
| `worker/worker.c` | Synthetic gradient-chunk sender | Done, tested |
| `paramserver/paramserver.c` | Baseline #1 (no aggregation) — sums raw contributions itself | Done, tested |
| `userspace_agg/agg.c` | Baseline #2 — the *same* slot/accumulate/emit algorithm the XDP program runs, as an ordinary socket program | Done, tested |
| `xdp_agg/xdp_agg.c` | The actual kernel-space aggregator | Compiles to valid eBPF bytecode (`make bpf`); reviewed and patched against an adversarial pass (see below); not yet load-tested against a real in-kernel verifier — needs a real Linux kernel, see [`docs/DEV_ENVIRONMENT.md`](docs/DEV_ENVIRONMENT.md) |
| `scripts/benchmark.py` | Real measurement harness across a worker-count sweep | Done, real data in `bench/results.csv` |
| `dashboard/index.html` | Live results dashboard charting `bench/results.csv` | Done |

Real bugs were found and fixed during this build (not just written and assumed
correct) — this is the honest, complete list, not a curated subset:
- Neither server originally deduplicated by `worker_id` — a duplicate/retried
  packet from the same worker would have been double-counted, silently corrupting
  the sum. Fixed with a per-slot `seen_worker[]` table.
- The test harness itself had a real bug: mixing `selectors.select()` (which
  watches the raw OS pipe) with a buffered `TextIOWrapper.readline()` silently lost
  lines. See the `Server` class docstring in `tests/test_correctness.py`.
- An early `xdp_agg.c` blew BPF's hard 512-byte kernel stack limit via a staging
  array that's invisible-sized in ordinary userspace C — caught by a real
  `clang -target bpf` compile, fixed by writing summed values directly into the
  packet under the lock instead.
- `scripts/benchmark.py` first measured `useragg`'s latency at the parameter
  server, which in "agg" mode only ever sees one already-summed packet per slot —
  every reading came back ~0us regardless of worker count, the tell that the
  measurement was happening in the wrong place. Fixed by instrumenting the real
  accumulation point (the aggregator itself).
- **An independent adversarial code review of `xdp_agg.c` found 10 confirmed
  issues, 2 critical**, all since fixed and regression-tested: (1) the packet
  write-back loop trusted a length value with no proven relationship to the
  current packet's own verified-safe buffer extent — a real out-of-bounds-write
  risk the in-kernel verifier should reject at load time, now closed by requiring
  every contribution's chunk_len to match the slot's before it's ever accumulated;
  (2) the userspace baseline was missing a length check XDP already had, so a
  truncated packet could silently sum stale bytes left over in a reused buffer
  from a prior, larger packet. See `xdp_agg.c`'s header comment for the complete
  list (including the moderate/minor findings: an unvalidated `num_workers` field
  that could leak map entries permanently, a forwarded packet that never updated
  its own `chunk_len` field, and a silent, now-counted packet-loss window at
  startup) and `tests/test_correctness.py`'s two newest tests for the regression
  coverage.

## Repository layout

```
protocol/       shared wire-format header (single source of truth)
worker/         synthetic gradient-chunk sender
paramserver/    baseline #1 (no aggregation) + the final receiver for #2/#3
userspace_agg/  baseline #2 (userspace aggregation, same algorithm as XDP)
xdp_agg/        the kernel-space XDP/eBPF aggregator -- compiles, not yet load-tested
tests/          correctness test suite (8/8 passing, driving the real binaries)
scripts/        benchmark harness -- real measured data in bench/results.csv
dashboard/      live results dashboard (dark/light, charts bench/results.csv)
docs/           full project spec (.md + .pdf) and the Linux/XDP dev-environment guide
```

## Research grounding

- **ATP: In-network Aggregation for Multi-tenant Learning** — Lao, Le, Mahajan,
  Chen, Wu, Akella, Swift. NSDI 2021, Best Paper Award.
- **Accelerating Distributed Training With Collaborative In-Network Aggregation**
  — IEEE/ACM Transactions on Networking, 2024 (DOI 10.1109/TNET.2024.3387948),
  cited as a related extension (multi-switch, asynchronous arrival), not the
  source of the fairness mechanism itself — see `docs/PROJECT_SPEC.md` §2.2 for
  why that distinction matters.

See the full spec for the corrected architecture (why `BPF_MAP_TYPE_HASH` +
`bpf_spin_lock`, not `BPF_MAP_TYPE_PERCPU_ARRAY`; why `XDP_TX` alone, not a
conflated `XDP_TX`/AF_XDP-zero-copy claim), the evaluation plan, the semester build
timeline, and the honest scope boundaries.

## License

MIT — see [`LICENSE`](LICENSE).
