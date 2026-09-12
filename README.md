# NetSum — In-Network Gradient Aggregation on Commodity Linux via XDP/eBPF

A CN + OS + distributed-systems research project: reproducing **ATP**'s
(*"In-network Aggregation for Multi-tenant Learning,"* NSDI 2021 Best Paper)
streaming, multi-tenant, fairness-aware gradient-aggregation mechanism — normally
built on a Barefoot/Intel Tofino programmable switch — on an ordinary Linux box
using XDP/eBPF instead. No specialized hardware.

**Full project specification:** [`docs/PROJECT_SPEC.md`](docs/PROJECT_SPEC.md)
(also available as a formatted PDF: [`docs/NetSum_Project_Spec.pdf`](docs/NetSum_Project_Spec.pdf))

## What's built and tested right now

The wire protocol and both non-kernel benchmark baselines are implemented, built,
and passing a real correctness test suite — no Linux/XDP environment required for
any of this:

```sh
make                              # builds bin/worker, bin/paramserver, bin/agg
python3 tests/test_correctness.py # 6/6 passing
```

| Component | What it is | Status |
|---|---|---|
| `protocol/grad_proto.h` | The wire format every other piece includes verbatim — Q16.16 fixed-point (no floats, since the BPF verifier forbids them), network byte order | Done, tested |
| `worker/worker.c` | Synthetic gradient-chunk sender | Done, tested |
| `paramserver/paramserver.c` | Baseline #1 (no aggregation) — sums raw contributions itself | Done, tested |
| `userspace_agg/agg.c` | Baseline #2 — the *same* slot/accumulate/emit algorithm the eventual XDP program runs, as an ordinary socket program | Done, tested |
| `xdp_agg/` | The actual kernel-space aggregator | Not started — needs a real Linux kernel; see [`docs/DEV_ENVIRONMENT.md`](docs/DEV_ENVIRONMENT.md) |

Two real bugs were found and fixed during this initial build (not just written and
assumed correct):
- Neither server originally deduplicated by `worker_id` — a duplicate/retried
  packet from the same worker would have been double-counted, silently corrupting
  the sum. Fixed with a per-slot `seen_worker[]` table; `tests/test_correctness.py`
  asserts on this directly.
- The test harness itself had a real bug: mixing `selectors.select()` (which
  watches the raw OS pipe) with a buffered `TextIOWrapper.readline()` silently lost
  lines. See the `Server` class docstring in `tests/test_correctness.py` for the
  full explanation — a genuine "don't layer two buffering models on one fd" lesson.

## Repository layout

```
protocol/       shared wire-format header (single source of truth)
worker/         synthetic gradient-chunk sender
paramserver/    baseline #1 (no aggregation) + the final receiver for #2/#3
userspace_agg/  baseline #2 (userspace aggregation, same algorithm as XDP)
xdp_agg/        the kernel-space XDP/eBPF aggregator (not yet started)
tests/          correctness test suite (6/6 passing, driving the real binaries)
scripts/        benchmark harness (planned, see build plan §6 of the spec)
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
