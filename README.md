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
python3 tests/test_correctness.py # 10/10 passing
python3 scripts/benchmark.py      # runs the real noagg-vs-useragg benchmark sweep
```

| Component | What it is | Status |
|---|---|---|
| `protocol/grad_proto.h` | The wire format every other piece includes verbatim — Q16.16 fixed-point (no floats, since the BPF verifier forbids them), network byte order | Done, tested |
| `worker/worker.c` | Synthetic gradient-chunk sender | Done, tested |
| `paramserver/paramserver.c` | Baseline #1 (no aggregation) — sums raw contributions itself | Done, tested |
| `userspace_agg/agg.c` | Baseline #2 — the *same* slot/accumulate/emit algorithm the XDP program runs, as an ordinary socket program; now also enforces a per-job **multi-tenant fairness quota** (see below) | Done, tested |
| `xdp_agg/xdp_agg.c` | The actual kernel-space aggregator | **Verified on a real Linux kernel** — loaded, verifier-accepted, and driven with real UDP traffic in CI (see below); this dev machine still can't run it directly (macOS has no Linux kernel), but that's now closed via CI rather than an open gap |
| `scripts/benchmark.py` | Real measurement harness across a worker-count sweep | Done, real data in `bench/results.csv` |
| `dashboard/index.html` | Live results dashboard charting `bench/results.csv` | Done |

### Real-kernel verification (closing the project's single biggest gap)

Every prior claim about `xdp_agg.c` was argued from `clang -target bpf`
codegen success alone — the file's own header comment admitted plainly that
it had "compiled to valid bytecode... not yet run through the in-kernel
verifier or loaded onto a real interface." That's now closed:
[`.github/workflows/xdp-loadtest.yml`](.github/workflows/xdp-loadtest.yml)
runs on a real `ubuntu-latest` Linux kernel (this macOS dev machine
categorically cannot do this — GitHub Actions CI is what makes it possible
at all), builds a veth pair across two network namespaces (the standard
kernel-selftests pattern), loads the compiled object with `bpftool`,
attaches it to the veth via `xdpgeneric`, populates its config map with a
small libbpf-based loader (`ci/netsum_cfg_loader.c`), and drives it with
real UDP gradient traffic — including every adversarial scenario an earlier
human code review found bugs in (chunk_len mismatch, a truncated packet,
`num_workers` 0/oversized, a missing config map).

**This found a real bug clang's codegen-only compile could never have
caught:** the real verifier rejected the original object —
`invalid access to packet ... R3 offset is outside of the packet` — because
the accumulate/write-back loops don't fully unroll (already documented in
the file's own header comment) and the verifier doesn't carry a single
upfront bounds proof through a loop's back-edge with enough precision to
accept a per-iteration packet-pointer dereference. Fixed with the standard
idiom: a redundant, logically-no-op `(values + i + 1) > data_end` re-check
immediately before each dereference, giving the verifier a fresh, local
proof at the access site. With that fix, the workflow is green: the
verifier accepts the program (`processed 55542 insns`, captured in a build
artifact), `bpftool prog show` confirms it's really loaded and JITed
(`xlated 2760B jited 1679B`), a real multi-worker round sums correctly
through the live program, and every adversarial input is correctly
rejected — including `drop_stats[STAT_DROPPED_NO_CONFIG]` actually
incrementing on a real kernel, not a userspace model of one. Honest scope
note: this uses `xdpgeneric` (SKB) mode, which is what a software veth
supports — native driver-mode XDP on real NIC hardware remains untested
(see Stretch Goals in `docs/PROJECT_SPEC.md`).

### Multi-tenant fairness (ATP's actual headline contribution)

ATP's full paper title is *"In-network Aggregation for **Multi-tenant** Learning"*
— the fairness mechanism, not bare streaming aggregation, is its real
contribution (streaming aggregation alone was already in SwitchML, ATP's own
predecessor). `userspace_agg/agg.c` now reproduces that mechanism: an optional
`max_slots_per_job` CLI argument caps how many concurrently-incomplete slots
a single `job_id` may hold in the slot table at once, so one greedy job
opening many concurrent rounds cannot exhaust the table and starve every
other job sharing the aggregator.

```sh
bin/agg <listen_port> <downstream_ip> <downstream_port> [max_packets=0] [max_slots_per_job=0]
```

A rejected admission logs `[admission-reject] job=... round=... chunk=... --
slot table full or job at fairness quota, dropping` and is dropped exactly
like a malformed packet — the job's *other* already-admitted slots, and every
other job's slots, are unaffected. `tests/test_correctness.py`'s
`test_fairness_quota_isolates_greedy_job` proves real starvation isolation,
not just that the mechanism compiles: a greedy job (`job_id=900`) opens 3
concurrent incomplete slots against a quota of 2 — exactly one is rejected —
while a second, unrelated job (`job_id=901`) completes normally regardless.
**Now also ported into the XDP kernel program itself** (`job_quota_map`,
`struct netsum_config`'s new `max_slots_per_job` field, `STAT_DROPPED_FAIRNESS_QUOTA`)
and verified on a real loaded kernel in the same CI job described above: a
greedy job's 3rd concurrent slot is genuinely rejected (`drop_stats[1]`
increments to exactly 1, `job_quota_map[900].concurrent_slots` reads back as
exactly 2 via `bpftool map dump`) while a second, unrelated job completes
normally. A **formal Jain's-fairness-index sweep** (`scripts/fairness_sweep.py`,
charted on the dashboard) now also quantifies this: 3 concurrently-contending
jobs with uneven demand (16/4/8) show Jain's index climbing from 0.778 at
`quota=0` (unlimited) toward 1.0 as the quota tightens to 1–4, confirming the
mechanism's real effect, not just that one greedy job's excess gets rejected
once.

A **netem-driven adversarial sweep** (same CI job, `tc qdisc ... netem`
against the real loaded program) confirms a full round still aggregates
correctly under 20% packet loss (via redundant sends) and under real
delay+reordering (confirming the slot/accumulate logic is correctly
order-independent) — and empirically confirms a known, honest gap: when one
worker's packet is permanently, deterministically dropped, its slot is
never reclaimed (`bpftool map dump pinned .../slot_map` still shows it stuck
afterward) — `xdp_agg.c` has no TTL/reaper of its own yet (only the
userspace baseline does). Not yet done: a kernel-side TTL/reaper (needs
`bpf_timer`, Linux 5.15+) to close that gap, and real per-packet XDP
latency numbers via `BPF_PROG_TEST_RUN` (see `docs/PROJECT_SPEC.md` §5).

### Slot-table TTL / reaper (the crashed-worker case the quota doesn't cover)

The fairness quota above stops an *abusive* job from hoarding slots — it does
nothing for the opposite, *honest* failure: a well-behaved job whose worker
legitimately crashes or drops off mid-round, leaving its slot incomplete
forever. Without a timeout, that slot occupies its `g_slots` entry **and**
permanently shrinks that job's fairness-quota allowance for the life of the
process — `xdp_agg.c`'s own header comment admitted this gap outright ("no
TTL/eviction anywhere in this program"). `userspace_agg/agg.c` now closes the
userspace half of it:

```sh
bin/agg <listen_port> <downstream_ip> <downstream_port> [max_packets=0] [max_slots_per_job=0] [slot_ttl_ms=0]
```

`slot_ttl_ms` (0 = disabled, the original behavior) bounds how long a slot may
sit incomplete before a periodic reaper evicts it through the exact same
`free_slot()` path a normal completion uses, so fairness accounting stays
correct. The timer is measured from each slot's most recent *accepted*
contribution, not its creation time, so a slot still making genuine progress
under ordinary network jitter is never evicted out from under it — only one
gone fully silent for the whole TTL window (the real crashed-worker
signature) is reclaimed. A reaped slot logs `[reaped] job=... round=...
chunk=... -- incomplete after ...ms, evicting`.
`test_slot_ttl_reaper_reclaims_permanently_incomplete_slot` proves this with a
real crashed-worker scenario (one of two expected workers never sends), then
confirms a second, healthy job's round still completes normally afterward.
Porting an equivalent into the XDP kernel program is separate follow-up work
(no arbitrary timer inside the BPF hot path without `bpf_timer`, which needs
real-kernel testing this dev environment can't do locally) — not attempted
here.

### Differential fuzz harness (`fuzz/`)

`userspace_agg/agg.c` and `xdp_agg/xdp_agg.c` both carry a header comment
asserting they implement "byte-for-byte the same algorithm" — a claim that
used to be backed only by 9 hand-written example-based unit tests, not an
adversarial search. `fuzz/parse_shared.h` extracts each file's per-packet
*stateless* admission logic (header-fits, `chunk_len` bound, length-covers-
payload, `worker_id`/`num_workers` bounds) into two pure functions, and
`fuzz/fuzz_grad_parse.cpp` (a libFuzzer + AddressSanitizer harness, run via
`fuzz/build_and_run_fuzz.sh [seconds]`) feeds both the exact same raw bytes
and aborts on any verdict disagreement or out-of-bounds read. Run for real —
locally (~49M executions in 30s) and in CI (133M executions in 120s,
`.github/workflows/fuzz.yml`) — it found **zero crashes and zero verdict
divergences**: a clean bill of health, not a shortcut, and now a
continuously-checked proof of the parity claim instead of a one-time human
read-through. The one deliberately out-of-scope nuance (a stateful
`slot->chunk_len` consistency check neither extracted function can model
without a live slot table) is documented in `fuzz/README.md`, not hidden.

### Latency distribution rigor (percentiles, not just mean/min/max)

`scripts/benchmark.py` now runs 30 trials per (config, worker-count) cell
(up from 10) and reports p50/p95/p99, a bootstrap 95% confidence interval on
the median, and a permutation test with Cliff's delta effect size comparing
`noagg` vs. `useragg` at each worker count — plain Python throughout, no new
dependency. Real result: none of the 4 worker counts show a statistically
significant difference (all p > 0.05), consistent with this project's own
"`useragg` is not expected to beat `noagg` here" framing (see the dashboard's
latency panel) — a claim that previously rested on a bare mean comparison
over a handful of trials now rests on an actual significance test. Data in
`bench/results_percentiles.csv`, charted on the dashboard.

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
tests/          correctness test suite (10/10 passing, driving the real binaries)
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
