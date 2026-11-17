# NetSum: in-network gradient aggregation on commodity Linux with XDP/eBPF

[![CI](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/ci.yml/badge.svg)](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/ci.yml)
[![XDP real-kernel load test](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/xdp-loadtest.yml/badge.svg)](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/xdp-loadtest.yml)
[![BPF unit tests](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/bpf-unit.yml/badge.svg)](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/bpf-unit.yml)
[![Fuzz](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Manav0559/xdp-gradient-aggregation/actions/workflows/fuzz.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Distributed training sums every worker's gradient on every step. ATP (NSDI
2021) does that summing inside a programmable switch; NetSum does it on an
ordinary Linux host with an XDP program in the kernel's receive path.

NetSum implements best-effort in-kernel aggregation with fallback to the
parameter server, resend-driven partial flushing, ACK-driven slot retirement,
an ATP-style aggregator pool with collision fallback, and a reliable windowed
worker. It is verified on a real kernel in CI and benchmarked on GitHub-hosted
runners over veth. **It is not a line-rate system;** see
[Results](#measured-results).

* Live dashboard: <https://manav0559.github.io/xdp-gradient-aggregation/dashboard/>
* Interactive demo: <https://manav0559.github.io/xdp-gradient-aggregation/demo/>. A JavaScript simulation of the protocol rules (slot pool, loss recovery, fallback, wire v3 exponents) that runs in the browser; append `?selftest` to run its built-in correctness check.
* Results: [`docs/RESULTS.md`](docs/RESULTS.md) · Design: [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) · History: [`docs/HISTORY.md`](docs/HISTORY.md)

## Architecture

```
 ns_w: workers                    aggregator host                        ns_ps: parameter server
 ┌───────────────┐  gradients   ┌──────────────────────────────┐ aggregates ┌───────────────┐
 │ worker 0..N-1 │ ───────────► │ veth_w0 ─► XDP: netsum_xdp_   │ ─────────► │ paramserver   │
 │ (reliable,    │              │           aggregate          │  partials  │ (merges by    │
 │  windowed)    │ ◄─────────── │           (slot map / array) │  fallbacks │  contributor  │
 └───────────────┘   results    │ veth_p0 ◄─ ACK retires slot  │ ◄───────── │  bitmap)      │
                     (routed)   └──────────────────────────────┘    ACK     └───────────────┘
                                  netsum-ctl: attach, config, stats, slots, sweep (TTL)
```

Every packet is a 20-byte header, up to 64 int32 values (Q16.16, or on v3
`round(x * 2^e)` with a per-chunk exponent *e* in the header), and (in v2
and v3) a 32-byte contributor bitmap. Packet kinds: raw contribution, RESEND, FALLBACK
(a contribution the aggregator passed through), PARTIAL (a flushed incomplete
sum), aggregate, ACK (the result) and REGISTER. A slot moves
`EMPTY -> ACCUMULATING -> COMPLETED -> EMPTY` (or `-> FLUSHED -> EMPTY`).
Details: [`docs/DESIGN_NOTES.md`](docs/DESIGN_NOTES.md) §1-§13.

## Quick start

**macOS or Linux, userspace only** (no kernel features needed):

```sh
make && make test            # unit tests + 5 Python suites, about 30 s
scripts/demo_local.sh        # PS + userspace aggregator + 3 reliable workers, with simulated loss
```

**Linux, with the XDP program** (root):

```sh
make bpf && make all ctl
sudo scripts/topo.sh up                                         # three namespaces
sudo ./bin/netsum-ctl attach --ifname veth_w0 --ifname veth_p0 --mode auto   # prints the mode the kernel chose
sudo ./bin/netsum-ctl config --ps-mac "$(sudo scripts/topo.sh mac ns_ps veth_p1)" --ps-ip 10.10.2.2 \
     --ps-port 9000 --agg-mac "$(sudo scripts/topo.sh mac '' veth_p0)" --agg-ip 10.10.2.1 --egress-ifname veth_p0
sudo ip netns exec ns_ps ./bin/paramserver --ack-to 10.10.2.1:9876 9000 agg &
for w in 0 1 2; do sudo ip netns exec ns_w ./bin/worker --mode reliable --to 10.10.1.1:9876 \
     --ps 10.10.2.2:9000 --job 1 --worker $w --workers 3 --rounds 100 --vector-len 1024 --fixed 0.5 & done; wait
sudo ./bin/netsum-ctl stats ; sudo ./bin/netsum-ctl slots
sudo ./bin/netsum-ctl sweep --ttl-ms 500 --once                   # reclaim stuck slots
make bpf-unit                                                    # BPF_PROG_TEST_RUN unit cases
```

## What is implemented

| Component | What it does | Verified by |
|---|---|---|
| `protocol/` | wire formats v2 and v3 (per-chunk exponent), one shared parser (`grad_parse.h`) for every path, counters, map layouts | unit tests, libFuzzer differential fuzzing, kernel corpus replay |
| `xdp_agg/xdp_agg.c` | in-kernel aggregation: admission checks, tombstones, overflow detection, quota with fallback, ACK retirement, RESEND flush, FALLBACK, array-mode aggregators, source rewrite, redirect; `netsum_sweep` for TTL | `bpf-unit.yml` (79 cases), `xdp-loadtest.yml` (real kernel, real UDP) |
| `userspace_agg/agg.c` | the same algorithm in a process: hash mode, or ATP's aggregator pool with collision fallback (`--array-slots-log2 N`); optional `recvmmsg`/`sendmmsg` batching on Linux (`--batch N`) | `tests/test_reliability.py`, sanitizer CI job, benchmark (including a batched and an array-mode baseline) |
| `paramserver/` | final summing node, merges raw/fallback/partial/aggregate packets by contributor set, sends results | `tests/test_fallback.py`, `tests/test_reliability.py` |
| `worker/` | one-shot sender and a reliable windowed worker with retransmission | `tests/test_reliability.py`, Scenarios H2/I2/J2 |
| `ctl/netsum_ctl.c` | libbpf control plane: attach (reports the real mode), config, stats, slots, jobs, sweep, verify | `ci/test_netsum_ctl.sh` |
| `scripts/bench_v2.sh` | closed-loop benchmark and fairness sweep on three namespaces | `bench.yml` |
| `examples/train_mlp/` | SGD training through NetSum, bit-identity checked | `train-demo.yml` |

## Measured results

From CI run 43765091283: GitHub runner, Linux 7.0, 4 vCPU Xeon, veth, 117
trials, every result checked exact, XDP packet accounting balanced in every
trial. Full tables, method and threats to validity:
[`docs/RESULTS.md`](docs/RESULTS.md).

| | 2 workers | 4 workers | 8 workers |
|---|---|---|---|
| throughput, XDP generic / userspace aggregator | **1.020** [1.014, 1.025] | **1.081** [1.076, 1.087] | **1.109** [1.105, 1.127] |
| throughput, XDP native / userspace aggregator | 0.949 [0.944, 0.958] | 1.006 [0.999, 1.012] (n.s.) | 1.024 [1.020, 1.042] |
| median round time, XDP generic / userspace | **0.919** [0.897, 0.951] | **0.950** [0.938, 0.962] | **0.929** [0.917, 0.940] |

Ratios of medians with bootstrap 95% CIs; permutation tests, Holm-corrected
(p_Holm <= 0.033 for every bold entry).

* **Replicated:** seven runs on four CPU types. On the Xeon 6975P-C (three
  runs) the 4- and 8-worker gains reproduced every time (6.7-10.9%); the
  2-worker gain was 2.0% twice and 0.6% (not significant) once. On the Xeon
  Platinum 8573C, the AMD EPYC 7763 (two runs) and the AMD EPYC 9V74 the gap
  was much larger, 1.31-1.69x throughput and 15-34% lower round time,
  because the userspace aggregator was far slower there. The direction held
  in all seven runs; the size depends on the machine.
* **In-kernel aggregation helps: by 1-11% on one runner type (growing with
  the number of workers; not significant at 2 workers in one of three runs),
  by 31-69% on three others, never by multiples of the work it removes.** A
  pre-registered variant of the userspace aggregator that batches its system
  calls (`recvmmsg`/`sendmmsg`) did not change its throughput in four runs on
  three CPU types, and XDP stayed ahead of it (7-9% at 4-8 workers on the
  6975P-C, 29-69% elsewhere); the batch sizes it reached were not measured. Per packet, the XDP program body costs 218-275 ns against
  540-1,669 ns for the userspace aggregator's processing (generic mode, 8
  down to 2 workers), so up to 2.5-6x less; the userspace figure includes
  its forwarding `sendto`, the XDP figure excludes the transmit after the
  redirect, and neither includes the receive path (generic XDP still
  allocates an skb; the userspace process spends 2.0-2.3 us of CPU per packet
  with all its system calls). On veth the XDP work runs on the sending CPU.
* **Native XDP on veth is slower than generic** (veth's native path adds a
  ring and NAPI hop); native numbers on veth say nothing about hardware NICs.
* **Multi-tenancy:** a drop-based per-job quota starves greedy jobs (Jain's
  index 0.34); falling back to the parameter server keeps
  demand-proportional shares (1.000), as does a small aggregator pool where
  half the contributions fall back.
* **Training:** an MLP trained through noagg, userspace and XDP aggregation,
  and through XDP with 5% packet loss, ends with weights bit-identical to the
  local quantized all-reduce and within 1e-6 loss of float training.
* **Quantization:** Q16.16 loses gradients below ~1e-5 (6% of N(0, 1e-4)
  values round to zero). Wire v3 adds a per-chunk exponent that workers agree
  on from the previous step's result: with every gradient scaled by 1e-4,
  Q16.16 training ends at 0.436 accuracy and v3 at 0.989 (float: 0.989),
  bit-identical across noagg, userspace and XDP, with and without 5% loss.
  A chunk that overflows is retried in the same step at a lower exponent.
  At exponent 16 (the same integers as Q16.16) v3 costs no measurable
  throughput: v3 / v2 between 0.998 and 1.004 on the userspace and XDP paths.

Not shown: physical NICs, native XDP on hardware, multi-host topologies,
line rate. The environment is a shared VM and veth is a software device.

## Correctness evidence

* **Bugs fixed red-first** (`docs/DESIGN_NOTES.md` §16): late duplicates
  re-creating slots (C1), worker ids beyond the fan-in (C2), fan-in
  disagreement (C3), silent overflow (C4), a parameter server without the
  aggregator's checks (C5), probe chains broken by deletion (C6), a quota that
  failed open (C7), a racy kernel quota (C8), the aggregate's source address
  (C9), a benchmark that did not measure aggregation (C10), a fuzzer testing
  copies (C11), tests that could not fail (C12), unrecoverable lost results
  (C13), and a livelock between partial flushes and retransmissions found by
  a kernel scenario (C14).
* **Kernel unit tests:** 79 `BPF_PROG_TEST_RUN` cases on the loaded program,
  covering every verdict and state transition, plus the fuzz corpus and
  5,000 mutations replayed against the userspace parser, on two builds whose
  disassembly is identical.
* **Kernel end to end:** 24 scenarios over real UDP and veth, including 20%
  loss, lost results recovered through the XDP path (hash and array mode), reordering, a permanently lost packet recovered through a sweeper
  flush, retransmission and fallback, and the sweeper leaving no slot behind;
  assertions on exact counter deltas.
* **Fuzzing:** the shipped parser against a reference parser under ASan.
* **Accounting:** every packet the XDP program sees ends in exactly one
  outcome counter; checked in every benchmark trial.

## How this relates to ATP

[ATP](https://www.usenix.org/conference/nsdi21/presentation/lao) (Lao, Le,
Mahajan, Chen, Wu, Akella, Swift; NSDI 2021, Best Paper) aggregates gradient
fragments in programmable top-of-rack switches.

* **Reproduced:** best-effort aggregation with a hash-indexed aggregator pool
  and fallback to the parameter server on collision (§3.5); the resend flag
  flushing partial aggregates to the PS (§3.7); deallocation of aggregators by
  the parameter packet, i.e. the ACK (§3.5); reclamation of abandoned
  aggregators by timestamp (§3.7); scaled-integer arithmetic with an overflow
  flag (§3.8); contributor bitmaps that prevent double counting at the PS.
* **Adapted:** one Linux host per aggregation point instead of a switch; a
  BPF hash map or a BPF array instead of switch registers; a userspace sweeper
  driving an in-kernel program instead of the switch's timestamp check;
  results unicast to workers instead of IGMP multicast; an optional per-job
  admission quota as an extra policy (it is not ATP's mechanism); on overflow,
  instead of ATP's floating-point re-request, wire v3 workers retry the chunk
  in the same step at a lower shared exponent.
* **Not reproduced:** the two-level (rack) hierarchy, ECN-based AIMD
  congestion control, dynamic re-hashing of colliding indexes, and Tofino line rate.

## Repository layout

```
protocol/      wire format, shared parser, counters, BPF map layouts
xdp_agg/       the XDP program (aggregation + sweep) and vendored BPF headers
userspace_agg/ the same algorithm as a process
paramserver/   parameter server
worker/        one-shot and reliable workers
common/        slot table shared by agg and paramserver
ctl/           netsum-ctl control plane (libbpf)
tests/         unit, Python suites, BPF_PROG_TEST_RUN harness
fuzz/          libFuzzer differential harness and corpus
ci/            helpers for the kernel scenarios
scripts/       topology, benchmarks, analysis, quantization study, demo
bench/         committed results: v2/, lite/, v1-macos-loopback/ (history)
examples/      training demo
dashboard/     static results page (GitHub Pages)
docs/          design notes, results, history, the original spec, the work log
```

## History

v1 had the protocol, the components and a real-kernel CI test, but its
benchmark measured process start-up on macOS loopback and never the XDP
path. v2 fixed the bugs above, added the reliability and fallback machinery,
and measured the XDP path. See [`docs/HISTORY.md`](docs/HISTORY.md) and the
step-by-step [`docs/WORKLOG.md`](docs/WORKLOG.md).

## Research grounding

* C. Lao, Y. Le, K. Mahajan, Y. Chen, W. Wu, A. Akella, M. Swift. *ATP:
  In-network Aggregation for Multi-tenant Learning.* USENIX NSDI 2021.
* A. Sapio, M. Canini, C.-Y. Ho, J. Nelson, P. Kalnis, C. Kim,
  A. Krishnamurthy, M. Moshref, D. Ports, P. Richtarik. *Scaling Distributed
  Machine Learning with In-Network Aggregation* (SwitchML). USENIX NSDI 2021.
* J. Fang, H. Xu, G. Zhao, Z. Yu, B. Shen, L. Xie. *Accelerating Distributed
  Training With Collaborative In-Network Aggregation.* IEEE/ACM Transactions
  on Networking 32(4):3437-3452, 2024. DOI 10.1109/TNET.2024.3387948.

The original project specification is in
[`docs/PROJECT_SPEC.md`](docs/PROJECT_SPEC.md).

## License

MIT, see [LICENSE](LICENSE).
