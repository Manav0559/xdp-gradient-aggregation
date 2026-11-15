# NetSum measured results

Every number here comes from a committed script run in CI; the run ID,
commit and environment are given with each table. Later sections supersede
earlier ones only where they say so.

## Benchmark-lite: first XDP measurements (open loop, two namespaces, `xdpgeneric`)

**Source:** workflow `bench-lite.yml`, run 43759600920, on PR head `29acb78`
(GitHub merge ref `3b0cc35`). Raw per-trial data: `bench/lite/raw.csv`
(288 trials); environment: `bench/lite/environment.json`; tables:
`bench/lite/summary.csv`, `bench/lite/comparisons.csv` and
`bench/lite/accounting.csv`, all produced by
`python3 scripts/bench_lite_analyze.py bench/lite/raw.csv bench/lite`.

**Environment:** GitHub-hosted runner, Linux `7.0.0-1014-aws` x86_64, 4 vCPU
(Intel Xeon 6975P-C), clang 18.1.3, libbpf 1.3.0; XDP attach mode read back
from `ip -d link`: `xdpgeneric`; no CPU pinning.

**What was measured** (method: `docs/DESIGN_NOTES.md` §15). One sender
process offers 25,000 single-chunk rounds (16 values per packet) for 2, 4 or 8
logical workers, round by round, paced at 100k, 200k or 400k packets/s or
unpaced, over a veth pair between two network namespaces. Three paths:
**noagg** (every contribution goes to the parameter server), **useragg**
(`bin/agg` sums in a process in the other namespace and forwards one packet
per round) and **xdp** (`xdp_agg.o` on `veth0` consumes partial
contributions and bounces each completed aggregate back with `XDP_TX`).
8 trials per cell; each trial starts from empty maps. The sender does not wait
for results (open loop), and nothing returns to the workers yet.

**Packet accounting balanced in 288/288 trials:** every packet sent was
received at the next hop or counted as a socket drop there, and every packet
the XDP program saw ended in exactly one outcome counter.

### Paced load (100k-400k packets/s)

All three paths completed **every round in every paced cell** (completion
ratio 1.0000, 95% CI [1.0000, 1.0000]). At a paced rate an open-loop
benchmark's goodput equals the offered rate, so these cells say only that no
path drops work up to 400k packets/s on this machine; they are not a speed
comparison (`bench/lite/results.md` lists every cell).

### Unpaced: how fast one sender can push rounds through each path

| Workers | sender pps noagg | sender pps useragg | sender pps xdp | goodput useragg (rounds/s) | goodput xdp (rounds/s) | completion useragg | completion xdp |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 634,076 | 548,722 | 625,958 | 214,011 | 313,209 | 0.8523 | 1.0000 |
| 4 | 636,878 | 589,034 | 726,190 | 147,368 | 181,625 | 1.0000 | 1.0000 |
| 8 | 634,604 | 557,604 | 856,650 | 69,727 | 107,110 | 1.0000 | 1.0000 |

Medians over 8 trials. Pre-registered comparisons, useragg vs xdp (two-sided
permutation test on Cliff's delta, 2,000 relabelings, seed 1234; Holm
correction within each family; with 8 vs 8 trials the smallest attainable
p is 1/2001 = 0.0005):

| Test | Workers | xdp median | useragg median | ratio xdp/useragg [95% CI] | Cliff's delta | p | p (Holm) |
|---|---:|---:|---:|---|---:|---:|---:|
| F1 goodput | 2 | 3.132e+05 | 2.14e+05 | 1.464 [1.362, 1.512] | 1.000 | 0.0005 | 0.0015 |
| F1 goodput | 4 | 1.816e+05 | 1.474e+05 | 1.232 [1.133, 1.384] | 1.000 | 0.0010 | 0.0015 |
| F1 goodput | 8 | 1.071e+05 | 6.973e+04 | 1.536 [1.467, 1.575] | 1.000 | 0.0005 | 0.0015 |
| F2 completion | 2 | 1 | 0.8523 | 1.173 [1.010, 1.321] | 0.875 | 0.0020 | 0.0060 |
| F2 completion | 4 | 1 | 1 | 1.000 [1.000, 1.000] | 0.000 | 1.0000 | 1.0000 |
| F2 completion | 8 | 1 | 1 | 1.000 [1.000, 1.000] | 0.000 | 1.0000 | 1.0000 |

### Per-packet processing cost

| Workers | XDP program, ns per invocation (range of cell medians) | `agg` process on-CPU ns per packet received |
|---:|---|---|
| 2 | 221-254 | 2,337-2,454 |
| 4 | 183-201 | 1,627-1,875 |
| 8 | 145-156 | 1,519-1,673 |

The XDP figure is `run_time_ns / run_cnt` from `kernel.bpf_stats_enabled`:
time inside the BPF program only. The `agg` figure is the process's on-CPU
time from `/proc/<pid>/schedstat` divided by packets it received, so it
includes its `recvfrom`/`sendto` system calls. **They are not like-for-like:**
neither includes the kernel's receive path before the hook or socket (skb
allocation, softirq), and that work is charged elsewhere.

### Interpretation

* **XDP aggregation was faster than userspace aggregation when the sender ran
  unpaced:** 1.46x (2 workers), 1.23x (4) and 1.54x (8) more completed rounds
  per second, significant after Holm correction at every worker count, with
  no overlap between the trial distributions (Cliff's delta = 1.000).
* **That gain is in what one sender can push, not in a measured aggregator
  ceiling.** In every unpaced cell goodput is about sender rate / workers,
  so the sender is the bottleneck for all three paths. The sender reached
  626k-857k packets/s toward XDP but only 549k-589k toward `agg`. The likely
  cause, not verified tonight: on veth the receiving side's processing runs
  on the sending CPU, and generic XDP consumes most packets (`XDP_DROP` of a
  partial contribution) before the UDP and socket layers, so each sent packet
  costs the sender's CPU less. Checking `/proc/softirqs` per CPU would
  confirm or refute this.
* **Userspace aggregation dropped work at 2 workers unpaced** (median
  completion 0.85; the agg socket overflowed), while XDP completed every
  round in every cell (F2, p_Holm = 0.006). At 4 and 8 workers neither lost work.
* **Per packet, the XDP program spends 145-254 ns** (less with more workers,
  because a larger share of packets are partial contributions that end in a
  drop instead of the rewrite-and-transmit path), against 1.5-2.5 us of
  on-CPU time per packet in the `agg` process.
* Versus **noagg**, the XDP path delivers N times fewer packets to the
  parameter server per round (by construction) at a comparable sender rate.

### Threats to validity

* Shared, virtualised 4-vCPU runner; noisy neighbours are possible. Trials
  are interleaved (trial-major loop) so drift spreads across cells.
* veth is a software device: the "wire" is a memory copy, and there is no
  NIC, DMA or real NAPI budget. Generic XDP still allocates an skb.
* Sender, aggregator and parameter server share one host's CPUs and nothing
  is pinned, so the paths do not get the same number of cores (`agg` is a
  separate process; XDP runs in softirq context).
* Open loop with no result path: this measures how much offered load each
  path absorbs, not training round time. Phase 6 adds a closed-loop,
  three-namespace benchmark with results returned to workers.
* One chunk size (16 values) and single-chunk rounds.

### What would be needed for line-rate claims

Two or three physical hosts with XDP-capable NICs (mlx5, i40e, ice), native
driver-mode XDP, RSS steering and pinned cores. Out of scope here.
