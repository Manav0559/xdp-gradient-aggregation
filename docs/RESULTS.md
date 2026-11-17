# NetSum measured results

Every number here comes from a committed script run in CI; the run ID,
commit and environment are given with each table. Later sections supersede
earlier ones only where they say so.

## v2: closed-loop benchmark on three namespaces (primary result)

**Source:** workflow `bench.yml`, run 43765091283, PR head `dc85e1a` (GitHub
merge ref `f52225e`). Per-trial data: `bench/v2/throughput.csv`,
`bench/v2/latency.csv`, `bench/v2/fairness.csv`; environment:
`bench/v2/environment.json`; every table below is
`python3 scripts/bench_analyze.py <artifact dir> bench/v2`. The 16 MB of
per-round latency samples (`latency_rounds.csv`) stay in the run's artifact
`netsum-bench-43765091283`; `bench/v2/summary_latency.csv` holds the pooled
percentiles computed from them.

**Environment:** GitHub-hosted runner, Linux `7.0.0-1016-aws` x86_64,
4 vCPU Intel Xeon 6975P-C, clang 21.1.8, libbpf 1.6.3. XDP attach modes read
back from the kernel: generic, and native (veth accepted native attach; the
PS-side veth has GRO enabled so redirected frames are delivered). Workers
pinned to CPUs 0-1, `agg` to CPU 2, the PS to CPU 3.

**What was measured** (method: `docs/DESIGN_NOTES.md` §15 and §13). Workers
in one namespace, the aggregator in the root namespace, the parameter server
in a third, routed with no rp_filter/accept_local relaxation; XDP is attached
to both aggregator interfaces and redirects aggregates out the PS-facing one.
The load generator is the reliable worker: each of N workers (2, 4, 8) sends
gradients of 1,024 values (16 chunks of 64) per round and waits for the PS's
results, so every configuration returns results to the workers and round
time is measured end to end at the worker. Throughput: 4,000 rounds with a
window of 64 chunks, 8 trials per cell. Latency: 2,000 synchronous rounds
(round r+1 starts after every result of round r), 5 trials per cell. Every
result in every trial was checked to be the exact expected sum; the run would
have failed otherwise.

**XDP packet accounting balanced in 117/117 trials** (every packet the
program saw ended in exactly one outcome counter).

### Throughput (window 64, closed loop)

| config | workers | attach | values/s median [95% CI] | rounds/s | XDP ns/run | agg CPU ns/pkt | PS CPU ns/chunk | in-network | retransmissions |
|---|---:|---|---|---:|---:|---:|---:|---:|---:|
| noagg | 2 | - | 5,565,225 [5,513,803, 5,579,910] | 5,435 | - | - | 11,496 | - | 0 |
| useragg | 2 | - | 5,986,412 [5,962,797, 6,017,874] | 5,846 | - | 2,316 | 10,681 | - | 0 |
| xdp-generic | 2 | generic | 6,103,577 [6,101,021, 6,133,270] | 5,961 | 302.8 | - | 10,479 | 1.000 | 0 |
| xdp-native | 2 | native | 5,682,268 [5,674,230, 5,723,092] | 5,549 | 316.2 | - | 11,257 | 1.000 | 0 |
| xdp-array | 2 | native | 5,779,568 [5,737,080, 5,803,097] | 5,644 | 267.4 | - | 11,060 | 0.999 | 0 |
| noagg | 4 | - | 3,068,423 [3,053,212, 3,073,310] | 2,997 | - | - | 20,839 | - | 0 |
| useragg | 4 | - | 3,284,859 [3,266,989, 3,295,177] | 3,208 | - | 2,334 | 19,412 | - | 0 |
| xdp-generic | 4 | generic | 3,549,666 [3,541,001, 3,555,735] | 3,466 | 282.1 | - | 18,006 | 1.000 | 0 |
| xdp-native | 4 | native | 3,305,485 [3,287,921, 3,317,534] | 3,228 | 279.6 | - | 19,342 | 1.000 | 0 |
| xdp-array | 4 | native | 3,334,149 [3,309,233, 3,344,249] | 3,256 | 241.5 | - | 19,175 | 0.999 | 0 |
| noagg | 8 | - | 1,601,003 [1,595,033, 1,610,535] | 1,563 | - | - | 39,924 | - | 0 |
| useragg | 8 | - | 1,777,301 [1,751,106, 1,781,802] | 1,736 | - | 2,039 | 35,940 | - | 0 |
| xdp-generic | 8 | generic | 1,971,498 [1,965,531, 1,982,698] | 1,925 | 255.8 | - | 32,398 | 1.000 | 0 |
| xdp-native | 8 | native | 1,819,670 [1,814,310, 1,834,863] | 1,777 | 252.8 | - | 35,111 | 1.000 | 0 |
| xdp-array | 8 | native | 1,833,739 [1,825,026, 1,837,451] | 1,791 | 228.6 | - | 34,833 | 0.999 | 0 |

### Round completion time (synchronous rounds, measured at the worker)

| config | workers | samples | p50 us [95% CI] | p95 us | p99 us [95% CI] | p99.9 us | agg algorithm ns/pkt | XDP ns/run |
|---|---:|---:|---|---:|---|---:|---:|---:|
| noagg | 2 | 20000 | 187 [185, 188] | 212 | 225 [223, 226] | 285 | - | - |
| useragg | 2 | 20000 | 186 [184, 188] | 233 | 276 [266, 282] | 347 | 1,669 | - |
| xdp-generic | 2 | 20000 | 171 [168, 174] | 207 | 223 [219, 226] | 254 | - | 275.2 |
| xdp-native | 2 | 20000 | 189 [186, 192] | 227 | 248 [245, 251] | 286 | - | 263.1 |
| xdp-array | 2 | 20000 | 187 [186, 189] | 225 | 247 [245, 253] | 274 | - | 239.6 |
| noagg | 4 | 40000 | 327 [326, 329] | 360 | 402 [397, 405] | 486 | - | - |
| useragg | 4 | 40000 | 322 [320, 323] | 398 | 425 [423, 428] | 816 | 908 | - |
| xdp-generic | 4 | 40000 | 306 [304, 307] | 377 | 394 [392, 397] | 703 | - | 251.6 |
| xdp-native | 4 | 40000 | 365 [363, 367] | 403 | 422 [420, 425] | 489 | - | 247.7 |
| xdp-array | 4 | 40000 | 361 [359, 362] | 399 | 420 [418, 421] | 548 | - | 219.2 |
| noagg | 8 | 80000 | 626 [624, 629] | 647 | 673 [666, 678] | 1,142 | - | - |
| useragg | 8 | 80000 | 615 [613, 618] | 648 | 681 [673, 689] | 1,762 | 540 | - |
| xdp-generic | 8 | 80000 | 572 [569, 575] | 604 | 625 [618, 628] | 913 | - | 218.1 |
| xdp-native | 8 | 80000 | 653 [650, 656] | 703 | 736 [732, 740] | 1,168 | - | 217.9 |
| xdp-array | 8 | 80000 | 645 [642, 648] | 693 | 727 [723, 731] | 1,295 | - | 191.4 |

### Pre-registered comparisons against userspace aggregation

| family | workers | config | config median | useragg median | ratio [95% CI] | Cliff's delta | p | p (Holm) | n |
|---|---:|---|---:|---:|---|---:|---:|---:|---|
| T_throughput | 2 | xdp-generic | 6,103,577 | 5,986,412 | 1.020 [1.014, 1.025] | 1.000 | 0.0005 | 0.0030 | 8 vs 8 |
| T_throughput | 2 | xdp-native | 5,682,268 | 5,986,412 | 0.949 [0.944, 0.958] | -1.000 | 0.0005 | 0.0030 | 8 vs 8 |
| T_throughput | 4 | xdp-generic | 3,549,666 | 3,284,859 | 1.081 [1.076, 1.087] | 1.000 | 0.0005 | 0.0030 | 8 vs 8 |
| T_throughput | 4 | xdp-native | 3,305,485 | 3,284,859 | 1.006 [0.999, 1.012] | 0.531 | 0.0895 | 0.0895 | 8 vs 8 |
| T_throughput | 8 | xdp-generic | 1,971,498 | 1,777,301 | 1.109 [1.105, 1.127] | 1.000 | 0.0005 | 0.0030 | 8 vs 8 |
| T_throughput | 8 | xdp-native | 1,819,670 | 1,777,301 | 1.024 [1.020, 1.042] | 1.000 | 0.0005 | 0.0030 | 8 vs 8 |
| L_round_p50 | 2 | xdp-generic | 170 | 185 | 0.919 [0.897, 0.951] | -1.000 | 0.0085 | 0.0325 | 5 vs 5 |
| L_round_p50 | 2 | xdp-native | 191 | 185 | 1.032 [0.989, 1.043] | 0.520 | 0.1984 | 0.1984 | 5 vs 5 |
| L_round_p50 | 4 | xdp-generic | 306 | 322 | 0.950 [0.938, 0.962] | -1.000 | 0.0070 | 0.0325 | 5 vs 5 |
| L_round_p50 | 4 | xdp-native | 365 | 322 | 1.134 [1.121, 1.144] | 1.000 | 0.0085 | 0.0325 | 5 vs 5 |
| L_round_p50 | 8 | xdp-generic | 574 | 618 | 0.929 [0.917, 0.940] | -1.000 | 0.0050 | 0.0300 | 5 vs 5 |
| L_round_p50 | 8 | xdp-native | 652 | 618 | 1.055 [1.050, 1.069] | 1.000 | 0.0065 | 0.0325 | 5 vs 5 |

### Fairness: three jobs with demand 4:2:1 sharing one XDP aggregator

| policy | goodput job1 (demand 64) | job2 (32) | job3 (16) | Jain raw | Jain / demand | retransmissions | in-network fraction |
|---|---:|---:|---:|---:|---:|---:|---:|
| none | 2,945 | 1,458 | 736 | 0.776 | 1.000 | 0 | 1.000 |
| quota-drop | 13 | 13 | 5,039 | 0.337 | 0.335 | 679 | 0.999 |
| quota-fallback | 2,896 | 1,448 | 731 | 0.779 | 1.000 | 0 | 0.995 |
| array-small | 2,794 | 1,419 | 696 | 0.779 | 1.000 | 0 | 0.494 |

XDP packet accounting balanced in 117/117 trials.

### Interpretation

* **Generic-mode XDP aggregation is faster than userspace aggregation on this
  machine, and the gap grows with the number of workers:** +2.0%, +8.1% and
  +10.9% aggregated values per second at 2, 4 and 8 workers, and a 5-8% lower
  median round time, all significant after Holm correction (throughput
  p_Holm = 0.003 each, Cliff's delta 1.0; latency p_Holm 0.030-0.033 with 5 vs
  5 trials). This is the first closed-loop answer to the project's question:
  yes, in-kernel aggregation helps here, by about 2-11%, not by multiples.
* **Native-mode XDP on veth is slower than generic mode** (-5.1% throughput at
  2 workers, no significant difference at 4, +2.4% at 8; median round time
  5-13% higher than userspace at 4 and 8 workers, no significant difference
  at 2). Native XDP on a veth pair does not skip skb
  allocation the way it does on a physical NIC: frames are handed to the
  peer through a ring and a NAPI poll, an extra queueing hop that generic mode,
  which runs inline in the sender's receive path, does not have. This is the
  likely cause and is not verified with kernel tracing here. Native-mode
  numbers on veth say nothing about native XDP on hardware.
* **Where the aggregation work runs.** NET_RX softirq counts per CPU are the
  same for noagg, generic and native XDP: ~40-47% on the worker CPUs (0-1) and
  the rest on the PS's CPU (3); the `agg` CPU (2) only sees softirqs in the
  userspace configuration. On veth the receive path, and therefore the XDP
  program, runs on the sending CPU, so XDP aggregation adds no context switch
  or extra core, while `bin/agg` costs a separate process and a full UDP
  receive and send per packet. This also confirms the hypothesis left open in
  benchmark-lite. (Softirq counts are invocations, not time.)
* **Per-packet cost:** the XDP program spends 191-316 ns per invocation
  (`run_time_ns / run_cnt`; lower with more workers because more packets are
  partial contributions); the userspace aggregator's algorithm alone takes
  0.5-1.7 us per packet and the whole process 2.0-2.3 us of CPU per packet
  received, including its system calls.
* **Versus no aggregation:** with N workers the PS receives N times fewer
  packets per chunk, yet the PS spends only 9-19% less CPU per chunk with XDP
  aggregation than with noagg, because it still sends one result to each of
  the N workers per chunk. Userspace aggregation is also faster than noagg
  (the PS is the bottleneck when it receives every contribution).
* **Array mode** (the ATP aggregator-pool design, 65,536 aggregators) runs
  0.8-1.7% faster than hash mode in native mode and aggregates 99.9% of
  contributions in-network at this load; its program cost is the lowest
  (191-267 ns per run).
* **Fairness.** With no policy, three jobs with demand 4:2:1 get goodput in
  exactly that ratio (Jain's index over goodput/demand 1.000). A per-job quota
  that **drops** over-quota contributions starves the two jobs whose window
  exceeds the quota: 13 rounds/s against 5,039 for the small job, 679
  retransmissions, Jain 0.34. The same quota with **fallback to the PS**
  keeps every job at its demand-proportional share (Jain/demand 1.000,
  0.5% of contributions aggregated at the PS). A deliberately small array of
  64 aggregators aggregates only 49% of contributions in-network but loses no
  goodput: collisions degrade to the PS, which is ATP's multi-tenancy design.

### Replication across runs and runner hardware

The same benchmark ran twice more on later commits whose measured code is
unchanged (`b6c88a5`, `94155a8`); every run had 117 trials, exact results and
balanced XDP accounting. Data: `bench/v2/replication-43784240541/` and
`bench/v2/replication-43785552861/` (each with raw CSVs, environment and the
analyzer's tables).

| run | runner CPU (kernel) | throughput, XDP generic / userspace at 2 / 4 / 8 workers | median round time, XDP generic / userspace | XDP native vs generic |
|---|---|---|---|---|
| 43765091283 (primary) | Xeon 6975P-C (7.0.0-1016-aws) | 1.020 / 1.081 / 1.109 | 0.919 / 0.950 / 0.929 | slower |
| 43785552861 | Xeon 6975P-C (7.0.0-1016-aws) | 1.020 / 1.078 / 1.102 | 0.923 / 0.938 / 0.927 | slower |
| 43784240541 | Xeon Platinum 8573C (7.0.0-1019-azure) | 1.685 / 1.420 / 1.369 | 0.705 / 0.663 / 0.787 | slower |

Every generic-vs-userspace comparison is significant after Holm correction in
all three runs (p_Holm <= 0.033). On the same runner type the effect
reproduces to within about one percentage point. On a different runner type
the userspace aggregator was much slower (2.8M vs 6.0M values/s at 2 workers)
while the XDP path lost less, so XDP's advantage grew to 37-69% throughput and
21-34% round time; native XDP was also faster than userspace there. The
direction (generic XDP ahead of the userspace aggregator; native XDP on veth
behind generic XDP) held everywhere; the size depends on the machine, which is
why no single speed-up figure is quoted without its environment. Fairness
results were the same in all three runs (quota-drop Jain 0.34; fallback
1.000).

### Threats to validity

* Shared 4-vCPU cloud VM; three runs on two CPU types (above). Trials of different configurations are
  interleaved (trial-major loop) so drift spreads across cells.
* veth is a software device; there is no NIC, DMA or real interrupt
  coalescing. Generic XDP still allocates an skb.
* Workers, aggregator and PS share one host. The workers' CPUs also run the
  aggregator's receive path (see above), so the XDP configurations get no
  extra core while `agg` has its own; that is a property of the topology.
* The load generator is closed loop with a 64-chunk window; at 8 workers the
  PS's CPU is the bottleneck in every configuration, which limits how large a
  difference the aggregator can make.
* Latency comparisons have 5 trials per cell, so the smallest attainable
  p-value is 0.004 before correction.

## Training through NetSum

**Source:** workflow `train-demo.yml`, run 43784240658 (PR head `b6c88a5`),
three-namespace topology, generic XDP; `examples/train_mlp/results/curves.csv`
is that run's artifact. Method: `examples/train_mlp/README.md`.

A 2-24-3 MLP (147 parameters, three chunks per gradient) trained for 200
steps of synchronous data-parallel SGD over 4 workers:

| path | final loss | final accuracy | retransmissions | summed gradient identical to local quantized sum |
|---|---:|---:|---:|---|
| float (local reference) | 0.355124 | 0.9889 | - | - |
| quant (local Q16.16) | 0.355125 | 0.9889 | - | - |
| noagg (through the PS) | 0.355125 | 0.9889 | 0 | every step |
| useragg | 0.355125 | 0.9889 | 0 | every step |
| xdp (generic) | 0.355125 | 0.9889 | 0 | every step |
| xdp with 5% loss on the workers' link | 0.355125 | 0.9889 | 492 | every step |

Integer sums are exact, so all four network paths produced **bit-identical
weights** to the local quantized run, including the lossy one: the
aggregator flushed 90 partials, forwarded 206 contributions to the PS as
fallbacks and re-sent 17 results, and the PS merged everything without a
single double-counted or missing worker. Q16.16 quantization moved the final
loss by 1e-6 against float. (XDP counters for the whole job: 6,382 packets =
4,828 accepted + 90 resend duplicates + 1 late duplicate + 206 fallbacks + 17
result re-sends + 1,240 ACKs.)

## Quantization formats

**Source:** `python3 scripts/quant_study.py --out bench/v2` (deterministic,
seed 1234; plain Python, runs in under a minute anywhere). Data:
`bench/v2/quant_formats.csv`, `bench/v2/quant_training.csv`.

Relative L2 error of the summed vector against the exact float64 sum, with
the fraction of 64-value chunks that overflowed int32 where non-zero, and the
fraction of non-zero inputs Q16.16 rounds to 0:

| data | fan-in | Q16.16 | ATP x1e8 | block exponent | float32 | Q16.16 underflow |
|---|---:|---:|---:|---:|---:|---:|
| gauss_1e-4 | 8 | 4.320e-02 | 2.682e-05 | 5.020e-09 | 5.722e-08 | 6.32% |
| gauss_1e-4 | 256 | 4.406e-02 | 2.745e-05 | 1.647e-07 | 2.992e-07 | 6.05% |
| gauss_1e-2 | 8 | 4.297e-04 | 2.699e-07 | 5.731e-09 | 5.942e-08 | 0.05% |
| gauss_1e-2 | 256 | 4.412e-04 | 2.928e-07 | 2.074e-07 | 2.921e-07 | 0.07% |
| gauss_1 | 8 | 4.663e-06 | 3.143e-09 | 4.734e-09 | 6.437e-08 | 0.00% |
| gauss_1 | 256 | 4.489e-06 | 1.168e+00 (ovf 100%) | 2.218e-07 | 2.858e-07 | 0.00% |
| student_t3 | 8 | 2.534e-04 | 1.659e-07 | 1.369e-08 | 5.886e-08 | 0.06% |
| student_t3 | 256 | 2.665e-04 | 1.762e-07 | 1.652e-06 | 2.818e-07 | 0.05% |
| mlp_step0 | 8 | 5.508e-05 | 3.406e-08 | 2.671e-09 | 4.271e-08 | 0.00% |
| mlp_step0 | 256 | 5.508e-05 | 1.010e+00 (ovf 67%) | 8.425e-08 | 9.707e-07 | 0.00% |
| mlp_step150 | 8 | 4.180e-04 | 2.364e-07 | 6.038e-09 | 4.636e-08 | 0.00% |
| mlp_step150 | 256 | 4.180e-04 | 2.364e-07 | 2.079e-07 | 7.905e-07 | 0.00% |

Training the demo MLP for 200 steps with each format gives the same final
loss to within 1e-6 (0.355124-0.355125, accuracy 0.9889 for all).

* **Q16.16** (NetSum's format) has a fixed resolution of 2^-16 = 1.5e-5. It
  is accurate for gradients around 1e-2 or larger (error ~4e-4) and for this
  small model, but for gradients of order 1e-4, common in deep networks, 6% of
  values round to zero and the sum is 4.4% off. Its range (|sum| < 32,768) is
  never the problem.
* **ATP's scaled int32** (x1e8) is far more precise for small values but its
  range is only |sum| < 21.5: it overflowed every chunk of unit-variance
  gradients and two thirds of the chunks of the MLP's first-step gradients at
  fan-in 256. ATP handles this with an overflow flag and a float fallback.
* **A per-chunk shared exponent** (block floating point) had the smallest
  error of the integer formats in almost every case (the exception is
  heavy-tailed data at fan-in 256, where one outlier forces a coarse scale
  for the whole chunk) and never overflowed,
  because it picks the scale from the data and the fan-in. On the wire it
  needs every worker to use the same exponent for a chunk; this oracle uses
  the current step's data from every worker, which no worker has.

**Recommendation (made before wire v3):** keep Q16.16 for now (it is what the kernel program and
the tests implement, and it is adequate for this demo), but it is the
weakest point for real models with small gradients. The next wire-format step
should be a per-chunk shared exponent carried in the header, with the
exponent agreed one iteration ahead. NetSum already flags overflow, so a
mis-chosen exponent fails loudly rather than silently. The next section
measures that design.

## Per-chunk exponent (wire v3)

**Design:** `docs/DESIGN_NOTES.md` §2. A v3 chunk carries `round(x * 2^e)`;
each chunk's *e* for step *t* is computed by every worker from step *t-1*'s
summed int32 values (`examples/train_mlp/scale_rule.py`), so no extra message
is needed.

**Offline check of the rule** (`python3 scripts/quant_study.py`,
`bench/v2/quant_scaled_training.csv`, deterministic). The demo MLP is trained
for 200 steps with every gradient multiplied by S and the learning rate
divided by S, so float training is unchanged while the values shrink.
`blockexp` is the oracle that sees the current step's data; `v3lagged` is
the rule NetSum ships:

| S | float64 | Q16.16 | oracle (blockexp) | v3 rule (lagged) | Q16.16 underflow | v3 underflow |
|---:|---|---|---|---|---:|---:|
| 1 | 0.3551 / 0.989 | 0.3551 / 0.989 | 0.3551 / 0.989 | 0.3551 / 0.989 | 0.06% | 0.00% |
| 1e-3 | 0.3551 / 0.989 | 0.3460 / 0.989 | 0.3551 / 0.989 | 0.3546 / 0.989 | 50.6% | 0.12% |
| 1e-4 | 0.3551 / 0.989 | 1.0901 / 0.436 | 0.3551 / 0.989 | 0.3560 / 0.989 | 99.9% | 0.45% |
| 1e-5 | 0.3551 / 0.989 | 1.1908 / 0.333 | 0.3551 / 0.989 | 0.3567 / 0.989 | 100% | 0.55% |

(final loss / accuracy; underflow is the fraction of non-zero inputs that
quantize to 0.) No chunk overflowed with either per-chunk format. The lagged
rule keeps float accuracy at every scale; its loss is up to 0.0016 above
float because it leaves 4 bits of headroom and follows the previous step, so
about 0.5% of the smallest values in a chunk still round to 0. At S = 1e-3
Q16.16 happens to end at a lower loss than float, after rounding half the
values to 0; it is not a better format.

**Through the network** (workflow `train-demo.yml`, run 43817130916, PR head
`ec7eeaf`, step "Train with small gradients"; data
`examples/train_mlp/results/curves_scale1e-4.csv`). S = 1e-4, four workers,
200 synchronous steps:

| path | final loss | accuracy | retransmissions | sum equal to the local v3 sum |
|---|---:|---:|---:|---|
| float (local) | 0.355124 | 0.9889 | - | - |
| Q16.16 (local) | 1.090061 | 0.4361 | - | - |
| v3 (local) | 0.356032 | 0.9889 | - | - |
| v3, noagg | 0.356032 | 0.9889 | 0 | every step |
| v3, userspace aggregation | 0.356032 | 0.9889 | 0 | every step |
| v3, XDP (generic) | 0.356032 | 0.9889 | 0 | every step |
| v3, XDP with 5% loss on one worker link | 0.356032 | 0.9889 | 428 | every step |

The kernel counted no `scale_mismatch` and no overflow. In the lossy run it
flushed 75 partials, forwarded 188 contributions as fallbacks and re-sent 30
results, all at the chunk's exponent. The same run's v2 step at S = 1
reproduced the earlier bit-identical result (`curves.csv` is unchanged).

**Cost.** The XDP program's verifier work rose from 335,067 to 422,645
instructions at 64 values per packet (stack 208 to 224 bytes) and from
663,811 to 840,360 at 128 (`bpf-unit.yml` run 43816639927,
`docs/DESIGN_NOTES.md` §6). The benchmarks still send v2 traffic, and the
throughput tables above come from the v2 program; this change's effect on
throughput is not analysed here.

**Recovery after OVERFLOW.** `train.py --spike-step 50 --spike-factor 1000`
multiplies the gradients sent at step 50 by 1,000 and divides the summed
result by 1,000, so training is unchanged while every chunk saturates at its
exponent. Each chunk comes back `OVERFLOW` and is retried in the same step at
`e - 8` under a new key (`docs/DESIGN_NOTES.md` §2). Locally through the
userspace aggregator and PS (200 steps): 3 chunks retried, final 0.3560 /
0.989, bit-identical to local `adapt`; both servers counted 3 overflows and
no `scale_mismatch`. `tests/test_scaled.py` runs a 40-step version.

On the kernel (workflow `train-demo.yml`, run 43825247951, PR head
`15a9bcd`, step "Retry after OVERFLOW"; data
`examples/train_mlp/results/curves_spike.csv`): noagg, userspace, XDP and XDP
with 5% loss on one worker link (520 retransmissions) each retried exactly the
3 chunks that overflowed at step 50 and ended at 0.356033 / 0.9889,
bit-identical to local `adapt` at every step (float: 0.355124 / 0.9889). The
XDP program counted 5 overflowed completions across its two runs (3 without
loss; under loss some overflowed contributions reached the PS as partials or
fallbacks instead) and no `scale_mismatch`. Each worker's v3 values are now bounded by
`INT32_MAX / N`; re-running the local S = 1e-4 paths after that change gives
the same final loss to six digits, so the table above stands.

**Scope.** One small model, synchronous rounds, one exponent per 64-value
chunk. On the kernel, v3 was exercised by the Python client; the C worker's
`--frac-bits` mode is tested only through the userspace aggregator and PS,
and it does not retry. Not shown: gradients that change scale by more than
16x per step other than the forced spike, and any effect on throughput.

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
  path absorbs, not training round time. The v2 benchmark above is the closed-loop,
  three-namespace benchmark with results returned to workers.
* One chunk size (16 values) and single-chunk rounds.

### What would be needed for line-rate claims (applies to both benchmarks)

Two or three physical hosts with XDP-capable NICs (mlx5, i40e, ice), native
driver-mode XDP, RSS steering and pinned cores. Out of scope here.
