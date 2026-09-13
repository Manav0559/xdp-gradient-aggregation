# NetSum: In-Network Gradient Aggregation on Commodity Linux via XDP/eBPF

**A CN + OS + Distributed-Systems Lab Project — Full Specification**

---

## 1. Pitch

Distributed training synchronizes gradients across workers on every step, and that
synchronization traffic — not compute — is the bottleneck once you have more than a
handful of workers. The 2021 NSDI Best Paper **ATP** (*"In-network Aggregation for
Multi-tenant Learning"*, Lao, Le, Mahajan, Chiang, Vahdat, Zhu — NSDI 2021) and its
2024 IEEE/ACM Transactions on Networking follow-up (*"Accelerating Distributed
Training With Collaborative In-Network Aggregation"*) solved this by summing gradient
chunks **inside a programmable switch**, on the wire, before they ever reach a
parameter server — cutting aggregator-side traffic and completion time. The catch:
that result needs a Barefoot/Intel Tofino programmable switch, hardware almost no
student (or most companies) will ever touch.

**NetSum reproduces ATP's actual mechanism — streaming, multi-tenant, fairness-aware
gradient aggregation — on a commodity Linux box using XDP/eBPF instead of a
programmable switch.** No specialized hardware, no P4, no simulator: a real Linux
kernel fast-path program parses gradient-chunk packets, accumulates partial sums
in-kernel, and forwards only the fully-aggregated result on to the parameter server —
architecturally identical to what ATP's switch does, just running on a $0 commodity
NIC instead of a $10,000+ ASIC.

This is simultaneously:
- **A real Computer Networks project** — in-network computing, a specific verified
  NSDI Best Paper as the reproduction target, a rigorous multi-baseline benchmark.
- **A real Operating Systems project** — kernel-space packet processing via eBPF/XDP,
  BPF map design under real concurrency constraints (multi-core RX steering), the BPF
  verifier's restrictions (no floating point, bounded loops, `bpf_spin_lock` for safe
  concurrent state), all in the actual Linux kernel datapath, not a model of it.
- **A real distributed-systems / SDE-systems project** — a wire protocol, fixed-point
  numerical design under real overflow constraints, and a controlled, honest
  benchmark isolating exactly what the kernel fast path buys over the same algorithm
  in userspace — the same "measure it, don't assert it" discipline as your
  itch-lob-engine benchmark harness.

---

## 2. Research Foundation — What This Reproduces, Precisely

### 2.1 The anchor paper

**ATP: In-network Aggregation for Multi-tenant Learning**
ChonLam Lao, Yanfang Le, Kshiteej Mahajan, Yixi Chen, Wenfei Wu, Aditya Akella,
Michael Swift — **NSDI 2021, Best Paper Award**.

Core idea: place a streaming aggregation function on a programmable switch (P4/Tofino)
sitting on the path between workers and a parameter server. As gradient-chunk packets
from different workers for the same (job, round, chunk) arrive at the switch, it
accumulates a running sum in switch memory; once every worker's contribution for that
slot has arrived, the switch emits **one** aggregated packet onward. This cuts
aggregator-uplink traffic by roughly the worker fan-in factor and removes the
aggregation step from the parameter server's CPU entirely.

ATP's headline contribution beyond a bare "sum packets on a switch" idea (already
explored by its predecessor **SwitchML**, NSDI 2021, same venue) is explicitly
**multi-tenant fairness**: the switch's aggregation memory (slot table) is a scarce,
shared resource, and ATP's real contribution is an admission/eviction policy so that
multiple concurrent training jobs sharing one switch get fair, starvation-free access
to aggregation slots instead of one greedy job monopolizing them. This is stated
directly in the paper's own title.

### 2.2 The 2024 follow-up (secondary reference, not the primary target)

**Accelerating Distributed Training With Collaborative In-Network Aggregation**
(IEEE/ACM Transactions on Networking, 2024, DOI 10.1109/TNET.2024.3387948) extends
ATP/SwitchML-style aggregation to **multiple switches** cooperating, and its actual
differentiator is handling **asynchronous, out-of-order gradient arrival across
switches** — a distinct problem from ATP's single-switch fairness question. NetSum
cites this as a real, verified, related extension and an explicit stretch-goal
direction (see §7), not as the source of the fairness mechanism itself — that
correction matters and was caught during adversarial review of this spec.

### 2.3 What NetSum specifically reproduces vs. extends

| ATP (switch/P4) | NetSum (commodity Linux/XDP) |
|---|---|
| Tofino ASIC, P4 program | Ordinary NIC, XDP/eBPF program (`clang` + `libbpf`) |
| Switch memory for slot table | `BPF_MAP_TYPE_HASH` keyed by `(job_id, round, chunk_id)` |
| In-switch admission/eviction policy for fairness | Slot-table admission policy in the XDP program, same fairness goal |
| Measured: completion time, fairness, switch memory use | Measured: completion time, Jain's fairness index, **plus** a from-scratch kernel-vs-userspace comparison ATP's own paper never needed (a switch has no "userspace" alternative to compare against) |

The kernel-vs-userspace comparison is NetSum's own genuine addition beyond
reproduction — it answers a question ATP's hardware context can't: *how much of the
benefit is "in-network aggregation" as an idea, versus specifically "in a
programmable switch's ASIC"?* Commodity XDP lets us isolate that for the first time
in a student-buildable setup.

---

## 3. System Architecture

```
 worker-0 ─┐                                                    ┌─ parameter
 worker-1 ─┤  UDP, fixed-point gradient chunks, one per (job,   │   server
   ...     ┼─ round, chunk_id, worker_id) ──────────────────────►  (userspace,
 worker-N ─┘                                                    │   receives only
                                                                 │   fully-summed
                    ┌────────────────────────────────┐          │   chunks)
                    │        aggregator host          │          │
                    │  ┌────────────────────────────┐│          │
    ingress NIC ────┼─►│ XDP program (kernel space) ││──────────┘
                    │  │  1. parse gradient header   ││   XDP_TX: only the
                    │  │  2. bpf_spin_lock'd partial- ││   FINAL summed packet
                    │  │     sum accumulate in a     ││   is forwarded; partial
                    │  │     BPF_MAP_TYPE_HASH slot  ││   contributions never
                    │  │  3. on last contribution:    ││   leave the kernel
                    │  │     rewrite + XDP_TX onward  ││
                    │  │  4. else: XDP_DROP (fully    ││
                    │  │     absorbed, not forwarded) ││
                    │  └────────────────────────────┘│
                    └────────────────────────────────┘
```

### 3.1 Wire protocol (designed from scratch, documented, versioned)

Fixed-size UDP payload header (no floating point — the BPF verifier forbids it in
kernel space, which forces a real fixed-point design, directly analogous to
itch-lob-engine's integer-tick price ladder):

```c
struct grad_hdr {
    uint32_t job_id;       // tenant / training job identifier
    uint32_t round;        // training step / iteration number
    uint32_t chunk_id;     // which slice of the gradient vector
    uint16_t worker_id;    // 0..N-1
    uint16_t num_workers;  // fan-in expected for this job this round
    uint16_t chunk_len;    // number of fixed-point values that follow
    uint16_t flags;        // reserved
};
// followed by chunk_len x int32_t fixed-point values (Q16.16)
```

Gradients are quantized to **Q16.16 fixed-point** before sending (worker-side, in
userspace — the quantization/dequantization error itself becomes a measured,
reported quantity, not an unstated approximation). Summing Q16.16 values is exact
integer addition; overflow bounds are computed from `num_workers × max_gradient_value`
and checked explicitly, not assumed away.

### 3.2 Correct concurrent accumulation (the flaw this spec fixes)

An earlier draft of this idea proposed `BPF_MAP_TYPE_PERCPU_ARRAY` for the partial-sum
table. That is wrong: multi-queue NICs steer packets from different workers for the
*same* aggregation slot to *different* CPU cores via RSS hashing, so per-CPU slots
never converge into one true sum without an extra cross-core reduction step. NetSum
instead uses a single **`BPF_MAP_TYPE_HASH`** whose value struct embeds a
`struct bpf_spin_lock`, giving correct, race-free accumulation regardless of which
core a given worker's packet lands on — the technically correct general solution, and
a genuine BPF-concurrency lesson (`bpf_spin_lock` is a real, narrow primitive with
real restrictions: no nested locks, held only across a bounded critical section) worth
demonstrating explicitly in the write-up.

### 3.3 Exit path: one clear answer, not two conflated ones

An earlier draft said the aggregated packet exits via *both* `XDP_TX` and "AF_XDP
zero-copy" as if interchangeable. They are not — `XDP_TX` retransmits a packet from
entirely inside the kernel/driver fast path; `AF_XDP` is a *userspace* socket API that
packets are handed to, and its true zero-copy mode additionally requires NIC driver
support NetSum's veth/Docker-netns testbed will not have. **NetSum uses `XDP_TX`
exclusively** for the aggregation-and-forward hot path — this is the honest "stays in
kernel space" design the pitch actually claims. AF_XDP zero-copy is named explicitly
as an out-of-scope stretch goal, gated on access to real NIC hardware (mlx5/i40e-class),
not part of the core deliverable.

---

## 4. Testbed

- **Environment:** a real Linux kernel is mandatory — XDP/eBPF do not exist on
  macOS/Darwin. Use a Linux VM (this project verified a working `multipass`/UTM Ubuntu
  24.04 VM, or an OrbStack/Docker Linux VM with `--privileged` and the host's real
  kernel) with a kernel ≥ 5.15 for stable `bpf_spin_lock` + `BPF_MAP_TYPE_HASH`
  support.
- **Topology:** N worker processes (2–16) in separate network namespaces or
  containers, connected via `veth` pairs to a bridge, feeding one aggregator host
  running the XDP program on its bridge-facing interface, itself connected to a
  parameter-server process.
- **Traffic generation:** synthetic fixed-point gradient chunks generated at a
  configurable rate/size (no real training loop required for the core deliverable —
  named honestly as synthetic, not oversold as "real ML training").

**Implementation status (real-kernel verification):** this project's actual
testbed for verifier/load testing is GitHub Actions' `ubuntu-latest` runners,
not a manually-provisioned VM — a real Linux kernel and real BPF verifier,
scripted and reproducible on every push
([`.github/workflows/xdp-loadtest.yml`](../.github/workflows/xdp-loadtest.yml)),
rather than a one-time manual session. It builds a veth pair across two
network namespaces (the standard kernel-selftests topology), loads
`xdp_agg.o`, and drives it with real UDP gradient traffic including every
adversarial input an earlier code review found bugs in. This found and fixed
one genuine defect `clang -target bpf` codegen could never catch: the
accumulate/write-back loops' bounds proof did not survive the loops' own
back-edge, since they don't fully unroll (already documented above) — fixed
with a redundant per-iteration bounds re-check, the standard idiom for this
situation. See `README.md`'s "Real-kernel verification" section for the full
account, including the exact verifier-rejection message and the real
numbers from the now-green run. Scope note: this uses `xdpgeneric` (SKB)
mode on a software veth, not native driver-mode XDP on physical NIC
hardware — that remains a stretch goal (§7).
- **Baselines** (both required, not optional — this is where the actual research
  comparison lives):
  1. **No aggregation** — every worker sends directly to the parameter server, which
     sums in userspace (the naive parameter-server pattern ATP/SwitchML improve on).
  2. **Userspace aggregation, same algorithm** — an ordinary `AF_INET` socket program
     implementing byte-for-byte the same slot/accumulate/emit logic as the XDP
     program, on the same host. This isolates exactly what moving the identical
     algorithm into the kernel fast path buys — the comparison ATP's switch-only
     context could never make, and NetSum's own real contribution.

---

## 5. Evaluation Plan (what makes this "research," not just "a build")

| Metric | How measured | Why it matters |
|---|---|---|
| End-to-end aggregation-round completion time | Timestamp first-worker-send → parameter-server-receive, vs. worker count (2→16) and chunk size | ATP's own headline metric |
| Aggregator-uplink traffic reduction | Bytes in vs. bytes out at the aggregator, vs. no-aggregation baseline | ATP's own headline metric |
| Per-packet processing latency | XDP path vs. userspace-AF_INET path, same host, same algorithm | NetSum's own addition — isolates the kernel-fast-path effect |
| Multi-tenant fairness | Jain's fairness index across 2–4 concurrent jobs sharing the aggregator's slot table under an admission policy | Reproduces ATP's actual headline contribution |
| Quantization error | Q16.16 round-trip error vs. original float gradients, reported honestly | Nobody in the ATP lineage has to report this (switches don't do ML-side quantization) — NetSum's protocol design makes it a real, measurable cost |
| Correctness under adversarial packet loss/reordering | Drop/reorder a controlled fraction of chunk packets (via `tc netem`) and report how the slot-table times out/handles incomplete aggregation, rather than silently under-counting | The failure mode a rushed implementation would most likely get wrong |

Every number reported must come from a script that actually ran, output committed
alongside the code — the same "every number is produced by a committed target you
can run" discipline as itch-lob-engine's benchmark suite.

**Implementation status (multi-tenant fairness row):** the per-job admission
quota is implemented and regression-tested in the userspace aggregator
(`userspace_agg/agg.c`'s `g_job_quota`/`find_or_create_job` machinery — see
`README.md`), proving the mechanism isolates a greedy job's excess demand from
a second job sharing the slot table. It has not yet been ported into the XDP
kernel program (`xdp_agg/xdp_agg.c`) or measured via a formal Jain's-index
sweep across 2–4 jobs — both remain open follow-ups, not silently claimed done.

**Implementation status (slot TTL / crashed-worker eviction):** the fairness
quota above only bounds a slot table shared by *concurrent* demand from an
abusive job; it does nothing when an *honest* job's worker legitimately
crashes mid-round, leaving its slot incomplete forever. `userspace_agg/agg.c`
now closes this with a configurable `slot_ttl_ms` that periodically reaps any
slot gone silent past its timeout (measured from the slot's last accepted
contribution, not its creation, so genuinely-progressing slots are never
disturbed), regression-tested with a real simulated crashed worker. Not yet
done: the equivalent in the XDP kernel program, which needs `bpf_timer`
(Linux 5.15+) and real-kernel testing this dev environment can't do locally.

---

## 6. Build Plan (Semester Timeline)

| Weeks | Deliverable |
|---|---|
| 1–2 | Wire protocol finalized + implemented; synthetic worker/parameter-server processes in plain UDP (no aggregation yet) — establishes the no-aggregation baseline and the traffic-generation harness |
| 3–4 | Userspace `AF_INET` aggregator (baseline #2) — same slot/accumulate/emit logic, in C, gets the algorithm right before it has to also survive the BPF verifier |
| 5–7 | XDP program: header parsing, `BPF_MAP_TYPE_HASH` + `bpf_spin_lock` accumulation, `XDP_TX` emit path, `XDP_DROP` for absorbed partials — the OS/kernel core of the project |
| 8 | Correctness test suite: unit-test the accumulation logic against hand-crafted packet sequences (out-of-order arrival, duplicate worker send, missing worker) before trusting any performance number |
| 9–10 | Multi-tenant fairness: slot-table admission policy for 2–4 concurrent jobs, Jain's-index measurement harness |
| 11 | Full benchmark sweep: all 3 configurations (no-agg / userspace-agg / XDP-agg) × worker count × chunk size, netem-injected loss/reorder runs |
| 12–13 | Write-up: architecture, corrected-vs-original-draft design decisions (§3.2–3.3 above are genuine engineering judgment calls worth documenting as such), full results with plots, honest discussion of what XDP buys and what it costs (quantization error, verifier constraints) |
| 14 (buffer) | Stretch goals if ahead of schedule (see §7) |

---

## 7. Explicit Stretch Goals (not required for a complete, honest deliverable)

- **Real NIC, driver-mode XDP + true AF_XDP zero-copy** — only meaningful with access
  to mlx5/i40e-class hardware; on the default veth testbed this cannot show a genuine
  effect, so it is out of scope for the core deliverable, not silently attempted.
- **Multi-switch/asynchronous aggregation** — following the 2024 ToN follow-up's
  actual contribution (out-of-order cross-switch arrival), extending NetSum to two
  cooperating aggregator hosts.
- **A real (even if tiny) training loop** — plugging NetSum's transport under an
  actual PyTorch `DistributedDataParallel`-style gradient sync, to replace synthetic
  chunks with genuine training gradients end to end.

---

## 8. Why This Is Not a Generic / Saturated CN Lab Project

- It is explicitly **not** the saturated "P4/Tofino SwitchML clone" pattern (near-zero
  student implementations exist on commodity eBPF/XDP instead of P4/bmv2, per a
  research-and-GitHub landscape scan performed before selecting this project).
- It is explicitly **not** a from-scratch, unfounded algorithm — every mechanism
  traces to a specific, verified, real paper (ATP, NSDI 2021 Best Paper; DOI-verified
  2024 ToN follow-up), with an honest "inspired-by, commodity-hardware adaptation"
  framing rather than an oversold "faithful reproduction" claim the original ASIC
  target makes literally impossible to fully replicate.
- It forces genuine, verifiable systems engineering absent from generic student CN
  projects: BPF-verifier-constrained fixed-point arithmetic, real multi-core
  concurrency correctness (not sidestepped with `PERCPU_ARRAY`), and a controlled
  kernel-vs-userspace comparison of the *same* algorithm — a real research question,
  not a foregone conclusion.

---

## 9. Resume / Interview Story

**For an SDE-systems interview:** "I implemented an ATP-style in-network gradient
aggregator using eBPF/XDP on commodity Linux instead of a Tofino switch — this meant
designing a fixed-point wire protocol (the kernel forbids floats), handling real
multi-core race conditions with `bpf_spin_lock` after finding that a naive per-CPU-map
design silently produced wrong sums, and building a controlled benchmark that
isolates exactly how much the in-kernel fast path buys over the identical algorithm in
userspace."

**For a research-oriented conversation:** "I reproduced ATP's (NSDI 2021 Best Paper)
core multi-tenant fairness mechanism on commodity hardware instead of a programmable
switch, which let me answer a question the original paper's ASIC context couldn't:
how much of the benefit is the in-network-aggregation *idea* versus the switch
*hardware* specifically."

Both stories are true, specific, and neither requires the listener to take a vague
claim on faith — every number in the completed project comes from a script that
actually ran.

---

## 10. Known Risks and Mitigations

| Risk | Mitigation |
|---|---|
| BPF verifier rejects a program shape (bounded-loop violations, map-value size limits) | Budget week 5–7 explicitly for verifier iteration; keep the accumulation logic as simple as possible (single hash lookup + spinlock + add), no unbounded loops over gradient chunks in one program invocation |
| Multi-core RX steering behaves differently across testbed environments (VM vs. bare metal) | The `BPF_MAP_TYPE_HASH` + `bpf_spin_lock` design is correct regardless of core count — this risk is designed around, not hoped away |
| Fairness admission-policy design (§5, week 9–10) is the least specified part of ATP's public description | Start from a simple, defensible policy (round-robin slot eviction under contention) and treat a more sophisticated policy as a documented refinement, not a blocker |
| XDP/eBPF toolchain setup friction (kernel version, `libbpf` version mismatches) | De-risked before week 1 by verifying a working compile-and-load toolchain first (see the accompanying repo's `docs/DEV_ENVIRONMENT.md`) |
