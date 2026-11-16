# NetSum v2 work log

Timestamped, factual record of the v2 upgrade on branch `overnight/netsum-v2`
(base `origin/polish/honest-results`, `f7ea415`). Deviations from the plan and
the reason for each are recorded here at the time they happen.

## 2026-11-16 01:35 IST — Phase 0

- Worktree `../netsum-overnight` on `overnight/netsum-v2`, created from
  `origin/polish/honest-results` (`f7ea415`); `git merge-base --is-ancestor` ok;
  `git status --porcelain` empty.
- Local Linux VM check: OrbStack is running (Docker 29.4.0, kernel
  `7.0.11-orbstack`, aarch64, 8 CPUs) and `docker run --privileged` works, but
  installing clang/libbpf/bpftool into an image fails twice with
  `No space left on device` inside the VM. Per the plan's 5-minute cap the VM was
  not repaired. **All kernel work goes through GitHub Actions.**
- Local baseline (macOS arm64, Apple clang + Homebrew LLVM):
  - `make clean && make`: clean build, no warnings.
  - `python3 tests/test_correctness.py`: 10/10 passed.
  - `make bpf`: compiles; exactly the 2 known `-Wpass-failed=transform-warning`
    loop-unroll warnings (accumulate and write-back loops).
  - `llvm-objdump -h xdp_agg/xdp_agg.o`: sections `xdp` (0xd00 bytes),
    `.maps` (0x80), `license`, `.BTF` (0x1986), `.BTF.ext` (0x9d0), debug sections.
  - `-fstack-usage`: `netsum_xdp_aggregate 352 static`.
- Baseline CI evidence: XDP run `38114728912` on `f7ea415` (green; CI `38114729060`
  and fuzz `38114728871` also green). Artifact `xdp-loadtest-evidence`:
  - verifier: `processed 110791 insns (limit 1000000) ... peak_states 93`,
    `stack depth 352`; `xlated 3568B jited 2138B`; attach mode `xdpgeneric`.
  - final `slot_map` keys (7): (900,0,0), (900,1,0), (950,0,0), (951,0,0),
    (102,0,0), (952,0,0), (101,0,0). (950,0,0) and (951,0,0) are the C1
    zombies; 101/102 are left over from Scenarios B/C; 900×2 and 952 are intended.
- PR #5 opened as draft against `polish/honest-results`. First CI on the
  untouched base: CI, fuzz (x2), XDP load test all green (run 43756011687 for XDP).
- Second look at the local VM: a tiny `alpine:3.20` container with `bpftool`
  (v7.3.0) loads the Mac-compiled `xdp_agg.o` through the real verifier on
  kernel 7.0.11 (aarch64): `processed 111099 insns`, `stack depth 352`. Gives a
  fast local verifier loop; VM disk has ~250 MB free, so containers are
  ephemeral and nothing of the owner's is pruned. CI stays the source of truth.

## 2026-11-16 01:42 IST — Phase 1 (red tests)

- `tests/netsum_packets.py`: one packet builder; `test_correctness.py` now
  imports it instead of defining its own.
- C12: `test_agg_basic_sum`'s `... or True` replaced by a real assertion
  (aggregator completes job 2 exactly once from 6 contributions). Passes.
- C12: `ci/check_drop_stat.py` now asserts an exact count (`== 1` for
  Scenarios E and G) instead of `> 0`.
- `agg` gains `--slot-capacity-log2 N` (debug, before the positional args) so
  the C6 test can force a known collision at capacity 16.
- `tests/test_protocol_v2.py`: 13 tests, all XFAIL on the base for the right
  reason (local run):
  - C1 `late_duplicate_after_completion_leaves_no_slot`: `concurrent_slots: 1, admitted_count: 2`.
  - C1 `late_duplicate_counts_against_quota`: round 1 gets 3x `[admission-reject]`.
  - C2 agg / paramserver: worker_ids 10,11,12 complete a 3-worker round.
  - C3 agg / paramserver: completes `contributions=3` using the fan-in-4 packet.
  - C3 single-claim: fan-in-1 completes, then the fan-in-3 workers leave a zombie (`concurrent_slots: 1`).
    Test asserts the decided semantics (one completion, no zombie), not "can't close".
  - C4 agg / paramserver: `sum[0]=-5536.000000`.
  - C5 truncated / num_workers=0: stale bytes summed; num_workers=0 slot stalls the round.
  - C6: K2=70016 split across two slots after K1=70000 freed (capacity 16).
  - C7: 0 quota rejects after 256 jobs churned the table (want 2).
- Kernel Scenarios K-O added to `xdp-loadtest.yml` after J. Deviation from the
  plan: instead of `continue-on-error`, each step asserts the bug's *symptom*
  while `NETSUM_EXPECT_RED_*` is '1' and the fixed behaviour when '0', so a
  scenario script error or an unexpected fix fails the run. A "Red/green ledger"
  step writes the state to the job summary.
- Fixed the false "Scenarios A-F/H/I complete or reject cleanly" evidence text.
- C6 does not apply to the kernel (BPF HASH maps handle collisions). C7's
  kernel scenario (P) deferred to Phase 3.
- CI on the Phase 1 commit (`3d4c1d0`, XDP run 43756729366, kernel x86 GitHub
  runner) is green and every red scenario reproduced on the real kernel:
  K `[complete] job=960 ... sum=3.0` from worker_ids 10-12; L1 961 sum 4.0
  (includes the fan-in-4 packet); L2 965 left a slot; M (962,0,0) re-created;
  N 963 `sum[0]=-5536.000000`; O 962 still present.

## 2026-11-16 01:54 IST — Phase 2 (protocol v2, userspace fixes)

- Decision: every v2 packet carries the 32-byte contributor bitmap (raw
  contributions set their own bit). Chosen up front instead of trying
  `bpf_xdp_adjust_tail` first: no tailroom dependency in `xdpgeneric`, one
  packet shape for every kind. Deviation from the plan's order, recorded in
  DESIGN_NOTES §Wire format.
- Decision (C7): a job entry lives only while the job has ACCUMULATING slots
  (tombstones are not charged to the quota, so they do not pin it); full job
  table fails closed (`drop_job_table_full`).
- Commit 1 (`201491e`) verified standalone in a scratch worktree: unit test
  passes, 10/10, all 13 bug tests still XFAIL.
- agg.c and paramserver.c rewritten on the shared parser and slot table;
  the worker now sends v2. The per-bug commits the plan lists (C1/C2-3/C4/C5/C7)
  landed as one commit because all of them are the same rewrite of the
  admission path; the test markers record which test covers which bug.
- Result: `make test` -> unit pass, 10/10, 13/13 bug tests pass (no XFAIL).
- Compatibility: the kernel still emits the v1-style aggregate
  (worker 0, fan-in 1); the paramserver parses it as a fan-in-1 raw
  contribution, so Scenarios A-J are unaffected until Phase 3.
- PS/agg now print `[stats-all]` (every `netsum_stats.h` counter) on SIGUSR1
  and at exit; `--quiet` suppresses per-slot lines; PS prints a `[summary]`
  line with first/last completion time on exit (SIGTERM handled).

Next step: push, check CI (K-O must stay expected-red), then Phase 3a
(build hygiene: USE_SYSTEM_LIBBPF, helper-ID check, -mcpu=v3).
- Phase 2 CI (`c6a42bf`): CI (now `make test`: unit + both suites), XDP load
  test green; K-O still expected-red as intended.

## 2026-11-16 02:05 IST — Phase 3 (kernel parity)

- `xdp_agg.c` rewritten on `grad_parse.h`, `netsum_maps.h` (new: one
  definition of every map layout, used by the program, the config loader and
  the harness; `ci/netsum_cfg_loader.c` no longer copies the struct) and
  `netsum_stats.h` (PERCPU_ARRAY `stats` replaces the 4-entry `drop_stats`).
- Steps 3c.1-3c.8 landed together, not one push each: the local verifier loop
  (Alpine + bpftool on the OrbStack 7.0.11 kernel) replaced the per-step CI
  pushes. Verifier on the first attempt: `stack depth 192` (was 352),
  `processed 177407 insns` (was ~111k).
- `tests/bpf/run_xdp_tests.c` (BPF_PROG_TEST_RUN harness): 50 cases incl. a
  corpus replay of 30 seeds + 5000 seeded mutations, 0 kernel/userspace
  verdict mismatches, 46 ms locally. One harness assumption was wrong:
  test-run's ingress device is `lo` (ifindex 1), so egress=1 is "same
  interface" and the program correctly uses XDP_TX; the redirect case now
  uses ifindex 4242 and a separate case covers the XDP_TX branch.
- `ci/check_helper_ids.py`: all 7 vendored helper IDs, 3 map types, 5 XDP
  actions, 3 update flags match Alpine's linux/bpf.h. CI repeats it on the runner.
- `USE_SYSTEM_LIBBPF`: implemented (Makefile on Linux with libbpf headers
  defines `NETSUM_USE_SYSTEM_LIBBPF`; `make bpf-compat` forces the vendored
  build); `bpf-unit.yml` builds both, diffs the disassembly and runs every
  case on both objects.
- Kernel scenarios K-O flipped to green (`NETSUM_EXPECT_RED_*` = '0') with
  exact counter deltas (K rej_worker_id=3, L num_workers_mismatch=3,
  M late_duplicate=1 + tombstone, N overflow=1, O no ACCUMULATING slot).
  Scenario J now asserts `accumulating` (still no kernel TTL until Phase 4).
- C9: config carries the aggregator MAC/IP; the workflow sets them to veth0's.

Next step: push; verify bpf-unit, XDP load test, CI and fuzz green; record
the CI verifier numbers (x86, 6.17); then Phase 3.5 (benchmark-lite).
- Phase 3 CI (`96548ae`): XDP load test run 43758934811 green on
  `7.0.0-1017-azure` x86_64 (runner kernel moved from 6.17 since the base run),
  `xdpgeneric`; verifier `stack depth 200`, `processed 158454 insns`.
  K: rej_worker_id=3, slot_created=0. L: num_workers_mismatch=3, 965 only a
  tombstone. M: (962,0,0) COMPLETED, late_duplicate=1. N: overflow=1,
  `[overflow] job=963` at the PS. O: no ACCUMULATING slot for 100/103-106/950/951/962.
  bpf-unit failed to *build* (glibc `gnu/stubs-32.h` under `-target bpf`);
  fixed with the same `-D__x86_64__` the other workflows pass.
- bpf-unit CI run 43759200542 (x86_64, libbpf 1.3.0): helper-ID check "all
  vendored IDs match"; system-libbpf and vendored builds both 1220
  instructions, **disassembly identical**; 50/50 cases on each object
  (57 ms / 59 ms), corpus replay 30 seeds + 5000 mutations with no mismatch.

## 2026-11-16 02:12 IST — Phase 3.5 (benchmark-lite)

- `bench/lite_sender.c` (paced open-loop sender, sendmmsg batches of 32),
  `scripts/bench_lite.sh` (topology, trials, counters), `scripts/netsum_stats.py`
  (stats moved out of the v1 benchmark; adds Holm and ratio-of-medians CIs),
  `scripts/bench_lite_analyze.py`, workflow `bench-lite.yml` (path-filtered).
- Kernel tombstones are not retired until Phase 4, so each
  trial uses 25,000 rounds (< 65,536 slots) and a freshly loaded program;
  agg and paramserver are restarted per trial.
- Paths: noagg = sender in root ns -> veth -> PS in ns1 (one crossing);
  useragg = sender in ns1 -> veth -> agg in root -> veth -> PS;
  xdp = sender in ns1 -> veth0 XDP hook -> XDP_TX -> PS. Open loop, no result path.
- Local dry run (OrbStack VM, not committed) found two analysis bugs before any
  CI data existed: (1) the accounting identity treated loss as imbalance;
  it now checks that every packet is either received or counted dropped at
  each hop and that every packet the XDP program saw has exactly one outcome
  counter; loss is reported as completion ratio. (2) /proc/pid/stat CPU ticks
  (10 ms) were too coarse; now /proc/pid/schedstat (ns).
- **Pre-registered comparisons (before the CI run):** per worker count
  {2,4,8}, useragg vs xdp with the sender unpaced: F1 goodput (rounds/s),
  F2 completion ratio; permutation test on |Cliff's delta| (2000 iterations,
  seed 1234), ratio of medians with bootstrap 95% CI, Holm within each family.
  Paced cells (100k/200k/400k pps) and per-packet costs are descriptive only;
  open-loop goodput at a paced rate equals the offered rate. 8 trials per cell.
- Phase 4 design decisions, made before coding: (a) close 3.5 first (commit
  the artifact + write-up); (b) FLUSHED is set in the kernel by a second
  program run through BPF_PROG_TEST_RUN by the sweeper (no userspace
  whole-value rewrite), 45-min cap, fallback = guarded BPF_F_LOCK update with
  the race documented; (c) PS re-sends the stored result for any late packet
  on a completed key (lost-result liveness), red test first; (d) REGISTER is
  idempotent and simply re-sent, no new ack kind; (e) ACKs go to the
  aggregator's gradient port 9876 with the ACK flag (one socket in agg, one
  dispatch in XDP): ack_port / NETSUM_ACK_PORT removed.

Next step: when bench-lite run (workflow "Benchmark-lite") finishes, download
artifact bench-lite-<id> into bench/lite/, commit with the run ID, write the
README/RESULTS lite section and DESIGN_NOTES §15; then Phase 4a in userspace.
- bench-lite run 43759600920 (head `29acb78`, merge ref `3b0cc35`), Linux
  `7.0.0-1014-aws`, 4 vCPU Xeon 6975P-C, `xdpgeneric` read back, 8 trials x
  36 cells = 288 trials, ~7 min. Accounting balanced 288/288.
  F1 (unpaced goodput xdp/useragg): 1.464 [1.362, 1.512], 1.232 [1.133, 1.384],
  1.536 [1.467, 1.575] at 2/4/8 workers, p_Holm 0.0015 each, delta 1.0.
  F2 (unpaced completion): useragg 0.8523 vs xdp 1.0 at 2 workers (p_Holm 0.006);
  equal (1.0) at 4 and 8. XDP 145-254 ns/run; agg 1.5-2.5 us on-CPU/packet.
  Every paced cell completed 100% on all paths.
  Caveat written into RESULTS.md: unpaced goodput ~= sender pps / workers on
  every path, so F1 shows the sender pushes more through XDP (likely: veth
  receive work runs on the sending CPU and XDP_DROP ends it before the UDP
  layer; /proc/softirqs not captured, so marked unverified).
- Workflow bug: the analysis step ran as the runner user on a root-owned
  output dir and `| tee` hid the failure, so the artifact has only raw.csv and
  environment.json. The committed tables are the committed analyzer run on
  the committed raw.csv. Fix in Phase 6's bench workflow (pipefail, chown).

## 2026-11-16 02:27 IST — Phase 4a + 4d in userspace

- `tests/test_reliability.py`: 7 tests written first, all XFAIL on the
  previous commit (no results, no `--ack-to`, no RESEND handling, no reliable mode).
- New bug **C13** (found while planning, not in the original audit): a worker
  whose result is lost could never finish, because the PS ignored late
  packets for keys it had completed. Fixed: the PS re-sends the stored result
  on any RESEND / fallback / partial / aggregate for a completed key.
- Parser: ACK may carry OVERFLOW (an overflowed round still needs a result so
  workers stop retrying). Fuzzer reference, corpus (`v2_ack_overflow.bin`) and
  unit test updated in the same commit; 15 s local fuzz clean.
- PS: REGISTER/direct-sender address book, results to workers and `--ack-to`.
  agg: ACK retirement, RESEND table (re-send aggregate / flush PARTIAL ->
  FLUSHED / forward FALLBACK). worker: `--mode reliable` (window, RTO with
  backoff, RESEND, REGISTER on every retransmit, `--sync`, drop injection,
  JSON summary with round-time percentiles).
- Reliable useragg run with drops (3 workers, 8 x 1024 values, drop every 5th
  tx and 7th result): 128/128 results per worker, 0 mismatches; agg 149 slots
  created / 149 retired by ACK, 16 partial flushes, 42 fallbacks; PS 21 result
  re-sends.
- One test bug fixed on the way (C13 test never drained the PS log before
  counting `[complete]` lines).

Next step: port ACK / RESEND / FLUSHED rows to xdp_agg.c with bpf-unit cases
(local Alpine loop), remove ack_port; then the 4b sweeper (kernel-side flush
program run via BPF_PROG_TEST_RUN); then 4c.

## 2026-11-16 02:38 IST — Phase 4 kernel port, 4b sweeper, Phase 5 netsum-ctl

- xdp_agg.c: ACK handling (retire COMPLETED/FLUSHED, discard stale
  ACCUMULATING and release its quota), RESEND table (re-send stored
  aggregate / flush PARTIAL -> FLUSHED / FALLBACK after a flush), one shared
  rewrite-and-forward tail. `ack_port` and NETSUM_ACK_PORT removed.
- 4b Design A, with one change: the sweeper does not write slots from
  userspace. A second program in the object, `netsum_sweep`, is run by
  `netsum-ctl sweep` through BPF_PROG_TEST_RUN once per key: under the slot
  lock it flushes an expired ACCUMULATING slot into a PARTIAL (the frame comes
  back as XDP_TX and the tool sends it to the PS) and marks it FLUSHED, or
  deletes an expired COMPLETED/FLUSHED slot. Quota release happens in-kernel.
  Remaining race: none on slot contents; a contribution that arrives between
  the sweeper's key snapshot and its step is simply part of the flushed sum
  or arrives after FLUSHED and is forwarded as FALLBACK.
- bpf-unit: 62 cases locally (Alpine, 7.0.11), including ACK in every state,
  RESEND rows, FLUSHED fallback and the sweep program. One old case ("resent
  duplicate is counted separately") was removed: under the RESEND table that
  input now flushes, which the new flush case covers.
- Phase 5 (pulled forward because the sweeper needs it): `ctl/netsum_ctl.c`
  with attach/detach (libbpf load + pin of both programs and all maps,
  `bpf_xdp_attach`, mode read back with `bpf_xdp_query`), config, stats (incl.
  run_cnt/run_time_ns from bpf_obj_get_info), slots (BPF_F_LOCK snapshot),
  jobs, sweep. No skeleton: bpf_object__open_file + pinning keeps it one file.
  `ci/test_netsum_ctl.sh` smoke test passes locally (attach generic, config,
  zero stats, stuck 2/3 round, sweep flushes one PARTIAL to a listener with
  sum 2.0 and bitmap {0,1}, second sweep retires, detach + unpin).
- `ci/netsum_cfg_loader.c` deleted; `grep "struct netsum_config {"` finds 1.
- xdp-loadtest.yml rewritten on netsum-ctl with new scenarios Q (ACK
  retirement), J2 (sweeper flush + retransmission -> FALLBACK -> completion),
  H2/I2 (reliable workers under 20% loss / delay+reorder), M and O now
  "absent after ACK or sweeper" (ACK retirement means a plain duplicate after
  the ACK reopens a slot; the sweeper reclaims it - same as ATP's switch).
  H and I kept as H-legacy / I-legacy. accept_local relaxation removed (the
  aggregate's source is now the aggregator, C9).
- bench_lite.sh / bench-lite.yml moved to netsum-ctl; the analysis step now
  chowns the output and uses pipefail (fixes the missing-summary bug).

Next step: push, debug CI until xdp-loadtest/bpf-unit/bench-lite are green;
record J2 timeline and H2 resend counts; then 4c (array mode + fallback).
- CI run 43761989748 (`72770cb`): bpf-unit 62/62 on both builds (disassembly
  identical, 1962 instructions for both programs); xdp-loadtest passed the
  netsum-ctl smoke test and Scenarios A-I including Q, then **J2 failed**:
  worker 0 gave up after 10 retries. PS log: `[partial] job=952 have=2/3`
  followed by 14 `[overlap]` rejections. Cause (new bug **C14**): the sweeper
  retired the FLUSHED slot, the workers' retransmissions re-created and
  completed it as {0,1,2}, and the PS rejected that aggregate because it
  overlapped the partial {0,1} it held; the aggregator re-sent it on every
  RESEND and the round never completed.
- Fix: PS merge by contributor sets (subset dropped, superset replaces,
  other overlap rejected). `tests/test_fallback.py` (7 tests); the superset
  and subset tests fail against the previous paramserver (checked by building
  `HEAD:paramserver/paramserver.c`) and pass now.
- CI run 43762407606 (`9b86b9c`, with the C14 fix): J2 now recovers: all 3
  workers got the correct result (1.5) in 1.50 s; PS `[partial] have=2/3`,
  then completion via the superset rule (the 300 ms TTL had also retired the
  FLUSHED slot, so the retransmissions re-created and completed it as {0,1,2}).
  Only the assertion `tx_fallback >= 1` failed, because that path did not run.
  J2 now uses TTL 1 s (flush at ~1.1 s, retransmit at 1.5 s, slot still
  FLUSHED) so the FALLBACK path is the one exercised; the superset path is
  covered by tests/test_fallback.py and was observed here on the real kernel.
- 4c kernel: array mode (`agg_array`, tag-checked, claim under the lock),
  collision -> FALLBACK + `fallback_keys` (LRU), quota policy `fallback` in
  hash mode, mode-aware ACK and sweep. First verifier attempt rejected
  (`R2 !read_ok`): a `goto` jumped over initialisers the forwarding tail
  reads; hoisting them fixed it. bpf-unit 69/69 locally (array cases use a
  16-entry pool via bpf_map__set_max_entries). netsum-ctl: --slots-log2,
  --slot-mode, array-aware slots and sweep. New CI scenarios G2 (fallback
  policy) and P (array mode, reliable workers).
- Deferred: array mode in the userspace agg (the benchmark compares hash mode
  in both paths; XDP array mode is an extra configuration).
- Correction: the section times above were first written from estimates and
  were wrong (up to four hours late); they now match the commit times
  (`git log --date=format:%H:%M`). Times from here on come from `date`.

## 2026-11-16 03:07 IST — Phase 6 (v2 benchmark), pre-registration

- New: scripts/topo.sh (three namespaces, routed through the root ns, no
  rp_filter/accept_local relaxation; GRO on the PS-side veth so native-mode
  redirect delivers), scripts/bench_v2.sh, scripts/bench_analyze.py,
  workflow bench.yml (path-filtered; results directory excluded).
- Load generator: the reliable worker itself (one process per logical worker,
  closed loop, results returned in every configuration). A first attempt at
  a --duration-ms mode was removed: workers of one synchronous job stopped at
  different rounds and the last round could never complete. Trials are fixed
  work (rounds x 1024 values) instead; fairness uses absolute round end times.
- Local checks (OrbStack 7.0.11, not committed): generic and native XDP both
  attach on veth and redirect into veth_p0 works in both modes with GRO on
  veth_p1; a scaled-down run of the whole matrix finished with XDP accounting
  balanced in 36/36 trials. Found and fixed on the way: `netsum-ctl detach`
  sent no mode flag, so the kernel detached "native" and left a generic
  program attached (next native attach: "File exists"); it now queries the
  attach mode and detaches that.
- v1 benchmark moved to scripts/legacy/ and bench/v1-macos-loopback/ (the
  dashboard's data paths updated so the live page keeps working).
- **Pre-registered comparisons (written before the CI run):**
  - Family T (throughput, window 64): per worker count {2,4,8}, xdp-generic vs
    useragg and xdp-native vs useragg on aggregated values delivered per
    second per job; 8 trials per cell; permutation test on |Cliff's delta|
    (2000 iterations, seed 1234), ratio of medians with bootstrap 95% CI,
    Holm over the family.
  - Family L (latency, synchronous rounds): same pairs, per-trial median round
    completion time at the worker; 5 trials per cell; same tests, Holm over
    the family. Pooled p50/p95/p99 (p99 only with >= 1000 samples) with
    bootstrap CIs resampling trials.
  - Descriptive only: noagg, xdp-array, per-packet costs (XDP ns/run, agg
    algorithm ns/pkt, on-CPU ns), NET_RX softirqs per CPU, fairness (Jain's
    index over raw goodput and goodput / demand, retransmissions, in-network
    fraction) under none / quota-drop / quota-fallback / array with 64 slots.
- xdp-loadtest run 43762839174 (`62db400`) **green**, all scenarios: J2
  took the FLUSHED -> FALLBACK path (tx_fallback 3, all 3 workers correct,
  slot absent); H2 (20% loss) 102 retransmissions, 64/64 correct results per
  worker; I2 (delay+reorder) all correct; G2 fallback_quota=1, tx_fallback=2,
  drop_quota=0; P (array mode) 32 rounds via reliable workers; O slot_map
  empty and no charged quota after the sweeper.
- CI on `7471b21`: bench v2 failed at its first trial (noagg, a worker gave
  up after 10 retries) and xdp-loadtest failed before any scenario (no
  bpftool package for that runner's kernel). Causes: (1) the GitHub runner
  has Docker's iptables `FORWARD DROP` policy, so traffic routed between the
  namespaces through the root ns was dropped (my local Alpine VM has no such
  policy); topo.sh now inserts ACCEPT rules for exactly the two links. (2)
  bpftool is no longer used anywhere: `netsum-ctl verify` loads the object
  through libbpf with BPF_LOG_STATS and prints insns/stack per program.
- 7b measured (local 7.0.11, `netsum-ctl verify`): max values/packet 64 ->
  aggregator 332,972 insns processed, stack 200; 128 -> 671,690; 256 ->
  rejected (verifier limit 1,000,000). Array mode roughly doubled the
  aggregator's verifier work (hash and array paths explored separately).
  Decision: keep 64 as the default; NETSUM_MAX_CHUNK_LEN is a build-time
  option, and bpf-unit records the table on the CI kernel. At 256 LLVM also
  turned the array-claim zeroing loop into memset(), which BPF cannot call;
  an empty asm barrier in the loop prevents it.

## 2026-11-16 06:35 IST — Phase 6 results (work resumed after a pause)

- CI on `dc85e1a`: all workflows green, including bench v2 run 43765091283
  (Linux 7.0.0-1016-aws, 4 vCPU Xeon 6975P-C, native attach accepted on veth,
  pinned CPUs). 117 trials, XDP accounting balanced 117/117, every result exact.
- Pre-registered family T (throughput): xdp-generic / useragg = 1.020,
  1.081, 1.109 at 2/4/8 workers (p_Holm 0.003 each); xdp-native / useragg =
  0.949 (p_Holm 0.003, slower), 1.006 (n.s.), 1.024 (p_Holm 0.003).
  Family L (median round time): xdp-generic 0.919 / 0.950 / 0.929 (p_Holm
  0.0325 / 0.0325 / 0.030); xdp-native 1.032 (n.s.), 1.134, 1.055 (slower).
- NET_RX softirqs per CPU identical for noagg / generic / native: the veth
  receive path (and the XDP program) runs on the workers' CPUs. Confirms the
  benchmark-lite hypothesis.
- Fairness: quota-drop starves the greedy jobs (13 vs 5,039 rounds/s, Jain
  0.34); quota-fallback 1.000 (demand-normalised); array-small 49% in-network
  with no goodput loss.
- Committed bench/v2/* (summaries regenerated locally with the committed
  analyzer from the artifact's CSVs; identical to the CI summary). The 16 MB
  latency_rounds.csv stays in the artifact.

Next step: Phase 7 training demo in CI (train-demo workflow), Phase 8
quantization study, Phase 9 docs and dashboard.

## 2026-11-16 06:55 IST — Phases 7 and 8

- 7a: multi-chunk vectors are in the reliable worker (`--vector-len`, short
  last chunk) and the Python client. Deviation: no `[round-complete]` line at
  the PS, which does not know how many chunks a round has; round completion
  is measured at the worker (`round_us_*`, `--emit-rounds`), which is the
  end-to-end number anyway.
- 7b: NETSUM_MAX_CHUNK_LEN stays 64 (verifier table above: 128 verifies at
  ~672k insns, 256 exceeds the 1M limit). Neither bpf_loop nor sub-blocks
  were tried; recorded as future work.
- 7c: examples/train_mlp (plain Python; NumPy is not installed on the Mac
  and not needed). train-demo run 43784240658: float / quant / noagg /
  useragg / xdp / xdp with 5% loss all end at loss 0.355125 (float
  0.355124), accuracy 0.9889; every network path bit-identical to the local
  quantized sum at every step; the lossy XDP run needed 492 retransmissions,
  90 partial flushes and 206 fallbacks and still matched exactly.
  tests/test_python_client.py: Python packer == C header bytes (3/3).
- 8: scripts/quant_study.py (15 s, deterministic). Q16.16 underflows 6% of
  N(0, 1e-4) values (4.4% sum error); ATP x1e8 overflows at fan-in 256 for
  unit-variance and early MLP gradients; per-chunk exponent best overall.
  Recommendation (README/RESULTS): next wire-format step is a shared
  per-chunk exponent agreed one iteration ahead.
- netsum_to_fixed now rounds half away from zero, saturates, maps NaN to 0
  (was truncation and UB out of range); unit tests for +-0.5 ULP, limits,
  +-inf, NaN; the Python quantizer matches it exactly.

Next step: Phase 9 (DESIGN_NOTES reorder and completion, HISTORY.md, README
rewrite, spec D3/D4/D5, dashboard v2, consistency greps), then final checks.

## 2026-11-16 07:20 IST — Phase 9 (documentation)

- Verified against primary sources before writing: ATP paper text (authors,
  NSDI 2021, §3.5 switch logic incl. hash-indexed aggregators, collision ->
  forward to PS, parameter packets deallocate; §3.6 end hosts; §3.7 resend
  flush and timestamp reclamation; §3.8 x1e8 scaling); "Awarded Best Paper!"
  on the USENIX presentation page; SwitchML authors from its PDF; the 2024 ToN
  paper's authors, volume, issue, pages and date from Crossref (DOI
  10.1109/TNET.2024.3387948). DBLP was behind a bot check. The GOAT PDF URL now
  returns HTML, so the system name "GOAT" could not be re-verified and is not
  used; the paper is cited by title, authors and venue.
- README rewritten (pitch with scope, architecture, quick start incl.
  scripts/demo_local.sh, component table, v2 results with CIs, correctness
  evidence, ATP relation: reproduced / adapted / not reproduced, layout,
  history, citations). docs/HISTORY.md with the four stories.
- DESIGN_NOTES reordered 1-16 with Topology, full Testing strategy, v2
  method, CI verifier tables (x86 run 43784550947: 335,067 / 663,811 /
  rejected at 64/128/256 values), kernel reclamation, open limitations.
- Spec: status box; D3 author list fixed; D4 mechanism rewritten in §1, §2.1,
  §2.3, §5 table, §9; D5 full citation. Same corrections in
  PROJECT_SPEC.html; NetSum_Project_Spec.pdf regenerated from it with headless
  Chrome (the original was printed the same way: Producer Skia/PDF).
- Comment migration: xdp_agg.c 344 -> 57 comment lines (601 -> 669 total; it
  now holds two programs and array mode, so the 300-400 target was not met),
  agg.c 237 -> 39, bpf_compat.h 61 -> 25, grad_proto.h header and helper
  comments shortened, worker/fuzz/test/ci docstrings trimmed.
- Dashboard: v2 panels (throughput with CI whiskers + comparison table, p50
  and p99, ns per packet, fairness + Jain, training curves, environment and
  caveats) from the committed CSVs; same hand-drawn SVG approach and theme;
  checked by rendering with headless Chrome (6 charts, 4 stat tiles, no
  error states). One fix found that way: the CSS uppercases chart titles, so
  "p50 (µs)" read as "P50 (MS)".
- Consistency greps: no stale "not benchmarked" text, no "headline
  contribution" misattribution outside history, no Chiang/Vahdat (md, html,
  pdf), attribution grep over the whole diff clean. pages.yml left untouched
  (one stale path in a comment) per the rule on Pages.

Next step: push, confirm every workflow green, final self-check, morning
report in the PR body and here, then the verdict page.

## 2026-11-16 07:45 IST — replication and final fixes

- Bench v2 re-ran on `b6c88a5` (run 43784240541, Xeon Platinum 8573C,
  7.0.0-1019-azure) and `94155a8` (run 43785552861, Xeon 6975P-C,
  7.0.0-1016-aws); measured code identical. Same runner type: generic/userspace
  1.020 / 1.078 / 1.102 (primary 1.020 / 1.081 / 1.109). Different CPU:
  1.685 / 1.420 / 1.369 throughput, 0.705 / 0.663 / 0.787 round time; native
  faster than userspace there but still behind generic. All comparisons of
  generic vs userspace significant in all runs; fairness identical. README,
  RESULTS and dashboard now say the direction is stable and the size depends
  on the machine. Data committed under bench/v2/replication-*/.
- DESIGN_NOTES §8 now has the full state x event table (all four states incl.
  FLUSHED; raw, same worker, RESEND, mismatch, ACK, TTL, array collision);
  leftover "Phase N" notes removed. README test time measured (30 s, 5 Python
  suites). Pages deploys the whole repo (`path: .`), so the dashboard's
  training panel works on the live site. No stray helper scripts tracked; the
  regenerated PDF holds no local path.
- Mistake found in the final CI check: the comment edit to fuzz.yml in
  `507ebcc` replaced the header comment "up to the next blank line", and there
  was none before `on:`, so the trigger block was deleted. GitHub then
  rejected the file ("workflow file issue") and the fuzzer did not run for
  `94155a8` and `d6af32b`. The local YAML parse accepted it (a file without
  `on:` is valid YAML). Fixed by restoring the triggers; the fuzz run on the
  fix is recorded below.

## 2026-11-16 07:17 IST — Final self-check and morning report

```
$ git status --porcelain
 M docs/OVERNIGHT_LOG.md
(empty before this log entry)
$ (attribution grep from the plan, run over git diff origin/polish/honest-results...HEAD)
attribution: clean
$ grep -rn "struct netsum_config {" --include=*.c --include=*.h . | wc -l
1
$ make clean && make && make unit && make test && make bpf
build warnings: 0; unit: 1 pass; bpf warnings: 0
test_slot_table: all checks passed
10/10 passed
13 tests, 0 unexpected
7 tests, 0 unexpected
7 tests, 0 failed
python client packer vs C header: 3/3 identical
$ gh pr view 5 --json isDraft,baseRefName,headRefName
isDraft=true base=polish/honest-results head=overnight/netsum-v2
checks on deb3d6b: all success (see PR body for run IDs)
```

### Overnight summary

**State:** Phases 0-9 complete, CI green on every workflow. Two items are scoped down: chunk size stays at 64 values, and the userspace aggregator has no array mode. Both are listed below.

**Merge order for the owner:** merge #3 → merge #4 → retarget this PR to `main` → review → merge. The Pages dashboard keeps showing v1 until then (Pages deploys `main`).

### What changed
- **Phase 0-1:** work log, design notes, then red tests for every confirmed bug (13 userspace tests and kernel Scenarios K-O, each asserting the bug's symptom). `3d4c1d0`
- **Phase 2:** protocol v2 with a contributor-bitmap trailer on every packet, one shared parser, a shared slot table with backward-shift deletion, and the userspace fixes for C1-C7. `201491e`, `c6a42bf`
- **Phase 3:** the XDP program reaches parity (tombstones, admission, overflow, atomic quota, source rewrite, per-CPU stats). Added a `BPF_PROG_TEST_RUN` harness, now 69 cases on two builds with identical disassembly. `96548ae`
- **Phase 3.5:** benchmark-lite, the first XDP numbers. `3d8311b`
- **Phase 4:** ACK/result path, reliable windowed worker, RESEND flush, FLUSHED→FALLBACK, a TTL sweeper run in-kernel through test-run, array-mode aggregators with collision fallback, and PS merge-by-set (C13, C14 found and fixed). `67c6411`, `72770cb`, `9b86b9c`, `62db400`
- **Phase 5:** `netsum-ctl` (attach with the actual mode read back, config, stats, slots, jobs, sweep, verify). CI moved to it; `netsum_cfg_loader.c` and `bpftool` are no longer used.
- **Phase 6:** closed-loop benchmark on three namespaces with a fairness sweep. `7471b21`, `5031160`, `d6af32b`
- **Phase 7-8:** training demo through every path, quantization study, exact Q16.16 rounding. `b6c88a5`, `38ec27d`
- **Phase 9:** README, dashboard, design notes and history rewritten; spec corrected; comments migrated. `507ebcc`, `94155a8`

### Bugs fixed (red → green)
| ID | What it was | Evidence it's fixed |
|----|-------------|---------------------|
| C1 | a late duplicate re-created a slot that never completes | test_c1_* pass; Scenarios M and O leave `slot_map` empty |
| C2 | worker_id was not checked against the fan-in | test_c2_*; Scenario K `rej_worker_id=3` |
| C3 | the fan-in was never cross-checked | test_c3_*; Scenario L `num_workers_mismatch` |
| C4 | silent int32 wrap of the sum | test_c4_*; Scenario N `[overflow]`, `overflow=1` |
| C5 | the PS lacked the length and fan-in checks | test_c5_* |
| C6 | a slot free broke probe chains | test_c6; randomized slot-table unit test |
| C7 | the quota failed open after 256 jobs | test_c7; bpf-unit "full job table fails closed" |
| C8 | kernel quota race and underflow | reserve-before-create plus saturating CAS (by design; single-CPU CI can't race it) |
| C9 | the aggregate kept the worker's source MAC/IP | bpf-unit frame checks; three-namespace redirect works |
| C10 | the benchmark measured process start-up | replaced by the v2 closed-loop benchmark |
| C11 | the fuzzer tested copies of the checks | fuzzes `grad_parse.h`; corpus replayed through the loaded program |
| C12 | `or True` test; ">0" checks | exact assertions throughout |
| C13 | a lost result could never be recovered | test_c13; the PS re-sends results |
| C14 | partial plus retransmitted aggregate livelocked | found by J2 on the CI kernel; test_fallback.py |

### Measured results (CI runs 43765091283 / 43785552861 / 43784240541; Linux 7.0; 4 vCPU; XDP generic and native)
- XDP generic vs userspace aggregator, throughput at 2/4/8 workers: **1.020 / 1.081 / 1.109** on a Xeon 6975P-C runner (reproduced at 1.020 / 1.078 / 1.102), and **1.685 / 1.420 / 1.369** on a Xeon Platinum 8573C runner. Median round time 5-8% lower (21-34% on the second CPU). All Holm-corrected, p_Holm ≤ 0.033.
- **Negative result:** native XDP on veth is slower than generic in every run; veth's native path adds a ring + NAPI hop.
- The XDP program costs 191-316 ns per packet; the userspace aggregator spends 2.0-2.3 µs of CPU per packet. XDP accounting balanced in 351/351 trials.
- Fairness: a drop quota starves greedy jobs (Jain 0.34); fallback to the PS stays demand-proportional (1.000).
- Training through noagg, userspace and XDP (also with 5% loss) is bit-identical to the local quantized all-reduce.

### Not done / open
- Userspace aggregator has hash mode only (no array mode).
- Max chunk stays 64 values. 128 verifies (664k insns); 256 exceeds the verifier limit. `bpf_loop` or sub-blocks are untried.
- No `BPF_PROG_TEST_RUN` micro-benchmark of individual paths; cost comes from `bpf_stats` only.
- The benchmark reports accounting but does not fail the run on an imbalance (none occurred).
- Correctness scenarios still run on the two-namespace topology; only the benchmark uses three.
- Lost results are injected only in userspace tests, not on the kernel path (netem loses gradients and ACKs there).
- The 2024 ToN paper is cited without the system name "GOAT", which I could not re-verify.
- Not built: ECN congestion control, rack hierarchy, float re-request on overflow, shared-exponent wire format.

### Things the owner should know
- Default behaviour changes: workers send v2 packets, and the PS sends results/ACKs (`--ack-to`). Quota policy defaults to none; `fallback` and `drop` are opt-in through `netsum-ctl config`. ACKs go to port 9876 with the ACK flag.
- The README now says plainly that the XDP advantage is 2-11% on one runner type and 37-69% on another.
- The spec PDF was regenerated (headless Chrome) after fixing the ATP author list and the fairness attribution.
- `docs/OVERNIGHT_LOG.md` has every step, including the mistakes and their fixes.

### How to reproduce
- macOS: `make && make test && scripts/demo_local.sh`
- Linux: `sudo scripts/topo.sh up && make bpf all ctl && sudo ./bin/netsum-ctl attach --ifname veth_w0 --ifname veth_p0 --mode auto && …` (README Quick start)
- CI: workflows on this PR. Artifacts: `xdp-loadtest-evidence`, `netsum-bench-<id>`, `train-demo-<id>`.


## 2026-11-16 11:47 IST — Next step: per-chunk shared exponent (wire v3)

Branch `feature/shared-exponent` from `main` (`795339b`), worktree
`../netsum-scaled`. Chosen because docs/RESULTS.md names it as the top next
step: Q16.16 rounds gradients below ~1e-5 to zero.

- Design (docs follow with the code): v3 packets carry e (0-63) in flags bits
  6-11 and values as round(x * 2^e). Every path sums only equal e, keeps e on
  what it emits, and propagates a worker's own saturation (OVERFLOW on a raw
  v3 contribution). Workers agree on e with no extra message: each round's
  summed result is identical at every worker, and an integer-only rule
  (examples/train_mlp/scale_rule.py) maps the previous int32 sum and e to the
  next e: put the previous max near 2^26 (4 bits of headroom), +8 after an
  all-zero sum, -8 after an overflow. Adaptive mode needs synchronous rounds.
- Offline check of that exact rule before any protocol code (200 steps of the
  demo MLP, gradients scaled by s and the learning rate by 1/s, so float
  training is unchanged): s = 1e-4: Q16.16 underflows 99.9% of values and
  ends at accuracy 0.4361 / loss 1.090; the lagged rule ends at 0.9889 /
  0.3560 (float 0.9889 / 0.3551), zero overflowing chunks. s = 1e-5: Q16.16
  does not train (0.3333); the rule 0.9889 / 0.3567.
- Plan: (1) format + scale consistency at a fixed e on every path,
  (2) adaptive client + demo, (3) retry under a distinct key after OVERFLOW.
  Benchmarks stay on v2 so committed results remain comparable.
- tests/test_scaled.py: 5 tests, XFAIL(S1) on main for the right reason (v3 is
  an unknown version today).

Next step: stage 1 in protocol/grad_parse.h, agg, paramserver, xdp_agg (with
bpf-unit cases), worker --frac-bits.

## 2026-11-16 12:03 IST — Wire v3 implemented (stages 1 and 2)

- `f48b926` v3 on every path (parser, PS, userspace aggregator, XDP state
  machine, forward tail, sweeper); slot records version and exponent in the
  former padding; `scale_mismatch` counter; v3 raw OVERFLOW. Version 3 is
  no longer the unknown-version example (now 4) in the unit test, bpf-unit,
  `bad_version.bin` and the fuzz reference; corpus regenerated (36 seeds).
  Mistake: I put the new BPF cases above the `sweep()` they call; CI
  failed to compile the harness; fixed in `6612ef9`. Also a test of mine
  captured a loop variable late (all packets from worker 2); fixed before
  commit.
- `8212e91` reliable C worker `--frac-bits`. bpf-unit run 43816639927:
  77 cases pass on both builds. Verifier at 64 values 422,645 insns / stack
  224 (was 335,067 / 208); 128 values 840,360 (was 663,811); 256 rejected.
- `ec7eeaf` Python client v3 + train.py `adapt` path, `--net-format v3`,
  `--grad-scale`. train-demo run 43817130916: at S = 1e-4 every v3 path
  (noagg, useragg, XDP, XDP + 5% loss with 428 retransmissions) is
  bit-identical to local adapt (0.356032 / 0.9889); Q16.16 1.090061 /
  0.4361; float 0.355124 / 0.9889. The v2 step at S = 1 is unchanged.
- `scripts/quant_study.py` now has the shipping lagged rule next to the
  oracle (`bench/v2/quant_scaled_training.csv`); it reproduces the earlier
  scratch simulation digit for digit, so every number quoted in the 11:47
  entry now has a committed source. Existing quant CSVs byte-identical.
- Docs: DESIGN_NOTES §1-§3, §6, §16; RESULTS new section; README. Removed
  the RESULTS parenthetical describing how SwitchML picks its exponent: I
  could not verify it, so the text now describes only NetSum's own rule.

Next step: commit docs, wait for bench/bench-lite on the PR (they run the
new program with v2 traffic), then stage 3 (retry under a new key after
OVERFLOW) only if time allows; otherwise record it as open.

## 2026-11-16 12:18 IST — Regression found in review: v1-opened slots

Review of the branch found that the XDP forward tail emitted at the slot's
stored version without clamping it, so a slot opened by a legacy v1 packet
(version 0) and completed or flushed by a v2 packet produced a 0xFFFF
aggregate with flags 0, which the PS rejects. main hard-coded v2 there; the
sweeper, agg and PS on this branch already clamped. No case covered mixed
v1/v2 slots. Red first: `9b4d5e8` added two BPF cases; bpf-unit run
43819068199 failed them on the kernel (flags 0x0000, 3 failures of 79).
Fix: clamp in the forward tail as everywhere else. Also reworded the
exponent-rule remark in DESIGN_NOTES (the rule exists only in Python),
corrected the quant study's runtime, and stated that the C worker's v3
mode is not exercised on the kernel.

Next step: CI green on the fix; then stop. Stage 3 (retry after OVERFLOW)
stays open.

CI on `b35240e`: all eight workflows green; bpf-unit 79 cases, 0 failures;
verifier at 64 values 425,243 insns (stack 224) with the fix, up from
422,645 at `8212e91`.

## 2026-11-16 (afternoon; time per commit) — Stage 3: in-step retry after OVERFLOW

On the user's "continue on xdp project".

- Order-independence first: with N workers each v3 value is now bounded by
  INT32_MAX // N (`scale_rule.worker_limit`), so no order of adding N
  values overflows an int32 accumulator. Overflow is therefore decided only
  by each worker's own saturation, which the local `adapt` reference
  computes identically; without the bound, an aggregator could flag an
  intermediate overflow whose final sum fits, depending on arrival order.
- Retry: an overflowed chunk is re-sent in the same step at e - 8 under the
  key `chunk_id | attempt << 24` (`netsum_client.retry_chunk_id`), so no
  slot, tombstone or stored result of the failed attempt can match. The
  client's loop moved into `exchange()` (explicit chunk ids);
  `allreduce()` is the v2 wrapper over it.
- `train.py --spike-step K --spike-factor F` forces it. Locally, 200 steps
  at S = 1e-4 with a x1000 spike at step 50 through agg + PS: 3 chunks
  retried in both `adapt` and the network path, bit-identical, final
  0.3560 / 0.989; agg and PS each counted 3 overflows, 0 scale_mismatch.
  Without a spike the S = 1e-4 local result is unchanged (0.3560 / 0.989,
  0 retries).
- Red check: the new test run against the previous commit's train.py fails,
  but only on the unknown `--spike-step` option, so it is not a meaningful
  red; the previous code's behaviour is in its source (it raised
  OverflowError, "retrying under a new key is not implemented").
- New CI step "Retry after OVERFLOW" in train-demo.yml: noagg, userspace,
  XDP and XDP + 5% loss with the spike; asserts 3 retried chunks per run,
  every step bit-identical to local adapt, kernel overflow >= 3.

Next step: push, read the new step's numbers into RESULTS, then stop.
