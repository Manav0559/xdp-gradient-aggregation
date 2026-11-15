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

## 2026-11-16 02:10 IST — Phase 1 (red tests)

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

## 2026-11-16 02:50 IST — Phase 2 (protocol v2, userspace fixes)

- Decision: every v2 packet carries the 32-byte contributor bitmap (raw
  contributions set their own bit). Chosen up front instead of trying
  `bpf_xdp_adjust_tail` first: no tailroom dependency in `xdpgeneric`, one
  packet shape for every kind. Deviation from the brief's order, recorded in
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

## 2026-11-16 03:45 IST — Phase 3 (kernel parity)

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

## 2026-11-16 04:40 IST — Phase 3.5 (benchmark-lite)

- `bench/lite_sender.c` (paced open-loop sender, sendmmsg batches of 32),
  `scripts/bench_lite.sh` (topology, trials, counters), `scripts/netsum_stats.py`
  (stats moved out of the v1 benchmark; adds Holm and ratio-of-medians CIs),
  `scripts/bench_lite_analyze.py`, workflow `bench-lite.yml` (path-filtered).
- Per the advisor: kernel tombstones are not retired until Phase 4, so each
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
- Phase 4 plan reviewed before coding. Adopted: (a) close 3.5 first (commit
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

## 2026-11-16 05:45 IST — Phase 4a + 4d in userspace

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
