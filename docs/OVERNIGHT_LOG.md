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
