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
