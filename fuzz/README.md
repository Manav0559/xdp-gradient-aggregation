# Differential fuzzing: agg.c vs. xdp_agg.c grad_hdr admission checks

`userspace_agg/agg.c` and `xdp_agg/xdp_agg.c` each carry a header comment
asserting they implement "byte-for-byte the same algorithm" for parsing and
admitting a raw `grad_hdr` packet. Before this directory existed, that claim
was backed only by 9 hand-written example-based unit tests
(`tests/test_correctness.py`) -- real regression coverage, but not an
adversarial search. A prior human adversarial code review already found 10
real bugs in exactly this validation logic (2 critical: an
out-of-bounds-write risk in `xdp_agg.c`'s write-back loop, and a
truncated-packet stale-read in `agg.c` -- see the "CRITICAL FIX" comments at
`userspace_agg/agg.c:231` and `xdp_agg/xdp_agg.c:51-64`). This directory adds
what a hand-written test suite structurally can't: a coverage-guided,
adversarial byte-sequence search, generated and mutated by libFuzzer under
AddressSanitizer, looking for the *next* class of edge case a human reviewer
would miss -- and for any future change to either file that silently breaks
parity with the other.

## What's covered

`fuzz/parse_shared.h` extracts each file's per-packet **stateless**
admission logic -- the checks that only need the received byte length and
the raw header fields, never a slot table -- into two small, pure functions:

- `agg_parse_stateless(data, n)` mirrors `userspace_agg/agg.c`'s checks
  exactly, in the order agg.c applies them: header must fit in `n`,
  `chunk_len > NETSUM_MAX_CHUNK_LEN`, `n` must actually cover
  `NETSUM_HDR_SIZE + chunk_len*4` bytes (the truncated-packet fix),
  `worker_id >= MAX_TRACKED_WORKERS` (256), `num_workers == 0` or
  `num_workers > MAX_TRACKED_WORKERS`.
- `xdp_parse_stateless(data, len)` mirrors `xdp_agg/xdp_agg.c`'s equivalent
  checks, translated from BPF's `(data, data_end)` pointer-pair convention
  to an ordinary `(data, data+len)` buffer -- same pointer-arithmetic bounds
  logic (`(void*)(hdr+1) > data_end`, `(void*)(values+chunk_len) > data_end`,
  etc.), not literally executing BPF bytecode. That needs a real Linux
  kernel and verifier; see `xdp_agg.c`'s own header comment on what
  compiling to BPF bytecode does and doesn't prove.

`fuzz/fuzz_grad_parse.cpp` is an `LLVMFuzzerTestOneInput` harness that feeds
the exact same raw bytes to both functions and checks two things on every
input:

1. **Neither function ever reads outside `[data, data+size)`.**
   AddressSanitizer catches this automatically, provided the functions never
   assume a fixed-size buffer beyond what `size` guarantees -- both check
   `len >= NETSUM_HDR_SIZE` before ever casting to `struct grad_hdr *` and
   dereferencing a field, the same discipline `xdp_agg.c`'s own `data_end`
   checks already follow.
2. **Both functions reach the same accept/reject verdict** (and, when both
   accept, parse the same `chunk_len`/`worker_id`/`num_workers`). Any
   divergence is a real parity bug between the two "byte-for-byte the same
   algorithm" implementations and calls `std::abort()`, so libFuzzer records
   it as a crash with a saved, minimizable reproducer input.

## What's deliberately *not* covered

Both `agg.c` and `xdp_agg.c` also have exactly one **stateful** admission
check: a contribution whose `chunk_len` disagrees with a slot's
already-established `chunk_len` (`agg.c:274`, `xdp_agg.c:311`). That check
needs a live slot table to exist at all -- there is no way to exercise it
from a pure `(data, len) -> verdict` function with no memory across calls,
so it's out of scope for this harness by construction, not by oversight.
`tests/test_correctness.py::test_chunk_len_mismatch_rejected_not_silently_summed`
already covers it end-to-end against the real compiled binaries. A genuinely
stateful differential harness (modeling a slot table on both sides) is a
reasonable future extension -- see the "known nuance" below for one thing it
would need to model.

`parse_shared.h` documents one more nuance worth knowing about rather than
hiding: in the real `xdp_agg.c`, the `num_workers` check only runs inside
`if (!slot)` -- i.e., only for the packet that creates a brand-new slot; a
later packet for an already-existing slot never has its `num_workers` field
read again. `agg.c`, by contrast, checks `num_workers` unconditionally on
*every* packet, existing slot or not. A pure stateless function can't tell
"first packet for this key" from "Nth packet," so `xdp_parse_stateless`
always applies the check -- the one case where both real implementations
actually run it. This is a real, narrow, pre-existing admission-policy
asymmetry between the two files (not a memory-safety or sum-correctness
bug -- it only changes which packets get rejected against an *already
valid* slot), and it's only reachable with live slot state, so it can't
surface as a divergence in this stateless harness. It's flagged here, and in
`parse_shared.h`'s comments, as a legitimate target for a future stateful
harness, not swept under the rug.

## Running it

```sh
fuzz/generate_corpus.py            # (re)generates fuzz/corpus/*.bin
fuzz/build_and_run_fuzz.sh         # 60s smoke run (default)
fuzz/build_and_run_fuzz.sh 300     # 300s
FUZZ_SECONDS=300 fuzz/build_and_run_fuzz.sh   # same, via env var
```

Requires `clang++` with the libFuzzer runtime. On macOS, the Xcode Command
Line Tools ship ASan but not `libclang_rt.fuzzer_osx.a` -- install LLVM via
Homebrew (`brew install llvm`); the script looks for
`/opt/homebrew/opt/llvm/bin/clang++` first and falls back to whatever
`clang++` resolves to on `PATH` otherwise (e.g. Linux, where the system
`clang++` from an LLVM package already bundles the fuzzer runtime). The
script compiles with:

```
clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address -o fuzz_grad_parse fuzz/fuzz_grad_parse.cpp
```

then runs the binary seeded from `fuzz/corpus/` and `fuzz/corpus/regressions/`
for the given duration. This fuzzes only the extracted admission-check logic
in `parse_shared.h` -- never the live XDP program itself, which
`xdp_agg.c`'s own header comment is explicit has only ever been compiled to
bytecode, not verifier- or load-tested on a real interface -- so no Linux
kernel, BPF verifier, or libbpf is needed anywhere in this directory; it
runs identically on macOS and Linux CI. Not wired into the `Makefile`'s
`test` target: libFuzzer isn't available the same uniform way across a
Linux/macOS CI matrix as the plain C build, so a standalone script is the
right amount of integration.

New coverage-increasing inputs libFuzzer discovers along the way are
written to `fuzz/findings/` (gitignored) rather than back into
`fuzz/corpus/` itself -- a short run explores well past the seed corpus, and
committing every mutation as if it were a curated seed would be noise, not
signal. `fuzz/corpus/` only grows when an input is promoted into it
deliberately.

## `corpus/`

Seed inputs, generated by `fuzz/generate_corpus.py` in byte-for-byte the
same raw `grad_hdr` + payload layout as
`tests/test_correctness.py`'s `_raw_grad_packet()` helper (that file is the
single source of truth for this hand-crafted-packet wire layout in test
code; the generator mirrors it rather than redefining its own):

- `valid.bin` -- a well-formed packet both functions must accept.
- `valid_max_chunk_len.bin` -- `chunk_len` exactly at `NETSUM_MAX_CHUNK_LEN`
  (64), the accept-side boundary of a strict `>` check.
- `truncated.bin` -- the exact shape of the critical truncated-packet
  regression: header claims `chunk_len=4`, zero payload bytes actually
  follow.
- `truncated_partial.bin` -- same idea, short by two values instead of all
  four.
- `chunk_len_exceeds_max.bin` -- `chunk_len=100 > NETSUM_MAX_CHUNK_LEN`.
- `worker_id_out_of_range.bin` / `worker_id_at_boundary.bin` -- `worker_id`
  just past and exactly at the last valid tracked id (255).
- `num_workers_zero.bin` / `num_workers_out_of_range.bin` -- the two ways
  `num_workers` can be degenerate.
- `empty.bin` / `too_short.bin` / `one_byte_short_of_header.bin` -- zero
  bytes, a handful of bytes, and one byte short of a full 20-byte header --
  the sharpest edges of the "does the header even fit" check.

## `corpus/regressions/`

Empty as of this writing -- no crash has been found yet to archive here. If
a future run ever finds one, the intended workflow (matching
itch-lob-engine's sibling `fuzz/` directory) is: archive the exact
(optionally libFuzzer-minimized) crashing input here so every future run
keeps replaying it, fix the root cause in whichever of `agg.c`/`xdp_agg.c`
actually has the bug, and add a matching regression test to
`tests/test_correctness.py`.

## Outcome of the last run

Clean. Two runs against the corpus above:

- Sanity check (`-runs=0`, no mutation): 12 executions (11 seed files plus
  libFuzzer's own empty-input probe), `accepted_both=3 rejected_both=9`,
  zero divergences -- confirms the harness itself is wired correctly and
  the parity check logic agrees with the hand-picked seeds' own expected
  accept/reject outcomes before trusting a longer run.
- Real fuzz run, 90 seconds: **143,698,567 executions**
  (~1.58M/s), `accepted_both=12,064,411 rejected_both=131,634,156`, edge
  coverage plateaued at 18/18 almost immediately, zero crashes, zero ASan
  reports, zero verdict divergences.

Coverage saturating this fast (18 edges, reached within the first few
hundred executions) is expected, not a sign the run under-explored: both
extracted functions are five sequential bounds checks over a 20-byte
header's worth of fields, a genuinely small branch space once the header
itself is present. This is a clean bill for the *stateless* admission-check
parity this harness targets -- both files' checks against the received
length/pointer bounds really do agree on every input this run tried, and
neither reads out of bounds doing it. It's a clean-bill for that coverage,
not a claim the two files can never disagree anywhere: see "What's
deliberately not covered" above for the specific classes (the stateful
`chunk_len`-mismatch check, and the documented `num_workers`/slot-existence
asymmetry) this harness cannot reach by construction. A longer run
periodically, and eventually a stateful sibling harness, are both
worthwhile as the code evolves -- the same recommendation
itch-lob-engine's own `fuzz/README.md` makes for its parser and
differential harnesses.
