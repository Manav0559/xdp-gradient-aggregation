# Differential fuzzing of the packet parser

`fuzz_grad_parse.cpp` is a libFuzzer + AddressSanitizer harness for
`protocol/grad_parse.h`, the one parser that `agg`, `paramserver` and the
XDP program all call. Every input is checked two ways:

1. **Differential:** `netsum_parse()` must return the same verdict (and, on
   success, the same worker id, fan-in, chunk length and packet kind) as a
   deliberately naive reference parser written inside the harness from the
   wire-format rules in `docs/DESIGN_NOTES.md` §Admission and validation.
2. **Memory safety:** each input is copied into an exactly-sized heap buffer
   and every byte the parser vouched for is read, so ASan reports any
   out-of-bounds access.

The kernel side gets its own differential check: the `bpf-unit` workflow
replays this corpus through the *loaded* XDP program with
`BPF_PROG_TEST_RUN` and compares its actions with the userspace verdicts.

## Run

```sh
python3 fuzz/generate_corpus.py      # regenerate fuzz/corpus/*.bin seeds
fuzz/build_and_run_fuzz.sh 60        # build with clang++ -fsanitize=fuzzer,address, fuzz 60 s
```

macOS needs Homebrew LLVM (`brew install llvm`); Apple's clang has no libFuzzer
runtime. CI (`.github/workflows/fuzz.yml`) runs it for 120 s on every push.

## Corpus

`generate_corpus.py` writes one valid packet of every kind (v1 raw; v2 raw,
resend, fallback, aggregate, overflow aggregate, partial, ACK, register) and
one seed per rejection rule (short header, truncation, missing v2 trailer,
chunk length 0 / > 64, worker id beyond fan-in, fan-in 0 / > 256, unknown
version, reserved bits, illegal flag combinations). Crash reproducers that
libFuzzer writes go to `fuzz/findings/` (ignored by git); promote real ones to
`fuzz/corpus/regressions/`.
