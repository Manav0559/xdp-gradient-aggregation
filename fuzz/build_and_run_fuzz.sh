#!/usr/bin/env bash
# Builds fuzz_grad_parse.cpp with clang's libFuzzer + ASan and runs it on
# fuzz/corpus/ for a bounded time; non-zero exit on a crash or a verdict
# divergence between netsum_parse() and the reference parser. Needs only
# clang with the libFuzzer runtime (on macOS: Homebrew LLVM).
# Usage: fuzz/build_and_run_fuzz.sh [seconds]   (or FUZZ_SECONDS=300)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOMEBREW_LLVM_CLANGXX="/opt/homebrew/opt/llvm/bin/clang++"

# Apple's clang++ has ASan but no libFuzzer runtime: prefer Homebrew LLVM.
if [ -x "${HOMEBREW_LLVM_CLANGXX}" ]; then
    CLANGXX="${HOMEBREW_LLVM_CLANGXX}"
elif command -v clang++ >/dev/null 2>&1; then
    CLANGXX="$(command -v clang++)"
else
    echo "error: clang++ not found." >&2
    echo "       libFuzzer requires clang (not gcc/g++). On macOS, the Xcode" >&2
    echo "       Command Line Tools clang lacks the libFuzzer runtime -- run" >&2
    echo "       'brew install llvm' and re-run this script. On Linux, install" >&2
    echo "       clang from your package manager." >&2
    exit 1
fi

DURATION="${1:-${FUZZ_SECONDS:-60}}"
BIN="${SCRIPT_DIR}/fuzz_grad_parse"
CORPUS_DIR="${SCRIPT_DIR}/corpus"
REGRESSIONS_DIR="${CORPUS_DIR}/regressions"
# New coverage-increasing inputs libFuzzer discovers along the way go to a
# gitignored findings/ dir, never back into the hand-picked corpus/ itself
# -- a short run turns up hundreds of mutations, and committing those as if
# they were curated seeds would be noise, not signal (same reasoning as
# itch-lob-engine's fuzz/build_and_run.sh).
FINDINGS_DIR="${SCRIPT_DIR}/findings"

mkdir -p "${CORPUS_DIR}" "${REGRESSIONS_DIR}" "${FINDINGS_DIR}"

echo "building ${BIN} with ${CLANGXX}..."
"${CLANGXX}" -std=c++17 -O1 -g -fsanitize=fuzzer,address \
    -o "${BIN}" "${SCRIPT_DIR}/fuzz_grad_parse.cpp"

echo "running for ${DURATION}s (seeded from ${CORPUS_DIR} and its regressions/)..."
"${BIN}" \
    -max_total_time="${DURATION}" \
    -artifact_prefix="${SCRIPT_DIR}/" \
    "${FINDINGS_DIR}" "${CORPUS_DIR}" "${REGRESSIONS_DIR}"

echo "clean: no crash or verdict divergence found in ${DURATION}s"
