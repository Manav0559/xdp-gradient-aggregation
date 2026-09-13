#!/usr/bin/env bash
# Compiles fuzz_grad_parse.cpp with clang's libFuzzer + ASan and smoke-runs
# it against fuzz/corpus/ for a bounded time, failing (non-zero exit) on
# any crash or verdict divergence. Mirrors the sibling itch-lob-engine
# project's fuzz/build_and_run*.sh scripts in structure and reasoning (same
# "standalone script, not wired into the Makefile" call, same macOS
# Homebrew-LLVM-clang fallback).
#
# This fuzzes only the extracted admission-check logic in
# fuzz/parse_shared.h -- never the live XDP program itself -- so it needs
# no Linux kernel, no BPF verifier, no libbpf, nothing beyond a real clang
# with the libFuzzer runtime. Works identically on macOS and Linux CI.
#
# Usage:
#   fuzz/build_and_run_fuzz.sh [seconds]
#   FUZZ_SECONDS=300 fuzz/build_and_run_fuzz.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOMEBREW_LLVM_CLANGXX="/opt/homebrew/opt/llvm/bin/clang++"

# On macOS, the Xcode Command Line Tools' clang++ ships ASan but not
# libclang_rt.fuzzer_osx.a, so -fsanitize=fuzzer fails at link time. Prefer
# a Homebrew LLVM clang++ when present; fall back to whatever's on PATH
# otherwise (e.g. Linux CI, where the system clang++ already bundles it).
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
