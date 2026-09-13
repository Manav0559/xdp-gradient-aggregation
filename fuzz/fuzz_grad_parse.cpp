// Differential libFuzzer harness for NetSum's grad_hdr admission-check
// logic: feeds the exact same raw bytes to agg_parse_stateless()
// (userspace_agg/agg.c's per-packet stateless checks) and
// xdp_parse_stateless() (xdp_agg.c's equivalent, translated from BPF's
// data/data_end pointer pair to a plain buffer+length -- see
// parse_shared.h) and asserts they reach the SAME accept/reject verdict on
// every input.
//
// Motivation: both agg.c and xdp_agg.c's own header comments assert they
// implement "byte-for-byte the same algorithm." Before this harness, that
// claim was backed only by 9 hand-written example-based unit tests
// (tests/test_correctness.py) -- not an adversarial search. A prior human
// adversarial code review already found 10 real bugs in exactly this
// validation logic (2 critical: an out-of-bounds-write risk in
// xdp_agg.c's write-back loop, and a truncated-packet stale-read in
// agg.c). This harness exists to keep searching for the next class of edge
// case a human reviewer would miss, and to catch any FUTURE change to
// either file that silently breaks parity with the other.
//
// Two things checked on every input:
//
//   (a) neither extracted function ever reads outside [data, data+size) --
//       AddressSanitizer catches this automatically, PROVIDED the
//       extracted functions never assume a fixed-size buffer beyond what
//       `size` actually guarantees. parse_shared.h's two functions both
//       check len >= NETSUM_HDR_SIZE before ever casting to
//       `struct grad_hdr *` and dereferencing a field -- exactly the
//       discipline xdp_agg.c's own data_end checks already follow.
//
//   (b) agg_parse_stateless() and xdp_parse_stateless() reach the SAME
//       verdict (and, when both accept, the same parsed chunk_len/
//       worker_id/num_workers) on every input. Any divergence is a real
//       parity bug between the two "byte-for-byte the same algorithm"
//       implementations, so it aborts -- libFuzzer records an abort() as a
//       crash and saves a minimized reproducer input under this script's
//       -artifact_prefix.
//
// See parse_shared.h's own comment on xdp_parse_stateless for the one
// known, documented, out-of-scope modeling nuance (the num_workers check's
// slot-existence dependence in the real xdp_agg.c, unreachable from a pure
// stateless function) that this harness deliberately does NOT flag as a
// divergence.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "parse_shared.h"

namespace {

// Process-lifetime counters (one DivergingHandler-style summary per whole
// fuzzing session, not per input) -- printed once at exit so a clean run's
// stderr says something more useful than silence.
std::uint64_t g_inputs = 0;
std::uint64_t g_accepted_both = 0;
std::uint64_t g_rejected_both = 0;

void print_summary() {
    std::fprintf(
        stderr,
        "[fuzz_grad_parse] inputs=%llu accepted_both=%llu rejected_both=%llu -- "
        "zero verdict divergences (any divergence aborts immediately, so reaching "
        "process exit at all means agg_parse_stateless() and xdp_parse_stateless() "
        "agreed on every input this run saw)\n",
        static_cast<unsigned long long>(g_inputs),
        static_cast<unsigned long long>(g_accepted_both),
        static_cast<unsigned long long>(g_rejected_both));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    static const bool registered = (std::atexit(print_summary), true);
    (void)registered;
    ++g_inputs;

    struct netsum_parse_result agg_r = agg_parse_stateless(data, size);
    struct netsum_parse_result xdp_r = xdp_parse_stateless(data, size);

    if (agg_r.verdict != xdp_r.verdict) {
        std::fprintf(stderr,
                      "DIVERGENCE: verdict mismatch on %zu-byte input -- "
                      "agg_parse_stateless=%s xdp_parse_stateless=%s\n",
                      size, agg_r.verdict == NETSUM_PARSE_ACCEPT ? "ACCEPT" : "REJECT",
                      xdp_r.verdict == NETSUM_PARSE_ACCEPT ? "ACCEPT" : "REJECT");
        std::abort();
    }

    if (agg_r.verdict == NETSUM_PARSE_ACCEPT) {
        ++g_accepted_both;
        if (agg_r.chunk_len != xdp_r.chunk_len || agg_r.worker_id != xdp_r.worker_id ||
            agg_r.num_workers != xdp_r.num_workers) {
            std::fprintf(
                stderr,
                "DIVERGENCE: both ACCEPTed a %zu-byte input but parsed fields differ -- "
                "agg(chunk_len=%u worker_id=%u num_workers=%u) "
                "xdp(chunk_len=%u worker_id=%u num_workers=%u)\n",
                size, agg_r.chunk_len, agg_r.worker_id, agg_r.num_workers, xdp_r.chunk_len,
                xdp_r.worker_id, xdp_r.num_workers);
            std::abort();
        }
    } else {
        ++g_rejected_both;
    }

    return 0;
}
