// Differential fuzzer for the shipped packet parser, protocol/grad_parse.h
// (the code agg, paramserver and xdp_agg actually call), against a naive
// reference written independently from the wire-format spec in
// docs/DESIGN_NOTES.md §Admission and validation. Any verdict or field
// mismatch aborts; ASan catches out-of-bounds reads.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../protocol/grad_parse.h"

namespace {

std::uint64_t g_inputs, g_accepted;

struct ref_result {
    int verdict;
    unsigned worker_id, num_workers, chunk_len, kind;
};

unsigned be16(const std::uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

// Reference: reads bytes by offset from (data, size), no shared code.
ref_result ref_parse(const std::uint8_t *d, std::size_t n)
{
    ref_result r{};
    if (n < 20) { r.verdict = NETSUM_REJ_SHORT_HDR; return r; }
    r.worker_id = be16(d + 12);
    r.num_workers = be16(d + 14);
    r.chunk_len = be16(d + 16);
    unsigned flags = be16(d + 18);
    unsigned version = flags >> 12, bits = flags & 0x3F;
    bool v2 = version == 2;
    if (version != 0 && version != 2) { r.verdict = NETSUM_REJ_VERSION; return r; }
    if ((version == 0 && flags != 0) || (flags & 0x0FC0)) { r.verdict = NETSUM_REJ_RESERVED_FLAGS; return r; }
    if (r.num_workers < 1 || r.num_workers > 256) { r.verdict = NETSUM_REJ_NUM_WORKERS; return r; }
    bool aggregate_id = r.worker_id == 0xFFFF;
    if (aggregate_id && !v2) { r.verdict = NETSUM_REJ_WORKER_ID; return r; }
    const unsigned RESEND = 1, ACK = 2, OVERFLOW = 4, FALLBACK = 8, PARTIAL = 16, REGISTER = 32;
    if (bits & REGISTER) {
        if (bits != REGISTER || aggregate_id) { r.verdict = NETSUM_REJ_FLAG_COMBO; return r; }
        r.kind = NETSUM_KIND_REGISTER;
    } else if (bits & ACK) {
        if (bits != ACK || !aggregate_id) { r.verdict = NETSUM_REJ_FLAG_COMBO; return r; }
        r.kind = NETSUM_KIND_ACK;
    } else if (aggregate_id) {
        if (bits & (RESEND | FALLBACK)) { r.verdict = NETSUM_REJ_FLAG_COMBO; return r; }
        r.kind = (bits & PARTIAL) ? NETSUM_KIND_PARTIAL : NETSUM_KIND_AGGREGATE;
    } else {
        if (bits & (PARTIAL | OVERFLOW)) { r.verdict = NETSUM_REJ_FLAG_COMBO; return r; }
        if (r.worker_id >= r.num_workers) { r.verdict = NETSUM_REJ_WORKER_ID; return r; }
        r.kind = NETSUM_KIND_RAW;
    }
    if (r.chunk_len > 64) { r.verdict = NETSUM_REJ_CHUNK_LEN_MAX; return r; }
    if (r.chunk_len == 0 && r.kind != NETSUM_KIND_REGISTER) { r.verdict = NETSUM_REJ_CHUNK_LEN_ZERO; return r; }
    std::size_t need = 20 + 4 * (std::size_t)r.chunk_len + (v2 ? 32 : 0);
    if (n < need) { r.verdict = NETSUM_REJ_TRUNCATED; return r; }
    r.verdict = NETSUM_OK;
    return r;
}

void print_summary()
{
    std::fprintf(stderr, "[fuzz_grad_parse] inputs=%llu accepted=%llu -- no divergence\n",
                 (unsigned long long)g_inputs, (unsigned long long)g_accepted);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    static const bool registered = (std::atexit(print_summary), true);
    (void)registered;
    ++g_inputs;
    // Copy into an exactly-sized heap buffer so ASan flags any read past the end.
    std::uint8_t *buf = static_cast<std::uint8_t *>(std::malloc(size ? size : 1));
    if (size)
        std::memcpy(buf, data, size);
    struct netsum_parsed p;
    int got = netsum_parse(buf, buf + size, &p);
    ref_result want = ref_parse(buf, size);
    bool fields_differ = got == NETSUM_OK &&
        (p.worker_id != want.worker_id || p.num_workers != want.num_workers ||
         p.chunk_len != want.chunk_len || p.kind != want.kind);
    if (got != want.verdict || fields_differ) {
        std::fprintf(stderr, "DIVERGENCE on %zu-byte input: netsum_parse=%d reference=%d\n",
                     size, got, want.verdict);
        std::abort();
    }
    if (got == NETSUM_OK) {
        ++g_accepted;
        const std::uint8_t *values = buf + NETSUM_HDR_SIZE;
        volatile std::uint8_t sink = 0;
        for (unsigned i = 0; i < p.payload_len; i++)  // touch every byte the parser vouched for
            sink = static_cast<std::uint8_t>(sink ^ values[i]);
    }
    std::free(buf);
    return 0;
}
