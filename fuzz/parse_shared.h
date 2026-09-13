/* NetSum grad_hdr admission checks -- extracted for differential fuzzing.
 *
 * Both userspace_agg/agg.c and xdp_agg/xdp_agg.c carry a header comment
 * asserting they implement "byte-for-byte the same algorithm." Before this
 * file existed, that claim was backed only by 9 hand-written example-based
 * unit tests (tests/test_correctness.py) -- not an adversarial search. A
 * prior human adversarial code review already found 10 real bugs in
 * exactly this validation logic (2 critical: an out-of-bounds-write risk
 * in xdp_agg.c's write-back loop, and a truncated-packet stale-read in
 * agg.c -- see the "CRITICAL FIX" comments at userspace_agg/agg.c:231 and
 * xdp_agg/xdp_agg.c:51-64). This header pulls each file's per-packet
 * STATELESS admission logic (the checks that only need the received byte
 * length and the raw header fields, never a slot table) out into two pure,
 * standalone functions so fuzz/fuzz_grad_parse.cpp can feed both the exact
 * same bytes and assert they always agree -- turning the "byte-for-byte
 * the same algorithm" comment into something a fuzzer actually checks,
 * millions of times a minute, instead of something only a human reviewer
 * verified once.
 *
 * Deliberately EXCLUDED from both functions below: the ONE check that is
 * genuinely stateful in both source files -- `slot->chunk_len != chunk_len`
 * (agg.c:274, xdp_agg.c:311, both guarding against a later worker's
 * contribution disagreeing with the chunk_len a slot's FIRST packet
 * established). That check needs a live slot to exist at all; there is no
 * way to exercise it from a pure (data, len) -> verdict function with no
 * memory across calls, so it is out of scope for this stateless
 * differential harness by construction, not by oversight.
 *
 * Both functions below are kept byte-for-byte faithful to their source
 * file's actual logic -- nothing here "fixes" or simplifies what's really
 * there, even where a nuance (see xdp_parse_stateless's comment below)
 * looks like it could be tightened. The whole point of this harness is to
 * test what's actually shipped.
 */
#ifndef NETSUM_FUZZ_PARSE_SHARED_H
#define NETSUM_FUZZ_PARSE_SHARED_H

#include <arpa/inet.h> /* ntohs/ntohl -- exactly what userspace_agg/agg.c includes and calls */
#include <stddef.h>
#include <stdint.h>

#include "../protocol/grad_proto.h"

/* Mirror userspace_agg/agg.c:40 (`#define MAX_TRACKED_WORKERS 256`) and
 * xdp_agg/xdp_agg.c:121 (`#define MAX_TRACKED_WORKERS_BITMAP_BYTES 32`,
 * i.e. 32*8 = 256 trackable worker_ids as a bitmap instead of a
 * byte-per-worker array) -- same numeric bound, reproduced here under
 * names that make clear which source file each traces back to. */
#define FUZZ_AGG_MAX_TRACKED_WORKERS 256
#define FUZZ_XDP_MAX_TRACKED_WORKERS_BITMAP_BYTES 32

enum netsum_parse_verdict {
    NETSUM_PARSE_ACCEPT = 0,
    NETSUM_PARSE_REJECT = 1,
};

struct netsum_parse_result {
    enum netsum_parse_verdict verdict;
    uint16_t chunk_len;
    uint16_t worker_id;
    uint16_t num_workers;
};

static inline struct netsum_parse_result netsum_reject(void) {
    struct netsum_parse_result r;
    r.verdict = NETSUM_PARSE_REJECT;
    r.chunk_len = 0;
    r.worker_id = 0;
    r.num_workers = 0;
    return r;
}

/* agg_parse_stateless -- mirrors userspace_agg/agg.c's per-packet
 * stateless admission checks, in the exact order agg.c applies them
 * (agg.c:217, 230, 245, 246, 253):
 *
 *   1. `n < NETSUM_HDR_SIZE`                                    (agg.c:217, `if (n < (ssize_t)NETSUM_HDR_SIZE) continue;`)
 *   2. `chunk_len > NETSUM_MAX_CHUNK_LEN`                        (agg.c:230)
 *   3. `n < NETSUM_HDR_SIZE + chunk_len*sizeof(int32_t)`         (agg.c:245 -- the truncated-packet-stale-read fix)
 *   4. `worker_id >= MAX_TRACKED_WORKERS`                        (agg.c:246)
 *   5. `num_workers == 0 || num_workers > MAX_TRACKED_WORKERS`   (agg.c:253)
 *
 * Check #1 is what makes this function safe to call with ANY (data, n),
 * including n == 0: the struct grad_hdr* cast and every field
 * dereference below it happen only after n >= NETSUM_HDR_SIZE is proven,
 * so this function never reads outside [data, data+n). */
static inline struct netsum_parse_result agg_parse_stateless(const uint8_t *data, size_t n) {
    if (n < NETSUM_HDR_SIZE) return netsum_reject(); /* agg.c:217 */

    const struct grad_hdr *hdr = (const struct grad_hdr *)data; /* safe: n >= NETSUM_HDR_SIZE just proven */
    uint16_t worker_id = ntohs(hdr->worker_id);
    uint16_t num_workers = ntohs(hdr->num_workers);
    uint16_t chunk_len = ntohs(hdr->chunk_len);

    if (chunk_len > NETSUM_MAX_CHUNK_LEN) return netsum_reject(); /* agg.c:230 */
    if (n < NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t)) return netsum_reject(); /* agg.c:245 */
    if (worker_id >= FUZZ_AGG_MAX_TRACKED_WORKERS) return netsum_reject(); /* agg.c:246 */
    if (num_workers == 0 || num_workers > FUZZ_AGG_MAX_TRACKED_WORKERS) return netsum_reject(); /* agg.c:253 */

    struct netsum_parse_result r;
    r.verdict = NETSUM_PARSE_ACCEPT;
    r.chunk_len = chunk_len;
    r.worker_id = worker_id;
    r.num_workers = num_workers;
    return r;
}

/* Byte-swap helpers matching xdp_agg/bpf_compat.h's netsum_bpf_ntohs /
 * netsum_bpf_ntohl EXACTLY (a manual swap, not <arpa/inet.h>'s ntohs/
 * ntohl, because a real BPF program is freestanding and has no libc) --
 * reproduced here under fuzz-local names so this file has zero dependency
 * on bpf_compat.h's SEC()/map-definition machinery, which is meaningless
 * outside a real BPF compile. Both give byte-identical results to
 * <arpa/inet.h>'s ntohs/ntohl on every little-endian host this project
 * targets (x86_64, arm64), which is every host this fuzz harness runs on
 * too. */
static inline uint16_t netsum_bpf_style_ntohs(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

/* xdp_parse_stateless -- mirrors xdp_agg/xdp_agg.c's grad_hdr admission
 * checks, translated from BPF's (data, data_end) pointer-pair convention
 * to an ordinary (data, data+len) buffer -- same pointer-arithmetic bounds
 * logic, not literally executing BPF bytecode (that needs a real Linux
 * verifier + kernel; see xdp_agg.c's own header comment on what compiling
 * to BPF bytecode does and does not prove). xdp_agg.c parses a full
 * Ethernet/IPv4/UDP/grad_hdr stack; this function starts exactly where
 * userspace_agg/agg.c's `in_packet` buffer already starts -- at the
 * grad_hdr itself -- since that's the only part of xdp_agg.c whose
 * admission logic has a userspace counterpart to differentially test
 * against.
 *
 * Faithfully reproduces, in order (xdp_agg.c:229, 232, 235, 238, 262):
 *
 *   1. `(void*)(hdr+1) > data_end`             => `len < NETSUM_HDR_SIZE`                                    (xdp_agg.c:229)
 *   2. `chunk_len > NETSUM_MAX_CHUNK_LEN`                                                                     (xdp_agg.c:232, XDP_DROP)
 *   3. `(void*)(values+chunk_len) > data_end`  => `len < NETSUM_HDR_SIZE + chunk_len*sizeof(int32_t)`         (xdp_agg.c:235, XDP_DROP -- the pointer-arithmetic form of agg.c's truncated-packet check; THIS is exactly the check whose absence was the critical out-of-bounds-write finding)
 *   4. `worker_id >= MAX_TRACKED_WORKERS_BITMAP_BYTES*8`                                                      (xdp_agg.c:238, XDP_DROP)
 *   5. `num_workers_hdr == 0 || num_workers_hdr > MAX_TRACKED_WORKERS_BITMAP_BYTES*8`                         (xdp_agg.c:262, XDP_DROP)
 *
 * (Check #1 in the real xdp_agg.c returns XDP_PASS, not XDP_DROP -- "not
 * our traffic, let the ordinary network stack handle it" rather than "this
 * IS our traffic and it's malformed." That's a real distinction for a
 * kernel packet-processing return code, but both outcomes mean the same
 * thing for this harness's purposes -- the packet never reaches slot
 * processing -- so both collapse to NETSUM_PARSE_REJECT here, the same way
 * agg.c's own `continue` collapses "too short to have a header" and
 * "malformed" into one non-admission outcome.)
 *
 * One real nuance, documented rather than silently papered over: in the
 * actual xdp_agg.c, check #5 lives inside `if (!slot)` (xdp_agg.c:247) --
 * it runs ONLY when this packet is the one creating a brand-new slot; a
 * later packet arriving for an already-existing slot skips it entirely
 * (hdr->num_workers is simply never read again once a slot exists, because
 * slot->num_workers_expected was already latched from the packet that
 * created it). A pure (data, len) -> verdict function has no slot table
 * and so cannot distinguish "first packet for this (job,round,chunk_id)"
 * from "Nth packet for an already-existing slot" -- there is no state here
 * at all. This extraction always applies check #5, i.e. it models every
 * fuzzer input as the packet that would create a brand-new slot -- the one
 * case where BOTH agg.c (which checks num_workers unconditionally on
 * EVERY packet, agg.c:253, existing slot or not) and xdp_agg.c actually
 * run this check, so it is the only faithful way to compare the two
 * without inventing slot state neither extracted function has.
 *
 * This is a modeling choice forced by testing only the stateless subset,
 * not a bug introduced by this file: it surfaces a genuine, narrow,
 * pre-existing admission-policy asymmetry between the two "byte-for-byte
 * identical" implementations -- agg.c keeps rejecting a bad-num_workers
 * packet even against an already-valid, already-existing slot; xdp_agg.c
 * stops caring once the slot exists at all. That asymmetry only manifests
 * with live slot state (a later packet, not a first one), so it cannot be
 * a memory-safety or sum-correctness bug reachable from either function
 * below, and is out of scope for this stateless harness by construction.
 * It is a legitimate candidate for a future STATEFUL differential harness
 * (one that models the slot table on both sides) -- see fuzz/README.md. */
static inline uint32_t netsum_bpf_style_ntohl(uint32_t v) {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
}

static inline struct netsum_parse_result xdp_parse_stateless(const uint8_t *data, size_t len) {
    if (len < NETSUM_HDR_SIZE) return netsum_reject(); /* xdp_agg.c:229, (void*)(hdr+1) > data_end */

    const struct grad_hdr *hdr = (const struct grad_hdr *)data; /* safe: len >= NETSUM_HDR_SIZE just proven */
    uint16_t chunk_len = netsum_bpf_style_ntohs(hdr->chunk_len);

    if (chunk_len > NETSUM_MAX_CHUNK_LEN) return netsum_reject(); /* xdp_agg.c:232 */
    /* xdp_agg.c:235 -- (void*)(values + chunk_len) > data_end, translated
     * to buffer+length arithmetic. This is the pointer-bounds check whose
     * absence was the critical out-of-bounds-write finding: without it,
     * the accumulate/write-back loops further down xdp_agg.c would trust a
     * header-claimed chunk_len the packet never actually backed with that
     * many bytes. */
    if (len < NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t)) return netsum_reject();

    uint16_t worker_id = netsum_bpf_style_ntohs(hdr->worker_id);
    if (worker_id >= FUZZ_XDP_MAX_TRACKED_WORKERS_BITMAP_BYTES * 8) return netsum_reject(); /* xdp_agg.c:238 */

    uint16_t num_workers_hdr = netsum_bpf_style_ntohs(hdr->num_workers);
    if (num_workers_hdr == 0 || num_workers_hdr > FUZZ_XDP_MAX_TRACKED_WORKERS_BITMAP_BYTES * 8) {
        return netsum_reject(); /* xdp_agg.c:262 -- modeled unconditionally, see comment above */
    }

    struct netsum_parse_result r;
    r.verdict = NETSUM_PARSE_ACCEPT;
    r.chunk_len = chunk_len;
    r.worker_id = worker_id;
    r.num_workers = num_workers_hdr;
    return r;
}

#endif /* NETSUM_FUZZ_PARSE_SHARED_H */
