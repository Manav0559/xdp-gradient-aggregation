/* NetSum wire protocol -- the single source of truth every component
 * (worker sender, parameter server, userspace aggregator, and eventually the
 * XDP program) includes verbatim. Never redefine this shape anywhere else.
 *
 * Fixed-point, not float: the eventual XDP/eBPF aggregator runs in the Linux
 * kernel, where the BPF verifier forbids floating-point instructions
 * entirely. Every gradient value on the wire is Q16.16 fixed-point (16
 * integer bits, 16 fractional bits, stored as a plain int32_t) so the exact
 * same struct and the exact same integer-addition accumulation logic works
 * unmodified in userspace C, in the eventual BPF program, and in the
 * correctness tests -- one aggregation algorithm, not three.
 *
 * Network byte order: every multi-byte field is big-endian on the wire
 * (hton?/ntoh? at the boundary), independent of the host's native
 * endianness -- required for a BPF program to parse a raw sk_buff
 * correctly regardless of what architecture it eventually runs on.
 */
#ifndef NETSUM_GRAD_PROTO_H
#define NETSUM_GRAD_PROTO_H

#include <stdint.h>

#define NETSUM_PORT 9876
#define NETSUM_MAX_CHUNK_LEN 64  /* fixed-point values per packet, at most */
#define NETSUM_Q_FRAC_BITS 16    /* Q16.16: 16 fractional bits */

/* On-the-wire header. Packed explicitly (no compiler-inserted padding) --
 * every field is naturally aligned already at these widths and this order,
 * but __attribute__((packed)) documents the intent and survives a future
 * field reordering mistake. 20 bytes, chosen to keep the whole header
 * inside one 64-byte cache line alongside a modest chunk payload, an
 * eventual performance consideration for the XDP parse path. */
struct grad_hdr {
    uint32_t job_id;       /* tenant / training job identifier */
    uint32_t round;        /* training step / iteration number */
    uint32_t chunk_id;     /* which slice of the gradient vector this is */
    uint16_t worker_id;    /* 0 .. num_workers-1 */
    uint16_t num_workers;  /* fan-in expected for this (job, round) */
    uint16_t chunk_len;    /* number of Q16.16 values that follow, <= NETSUM_MAX_CHUNK_LEN */
    uint16_t flags;        /* version nibble + NETSUM_F_* bits, see below */
} __attribute__((packed));

#define NETSUM_HDR_SIZE (sizeof(struct grad_hdr))

/* ---- v2 (docs/DESIGN_NOTES.md §Wire format) -------------------------------
 * flags, host order: bits 15-12 version (0 = legacy v1, 2 = v2), bits 0-5
 * NETSUM_F_*, bits 6-11 reserved (must be 0). v1 packets have flags == 0.
 * Every v2 packet is: grad_hdr | chunk_len int32 values | 32-byte contributor
 * bitmap (bit w set iff worker w's contribution is included). A raw
 * contribution sets only its own bit, so an aggregator can turn it into an
 * aggregate in place without growing the packet. */
#define NETSUM_VERSION_SHIFT 12
#define NETSUM_VERSION_V2 2
#define NETSUM_FLAGS_V2 ((uint16_t)(NETSUM_VERSION_V2 << NETSUM_VERSION_SHIFT))
#define NETSUM_F_RESEND   0x0001u /* worker retransmission */
#define NETSUM_F_ACK      0x0002u /* PS result/ACK toward aggregator and workers */
#define NETSUM_F_OVERFLOW 0x0004u /* aggregate whose accumulation overflowed */
#define NETSUM_F_FALLBACK 0x0008u /* raw contribution forwarded un-aggregated */
#define NETSUM_F_PARTIAL  0x0010u /* flushed incomplete aggregate */
#define NETSUM_F_REGISTER 0x0020u /* worker -> PS registration, no values */
#define NETSUM_F_KNOWN    0x003Fu
#define NETSUM_F_RESERVED 0x0FC0u

#define NETSUM_MAX_FANIN 256
#define NETSUM_BITMAP_BYTES (NETSUM_MAX_FANIN / 8)
#define NETSUM_WORKER_AGGREGATE 0xFFFFu /* worker_id on aggregator/PS output */

#define NETSUM_MAX_PACKET_SIZE \
    (NETSUM_HDR_SIZE + NETSUM_MAX_CHUNK_LEN * sizeof(int32_t) + NETSUM_BITMAP_BYTES)

#ifdef __cplusplus
#define NETSUM_STATIC_ASSERT static_assert
#else
#define NETSUM_STATIC_ASSERT _Static_assert
#endif
NETSUM_STATIC_ASSERT(sizeof(struct grad_hdr) == 20, "grad_hdr must stay 20 bytes");
NETSUM_STATIC_ASSERT(NETSUM_BITMAP_BYTES == 32, "bitmap trailer is 32 bytes");
/* Ethernet 14 + IPv4 20 + UDP 8 + max payload must fit a 1500-byte MTU frame. */
NETSUM_STATIC_ASSERT(20 + 8 + NETSUM_MAX_PACKET_SIZE <= 1500, "max packet exceeds MTU");

/* Forced inlining: BPF forbids calls while a spin lock is held. */
#ifndef NETSUM_INLINE
#define NETSUM_INLINE static inline __attribute__((always_inline))
#endif

/* Wrapping int32 add that reports signed overflow; no C UB (unsigned
 * arithmetic), no branches, so the same code runs in userspace and BPF. */
NETSUM_INLINE int netsum_add_i32(int32_t *acc, int32_t v) {
    uint32_t a = (uint32_t)*acc, b = (uint32_t)v, r = a + b;
    *acc = (int32_t)r;
    return (int)(((a ^ r) & (b ^ r)) >> 31);
}

/* Q16.16 <-> double conversions, used ONLY on the userspace side (worker
 * quantizing a real gradient before send, or a test harness checking
 * round-trip error). The eventual BPF aggregator never calls these -- it
 * only ever adds two int32_t fixed-point values together, which is exact
 * integer arithmetic with no float instructions anywhere in the kernel
 * path. */
static inline int32_t netsum_to_fixed(double v) {
    return (int32_t)(v * (double)(1 << NETSUM_Q_FRAC_BITS));
}

static inline double netsum_to_double(int32_t fixed) {
    return (double)fixed / (double)(1 << NETSUM_Q_FRAC_BITS);
}

/* Bound check: with `n` workers each contributing a value whose magnitude
 * never exceeds `max_abs` (in real units, not fixed-point), the summed
 * Q16.16 accumulator must not exceed int32_t's range. Call this at
 * configuration time, not per-packet -- it is a static property of a
 * deployment's chosen (num_workers, max_abs) pair, not something to check
 * on every add. */
static inline int netsum_sum_fits_i32(int num_workers, double max_abs) {
    double max_fixed_sum = (double)num_workers * max_abs * (double)(1 << NETSUM_Q_FRAC_BITS);
    return max_fixed_sum < 2147483647.0 && -max_fixed_sum > -2147483648.0;
}

#endif /* NETSUM_GRAD_PROTO_H */
