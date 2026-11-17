/* NetSum wire format: the one definition of a gradient packet, included by
 * every component (worker, aggregator, parameter server, XDP program, tests).
 * Big-endian on the wire; values are Q16.16 int32 because BPF has no floating
 * point and integer sums are exact. Layout and flags: docs/DESIGN_NOTES.md
 * §Wire format; number format: §Fixed point. */
#ifndef NETSUM_GRAD_PROTO_H
#define NETSUM_GRAD_PROTO_H

#include <stdint.h>

#define NETSUM_PORT 9876
/* Values per packet, at most. Overridable at build time
 * (-DNETSUM_MAX_CHUNK_LEN=N) to measure the verifier cost of larger packets;
 * every component must be built with the same value. */
#ifndef NETSUM_MAX_CHUNK_LEN
#define NETSUM_MAX_CHUNK_LEN 64
#endif
#define NETSUM_Q_FRAC_BITS 16    /* Q16.16: 16 fractional bits */

/* 20 bytes, packed, all fields naturally aligned. */
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
#define NETSUM_VERSION_V3 3 /* v2 + per-chunk exponent in bits 6-11 */
#define NETSUM_FLAGS_V2 ((uint16_t)(NETSUM_VERSION_V2 << NETSUM_VERSION_SHIFT))
#define NETSUM_FRAC_SHIFT 6
#define NETSUM_FRAC_MASK 0x0FC0u /* v3: values are round(x * 2^e), e = 0..63 */
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

/* Flags word for a packet of the given version and exponent (v1: no flags;
 * v2: exponent fixed at 16, not encoded). */
NETSUM_INLINE uint16_t netsum_wire_flags(uint8_t version, uint8_t frac_bits, uint16_t bits)
{
    if (version == NETSUM_VERSION_V3)
        return (uint16_t)((NETSUM_VERSION_V3 << NETSUM_VERSION_SHIFT) |
                          ((frac_bits & 63u) << NETSUM_FRAC_SHIFT) | bits);
    if (version == NETSUM_VERSION_V2)
        return (uint16_t)(NETSUM_FLAGS_V2 | bits);
    return 0;
}

/* Wrapping int32 add that reports signed overflow; no C UB (unsigned
 * arithmetic), no branches, so the same code runs in userspace and BPF. */
NETSUM_INLINE int netsum_add_i32(int32_t *acc, int32_t v) {
    uint32_t a = (uint32_t)*acc, b = (uint32_t)v, r = a + b;
    *acc = (int32_t)r;
    return (int)(((a ^ r) & (b ^ r)) >> 31);
}

/* Q16.16 <-> double, userspace only (the kernel only adds int32 values). */
/* 2^e as a double, exactly, without libm (|e| <= 63). */
static inline double netsum_pow2(int e) {
    double s = 1.0;
    for (int i = 0; i < e; i++)
        s *= 2.0;
    for (int i = 0; i > e; i--)
        s *= 0.5;
    return s;
}

/* round(v * 2^e), half away from zero; saturates at the int32 limits (and
 * sets *saturated, if given); NaN -> 0. */
static inline int32_t netsum_to_scaled(double v, int e, int *saturated) {
    if (saturated)
        *saturated = 0;
    if (v != v)
        return 0;
    double s = v * netsum_pow2(e);
    if (s >= 2147483647.0 || s <= -2147483648.0) {
        if (saturated)
            *saturated = 1;
        return s > 0 ? 2147483647 : -2147483647 - 1;
    }
    return (int32_t)(s >= 0 ? s + 0.5 : s - 0.5);
}

static inline double netsum_from_scaled(int32_t v, int e) {
    return (double)v / netsum_pow2(e);
}

static inline int32_t netsum_to_fixed(double v) {
    return netsum_to_scaled(v, NETSUM_Q_FRAC_BITS, 0);
}

static inline double netsum_to_double(int32_t fixed) {
    return (double)fixed / (double)(1 << NETSUM_Q_FRAC_BITS);
}

/* Configuration-time check: can n values of magnitude max_abs sum within int32? */
static inline int netsum_sum_fits_i32(int num_workers, double max_abs) {
    double max_fixed_sum = (double)num_workers * max_abs * (double)(1 << NETSUM_Q_FRAC_BITS);
    return max_fixed_sum < 2147483647.0 && -max_fixed_sum > -2147483648.0;
}

#endif /* NETSUM_GRAD_PROTO_H */
