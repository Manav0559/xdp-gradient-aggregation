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
    uint16_t flags;        /* reserved, must be 0 for now */
} __attribute__((packed));

#define NETSUM_HDR_SIZE (sizeof(struct grad_hdr))
#define NETSUM_MAX_PACKET_SIZE (NETSUM_HDR_SIZE + NETSUM_MAX_CHUNK_LEN * sizeof(int32_t))

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
