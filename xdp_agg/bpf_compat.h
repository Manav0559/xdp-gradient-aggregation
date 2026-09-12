/* Minimal, vendored subset of the Linux BPF UAPI + libbpf helper
 * declarations -- just enough to compile xdp_agg.c to BPF bytecode with
 * `clang -target bpf` on a machine that has no Linux kernel headers or
 * libbpf installed at all (this repo was developed partly on macOS, where
 * neither exists, and libbpf itself has no macOS build -- see
 * docs/DEV_ENVIRONMENT.md).
 *
 * This is a real, standard technique for portable BPF sources (several
 * upstream projects vendor a header subset for exactly this reason), NOT a
 * reimplementation of BPF semantics -- every value and struct layout below
 * is copied verbatim from the stable, versioned UAPI
 * (include/uapi/linux/bpf.h) and libbpf's bpf_helpers.h, which are an ABI
 * contract the kernel guarantees not to break.
 *
 * On a real Linux dev box with libbpf-dev installed, prefer the real
 * <linux/bpf.h> + <bpf/bpf_helpers.h> instead of this file -- see the
 * Makefile's USE_SYSTEM_LIBBPF switch.
 */
#ifndef NETSUM_BPF_COMPAT_H
#define NETSUM_BPF_COMPAT_H

#include <stdint.h>

/* ---- SEC() / license macros (libbpf convention) ---- */
#define SEC(name) __attribute__((section(name), used))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* ---- XDP program return codes (uapi/linux/bpf.h, enum xdp_action) ---- */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

/* ---- xdp_md context (uapi/linux/bpf.h struct xdp_md) ----
 * data/data_end/data_meta are __u32 OFFSETS from a base the verifier
 * tracks, NOT raw pointers -- the standard, slightly surprising XDP
 * convention every real xdp program has to cast through. */
struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t ingress_ifindex;
    uint32_t rx_queue_index;
    uint32_t egress_ifindex;
};

/* ---- BPF map type + map-definition convention (BTF-style, matches
 * modern libbpf's `struct { __uint(...); ... } SEC(".maps");` idiom) ---- */
#define BPF_MAP_TYPE_HASH 1

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* ---- bpf_spin_lock (uapi/linux/bpf.h struct bpf_spin_lock) ----
 * Opaque 4-byte lock word; the verifier enforces its own rules about where
 * this field may appear (must be the only thing accessed between lock/
 * unlock, no helper calls while held except a narrow allowlist) -- this
 * struct's layout is the one piece of real kernel ABI that must match
 * exactly, since the verifier inspects it by field, not just by size. */
struct bpf_spin_lock {
    uint32_t val;
};

/* ---- Helper function declarations ----
 * BPF helpers are called through fixed, ABI-stable integer IDs cast to a
 * function pointer at compile time -- this is not a linker trick, it's how
 * every real BPF program invokes kernel helpers, verbatim from libbpf's
 * bpf_helper_defs.h. The verifier resolves these calls to real kernel
 * functions at load time based on the ID encoded in the instruction, not
 * by symbol name -- so an -O2 build with these exact signatures produces
 * byte-identical instructions to building against the real libbpf header.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) = (void *)44;
static void (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static void (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
static long (*bpf_trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *)6;

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

/* be16/be32 helpers -- big-endian wire values need converting on the
 * (little-endian, x86_64/arm64) hosts this program actually loads on;
 * doing this by hand rather than pulling in <arpa/inet.h> (a libc header,
 * not meaningful inside a freestanding BPF program with no libc). */
static __always_inline uint16_t netsum_bpf_ntohs(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}
static __always_inline uint32_t netsum_bpf_ntohl(uint32_t v) {
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8) | ((v & 0xff000000u) >> 24);
}
#define netsum_bpf_htons netsum_bpf_ntohs
#define netsum_bpf_htonl netsum_bpf_ntohl

char _license[] SEC("license") = "GPL";

#endif /* NETSUM_BPF_COMPAT_H */
