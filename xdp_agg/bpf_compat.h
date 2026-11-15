/* Minimal vendored subset of <linux/bpf.h> + <bpf/bpf_helpers.h>, so the XDP
 * program compiles with any clang that has the BPF backend (e.g. Homebrew LLVM
 * on macOS) without kernel or libbpf headers. On Linux with libbpf installed
 * the Makefile defines NETSUM_USE_SYSTEM_LIBBPF and the real headers are used
 * instead; CI builds both and checks they produce the same program.
 * Helper IDs are checked against the runner's linux/bpf.h by
 * ci/check_helper_ids.py; do not add one without running that check. */
#ifndef NETSUM_BPF_COMPAT_H
#define NETSUM_BPF_COMPAT_H

#include <stdint.h>

#define SEC(name) __attribute__((section(name), used))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t ingress_ifindex;
    uint32_t rx_queue_index;
    uint32_t egress_ifindex;
};

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

/* libbpf BTF map-definition macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct bpf_spin_lock {
    uint32_t val;
};

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_redirect)(uint32_t ifindex, uint64_t flags) = (void *)23;
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;

#endif /* NETSUM_BPF_COMPAT_H */
