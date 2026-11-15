/* BPF map key/value layouts, shared by xdp_agg.c and every userspace tool
 * that reads or writes the maps (config loader, bpf-unit harness, netsum-ctl).
 * One definition; sizes are pinned with static asserts. */
#ifndef NETSUM_MAPS_H
#define NETSUM_MAPS_H

#include <stdint.h>

#include "grad_proto.h"

#ifdef __bpf__
#define NETSUM_LOCK_T struct bpf_spin_lock
#else
#define NETSUM_LOCK_T struct { uint32_t val; }
#endif

enum netsum_slot_state {
    NETSUM_SLOT_EMPTY = 0,
    NETSUM_SLOT_ACCUMULATING = 1,
    NETSUM_SLOT_COMPLETED = 2,
    NETSUM_SLOT_FLUSHED = 3,
};

enum netsum_quota_policy {
    NETSUM_QUOTA_NONE = 0,
    NETSUM_QUOTA_DROP = 1,
    NETSUM_QUOTA_FALLBACK = 2,
};

struct grad_slot_key {
    uint32_t job_id;
    uint32_t round;
    uint32_t chunk_id;
};

struct grad_slot {
    NETSUM_LOCK_T lock;
    uint8_t state;            /* enum netsum_slot_state */
    uint8_t overflowed;       /* sticky: some lane overflowed */
    uint8_t charged;          /* holds one unit of its job's quota */
    uint8_t _pad0;
    uint16_t fanin;
    uint16_t chunk_len;
    uint16_t contributors;
    uint16_t _pad1;
    uint64_t last_touched_ns; /* bpf_ktime_get_ns() (CLOCK_MONOTONIC) */
    uint8_t bitmap[NETSUM_BITMAP_BYTES];
    int32_t sum[NETSUM_MAX_CHUNK_LEN];
};

/* config_map[0]. Addresses and ports are stored in network byte order. */
struct netsum_config {
    uint8_t ps_mac[6];
    uint8_t agg_mac[6];        /* all-zero: keep the frame's source MAC */
    uint32_t ps_ip;
    uint32_t agg_ip;           /* 0: keep the frame's source IP */
    uint16_t ps_port;
    uint16_t ack_port;
    uint32_t egress_ifindex;   /* 0 or ingress: XDP_TX; otherwise bpf_redirect */
    uint32_t max_slots_per_job;/* 0: no quota */
    uint32_t quota_policy;     /* enum netsum_quota_policy */
    uint32_t slot_ttl_ms;      /* read by the userspace sweeper */
};

struct job_quota_entry {
    uint32_t concurrent_slots; /* charged ACCUMULATING slots */
    uint32_t _pad;
};

NETSUM_STATIC_ASSERT(sizeof(struct grad_slot_key) == 12, "grad_slot_key layout");
NETSUM_STATIC_ASSERT(sizeof(struct grad_slot) == 312, "grad_slot layout");
NETSUM_STATIC_ASSERT(sizeof(struct netsum_config) == 40, "netsum_config layout");
NETSUM_STATIC_ASSERT(sizeof(struct job_quota_entry) == 8, "job_quota_entry layout");

#endif /* NETSUM_MAPS_H */
