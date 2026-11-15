/* NetSum XDP aggregator: sums gradient contributions in the kernel receive
 * path and forwards one aggregate per (job, round, chunk) to the parameter
 * server. Same state machine and admission rules as userspace_agg/agg.c:
 * EMPTY -> ACCUMULATING -> COMPLETED (tombstone, kept until ACK or TTL).
 *
 * Invariants: every packet access is bounds-checked against data_end in the
 * same basic block; no helper is called while a slot's spin lock is held;
 * at most one lock is held at a time.
 * Design: docs/DESIGN_NOTES.md §Admission, §Concurrency, §Verifier constraints. */
#ifdef NETSUM_USE_SYSTEM_LIBBPF
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#else
#include "bpf_compat.h"
#endif

#include "../protocol/grad_parse.h"
#include "../protocol/netsum_maps.h"
#include "../protocol/netsum_stats.h"

char _license[] SEC("license") = "GPL";

struct netsum_eth {
    uint8_t h_dest[6];
    uint8_t h_source[6];
    uint16_t h_proto;
} __attribute__((packed));

struct netsum_ip {
    uint8_t ihl_version;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct netsum_udp {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

#define ETH_P_IP_BE 0x0008 /* htons(0x0800) */
#define IPPROTO_UDP_NUM 17
#define IP_MF_OFFSET_MASK_BE 0xFF3F /* htons(0x3FFF) */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct grad_slot_key);
    __type(value, struct grad_slot);
} slot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct netsum_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, struct job_quota_entry);
} job_quota_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NS_STAT__COUNT);
    __type(key, uint32_t);
    __type(value, uint64_t);
} stats SEC(".maps");

/* Zeroed template for new slots, so no 300-byte struct lives on the stack.
 * Per-CPU maps may not hold a spin lock, hence the lock-free twin type. */
struct grad_slot_init {
    uint32_t lock_placeholder;
    struct grad_slot_key tag;
    uint8_t state, overflowed, charged, _pad0;
    uint16_t fanin, chunk_len, contributors, _pad1;
    uint64_t last_touched_ns;
    uint8_t bitmap[NETSUM_BITMAP_BYTES];
    int32_t sum[NETSUM_MAX_CHUNK_LEN];
};

_Static_assert(sizeof(struct grad_slot_init) == sizeof(struct grad_slot), "template matches slot layout");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct grad_slot_init);
} slot_template SEC(".maps");

/* Array mode (ATP-style): a fixed pool of aggregators indexed by
 * netsum_slot_hash(key) & slot_mask, each tagged with the key that owns it.
 * A busy aggregator owned by another key means fallback to the PS. netsum-ctl
 * sets max_entries before load (--slots-log2). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, uint32_t);
    __type(value, struct grad_slot);
} agg_array SEC(".maps");

/* Keys that have fallen back: later contributions for them fall back too,
 * so no worker is aggregated both in-network and at the PS. LRU: an evicted
 * entry is safe because the PS merges by contributor set (DESIGN_NOTES §Fallback). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct grad_slot_key);
    __type(value, uint8_t);
} fallback_keys SEC(".maps");

static __always_inline void stat_inc(uint32_t id)
{
    uint64_t *v = bpf_map_lookup_elem(&stats, &id);
    if (v)
        (*v)++;
}

/* Reserve one quota unit before creating a slot (bug C8): the atomic add
 * returns the previous value, so concurrent CPUs cannot all pass the check. */
static __always_inline int quota_reserve(uint32_t job_id, uint32_t max)
{
    struct job_quota_entry *jq = bpf_map_lookup_elem(&job_quota_map, &job_id);
    if (!jq) {
        struct job_quota_entry fresh = {0, 0};
        bpf_map_update_elem(&job_quota_map, &job_id, &fresh, BPF_NOEXIST);
        jq = bpf_map_lookup_elem(&job_quota_map, &job_id);
        if (!jq)
            return -1; /* job table full: fail closed (bug C7) */
    }
    uint32_t old = __sync_fetch_and_add(&jq->concurrent_slots, 1);
    if (old >= max) {
        __sync_fetch_and_sub(&jq->concurrent_slots, 1);
        return -2;
    }
    return 0;
}

/* Saturating decrement; frees the job's entry when it reaches zero. */
static __always_inline void quota_release(uint32_t job_id)
{
    struct job_quota_entry *jq = bpf_map_lookup_elem(&job_quota_map, &job_id);
    if (!jq)
        return;
    for (int i = 0; i < 4; i++) {
        uint32_t cur = jq->concurrent_slots;
        if (cur == 0)
            return;
        if (__sync_val_compare_and_swap(&jq->concurrent_slots, cur, cur - 1) == cur) {
            if (cur == 1)
                bpf_map_delete_elem(&job_quota_map, &job_id);
            return;
        }
    }
}

static __always_inline uint16_t ip_checksum(const struct netsum_ip *iph)
{
    const uint16_t *w = (const uint16_t *)iph;
    uint32_t sum = 0;
#pragma unroll
    for (int i = 0; i < 10; i++)
        if (i != 5)
            sum += w[i];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

enum outcome {
    OUT_ACCEPTED = 0,
    OUT_COMPLETED,       /* forward the aggregate */
    OUT_RESEND_RESULT,   /* RESEND on a completed slot: forward the stored aggregate again */
    OUT_FLUSH,           /* RESEND of a held worker: forward the partial, slot -> FLUSHED */
    OUT_FALLBACK,        /* contribution to a FLUSHED slot: forward it raw, flagged FALLBACK */
    OUT_COLLISION,       /* array mode: aggregator owned by another key -> FALLBACK */
    OUT_DUPLICATE,
    OUT_RESEND_DUPLICATE,
    OUT_LATE,
    OUT_FANIN_MISMATCH,
    OUT_CHUNK_LEN_MISMATCH,
};

/* Copies a slot's sum (and, for v2, its contributor bitmap) into the packet.
 * Called with the slot lock held: no helpers, bounds checked per access. */
static __always_inline void copy_slot_out(struct grad_slot *slot, int32_t *values, uint16_t chunk_len,
                                          int v2, void *data_end)
{
    for (int i = 0; i < NETSUM_MAX_CHUNK_LEN; i++) {
        if (i >= chunk_len)
            break;
        if ((void *)(values + i + 1) > data_end)
            break;
        values[i] = (int32_t)netsum_htonl((uint32_t)slot->sum[i]);
    }
    if (!v2)
        return;
    uint8_t *bm = (uint8_t *)(values + chunk_len);
    if ((void *)(bm + NETSUM_BITMAP_BYTES) > data_end)
        return;
#pragma unroll
    for (int b = 0; b < NETSUM_BITMAP_BYTES; b++)
        bm[b] = slot->bitmap[b];
}

/* ACK from the parameter server: the key is finished, drop our state. An ACK
 * for a slot that is still accumulating means the PS completed the key from
 * fallbacks or partials, so our partial sum is stale. */
static __always_inline int handle_ack(const struct netsum_parsed *p, const struct netsum_config *cfg)
{
    stat_inc(NS_ACK_SEEN);
    struct grad_slot_key key = {p->job_id, p->round, p->chunk_id};
    bpf_map_delete_elem(&fallback_keys, &key);
    int array = cfg && cfg->slot_mode == NETSUM_SLOT_MODE_ARRAY;
    struct grad_slot *slot;
    if (array) {
        uint32_t idx = netsum_slot_hash(key.job_id, key.round, key.chunk_id) & cfg->slot_mask;
        slot = bpf_map_lookup_elem(&agg_array, &idx);
    } else {
        slot = bpf_map_lookup_elem(&slot_map, &key);
    }
    if (!slot) {
        stat_inc(NS_ACK_UNEXPECTED);
        return XDP_DROP;
    }
    int accumulating, charged, owned = 1;
    bpf_spin_lock(&slot->lock);
    if (array && (slot->state == NETSUM_SLOT_EMPTY || slot->tag.job_id != key.job_id ||
                  slot->tag.round != key.round || slot->tag.chunk_id != key.chunk_id))
        owned = 0; /* the aggregator now belongs to another key */
    accumulating = slot->state == NETSUM_SLOT_ACCUMULATING;
    charged = owned ? slot->charged : 0;
    if (owned) {
        slot->charged = 0;
        slot->state = NETSUM_SLOT_EMPTY;
    }
    bpf_spin_unlock(&slot->lock);
    if (!owned) {
        stat_inc(NS_ACK_UNEXPECTED);
        return XDP_DROP;
    }
    if (!array)
        bpf_map_delete_elem(&slot_map, &key);
    if (charged)
        quota_release(p->job_id);
    stat_inc(accumulating ? NS_ACK_UNEXPECTED : NS_SLOT_RETIRED_ACK);
    return XDP_DROP;
}

SEC("xdp")
int netsum_xdp_aggregate(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct netsum_eth *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != ETH_P_IP_BE)
        return XDP_PASS;
    struct netsum_ip *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || (iph->ihl_version >> 4) != 4 ||
        iph->protocol != IPPROTO_UDP_NUM)
        return XDP_PASS;
    if ((iph->ihl_version & 0x0f) != 5) {
        stat_inc(NS_PASS_IP_OPTIONS);
        return XDP_PASS;
    }
    if (iph->frag_off & IP_MF_OFFSET_MASK_BE) {
        stat_inc(NS_PASS_FRAGMENT);
        return XDP_PASS;
    }
    struct netsum_udp *udp = (void *)(iph + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != netsum_htons(NETSUM_PORT)) {
        stat_inc(NS_PASS_NOT_OURS);
        return XDP_PASS;
    }
    stat_inc(NS_RX_TOTAL);

    /* Frames may carry Ethernet padding, so the UDP length (not data_end)
     * bounds the payload; it must agree with the IP length and the frame. */
    uint16_t udp_len = netsum_ntohs(udp->len);
    if (udp_len < sizeof(*udp) || netsum_ntohs(iph->tot_len) != sizeof(*iph) + udp_len ||
        (void *)udp + udp_len > data_end) {
        stat_inc(NS_REJ_UDP_LEN);
        return XDP_DROP;
    }

    struct netsum_parsed p;
    void *payload = (void *)(udp + 1);
    enum netsum_verdict v = netsum_parse(payload, data_end, &p);
    if (v == NETSUM_OK && NETSUM_HDR_SIZE + p.payload_len > (uint32_t)udp_len - sizeof(*udp))
        v = NETSUM_REJ_TRUNCATED;
    if (v != NETSUM_OK) {
        stat_inc(NS_FROM_VERDICT(v));
        return XDP_DROP;
    }
    uint32_t cfg_key = 0;
    struct netsum_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (p.kind == NETSUM_KIND_ACK)
        return handle_ack(&p, cfg);
    if (p.kind == NETSUM_KIND_REGISTER) {
        stat_inc(NS_PASS_CONTROL);
        return XDP_PASS;
    }
    if (p.kind != NETSUM_KIND_RAW) {
        stat_inc(NS_REJ_KIND);
        return XDP_PASS;
    }
    uint16_t chunk_len = p.chunk_len;
    if (chunk_len > NETSUM_MAX_CHUNK_LEN)
        return XDP_DROP; /* already guaranteed by the parser; bounds it for the verifier */
    int v2 = p.version == NETSUM_VERSION_V2;
    int resend = (p.flags & NETSUM_F_RESEND) != 0;

    struct grad_slot_key key = {p.job_id, p.round, p.chunk_id};
    uint64_t now = bpf_ktime_get_ns();
    int array = cfg && cfg->slot_mode == NETSUM_SLOT_MODE_ARRAY;
    int fallback_policy = cfg && cfg->quota_policy == NETSUM_QUOTA_FALLBACK;
    int outcome = OUT_ACCEPTED;
    struct grad_slot *slot = 0;
    /* Everything the forwarding tail reads is initialised before the first
     * goto: jumping over an initialiser leaves the value undefined, and the
     * compiler may then spill a clobbered register the verifier rejects. */
    int32_t *values = (int32_t *)((uint8_t *)payload + NETSUM_HDR_SIZE);
    int release_quota = 0, overflowed = 0, copy_out = 0;
    uint16_t fanin = 0, agg_flags = 0;

    if ((array || fallback_policy) && bpf_map_lookup_elem(&fallback_keys, &key)) {
        outcome = OUT_FALLBACK; /* this key already lives at the PS */
        goto forward;
    }
    if (array) {
        uint32_t idx = netsum_slot_hash(key.job_id, key.round, key.chunk_id) & cfg->slot_mask;
        slot = bpf_map_lookup_elem(&agg_array, &idx);
        if (!slot)
            return XDP_DROP;
        goto locked;
    }
    slot = bpf_map_lookup_elem(&slot_map, &key);
    if (!slot) {
        uint32_t max = cfg ? cfg->max_slots_per_job : 0;
        int charged = 0;
        if (max) {
            int rc = quota_reserve(p.job_id, max);
            if (rc == -1) {
                stat_inc(NS_DROP_JOB_TABLE_FULL);
                return XDP_DROP;
            }
            if (rc == -2) {
                if (fallback_policy) { /* degrade to the PS instead of dropping */
                    uint8_t one = 1;
                    bpf_map_update_elem(&fallback_keys, &key, &one, BPF_ANY);
                    stat_inc(NS_FALLBACK_QUOTA);
                    outcome = OUT_FALLBACK;
                    goto forward;
                }
                stat_inc(NS_DROP_QUOTA);
                return XDP_DROP;
            }
            charged = 1;
        }
        uint32_t zero = 0;
        struct grad_slot_init *tmpl = bpf_map_lookup_elem(&slot_template, &zero);
        if (!tmpl) {
            if (charged)
                quota_release(p.job_id);
            return XDP_DROP;
        }
        tmpl->state = NETSUM_SLOT_ACCUMULATING;
        tmpl->fanin = p.num_workers;
        tmpl->chunk_len = chunk_len;
        tmpl->charged = (uint8_t)charged;
        tmpl->last_touched_ns = now;
        long rc = bpf_map_update_elem(&slot_map, &key, tmpl, BPF_NOEXIST);
        if (rc == 0) {
            stat_inc(NS_SLOT_CREATED);
        } else if (charged) {
            quota_release(p.job_id); /* lost the creation race, or the map is full */
        }
        slot = bpf_map_lookup_elem(&slot_map, &key);
        if (!slot) {
            if (fallback_policy) {
                uint8_t one = 1;
                bpf_map_update_elem(&fallback_keys, &key, &one, BPF_ANY);
                stat_inc(NS_FALLBACK_COLLISION); /* no aggregator available */
                outcome = OUT_FALLBACK;
                goto forward;
            }
            stat_inc(NS_DROP_MAP_FULL);
            return XDP_DROP;
        }
    }

locked:

    bpf_spin_lock(&slot->lock);
    if (array && slot->state == NETSUM_SLOT_EMPTY) { /* claim a free aggregator */
        slot->tag = key;
        slot->state = NETSUM_SLOT_ACCUMULATING;
        slot->fanin = p.num_workers;
        slot->chunk_len = chunk_len;
        slot->contributors = 0;
        slot->overflowed = 0;
        slot->charged = 0;
        slot->last_touched_ns = now;
#pragma unroll
        for (int b = 0; b < NETSUM_BITMAP_BYTES; b++)
            slot->bitmap[b] = 0;
        for (int i = 0; i < NETSUM_MAX_CHUNK_LEN; i++)
            slot->sum[i] = 0;
    }
    int held = (slot->bitmap[(p.worker_id >> 3) & 31] >> (p.worker_id & 7)) & 1;
    if (array && (slot->tag.job_id != key.job_id || slot->tag.round != key.round ||
                  slot->tag.chunk_id != key.chunk_id)) {
        outcome = OUT_COLLISION; /* aggregator busy with another key */
    } else if (p.num_workers != slot->fanin) {
        outcome = OUT_FANIN_MISMATCH;
    } else if (chunk_len != slot->chunk_len) {
        outcome = OUT_CHUNK_LEN_MISMATCH;
    } else if (slot->state == NETSUM_SLOT_COMPLETED) {
        if (resend) { /* the aggregate or the PS's result was lost */
            outcome = OUT_RESEND_RESULT;
            copy_out = 1;
        } else {
            outcome = OUT_LATE;
        }
    } else if (slot->state == NETSUM_SLOT_FLUSHED) {
        outcome = (held && !resend) ? OUT_DUPLICATE : (v2 ? OUT_FALLBACK : OUT_LATE);
    } else if (slot->state != NETSUM_SLOT_ACCUMULATING) {
        outcome = OUT_LATE;
    } else if (held) {
        if (resend && v2) { /* stuck round: hand the partial to the PS (ATP flush) */
            outcome = OUT_FLUSH;
            copy_out = 1;
            slot->state = NETSUM_SLOT_FLUSHED;
            slot->last_touched_ns = now;
            release_quota = slot->charged;
            slot->charged = 0;
        } else {
            outcome = resend ? OUT_RESEND_DUPLICATE : OUT_DUPLICATE;
        }
    } else {
        int completing = slot->contributors + 1 == slot->fanin;
        for (int i = 0; i < NETSUM_MAX_CHUNK_LEN; i++) {
            if (i >= chunk_len)
                break;
            if ((void *)(values + i + 1) > data_end)
                break;
            int32_t acc = slot->sum[i];
            slot->overflowed |= (uint8_t)netsum_add_i32(&acc, (int32_t)netsum_ntohl((uint32_t)values[i]));
            slot->sum[i] = acc;
            if (completing)
                values[i] = (int32_t)netsum_htonl((uint32_t)acc);
        }
        slot->bitmap[(p.worker_id >> 3) & 31] |= (uint8_t)(1u << (p.worker_id & 7));
        slot->contributors++;
        slot->last_touched_ns = now;
        if (completing) {
            outcome = OUT_COMPLETED;
            slot->state = NETSUM_SLOT_COMPLETED;
            release_quota = slot->charged;
            slot->charged = 0;
            if (v2) {
                uint8_t *bm = (uint8_t *)(values + chunk_len);
                if ((void *)(bm + NETSUM_BITMAP_BYTES) <= data_end) {
#pragma unroll
                    for (int b = 0; b < NETSUM_BITMAP_BYTES; b++)
                        bm[b] = slot->bitmap[b];
                }
            }
        }
    }
    if (copy_out)
        copy_slot_out(slot, values, chunk_len, v2, data_end);
    overflowed = slot->overflowed;
    fanin = slot->fanin;
    bpf_spin_unlock(&slot->lock);

    if (release_quota)
        quota_release(p.job_id);

    switch (outcome) {
    case OUT_ACCEPTED:
        stat_inc(NS_ACCEPTED);
        return XDP_DROP; /* consumed into the slot */
    case OUT_DUPLICATE:
        stat_inc(NS_DUPLICATE);
        return XDP_DROP;
    case OUT_RESEND_DUPLICATE:
        stat_inc(NS_RESEND_DUPLICATE);
        return XDP_DROP;
    case OUT_LATE:
        stat_inc(NS_LATE_DUPLICATE);
        return XDP_DROP;
    case OUT_FANIN_MISMATCH:
        stat_inc(NS_NUM_WORKERS_MISMATCH);
        return XDP_DROP;
    case OUT_CHUNK_LEN_MISMATCH:
        stat_inc(NS_CHUNK_LEN_MISMATCH);
        return XDP_DROP;
    case OUT_COMPLETED:
        stat_inc(NS_ACCEPTED);
        stat_inc(NS_SLOT_COMPLETED);
        if (overflowed)
            stat_inc(NS_OVERFLOW);
        break;
    case OUT_RESEND_RESULT:
        stat_inc(NS_TX_RESULT_RESEND);
        break;
    case OUT_FLUSH:
        stat_inc(NS_RESEND_DUPLICATE);
        stat_inc(NS_SLOT_FLUSHED_PARTIAL);
        agg_flags = NETSUM_F_PARTIAL;
        break;
    case OUT_COLLISION: {
        uint8_t one = 1;
        bpf_map_update_elem(&fallback_keys, &key, &one, BPF_ANY);
        stat_inc(NS_FALLBACK_COLLISION);
        outcome = OUT_FALLBACK;
        break;
    }
    default: /* OUT_FALLBACK */
        break;
    }

forward:
    if (outcome == OUT_FALLBACK && !v2) {
        stat_inc(NS_LATE_DUPLICATE); /* v1 has no FALLBACK flag */
        return XDP_DROP;
    }

    if (!cfg) {
        stat_inc(NS_DROP_NO_CONFIG);
        return XDP_DROP;
    }
    if (iph->ttl <= 1) {
        stat_inc(NS_REJ_TTL);
        return XDP_DROP;
    }
    struct grad_hdr *h = payload;
    if ((void *)(h + 1) > data_end)
        return XDP_DROP;
    if (outcome == OUT_FALLBACK) {
        h->flags = netsum_htons((uint16_t)(p.flags | NETSUM_F_FALLBACK));
        stat_inc(NS_TX_FALLBACK);
    } else if (v2) {
        h->worker_id = netsum_htons(NETSUM_WORKER_AGGREGATE);
        h->num_workers = netsum_htons(fanin);
        h->flags = netsum_htons((uint16_t)(NETSUM_FLAGS_V2 | agg_flags | (overflowed ? NETSUM_F_OVERFLOW : 0)));
        stat_inc(agg_flags ? NS_TX_PARTIAL : NS_TX_AGGREGATE);
    } else {
        if (overflowed)
            return XDP_DROP; /* v1 cannot signal overflow; counted above */
        h->worker_id = 0;  /* legacy v1 aggregate: worker 0 of fan-in 1 */
        h->num_workers = netsum_htons(1);
        stat_inc(NS_TX_AGGREGATE);
    }

    /* Shared forwarding tail: address everything we emit to the PS. */
    for (int i = 0; i < 6; i++)
        eth->h_dest[i] = cfg->ps_mac[i];
    if (cfg->agg_mac[0] | cfg->agg_mac[1] | cfg->agg_mac[2] | cfg->agg_mac[3] | cfg->agg_mac[4] | cfg->agg_mac[5])
        for (int i = 0; i < 6; i++)
            eth->h_source[i] = cfg->agg_mac[i];
    if (cfg->agg_ip)
        iph->saddr = cfg->agg_ip;
    iph->daddr = cfg->ps_ip;
    iph->ttl--;
    iph->check = 0;
    iph->check = ip_checksum(iph);
    udp->dest = cfg->ps_port;
    udp->check = 0; /* optional for IPv4 (RFC 768) */
    if (cfg->egress_ifindex && cfg->egress_ifindex != ctx->ingress_ifindex)
        return bpf_redirect(cfg->egress_ifindex, 0);
    return XDP_TX;
}

/* TTL sweeper step, run from userspace with BPF_PROG_TEST_RUN (never
 * attached). Input: a frame whose payload is a grad_hdr naming the key,
 * followed by the TTL in ns (u64, host order) and room for a full packet.
 * Under the slot lock, an ACCUMULATING slot idle for longer than the TTL is
 * flushed: the frame is rewritten into a PARTIAL aggregate (XDP_TX tells the
 * caller to send it to the PS) and the slot becomes FLUSHED. An expired
 * COMPLETED or FLUSHED slot is deleted (XDP_DROP). Otherwise XDP_PASS.
 * Doing the transition here keeps every slot write under the kernel lock. */
SEC("xdp")
int netsum_sweep(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct grad_hdr *h = (struct grad_hdr *)((uint8_t *)data + NETSUM_SWEEP_PAYLOAD_OFFSET);
    int32_t *values = (int32_t *)(h + 1);
    if ((void *)(values + NETSUM_MAX_CHUNK_LEN) + NETSUM_BITMAP_BYTES > data_end)
        return XDP_ABORTED;
    uint64_t ttl_ns;
    __builtin_memcpy(&ttl_ns, values, sizeof(ttl_ns));
    /* flags == NETSUM_SWEEP_ARRAY_INDEX: job_id carries an agg_array index */
    int array = netsum_ntohs(h->flags) == NETSUM_SWEEP_ARRAY_INDEX;
    struct grad_slot_key key = {netsum_ntohl(h->job_id), netsum_ntohl(h->round), netsum_ntohl(h->chunk_id)};
    struct grad_slot *slot;
    if (array) {
        uint32_t idx = key.job_id;
        slot = bpf_map_lookup_elem(&agg_array, &idx);
    } else {
        slot = bpf_map_lookup_elem(&slot_map, &key);
    }
    if (!slot)
        return XDP_PASS;
    uint64_t now = bpf_ktime_get_ns();
    int action = XDP_PASS, release_quota = 0, overflowed = 0;
    uint16_t fanin = 0, chunk_len = 0;

    bpf_spin_lock(&slot->lock);
    if (array)
        key = slot->tag;
    if (slot->state != NETSUM_SLOT_EMPTY && now - slot->last_touched_ns >= ttl_ns) {
        if (slot->state == NETSUM_SLOT_ACCUMULATING) {
            action = XDP_TX;
            slot->state = NETSUM_SLOT_FLUSHED;
            slot->last_touched_ns = now;
            release_quota = slot->charged;
            slot->charged = 0;
            fanin = slot->fanin;
            chunk_len = slot->chunk_len;
            overflowed = slot->overflowed;
            if (chunk_len > NETSUM_MAX_CHUNK_LEN)
                chunk_len = NETSUM_MAX_CHUNK_LEN;
            copy_slot_out(slot, values, chunk_len, 1, data_end);
        } else {
            action = XDP_DROP;
            if (array)
                slot->state = NETSUM_SLOT_EMPTY;
        }
    }
    bpf_spin_unlock(&slot->lock);

    if (action == XDP_DROP) {
        if (!array)
            bpf_map_delete_elem(&slot_map, &key);
        stat_inc(NS_SLOT_RETIRED_TTL);
    } else if (action == XDP_TX) {
        h->job_id = netsum_htonl(key.job_id);
        h->round = netsum_htonl(key.round);
        h->chunk_id = netsum_htonl(key.chunk_id);
        if (release_quota)
            quota_release(key.job_id);
        h->worker_id = netsum_htons(NETSUM_WORKER_AGGREGATE);
        h->num_workers = netsum_htons(fanin);
        h->chunk_len = netsum_htons(chunk_len);
        h->flags = netsum_htons((uint16_t)(NETSUM_FLAGS_V2 | NETSUM_F_PARTIAL | (overflowed ? NETSUM_F_OVERFLOW : 0)));
        stat_inc(NS_SLOT_FLUSHED_PARTIAL);
        stat_inc(NS_TX_PARTIAL);
    }
    return action;
}
