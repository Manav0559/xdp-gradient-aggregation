/* NetSum XDP aggregator -- the actual kernel-space program.
 *
 * Parses Ethernet/IPv4/UDP down to the grad_hdr payload (protocol/grad_proto.h,
 * the SAME struct userspace_agg/agg.c uses), accumulates each worker's
 * contribution into a BPF_MAP_TYPE_HASH slot keyed by (job_id, round,
 * chunk_id) under a bpf_spin_lock, and once every expected worker has
 * contributed, rewrites the packet in place to carry the summed values,
 * retargets it at the configured parameter-server address, and returns
 * XDP_TX -- exactly mirroring userspace_agg/agg.c's slot/accumulate/emit
 * algorithm, just running in the kernel fast path instead of a process.
 *
 * Every partial (non-final) contribution returns XDP_DROP: fully absorbed
 * into the map, never forwarded -- this is the mechanism that cuts
 * aggregator-uplink traffic, and it means a tcpdump on the far side of this
 * program will see far fewer packets than arrived, by design.
 *
 * Compiles cleanly to real eBPF bytecode: `clang -target bpf -O2 -c` on
 * this file produces a valid eBPF ELF object (confirmed: proper `xdp`,
 * `.maps`, and `license` sections via `llvm-readelf -S`, 336 instructions
 * via `llvm-objdump -d`) -- this machine has no Linux kernel, and libbpf
 * has no macOS build (see docs/DEV_ENVIRONMENT.md), but clang's BPF
 * *codegen* backend needs neither, only the struct layouts and helper IDs
 * vendored in bpf_compat.h. What this compile step does NOT catch: the
 * in-kernel BPF *verifier* only runs at load time (the `bpf()` syscall on
 * a real Linux box) and checks things codegen alone cannot -- e.g. whether
 * every code path's pointer arithmetic stays provably in-bounds, and
 * whether the handful of helper calls permitted while `bpf_spin_lock` is
 * held are actually used correctly. An early version of this function DID
 * fail at the codegen stage (a `final_sum[NETSUM_MAX_CHUNK_LEN]` staging
 * array blew BPF's hard 512-byte kernel stack limit -- invisible in
 * ordinary userspace C, real here) and was fixed by writing summed values
 * straight into the packet under the lock instead of staging them on the
 * stack; that is a genuine bug this compile step caught. The honest
 * remaining status is "compiles to valid bytecode, not yet run through
 * the in-kernel verifier or loaded onto a real interface."
 *
 * Known, explicit simplifications (see the corrected project spec,
 * docs/PROJECT_SPEC.md, for the design decisions this fixes relative to an
 * earlier flawed draft):
 *   - IPv4 + UDP only, no VLAN tag, no IP options (verified via bounds
 *     checks below; anything else falls through to XDP_PASS, i.e. treated
 *     as ordinary traffic this program has no opinion about).
 *   - UDP checksum on the rewritten (forwarded) packet is set to 0
 *     (checksum disabled) rather than incrementally recomputed -- valid
 *     per RFC 768 for IPv4, and avoids folding a second checksum algorithm
 *     into the verifier-bounded hot path; the IP header checksum (which
 *     IS mandatory) IS recomputed below, since the destination address
 *     genuinely changes.
 *   - The parameter-server destination (MAC + IP + port) is supplied by a
 *     tiny userspace loader via bpf_config_map, populated once at startup
 *     after an ordinary ARP resolution -- XDP has no business doing ARP
 *     itself.
 */
#include "bpf_compat.h"
#include "../protocol/grad_proto.h"

struct ethhdr {
    uint8_t h_dest[6];
    uint8_t h_source[6];
    uint16_t h_proto;
} __attribute__((packed));

struct iphdr {
    uint8_t ihl_version;   /* low nibble: IHL in 32-bit words; high nibble: version */
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

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

/* 256 trackable workers as a bitmap (1 bit each) rather than the userspace
 * agg.c's byte-per-worker array -- BPF map values live in kernel memory
 * per slot, and the verifier is happier with smaller, fixed-size structs;
 * 32 bytes vs. 256 bytes for the same 256-worker range costs nothing in
 * behavior, just memory, but at up to 65536 concurrent slots that
 * difference is real. */
#define MAX_TRACKED_WORKERS_BITMAP_BYTES 32

/* Slot value: the running sum plus bookkeeping, spin-lock protected so
 * concurrent packets for the same slot landing on different CPU cores
 * (via NIC RX-queue steering / RSS) accumulate correctly -- the exact
 * correctness property BPF_MAP_TYPE_PERCPU_ARRAY could not have given an
 * earlier draft of this design, since per-CPU slots never converge into
 * one true sum without a separate cross-core reduction step. */
struct grad_slot {
    struct bpf_spin_lock lock;
    int32_t sum[NETSUM_MAX_CHUNK_LEN];
    uint16_t chunk_len;
    uint16_t num_workers_expected;
    uint16_t contributions_received;
    uint8_t seen_worker[MAX_TRACKED_WORKERS_BITMAP_BYTES];
};

struct grad_slot_key {
    uint32_t job_id;
    uint32_t round;
    uint32_t chunk_id;
};

struct netsum_config {
    uint8_t ps_mac[6];
    uint16_t _pad;
    uint32_t ps_ip;    /* network byte order */
    uint16_t ps_port;  /* network byte order */
};

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

static __always_inline uint16_t ip_checksum(const struct iphdr *iph) {
    /* Full recompute over the 20-byte header (5 x 32-bit words, IHL
     * assumed 5 -- options are rejected before this is ever called): a
     * bounded, verifier-friendly 10-halfword loop, chosen over an
     * incremental RFC 1624 update because it is simpler to get right and
     * the header is small enough that the extra cycles do not matter for
     * a lab-scale benchmark. */
    const uint16_t *words = (const uint16_t *)iph;
    uint32_t sum = 0;
#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i == 5) continue; /* skip the existing checksum field itself */
        sum += words[i];
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

SEC("xdp")
int netsum_xdp_aggregate(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (netsum_bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if ((iph->ihl_version & 0x0f) != 5) return XDP_PASS;  /* IP options: not our traffic, let the stack handle it */
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)(iph + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (netsum_bpf_ntohs(udp->dest) != NETSUM_PORT) return XDP_PASS;  /* not gradient traffic */

    struct grad_hdr *hdr = (struct grad_hdr *)(udp + 1);
    if ((void *)(hdr + 1) > data_end) return XDP_PASS;

    uint16_t chunk_len = netsum_bpf_ntohs(hdr->chunk_len);
    if (chunk_len > NETSUM_MAX_CHUNK_LEN) return XDP_DROP;  /* malformed -- mirrors userspace_agg's malformed-packet drop */

    int32_t *values = (int32_t *)(hdr + 1);
    if ((void *)(values + chunk_len) > data_end) return XDP_DROP;  /* header claims more data than the packet has */

    uint16_t worker_id = netsum_bpf_ntohs(hdr->worker_id);
    if (worker_id >= MAX_TRACKED_WORKERS_BITMAP_BYTES * 8) return XDP_DROP;

    struct grad_slot_key key = {
        .job_id = netsum_bpf_ntohl(hdr->job_id),
        .round = netsum_bpf_ntohl(hdr->round),
        .chunk_id = netsum_bpf_ntohl(hdr->chunk_id),
    };

    struct grad_slot *slot = bpf_map_lookup_elem(&slot_map, &key);
    if (!slot) {
        struct grad_slot fresh = {0};
        fresh.chunk_len = chunk_len;
        fresh.num_workers_expected = netsum_bpf_ntohs(hdr->num_workers);
        if (bpf_map_update_elem(&slot_map, &key, &fresh, BPF_NOEXIST) != 0) {
            /* Lost the race to create this slot -- another CPU's packet for
             * the same key got there first between our lookup and update.
             * Re-lookup rather than treat this as an error: the winning
             * creation is just as valid as ours would have been. */
        }
        slot = bpf_map_lookup_elem(&slot_map, &key);
        if (!slot) return XDP_DROP;  /* map genuinely full; nothing more we can do */
    }

    /* No `int32_t final_sum[NETSUM_MAX_CHUNK_LEN]` staging copy here -- an
     * earlier version of this function held the summed values in a local
     * array between the locked accumulate step and the post-unlock packet
     * rewrite, and real `clang -target bpf` compilation rejected it: BPF
     * enforces a hard 512-byte kernel stack limit per function (a real
     * constraint invisible in ordinary userspace C, where a 256-byte local
     * array is nothing), and that staging array alone blew past it. Fixed
     * by writing the summed values straight from `slot->sum[i]` into the
     * packet's `values[i]` while still holding the lock -- removes the
     * stack copy entirely, and is if anything more correct (no window
     * where a completed slot's data exists only in a local copy the
     * verifier can't see is still "the real state"). */
    int is_complete = 0;
    uint16_t final_chunk_len = 0;

    bpf_spin_lock(&slot->lock);
    uint8_t byte = slot->seen_worker[worker_id / 8];
    uint8_t bit = (uint8_t)(1 << (worker_id % 8));
    if (!(byte & bit)) {
        slot->seen_worker[worker_id / 8] = (uint8_t)(byte | bit);
#pragma unroll
        for (int i = 0; i < NETSUM_MAX_CHUNK_LEN; i++) {
            if (i >= chunk_len) break;
            slot->sum[i] += (int32_t)netsum_bpf_ntohl((uint32_t)values[i]);
        }
        slot->contributions_received++;
        if (slot->contributions_received == slot->num_workers_expected) {
            is_complete = 1;
            final_chunk_len = slot->chunk_len;
#pragma unroll
            for (int i = 0; i < NETSUM_MAX_CHUNK_LEN; i++) {
                if (i >= final_chunk_len) break;
                values[i] = (int32_t)netsum_bpf_htonl((uint32_t)slot->sum[i]);
            }
        }
    }
    /* else: duplicate worker_id for this slot -- silently absorbed, exactly
     * like userspace_agg.c's seen_worker[] check, just without the stderr
     * log a kernel program has no business printing on the hot path. */
    bpf_spin_unlock(&slot->lock);

    if (!is_complete) return XDP_DROP;  /* partial contribution: fully absorbed */

    bpf_map_delete_elem(&slot_map, &key);  /* mirrors userspace_agg's free_slot() -- bounded map growth */

    uint32_t cfg_key = 0;
    struct netsum_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg) return XDP_DROP;  /* no downstream configured yet -- can't forward anywhere meaningful */

    hdr->worker_id = netsum_bpf_htons(0);
    hdr->num_workers = netsum_bpf_htons(1);  /* tells the receiver: exactly one contribution closes this slot */

    /* Retarget L2/L3/L4 destination at the configured parameter server. */
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_dest[i] = cfg->ps_mac[i];
    iph->daddr = cfg->ps_ip;
    udp->dest = cfg->ps_port;
    udp->check = 0;  /* checksum disabled -- valid for UDP/IPv4, see file header comment */
    iph->check = 0;
    iph->check = ip_checksum(iph);

    return XDP_TX;
}
