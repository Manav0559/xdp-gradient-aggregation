/* Unit tests for the loaded XDP program via BPF_PROG_TEST_RUN: each case
 * builds an Ethernet/IPv4/UDP/grad_hdr frame, runs the real verified program
 * on it, and checks the XDP action, the output frame, slot state and the
 * per-CPU stats. Also replays fuzz/corpus (plus seeded mutations) and checks
 * the kernel's verdicts against the userspace parser's.
 * Linux only; needs root (CAP_BPF + CAP_NET_ADMIN).
 * Usage: run_xdp_tests <xdp_agg.o> <fuzz corpus dir> */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../protocol/grad_parse.h"
#include "../../protocol/netsum_maps.h"
#include "../../protocol/netsum_stats.h"

static int array_fd, fallback_fd;
static int prog_fd, sweep_fd, slot_fd, config_fd, quota_fd, stats_fd, ncpus;
static int cases, failures;
static uint64_t snap[NS_STAT__COUNT];
static const char *current = "";

#define CHECK(cond, ...)                                              \
    do {                                                              \
        if (!(cond)) {                                                \
            failures++;                                               \
            fprintf(stderr, "FAIL [%s] line %d: ", current, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                             \
            fprintf(stderr, "\n");                                    \
        }                                                             \
    } while (0)

static const uint8_t PS_MAC[6] = {0x02, 0, 0, 0, 0, 0x99};
static const uint8_t AGG_MAC[6] = {0x02, 0, 0, 0, 0, 0xaa};
#define PS_IP 0x0a000063u   /* 10.0.0.99 */
#define AGG_IP 0x0a000001u  /* 10.0.0.1 */
#define PS_PORT 9000

struct frame {
    uint32_t job, round, chunk;
    uint16_t wid, nw, chunk_len, flags;
    int32_t val;          /* lane i carries val + i */
    int lanes_equal;      /* if set, every lane carries val */
    int v1;               /* legacy: no trailer, flags 0 */
    uint8_t ttl, ihl, proto;
    uint16_t frag, dport, eth_proto;
    int udp_len_delta;    /* corrupt udp->len */
    int drop_tail;        /* remove bytes from the end */
    const uint8_t *raw_payload; /* if set, use as grad payload verbatim */
    size_t raw_len;
};

static uint64_t stat_now(int id)
{
    uint64_t vals[512];
    uint32_t key = (uint32_t)id;
    if (bpf_map_lookup_elem(stats_fd, &key, vals))
        return 0;
    uint64_t s = 0;
    for (int c = 0; c < ncpus; c++)
        s += vals[c];
    return s;
}

static void begin(const char *name)
{
    current = name;
    cases++;
    for (int i = 0; i < NS_STAT__COUNT; i++)
        snap[i] = stat_now(i);
}

static uint64_t delta(int id) { return stat_now(id) - snap[id]; }

static uint16_t csum_ip(const uint8_t *ip)
{
    uint32_t s = 0;
    for (int i = 0; i < 20; i += 2)
        if (i != 10)
            s += (uint32_t)(ip[i] << 8 | ip[i + 1]);
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) << 16 | get16(p + 2); }

static size_t build(uint8_t *buf, struct frame f)
{
    memset(buf, 0, 2048);
    if (!f.ttl) f.ttl = 64;
    if (!f.ihl) f.ihl = 5;
    if (!f.proto) f.proto = 17;
    if (!f.dport) f.dport = NETSUM_PORT;
    if (!f.eth_proto) f.eth_proto = 0x0800;
    uint8_t *eth = buf, *ip = buf + 14, *udp = ip + 20, *pl = udp + 8;
    memcpy(eth, AGG_MAC, 6);
    const uint8_t src[6] = {0x02, 0, 0, 0, 0, 0x01};
    memcpy(eth + 6, src, 6);
    put16(eth + 12, f.eth_proto);

    size_t plen;
    if (f.raw_payload) {
        memcpy(pl, f.raw_payload, f.raw_len);
        plen = f.raw_len;
    } else {
        put32(pl, f.job);
        put32(pl + 4, f.round);
        put32(pl + 8, f.chunk);
        put16(pl + 12, f.wid);
        put16(pl + 14, f.nw);
        put16(pl + 16, f.chunk_len);
        put16(pl + 18, f.v1 ? f.flags : (uint16_t)(NETSUM_FLAGS_V2 | f.flags));
        plen = 20;
        for (int i = 0; i < f.chunk_len && i < 128; i++, plen += 4)
            put32(pl + plen, (uint32_t)(f.val + (f.lanes_equal ? 0 : i)));
        if (!f.v1) {
            if (f.wid < 256)
                pl[plen + f.wid / 8] = (uint8_t)(1u << (f.wid % 8));
            plen += 32;
        }
    }
    if (f.drop_tail)
        plen -= (size_t)f.drop_tail;
    ip[0] = (uint8_t)(0x40 | f.ihl);
    put16(ip + 2, (uint16_t)(20 + 8 + plen));
    put16(ip + 6, f.frag);
    ip[8] = f.ttl;
    ip[9] = f.proto;
    put32(ip + 12, 0x0a000002u);
    put32(ip + 16, AGG_IP);
    put16(ip + 10, csum_ip(ip));
    put16(udp, 40000);
    put16(udp + 2, f.dport);
    put16(udp + 4, (uint16_t)(8 + plen + f.udp_len_delta));
    size_t total = 14 + 20 + 8 + plen;
    return total < 60 ? 60 : total; /* Ethernet minimum frame, zero padded */
}

static int run(const uint8_t *in, size_t len, uint8_t *out, uint32_t *out_len)
{
    LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = in, .data_size_in = (uint32_t)len,
                .data_out = out, .data_size_out = 4096, .repeat = 1);
    int err = bpf_prog_test_run_opts(prog_fd, &o);
    if (err) {
        fprintf(stderr, "bpf_prog_test_run_opts: %s\n", strerror(errno));
        exit(2);
    }
    if (out_len)
        *out_len = o.data_size_out;
    return (int)o.retval;
}

static int send_frame(struct frame f, uint8_t *out)
{
    uint8_t in[2048];
    size_t len = build(in, f);
    return run(in, len, out, NULL);
}

static int slot_get(uint32_t job, uint32_t round, uint32_t chunk, struct grad_slot *s)
{
    struct grad_slot_key k = {job, round, chunk};
    return bpf_map_lookup_elem(slot_fd, &k, s) == 0;
}

static uint16_t g_slot_mode;
static uint32_t g_quota_policy = 0xFFFFFFFFu; /* default: drop if max_slots */

static void set_config(uint32_t max_slots, uint32_t egress)
{
    struct netsum_config c;
    memset(&c, 0, sizeof(c));
    memcpy(c.ps_mac, PS_MAC, 6);
    memcpy(c.agg_mac, AGG_MAC, 6);
    c.ps_ip = __builtin_bswap32(PS_IP);
    c.agg_ip = __builtin_bswap32(AGG_IP);
    c.ps_port = __builtin_bswap16(PS_PORT);
    c.egress_ifindex = egress;
    c.max_slots_per_job = max_slots;
    c.quota_policy = g_quota_policy != 0xFFFFFFFFu ? g_quota_policy : (max_slots ? NETSUM_QUOTA_DROP : NETSUM_QUOTA_NONE);
    c.slot_mode = g_slot_mode;
    c.slot_mask = 15; /* agg_array is sized to 16 before load */
    uint32_t zero = 0;
    if (bpf_map_update_elem(config_fd, &zero, &c, BPF_ANY))
        fprintf(stderr, "config update failed: %s\n", strerror(errno));
}

#define F(...) ((struct frame){__VA_ARGS__})

/* ---- not ours / pass paths ---------------------------------------------- */

static void test_pass_paths(void)
{
    uint8_t out[4096];
    begin("non-IPv4 ethertype passes");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .eth_proto = 0x86dd), out) == XDP_PASS, "action");
    begin("non-UDP passes");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .proto = 6), out) == XDP_PASS, "action");
    begin("other UDP port passes and is counted");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .dport = 53), out) == XDP_PASS, "action");
    CHECK(delta(NS_PASS_NOT_OURS) == 1, "pass_not_ours");
    begin("IP options pass and are counted");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .ihl = 6), out) == XDP_PASS, "action");
    CHECK(delta(NS_PASS_IP_OPTIONS) == 1, "pass_ip_options");
    begin("IPv4 fragment (MF) passes and is counted");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .frag = 0x2000), out) == XDP_PASS, "action");
    CHECK(delta(NS_PASS_FRAGMENT) == 1, "pass_fragment");
    begin("IPv4 non-first fragment passes");
    CHECK(send_frame(F(.job = 1, .nw = 1, .chunk_len = 1, .frag = 0x0010), out) == XDP_PASS, "action");
    CHECK(delta(NS_PASS_FRAGMENT) == 1, "pass_fragment");
    begin("REGISTER passes as control");
    CHECK(send_frame(F(.job = 1, .wid = 0, .nw = 2, .chunk_len = 0, .flags = NETSUM_F_REGISTER), out) == XDP_PASS, "action");
    CHECK(delta(NS_PASS_CONTROL) == 1, "pass_control");
    begin("ACK for an unknown key is consumed and counted");
    CHECK(send_frame(F(.job = 1, .wid = 0xFFFF, .nw = 2, .chunk_len = 1, .flags = NETSUM_F_ACK), out) == XDP_DROP, "action");
    CHECK(delta(NS_ACK_SEEN) == 1 && delta(NS_ACK_UNEXPECTED) == 1, "ack counters");
    begin("aggregate arriving at an aggregator passes, counted rej_kind");
    CHECK(send_frame(F(.job = 1, .wid = 0xFFFF, .nw = 2, .chunk_len = 1), out) == XDP_PASS, "action");
    CHECK(delta(NS_REJ_KIND) == 1, "rej_kind");
}

/* ---- parser verdicts ---------------------------------------------------- */

static void expect_reject(const char *name, struct frame f, int stat)
{
    uint8_t out[4096];
    begin(name);
    CHECK(send_frame(f, out) == XDP_DROP, "action");
    CHECK(delta(stat) == 1, "stat %d delta %llu", stat, (unsigned long long)delta(stat));
    CHECK(delta(NS_SLOT_CREATED) == 0, "no slot created");
}

static void test_verdicts(void)
{
    static const uint8_t short_hdr[10] = {0};
    expect_reject("short header", F(.raw_payload = short_hdr, .raw_len = 10), NS_REJ_SHORT_HDR);
    expect_reject("chunk_len > max", F(.job = 2, .nw = 1, .chunk_len = 65), NS_REJ_CHUNK_LEN_MAX);
    expect_reject("chunk_len 0", F(.job = 2, .nw = 1, .chunk_len = 0), NS_REJ_CHUNK_LEN_ZERO);
    expect_reject("truncated values", F(.job = 2, .nw = 1, .chunk_len = 4, .drop_tail = 40), NS_REJ_TRUNCATED);
    expect_reject("v2 missing trailer", F(.job = 2, .nw = 1, .chunk_len = 4, .drop_tail = 32), NS_REJ_TRUNCATED);
    expect_reject("fan-in 0", F(.job = 2, .nw = 0, .chunk_len = 1), NS_REJ_NUM_WORKERS);
    expect_reject("fan-in 257", F(.job = 2, .nw = 257, .chunk_len = 1), NS_REJ_NUM_WORKERS);
    expect_reject("worker_id >= fan-in (C2)", F(.job = 2, .wid = 10, .nw = 3, .chunk_len = 1), NS_REJ_WORKER_ID);
    expect_reject("unknown version", F(.job = 2, .nw = 1, .chunk_len = 1, .v1 = 1, .flags = 0x3000), NS_REJ_VERSION);
    expect_reject("reserved flag bit", F(.job = 2, .nw = 1, .chunk_len = 1, .flags = 0x0040), NS_REJ_RESERVED_FLAGS);
    expect_reject("v1 with flags", F(.job = 2, .nw = 1, .chunk_len = 1, .v1 = 1, .flags = 1), NS_REJ_RESERVED_FLAGS);
    expect_reject("PARTIAL from a worker", F(.job = 2, .nw = 1, .chunk_len = 1, .flags = NETSUM_F_PARTIAL), NS_REJ_FLAG_COMBO);
    expect_reject("udp->len too long", F(.job = 2, .nw = 1, .chunk_len = 1, .udp_len_delta = 4), NS_REJ_UDP_LEN);
    expect_reject("udp->len too short for payload", F(.job = 2, .nw = 1, .chunk_len = 1, .udp_len_delta = -4), NS_REJ_UDP_LEN);
}

/* ---- state machine -------------------------------------------------------- */

static void check_aggregate_frame(const uint8_t *out, uint16_t fanin, uint16_t chunk_len,
                                  int32_t expect_lane0, int overflow)
{
    const uint8_t *ip = out + 14, *udp = ip + 20, *pl = udp + 8;
    CHECK(memcmp(out, PS_MAC, 6) == 0, "dst mac rewritten");
    CHECK(memcmp(out + 6, AGG_MAC, 6) == 0, "src mac rewritten (C9)");
    CHECK(get32(ip + 16) == PS_IP, "daddr");
    CHECK(get32(ip + 12) == AGG_IP, "saddr rewritten (C9)");
    CHECK(ip[8] == 63, "ttl decremented (G11): %u", ip[8]);
    CHECK(get16(ip + 10) == csum_ip(ip), "ip checksum valid");
    CHECK(get16(udp + 2) == PS_PORT, "udp dport");
    CHECK(get16(pl + 12) == 0xFFFF, "worker_id = aggregate");
    CHECK(get16(pl + 14) == fanin, "num_workers = fan-in");
    CHECK(get16(pl + 16) == chunk_len, "chunk_len");
    uint16_t fl = get16(pl + 18);
    CHECK(fl >> 12 == 2, "v2");
    CHECK(!!(fl & NETSUM_F_OVERFLOW) == overflow, "overflow flag %d", !!(fl & NETSUM_F_OVERFLOW));
    if (!overflow)
        CHECK((int32_t)get32(pl + 20) == expect_lane0, "lane 0 = %d, want %d", (int32_t)get32(pl + 20), expect_lane0);
    unsigned pc = 0;
    for (int i = 0; i < 32; i++)
        pc += (unsigned)__builtin_popcount(pl[20 + 4 * chunk_len + i]);
    CHECK(pc == fanin, "bitmap popcount %u", pc);
}

static void test_state_machine(void)
{
    uint8_t out[4096];
    struct grad_slot s;

    begin("fan-in 1 completes immediately, frame rewritten");
    CHECK(send_frame(F(.job = 100, .nw = 1, .chunk_len = 4, .val = 7), out) == XDP_TX, "action");
    check_aggregate_frame(out, 1, 4, 7, 0);
    CHECK(slot_get(100, 0, 0, &s) && s.state == NETSUM_SLOT_COMPLETED, "tombstone kept (C1)");
    CHECK(delta(NS_TX_AGGREGATE) == 1 && delta(NS_SLOT_COMPLETED) == 1, "counters");

    begin("first contribution of 3 is consumed");
    CHECK(send_frame(F(.job = 101, .wid = 0, .nw = 3, .chunk_len = 4, .val = 10), out) == XDP_DROP, "action");
    CHECK(slot_get(101, 0, 0, &s) && s.state == NETSUM_SLOT_ACCUMULATING && s.contributors == 1, "accumulating 1/3");
    CHECK(s.last_touched_ns > 0, "last_touched_ns stamped");
    uint64_t t1 = s.last_touched_ns;
    CHECK(delta(NS_ACCEPTED) == 1 && delta(NS_SLOT_CREATED) == 1, "accepted");

    begin("duplicate worker is counted, not summed");
    CHECK(send_frame(F(.job = 101, .wid = 0, .nw = 3, .chunk_len = 4, .val = 10), out) == XDP_DROP, "action");
    CHECK(delta(NS_DUPLICATE) == 1, "duplicate");
    begin("fan-in disagreement is rejected (C3)");
    CHECK(send_frame(F(.job = 101, .wid = 1, .nw = 4, .chunk_len = 4, .val = 10), out) == XDP_DROP, "action");
    CHECK(delta(NS_NUM_WORKERS_MISMATCH) == 1, "mismatch");
    begin("chunk_len disagreement is rejected");
    CHECK(send_frame(F(.job = 101, .wid = 1, .nw = 3, .chunk_len = 2, .val = 10), out) == XDP_DROP, "action");
    CHECK(delta(NS_CHUNK_LEN_MISMATCH) == 1, "chunk_len mismatch");
    CHECK(slot_get(101, 0, 0, &s) && s.contributors == 1, "slot untouched by rejects");
    CHECK(s.last_touched_ns == t1, "rejects do not refresh last_touched_ns");

    begin("second contribution");
    CHECK(send_frame(F(.job = 101, .wid = 1, .nw = 3, .chunk_len = 4, .val = 20), out) == XDP_DROP, "action");
    CHECK(slot_get(101, 0, 0, &s) && s.last_touched_ns > t1, "last_touched_ns advanced");
    begin("completing contribution forwards the sum");
    CHECK(send_frame(F(.job = 101, .wid = 2, .nw = 3, .chunk_len = 4, .val = 30), out) == XDP_TX, "action");
    check_aggregate_frame(out, 3, 4, 60, 0);
    const uint8_t *lanes = out + 14 + 20 + 8 + 20;
    CHECK((int32_t)get32(lanes + 12) == 60 + 9, "lane 3 = 3 workers x lane offset");
    begin("late duplicate after completion is absorbed (C1)");
    CHECK(send_frame(F(.job = 101, .wid = 1, .nw = 3, .chunk_len = 4, .val = 20), out) == XDP_DROP, "action");
    CHECK(delta(NS_LATE_DUPLICATE) == 1 && delta(NS_SLOT_CREATED) == 0, "late, no new slot");
    CHECK(slot_get(101, 0, 0, &s) && s.state == NETSUM_SLOT_COMPLETED, "still a tombstone");

    begin("fan-in-1 claim closes the round; later fan-in-3 workers are absorbed (C3/L2)");
    CHECK(send_frame(F(.job = 102, .wid = 0, .nw = 1, .chunk_len = 1, .val = 1), out) == XDP_TX, "first");
    CHECK(send_frame(F(.job = 102, .wid = 1, .nw = 3, .chunk_len = 1, .val = 1), out) == XDP_DROP, "w1");
    CHECK(send_frame(F(.job = 102, .wid = 2, .nw = 3, .chunk_len = 1, .val = 1), out) == XDP_DROP, "w2");
    CHECK(delta(NS_NUM_WORKERS_MISMATCH) == 2 && delta(NS_SLOT_CREATED) == 1, "absorbed as mismatch");

    begin("fan-in 256");
    int act = 0;
    for (int w = 0; w < 256; w++)
        act = send_frame(F(.job = 103, .wid = (uint16_t)w, .nw = 256, .chunk_len = 1, .val = 1, .lanes_equal = 1), out);
    CHECK(act == XDP_TX, "completes at the 256th");
    check_aggregate_frame(out, 256, 1, 256, 0);

    begin("chunk_len 64 sums every lane");
    send_frame(F(.job = 104, .wid = 0, .nw = 2, .chunk_len = 64, .val = 1000), out);
    CHECK(send_frame(F(.job = 104, .wid = 1, .nw = 2, .chunk_len = 64, .val = 2000), out) == XDP_TX, "action");
    lanes = out + 14 + 20 + 8 + 20;
    int ok = 1;
    for (int i = 0; i < 64; i++)
        ok &= (int32_t)get32(lanes + 4 * i) == 3000 + 2 * i;
    CHECK(ok, "all 64 lanes");

    begin("legacy v1 contributions produce a v1 aggregate");
    send_frame(F(.job = 105, .wid = 0, .nw = 2, .chunk_len = 2, .val = 5, .v1 = 1), out);
    CHECK(send_frame(F(.job = 105, .wid = 1, .nw = 2, .chunk_len = 2, .val = 6, .v1 = 1), out) == XDP_TX, "action");
    const uint8_t *pl = out + 14 + 20 + 8;
    CHECK(get16(pl + 12) == 0 && get16(pl + 14) == 1 && get16(pl + 18) == 0, "v1 aggregate header");
    CHECK((int32_t)get32(pl + 20) == 11, "v1 sum");
}

static void test_overflow(void)
{
    uint8_t out[4096];
    begin("sum exactly INT32_MAX does not overflow");
    send_frame(F(.job = 200, .wid = 0, .nw = 2, .chunk_len = 1, .val = 2147483646), out);
    CHECK(send_frame(F(.job = 200, .wid = 1, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_TX, "action");
    check_aggregate_frame(out, 2, 1, 2147483647, 0);
    begin("INT32_MAX + 1 sets OVERFLOW (C4)");
    send_frame(F(.job = 201, .wid = 0, .nw = 2, .chunk_len = 1, .val = 2147483647), out);
    CHECK(send_frame(F(.job = 201, .wid = 1, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_TX, "action");
    check_aggregate_frame(out, 2, 1, 0, 1);
    CHECK(delta(NS_OVERFLOW) == 1, "overflow counted");
    begin("INT32_MIN - 1 sets OVERFLOW");
    send_frame(F(.job = 202, .wid = 0, .nw = 2, .chunk_len = 1, .val = -2147483647 - 1), out);
    CHECK(send_frame(F(.job = 202, .wid = 1, .nw = 2, .chunk_len = 1, .val = -1), out) == XDP_TX, "action");
    check_aggregate_frame(out, 2, 1, 0, 1);
    begin("3 x 20000.0 in Q16.16 overflows instead of wrapping to -5536.0");
    for (int w = 0; w < 2; w++)
        send_frame(F(.job = 203, .wid = (uint16_t)w, .nw = 3, .chunk_len = 1, .val = 1310720000), out);
    CHECK(send_frame(F(.job = 203, .wid = 2, .nw = 3, .chunk_len = 1, .val = 1310720000), out) == XDP_TX, "action");
    check_aggregate_frame(out, 3, 1, 0, 1);
}

static void clear_quota_map(void)
{
    uint32_t k, next;
    while (bpf_map_get_next_key(quota_fd, NULL, &next) == 0) {
        k = next;
        bpf_map_delete_elem(quota_fd, &k);
    }
}

static uint32_t quota_of(uint32_t job)
{
    struct job_quota_entry e;
    return bpf_map_lookup_elem(quota_fd, &job, &e) == 0 ? e.concurrent_slots : 0xFFFFFFFFu;
}

static void test_quota(void)
{
    uint8_t out[4096];
    set_config(1, 0);
    begin("quota admits the first slot");
    CHECK(send_frame(F(.job = 300, .round = 0, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_DROP, "accepted");
    CHECK(quota_of(300) == 1, "charged 1");
    begin("quota drops a second concurrent slot");
    CHECK(send_frame(F(.job = 300, .round = 1, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_DROP, "action");
    CHECK(delta(NS_DROP_QUOTA) == 1, "drop_quota");
    begin("completion releases the unit and frees the entry (C7)");
    CHECK(send_frame(F(.job = 300, .round = 0, .wid = 1, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_TX, "completes");
    CHECK(quota_of(300) == 0xFFFFFFFFu, "entry deleted at zero");
    begin("tombstones are not charged: next round is admitted");
    CHECK(send_frame(F(.job = 300, .round = 1, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_DROP, "accepted");
    CHECK(delta(NS_DROP_QUOTA) == 0 && delta(NS_SLOT_CREATED) == 1, "admitted");
    CHECK(quota_of(300) == 1, "charged again");

    begin("full job table fails closed (C7)");
    clear_quota_map();
    for (uint32_t j = 0; j < 256; j++)
        send_frame(F(.job = 1000 + j, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out);
    CHECK(send_frame(F(.job = 2000, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_DROP, "action");
    CHECK(delta(NS_DROP_JOB_TABLE_FULL) == 1, "drop_job_table_full = %llu", (unsigned long long)delta(NS_DROP_JOB_TABLE_FULL));
    struct grad_slot s;
    CHECK(!slot_get(2000, 0, 0, &s), "no slot for the rejected job");
    clear_quota_map();
    set_config(0, 0);
}

static void test_config_and_forwarding(void)
{
    uint8_t out[4096];
    begin("missing config: completion is dropped and counted");
    uint32_t zero = 0;
    bpf_map_delete_elem(config_fd, &zero);
    send_frame(F(.job = 400, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out);
    CHECK(send_frame(F(.job = 400, .wid = 1, .nw = 2, .chunk_len = 1, .val = 1), out) == XDP_DROP, "action");
    CHECK(delta(NS_DROP_NO_CONFIG) == 1, "drop_no_config");
    set_config(0, 0);
    begin("TTL <= 1 on the completing packet is dropped");
    CHECK(send_frame(F(.job = 401, .nw = 1, .chunk_len = 1, .val = 1, .ttl = 1), out) == XDP_DROP, "action");
    CHECK(delta(NS_REJ_TTL) == 1, "rej_ttl");
    begin("egress ifindex == ingress (test-run ingress is lo, ifindex 1) uses XDP_TX");
    set_config(0, 1);
    CHECK(send_frame(F(.job = 403, .nw = 1, .chunk_len = 1, .val = 1), out) == XDP_TX, "action");
    begin("egress ifindex != ingress redirects");
    set_config(0, 4242);
    CHECK(send_frame(F(.job = 402, .nw = 1, .chunk_len = 1, .val = 1), out) == XDP_REDIRECT, "action");
    set_config(0, 0);
}

/* ---- result path: ACK, RESEND, FLUSHED -------------------------------------- */

static void test_ack_and_resend(void)
{
    uint8_t out[4096];
    struct grad_slot s;

    begin("ACK retires a COMPLETED tombstone");
    send_frame(F(.job = 500, .nw = 1, .chunk_len = 2, .val = 5), out);
    CHECK(send_frame(F(.job = 500, .wid = 0xFFFF, .nw = 1, .chunk_len = 2, .flags = NETSUM_F_ACK), out) == XDP_DROP, "action");
    CHECK(!slot_get(500, 0, 0, &s), "slot deleted");
    CHECK(delta(NS_SLOT_RETIRED_ACK) == 1, "slot_retired_ack");

    begin("ACK for an ACCUMULATING slot discards it and releases its quota unit");
    set_config(4, 0);
    send_frame(F(.job = 501, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out);
    CHECK(quota_of(501) == 1, "charged");
    CHECK(send_frame(F(.job = 501, .wid = 0xFFFF, .nw = 2, .chunk_len = 1, .flags = NETSUM_F_ACK), out) == XDP_DROP, "action");
    CHECK(!slot_get(501, 0, 0, &s), "slot deleted");
    CHECK(quota_of(501) == 0xFFFFFFFFu, "quota released");
    CHECK(delta(NS_ACK_UNEXPECTED) == 1, "ack_unexpected");
    set_config(0, 0);

    begin("RESEND on a COMPLETED slot re-sends the stored aggregate");
    send_frame(F(.job = 502, .wid = 0, .nw = 2, .chunk_len = 3, .val = 10), out);
    send_frame(F(.job = 502, .wid = 1, .nw = 2, .chunk_len = 3, .val = 20), out);
    CHECK(send_frame(F(.job = 502, .wid = 1, .nw = 2, .chunk_len = 3, .val = 999, .flags = NETSUM_F_RESEND), out) == XDP_TX, "action");
    check_aggregate_frame(out, 2, 3, 30, 0);
    CHECK(delta(NS_TX_RESULT_RESEND) == 1, "tx_result_resend");
    begin("plain duplicate on a COMPLETED slot stays a late duplicate");
    CHECK(send_frame(F(.job = 502, .wid = 1, .nw = 2, .chunk_len = 3, .val = 20), out) == XDP_DROP, "action");
    CHECK(delta(NS_LATE_DUPLICATE) == 1, "late");

    begin("RESEND of a held worker flushes the partial (ATP) and marks FLUSHED");
    set_config(4, 0);
    send_frame(F(.job = 503, .wid = 0, .nw = 3, .chunk_len = 2, .val = 100), out);
    send_frame(F(.job = 503, .wid = 1, .nw = 3, .chunk_len = 2, .val = 200), out);
    CHECK(send_frame(F(.job = 503, .wid = 1, .nw = 3, .chunk_len = 2, .val = 200, .flags = NETSUM_F_RESEND), out) == XDP_TX, "action");
    const uint8_t *pl = out + 14 + 20 + 8;
    CHECK(get16(pl + 12) == 0xFFFF && get16(pl + 14) == 3, "aggregate header");
    CHECK((get16(pl + 18) & NETSUM_F_PARTIAL) && get16(pl + 18) >> 12 == 2, "PARTIAL flag");
    CHECK((int32_t)get32(pl + 20) == 300 && (int32_t)get32(pl + 24) == 302, "partial sum, not the resent values");
    CHECK(pl[20 + 8] == 0x03, "bitmap {0,1}");
    CHECK(slot_get(503, 0, 0, &s) && s.state == NETSUM_SLOT_FLUSHED, "FLUSHED");
    CHECK(quota_of(503) == 0xFFFFFFFFu, "quota released on flush");
    CHECK(delta(NS_SLOT_FLUSHED_PARTIAL) == 1 && delta(NS_TX_PARTIAL) == 1, "counters");
    set_config(0, 0);

    begin("a new worker's contribution to a FLUSHED slot goes to the PS as FALLBACK");
    CHECK(send_frame(F(.job = 503, .wid = 2, .nw = 3, .chunk_len = 2, .val = 400), out) == XDP_TX, "action");
    CHECK(get16(pl + 12) == 2 && (get16(pl + 18) & NETSUM_F_FALLBACK), "raw worker 2, FALLBACK");
    CHECK((int32_t)get32(pl + 20) == 400, "own values kept");
    CHECK(memcmp(out, PS_MAC, 6) == 0 && get32(out + 14 + 16) == PS_IP, "addressed to the PS");
    CHECK(delta(NS_TX_FALLBACK) == 1, "tx_fallback");
    begin("a held worker's plain duplicate to a FLUSHED slot is dropped");
    CHECK(send_frame(F(.job = 503, .wid = 0, .nw = 3, .chunk_len = 2, .val = 100), out) == XDP_DROP, "action");
    CHECK(delta(NS_DUPLICATE) == 1, "duplicate");
    begin("ACK retires a FLUSHED slot");
    CHECK(send_frame(F(.job = 503, .wid = 0xFFFF, .nw = 3, .chunk_len = 2, .flags = NETSUM_F_ACK), out) == XDP_DROP, "action");
    CHECK(!slot_get(503, 0, 0, &s) && delta(NS_SLOT_RETIRED_ACK) == 1, "retired");
}

static int sweep(uint32_t job, uint64_t ttl_ns, uint8_t *out)
{
    uint8_t in[NETSUM_SWEEP_FRAME_SIZE];
    memset(in, 0, sizeof(in));
    uint8_t *h = in + NETSUM_SWEEP_PAYLOAD_OFFSET;
    put32(h, job);
    memcpy(h + 20, &ttl_ns, 8);
    LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = in, .data_size_in = sizeof(in),
                .data_out = out, .data_size_out = 4096, .repeat = 1);
    if (bpf_prog_test_run_opts(sweep_fd, &o)) {
        fprintf(stderr, "sweep test run: %s\n", strerror(errno));
        exit(2);
    }
    return (int)o.retval;
}

static void test_sweep(void)
{
    uint8_t out[4096];
    struct grad_slot s;
    begin("sweep leaves a fresh slot alone");
    send_frame(F(.job = 600, .wid = 1, .nw = 3, .chunk_len = 2, .val = 7), out);
    CHECK(sweep(600, 60ull * 1000000000ull, out) == XDP_PASS, "action");
    CHECK(slot_get(600, 0, 0, &s) && s.state == NETSUM_SLOT_ACCUMULATING, "untouched");
    begin("sweep flushes an expired ACCUMULATING slot as PARTIAL");
    set_config(4, 0);
    send_frame(F(.job = 601, .wid = 1, .nw = 3, .chunk_len = 2, .val = 7), out);
    CHECK(quota_of(601) == 1, "charged");
    CHECK(sweep(601, 0, out) == XDP_TX, "action");
    const uint8_t *pl = out + NETSUM_SWEEP_PAYLOAD_OFFSET;
    CHECK(get32(pl) == 601 && get16(pl + 12) == 0xFFFF && get16(pl + 14) == 3 && get16(pl + 16) == 2, "header");
    CHECK(get16(pl + 18) == (NETSUM_FLAGS_V2 | NETSUM_F_PARTIAL), "flags");
    CHECK((int32_t)get32(pl + 20) == 7 && (int32_t)get32(pl + 24) == 8 && pl[28] == 0x02, "sum and bitmap {1}");
    CHECK(slot_get(601, 0, 0, &s) && s.state == NETSUM_SLOT_FLUSHED, "FLUSHED");
    CHECK(quota_of(601) == 0xFFFFFFFFu, "quota released");
    CHECK(delta(NS_SLOT_FLUSHED_PARTIAL) == 1, "counted");
    set_config(0, 0);
    begin("sweep deletes an expired FLUSHED slot");
    CHECK(sweep(601, 0, out) == XDP_DROP, "action");
    CHECK(!slot_get(601, 0, 0, &s) && delta(NS_SLOT_RETIRED_TTL) == 1, "deleted");
    begin("sweep deletes an expired COMPLETED tombstone");
    send_frame(F(.job = 602, .nw = 1, .chunk_len = 1, .val = 1), out);
    CHECK(sweep(602, 0, out) == XDP_DROP, "action");
    CHECK(!slot_get(602, 0, 0, &s), "deleted");
    begin("sweep on a missing key does nothing");
    CHECK(sweep(603, 0, out) == XDP_PASS, "action");
}

/* ---- array mode (ATP-style aggregators) and fallback ------------------------- */

static int array_get(uint32_t job, struct grad_slot *s)
{
    uint32_t idx = netsum_slot_hash(job, 0, 0) & 15;
    return bpf_map_lookup_elem(array_fd, &idx, s) == 0;
}

static int fallback_has(uint32_t job)
{
    struct grad_slot_key k = {job, 0, 0};
    uint8_t v;
    return bpf_map_lookup_elem(fallback_fd, &k, &v) == 0;
}

static uint32_t colliding_job(uint32_t base, uint32_t with)
{
    uint32_t want = netsum_slot_hash(with, 0, 0) & 15;
    for (uint32_t j = base;; j++)
        if (j != with && (netsum_slot_hash(j, 0, 0) & 15) == want)
            return j;
}

static void test_array_mode(void)
{
    uint8_t out[4096];
    struct grad_slot s;
    g_slot_mode = NETSUM_SLOT_MODE_ARRAY;
    set_config(0, 0);
    const uint8_t *pl = out + 14 + 20 + 8;

    begin("array: a free aggregator is claimed and completes");
    uint32_t k1 = 7000;
    send_frame(F(.job = k1, .wid = 0, .nw = 2, .chunk_len = 2, .val = 3), out);
    CHECK(array_get(k1, &s) && s.state == NETSUM_SLOT_ACCUMULATING && s.tag.job_id == k1, "claimed with tag");
    CHECK(send_frame(F(.job = k1, .wid = 1, .nw = 2, .chunk_len = 2, .val = 4), out) == XDP_TX, "completes");
    check_aggregate_frame(out, 2, 2, 7, 0);
    begin("array: ACK frees the aggregator");
    send_frame(F(.job = k1, .wid = 0xFFFF, .nw = 2, .chunk_len = 2, .flags = NETSUM_F_ACK), out);
    CHECK(array_get(k1, &s) && s.state == NETSUM_SLOT_EMPTY, "EMPTY");
    CHECK(delta(NS_SLOT_RETIRED_ACK) == 1, "retired");

    begin("array: a busy aggregator owned by another key -> FALLBACK to the PS");
    uint32_t a = 7100, b = colliding_job(7101, 7100);
    send_frame(F(.job = a, .wid = 0, .nw = 2, .chunk_len = 2, .val = 1), out);
    CHECK(send_frame(F(.job = b, .wid = 0, .nw = 2, .chunk_len = 2, .val = 50), out) == XDP_TX, "action");
    CHECK(get32(pl) == b && get16(pl + 12) == 0 && (get16(pl + 18) & NETSUM_F_FALLBACK), "raw contribution, FALLBACK");
    CHECK((int32_t)get32(pl + 20) == 50 && memcmp(out, PS_MAC, 6) == 0, "own values, to the PS");
    CHECK(array_get(a, &s) && s.tag.job_id == a && s.contributors == 1, "owner's slot untouched");
    CHECK(fallback_has(b) && delta(NS_FALLBACK_COLLISION) == 1 && delta(NS_TX_FALLBACK) == 1, "recorded");
    begin("array: a fallen-back key keeps falling back even once its aggregator is free");
    send_frame(F(.job = a, .wid = 1, .nw = 2, .chunk_len = 2, .val = 1), out);
    send_frame(F(.job = a, .wid = 0xFFFF, .nw = 2, .chunk_len = 2, .flags = NETSUM_F_ACK), out);
    CHECK(array_get(a, &s) && s.state == NETSUM_SLOT_EMPTY, "free now");
    CHECK(send_frame(F(.job = b, .wid = 1, .nw = 2, .chunk_len = 2, .val = 60), out) == XDP_TX, "action");
    CHECK(get16(pl + 18) & NETSUM_F_FALLBACK, "still FALLBACK");
    CHECK(array_get(b, &s) && s.state == NETSUM_SLOT_EMPTY, "not claimed: no worker split across paths");
    begin("array: the PS's ACK for a fallen-back key clears its fallback entry");
    send_frame(F(.job = b, .wid = 0xFFFF, .nw = 2, .chunk_len = 2, .flags = NETSUM_F_ACK), out);
    CHECK(!fallback_has(b), "cleared");

    begin("array: sweep flushes an expired aggregator by index and frees it");
    uint32_t c = 7200;
    send_frame(F(.job = c, .wid = 2, .nw = 3, .chunk_len = 1, .val = 9), out);
    uint8_t in[NETSUM_SWEEP_FRAME_SIZE];
    memset(in, 0, sizeof(in));
    uint8_t *h = in + NETSUM_SWEEP_PAYLOAD_OFFSET;
    put32(h, netsum_slot_hash(c, 0, 0) & 15);
    put16(h + 18, NETSUM_SWEEP_ARRAY_INDEX);
    uint64_t zero_ttl = 0;
    memcpy(h + 20, &zero_ttl, 8);
    LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = in, .data_size_in = sizeof(in), .data_out = out,
                .data_size_out = 4096, .repeat = 1);
    CHECK(bpf_prog_test_run_opts(sweep_fd, &o) == 0 && o.retval == XDP_TX, "flushed");
    const uint8_t *sp = out + NETSUM_SWEEP_PAYLOAD_OFFSET;
    CHECK(get32(sp) == c && (get16(sp + 18) & NETSUM_F_PARTIAL) && (int32_t)get32(sp + 20) == 9, "PARTIAL named by tag");
    CHECK(array_get(c, &s) && s.state == NETSUM_SLOT_FLUSHED, "FLUSHED");
    CHECK(bpf_prog_test_run_opts(sweep_fd, &o) == 0 && o.retval == XDP_DROP, "retired");
    CHECK(array_get(c, &s) && s.state == NETSUM_SLOT_EMPTY, "EMPTY");

    g_slot_mode = NETSUM_SLOT_MODE_HASH;
    set_config(0, 0);
}

static void test_quota_fallback_policy(void)
{
    uint8_t out[4096];
    const uint8_t *pl = out + 14 + 20 + 8;
    g_quota_policy = NETSUM_QUOTA_FALLBACK;
    set_config(1, 0);
    begin("quota policy fallback: over-quota slots go to the PS instead of being dropped");
    send_frame(F(.job = 7300, .round = 0, .wid = 0, .nw = 2, .chunk_len = 1, .val = 1), out);
    CHECK(send_frame(F(.job = 7300, .round = 1, .wid = 0, .nw = 2, .chunk_len = 1, .val = 5), out) == XDP_TX, "action");
    CHECK(get32(pl + 4) == 1 && (get16(pl + 18) & NETSUM_F_FALLBACK), "round 1 forwarded as FALLBACK");
    CHECK(delta(NS_FALLBACK_QUOTA) == 1 && delta(NS_DROP_QUOTA) == 0, "counted as fallback, not drop");
    g_quota_policy = 0xFFFFFFFFu;
    clear_quota_map();
    set_config(0, 0);
}

/* ---- corpus replay: kernel verdicts vs the userspace parser -------------- */

static int expected_action_ok(const struct netsum_parsed *p)
{
    if (p->kind == NETSUM_KIND_RAW)
        return -1; /* DROP or TX, depending on slot state */
    return p->kind == NETSUM_KIND_ACK ? XDP_DROP : XDP_PASS; /* ACKs are consumed */
}

static void replay_one(const uint8_t *payload, size_t len, int *mismatches)
{
    if (len > 1400)
        return;
    uint8_t out[4096], in[2048];
    struct netsum_parsed p;
    enum netsum_verdict v = netsum_parse(payload, payload + len, &p);
    size_t flen = build(in, F(.raw_payload = payload, .raw_len = len));
    uint64_t before = v == NETSUM_OK ? 0 : stat_now(NS_FROM_VERDICT(v));
    int act = run(in, flen, out, NULL);
    int ok;
    if (v != NETSUM_OK) {
        ok = act == XDP_DROP && stat_now(NS_FROM_VERDICT(v)) == before + 1;
    } else {
        int want = expected_action_ok(&p);
        ok = want == -1 ? (act == XDP_DROP || act == XDP_TX) : act == want;
    }
    if (!ok && (*mismatches)++ < 5)
        fprintf(stderr, "  corpus mismatch: len %zu userspace verdict %d kind %d, kernel action %d\n",
                len, v, v == NETSUM_OK ? p.kind : -1, act);
}

static void test_corpus(const char *dir)
{
    begin("fuzz corpus + 5000 seeded mutations agree with netsum_parse");
    int mismatches = 0, files = 0;
    uint8_t seeds[64][512];
    size_t seed_len[64];
    DIR *d = opendir(dir);
    CHECK(d != NULL, "open %s", dir);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) && files < 64) {
        if (!strstr(e->d_name, ".bin"))
            continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        FILE *f = fopen(path, "rb");
        if (!f)
            continue;
        seed_len[files] = fread(seeds[files], 1, sizeof(seeds[files]), f);
        fclose(f);
        replay_one(seeds[files], seed_len[files], &mismatches);
        files++;
    }
    closedir(d);
    CHECK(files > 10, "corpus has %d files", files);
    uint64_t rng = 0x9E3779B97F4A7C15ULL;
    for (int n = 0; n < 5000 && files; n++) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        int s = (int)(rng % (uint64_t)files);
        uint8_t buf[512];
        size_t len = seed_len[s];
        memcpy(buf, seeds[s], len);
        int flips = 1 + (int)(rng >> 40) % 4;
        for (int k = 0; k < flips && len; k++) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            buf[rng % len] ^= (uint8_t)(rng >> 32);
        }
        if ((rng >> 20) % 8 == 0 && len > 1)
            len -= (size_t)(rng >> 24) % len;
        replay_one(buf, len, &mismatches);
    }
    CHECK(mismatches == 0, "%d kernel/userspace verdict mismatches", mismatches);
    printf("  corpus replay: %d seed files + 5000 mutations\n", files);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <xdp_agg.o> <corpus dir>\n", argv[0]);
        return 2;
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (obj)
        bpf_map__set_max_entries(bpf_object__find_map_by_name(obj, "agg_array"), 16);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "failed to open/load %s: %s\n", argv[1], strerror(errno));
        return 2;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "netsum_xdp_aggregate");
    prog_fd = bpf_program__fd(prog);
    sweep_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "netsum_sweep"));
    slot_fd = bpf_object__find_map_fd_by_name(obj, "slot_map");
    config_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    quota_fd = bpf_object__find_map_fd_by_name(obj, "job_quota_map");
    stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    array_fd = bpf_object__find_map_fd_by_name(obj, "agg_array");
    fallback_fd = bpf_object__find_map_fd_by_name(obj, "fallback_keys");
    ncpus = libbpf_num_possible_cpus();
    if (prog_fd < 0 || sweep_fd < 0 || slot_fd < 0 || config_fd < 0 || quota_fd < 0 || stats_fd < 0 || ncpus <= 0 || ncpus > 512) {
        fprintf(stderr, "program or maps not found\n");
        return 2;
    }
    set_config(0, 0);

    test_pass_paths();
    test_verdicts();
    test_state_machine();
    test_overflow();
    test_quota();
    test_config_and_forwarding();
    test_ack_and_resend();
    test_sweep();
    test_array_mode();
    test_quota_fallback_policy();
    test_corpus(argv[2]);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("bpf-unit: %d cases, %d failures, %.0f ms\n", cases, failures, ms);
    bpf_object__close(obj);
    return failures ? 1 : 0;
}
