/* NetSum parameter server: the final summing node. Behaviour is driven by
 * the packet itself, not the CLI mode: raw and FALLBACK contributions are
 * summed here, complete or PARTIAL aggregates are merged by contributor
 * bitmap, and a key completes when its contributors cover the fan-in.
 * Overlapping contributor sets are rejected so nothing is counted twice.
 * Design: docs/DESIGN_NOTES.md §Admission, §Fallback. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../common/slot_table.h"
#include "../protocol/grad_parse.h"
#include "../protocol/netsum_stats.h"

#define HOUSEKEEPING_MS 50

static struct {
    struct slot_table table;
    struct tomb_fifo tombs;
    long tomb_ttl_ms;
    int quiet;
    uint64_t stats[NS_STAT__COUNT];
    uint64_t rx_fallback, rx_partial, rx_aggregate;
    long completed;
    int64_t first_complete_us, last_complete_us;
} g;

static volatile sig_atomic_t g_dump_requested, g_stop;

static void on_signal(int sig)
{
    if (sig == SIGUSR1)
        g_dump_requested = 1;
    else
        g_stop = 1;
}

static int64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void dump_stats(void)
{
    fprintf(stderr, "[stats-all] {");
    for (int i = 0; i < NS_STAT__COUNT; i++)
        fprintf(stderr, "\"%s\":%llu,", netsum_stat_names[i], (unsigned long long)g.stats[i]);
    fprintf(stderr, "\"rx_fallback\":%llu,\"rx_partial\":%llu,\"rx_aggregate\":%llu}\n",
            (unsigned long long)g.rx_fallback, (unsigned long long)g.rx_partial,
            (unsigned long long)g.rx_aggregate);
    fflush(stderr);
}

static void complete(struct slot *s, int64_t now)
{
    if (s->overflowed) {
        g.stats[NS_OVERFLOW]++;
        fprintf(stderr, "[overflow] job=%u round=%u chunk=%u contributions=%u -- sum not representable in Q16.16\n",
                s->key.job_id, s->key.round, s->key.chunk_id, s->contributions);
    } else {
        g.completed++;
        if (!g.first_complete_us)
            g.first_complete_us = now;
        g.last_complete_us = now;
        if (!g.quiet)
            fprintf(stderr, "[complete] job=%u round=%u chunk=%u contributions=%u sum[0]=%.6f latency_us=%lld\n",
                    s->key.job_id, s->key.round, s->key.chunk_id, s->contributions,
                    netsum_to_double(s->sum[0]), (long long)(now - s->first_us));
    }
    s->state = SLOT_COMPLETED;
    s->completed_us = now;
    g.stats[NS_SLOT_COMPLETED]++;
    g.stats[NS_SLOT_RETIRED_TTL] += (uint64_t)tomb_push(&g.tombs, &g.table, s->key, now);
}

static void handle(const uint8_t *pkt, const struct netsum_parsed *p, int64_t now)
{
    int is_agg = p->kind == NETSUM_KIND_AGGREGATE || p->kind == NETSUM_KIND_PARTIAL;
    if (p->kind != NETSUM_KIND_RAW && !is_agg) {
        g.stats[NS_PASS_CONTROL]++; /* REGISTER / ACK: handled by the result path */
        return;
    }

    uint8_t in_bm[NETSUM_BITMAP_BYTES] = {0};
    if (is_agg) {
        memcpy(in_bm, netsum_trailer(pkt, p), NETSUM_BITMAP_BYTES);
        unsigned pc = bitmap_popcount(in_bm);
        if (pc == 0 || bitmap_span(in_bm) > p->num_workers ||
            (p->kind == NETSUM_KIND_AGGREGATE && pc != p->num_workers)) {
            g.stats[NS_REJ_KIND]++;
            return;
        }
        if (p->kind == NETSUM_KIND_PARTIAL)
            g.rx_partial++;
        else
            g.rx_aggregate++;
    } else {
        bitmap_set(in_bm, p->worker_id);
        if (p->flags & NETSUM_F_FALLBACK)
            g.rx_fallback++;
    }

    struct slot_key key = {p->job_id, p->round, p->chunk_id};
    struct slot *s = st_find(&g.table, key);
    if (!s) {
        s = st_insert(&g.table, key);
        if (!s) {
            g.stats[NS_DROP_MAP_FULL]++;
            if (!g.quiet)
                fprintf(stderr, "slot table full, dropping job=%u round=%u chunk=%u\n",
                        p->job_id, p->round, p->chunk_id);
            return;
        }
        s->fanin = p->num_workers;
        s->chunk_len = p->chunk_len;
        s->first_us = now;
        g.stats[NS_SLOT_CREATED]++;
    }

    if (p->num_workers != s->fanin) {
        g.stats[NS_NUM_WORKERS_MISMATCH]++;
        if (!g.quiet)
            fprintf(stderr, "[num_workers mismatch] job=%u round=%u chunk=%u worker=%u sent num_workers=%u, slot expects %u -- dropping\n",
                    p->job_id, p->round, p->chunk_id, p->worker_id, p->num_workers, s->fanin);
        return;
    }
    if (p->chunk_len != s->chunk_len) {
        g.stats[NS_CHUNK_LEN_MISMATCH]++;
        if (!g.quiet)
            fprintf(stderr, "[chunk_len mismatch] job=%u round=%u chunk=%u sent chunk_len=%u, slot expects %u -- dropping\n",
                    p->job_id, p->round, p->chunk_id, p->chunk_len, s->chunk_len);
        return;
    }
    if (s->state == SLOT_COMPLETED) {
        g.stats[is_agg ? NS_AGGREGATE_CONFLICT : NS_LATE_DUPLICATE]++;
        return;
    }
    if (bitmap_overlaps(in_bm, s->bitmap)) {
        if (is_agg) {
            g.stats[NS_OVERLAP_REJECTED]++;
            if (!g.quiet)
                fprintf(stderr, "[overlap] job=%u round=%u chunk=%u -- aggregate overlaps contributors already held, dropping\n",
                        p->job_id, p->round, p->chunk_id);
        } else {
            g.stats[NS_DUPLICATE]++;
            if (!g.quiet)
                fprintf(stderr, "[dup] job=%u round=%u chunk=%u worker=%u already contributed -- dropping duplicate\n",
                        p->job_id, p->round, p->chunk_id, p->worker_id);
        }
        return;
    }

    if (is_agg && (p->flags & NETSUM_F_OVERFLOW))
        s->overflowed = 1;
    const uint8_t *v = pkt + NETSUM_HDR_SIZE;
    for (int i = 0; i < p->chunk_len; i++) {
        uint32_t be;
        memcpy(&be, v + 4 * i, 4);
        s->overflowed |= (uint8_t)netsum_add_i32(&s->sum[i], (int32_t)ntohl(be));
    }
    for (int i = 0; i < NETSUM_BITMAP_BYTES; i++)
        s->bitmap[i] |= in_bm[i];
    s->contributors = (uint16_t)bitmap_popcount(s->bitmap);
    s->contributions++;
    s->touched_us = now;
    g.stats[NS_ACCEPTED]++;
    if (s->contributors == s->fanin)
        complete(s, now);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--quiet] [--slot-capacity-log2 N] [--tombstone-ttl-ms N]\n"
            "          <listen_port> <mode: noagg|agg> [max_packets=0 (0=unbounded)]\n"
            "  mode is informational: behaviour follows each packet's kind.\n"
            "  --quiet suppresses per-slot lines; a [summary] line is printed on exit.\n",
            prog);
}

int main(int argc, char **argv)
{
    unsigned cap_log2 = 16;
    g.tomb_ttl_ms = 10000;
    int a = 1;
    for (; a < argc && strncmp(argv[a], "--", 2) == 0; a++) {
        if (strcmp(argv[a], "--quiet") == 0) {
            g.quiet = 1;
        } else if (strcmp(argv[a], "--slot-capacity-log2") == 0 && a + 1 < argc) {
            cap_log2 = (unsigned)atoi(argv[++a]);
            if (cap_log2 < 4 || cap_log2 > 22) {
                fprintf(stderr, "--slot-capacity-log2 must be in [4, 22]\n");
                return 1;
            }
        } else if (strcmp(argv[a], "--tombstone-ttl-ms") == 0 && a + 1 < argc) {
            g.tomb_ttl_ms = atol(argv[++a]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (argc - a < 2) {
        usage(argv[0]);
        return 1;
    }
    int listen_port = atoi(argv[a]);
    const char *mode = argv[a + 1];
    long max_packets = argc - a > 2 ? atol(argv[a + 2]) : 0;

    if (st_init(&g.table, cap_log2) != 0 || tomb_init(&g.tombs, g.table.cap) != 0) {
        fprintf(stderr, "out of memory for slot table\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal; /* no SA_RESTART: recvfrom returns EINTR */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int rcvbuf = 4 << 20;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct timeval tv = {0, HOUSEKEEPING_MS * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)listen_port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    fprintf(stderr, "paramserver listening on :%d mode=%s\n", listen_port, mode);

    uint8_t pkt[NETSUM_MAX_PACKET_SIZE + 1];
    long packets_seen = 0;
    while (!g_stop && (max_packets == 0 || packets_seen < max_packets)) {
        g.stats[NS_SLOT_RETIRED_TTL] += (uint64_t)tomb_expire(&g.tombs, &g.table, now_us(),
                                                             (int64_t)g.tomb_ttl_ms * 1000);
        if (g_dump_requested) {
            g_dump_requested = 0;
            dump_stats();
        }
        ssize_t n = recvfrom(sock, pkt, sizeof(pkt), 0, NULL, NULL);
        if (n < 0)
            continue;
        packets_seen++;
        g.stats[NS_RX_TOTAL]++;
        struct netsum_parsed p;
        enum netsum_verdict v = netsum_parse(pkt, pkt + n, &p);
        if (v != NETSUM_OK) {
            g.stats[NS_FROM_VERDICT(v)]++;
            continue;
        }
        handle(pkt, &p, now_us());
    }
    fprintf(stderr, "paramserver: %ld packets seen, %ld slots completed\n", packets_seen, g.completed);
    fprintf(stderr, "[summary] {\"packets\":%ld,\"completed\":%ld,\"first_complete_us\":%lld,\"last_complete_us\":%lld}\n",
            packets_seen, g.completed, (long long)g.first_complete_us, (long long)g.last_complete_us);
    dump_stats();
    close(sock);
    return 0;
}
