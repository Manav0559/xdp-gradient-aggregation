/* NetSum userspace aggregator: the same slot / accumulate / emit algorithm as
 * xdp_agg.c, run in an ordinary single-threaded process, so the benchmark can
 * compare "kernel fast path" against "userspace" for one algorithm.
 *
 * Per (job, round, chunk) slot: EMPTY -> ACCUMULATING -> COMPLETED (tombstone)
 * -> EMPTY. The first accepted contribution fixes the fan-in and chunk_len;
 * disagreeing, duplicate and late contributions are counted and dropped.
 * Design: docs/DESIGN_NOTES.md §Admission, §Slot storage, §Reclamation. */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
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

#define JOB_TABLE_CAPACITY 256
#define HOUSEKEEPING_MS 50

/* A job entry exists only while the job has ACCUMULATING slots; tombstones
 * are not charged to the quota, so they do not pin the entry (bug C7). */
struct job {
    int in_use;
    uint32_t job_id;
    uint32_t accumulating;
    uint32_t admitted;
    uint32_t rejected;
};

static struct {
    struct slot_table table;
    struct tomb_fifo tombs;
    struct job jobs[JOB_TABLE_CAPACITY];
    long quota;
    long slot_ttl_ms;
    long tomb_ttl_ms;
    int quiet;
    uint64_t stats[NS_STAT__COUNT];
    int out_sock;
    struct sockaddr_in downstream;
    long packets_out;
    int profile;
    uint64_t profile_ns, profile_pkts;
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

static struct job *job_find(uint32_t job_id)
{
    for (int i = 0; i < JOB_TABLE_CAPACITY; i++)
        if (g.jobs[i].in_use && g.jobs[i].job_id == job_id)
            return &g.jobs[i];
    return NULL;
}

static struct job *job_get(uint32_t job_id)
{
    struct job *j = job_find(job_id);
    if (j)
        return j;
    for (int i = 0; i < JOB_TABLE_CAPACITY; i++)
        if (!g.jobs[i].in_use) {
            g.jobs[i] = (struct job){1, job_id, 0, 0, 0};
            return &g.jobs[i];
        }
    return NULL;
}

static void job_release_slot(uint32_t job_id)
{
    struct job *j = job_find(job_id);
    if (!j)
        return;
    if (j->accumulating > 0)
        j->accumulating--;
    if (j->accumulating == 0) {
        if (!g.quiet)
            fprintf(stderr, "[job-retired] {\"job_id\":%u,\"admitted_count\":%u,\"rejected_count\":%u}\n",
                    j->job_id, j->admitted, j->rejected);
        j->in_use = 0;
    }
}

static void dump_stats(void)
{
    for (int i = 0; i < JOB_TABLE_CAPACITY; i++) {
        struct job *j = &g.jobs[i];
        if (j->in_use)
            fprintf(stderr,
                    "[stats] {\"job_id\":%u,\"concurrent_slots\":%u,\"admitted_count\":%u,\"rejected_count\":%u}\n",
                    j->job_id, j->accumulating, j->admitted, j->rejected);
    }
    size_t by_state[4] = {0};
    for (size_t i = 0; i < g.table.cap; i++)
        by_state[g.table.slots[i].state & 3]++;
    fprintf(stderr, "[stats-all] {");
    for (int i = 0; i < NS_STAT__COUNT; i++)
        fprintf(stderr, "\"%s\":%llu,", netsum_stat_names[i], (unsigned long long)g.stats[i]);
    fprintf(stderr, "\"slots_accumulating\":%zu,\"slots_completed\":%zu,\"slots_flushed\":%zu,"
            "\"profile_ns\":%llu,\"profile_pkts\":%llu}\n",
            by_state[SLOT_ACCUMULATING], by_state[SLOT_COMPLETED], by_state[SLOT_FLUSHED],
            (unsigned long long)g.profile_ns, (unsigned long long)g.profile_pkts);
    fflush(stderr);
}

/* Drops ACCUMULATING slots idle for longer than the TTL (crashed workers).
 * Backward-shift deletion moves a later entry into index i, so i is
 * re-examined after a delete instead of advancing. */
static void reap_expired(int64_t now)
{
    int64_t ttl = (int64_t)g.slot_ttl_ms * 1000;
    size_t i = 0;
    while (i < g.table.cap) {
        struct slot *s = &g.table.slots[i];
        if (s->state == SLOT_ACCUMULATING && now - s->touched_us >= ttl) {
            fprintf(stderr, "[reaped] job=%u round=%u chunk=%u -- incomplete after %lldms, evicting\n",
                    s->key.job_id, s->key.round, s->key.chunk_id,
                    (long long)((now - s->touched_us) / 1000));
            uint32_t job_id = s->key.job_id;
            st_delete(&g.table, s);
            job_release_slot(job_id);
            g.stats[NS_SLOT_REAPED]++;
            continue;
        }
        i++;
    }
}

static void emit_aggregate(const struct slot *s, uint16_t extra_flags)
{
    uint8_t out[NETSUM_MAX_PACKET_SIZE];
    struct grad_hdr *h = (struct grad_hdr *)out;
    int32_t *vals = (int32_t *)(out + NETSUM_HDR_SIZE);
    h->job_id = htonl(s->key.job_id);
    h->round = htonl(s->key.round);
    h->chunk_id = htonl(s->key.chunk_id);
    h->worker_id = htons(NETSUM_WORKER_AGGREGATE);
    h->num_workers = htons(s->fanin);
    h->chunk_len = htons(s->chunk_len);
    h->flags = htons(netsum_wire_flags(s->version == NETSUM_VERSION_V3 ? NETSUM_VERSION_V3 : NETSUM_VERSION_V2,
                                       s->frac_bits, (uint16_t)(extra_flags | (s->overflowed ? NETSUM_F_OVERFLOW : 0))));
    for (int i = 0; i < s->chunk_len; i++)
        vals[i] = (int32_t)htonl((uint32_t)s->sum[i]);
    memcpy(out + NETSUM_HDR_SIZE + (size_t)s->chunk_len * 4, s->bitmap, NETSUM_BITMAP_BYTES);
    size_t len = NETSUM_HDR_SIZE + (size_t)s->chunk_len * 4 + NETSUM_BITMAP_BYTES;
    if (sendto(g.out_sock, out, len, 0, (struct sockaddr *)&g.downstream, sizeof(g.downstream)) < 0) {
        perror("sendto(downstream)");
        return;
    }
    g.packets_out++;
    g.stats[(extra_flags & NETSUM_F_PARTIAL) ? NS_TX_PARTIAL : NS_TX_AGGREGATE]++;
}

/* Forwards a raw contribution unchanged except for the FALLBACK flag, so the
 * parameter server aggregates it itself. */
static void forward_fallback(const uint8_t *pkt, const struct netsum_parsed *p)
{
    uint8_t out[NETSUM_MAX_PACKET_SIZE];
    size_t len = NETSUM_HDR_SIZE + p->payload_len;
    memcpy(out, pkt, len);
    ((struct grad_hdr *)out)->flags = htons((uint16_t)(p->flags | NETSUM_F_FALLBACK));
    if (sendto(g.out_sock, out, len, 0, (struct sockaddr *)&g.downstream, sizeof(g.downstream)) >= 0)
        g.stats[NS_TX_FALLBACK]++;
}

static void retire_state(struct slot *s, int64_t now, uint8_t state)
{
    s->state = state;
    s->completed_us = now;
    g.stats[NS_SLOT_RETIRED_TTL] += (uint64_t)tomb_push(&g.tombs, &g.table, s->key, now);
}

/* ACK from the parameter server: the key is finished everywhere, so drop all
 * state for it. An ACK for a slot still accumulating means the PS completed
 * the key without us (fallback or partials); our partial sum is stale. */
static void handle_ack(const struct netsum_parsed *p)
{
    g.stats[NS_ACK_SEEN]++;
    struct slot *s = st_find(&g.table, (struct slot_key){p->job_id, p->round, p->chunk_id});
    if (!s) {
        g.stats[NS_ACK_UNEXPECTED]++;
        return;
    }
    if (s->state == SLOT_ACCUMULATING) {
        g.stats[NS_ACK_UNEXPECTED]++;
        uint32_t job_id = s->key.job_id;
        st_delete(&g.table, s);
        job_release_slot(job_id);
        return;
    }
    st_delete(&g.table, s);
    g.stats[NS_SLOT_RETIRED_ACK]++;
}

static void admission_reject(const struct netsum_parsed *p, enum netsum_stat why)
{
    g.stats[why]++;
    if (!g.quiet)
        fprintf(stderr,
                "[admission-reject] job=%u round=%u chunk=%u -- slot table full or job at fairness quota, dropping\n",
                p->job_id, p->round, p->chunk_id);
}

static void handle_contribution(const uint8_t *pkt, const struct netsum_parsed *p, int64_t now)
{
    struct slot_key key = {p->job_id, p->round, p->chunk_id};
    struct slot *s = st_find(&g.table, key);

    if (!s) {
        struct job *j = job_get(p->job_id);
        if (!j) {
            admission_reject(p, NS_DROP_JOB_TABLE_FULL); /* fail closed */
            return;
        }
        if (g.quota > 0 && j->accumulating >= (uint32_t)g.quota) {
            j->rejected++;
            admission_reject(p, NS_DROP_QUOTA);
            return;
        }
        s = st_insert(&g.table, key);
        if (!s) {
            if (j->accumulating == 0)
                j->in_use = 0;
            admission_reject(p, NS_DROP_MAP_FULL);
            return;
        }
        s->fanin = p->num_workers;
        s->chunk_len = p->chunk_len;
        s->frac_bits = p->frac_bits;
        s->version = p->version;
        s->first_us = now;
        j->accumulating++;
        j->admitted++;
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
            fprintf(stderr, "[chunk_len mismatch] job=%u round=%u chunk=%u worker=%u sent chunk_len=%u, slot expects %u -- dropping\n",
                    p->job_id, p->round, p->chunk_id, p->worker_id, p->chunk_len, s->chunk_len);
        return;
    }
    if (p->frac_bits != s->frac_bits) {
        g.stats[NS_SCALE_MISMATCH]++;
        if (!g.quiet)
            fprintf(stderr, "[scale mismatch] job=%u round=%u chunk=%u worker=%u sent e=%u, slot expects %u -- dropping\n",
                    p->job_id, p->round, p->chunk_id, p->worker_id, p->frac_bits, s->frac_bits);
        return;
    }
    int resend = (p->flags & NETSUM_F_RESEND) != 0;
    if (s->state == SLOT_COMPLETED) {
        if (resend) {
            /* The aggregate or the PS's result was lost: send the stored sum again. */
            g.stats[NS_TX_RESULT_RESEND]++;
            emit_aggregate(s, 0);
            return;
        }
        g.stats[NS_LATE_DUPLICATE]++;
        if (!g.quiet)
            fprintf(stderr, "[late-dup] job=%u round=%u chunk=%u worker=%u -- round already completed\n",
                    p->job_id, p->round, p->chunk_id, p->worker_id);
        return;
    }
    if (s->state == SLOT_FLUSHED) {
        if (bitmap_test(s->bitmap, p->worker_id) && !resend) {
            g.stats[NS_DUPLICATE]++;
            return;
        }
        forward_fallback(pkt, p); /* the PS owns this key now */
        return;
    }
    if (bitmap_test(s->bitmap, p->worker_id) && resend) {
        /* A worker resending something we hold: the round is stuck on another
         * worker's lost packet. Hand the partial sum to the PS (ATP's flush). */
        g.stats[NS_RESEND_DUPLICATE]++;
        g.stats[NS_SLOT_FLUSHED_PARTIAL]++;
        emit_aggregate(s, NETSUM_F_PARTIAL);
        uint32_t job_id = s->key.job_id;
        retire_state(s, now, SLOT_FLUSHED);
        job_release_slot(job_id);
        return;
    }
    if (bitmap_test(s->bitmap, p->worker_id)) {
        g.stats[NS_DUPLICATE]++;
        if (!g.quiet)
            fprintf(stderr, "[dup] job=%u round=%u chunk=%u worker=%u already contributed -- dropping duplicate\n",
                    p->job_id, p->round, p->chunk_id, p->worker_id);
        return;
    }

    const uint8_t *v = pkt + NETSUM_HDR_SIZE;
    for (int i = 0; i < p->chunk_len; i++) {
        uint32_t be;
        memcpy(&be, v + 4 * i, 4);
        s->overflowed |= (uint8_t)netsum_add_i32(&s->sum[i], (int32_t)ntohl(be));
    }
    if (p->flags & NETSUM_F_OVERFLOW) /* the worker's own value saturated */
        s->overflowed = 1;
    bitmap_set(s->bitmap, p->worker_id);
    s->contributions++;
    s->contributors++;
    s->touched_us = now;
    g.stats[NS_ACCEPTED]++;
    if (s->contributors < s->fanin)
        return;

    if (s->overflowed) {
        g.stats[NS_OVERFLOW]++;
        fprintf(stderr, "[overflow] job=%u round=%u chunk=%u contributions=%u -- sum not representable in Q16.16\n",
                p->job_id, p->round, p->chunk_id, s->contributions);
    } else if (!g.quiet) {
        fprintf(stderr, "[complete] job=%u round=%u chunk=%u contributions=%u sum[0]=%.9g latency_us=%lld\n",
                p->job_id, p->round, p->chunk_id, s->contributions, netsum_from_scaled(s->sum[0], s->frac_bits),
                (long long)(now - s->first_us));
    }
    emit_aggregate(s, 0);
    g.stats[NS_SLOT_COMPLETED]++;
    retire_state(s, now, SLOT_COMPLETED);
    job_release_slot(p->job_id);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--slot-capacity-log2 N] [--tombstone-ttl-ms N] [--quiet] [--profile]\n"
            "          <listen_port> <downstream_ip> <downstream_port>\n"
            "          [max_packets=0] [max_slots_per_job=0] [slot_ttl_ms=0]\n"
            "  max_slots_per_job: per-job cap on ACCUMULATING slots (0 = none)\n"
            "  slot_ttl_ms:       drop ACCUMULATING slots idle this long (0 = never)\n"
            "  --tombstone-ttl-ms: keep completed rounds this long to absorb late\n"
            "                     duplicates (default 2000)\n"
            "  SIGUSR1 prints [stats] per job and one [stats-all] counter line.\n",
            prog);
}

int main(int argc, char **argv)
{
    unsigned cap_log2 = 16;
    g.tomb_ttl_ms = 2000;
    int a = 1;
    for (; a < argc && strncmp(argv[a], "--", 2) == 0; a++) {
        if (strcmp(argv[a], "--quiet") == 0) {
            g.quiet = 1;
        } else if (strcmp(argv[a], "--profile") == 0) {
            g.profile = 1;
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
    if (argc - a < 3) {
        usage(argv[0]);
        return 1;
    }
    int listen_port = atoi(argv[a]);
    const char *downstream_ip = argv[a + 1];
    int downstream_port = atoi(argv[a + 2]);
    long max_packets = argc - a > 3 ? atol(argv[a + 3]) : 0;
    g.quota = argc - a > 4 ? atol(argv[a + 4]) : 0;
    g.slot_ttl_ms = argc - a > 5 ? atol(argv[a + 5]) : 0;

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

    int in_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (in_sock < 0) {
        perror("socket(in)");
        return 1;
    }
    int one = 1;
    setsockopt(in_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int rcvbuf = 4 << 20;
    setsockopt(in_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct sockaddr_in in_addr;
    memset(&in_addr, 0, sizeof(in_addr));
    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = INADDR_ANY;
    in_addr.sin_port = htons((uint16_t)listen_port);
    if (bind(in_sock, (struct sockaddr *)&in_addr, sizeof(in_addr)) < 0) {
        perror("bind");
        return 1;
    }

    /* Wake periodically so tombstone expiry and the TTL reaper run when idle. */
    long tick_ms = HOUSEKEEPING_MS;
    if (g.slot_ttl_ms > 0 && g.slot_ttl_ms / 4 < tick_ms)
        tick_ms = g.slot_ttl_ms / 4 > 0 ? g.slot_ttl_ms / 4 : 1;
    struct timeval tv = {tick_ms / 1000, (tick_ms % 1000) * 1000};
    setsockopt(in_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    g.out_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g.out_sock < 0) {
        perror("socket(out)");
        return 1;
    }
    memset(&g.downstream, 0, sizeof(g.downstream));
    g.downstream.sin_family = AF_INET;
    g.downstream.sin_port = htons((uint16_t)downstream_port);
    if (inet_pton(AF_INET, downstream_ip, &g.downstream.sin_addr) != 1) {
        fprintf(stderr, "invalid downstream_ip: %s\n", downstream_ip);
        return 1;
    }
    fprintf(stderr, "userspace aggregator listening on :%d, forwarding to %s:%d\n",
            listen_port, downstream_ip, downstream_port);

    uint8_t pkt[NETSUM_MAX_PACKET_SIZE + 1];
    long packets_in = 0;
    int64_t last_reap = now_us();
    while (!g_stop && (max_packets == 0 || packets_in < max_packets)) {
        int64_t now = now_us();
        if (g.slot_ttl_ms > 0 && now - last_reap >= (int64_t)tick_ms * 1000) {
            reap_expired(now);
            last_reap = now;
        }
        g.stats[NS_SLOT_RETIRED_TTL] += (uint64_t)tomb_expire(&g.tombs, &g.table, now,
                                                             (int64_t)g.tomb_ttl_ms * 1000);
        if (g_dump_requested) {
            g_dump_requested = 0;
            dump_stats();
        }

        ssize_t n = recvfrom(in_sock, pkt, sizeof(pkt), 0, NULL, NULL);
        if (n < 0)
            continue; /* EINTR (SIGUSR1) or EAGAIN (housekeeping tick) */
        packets_in++;
        g.stats[NS_RX_TOTAL]++;
        struct netsum_parsed p;
        enum netsum_verdict v = netsum_parse(pkt, pkt + n, &p);
        if (v != NETSUM_OK) {
            g.stats[NS_FROM_VERDICT(v)]++;
            continue;
        }
        if (p.kind == NETSUM_KIND_ACK) {
            handle_ack(&p);
            continue;
        }
        if (p.kind != NETSUM_KIND_RAW) {
            g.stats[NS_REJ_KIND]++;
            continue;
        }
        if (g.profile) { /* algorithm cost only: excludes recvfrom, includes the forward sendto */
            struct timespec t1, t2;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            handle_contribution(pkt, &p, now_us());
            clock_gettime(CLOCK_MONOTONIC, &t2);
            g.profile_ns += (uint64_t)((t2.tv_sec - t1.tv_sec) * 1000000000LL + (t2.tv_nsec - t1.tv_nsec));
            g.profile_pkts++;
        } else {
            handle_contribution(pkt, &p, now_us());
        }
    }
    fprintf(stderr, "userspace aggregator: %ld packets in, %ld aggregated packets out\n",
            packets_in, g.packets_out);
    dump_stats();
    close(in_sock);
    close(g.out_sock);
    return 0;
}
