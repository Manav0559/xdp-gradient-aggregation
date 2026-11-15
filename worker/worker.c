/* NetSum worker: generates synthetic gradient chunks, quantizes them to
 * Q16.16 fixed-point, and sends them over UDP following grad_proto.h -- the
 * same sender binary feeds all three benchmark configurations (no-agg,
 * userspace-agg, XDP-agg); only the destination address changes.
 *
 * Deliberately synthetic gradients, not a real training loop -- named
 * honestly in the project docs as such. Values are drawn from a fixed seed
 * so every worker/run combination is reproducible.
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "../protocol/grad_proto.h"

static double xorshift_double(uint64_t *state) {
    /* Deterministic, seedable, dependency-free PRNG -- reproducibility
     * across (worker_id, round) matters more here than statistical
     * quality, and this avoids pulling in a real RNG library for a
     * synthetic-gradient generator. */
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return ((double)(x % 2000000) / 1000000.0) - 1.0;  /* uniform in [-1, 1) */
}

static long now_micros(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000000L + tv.tv_usec;
}

static int oneshot_main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr,
            "usage: %s <dest_ip> <dest_port> <job_id> <worker_id> <num_workers> "
            "<num_rounds> <chunk_len> [max_abs_grad=1.0] [fixed_value]\n"
            "  fixed_value: if given, every gradient component sent is exactly\n"
            "  this constant instead of a pseudo-random value -- deterministic\n"
            "  test mode only, so a correctness test can assert an exact\n"
            "  expected sum (num_workers * fixed_value) instead of re-deriving\n"
            "  the PRNG sequence in a second language.\n", argv[0]);
        return 1;
    }
    const char *dest_ip = argv[1];
    int dest_port = atoi(argv[2]);
    uint32_t job_id = (uint32_t)strtoul(argv[3], NULL, 10);
    uint16_t worker_id = (uint16_t)atoi(argv[4]);
    uint16_t num_workers = (uint16_t)atoi(argv[5]);
    int num_rounds = atoi(argv[6]);
    uint16_t chunk_len = (uint16_t)atoi(argv[7]);
    double max_abs_grad = argc > 8 ? atof(argv[8]) : 1.0;
    int has_fixed_value = argc > 9;
    double fixed_value = has_fixed_value ? atof(argv[9]) : 0.0;

    if (chunk_len > NETSUM_MAX_CHUNK_LEN) {
        fprintf(stderr, "chunk_len %u exceeds NETSUM_MAX_CHUNK_LEN %d\n",
                chunk_len, NETSUM_MAX_CHUNK_LEN);
        return 1;
    }
    if (!netsum_sum_fits_i32(num_workers, max_abs_grad)) {
        fprintf(stderr,
            "warning: num_workers=%u x max_abs_grad=%.3f in Q16.16 may overflow "
            "int32_t on full-magnitude adversarial input -- reduce max_abs_grad "
            "or num_workers, or this is an intentional overflow test\n",
            num_workers, max_abs_grad);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)dest_port);
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) != 1) {
        fprintf(stderr, "invalid dest_ip: %s\n", dest_ip);
        return 1;
    }

    uint8_t packet[NETSUM_MAX_PACKET_SIZE];
    struct grad_hdr *hdr = (struct grad_hdr *)packet;
    int32_t *values = (int32_t *)(packet + NETSUM_HDR_SIZE);
    size_t packet_len = NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t) + NETSUM_BITMAP_BYTES;
    /* v2 contributor-bitmap trailer: only this worker's bit. */
    uint8_t *trailer = packet + NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t);
    memset(trailer, 0, NETSUM_BITMAP_BYTES);
    if (worker_id < NETSUM_MAX_FANIN)
        trailer[worker_id / 8] = (uint8_t)(1u << (worker_id % 8));

    /* Seed depends on worker_id so different workers generate different
     * (but reproducible) gradient values for the same round. */
    uint64_t rng_state = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)worker_id << 32) ^ 0xA5A5A5A5u;

    long t_start = now_micros();
    for (int round = 0; round < num_rounds; round++) {
        hdr->job_id = htonl(job_id);
        hdr->round = htonl((uint32_t)round);
        hdr->chunk_id = htonl(0);  /* single-chunk gradients for the MVP; multi-chunk is a direct extension */
        hdr->worker_id = htons(worker_id);
        hdr->num_workers = htons(num_workers);
        hdr->chunk_len = htons(chunk_len);
        hdr->flags = htons(NETSUM_FLAGS_V2);

        for (int i = 0; i < chunk_len; i++) {
            double v = has_fixed_value ? fixed_value : xorshift_double(&rng_state) * max_abs_grad;
            values[i] = htonl((uint32_t)netsum_to_fixed(v));
        }

        ssize_t sent = sendto(sock, packet, packet_len, 0,
                               (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            fprintf(stderr, "sendto failed at round %d: %s\n", round, strerror(errno));
            return 1;
        }
    }
    long t_end = now_micros();

    fprintf(stderr, "worker %u: sent %d rounds x %u values to %s:%d in %ld us\n",
            worker_id, num_rounds, chunk_len, dest_ip, dest_port, t_end - t_start);
    close(sock);
    return 0;
}

/* ---- reliable mode (docs/DESIGN_NOTES.md §Reliability) --------------------
 * A gradient of `vector_len` values per round is split into chunks of
 * `chunk_len`. Up to `window` chunks are in flight; each waits for its result
 * (an ACK from the parameter server). A chunk with no result after its RTO is
 * re-sent with RESEND, with exponential backoff (x2, capped at 1 s); after
 * `max_retries` the worker gives up with exit code 2. REGISTER is re-sent with
 * every retransmission, so a lost registration heals itself. Single thread,
 * poll() on one socket, CLOCK_MONOTONIC. */

struct rel_chunk {
    uint8_t state; /* 0 unsent, 1 in flight, 2 done */
    uint8_t retries;
    int64_t deadline_us;
    int64_t rto_us;
};

struct rel {
    int sock;
    struct sockaddr_in to, ps;
    uint32_t job;
    uint16_t worker, workers, chunk_len, last_len;
    uint32_t rounds, chunks_per_round;
    unsigned window, max_retries, drop_every, drop_result_every;
    int64_t rto_us;
    int sync, has_fixed;
    double fixed;
    uint64_t seed;
    struct rel_chunk *c;
    int64_t *round_start, *round_end;
    uint32_t *round_left;
    uint64_t sent, resent, results, dup_results, mismatches, overflow_results, dropped_tx, dropped_rx;
    uint64_t first_tx, results_seen;
};

static int64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int parse_hostport(const char *spec, struct sockaddr_in *out)
{
    char host[64];
    const char *colon = strrchr(spec, ':');
    if (!colon || (size_t)(colon - spec) >= sizeof(host))
        return -1;
    memcpy(host, spec, (size_t)(colon - spec));
    host[colon - spec] = 0;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)atoi(colon + 1));
    return inet_pton(AF_INET, host, &out->sin_addr) == 1 ? 0 : -1;
}

static uint16_t rel_len(const struct rel *r, uint32_t chunk)
{
    return chunk + 1 == r->chunks_per_round ? r->last_len : r->chunk_len;
}

/* Deterministic value for (seed, worker, round, chunk, lane). */
static int32_t rel_value(const struct rel *r, uint32_t round, uint32_t chunk, unsigned lane)
{
    if (r->has_fixed)
        return netsum_to_fixed(r->fixed);
    uint64_t x = r->seed ^ ((uint64_t)r->worker << 48) ^ ((uint64_t)round << 24) ^ ((uint64_t)chunk << 8) ^ lane;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return netsum_to_fixed(((double)(x % 2000001) / 1000000.0) - 1.0);
}

static void rel_send(struct rel *r, uint32_t idx, int resend)
{
    uint8_t pkt[NETSUM_MAX_PACKET_SIZE];
    uint32_t round = idx / r->chunks_per_round, chunk = idx % r->chunks_per_round;
    uint16_t len = rel_len(r, chunk);
    struct grad_hdr *h = (struct grad_hdr *)pkt;
    h->job_id = htonl(r->job);
    h->round = htonl(round);
    h->chunk_id = htonl(chunk);
    h->worker_id = htons(r->worker);
    h->num_workers = htons(r->workers);
    h->chunk_len = htons(len);
    h->flags = htons((uint16_t)(NETSUM_FLAGS_V2 | (resend ? NETSUM_F_RESEND : 0)));
    for (unsigned i = 0; i < len; i++) {
        uint32_t be = htonl((uint32_t)rel_value(r, round, chunk, i));
        memcpy(pkt + NETSUM_HDR_SIZE + 4 * i, &be, 4);
    }
    uint8_t *bm = pkt + NETSUM_HDR_SIZE + 4 * (size_t)len;
    memset(bm, 0, NETSUM_BITMAP_BYTES);
    bm[r->worker / 8] = (uint8_t)(1u << (r->worker % 8));
    size_t plen = NETSUM_HDR_SIZE + 4 * (size_t)len + NETSUM_BITMAP_BYTES;
    if (!resend && r->drop_every && ++r->first_tx % r->drop_every == 0) {
        r->dropped_tx++; /* simulated loss of a first transmission */
        return;
    }
    sendto(r->sock, pkt, plen, 0, (struct sockaddr *)&r->to, sizeof(r->to));
}

static void rel_register(struct rel *r)
{
    uint8_t pkt[NETSUM_HDR_SIZE + NETSUM_BITMAP_BYTES];
    struct grad_hdr *h = (struct grad_hdr *)pkt;
    h->job_id = htonl(r->job);
    h->round = 0;
    h->chunk_id = 0;
    h->worker_id = htons(r->worker);
    h->num_workers = htons(r->workers);
    h->chunk_len = 0;
    h->flags = htons((uint16_t)(NETSUM_FLAGS_V2 | NETSUM_F_REGISTER));
    memset(pkt + NETSUM_HDR_SIZE, 0, NETSUM_BITMAP_BYTES);
    pkt[NETSUM_HDR_SIZE + r->worker / 8] = (uint8_t)(1u << (r->worker % 8));
    sendto(r->sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&r->ps, sizeof(r->ps));
}

static void rel_on_result(struct rel *r, const uint8_t *pkt, ssize_t n, int64_t now)
{
    if (n < (ssize_t)NETSUM_HDR_SIZE)
        return;
    const struct grad_hdr *h = (const struct grad_hdr *)pkt;
    uint16_t flags = ntohs(h->flags);
    if (!(flags & NETSUM_F_ACK) || ntohl(h->job_id) != r->job)
        return;
    uint32_t round = ntohl(h->round), chunk = ntohl(h->chunk_id);
    if (round >= r->rounds || chunk >= r->chunks_per_round)
        return;
    uint16_t len = ntohs(h->chunk_len);
    if (len != rel_len(r, chunk) || n < (ssize_t)(NETSUM_HDR_SIZE + 4 * (size_t)len))
        return;
    uint32_t idx = round * r->chunks_per_round + chunk;
    struct rel_chunk *c = &r->c[idx];
    if (c->state != 1) {
        r->dup_results++;
        return;
    }
    if (r->drop_result_every && ++r->results_seen % r->drop_result_every == 0) {
        r->dropped_rx++; /* simulated loss of a result */
        return;
    }
    c->state = 2;
    r->results++;
    if (flags & NETSUM_F_OVERFLOW) {
        r->overflow_results++;
    } else if (r->has_fixed) {
        int32_t want = (int32_t)((int64_t)netsum_to_fixed(r->fixed) * r->workers);
        for (unsigned i = 0; i < len; i++) {
            uint32_t be;
            memcpy(&be, pkt + NETSUM_HDR_SIZE + 4 * i, 4);
            if ((int32_t)ntohl(be) != want) {
                r->mismatches++;
                break;
            }
        }
    }
    if (--r->round_left[round] == 0)
        r->round_end[round] = now;
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static int reliable_main(int argc, char **argv)
{
    struct rel r;
    memset(&r, 0, sizeof(r));
    r.workers = 1;
    r.rounds = 1;
    r.chunk_len = NETSUM_MAX_CHUNK_LEN;
    r.window = 64;
    r.rto_us = 50000;
    r.max_retries = 10;
    r.seed = 0x9E3779B97F4A7C15ULL;
    uint32_t vector_len = 0;
    int have_to = 0, have_ps = 0;
    for (int a = 1; a < argc; a++) {
        const char *k = argv[a], *v = a + 1 < argc ? argv[a + 1] : NULL;
        if (!strcmp(k, "--sync")) { r.sync = 1; continue; }
        if (!v) { fprintf(stderr, "missing value for %s\n", k); return 1; }
        a++;
        if (!strcmp(k, "--to")) have_to = parse_hostport(v, &r.to) == 0;
        else if (!strcmp(k, "--ps")) have_ps = parse_hostport(v, &r.ps) == 0;
        else if (!strcmp(k, "--job")) r.job = (uint32_t)strtoul(v, NULL, 10);
        else if (!strcmp(k, "--worker")) r.worker = (uint16_t)atoi(v);
        else if (!strcmp(k, "--workers")) r.workers = (uint16_t)atoi(v);
        else if (!strcmp(k, "--rounds")) r.rounds = (uint32_t)strtoul(v, NULL, 10);
        else if (!strcmp(k, "--vector-len")) vector_len = (uint32_t)strtoul(v, NULL, 10);
        else if (!strcmp(k, "--chunk-len")) r.chunk_len = (uint16_t)atoi(v);
        else if (!strcmp(k, "--window")) r.window = (unsigned)atoi(v);
        else if (!strcmp(k, "--rto-ms")) r.rto_us = (int64_t)atoi(v) * 1000;
        else if (!strcmp(k, "--max-retries")) r.max_retries = (unsigned)atoi(v);
        else if (!strcmp(k, "--fixed")) { r.has_fixed = 1; r.fixed = atof(v); }
        else if (!strcmp(k, "--seed")) r.seed = strtoull(v, NULL, 10);
        else if (!strcmp(k, "--drop-every")) r.drop_every = (unsigned)atoi(v);
        else if (!strcmp(k, "--drop-result-every")) r.drop_result_every = (unsigned)atoi(v);
        else { fprintf(stderr, "unknown option %s\n", k); return 1; }
    }
    if (!have_to || !have_ps || r.workers < 1 || r.workers > NETSUM_MAX_FANIN || r.worker >= r.workers ||
        r.chunk_len < 1 || r.chunk_len > NETSUM_MAX_CHUNK_LEN || r.window < 1 || r.rounds < 1) {
        fprintf(stderr,
                "usage: worker --mode reliable --to IP:PORT --ps IP:PORT --job J --worker W --workers N\n"
                "         [--rounds R] [--vector-len V] [--chunk-len C<=64] [--window W] [--rto-ms MS]\n"
                "         [--max-retries K] [--fixed X | --seed S] [--sync] [--drop-every K] [--drop-result-every K]\n");
        return 1;
    }
    if (vector_len == 0)
        vector_len = r.chunk_len;
    r.chunks_per_round = (vector_len + r.chunk_len - 1) / r.chunk_len;
    r.last_len = (uint16_t)(vector_len - (r.chunks_per_round - 1) * r.chunk_len);
    uint64_t total = (uint64_t)r.rounds * r.chunks_per_round;
    r.c = calloc(total, sizeof(*r.c));
    r.round_start = calloc(r.rounds, sizeof(int64_t));
    r.round_end = calloc(r.rounds, sizeof(int64_t));
    r.round_left = calloc(r.rounds, sizeof(uint32_t));
    unsigned *inflight = calloc(r.window, sizeof(unsigned));
    if (!r.c || !r.round_start || !r.round_end || !r.round_left || !inflight) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    for (uint32_t i = 0; i < r.rounds; i++)
        r.round_left[i] = r.chunks_per_round;
    r.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (r.sock < 0) {
        perror("socket");
        return 1;
    }
    fcntl(r.sock, F_SETFL, fcntl(r.sock, F_GETFL) | O_NONBLOCK);
    int buf = 4 << 20;
    setsockopt(r.sock, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(r.sock, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    struct sockaddr_in any;
    memset(&any, 0, sizeof(any));
    any.sin_family = AF_INET;
    if (bind(r.sock, (struct sockaddr *)&any, sizeof(any)) < 0) {
        perror("bind");
        return 1;
    }

    rel_register(&r);
    int64_t t0 = mono_us();
    uint64_t next = 0, done = 0;
    unsigned nin = 0;
    uint8_t pkt[NETSUM_MAX_PACKET_SIZE + 1];
    while (done < total) {
        int64_t now = mono_us();
        uint64_t limit = total;
        if (r.sync) {
            uint32_t cur = (uint32_t)(done / r.chunks_per_round); /* rounds finish in order under --sync */
            limit = (uint64_t)(cur + 1) * r.chunks_per_round;
        }
        while (nin < r.window && next < limit) {
            uint32_t round = (uint32_t)(next / r.chunks_per_round);
            if (!r.round_start[round])
                r.round_start[round] = now;
            r.c[next].state = 1;
            r.c[next].rto_us = r.rto_us;
            r.c[next].deadline_us = now + r.rto_us;
            rel_send(&r, (uint32_t)next, 0);
            r.sent++;
            inflight[nin++] = (unsigned)next++;
        }
        int64_t earliest = INT64_MAX;
        for (unsigned i = 0; i < nin; i++)
            if (r.c[inflight[i]].deadline_us < earliest)
                earliest = r.c[inflight[i]].deadline_us;
        int timeout_ms = earliest == INT64_MAX ? 100 : (int)((earliest - now + 999) / 1000);
        struct pollfd pfd = {r.sock, POLLIN, 0};
        if (poll(&pfd, 1, timeout_ms < 0 ? 0 : timeout_ms) > 0) {
            ssize_t n;
            while ((n = recv(r.sock, pkt, sizeof(pkt), 0)) > 0)
                rel_on_result(&r, pkt, n, mono_us());
        }
        now = mono_us();
        int registered_again = 0;
        for (unsigned i = 0; i < nin;) {
            struct rel_chunk *c = &r.c[inflight[i]];
            if (c->state == 2) {
                inflight[i] = inflight[--nin];
                done++;
                continue;
            }
            if (c->deadline_us <= now) {
                if (++c->retries > r.max_retries) {
                    fprintf(stderr, "worker %u: chunk %u gave up after %u retries\n", r.worker, inflight[i], r.max_retries);
                    return 2;
                }
                c->rto_us = c->rto_us * 2 > 1000000 ? 1000000 : c->rto_us * 2;
                c->deadline_us = now + c->rto_us;
                if (!registered_again++)
                    rel_register(&r);
                rel_send(&r, inflight[i], 1);
                r.resent++;
            }
            i++;
        }
    }
    int64_t elapsed = mono_us() - t0;
    int64_t *rt = calloc(r.rounds, sizeof(int64_t));
    for (uint32_t i = 0; i < r.rounds; i++)
        rt[i] = r.round_end[i] - r.round_start[i];
    qsort(rt, r.rounds, sizeof(int64_t), cmp_i64);
#define PCT(p) rt[(size_t)((double)(r.rounds - 1) * (p))]
    printf("{\"worker_id\":%u,\"rounds\":%u,\"chunks\":%llu,\"sent\":%llu,\"resent\":%llu,\"results\":%llu,"
           "\"dup_results\":%llu,\"result_mismatches\":%llu,\"overflow_results\":%llu,\"dropped_tx\":%llu,"
           "\"dropped_rx\":%llu,\"verified\":%s,\"elapsed_us\":%lld,\"round_us_p50\":%lld,\"round_us_p95\":%lld,"
           "\"round_us_p99\":%lld,\"round_us_max\":%lld}\n",
           r.worker, r.rounds, (unsigned long long)total, (unsigned long long)r.sent, (unsigned long long)r.resent,
           (unsigned long long)r.results, (unsigned long long)r.dup_results, (unsigned long long)r.mismatches,
           (unsigned long long)r.overflow_results, (unsigned long long)r.dropped_tx, (unsigned long long)r.dropped_rx,
           r.has_fixed ? "true" : "false", (long long)elapsed, (long long)PCT(0.50), (long long)PCT(0.95),
           (long long)PCT(0.99), (long long)rt[r.rounds - 1]);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2 && strcmp(argv[1], "--mode") == 0) {
        const char *mode = argv[2];
        argv[2] = argv[0];
        if (strcmp(mode, "reliable") == 0)
            return reliable_main(argc - 2, argv + 2);
        if (strcmp(mode, "oneshot") == 0)
            return oneshot_main(argc - 2, argv + 2);
        fprintf(stderr, "unknown mode %s (oneshot|reliable)\n", mode);
        return 1;
    }
    return oneshot_main(argc, argv);
}
