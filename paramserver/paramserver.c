/* NetSum parameter server -- the final receiver in all three benchmark
 * configurations:
 *   --mode noagg : baseline #1. Every worker sends here directly; this
 *                  process itself sums num_workers raw contributions per
 *                  (job_id, round, chunk_id) slot -- the naive
 *                  parameter-server pattern ATP/SwitchML improve on.
 *   --mode agg   : baseline #2/#3 receiver. An upstream aggregator (the
 *                  userspace AF_INET aggregator, or eventually the XDP
 *                  program) has already summed all workers' contributions
 *                  into one packet per slot; this process just records it.
 *                  Same slot-table code path either way -- in "agg" mode
 *                  num_workers is effectively 1 (one packet closes the
 *                  slot), so there is exactly one accumulation code path
 *                  for both modes, not two.
 *
 * Slot table: fixed-capacity open-addressing hash table keyed by
 * (job_id, round, chunk_id). Sized for one benchmark run's worth of
 * (job, round) pairs, not designed as a general-purpose long-running
 * service -- a real production parameter server would need slot eviction
 * for state that never completes; this is out of scope for the MVP and
 * noted as such rather than silently absent.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../protocol/grad_proto.h"

#define SLOT_TABLE_CAPACITY 65536  /* must be a power of 2 */

#define MAX_TRACKED_WORKERS 256

typedef struct {
    int in_use;
    uint32_t job_id, round, chunk_id;
    uint16_t num_workers_expected;
    uint16_t contributions_received;
    int32_t sum[NETSUM_MAX_CHUNK_LEN];
    uint16_t chunk_len;
    long first_seen_micros;
    long completed_micros;  /* 0 until complete */
    /* Which worker_ids have already contributed to this slot -- without
     * this, a duplicate send from the same worker_id (a retried packet, a
     * buggy worker, or a deliberate adversarial test) gets double-counted
     * as if it were a distinct worker's contribution, closing the slot
     * with a silently wrong sum and an undercount of real contributors.
     * worker_id > MAX_TRACKED_WORKERS is rejected outright below. */
    uint8_t seen_worker[MAX_TRACKED_WORKERS];
} slot_t;

static slot_t g_slots[SLOT_TABLE_CAPACITY];

static uint64_t slot_key(uint32_t job_id, uint32_t round, uint32_t chunk_id) {
    /* FNV-1a over the three fields -- good-enough dispersion for a bounded
     * benchmark run's key space, no external hash library needed. */
    uint64_t h = 1469598103934665603ULL;
    uint32_t fields[3] = {job_id, round, chunk_id};
    const uint8_t *bytes = (const uint8_t *)fields;
    for (size_t i = 0; i < sizeof(fields); i++) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Open-addressing lookup-or-create. Returns NULL only if the table is
 * completely full (should never happen at benchmark scale; capacity is
 * chosen generously). */
static slot_t *find_or_create_slot(uint32_t job_id, uint32_t round, uint32_t chunk_id) {
    uint64_t h = slot_key(job_id, round, chunk_id);
    for (size_t probe = 0; probe < SLOT_TABLE_CAPACITY; probe++) {
        size_t idx = (h + probe) & (SLOT_TABLE_CAPACITY - 1);
        slot_t *s = &g_slots[idx];
        if (!s->in_use) {
            memset(s, 0, sizeof(*s));
            s->in_use = 1;
            s->job_id = job_id;
            s->round = round;
            s->chunk_id = chunk_id;
            return s;
        }
        if (s->job_id == job_id && s->round == round && s->chunk_id == chunk_id) {
            return s;
        }
    }
    return NULL;
}

static long now_micros(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000000L + tv.tv_usec;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <listen_port> <mode: noagg|agg> [max_packets=0 (0=unbounded)]\n", argv[0]);
        return 1;
    }
    int listen_port = atoi(argv[1]);
    int agg_mode = strcmp(argv[2], "agg") == 0;
    long max_packets = argc > 3 ? atol(argv[3]) : 0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)listen_port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    fprintf(stderr, "paramserver listening on :%d mode=%s\n", listen_port, agg_mode ? "agg" : "noagg");

    uint8_t packet[NETSUM_MAX_PACKET_SIZE];
    long packets_seen = 0;
    long slots_completed = 0;

    while (max_packets == 0 || packets_seen < max_packets) {
        ssize_t n = recvfrom(sock, packet, sizeof(packet), 0, NULL, NULL);
        if (n < (ssize_t)NETSUM_HDR_SIZE) continue;  /* truncated/garbage, drop */
        packets_seen++;

        struct grad_hdr *hdr = (struct grad_hdr *)packet;
        int32_t *values = (int32_t *)(packet + NETSUM_HDR_SIZE);

        uint32_t job_id = ntohl(hdr->job_id);
        uint32_t round = ntohl(hdr->round);
        uint32_t chunk_id = ntohl(hdr->chunk_id);
        uint16_t worker_id = ntohs(hdr->worker_id);
        uint16_t num_workers = ntohs(hdr->num_workers);
        uint16_t chunk_len = ntohs(hdr->chunk_len);
        (void)worker_id;

        if (chunk_len > NETSUM_MAX_CHUNK_LEN) continue;  /* malformed, drop */
        if (worker_id >= MAX_TRACKED_WORKERS) continue;  /* out of tracked range, drop */

        slot_t *slot = find_or_create_slot(job_id, round, chunk_id);
        if (!slot) { fprintf(stderr, "slot table full, dropping\n"); continue; }

        if (slot->contributions_received == 0) {
            slot->first_seen_micros = now_micros();
            slot->chunk_len = chunk_len;
            slot->num_workers_expected = agg_mode ? 1 : num_workers;
        }

        if (slot->seen_worker[worker_id]) {
            fprintf(stderr,
                "[dup] job=%u round=%u chunk=%u worker=%u already contributed -- dropping duplicate\n",
                job_id, round, chunk_id, worker_id);
            continue;
        }
        slot->seen_worker[worker_id] = 1;

        for (int i = 0; i < chunk_len && i < NETSUM_MAX_CHUNK_LEN; i++) {
            slot->sum[i] += (int32_t)ntohl((uint32_t)values[i]);
        }
        slot->contributions_received++;

        if (slot->contributions_received == slot->num_workers_expected && slot->completed_micros == 0) {
            slot->completed_micros = now_micros();
            slots_completed++;
            fprintf(stderr,
                "[complete] job=%u round=%u chunk=%u contributions=%u sum[0]=%.6f latency_us=%ld\n",
                job_id, round, chunk_id, slot->contributions_received,
                netsum_to_double(slot->sum[0]),
                slot->completed_micros - slot->first_seen_micros);
        }
    }

    fprintf(stderr, "paramserver: %ld packets seen, %ld slots completed\n", packets_seen, slots_completed);
    close(sock);
    return 0;
}
