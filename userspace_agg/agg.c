/* NetSum userspace aggregator -- baseline #2, and the fairness anchor for
 * the whole project's central measurement. Implements byte-for-byte the
 * same slot/accumulate/emit algorithm the eventual XDP program will run in
 * the kernel: receive a raw per-worker contribution, accumulate it into a
 * per-(job,round,chunk) slot, and once every expected worker has
 * contributed, emit exactly one summed packet onward -- never forward a
 * partial contribution.
 *
 * This process is intentionally single-threaded, single-socket: the
 * project's core comparison is "the identical algorithm, in the kernel
 * fast path vs. in an ordinary process," and adding userspace
 * multi-threading here would conflate a threading advantage with the
 * kernel-fast-path question the benchmark exists to isolate.
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
    /* See paramserver.c's identical field for why this exists: without it,
     * a duplicate send from the same worker_id double-counts and closes
     * the slot with a wrong sum -- the exact failure mode
     * tests/test_correctness.py's duplicate-worker case checks for. */
    uint8_t seen_worker[MAX_TRACKED_WORKERS];
} slot_t;

static slot_t g_slots[SLOT_TABLE_CAPACITY];

static uint64_t slot_key(uint32_t job_id, uint32_t round, uint32_t chunk_id) {
    uint64_t h = 1469598103934665603ULL;
    uint32_t fields[3] = {job_id, round, chunk_id};
    const uint8_t *bytes = (const uint8_t *)fields;
    for (size_t i = 0; i < sizeof(fields); i++) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    return h;
}

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

/* A completed slot is freed immediately after emitting -- unlike the
 * parameter server (which keeps completed slots around for the benchmark
 * harness to inspect), the aggregator's slot table must not grow without
 * bound across a long run, so this frees the entry back to "not in use"
 * once it closes. This mirrors a real constraint the eventual BPF map
 * (fixed-size, no growth) will have too. */
static void free_slot(slot_t *s) {
    s->in_use = 0;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <listen_port> <downstream_ip> <downstream_port> <max_packets=0>\n",
            argv[0]);
        return 1;
    }
    int listen_port = atoi(argv[1]);
    const char *downstream_ip = argv[2];
    int downstream_port = atoi(argv[3]);
    long max_packets = argc > 4 ? atol(argv[4]) : 0;

    int in_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (in_sock < 0) { perror("socket(in)"); return 1; }
    int reuse = 1;
    setsockopt(in_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in in_addr;
    memset(&in_addr, 0, sizeof(in_addr));
    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = INADDR_ANY;
    in_addr.sin_port = htons((uint16_t)listen_port);
    if (bind(in_sock, (struct sockaddr *)&in_addr, sizeof(in_addr)) < 0) {
        perror("bind");
        return 1;
    }

    int out_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (out_sock < 0) { perror("socket(out)"); return 1; }
    struct sockaddr_in downstream;
    memset(&downstream, 0, sizeof(downstream));
    downstream.sin_family = AF_INET;
    downstream.sin_port = htons((uint16_t)downstream_port);
    if (inet_pton(AF_INET, downstream_ip, &downstream.sin_addr) != 1) {
        fprintf(stderr, "invalid downstream_ip: %s\n", downstream_ip);
        return 1;
    }

    fprintf(stderr, "userspace aggregator listening on :%d, forwarding to %s:%d\n",
            listen_port, downstream_ip, downstream_port);

    uint8_t in_packet[NETSUM_MAX_PACKET_SIZE];
    uint8_t out_packet[NETSUM_MAX_PACKET_SIZE];
    long packets_in = 0, packets_out = 0;

    while (max_packets == 0 || packets_in < max_packets) {
        ssize_t n = recvfrom(in_sock, in_packet, sizeof(in_packet), 0, NULL, NULL);
        if (n < (ssize_t)NETSUM_HDR_SIZE) continue;
        packets_in++;

        struct grad_hdr *hdr = (struct grad_hdr *)in_packet;
        int32_t *values = (int32_t *)(in_packet + NETSUM_HDR_SIZE);

        uint32_t job_id = ntohl(hdr->job_id);
        uint32_t round = ntohl(hdr->round);
        uint32_t chunk_id = ntohl(hdr->chunk_id);
        uint16_t worker_id = ntohs(hdr->worker_id);
        uint16_t num_workers = ntohs(hdr->num_workers);
        uint16_t chunk_len = ntohs(hdr->chunk_len);

        if (chunk_len > NETSUM_MAX_CHUNK_LEN) continue;  /* malformed, drop -- mirrors XDP_DROP for a bad parse */
        if (worker_id >= MAX_TRACKED_WORKERS) continue;

        slot_t *slot = find_or_create_slot(job_id, round, chunk_id);
        if (!slot) { fprintf(stderr, "slot table full, dropping\n"); continue; }

        if (slot->contributions_received == 0) {
            slot->chunk_len = chunk_len;
            slot->num_workers_expected = num_workers;
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

        if (slot->contributions_received < slot->num_workers_expected) {
            /* Partial contribution: fully absorbed, nothing forwarded --
             * mirrors XDP_DROP in the eventual kernel program. This is the
             * mechanism that cuts aggregator-uplink traffic: N raw packets
             * in, exactly one summed packet out. */
            continue;
        }

        /* Last contribution just arrived: emit exactly one aggregated
         * packet downstream -- mirrors XDP_TX in the eventual kernel
         * program, and is the only place this process's slot state
         * crosses back onto the wire. */
        struct grad_hdr *out_hdr = (struct grad_hdr *)out_packet;
        int32_t *out_values = (int32_t *)(out_packet + NETSUM_HDR_SIZE);
        out_hdr->job_id = htonl(job_id);
        out_hdr->round = htonl(round);
        out_hdr->chunk_id = htonl(chunk_id);
        out_hdr->worker_id = htons(0);       /* aggregated: no single worker owns this */
        out_hdr->num_workers = htons(1);     /* tells the receiver: exactly one contribution closes this slot */
        out_hdr->chunk_len = htons(slot->chunk_len);
        out_hdr->flags = htons(0);
        for (int i = 0; i < slot->chunk_len; i++) {
            out_values[i] = htonl((uint32_t)slot->sum[i]);
        }
        size_t out_len = NETSUM_HDR_SIZE + (size_t)slot->chunk_len * sizeof(int32_t);
        if (sendto(out_sock, out_packet, out_len, 0,
                   (struct sockaddr *)&downstream, sizeof(downstream)) < 0) {
            perror("sendto(downstream)");
        } else {
            packets_out++;
        }
        free_slot(slot);
    }

    fprintf(stderr, "userspace aggregator: %ld packets in, %ld aggregated packets out\n",
            packets_in, packets_out);
    close(in_sock);
    close(out_sock);
    return 0;
}
