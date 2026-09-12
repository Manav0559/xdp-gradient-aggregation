/* NetSum worker: generates synthetic gradient chunks, quantizes them to
 * Q16.16 fixed-point, and sends them over UDP following grad_proto.h -- the
 * same sender binary feeds all three benchmark configurations (no-agg,
 * userspace-agg, XDP-agg); only the destination address changes.
 *
 * Deliberately synthetic gradients, not a real training loop -- named
 * honestly in the project docs as such. Values are drawn from a fixed seed
 * so every worker/run combination is reproducible.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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

int main(int argc, char **argv) {
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
    size_t packet_len = NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t);

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
        hdr->flags = htons(0);

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
