/* Open-loop, paced load generator for benchmark-lite: one process sends
 * `rounds` single-chunk rounds for `workers` logical workers (round-major, so
 * slots complete progressively), at a target packet rate (0 = as fast as
 * possible). Every lane carries 1.0, so a round's exact sum is `workers`.
 * Linux batches with sendmmsg; elsewhere it falls back to sendto.
 * Prints one JSON line: packets offered, sent, elapsed time, achieved rate. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../protocol/grad_proto.h"

#define BATCH 32

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static size_t build(uint8_t *p, uint32_t job, uint32_t round, uint16_t w, uint16_t workers,
                    uint16_t chunk_len)
{
    struct grad_hdr *h = (struct grad_hdr *)p;
    h->job_id = htonl(job);
    h->round = htonl(round);
    h->chunk_id = 0;
    h->worker_id = htons(w);
    h->num_workers = htons(workers);
    h->chunk_len = htons(chunk_len);
    h->flags = htons(NETSUM_FLAGS_V2);
    int32_t one = (int32_t)htonl((uint32_t)netsum_to_fixed(1.0));
    uint8_t *v = p + NETSUM_HDR_SIZE;
    for (int i = 0; i < chunk_len; i++)
        memcpy(v + 4 * i, &one, 4);
    uint8_t *bm = v + 4 * chunk_len;
    memset(bm, 0, NETSUM_BITMAP_BYTES);
    bm[w / 8] = (uint8_t)(1u << (w % 8));
    return NETSUM_HDR_SIZE + 4u * chunk_len + NETSUM_BITMAP_BYTES;
}

int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: %s <dest_ip> <dest_port> <job_id> <workers> <rounds> <rate_pps|0> <chunk_len>\n",
                argv[0]);
        return 1;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1) {
        fprintf(stderr, "bad dest_ip\n");
        return 1;
    }
    uint32_t job = (uint32_t)strtoul(argv[3], NULL, 10);
    uint16_t workers = (uint16_t)atoi(argv[4]);
    uint32_t rounds = (uint32_t)strtoul(argv[5], NULL, 10);
    double rate = atof(argv[6]);
    uint16_t chunk_len = (uint16_t)atoi(argv[7]);
    if (workers < 1 || workers > NETSUM_MAX_FANIN || chunk_len < 1 || chunk_len > NETSUM_MAX_CHUNK_LEN) {
        fprintf(stderr, "workers must be 1..256 and chunk_len 1..64\n");
        return 1;
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }
    int sndbuf = 4 << 20;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("connect");
        return 1;
    }

    static uint8_t bufs[BATCH][NETSUM_MAX_PACKET_SIZE];
    uint64_t total = (uint64_t)rounds * workers, offered = 0, sent = 0, errors = 0;
    int64_t t0 = now_ns();
    double ns_per_pkt = rate > 0 ? 1e9 / rate : 0;
    while (offered < total) {
        int n = 0;
        size_t len = 0;
        while (n < BATCH && offered + (uint64_t)n < total) {
            uint64_t i = offered + (uint64_t)n;
            len = build(bufs[n], job, (uint32_t)(i / workers), (uint16_t)(i % workers), workers, chunk_len);
            n++;
        }
        if (ns_per_pkt > 0) { /* pace: the batch may start once its first packet is due */
            int64_t due = t0 + (int64_t)((double)offered * ns_per_pkt);
            while (now_ns() < due)
                ;
        }
#ifdef __linux__
        struct mmsghdr msgs[BATCH];
        struct iovec iov[BATCH];
        memset(msgs, 0, sizeof(msgs));
        for (int i = 0; i < n; i++) {
            iov[i].iov_base = bufs[i];
            iov[i].iov_len = len;
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int done = 0;
        while (done < n) {
            int r = sendmmsg(s, msgs + done, (unsigned)(n - done), 0);
            if (r < 0) {
                if (errno == ENOBUFS || errno == EAGAIN) {
                    errors++;
                    continue;
                }
                perror("sendmmsg");
                return 1;
            }
            done += r;
        }
        sent += (uint64_t)n;
#else
        for (int i = 0; i < n; i++) {
            if (send(s, bufs[i], len, 0) < 0)
                errors++;
            else
                sent++;
        }
#endif
        offered += (uint64_t)n;
    }
    int64_t el = now_ns() - t0;
    printf("{\"offered\":%llu,\"sent\":%llu,\"send_retries\":%llu,\"elapsed_us\":%lld,\"achieved_pps\":%.0f}\n",
           (unsigned long long)offered, (unsigned long long)sent, (unsigned long long)errors,
           (long long)(el / 1000), (double)sent * 1e9 / (double)(el ? el : 1));
    close(s);
    return 0;
}
