/* Prints sample v2 packets built from protocol/grad_proto.h, one hex line
 * each, so tests/test_python_client.py can check that the Python client's
 * packer produces exactly the same bytes. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../../protocol/grad_proto.h"

static void dump(uint32_t job, uint32_t round, uint32_t chunk, uint16_t worker, uint16_t workers,
                 uint16_t flags, const int32_t *vals, uint16_t n)
{
    uint8_t buf[NETSUM_MAX_PACKET_SIZE];
    struct grad_hdr *h = (struct grad_hdr *)buf;
    h->job_id = htonl(job);
    h->round = htonl(round);
    h->chunk_id = htonl(chunk);
    h->worker_id = htons(worker);
    h->num_workers = htons(workers);
    h->chunk_len = htons(n);
    h->flags = htons((uint16_t)(NETSUM_FLAGS_V2 | flags));
    for (uint16_t i = 0; i < n; i++) {
        uint32_t be = htonl((uint32_t)vals[i]);
        memcpy(buf + NETSUM_HDR_SIZE + 4 * i, &be, 4);
    }
    uint8_t *bm = buf + NETSUM_HDR_SIZE + 4 * n;
    memset(bm, 0, NETSUM_BITMAP_BYTES);
    bm[worker / 8] = (uint8_t)(1u << (worker % 8));
    for (size_t i = 0; i < NETSUM_HDR_SIZE + 4u * n + NETSUM_BITMAP_BYTES; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(void)
{
    const int32_t a[3] = {65536, -32768, 2147483647};
    const int32_t b[1] = {-2147483647 - 1};
    dump(4242, 0, 0, 0, 4, 0, a, 3);
    dump(7, 123456, 2, 3, 4, NETSUM_F_RESEND, b, 1);
    dump(0xFFFFFFFFu, 0xFFFFFFFFu, 65, 255, 256, 0, a, 2);
    return 0;
}
