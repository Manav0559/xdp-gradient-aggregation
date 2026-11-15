/* Unit tests for common/slot_table.h, the overflow-detecting add and the
 * shared parser. Randomised operations are checked against a trivially
 * correct reference (linear scan). Built and run by `make unit`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../common/slot_table.h"
#include "../../protocol/grad_parse.h"
#include "../../protocol/netsum_stats.h"

static int failures;
#define CHECK(cond, ...)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);           \
            fprintf(stderr, __VA_ARGS__);                                  \
            fprintf(stderr, "\n");                                         \
        }                                                                  \
    } while (0)

static uint64_t rng = 0x243F6A8885A308D3ULL;
static uint32_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return (uint32_t)rng;
}

#define REF_MAX 4096
struct ref_entry {
    int live;
    struct slot_key k;
    uint32_t tag;
};
static struct ref_entry ref[REF_MAX];

static struct ref_entry *ref_find(struct slot_key k)
{
    for (int i = 0; i < REF_MAX; i++)
        if (ref[i].live && st_key_eq(ref[i].k, k))
            return &ref[i];
    return NULL;
}

static size_t ref_count(void)
{
    size_t n = 0;
    for (int i = 0; i < REF_MAX; i++)
        n += (size_t)ref[i].live;
    return n;
}

static void test_random_ops(unsigned log2, unsigned key_universe, int ops)
{
    struct slot_table t;
    CHECK(st_init(&t, log2) == 0, "init");
    memset(ref, 0, sizeof(ref));
    for (int n = 0; n < ops; n++) {
        struct slot_key k = {rnd() % key_universe, rnd() % 3, 0};
        uint32_t op = rnd() % 3;
        struct slot *s = st_find(&t, k);
        struct ref_entry *r = ref_find(k);
        CHECK((s != NULL) == (r != NULL), "presence mismatch at op %d", n);
        if (s && r)
            CHECK((uint32_t)s->sum[0] == r->tag, "payload mismatch at op %d", n);
        if (op < 2 && !s) {
            struct slot *ins = st_insert(&t, k);
            if (t.count + 1 >= t.cap && !ins)
                continue;
            CHECK(ins != NULL, "insert failed with count %zu cap %zu", t.count, t.cap);
            if (!ins)
                continue;
            uint32_t tag = rnd();
            ins->sum[0] = (int32_t)tag;
            for (int i = 0; i < REF_MAX; i++)
                if (!ref[i].live) {
                    ref[i] = (struct ref_entry){1, k, tag};
                    break;
                }
        } else if (op == 2 && s) {
            st_delete(&t, s);
            r->live = 0;
        }
        CHECK(t.count == ref_count(), "count %zu vs ref %zu", t.count, ref_count());
    }
    /* Every surviving reference key must still be findable. */
    for (int i = 0; i < REF_MAX; i++)
        if (ref[i].live)
            CHECK(st_find(&t, ref[i].k) != NULL, "lost key job=%u", ref[i].k.job_id);
    st_free(&t);
}

static void test_collision_cluster(void)
{
    /* Fill a 16-slot table with a cluster of keys sharing one home bucket,
     * delete from the middle, and check every remaining key is reachable. */
    struct slot_table t;
    st_init(&t, 4);
    struct slot_key keys[8];
    int n = 0;
    size_t home = (size_t)-1;
    for (uint32_t j = 0; n < 8 && j < 100000; j++) {
        struct slot_key k = {j, 0, 0};
        size_t h = st_hash(k) & 15;
        if (home == (size_t)-1)
            home = h;
        if (h == home)
            keys[n++] = k;
    }
    CHECK(n == 8, "found %d colliding keys", n);
    for (int i = 0; i < n; i++)
        CHECK(st_insert(&t, keys[i]) != NULL, "insert %d", i);
    for (int del = 1; del < n; del += 2) {
        st_delete(&t, st_find(&t, keys[del]));
        for (int i = 0; i < n; i++) {
            int deleted = (i % 2 == 1) && i <= del;
            CHECK((st_find(&t, keys[i]) != NULL) == !deleted, "key %d after deleting %d", i, del);
        }
    }
    st_free(&t);
}

static void test_tombstones(void)
{
    struct slot_table t;
    struct tomb_fifo f;
    st_init(&t, 6);
    tomb_init(&f, 4);
    for (uint32_t j = 0; j < 6; j++) {
        struct slot *s = st_insert(&t, (struct slot_key){j, 0, 0});
        s->state = SLOT_COMPLETED;
        s->completed_us = 100 + j;
        tomb_push(&f, &t, s->key, s->completed_us);
    }
    /* Ring of 4: pushing 6 retired the two oldest early. */
    CHECK(t.count == 4, "count after overflow push = %zu", t.count);
    CHECK(tomb_expire(&f, &t, 105, 2) == 2, "expire by ttl");
    CHECK(t.count == 2, "count after expire = %zu", t.count);
    /* A slot re-created after retirement must not be retired by a stale entry. */
    struct slot *s = st_find(&t, (struct slot_key){4, 0, 0});
    s->completed_us = 999;
    CHECK(tomb_expire(&f, &t, 1000, 1) == 1, "stale entry skipped");
    CHECK(st_find(&t, (struct slot_key){4, 0, 0}) != NULL, "re-completed slot kept");
    st_free(&t);
    free(f.ring);
}

static void test_add_overflow(void)
{
    int32_t a = 2147483647 - 5;
    CHECK(netsum_add_i32(&a, 5) == 0 && a == 2147483647, "INT32_MAX exact");
    a = 2147483647;
    CHECK(netsum_add_i32(&a, 1) == 1, "INT32_MAX + 1 overflows");
    a = -2147483647 - 1;
    CHECK(netsum_add_i32(&a, -1) == 1, "INT32_MIN - 1 overflows");
    a = -5;
    CHECK(netsum_add_i32(&a, 3) == 0 && a == -2, "small negative");
    a = 1310720000; /* 20000.0 in Q16.16 */
    int o = netsum_add_i32(&a, 1310720000);
    CHECK(o == 1, "2 x 20000.0 overflows Q16.16");
}

static void test_bitmap(void)
{
    uint8_t a[NETSUM_BITMAP_BYTES] = {0}, b[NETSUM_BITMAP_BYTES] = {0};
    bitmap_set(a, 0);
    bitmap_set(a, 255);
    bitmap_set(b, 254);
    CHECK(bitmap_popcount(a) == 2, "popcount");
    CHECK(bitmap_span(a) == 256, "span");
    CHECK(!bitmap_overlaps(a, b), "no overlap");
    bitmap_set(b, 255);
    CHECK(bitmap_overlaps(a, b), "overlap");
}

static void test_parse(void)
{
    uint8_t buf[NETSUM_MAX_PACKET_SIZE] = {0};
    struct grad_hdr *h = (struct grad_hdr *)buf;
    struct netsum_parsed p;
    h->num_workers = netsum_htons(3);
    h->worker_id = netsum_htons(1);
    h->chunk_len = netsum_htons(2);
    CHECK(netsum_parse(buf, buf + 20 + 8, &p) == NETSUM_OK, "v1 ok");
    CHECK(netsum_parse(buf, buf + 20 + 7, &p) == NETSUM_REJ_TRUNCATED, "v1 truncated");
    CHECK(netsum_parse(buf, buf + 19, &p) == NETSUM_REJ_SHORT_HDR, "short");
    h->flags = netsum_htons(NETSUM_FLAGS_V2);
    CHECK(netsum_parse(buf, buf + 20 + 8, &p) == NETSUM_REJ_TRUNCATED, "v2 needs trailer");
    CHECK(netsum_parse(buf, buf + 20 + 8 + 32, &p) == NETSUM_OK, "v2 ok");
    h->worker_id = netsum_htons(3);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_WORKER_ID, "worker_id >= fan-in");
    h->worker_id = netsum_htons(NETSUM_WORKER_AGGREGATE);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_OK && p.kind == NETSUM_KIND_AGGREGATE, "aggregate");
    h->flags = netsum_htons(NETSUM_FLAGS_V2 | NETSUM_F_RESEND);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_FLAG_COMBO, "resend aggregate");
    h->flags = netsum_htons(NETSUM_FLAGS_V2 | NETSUM_F_ACK | NETSUM_F_OVERFLOW);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_OK && p.kind == NETSUM_KIND_ACK, "overflow result");
    h->flags = netsum_htons(NETSUM_FLAGS_V2 | NETSUM_F_ACK | NETSUM_F_RESEND);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_FLAG_COMBO, "ACK|RESEND");
    h->flags = netsum_htons(NETSUM_FLAGS_V2 | 0x0040);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_RESERVED_FLAGS, "reserved");
    h->flags = netsum_htons(0x3000);
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_VERSION, "version 3");
    h->flags = 0;
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_WORKER_ID, "v1 cannot be aggregate");
    h->worker_id = 0;
    h->num_workers = 0;
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_NUM_WORKERS, "fan-in 0");
    h->num_workers = netsum_htons(3);
    h->chunk_len = 0;
    CHECK(netsum_parse(buf, buf + 60, &p) == NETSUM_REJ_CHUNK_LEN_ZERO, "empty chunk");
    h->chunk_len = netsum_htons(NETSUM_MAX_CHUNK_LEN + 1);
    CHECK(netsum_parse(buf, buf + sizeof(buf), &p) == NETSUM_REJ_CHUNK_LEN_MAX, "too long");
    CHECK(netsum_stat_names[NS_STAT__COUNT - 1] != NULL, "every stat has a name");
    CHECK(NS_FROM_VERDICT(NETSUM_REJ_FLAG_COMBO) == NS_REJ_FLAG_COMBO, "verdict->stat map");
}

int main(void)
{
    test_random_ops(6, 50, 100000);    /* dense: heavy clustering near capacity */
    test_random_ops(10, 3000, 100000); /* sparse */
    test_collision_cluster();
    test_tombstones();
    test_add_overflow();
    test_bitmap();
    test_parse();
    if (failures) {
        fprintf(stderr, "test_slot_table: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_slot_table: all checks passed\n");
    return 0;
}
