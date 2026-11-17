/* Open-addressing slot table shared by agg and paramserver.
 *
 * Linear probing with backward-shift deletion (Knuth vol. 3, Algorithm R):
 * no tombstone markers, so a freed slot never breaks another key's probe
 * chain (bug C6). Deletion moves entries, so slot pointers are invalid after
 * st_delete(). One slot is always left empty so probes terminate.
 * See docs/DESIGN_NOTES.md §Slot storage. */
#ifndef NETSUM_SLOT_TABLE_H
#define NETSUM_SLOT_TABLE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../protocol/grad_proto.h"

enum slot_state {
    SLOT_EMPTY = 0,
    SLOT_ACCUMULATING,
    SLOT_COMPLETED,   /* tombstone: sum kept so a resend can re-emit it */
    SLOT_FLUSHED,
};

struct slot_key {
    uint32_t job_id, round, chunk_id;
};

struct slot {
    struct slot_key key;
    uint8_t state;
    uint8_t overflowed;
    uint8_t frac_bits;          /* exponent every contribution must share */
    uint8_t version;            /* wire version of the first contribution */
    uint16_t fanin;
    uint16_t chunk_len;
    uint16_t contributions;     /* packets merged into this slot */
    uint16_t contributors;      /* popcount(bitmap) */
    int64_t first_us;
    int64_t touched_us;
    int64_t completed_us;
    uint8_t bitmap[NETSUM_BITMAP_BYTES];
    int32_t sum[NETSUM_MAX_CHUNK_LEN];
};

struct slot_table {
    struct slot *slots;
    size_t cap;   /* power of two */
    size_t count; /* non-empty slots */
};

static inline uint64_t st_hash(struct slot_key k)
{
    /* FNV-1a over the three fields in host byte order. */
    uint64_t h = 1469598103934665603ULL;
    const uint8_t *b = (const uint8_t *)&k;
    for (size_t i = 0; i < sizeof(k); i++) {
        h ^= b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline int st_key_eq(struct slot_key a, struct slot_key b)
{
    return a.job_id == b.job_id && a.round == b.round && a.chunk_id == b.chunk_id;
}

static inline int st_init(struct slot_table *t, unsigned log2)
{
    _Static_assert(sizeof(struct slot_key) == 12, "slot_key must be unpadded");
    t->cap = (size_t)1 << log2;
    t->count = 0;
    t->slots = calloc(t->cap, sizeof(struct slot));
    return t->slots ? 0 : -1;
}

static inline void st_free(struct slot_table *t)
{
    free(t->slots);
    t->slots = NULL;
}

static inline struct slot *st_find(struct slot_table *t, struct slot_key k)
{
    size_t mask = t->cap - 1;
    for (size_t i = st_hash(k) & mask;; i = (i + 1) & mask) {
        struct slot *s = &t->slots[i];
        if (s->state == SLOT_EMPTY)
            return NULL;
        if (st_key_eq(s->key, k))
            return s;
    }
}

/* Inserts a zeroed ACCUMULATING slot for k (caller ensures k is absent).
 * Returns NULL when the table is full. */
static inline struct slot *st_insert(struct slot_table *t, struct slot_key k)
{
    if (t->count + 1 >= t->cap)
        return NULL;
    size_t mask = t->cap - 1;
    size_t i = st_hash(k) & mask;
    while (t->slots[i].state != SLOT_EMPTY)
        i = (i + 1) & mask;
    struct slot *s = &t->slots[i];
    memset(s, 0, sizeof(*s));
    s->key = k;
    s->state = SLOT_ACCUMULATING;
    t->count++;
    return s;
}

static inline void st_delete(struct slot_table *t, struct slot *victim)
{
    size_t mask = t->cap - 1;
    size_t i = (size_t)(victim - t->slots);
    size_t j = i;
    for (;;) {
        j = (j + 1) & mask;
        if (t->slots[j].state == SLOT_EMPTY)
            break;
        size_t home = st_hash(t->slots[j].key) & mask;
        /* Move j back into the hole at i unless its home lies cyclically in (i, j]. */
        int home_in_range = (i <= j) ? (home > i && home <= j) : (home > i || home <= j);
        if (!home_in_range) {
            t->slots[i] = t->slots[j];
            i = j;
        }
    }
    memset(&t->slots[i], 0, sizeof(t->slots[i]));
    t->count--;
}

static inline int bitmap_test(const uint8_t *bm, unsigned w)
{
    return (bm[w >> 3] >> (w & 7)) & 1;
}

static inline void bitmap_set(uint8_t *bm, unsigned w)
{
    bm[w >> 3] = (uint8_t)(bm[w >> 3] | (1u << (w & 7)));
}

static inline int bitmap_overlaps(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < NETSUM_BITMAP_BYTES; i++)
        if (a[i] & b[i])
            return 1;
    return 0;
}

/* 1 iff every bit of a is also set in b. */
static inline int bitmap_subset(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < NETSUM_BITMAP_BYTES; i++)
        if (a[i] & ~b[i])
            return 0;
    return 1;
}

static inline unsigned bitmap_popcount(const uint8_t *bm)
{
    unsigned n = 0;
    for (int i = 0; i < NETSUM_BITMAP_BYTES; i++)
        n += (unsigned)__builtin_popcount(bm[i]);
    return n;
}

/* Highest set bit + 1, i.e. the smallest fan-in this bitmap is valid for. */
static inline unsigned bitmap_span(const uint8_t *bm)
{
    for (int i = NETSUM_BITMAP_BYTES - 1; i >= 0; i--)
        if (bm[i])
            return (unsigned)(i * 8 + 32 - __builtin_clz((unsigned)bm[i]));
    return 0;
}

/* FIFO of completed (or flushed) keys, used to retire tombstones after a TTL without
 * scanning the table. An entry is acted on only if the slot still exists,
 * is COMPLETED or FLUSHED, and reached that state at the recorded time. */
struct tomb_entry {
    struct slot_key key;
    int64_t completed_us;
};

struct tomb_fifo {
    struct tomb_entry *ring;
    size_t cap, head, len;
};

static inline int tomb_init(struct tomb_fifo *f, size_t cap)
{
    f->cap = cap;
    f->head = f->len = 0;
    f->ring = calloc(cap, sizeof(*f->ring));
    return f->ring ? 0 : -1;
}

/* Retires the oldest tombstone if it is still live; returns 1 if a slot was
 * deleted. */
static inline int tomb_pop_retire(struct tomb_fifo *f, struct slot_table *t)
{
    struct tomb_entry e = f->ring[f->head];
    f->head = (f->head + 1) % f->cap;
    f->len--;
    struct slot *s = st_find(t, e.key);
    if (s && (s->state == SLOT_COMPLETED || s->state == SLOT_FLUSHED) &&
        s->completed_us == e.completed_us) {
        st_delete(t, s);
        return 1;
    }
    return 0;
}

/* Records a completion; if the ring is full, retires the oldest first.
 * Returns the number of slots retired early. */
static inline int tomb_push(struct tomb_fifo *f, struct slot_table *t, struct slot_key k,
                            int64_t completed_us)
{
    int retired = 0;
    if (f->len == f->cap)
        retired = tomb_pop_retire(f, t);
    f->ring[(f->head + f->len) % f->cap] = (struct tomb_entry){k, completed_us};
    f->len++;
    return retired;
}

/* Retires every tombstone older than ttl_us; returns how many were deleted. */
static inline int tomb_expire(struct tomb_fifo *f, struct slot_table *t, int64_t now_us,
                              int64_t ttl_us)
{
    int retired = 0;
    while (f->len && now_us - f->ring[f->head].completed_us >= ttl_us)
        retired += tomb_pop_retire(f, t);
    return retired;
}

#endif /* NETSUM_SLOT_TABLE_H */
