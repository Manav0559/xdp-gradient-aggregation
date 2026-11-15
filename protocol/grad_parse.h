/* NetSum packet validation shared by agg, paramserver, the fuzzer and the
 * XDP program: one definition of "valid packet". Written in (data, data_end)
 * pointer-pair style with a bounds check directly before each access, no
 * loops and no libc, so the same source passes the BPF verifier.
 * Semantics: docs/DESIGN_NOTES.md §Admission and validation. */
#ifndef NETSUM_GRAD_PARSE_H
#define NETSUM_GRAD_PARSE_H

#include "grad_proto.h"

enum netsum_verdict {
    NETSUM_OK = 0,
    NETSUM_REJ_SHORT_HDR,      /* fewer bytes than grad_hdr */
    NETSUM_REJ_CHUNK_LEN_MAX,  /* chunk_len > NETSUM_MAX_CHUNK_LEN */
    NETSUM_REJ_CHUNK_LEN_ZERO, /* chunk_len == 0 on a packet that carries values */
    NETSUM_REJ_TRUNCATED,      /* payload shorter than chunk_len values (+ v2 trailer) */
    NETSUM_REJ_NUM_WORKERS,    /* fan-in 0 or > NETSUM_MAX_FANIN */
    NETSUM_REJ_WORKER_ID,      /* raw contribution with worker_id >= num_workers */
    NETSUM_REJ_VERSION,        /* unknown version nibble */
    NETSUM_REJ_RESERVED_FLAGS, /* reserved bits set (or any flag on a v1 packet) */
    NETSUM_REJ_FLAG_COMBO,     /* flags that cannot appear together or on this kind */
    NETSUM_VERDICT__COUNT
};

enum netsum_kind {
    NETSUM_KIND_RAW = 0,   /* worker contribution (incl. RESEND / FALLBACK) */
    NETSUM_KIND_AGGREGATE, /* complete aggregate (worker_id 0xFFFF, no PARTIAL) */
    NETSUM_KIND_PARTIAL,   /* flushed partial aggregate */
    NETSUM_KIND_ACK,       /* PS result */
    NETSUM_KIND_REGISTER,  /* worker registration */
};

struct netsum_parsed {
    uint32_t job_id, round, chunk_id;
    uint16_t worker_id, num_workers, chunk_len, flags;
    uint8_t version;
    uint8_t kind;          /* enum netsum_kind */
    uint16_t payload_len;  /* bytes after the header: values (+ trailer on v2) */
};

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define netsum_ntohs(x) ((uint16_t)(x))
#define netsum_ntohl(x) ((uint32_t)(x))
#else
#define netsum_ntohs(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
#define netsum_ntohl(x) ((uint32_t)__builtin_bswap32((uint32_t)(x)))
#endif
#define netsum_htons netsum_ntohs
#define netsum_htonl netsum_ntohl

NETSUM_INLINE enum netsum_verdict
netsum_parse(const void *data, const void *data_end, struct netsum_parsed *out)
{
    const struct grad_hdr *h = (const struct grad_hdr *)data;
    if ((const uint8_t *)h + sizeof(*h) > (const uint8_t *)data_end)
        return NETSUM_REJ_SHORT_HDR;

    out->job_id = netsum_ntohl(h->job_id);
    out->round = netsum_ntohl(h->round);
    out->chunk_id = netsum_ntohl(h->chunk_id);
    out->worker_id = netsum_ntohs(h->worker_id);
    out->num_workers = netsum_ntohs(h->num_workers);
    out->chunk_len = netsum_ntohs(h->chunk_len);
    out->flags = netsum_ntohs(h->flags);
    out->version = (uint8_t)(out->flags >> NETSUM_VERSION_SHIFT);
    out->kind = NETSUM_KIND_RAW;
    out->payload_len = 0;

    uint16_t f = out->flags & NETSUM_F_KNOWN;
    int v2 = out->version == NETSUM_VERSION_V2;
    if (out->version != 0 && !v2)
        return NETSUM_REJ_VERSION;
    if ((!v2 && out->flags != 0) || (out->flags & NETSUM_F_RESERVED))
        return NETSUM_REJ_RESERVED_FLAGS;

    if (out->num_workers == 0 || out->num_workers > NETSUM_MAX_FANIN)
        return NETSUM_REJ_NUM_WORKERS;

    int agg_id = out->worker_id == NETSUM_WORKER_AGGREGATE;
    if (agg_id && !v2)
        return NETSUM_REJ_WORKER_ID;
    if (f & NETSUM_F_REGISTER) {
        if (f != NETSUM_F_REGISTER || agg_id)
            return NETSUM_REJ_FLAG_COMBO;
        out->kind = NETSUM_KIND_REGISTER;
    } else if (f & NETSUM_F_ACK) {
        if (f != NETSUM_F_ACK || !agg_id)
            return NETSUM_REJ_FLAG_COMBO;
        out->kind = NETSUM_KIND_ACK;
    } else if (agg_id) {
        if (f & (NETSUM_F_RESEND | NETSUM_F_FALLBACK))
            return NETSUM_REJ_FLAG_COMBO;
        out->kind = (f & NETSUM_F_PARTIAL) ? NETSUM_KIND_PARTIAL : NETSUM_KIND_AGGREGATE;
    } else {
        if (f & (NETSUM_F_PARTIAL | NETSUM_F_OVERFLOW))
            return NETSUM_REJ_FLAG_COMBO;
        if (out->worker_id >= out->num_workers)
            return NETSUM_REJ_WORKER_ID;
    }

    if (out->chunk_len > NETSUM_MAX_CHUNK_LEN)
        return NETSUM_REJ_CHUNK_LEN_MAX;
    if (out->chunk_len == 0 && out->kind != NETSUM_KIND_REGISTER)
        return NETSUM_REJ_CHUNK_LEN_ZERO;

    uint32_t need = (uint32_t)out->chunk_len * 4u + (v2 ? NETSUM_BITMAP_BYTES : 0u);
    if ((const uint8_t *)(h + 1) + need > (const uint8_t *)data_end)
        return NETSUM_REJ_TRUNCATED;
    out->payload_len = (uint16_t)need;
    return NETSUM_OK;
}

/* Pointer to the contributor bitmap of a validated v2 packet. */
NETSUM_INLINE const uint8_t *netsum_trailer(const void *data, const struct netsum_parsed *p)
{
    return (const uint8_t *)data + NETSUM_HDR_SIZE + (uint32_t)p->chunk_len * 4u;
}

#endif /* NETSUM_GRAD_PARSE_H */
