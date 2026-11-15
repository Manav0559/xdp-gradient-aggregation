/* Counter IDs shared by xdp_agg (PERCPU_ARRAY index), agg, paramserver and
 * netsum-ctl, so every path reports the same names. Names: netsum_stat_names. */
#ifndef NETSUM_STATS_H
#define NETSUM_STATS_H

enum netsum_stat {
    NS_RX_TOTAL = 0,          /* packets that reached the grad_hdr parse */
    NS_PASS_NOT_OURS,         /* non-IPv4 / non-UDP / other port: XDP_PASS */
    NS_PASS_FRAGMENT,         /* IPv4 fragment: XDP_PASS */
    NS_PASS_IP_OPTIONS,       /* IHL != 5: XDP_PASS */
    NS_PASS_CONTROL,          /* REGISTER (and ACKs a path does not consume) passed on */
    NS_REJ_SHORT_HDR,         /* the NS_REJ_* block mirrors enum netsum_verdict */
    NS_REJ_CHUNK_LEN_MAX,
    NS_REJ_CHUNK_LEN_ZERO,
    NS_REJ_TRUNCATED,
    NS_REJ_NUM_WORKERS,
    NS_REJ_WORKER_ID,
    NS_REJ_VERSION,
    NS_REJ_RESERVED_FLAGS,
    NS_REJ_FLAG_COMBO,
    NS_REJ_UDP_LEN,           /* udp->len / tot_len inconsistent with the frame */
    NS_REJ_TTL,               /* ttl <= 1 on a packet we would forward */
    NS_REJ_KIND,              /* valid packet of a kind this path does not accept */
    NS_ACCEPTED,              /* contribution added to a slot */
    NS_DUPLICATE,
    NS_RESEND_DUPLICATE,
    NS_LATE_DUPLICATE,
    NS_NUM_WORKERS_MISMATCH,
    NS_CHUNK_LEN_MISMATCH,
    NS_OVERLAP_REJECTED,      /* aggregate/partial partially overlapping contributors held */
    NS_OVERLAP_SUBSET,        /* aggregate/partial whose contributors are all held: dropped */
    NS_OVERLAP_SUPERSET,      /* aggregate/partial covering everything held: replaces it */
    NS_AGGREGATE_CONFLICT,    /* aggregate for a key already completed */
    NS_SLOT_CREATED,
    NS_SLOT_COMPLETED,
    NS_SLOT_RETIRED_ACK,
    NS_SLOT_RETIRED_TTL,
    NS_SLOT_REAPED,           /* ACCUMULATING slot dropped by TTL */
    NS_SLOT_FLUSHED_PARTIAL,
    NS_FALLBACK_COLLISION,
    NS_FALLBACK_QUOTA,
    NS_DROP_QUOTA,
    NS_DROP_MAP_FULL,
    NS_DROP_JOB_TABLE_FULL,
    NS_DROP_NO_CONFIG,
    NS_OVERFLOW,
    NS_TX_AGGREGATE,
    NS_TX_PARTIAL,
    NS_TX_FALLBACK,
    NS_TX_RESULT_RESEND,
    NS_ACK_SEEN,
    NS_ACK_UNEXPECTED,
    NS_STAT__COUNT
};

#ifndef __bpf__
static const char *const netsum_stat_names[NS_STAT__COUNT] = {
    "rx_total", "pass_not_ours", "pass_fragment", "pass_ip_options", "pass_control",
    "rej_short_hdr", "rej_chunk_len_max", "rej_chunk_len_zero", "rej_truncated",
    "rej_num_workers", "rej_worker_id", "rej_version", "rej_reserved_flags",
    "rej_flag_combo", "rej_udp_len", "rej_ttl", "rej_kind", "accepted", "duplicate",
    "resend_duplicate", "late_duplicate", "num_workers_mismatch", "chunk_len_mismatch",
    "overlap_rejected", "overlap_subset", "overlap_superset", "aggregate_conflict", "slot_created", "slot_completed",
    "slot_retired_ack", "slot_retired_ttl", "slot_reaped", "slot_flushed_partial",
    "fallback_collision", "fallback_quota", "drop_quota", "drop_map_full",
    "drop_job_table_full", "drop_no_config", "overflow", "tx_aggregate", "tx_partial",
    "tx_fallback", "tx_result_resend", "ack_seen", "ack_unexpected",
};
#endif

/* enum netsum_verdict v maps to stat NS_REJ_SHORT_HDR + v - 1. */
#define NS_FROM_VERDICT(v) (NS_REJ_SHORT_HDR + (v) - 1)

#endif /* NETSUM_STATS_H */
