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
 *
 * Multi-tenant fairness (optional `max_slots_per_job` CLI argument): a
 * real per-job admission quota on concurrently-incomplete slots, so one
 * greedy job spamming many concurrent rounds cannot starve every other
 * job sharing this aggregator out of the slot table. This reproduces
 * ATP's actual headline contribution -- its paper's own title is
 * literally "...for Multi-tenant Learning" -- not just its bare
 * streaming-aggregation mechanism (which SwitchML, ATP's predecessor,
 * already had). See tests/test_correctness.py's fairness tests for a
 * worked example: a greedy job hitting its quota while a second,
 * well-behaved job's slots are admitted normally.
 *
 * Slot TTL / reaper (optional `slot_ttl_ms` CLI argument): the fairness
 * quota above stops an ABUSIVE job from hoarding slots, but does nothing
 * for the opposite, honest failure mode -- a well-behaved job whose worker
 * legitimately crashes or drops off the network mid-round, after its slot
 * was admitted but before every expected worker ever contributed. That
 * slot would otherwise sit `in_use` forever: one dead entry in
 * `g_slots`, and worse, one permanent tick against that job's
 * `concurrent_slots` fairness allowance, silently shrinking its real quota
 * over the life of the process. xdp_agg.c's own header comment admits
 * this same gap exists there too ("no TTL/eviction anywhere in this
 * program") -- this is the userspace-side fix; porting an equivalent into
 * the kernel program is separate follow-up work (no arbitrary timers in
 * the BPF hot path without `bpf_timer`, which needs real-kernel testing),
 * intentionally out of scope here.
 *
 * `slot_ttl_ms` (0 = disabled, preserving the exact prior behavior for
 * every existing test) bounds how long a slot may sit incomplete before a
 * periodic reaper sweep evicts it via the exact same `free_slot()` path a
 * normal completion uses, so `concurrent_slots` accounting stays correct
 * across an eviction.
 *
 * Design choice -- LAST-TOUCHED, not creation time: each slot's age is
 * measured from its most recent ACCEPTED contribution (`last_touched_micros`),
 * not from when the slot was first created. A slot that's still making
 * genuine progress (contributions trickling in from different workers
 * under ordinary network jitter) shouldn't be evicted out from under it
 * just because it happened to open a while ago; only a slot that has gone
 * fully silent for the whole TTL window -- the actual crashed-worker
 * signature -- should be reclaimed. Rejected contributions (duplicate,
 * chunk_len mismatch) do NOT refresh this timestamp, since those aren't
 * real progress either.
 *
 * Mechanism note: the main loop's `recvfrom()` is normally blocking with
 * no timeout, which would never wake up to run the reaper if a stuck
 * slot's whole socket goes silent (exactly the scenario being fixed). When
 * `slot_ttl_ms > 0`, `SO_RCVTIMEO` is set on the inbound socket so
 * `recvfrom()` periodically returns `EWOULDBLOCK`/`EAGAIN` on its own,
 * which the existing `n < NETSUM_HDR_SIZE` check already treats as a
 * harmless "nothing this iteration" (it doesn't count toward
 * `max_packets` or log anything) -- giving the loop a chance to run the
 * reaper sweep even under total silence. When `slot_ttl_ms == 0` no
 * timeout is ever installed, so recvfrom stays exactly as blocking as
 * before and every existing test's behavior is unchanged.
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
#define JOB_TABLE_CAPACITY 256     /* must be a power of 2 -- concurrent distinct job_ids tracked for fairness */

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
    /* first-contribution-to-last-contribution timing: THIS is where the
     * real accumulation latency lives in the useragg benchmark
     * configuration, not at the parameter server -- the parameter server
     * in "agg" mode receives exactly one already-summed packet per slot,
     * so its own first-seen-to-complete gap measures nothing meaningful
     * (an early version of the benchmark harness measured latency there
     * and got near-zero numbers for every worker count, which was the
     * tell that something was being measured in the wrong place). */
    long first_seen_micros;
    /* Slot-TTL reaper: timestamp of the most recent ACCEPTED contribution
     * (or slot creation, since creation always immediately processes a
     * contribution in the same recvfrom() iteration -- see the header
     * comment's "LAST-TOUCHED, not creation time" note for why this is
     * "last touched" rather than "first seen"). A slot whose age exceeds
     * slot_ttl_ms is evicted by reap_expired_slots(). */
    long last_touched_micros;
} slot_t;

static slot_t g_slots[SLOT_TABLE_CAPACITY];

/* Multi-tenant fairness -- this is ATP's actual headline contribution
 * (its title is literally "...for Multi-tenant Learning"), reproduced
 * here as a real per-job admission policy rather than left as a "planned"
 * checkbox: the shared slot table is a scarce resource multiple
 * concurrent training jobs can contend for, and without an admission
 * policy, one greedy job spamming many concurrent (round, chunk_id) slots
 * could starve every other job sharing this aggregator. `g_job_quota`, set
 * from the CLI (0 = unlimited, preserving the exact prior behavior for
 * every existing test), caps how many INCOMPLETE slots a single job_id
 * may occupy at once; a job at its quota has its next new-slot attempt
 * rejected outright, the same way a switch with a full slot table would
 * reject it -- it does not touch slots the job already has in flight. */
static long g_job_quota = 0;  /* 0 = unlimited */

typedef struct {
    int in_use;
    uint32_t job_id;
    uint32_t concurrent_slots;
} job_entry_t;

static job_entry_t g_jobs[JOB_TABLE_CAPACITY];

static uint32_t job_hash(uint32_t job_id) {
    uint32_t h = job_id;
    h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13; h *= 0xc2b2ae35u; h ^= h >> 16;
    return h;
}

static job_entry_t *find_or_create_job(uint32_t job_id) {
    uint32_t h = job_hash(job_id);
    for (size_t probe = 0; probe < JOB_TABLE_CAPACITY; probe++) {
        size_t idx = (h + probe) & (JOB_TABLE_CAPACITY - 1);
        job_entry_t *j = &g_jobs[idx];
        if (!j->in_use) { j->in_use = 1; j->job_id = job_id; j->concurrent_slots = 0; return j; }
        if (j->job_id == job_id) return j;
    }
    return NULL;  /* more than JOB_TABLE_CAPACITY distinct concurrent job_ids -- not expected at benchmark scale */
}

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
            /* About to CREATE a brand-new slot for this job -- this is the
             * one place the fairness admission policy applies. An
             * existing slot this job already holds is never affected by
             * its own quota; only a NEW one can be rejected. */
            job_entry_t *job = find_or_create_job(job_id);
            if (job && g_job_quota > 0 && job->concurrent_slots >= (uint32_t)g_job_quota) {
                return NULL;
            }
            memset(s, 0, sizeof(*s));
            s->in_use = 1;
            s->job_id = job_id;
            s->round = round;
            s->chunk_id = chunk_id;
            if (job) job->concurrent_slots++;
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
    job_entry_t *job = find_or_create_job(s->job_id);  /* must already exist -- this slot incremented it on creation */
    if (job && job->concurrent_slots > 0) job->concurrent_slots--;
    s->in_use = 0;
}

static long now_micros(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000000L + tv.tv_usec;
}

/* Slot-TTL reaper: a plain linear scan of the fixed-size slot table. This
 * is fine at benchmark scale (SLOT_TABLE_CAPACITY entries, swept only a
 * few times per second -- see the interval computation in main()), the
 * same "fixed-size table, no growth" constraint the eventual BPF map will
 * share. Any slot whose age (now - last_touched_micros) exceeds
 * slot_ttl_ms is evicted via free_slot() -- the exact same path a normal
 * completion uses -- so the owning job's concurrent_slots fairness count
 * decrements correctly instead of leaking. */
static void reap_expired_slots(long slot_ttl_ms) {
    long now = now_micros();
    long ttl_micros = slot_ttl_ms * 1000L;
    for (size_t i = 0; i < SLOT_TABLE_CAPACITY; i++) {
        slot_t *s = &g_slots[i];
        if (!s->in_use) continue;
        long age_micros = now - s->last_touched_micros;
        if (age_micros >= ttl_micros) {
            fprintf(stderr,
                "[reaped] job=%u round=%u chunk=%u -- incomplete after %ldms, evicting\n",
                s->job_id, s->round, s->chunk_id, age_micros / 1000);
            free_slot(s);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "usage: %s <listen_port> <downstream_ip> <downstream_port> [max_packets=0] [max_slots_per_job=0] [slot_ttl_ms=0]\n"
            "  max_slots_per_job: fairness admission quota -- caps how many\n"
            "  concurrently-incomplete slots a single job_id may occupy (0 =\n"
            "  unlimited, the original behavior). Reproduces ATP's actual\n"
            "  headline contribution: a shared aggregator serving multiple\n"
            "  tenants must not let one greedy job starve the others.\n"
            "  slot_ttl_ms: eviction timeout for a slot that never completes\n"
            "  (e.g. a crashed/dropped worker) -- 0 = disabled, the original\n"
            "  behavior. Without this, an incomplete slot occupies its\n"
            "  g_slots entry AND its job's fairness-quota allowance forever.\n",
            argv[0]);
        return 1;
    }
    int listen_port = atoi(argv[1]);
    const char *downstream_ip = argv[2];
    int downstream_port = atoi(argv[3]);
    long max_packets = argc > 4 ? atol(argv[4]) : 0;
    g_job_quota = argc > 5 ? atol(argv[5]) : 0;
    long slot_ttl_ms = argc > 6 ? atol(argv[6]) : 0;

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

    /* Only installed when the TTL reaper is actually enabled -- when
     * slot_ttl_ms == 0, in_sock stays exactly as blocking-with-no-timeout
     * as it always was, so every existing test's behavior is byte-for-byte
     * unchanged. When enabled, the timeout is a quarter of the TTL (floor
     * 1ms) so the reaper sweeps several times per TTL window -- fine
     * granularity without spinning -- and a recvfrom() that times out
     * returns EWOULDBLOCK/EAGAIN, which the main loop's existing
     * `n < NETSUM_HDR_SIZE` check already treats as a harmless no-op
     * iteration (see the header comment's "Mechanism note"). */
    long reap_interval_micros = 0;
    if (slot_ttl_ms > 0) {
        long interval_ms = slot_ttl_ms / 4;
        if (interval_ms < 1) interval_ms = 1;
        reap_interval_micros = interval_ms * 1000L;
        struct timeval rcv_timeout;
        rcv_timeout.tv_sec = interval_ms / 1000;
        rcv_timeout.tv_usec = (interval_ms % 1000) * 1000;
        setsockopt(in_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout));
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
    long last_reap_micros = now_micros();

    while (max_packets == 0 || packets_in < max_packets) {
        if (slot_ttl_ms > 0) {
            long now = now_micros();
            if (now - last_reap_micros >= reap_interval_micros) {
                reap_expired_slots(slot_ttl_ms);
                last_reap_micros = now;
            }
        }

        ssize_t n = recvfrom(in_sock, in_packet, sizeof(in_packet), 0, NULL, NULL);
        if (n < (ssize_t)NETSUM_HDR_SIZE) continue;  /* also catches the SO_RCVTIMEO EWOULDBLOCK/EAGAIN wakeup -- not a real error, not counted */
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
        /* CRITICAL FIX (found by an adversarial review that also reviewed
         * xdp_agg.c, comparing the two): this check was missing entirely.
         * `in_packet` is a fixed-size buffer reused across every
         * recvfrom() call and NEVER cleared between them. Without
         * verifying the actual received length `n` covers
         * NETSUM_HDR_SIZE + chunk_len*sizeof(int32_t), a truncated/
         * malformed datagram that merely CLAIMS a large chunk_len (while
         * actually being short) would read past what this packet really
         * delivered and silently sum stale leftover bytes from a PRIOR,
         * larger packet into the running total -- with no crash, no log,
         * nothing to signal the corruption. The XDP program (xdp_agg.c)
         * already had the equivalent check against `data_end`; this
         * brings the two back into the "byte-for-byte the same algorithm"
         * parity this file's own header comment claims. */
        if ((size_t)n < NETSUM_HDR_SIZE + (size_t)chunk_len * sizeof(int32_t)) continue;
        if (worker_id >= MAX_TRACKED_WORKERS) continue;
        /* Reject a degenerate/out-of-range num_workers before it can ever
         * create a slot that could never legitimately complete (0) or
         * that exceeds what MAX_TRACKED_WORKERS' seen_worker[] can even
         * track -- same fix as xdp_agg.c's slot-creation validation, same
         * reasoning: a bad value here would otherwise occupy one of the
         * 65536 slot-table entries forever, with no TTL/eviction. */
        if (num_workers == 0 || num_workers > MAX_TRACKED_WORKERS) continue;

        slot_t *slot = find_or_create_slot(job_id, round, chunk_id);
        if (!slot) {
            /* Two different reasons collapse to the same NULL return from
             * find_or_create_slot(): the whole 65536-entry table is full
             * (essentially never at benchmark scale), or -- the
             * realistic case when g_job_quota > 0 -- this specific job_id
             * is already at its fairness quota. Logged distinctly so a
             * fairness benchmark can grep for exactly the rejection it's
             * testing for. */
            fprintf(stderr,
                "[admission-reject] job=%u round=%u chunk=%u -- slot table full or job at fairness quota, dropping\n",
                job_id, round, chunk_id);
            continue;
        }

        if (slot->contributions_received == 0) {
            slot->chunk_len = chunk_len;
            slot->num_workers_expected = num_workers;
            slot->first_seen_micros = now_micros();
        } else if (slot->chunk_len != chunk_len) {
            /* Same fix as xdp_agg.c's chunk_len-consistency check: a
             * contribution that disagrees with the slot's established
             * chunk_len would otherwise get summed using its OWN chunk_len
             * as the loop bound below, silently producing a sum
             * inconsistent with what any single worker actually sent.
             * Reject the one inconsistent contribution, not the whole
             * slot. */
            fprintf(stderr,
                "[chunk_len mismatch] job=%u round=%u chunk=%u worker=%u sent chunk_len=%u, slot expects %u -- dropping\n",
                job_id, round, chunk_id, worker_id, chunk_len, slot->chunk_len);
            continue;
        }

        if (slot->seen_worker[worker_id]) {
            fprintf(stderr,
                "[dup] job=%u round=%u chunk=%u worker=%u already contributed -- dropping duplicate\n",
                job_id, round, chunk_id, worker_id);
            continue;
        }
        slot->seen_worker[worker_id] = 1;
        /* "Last touched," not "first seen": this line is why a slot still
         * receiving genuine contributions never gets reaped, even if it's
         * been open a long time -- only one that's gone fully silent for
         * the whole TTL window does. See the header comment's "LAST-
         * TOUCHED, not creation time" note. */
        slot->last_touched_micros = now_micros();

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

        /* Last contribution just arrived: this is the real "aggregation
         * completed" event the benchmark harness needs a timestamp for --
         * logged in the same "[complete] ... latency_us=" shape
         * paramserver.c uses (same regex parses both), so
         * scripts/benchmark.py can pull the true accumulation latency from
         * here instead of the parameter server, which in "agg" mode only
         * ever sees a single already-summed packet and so measures nothing
         * meaningful of its own. */
        long completed_micros = now_micros();
        fprintf(stderr,
            "[complete] job=%u round=%u chunk=%u contributions=%u sum[0]=%.6f latency_us=%ld\n",
            job_id, round, chunk_id, slot->contributions_received,
            netsum_to_double(slot->sum[0]), completed_micros - slot->first_seen_micros);

        /* Emit exactly one aggregated packet downstream -- mirrors XDP_TX
         * in the eventual kernel program, and is the only place this
         * process's slot state crosses back onto the wire. */
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
