/* netsum-ctl: control plane for the NetSum XDP aggregator (libbpf).
 * Loads and pins the program and maps, attaches to interfaces (reporting the
 * attach mode the kernel actually chose), writes config, reads counters and
 * slots, and runs the TTL sweeper (which drives the in-kernel netsum_sweep
 * program with BPF_PROG_TEST_RUN, so every slot transition happens under the
 * slot lock). Map layouts come from protocol/netsum_maps.h.
 * Exit codes: 0 ok, 1 usage, 2 environment, 3 BPF load/verifier, 4 runtime.
 * See docs/DESIGN_NOTES.md §Control plane. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../protocol/grad_parse.h"
#include "../protocol/netsum_maps.h"
#include "../protocol/netsum_stats.h"

#define EXIT_USAGE 1
#define EXIT_ENV 2
#define EXIT_LOAD 3
#define EXIT_RUNTIME 4
#define MAX_IFACES 4

struct ctl {
    const char *pin;
    const char *obj_path;
    const char *ifnames[MAX_IFACES];
    int n_ifnames;
    const char *mode;
    int json;
    int reset;
    int once;
    int unpin;
    long ttl_ms, interval_ms, duration_ms;
    const char *state_filter;
    long job_filter;
    const char *flush_to;
    /* config */
    const char *ps_mac, *ps_ip, *agg_mac, *agg_ip, *egress_ifname, *quota_policy;
    long ps_port, max_slots, slot_ttl_ms;
    int delete_config;
};

static int fail(int code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "netsum-ctl: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return code;
}

static char g_verifier_log[1 << 16];
static size_t g_verifier_len;

static int capture_libbpf(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    int n = vsnprintf(g_verifier_log + g_verifier_len, sizeof(g_verifier_log) - g_verifier_len, fmt, ap);
    if (n > 0 && g_verifier_len + (size_t)n < sizeof(g_verifier_log))
        g_verifier_len += (size_t)n;
    return 0;
}

static int pinned_fd(const struct ctl *c, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", c->pin, name);
    return bpf_obj_get(path);
}

static int need_fd(const struct ctl *c, const char *name, int *fd)
{
    *fd = pinned_fd(c, name);
    if (*fd < 0)
        return fail(EXIT_ENV, "cannot open %s/%s: %s (run 'netsum-ctl attach' first)", c->pin, name,
                    strerror(errno));
    return 0;
}

static const char *mode_name(__u8 mode)
{
    switch (mode) {
    case XDP_ATTACHED_DRV: return "native";
    case XDP_ATTACHED_SKB: return "generic";
    case XDP_ATTACHED_HW: return "offload";
    case XDP_ATTACHED_MULTI: return "multi";
    default: return "none";
    }
}

/* ---- attach / detach -------------------------------------------------------- */

static int attach_one(const struct ctl *c, int prog_fd, const char *ifname)
{
    unsigned ifindex = if_nametoindex(ifname);
    if (!ifindex)
        return fail(EXIT_ENV, "no interface %s", ifname);
    __u32 flags = 0;
    if (!strcmp(c->mode, "native"))
        flags = XDP_FLAGS_DRV_MODE;
    else if (!strcmp(c->mode, "generic"))
        flags = XDP_FLAGS_SKB_MODE;
    else if (strcmp(c->mode, "auto"))
        return fail(EXIT_USAGE, "--mode must be native, generic or auto");
    if (bpf_xdp_attach((int)ifindex, prog_fd, flags, NULL))
        return fail(EXIT_ENV, "attach to %s (%s mode) failed: %s", ifname, c->mode, strerror(errno));
    LIBBPF_OPTS(bpf_xdp_query_opts, q);
    if (bpf_xdp_query((int)ifindex, 0, &q))
        return fail(EXIT_RUNTIME, "query %s: %s", ifname, strerror(errno));
    if (c->json)
        printf("{\"ifname\":\"%s\",\"ifindex\":%u,\"requested\":\"%s\",\"attached\":\"%s\"}\n", ifname, ifindex,
               c->mode, mode_name(q.attach_mode));
    else
        printf("attached to %s (ifindex %u): requested %s, kernel reports %s\n", ifname, ifindex, c->mode,
               mode_name(q.attach_mode));
    return 0;
}

static int cmd_attach(struct ctl *c)
{
    if (!c->n_ifnames)
        return fail(EXIT_USAGE, "attach needs --ifname");
    int prog_fd = pinned_fd(c, "netsum_xdp_aggregate");
    if (prog_fd < 0) { /* first attach: load and pin */
        libbpf_set_print(capture_libbpf);
        struct bpf_object *obj = bpf_object__open_file(c->obj_path, NULL);
        if (!obj)
            return fail(EXIT_LOAD, "open %s: %s", c->obj_path, strerror(errno));
        if (bpf_object__load(obj)) {
            fprintf(stderr, "%.*s", (int)g_verifier_len, g_verifier_log);
            return fail(EXIT_LOAD, "load %s failed (verifier log above)", c->obj_path);
        }
        mkdir(c->pin, 0700);
        if (bpf_object__pin_maps(obj, c->pin))
            return fail(EXIT_ENV, "pin maps under %s: %s", c->pin, strerror(errno));
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", c->pin, bpf_program__name(prog));
            if (bpf_program__pin(prog, path))
                return fail(EXIT_ENV, "pin %s: %s", path, strerror(errno));
        }
        prog_fd = pinned_fd(c, "netsum_xdp_aggregate");
        if (prog_fd < 0)
            return fail(EXIT_RUNTIME, "program not pinned");
    }
    for (int i = 0; i < c->n_ifnames; i++) {
        int rc = attach_one(c, prog_fd, c->ifnames[i]);
        if (rc)
            return rc;
    }
    return 0;
}

static int cmd_detach(struct ctl *c)
{
    for (int i = 0; i < c->n_ifnames; i++) {
        unsigned ifindex = if_nametoindex(c->ifnames[i]);
        if (!ifindex)
            return fail(EXIT_ENV, "no interface %s", c->ifnames[i]);
        if (bpf_xdp_detach((int)ifindex, 0, NULL))
            return fail(EXIT_ENV, "detach %s: %s", c->ifnames[i], strerror(errno));
    }
    if (c->unpin) {
        const char *names[] = {"netsum_xdp_aggregate", "netsum_sweep", "slot_map", "config_map",
                               "job_quota_map", "stats", "slot_template"};
        char path[512];
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            snprintf(path, sizeof(path), "%s/%s", c->pin, names[i]);
            unlink(path);
        }
        rmdir(c->pin);
    }
    return 0;
}

/* ---- config ------------------------------------------------------------------ */

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)b[i];
    return 0;
}

static int cmd_config(struct ctl *c)
{
    int fd, rc = need_fd(c, "config_map", &fd);
    if (rc)
        return rc;
    uint32_t key = 0;
    if (c->delete_config) {
        bpf_map_delete_elem(fd, &key);
        return 0;
    }
    struct netsum_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    struct in_addr ip;
    if (!c->ps_mac || !c->ps_ip || !c->ps_port || parse_mac(c->ps_mac, cfg.ps_mac) ||
        inet_pton(AF_INET, c->ps_ip, &ip) != 1)
        return fail(EXIT_USAGE, "config needs --ps-mac, --ps-ip and --ps-port");
    cfg.ps_ip = ip.s_addr;
    cfg.ps_port = htons((uint16_t)c->ps_port);
    if (c->agg_mac && parse_mac(c->agg_mac, cfg.agg_mac))
        return fail(EXIT_USAGE, "bad --agg-mac");
    if (c->agg_ip) {
        if (inet_pton(AF_INET, c->agg_ip, &ip) != 1)
            return fail(EXIT_USAGE, "bad --agg-ip");
        cfg.agg_ip = ip.s_addr;
    }
    if (c->egress_ifname && !(cfg.egress_ifindex = if_nametoindex(c->egress_ifname)))
        return fail(EXIT_ENV, "no interface %s", c->egress_ifname);
    cfg.max_slots_per_job = (uint32_t)c->max_slots;
    cfg.slot_ttl_ms = (uint32_t)c->slot_ttl_ms;
    const char *qp = c->quota_policy ? c->quota_policy : (c->max_slots ? "drop" : "none");
    if (!strcmp(qp, "none"))
        cfg.quota_policy = NETSUM_QUOTA_NONE;
    else if (!strcmp(qp, "drop"))
        cfg.quota_policy = NETSUM_QUOTA_DROP;
    else if (!strcmp(qp, "fallback"))
        cfg.quota_policy = NETSUM_QUOTA_FALLBACK;
    else
        return fail(EXIT_USAGE, "--quota-policy must be none, drop or fallback");
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY))
        return fail(EXIT_RUNTIME, "write config_map: %s", strerror(errno));
    if (c->json)
        printf("{\"ps\":\"%s:%ld\",\"egress_ifindex\":%u,\"max_slots_per_job\":%u,\"quota_policy\":\"%s\",\"slot_ttl_ms\":%u}\n",
               c->ps_ip, c->ps_port, cfg.egress_ifindex, cfg.max_slots_per_job, qp, cfg.slot_ttl_ms);
    return 0;
}

/* ---- stats / slots / jobs ------------------------------------------------------ */

static int cmd_stats(struct ctl *c)
{
    int fd, rc = need_fd(c, "stats", &fd);
    if (rc)
        return rc;
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return fail(EXIT_RUNTIME, "cannot count CPUs");
    uint64_t *vals = calloc((size_t)ncpus, sizeof(uint64_t));
    if (c->json)
        printf("{");
    for (uint32_t k = 0; k < NS_STAT__COUNT; k++) {
        uint64_t sum = 0;
        if (c->reset) {
            memset(vals, 0, (size_t)ncpus * sizeof(uint64_t));
            bpf_map_update_elem(fd, &k, vals, BPF_ANY);
        } else if (!bpf_map_lookup_elem(fd, &k, vals)) {
            for (int i = 0; i < ncpus; i++)
                sum += vals[i];
        }
        if (c->json)
            printf("%s\"%s\":%llu", k ? "," : "", netsum_stat_names[k], (unsigned long long)sum);
        else if (sum)
            printf("%-24s %llu\n", netsum_stat_names[k], (unsigned long long)sum);
    }
    int prog_fd = pinned_fd(c, "netsum_xdp_aggregate");
    if (prog_fd >= 0) {
        struct bpf_prog_info info;
        __u32 len = sizeof(info);
        memset(&info, 0, sizeof(info));
        if (!bpf_obj_get_info_by_fd(prog_fd, &info, &len)) {
            if (c->json)
                printf(",\"prog_run_cnt\":%llu,\"prog_run_time_ns\":%llu", (unsigned long long)info.run_cnt,
                       (unsigned long long)info.run_time_ns);
            else if (info.run_cnt)
                printf("%-24s %.1f ns/run over %llu runs (kernel.bpf_stats_enabled)\n", "program",
                       (double)info.run_time_ns / (double)info.run_cnt, (unsigned long long)info.run_cnt);
        }
    }
    if (c->json)
        printf("}\n");
    free(vals);
    return 0;
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static const char *state_name(uint8_t s)
{
    static const char *names[] = {"empty", "accumulating", "completed", "flushed"};
    return s < 4 ? names[s] : "?";
}

static int cmd_slots(struct ctl *c)
{
    int fd, rc = need_fd(c, "slot_map", &fd);
    if (rc)
        return rc;
    struct grad_slot_key k, next;
    struct grad_slot v;
    int first = 1, have = bpf_map_get_next_key(fd, NULL, &next) == 0;
    uint64_t now = mono_ns();
    if (c->json)
        printf("[");
    while (have) {
        k = next;
        have = bpf_map_get_next_key(fd, &k, &next) == 0;
        if (bpf_map_lookup_elem_flags(fd, &k, &v, BPF_F_LOCK))
            continue;
        if (c->job_filter >= 0 && k.job_id != (uint32_t)c->job_filter)
            continue;
        if (strcmp(c->state_filter, "any") && strcmp(c->state_filter, state_name(v.state)))
            continue;
        double age_ms = (double)(now - v.last_touched_ns) / 1e6;
        if (c->json)
            printf("%s{\"job_id\":%u,\"round\":%u,\"chunk_id\":%u,\"state\":\"%s\",\"contributors\":%u,"
                   "\"fanin\":%u,\"chunk_len\":%u,\"overflowed\":%u,\"charged\":%u,\"age_ms\":%.1f}",
                   first ? "" : ",", k.job_id, k.round, k.chunk_id, state_name(v.state), v.contributors, v.fanin,
                   v.chunk_len, v.overflowed, v.charged, age_ms);
        else
            printf("job %u round %u chunk %u: %s %u/%u chunk_len %u age %.1f ms%s\n", k.job_id, k.round,
                   k.chunk_id, state_name(v.state), v.contributors, v.fanin, v.chunk_len, age_ms,
                   v.overflowed ? " overflowed" : "");
        first = 0;
    }
    if (c->json)
        printf("]\n");
    return 0;
}

static int cmd_jobs(struct ctl *c)
{
    int fd, rc = need_fd(c, "job_quota_map", &fd);
    if (rc)
        return rc;
    uint32_t k, next;
    struct job_quota_entry v;
    int first = 1, have = bpf_map_get_next_key(fd, NULL, &next) == 0;
    if (c->json)
        printf("[");
    while (have) {
        k = next;
        have = bpf_map_get_next_key(fd, &k, &next) == 0;
        if (bpf_map_lookup_elem(fd, &k, &v))
            continue;
        if (c->json)
            printf("%s{\"job_id\":%u,\"concurrent_slots\":%u}", first ? "" : ",", k, v.concurrent_slots);
        else
            printf("job %u: %u charged slot(s)\n", k, v.concurrent_slots);
        first = 0;
    }
    if (c->json)
        printf("]\n");
    return 0;
}

/* ---- sweep ----------------------------------------------------------------------- */

static int cmd_sweep(struct ctl *c)
{
    int slot_fd, sweep_fd, cfg_fd, rc;
    if ((rc = need_fd(c, "slot_map", &slot_fd)) || (rc = need_fd(c, "netsum_sweep", &sweep_fd)) ||
        (rc = need_fd(c, "config_map", &cfg_fd)))
        return rc;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    uint32_t zero = 0;
    struct netsum_config cfg;
    int have_cfg = bpf_map_lookup_elem(cfg_fd, &zero, &cfg) == 0;
    long ttl_ms = c->ttl_ms >= 0 ? c->ttl_ms : (have_cfg ? (long)cfg.slot_ttl_ms : -1);
    if (ttl_ms < 0)
        return fail(EXIT_USAGE, "sweep needs --ttl-ms (or slot_ttl_ms in config)");
    if (c->flush_to) {
        char host[64];
        const char *colon = strrchr(c->flush_to, ':');
        if (!colon || (size_t)(colon - c->flush_to) >= sizeof(host))
            return fail(EXIT_USAGE, "bad --flush-to");
        memcpy(host, c->flush_to, (size_t)(colon - c->flush_to));
        host[colon - c->flush_to] = 0;
        to.sin_port = htons((uint16_t)atoi(colon + 1));
        if (inet_pton(AF_INET, host, &to.sin_addr) != 1)
            return fail(EXIT_USAGE, "bad --flush-to address");
    } else if (have_cfg) {
        to.sin_addr.s_addr = cfg.ps_ip;
        to.sin_port = cfg.ps_port;
    } else {
        return fail(EXIT_USAGE, "sweep needs --flush-to or a config");
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return fail(EXIT_ENV, "socket: %s", strerror(errno));

    uint64_t ttl_ns = (uint64_t)ttl_ms * 1000000ull;
    uint64_t passes = 0, flushed = 0, retired = 0, examined = 0;
    uint64_t t_end = c->duration_ms > 0 ? mono_ns() + (uint64_t)c->duration_ms * 1000000ull : 0;
    size_t cap = 1 << 17;
    struct grad_slot_key *keys = malloc(cap * sizeof(*keys));
    for (;;) {
        /* Snapshot the key set first: the sweep step deletes entries. */
        size_t n = 0;
        struct grad_slot_key k, next;
        int have = bpf_map_get_next_key(slot_fd, NULL, &next) == 0;
        while (have && n < cap) {
            keys[n++] = next;
            k = next;
            have = bpf_map_get_next_key(slot_fd, &k, &next) == 0;
        }
        for (size_t i = 0; i < n; i++) {
            uint8_t in[NETSUM_SWEEP_FRAME_SIZE], out[NETSUM_SWEEP_FRAME_SIZE + 64];
            memset(in, 0, sizeof(in));
            struct grad_hdr *h = (struct grad_hdr *)(in + NETSUM_SWEEP_PAYLOAD_OFFSET);
            h->job_id = htonl(keys[i].job_id);
            h->round = htonl(keys[i].round);
            h->chunk_id = htonl(keys[i].chunk_id);
            memcpy(h + 1, &ttl_ns, sizeof(ttl_ns));
            LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = in, .data_size_in = sizeof(in), .data_out = out,
                        .data_size_out = sizeof(out), .repeat = 1);
            if (bpf_prog_test_run_opts(sweep_fd, &o))
                return fail(EXIT_RUNTIME, "sweep step: %s", strerror(errno));
            examined++;
            if (o.retval == XDP_TX) {
                const struct grad_hdr *oh = (const struct grad_hdr *)(out + NETSUM_SWEEP_PAYLOAD_OFFSET);
                size_t len = NETSUM_HDR_SIZE + 4 * (size_t)ntohs(oh->chunk_len) + NETSUM_BITMAP_BYTES;
                sendto(sock, oh, len, 0, (struct sockaddr *)&to, sizeof(to));
                flushed++;
                if (!c->json)
                    printf("[partial-flush] job=%u round=%u chunk=%u\n", keys[i].job_id, keys[i].round,
                           keys[i].chunk_id);
            } else if (o.retval == XDP_DROP) {
                retired++;
            }
        }
        passes++;
        if (c->once || (t_end && mono_ns() >= t_end))
            break;
        usleep((useconds_t)(c->interval_ms > 0 ? c->interval_ms : 100) * 1000);
    }
    printf("{\"passes\":%llu,\"examined\":%llu,\"flushed_partial\":%llu,\"retired\":%llu}\n",
           (unsigned long long)passes, (unsigned long long)examined, (unsigned long long)flushed,
           (unsigned long long)retired);
    free(keys);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: netsum-ctl [--pin DIR] [--json] <command> [options]\n"
            "  attach  --ifname IF [--ifname IF2] [--mode native|generic|auto] [--obj xdp_agg/xdp_agg.o]\n"
            "  detach  --ifname IF [--unpin]\n"
            "  config  --ps-mac MAC --ps-ip IP --ps-port N [--agg-mac MAC --agg-ip IP] [--egress-ifname IF]\n"
            "          [--max-slots-per-job N] [--quota-policy none|drop|fallback] [--slot-ttl-ms N] | --delete\n"
            "  stats   [--reset]\n"
            "  slots   [--state any|accumulating|completed|flushed] [--job N]\n"
            "  jobs\n"
            "  sweep   --ttl-ms N [--interval-ms M] [--once | --duration-ms D] [--flush-to IP:PORT]\n"
            "default --pin is /sys/fs/bpf/netsum\n");
}

int main(int argc, char **argv)
{
    struct ctl c;
    memset(&c, 0, sizeof(c));
    c.pin = "/sys/fs/bpf/netsum";
    c.obj_path = "xdp_agg/xdp_agg.o";
    c.mode = "auto";
    c.ttl_ms = -1;
    c.job_filter = -1;
    c.state_filter = "any";
    enum { O_PIN = 256, O_OBJ, O_IF, O_MODE, O_JSON, O_RESET, O_ONCE, O_UNPIN, O_TTL, O_INTERVAL, O_DURATION,
           O_STATE, O_JOB, O_FLUSH, O_PSMAC, O_PSIP, O_PSPORT, O_AGGMAC, O_AGGIP, O_EGRESS, O_MAX, O_POLICY,
           O_SLOTTTL, O_DELETE };
    static const struct option opts[] = {
        {"pin", required_argument, 0, O_PIN}, {"obj", required_argument, 0, O_OBJ},
        {"ifname", required_argument, 0, O_IF}, {"mode", required_argument, 0, O_MODE},
        {"json", no_argument, 0, O_JSON}, {"reset", no_argument, 0, O_RESET}, {"once", no_argument, 0, O_ONCE},
        {"unpin", no_argument, 0, O_UNPIN}, {"ttl-ms", required_argument, 0, O_TTL},
        {"interval-ms", required_argument, 0, O_INTERVAL}, {"duration-ms", required_argument, 0, O_DURATION},
        {"state", required_argument, 0, O_STATE}, {"job", required_argument, 0, O_JOB},
        {"flush-to", required_argument, 0, O_FLUSH}, {"ps-mac", required_argument, 0, O_PSMAC},
        {"ps-ip", required_argument, 0, O_PSIP}, {"ps-port", required_argument, 0, O_PSPORT},
        {"agg-mac", required_argument, 0, O_AGGMAC}, {"agg-ip", required_argument, 0, O_AGGIP},
        {"egress-ifname", required_argument, 0, O_EGRESS}, {"max-slots-per-job", required_argument, 0, O_MAX},
        {"quota-policy", required_argument, 0, O_POLICY}, {"slot-ttl-ms", required_argument, 0, O_SLOTTTL},
        {"delete", no_argument, 0, O_DELETE}, {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (o) {
        case O_PIN: c.pin = optarg; break;
        case O_OBJ: c.obj_path = optarg; break;
        case O_IF:
            if (c.n_ifnames == MAX_IFACES)
                return fail(EXIT_USAGE, "at most %d --ifname", MAX_IFACES);
            c.ifnames[c.n_ifnames++] = optarg;
            break;
        case O_MODE: c.mode = optarg; break;
        case O_JSON: c.json = 1; break;
        case O_RESET: c.reset = 1; break;
        case O_ONCE: c.once = 1; break;
        case O_UNPIN: c.unpin = 1; break;
        case O_TTL: c.ttl_ms = atol(optarg); break;
        case O_INTERVAL: c.interval_ms = atol(optarg); break;
        case O_DURATION: c.duration_ms = atol(optarg); break;
        case O_STATE: c.state_filter = optarg; break;
        case O_JOB: c.job_filter = atol(optarg); break;
        case O_FLUSH: c.flush_to = optarg; break;
        case O_PSMAC: c.ps_mac = optarg; break;
        case O_PSIP: c.ps_ip = optarg; break;
        case O_PSPORT: c.ps_port = atol(optarg); break;
        case O_AGGMAC: c.agg_mac = optarg; break;
        case O_AGGIP: c.agg_ip = optarg; break;
        case O_EGRESS: c.egress_ifname = optarg; break;
        case O_MAX: c.max_slots = atol(optarg); break;
        case O_POLICY: c.quota_policy = optarg; break;
        case O_SLOTTTL: c.slot_ttl_ms = atol(optarg); break;
        case O_DELETE: c.delete_config = 1; break;
        default: usage(); return EXIT_USAGE;
        }
    }
    if (optind >= argc) {
        usage();
        return EXIT_USAGE;
    }
    const char *cmd = argv[optind];
    if (!strcmp(cmd, "attach")) return cmd_attach(&c);
    if (!strcmp(cmd, "detach")) return cmd_detach(&c);
    if (!strcmp(cmd, "config")) return cmd_config(&c);
    if (!strcmp(cmd, "stats")) return cmd_stats(&c);
    if (!strcmp(cmd, "slots")) return cmd_slots(&c);
    if (!strcmp(cmd, "jobs")) return cmd_jobs(&c);
    if (!strcmp(cmd, "sweep")) return cmd_sweep(&c);
    usage();
    return EXIT_USAGE;
}
