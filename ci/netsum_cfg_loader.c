/* Writes config_map[0] through its pinned path, using the shared
 * struct netsum_config from protocol/netsum_maps.h (no local copy).
 * Usage: netsum_cfg_loader <pinned config_map> <ps_mac> <ps_ip> <ps_port>
 *            [max_slots_per_job] [agg_mac agg_ip] [egress_ifindex] */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../protocol/netsum_maps.h"

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)b[i];
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5 || argc == 7) {
        fprintf(stderr, "usage: %s <pinned config_map> <ps_mac> <ps_ip> <ps_port> "
                        "[max_slots_per_job] [agg_mac agg_ip] [egress_ifindex]\n", argv[0]);
        return 1;
    }
    struct netsum_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    struct in_addr ip;
    if (parse_mac(argv[2], cfg.ps_mac) || inet_pton(AF_INET, argv[3], &ip) != 1) {
        fprintf(stderr, "bad ps_mac or ps_ip\n");
        return 1;
    }
    cfg.ps_ip = ip.s_addr;
    cfg.ps_port = htons((uint16_t)atoi(argv[4]));
    cfg.ack_port = htons(NETSUM_ACK_PORT);
    if (argc > 5)
        cfg.max_slots_per_job = (uint32_t)strtoul(argv[5], NULL, 10);
    cfg.quota_policy = cfg.max_slots_per_job ? NETSUM_QUOTA_DROP : NETSUM_QUOTA_NONE;
    if (argc > 7) {
        if (parse_mac(argv[6], cfg.agg_mac) || inet_pton(AF_INET, argv[7], &ip) != 1) {
            fprintf(stderr, "bad agg_mac or agg_ip\n");
            return 1;
        }
        cfg.agg_ip = ip.s_addr;
    }
    if (argc > 8)
        cfg.egress_ifindex = (uint32_t)strtoul(argv[8], NULL, 10);

    int fd = bpf_obj_get(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }
    uint32_t key = 0;
    if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
        fprintf(stderr, "bpf_map_update_elem(config_map): %s\n", strerror(errno));
        return 1;
    }
    printf("config_map[0] written: ps_port=%s max_slots_per_job=%u agg_ip=%s egress_ifindex=%u\n",
           argv[4], cfg.max_slots_per_job, argc > 7 ? argv[7] : "(unchanged)", cfg.egress_ifindex);
    return 0;
}
