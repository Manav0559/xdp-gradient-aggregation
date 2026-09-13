/* netsum_cfg_loader: a tiny CI-only helper that writes exactly one entry
 * into xdp_agg.c's pinned `config_map` (BPF_MAP_TYPE_HASH, key uint32_t 0,
 * value struct netsum_config), using libbpf's low-level bpf() syscall
 * wrappers (bpf_obj_get / bpf_map_update_elem from <bpf/bpf.h>) against the
 * map's pinned bpffs path -- no custom ELF or BTF parsing needed, since
 * `bpftool ... pinmaps DIR` (used by the CI workflow) already pins every
 * map from xdp_agg.o under DIR by name.
 *
 * struct netsum_config is copied here VERBATIM from xdp_agg/xdp_agg.c --
 * this is the one place a layout mismatch would silently corrupt the
 * config the real kernel program reads, so if that struct ever changes,
 * this copy must change with it.
 *
 * Usage: netsum_cfg_loader <config_map_pinned_path> <mac aa:bb:cc:dd:ee:ff> <ipv4> <port>
 */
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct netsum_config {
    uint8_t ps_mac[6];
    uint16_t _pad;
    uint32_t ps_ip;   /* network byte order */
    uint16_t ps_port; /* network byte order */
};

static int parse_mac(const char *s, uint8_t out[6]) {
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <config_map_pinned_path> <mac> <ipv4> <port>\n", argv[0]);
        return 1;
    }
    const char *map_path = argv[1];
    const char *mac_str = argv[2];
    const char *ip_str = argv[3];
    int port = atoi(argv[4]);

    struct netsum_config cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (parse_mac(mac_str, cfg.ps_mac) != 0) {
        fprintf(stderr, "invalid mac: %s\n", mac_str);
        return 1;
    }
    if (inet_pton(AF_INET, ip_str, &cfg.ps_ip) != 1) {
        /* inet_pton writes the address already in network byte order --
         * exactly what ps_ip wants, no htonl needed. */
        fprintf(stderr, "invalid ipv4: %s\n", ip_str);
        return 1;
    }
    cfg.ps_port = htons((uint16_t)port);

    fprintf(stderr,
            "netsum_cfg_loader: writing ps_mac=%02x:%02x:%02x:%02x:%02x:%02x "
            "ps_ip=%s ps_port=%d (sizeof(struct netsum_config)=%zu) to %s\n",
            cfg.ps_mac[0], cfg.ps_mac[1], cfg.ps_mac[2], cfg.ps_mac[3], cfg.ps_mac[4], cfg.ps_mac[5],
            ip_str, port, sizeof(cfg), map_path);

    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    uint32_t key = 0;
    int rc = bpf_map_update_elem(fd, &key, &cfg, BPF_ANY);
    if (rc != 0) {
        perror("bpf_map_update_elem");
        close(fd);
        return 1;
    }
    close(fd);
    fprintf(stderr, "netsum_cfg_loader: config_map[0] written OK\n");
    return 0;
}
