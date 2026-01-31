// agent_rx_srcip.c
// One-click: load obj once (pin progs + pin maps) + attach eBPF on each dev egress
//          + build per-dev tc (htb+netem) with flower src_ip -> class
//          + UDP update BPF map(key={ifindex,src_ip}) and tc change (delay/jitter/rate)
//
// Build:
//   gcc -O2 -Wall agent_rx_srcip.c -o agent_rx -lbpf
//
// Run:
//   sudo ./agent_rx test2.o classifier egress 9000 /sys/fs/bpf/lsdb veth1.0.1 veth2.0.1 veth3.0.1
//
// UDP payload (text), repeat groups:
//   "dev src_ip loss delay_us jitter_us rate_mbit ..."

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <dirent.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo) { (void)signo; g_stop = 1; }

static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    return rc;
}

// Return first entry path under dir (skip . and ..). Store into out.
static int first_entry_path(const char *dir, char *out, size_t outlen) {
    DIR *d = opendir(dir);
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        int ret = snprintf(out, outlen, "%s/%s", dir, de->d_name);
        if (ret < 0 || (size_t)ret >= outlen) {
            closedir(d);
            return -1;
        }
        closedir(d);
        return 0;
    }
    closedir(d);
    return -1;
}

static int ensure_bpffs_and_dirs(const char *pin_root) {
    run_cmd("mount | grep -q \"/sys/fs/bpf type bpf\" || mount -t bpf bpf /sys/fs/bpf");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/progs %s/maps", pin_root, pin_root);
    return run_cmd(cmd);
}

static int load_once_pin_all(const char *obj, const char *pin_root) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s/progs/* %s/maps/* 2>/dev/null || true", pin_root, pin_root);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "bpftool prog loadall %s %s/progs pinmaps %s/maps",
             obj, pin_root, pin_root);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed: %s\n", cmd);
        return -1;
    }
    return 0;
}

// ---- tc layout (per dev) ----
// root: htb 1:
// default class: 1:10 (no match)
// peer classes: 1:<recvId><srcId>   e.g. recv=1, src=2 => 1:12
// netem handle equals minor: <minor>:
// filters: flower src_ip 10.0.0.<srcId> -> flowid 1:<minor>

static int parse_recv_id_from_dev(const char *dev) {
    int id = -1;
    // expect "veth<id>."
    if (sscanf(dev, "veth%d.", &id) == 1 && id >= 1 && id <= 254) return id;
    return -1;
}

static void ensure_tc_base(const char *dev) {
    char cmd[1024];

    // root htb + default class 1:10 + netem under 1:10
    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root handle 1: htb default 10", dev);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "tc class replace dev %s parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit", dev);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s parent 1:10 handle 10: netem delay 0us 0us", dev);
    run_cmd(cmd);
}

static void ensure_tc_link(const char *dev, int recv_id, int src_id) {
    char cmd[1024];
    int minor = recv_id * 10 + src_id; // e.g. 12, 13, 21, 23, 31, 32

    // class + netem
    snprintf(cmd, sizeof(cmd),
             "tc class replace dev %s parent 1: classid 1:%d htb rate 1000mbit ceil 1000mbit",
             dev, minor);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc qdisc replace dev %s parent 1:%d handle %d: netem delay 0us 0us",
             dev, minor, minor);
    run_cmd(cmd);

    // flower src_ip -> flowid
    snprintf(cmd, sizeof(cmd),
             "tc filter replace dev %s protocol ip parent 1: prio 10 flower src_ip 10.0.0.%d flowid 1:%d",
             dev, src_id, minor);
    run_cmd(cmd);
}

static void apply_tc_params(const char *dev, int recv_id, int src_id,
                            uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    char cmd[1024];
    int minor = recv_id * 10 + src_id;

    if (rate_mbit == 0) rate_mbit = 1;

    snprintf(cmd, sizeof(cmd),
             "tc class change dev %s classid 1:%d htb rate %umbit ceil %umbit",
             dev, minor, rate_mbit, rate_mbit);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc qdisc change dev %s parent 1:%d handle %d: netem delay %uus %uus",
             dev, minor, minor, delay_us, jitter_us);
    run_cmd(cmd);
}

static int attach_bpf_filter_on_root(const char *dev, const char *dir, const char *pinned_prog_path) {
    // IMPORTANT: 我们用 root htb，所以不能再用 clsact；直接把 bpf filter 挂到 parent 1:
    // prio 1，确保先于 flower(prio 10) 执行丢包
    char cmd[1024];
    (void)dir; // 这里固定按 root parent 1: 做 egress shaping，dir 参数仅保留兼容

    snprintf(cmd, sizeof(cmd),
             "tc filter replace dev %s parent 1: protocol all prio 1 bpf direct-action pinned %s",
             dev, pinned_prog_path);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to attach bpf filter on %s parent 1:\n  %s\n", dev, cmd);
        return -1;
    }
    return 0;
}

struct topo_key {
    uint32_t ifindex;
    uint32_t src_ip; // network order
};

struct topo_params {
    uint32_t loss_percent;
    uint32_t delay_us;
    uint32_t jitter_us;
    uint32_t rate_mbit;
};

static int get_map_sizes(int map_fd, uint32_t *value_size, uint32_t *key_size) {
    struct bpf_map_info info;
    __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(map_fd, &info, &len) != 0) return -1;
    *value_size = info.value_size;
    *key_size = info.key_size;
    return 0;
}

static uint32_t clamp100_u32(uint32_t v) { return (v > 100) ? 100 : v; }

static int update_map_one(int map_fd, const char *dev, const char *src_ip_str,
                          uint32_t loss, uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    unsigned ifindex = if_nametoindex(dev);
    if (ifindex == 0) {
        fprintf(stderr, "WARN: unknown dev '%s'\n", dev);
        return -1;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, src_ip_str, &a) != 1) {
        fprintf(stderr, "WARN: bad src_ip '%s'\n", src_ip_str);
        return -1;
    }

    struct topo_key key = {
        .ifindex = (uint32_t)ifindex,
        .src_ip  = a.s_addr, // network order
    };

    struct topo_params val = {
        .loss_percent = clamp100_u32(loss),
        .delay_us = delay_us,
        .jitter_us = jitter_us,
        .rate_mbit = rate_mbit,
    };

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return -1;
    }

    // apply tc (delay/jitter/rate) based on src_id inferred from 10.0.0.X
    uint32_t ip_host = ntohl(a.s_addr);
    int src_id = (int)(ip_host & 0xff);

    int recv_id = parse_recv_id_from_dev(dev);
    if (recv_id < 0) {
        fprintf(stderr, "WARN: cannot infer recv_id from dev '%s' (expect veth<id>.*). Skip tc apply.\n", dev);
        return 0;
    }
    if (src_id <= 0 || src_id > 254 || src_id == recv_id) {
        // ignore weird
        return 0;
    }

    apply_tc_params(dev, recv_id, src_id, delay_us, jitter_us, rate_mbit);

    printf("Update: dev=%s ifindex=%u src=%s loss=%u delay=%u jitter=%u rate=%u\n",
           dev, ifindex, src_ip_str, val.loss_percent, delay_us, jitter_us, rate_mbit);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
            "Usage:\n"
            "  sudo %s <obj.o> <sec_name> <egress|ingress> <port> <pin_root> <dev1> [dev2 ...]\n"
            "Example:\n"
            "  sudo %s test2.o classifier egress 9000 /sys/fs/bpf/lsdb veth1.0.1 veth2.0.1 veth3.0.1\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *obj      = argv[1];
    const char *sec      = argv[2]; // section name, e.g. "classifier"
    const char *dir      = argv[3];
    int port             = atoi(argv[4]);
    const char *pin_root = argv[5];

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    if (ensure_bpffs_and_dirs(pin_root) != 0) {
        fprintf(stderr, "Failed to setup bpffs/dirs\n");
        return 1;
    }
    if (load_once_pin_all(obj, pin_root) != 0) {
        fprintf(stderr, "Failed to load/pin %s\n", obj);
        return 1;
    }

    char pinned_prog[512];
    snprintf(pinned_prog, sizeof(pinned_prog), "%s/progs/%s", pin_root, sec);

    // find first pinned map (assume only one map)
    char maps_dir[512], pinned_map[512];
    snprintf(maps_dir, sizeof(maps_dir), "%s/maps", pin_root);
    if (first_entry_path(maps_dir, pinned_map, sizeof(pinned_map)) != 0) {
        fprintf(stderr, "No pinned maps found under %s\n", maps_dir);
        return 1;
    }

    // open map
    int map_fd = bpf_obj_get(pinned_map);
    if (map_fd < 0) {
        perror("bpf_obj_get(pinned_map)");
        fprintf(stderr, "Failed to open pinned map: %s\n", pinned_map);
        return 1;
    }

    uint32_t value_size = 0, key_size = 0;
    if (get_map_sizes(map_fd, &value_size, &key_size) != 0) {
        perror("bpf_obj_get_info_by_fd(map)");
        return 1;
    }
    if (value_size != sizeof(struct topo_params) || key_size != sizeof(struct topo_key)) {
        fprintf(stderr, "Map size mismatch: key_size=%u (need %zu), value_size=%u (need %zu)\n",
                key_size, sizeof(struct topo_key), value_size, sizeof(struct topo_params));
        return 1;
    }

    // setup tc + attach bpf on each dev
    for (int i = 6; i < argc; i++) {
        const char *dev = argv[i];
        int recv_id = parse_recv_id_from_dev(dev);

        ensure_tc_base(dev);

        // 3-node default: for recv_id, create links for all other node ids 1..3
        // (你后面扩展 N 节点，可以改成从 dev 列表里推导 peers)
        if (recv_id >= 1 && recv_id <= 3) {
            for (int src_id = 1; src_id <= 3; src_id++) {
                if (src_id == recv_id) continue;
                ensure_tc_link(dev, recv_id, src_id);
            }
        }

        // attach bpf dropper as prio 1 filter on parent 1:
        if (attach_bpf_filter_on_root(dev, dir, pinned_prog) != 0) return 1;

        printf("Dev ready: %s (recv_id=%d), bpf=%s, map=%s\n", dev, recv_id, pinned_prog, pinned_map);
    }

    printf("Pinned map: %s (key_size=%u, value_size=%u)\n", pinned_map, key_size, value_size);
    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Payload groups:\n");
    printf("  dev src_ip loss delay_us jitter_us rate_mbit\n");
    printf("Example:\n");
    printf("  echo -n \"veth1.0.1 10.0.0.2 10 30000 5000 100 veth1.0.1 10.0.0.3 30 100000 20000 50\" | nc -u -w1 127.0.0.1 %d\n", port);

    // UDP server
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }

    while (!g_stop) {
        char buf[4096];
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);

        ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        buf[n] = '\0';

        char *save = NULL;
        char *tok = strtok_r(buf, " \t\r\n", &save);
        int updates = 0;

        while (tok) {
            char dev[IF_NAMESIZE];
            snprintf(dev, sizeof(dev), "%s", tok);

            char *t_src = strtok_r(NULL, " \t\r\n", &save);
            char *t_loss = strtok_r(NULL, " \t\r\n", &save);
            char *t_dly  = strtok_r(NULL, " \t\r\n", &save);
            char *t_jit  = strtok_r(NULL, " \t\r\n", &save);
            char *t_rate = strtok_r(NULL, " \t\r\n", &save);
            if (!t_src || !t_loss || !t_dly || !t_jit || !t_rate) break;

            uint32_t loss = (uint32_t)strtoul(t_loss, NULL, 10);
            uint32_t delay_us = (uint32_t)strtoul(t_dly, NULL, 10);
            uint32_t jitter_us = (uint32_t)strtoul(t_jit, NULL, 10);
            uint32_t rate_mbit = (uint32_t)strtoul(t_rate, NULL, 10);

            if (update_map_one(map_fd, dev, t_src, loss, delay_us, jitter_us, rate_mbit) == 0) {
                updates++;
            }

            tok = strtok_r(NULL, " \t\r\n", &save);
        }

        char ipbuf[64];
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        printf("From %s:%u bytes=%zd updates=%d\n", ipbuf, ntohs(peer.sin_port), n, updates);
        fflush(stdout);
    }

    close(s);
    close(map_fd);
    printf("Agent exit.\n");
    return 0;
}
