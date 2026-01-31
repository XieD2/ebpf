// agent_expend.c
// CORE host veth naming: veth{node_hex}.0.{session_short_id}
// Container side often ends with 'p': veth{node_hex}.0.{sid}p
//
// One-click:
//  1) load eBPF obj once, pin progs + maps under pin_root
//  2) per dev: setup root HTB + per-src class/netem + flower(src_ip)->class
//  3) per dev: attach eBPF dropper as tc bpf filter on parent 1: (prio 1)
//  4) UDP updates: update BPF map(key={ifindex,src_ip}) and tc change (delay/jitter/rate)
//
// IMPORTANT FIX:
//  tc interprets classid/handle numbers as HEX by default.
//  So we MUST print minor in hex (4 digits) to avoid overflow parsing.
//
// Build:
//   gcc -O2 -Wall agent_expend.c -o agent_expend -lbpf
//
// Run:
//   sudo ./agent_expend ebpf.o classifier egress 9000 /sys/fs/bpf/lsdb $(ls /sys/class/net | grep -E '^veth[0-9a-f]+\.0\.1$' | sort -V)
//
// UDP payload (text), repeat groups:
//   "dev src_ip loss delay_us jitter_us rate_mbit ..."
// Example:
//   echo -n "vetha.0.1 10.0.0.2 20 30000 5000 100" | nc -u -w1 127.0.0.1 9000

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
#include <sys/select.h>  // 添加select头文件

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo) { (void)signo; g_stop = 1; }

static int run_cmd(const char *cmd) {//所有配置都通过shell命令执行
    int rc = system(cmd);
    return rc;
}

// 从目录里找到第一个文件
static int first_entry_path(const char *dir, char *out, size_t outlen) {//dir: 目录路径, out: 存储第一个目录项的完整路径， outlen: 缓冲区out的大小 
    DIR *d = opendir(dir);
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;//跳过当前目录和父目录
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

static int ensure_bpffs_and_dirs(const char *pin_root) {//挂载bpffs并创建pin目录
    run_cmd("mount | grep -q \"/sys/fs/bpf type bpf\" || mount -t bpf bpf /sys/fs/bpf");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/progs %s/maps", pin_root, pin_root);
    return run_cmd(cmd);
}

static int load_once_pin_all(const char *obj, const char *pin_root) {//一次性加载ebpf 并 pin
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

static int ends_with_p(const char *s) {//判断是否是容器侧veth
    size_t n = strlen(s);
    return (n > 0 && s[n - 1] == 'p');
}

// veth命名解析
static int parse_core_veth(const char *dev, int *node_id, int *if_id, int *sid, int *is_container_side) {
    char node_str[32] = {0};
    int iface = -1;
    char sid_str[32] = {0};

    if (sscanf(dev, "veth%31[^.].%d.%31s", node_str, &iface, sid_str) != 3) {
        return -1;
    }

    // node id is hex string (e.g., a, 10, 65 ...)
    char *end = NULL;
    unsigned long node = strtoul(node_str, &end, 16);
    if (end == node_str || *end != '\0') return -1;
    if (node < 1 || node > 254) return -1;

    // sid may end with 'p'
    int cont = 0;
    size_t sl = strlen(sid_str);
    if (sl > 0 && sid_str[sl - 1] == 'p') {
        cont = 1;
        sid_str[sl - 1] = '\0';
    }

    char *end2 = NULL;
    unsigned long sid_ul = strtoul(sid_str, &end2, 10);
    if (end2 == sid_str || *end2 != '\0') return -1;
    if (sid_ul > 65535) return -1;

    *node_id = (int)node;
    *if_id = iface;
    *sid = (int)sid_ul;
    *is_container_side = cont;
    return 0;
}

static int parse_recv_id_from_dev(const char *dev) {
    int node_id, if_id, sid, is_cont;
    if (parse_core_veth(dev, &node_id, &if_id, &sid, &is_cont) == 0) {
        if (is_cont) return -1;
        return node_id; // decimal node id
    }
    return -1;
}

// -------- tc layout (per dev) --------
// root: htb 1:
// default class: 1:10 (no match)
// per-src class: 1:<minor_hex4> where minor = (recv_id<<8)|src_id
// netem handle equals minor_hex4: <minor_hex4>:
// filter: flower src_ip 10.0.0.<src_id> -> flowid 1:<minor_hex4>

static void ensure_tc_base(const char *dev) {
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root handle 1: htb default 10", dev);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "tc class replace dev %s parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit", dev);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s parent 1:10 handle 10: netem delay 0us 0us", dev);
    run_cmd(cmd);
}

static unsigned make_minor_u16(int recv_id, int src_id) {
    return (unsigned)(((recv_id & 0xff) << 8) | (src_id & 0xff)); // 0x0000..0xffff
}

static void minor_to_hex4(unsigned minor, char out[8]) {
    // tc expects hex-ish identifiers; force 4 hex digits to be safe.
    snprintf(out, 8, "%04x", minor & 0xffff);
}

static void ensure_tc_link(const char *dev, int recv_id, int src_id) {
    char cmd[1024];
    unsigned minor = make_minor_u16(recv_id, src_id);
    char mid[8];
    minor_to_hex4(minor, mid);

    snprintf(cmd, sizeof(cmd),
             "tc class replace dev %s parent 1: classid 1:%s htb rate 1000mbit ceil 1000mbit",
             dev, mid);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc qdisc replace dev %s parent 1:%s handle %s: netem delay 0us 0us",
             dev, mid, mid);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc filter replace dev %s protocol ip parent 1: prio 10 flower src_ip 10.0.0.%d flowid 1:%s",
             dev, src_id, mid);
    run_cmd(cmd);
}

static void apply_tc_params(const char *dev, int recv_id, int src_id,
                            uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    char cmd[1024];
    unsigned minor = make_minor_u16(recv_id, src_id);
    char mid[8];
    minor_to_hex4(minor, mid);

    if (rate_mbit == 0) rate_mbit = 1;

    snprintf(cmd, sizeof(cmd),
             "tc class change dev %s classid 1:%s htb rate %umbit ceil %umbit",
             dev, mid, rate_mbit, rate_mbit);
    run_cmd(cmd);

    snprintf(cmd, sizeof(cmd),
             "tc qdisc change dev %s parent 1:%s handle %s: netem delay %uus %uus",
             dev, mid, mid, delay_us, jitter_us);
    run_cmd(cmd);
}

static int attach_bpf_filter_on_root(const char *dev, const char *pinned_prog_path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "tc filter replace dev %s parent 1: protocol all prio 1 bpf direct-action pinned %s",
             dev, pinned_prog_path);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to attach bpf filter on %s parent 1:\n  %s\n", dev, cmd);
        return -1;
    }
    return 0;
}

// -------- BPF map key/value --------
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

// Collect unique node ids from dev list (host-side only)
static int collect_nodes_from_devs(int argc, char **argv, int dev_start, int *nodes_out, int max_nodes) {
    int n = 0;
    for (int i = dev_start; i < argc; i++) {
        int node_id, if_id, sid, is_cont;
        if (parse_core_veth(argv[i], &node_id, &if_id, &sid, &is_cont) != 0) continue;
        if (is_cont) continue;

        int exist = 0;
        for (int k = 0; k < n; k++) {
            if (nodes_out[k] == node_id) { exist = 1; break; }
        }
        if (!exist && n < max_nodes) nodes_out[n++] = node_id;
    }
    return n;
}

static int update_map_one(int map_fd, const char *dev, const char *src_ip_str,
                          uint32_t loss, uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    if (ends_with_p(dev)) {
        fprintf(stderr, "WARN: dev '%s' looks container-side (endswith p), skip\n", dev);
        return -1;
    }

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

    // src_id from src_ip last octet (decimal!)
    uint32_t ip_host = ntohl(a.s_addr);
    int src_id = (int)(ip_host & 0xff);

    int recv_id = parse_recv_id_from_dev(dev);
    if (recv_id < 0) {
        fprintf(stderr, "WARN: cannot infer recv_id from dev '%s' (expect veth{hex}.0.{sid}). Skip tc apply.\n", dev);
        return 0;
    }
    if (src_id <= 0 || src_id > 254 || src_id == recv_id) {
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
            "  sudo %s ebpf.o classifier egress 9000 /sys/fs/bpf/lsdb veth2.0.1 vetha.0.1 veth10.0.1\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *obj      = argv[1];
    const char *sec      = argv[2];
    const char *dir      = argv[3];
    (void)dir; // kept for compatibility
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

    // Collect node ids from dev list
    int nodes[256];
    int node_cnt = collect_nodes_from_devs(argc, argv, 6, nodes, 256);
    if (node_cnt <= 0) {
        fprintf(stderr, "No valid host-side veth devs found in args.\n");
        return 1;
    }

    // setup tc + attach bpf on each dev
    for (int i = 6; i < argc; i++) {
        const char *dev = argv[i];

        int recv_id = parse_recv_id_from_dev(dev);
        if (recv_id < 0) {
            fprintf(stderr, "Skip dev '%s' (not host-side veth{hex}.0.{sid})\n", dev);
            continue;
        }

        ensure_tc_base(dev);

        // create per-src rules for all other nodes
        for (int k = 0; k < node_cnt; k++) {
            int src_id = nodes[k];
            if (src_id == recv_id) continue;
            ensure_tc_link(dev, recv_id, src_id);
        }

        if (attach_bpf_filter_on_root(dev, pinned_prog) != 0) return 1;

        printf("Dev ready: %s (recv_id=%d), bpf=%s, map=%s\n", dev, recv_id, pinned_prog, pinned_map);
    }

    printf("Pinned map: %s (key_size=%u, value_size=%u)\n", pinned_map, key_size, value_size);
    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Payload groups:\n");
    printf("  dev src_ip loss delay_us jitter_us rate_mbit\n");
    printf("Example:\n");
    printf("  echo -n \"vetha.0.1 10.0.0.2 20 30000 5000 100\" | nc -u -w1 127.0.0.1 %d\n", port);

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
        fd_set readfds;  // 定义文件描述符集合
        FD_ZERO(&readfds);  // 清空集合
        FD_SET(s, &readfds);  // 将socket加入集合

        struct timeval timeout = {1, 0};  // 设置1秒超时

        // 使用select等待数据或超时，同时允许信号中断
        int ret = select(s + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) continue;  // 处理信号中断
            perror("select");
            break;
        }

        // 如果检测到停止信号，直接退出循环
        if (g_stop) break;

        // 如果有数据包到达，处理它
        if (FD_ISSET(s, &readfds)) {
            char buf[4096];
            struct sockaddr_in peer;
            socklen_t peerlen = sizeof(peer);

            ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&peer, &peerlen);
            if (n < 0) {
                if (errno == EINTR) continue;  // 处理信号中断
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

                char *t_src  = strtok_r(NULL, " \t\r\n", &save);
                char *t_loss = strtok_r(NULL, " \t\r\n", &save);
                char *t_dly  = strtok_r(NULL, " \t\r\n", &save);
                char *t_jit  = strtok_r(NULL, " \t\r\n", &save);
                char *t_rate = strtok_r(NULL, " \t\r\n", &save);
                if (!t_src || !t_loss || !t_dly || !t_jit || !t_rate) break;

                uint32_t loss      = (uint32_t)strtoul(t_loss, NULL, 10);
                uint32_t delay_us  = (uint32_t)strtoul(t_dly,  NULL, 10);
                uint32_t jitter_us = (uint32_t)strtoul(t_jit,  NULL, 10);
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
    }

    close(s);
    close(map_fd);
    printf("Agent exit.\n");
    return 0;
}