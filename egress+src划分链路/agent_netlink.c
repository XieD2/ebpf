// agent_expend_nl.c
// Replace all "tc ..." shell calls with rtnetlink (libnl-route).
// Replace "tc filter ... bpf pinned ..." with libbpf tc hook attach (clsact).
//
// Build:
//   gcc -O2 -Wall agent_expend_nl.c -o agent_expend_nl -lbpf -lnl-3 -lnl-route-3
//
// Run:
//   sudo ./agent_expend_nl ebpf.o classifier egress 9000 /sys/fs/bpf/lsdb $(ls /sys/class/net | grep -E '^veth[0-9a-f]+\.0\.1$' | sort -V)

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>  
#include <sys/select.h>
#include <unistd.h>

// libnl-route
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <netlink/route/classifier.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/qdisc/netem.h>
#include <netlink/route/cls/u32.h>

#ifndef TC_HANDLE
#define TC_HANDLE(maj, min) (TC_H_MAJ((maj) << 16) | TC_H_MIN(min))
#endif

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo) { (void)signo; g_stop = 1; }

// ------------------ helpers ------------------
static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    return rc;
}

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

static int ends_with_p(const char *s) {
    size_t n = strlen(s);
    return (n > 0 && s[n - 1] == 'p');
}

static int parse_core_veth(const char *dev, int *node_id, int *if_id, int *sid, int *is_container_side) {
    char node_str[32] = {0};
    int iface = -1;
    char sid_str[32] = {0};

    if (sscanf(dev, "veth%31[^.].%d.%31s", node_str, &iface, sid_str) != 3) {
        return -1;
    }

    char *end = NULL;
    unsigned long node = strtoul(node_str, &end, 16);
    if (end == node_str || *end != '\0') return -1;
    if (node < 1 || node > 254) return -1;

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
        return node_id;
    }
    return -1;
}

static unsigned make_minor_u16(int recv_id, int src_id) {
    return (unsigned)(((recv_id & 0xff) << 8) | (src_id & 0xff));
}

static uint64_t mbit_to_bytes_per_sec(uint32_t mbit) {
    // tc "mbit" = 1e6 bits/s
    // bytes/s = bits/s / 8
    return (uint64_t)mbit * 1000000ULL / 8ULL;
}

// ------------------ libnl context ------------------
struct nl_ctx {
    struct nl_sock  *sk;
    struct nl_cache *link_cache;
};

static int nl_ctx_init(struct nl_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->sk = nl_socket_alloc();
    if (!ctx->sk) return -1;

    int err = nl_connect(ctx->sk, NETLINK_ROUTE);
    if (err < 0) {
        fprintf(stderr, "nl_connect: %s\n", nl_geterror(err));
        return -1;
    }

    err = rtnl_link_alloc_cache(ctx->sk, AF_UNSPEC, &ctx->link_cache);
    if (err < 0) {
        fprintf(stderr, "rtnl_link_alloc_cache: %s\n", nl_geterror(err));
        return -1;
    }
    return 0;
}

static void nl_ctx_destroy(struct nl_ctx *ctx) {
    if (ctx->link_cache) nl_cache_free(ctx->link_cache);
    if (ctx->sk) nl_socket_free(ctx->sk);
    memset(ctx, 0, sizeof(*ctx));
}

static struct rtnl_link *nl_link_get(struct nl_ctx *ctx, const char *dev) {
    struct rtnl_link *link = rtnl_link_get_by_name(ctx->link_cache, dev);
    return link;
}

// ------------------ TC via libnl ------------------
//
// Layout per dev:
//   root qdisc: htb 1:  (defcls = 1:0x10)
//   default class: 1:0x10  (rate=1000mbit)
//   leaf qdisc on default: netem handle 0x10: (delay=0)
//
//   per src:
//     class: 1:<minor> parent 1: (rate=1000mbit initial)
//     leaf:  netem parent 1:<minor> handle <minor>:
//     filter: u32 match src ip -> classid 1:<minor> (parent 1: prio 10)

static int tc_qdisc_replace_htb_root(struct nl_ctx *ctx, struct rtnl_link *link) {
    int err;
    struct rtnl_qdisc *q = rtnl_qdisc_alloc();
    if (!q) return -1;

    rtnl_tc_set_link(TC_CAST(q), link);
    rtnl_tc_set_parent(TC_CAST(q), TC_H_ROOT);
    rtnl_tc_set_handle(TC_CAST(q), TC_HANDLE(1, 0));

    err = rtnl_tc_set_kind(TC_CAST(q), "htb");
    if (err < 0) {
        fprintf(stderr, "set_kind(htb): %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    // default class 1:0x10 (matches your old "default 10" behavior)
    err = rtnl_htb_set_defcls(q, TC_HANDLE(1, 0x10));
    if (err < 0) {
        fprintf(stderr, "rtnl_htb_set_defcls: %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    // rate2quantum: keep simple like libnl test does
    rtnl_htb_set_rate2quantum(q, 1);

    // Replace semantics: delete then add is the most compatible way across kernels.
    (void)rtnl_qdisc_delete(ctx->sk, q);
    err = rtnl_qdisc_add(ctx->sk, q, NLM_F_CREATE);
    if (err < 0) {
        fprintf(stderr, "rtnl_qdisc_add(htb): %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    rtnl_qdisc_put(q);
    return 0;
}

static int tc_class_replace_htb(struct nl_ctx *ctx, struct rtnl_link *link,
                                uint32_t parent_maj, uint32_t parent_min,
                                uint32_t child_maj, uint32_t child_min,
                                uint64_t rate_Bps, uint64_t ceil_Bps,
                                uint32_t burst_bytes, uint32_t cburst_bytes,
                                uint32_t prio) {
    int err;
    struct rtnl_class *cl = rtnl_class_alloc();
    if (!cl) return -1;

    rtnl_tc_set_link(TC_CAST(cl), link);
    rtnl_tc_set_parent(TC_CAST(cl), TC_HANDLE(parent_maj, parent_min));
    rtnl_tc_set_handle(TC_CAST(cl), TC_HANDLE(child_maj, child_min));

    err = rtnl_tc_set_kind(TC_CAST(cl), "htb");
    if (err < 0) {
        fprintf(stderr, "set_kind(class htb): %s\n", nl_geterror(err));
        rtnl_class_put(cl);
        return -1;
    }

    (void)rtnl_htb_set_prio(cl, prio);

    if (rate_Bps) (void)rtnl_htb_set_rate(cl, (uint32_t)rate_Bps); // wrapper exists; internally uses *_rate64
    if (ceil_Bps) (void)rtnl_htb_set_ceil(cl, (uint32_t)ceil_Bps);

    if (burst_bytes) (void)rtnl_htb_set_rbuffer(cl, burst_bytes);
    if (cburst_bytes) (void)rtnl_htb_set_cbuffer(cl, cburst_bytes);

    // Replace by re-adding with CREATE (kernel updates existing by handle)
    err = rtnl_class_add(ctx->sk, cl, NLM_F_CREATE);
    if (err < 0) {
        fprintf(stderr, "rtnl_class_add(htb): %s\n", nl_geterror(err));
        rtnl_class_put(cl);
        return -1;
    }

    rtnl_class_put(cl);
    return 0;
}

static int tc_qdisc_replace_netem(struct nl_ctx *ctx, struct rtnl_link *link,
                                  uint32_t parent_maj, uint32_t parent_min,
                                  uint32_t handle_maj,
                                  int delay_us, int jitter_us) {
    int err;
    struct rtnl_qdisc *q = rtnl_qdisc_alloc();
    if (!q) return -1;

    rtnl_tc_set_link(TC_CAST(q), link);
    rtnl_tc_set_parent(TC_CAST(q), TC_HANDLE(parent_maj, parent_min));
    rtnl_tc_set_handle(TC_CAST(q), TC_HANDLE(handle_maj, 0));

    err = rtnl_tc_set_kind(TC_CAST(q), "netem");
    if (err < 0) {
        fprintf(stderr, "set_kind(netem): %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    // libnl netem delay/jitter unit: microseconds
    rtnl_netem_set_delay(q, delay_us);
    rtnl_netem_set_jitter(q, jitter_us);

    // Replace: delete then add
    (void)rtnl_qdisc_delete(ctx->sk, q);
    err = rtnl_qdisc_add(ctx->sk, q, NLM_F_CREATE);
    if (err < 0) {
        fprintf(stderr, "rtnl_qdisc_add(netem): %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    rtnl_qdisc_put(q);
    return 0;
}

static int tc_filter_add_u32_srcip_to_class(struct nl_ctx *ctx, struct rtnl_link *link,
                                            uint32_t prio,
                                            uint32_t src_ip_be,
                                            uint32_t classid) {
    int err;
    struct rtnl_cls *cls = rtnl_cls_alloc();
    if (!cls) return -1;

    rtnl_tc_set_link(TC_CAST(cls), link);
    err = rtnl_tc_set_kind(TC_CAST(cls), "u32");
    if (err < 0) {
        fprintf(stderr, "set_kind(u32): %s\n", nl_geterror(err));
        rtnl_cls_put(cls);
        return -1;
    }

    rtnl_cls_set_prio(cls, prio);
    rtnl_cls_set_protocol(cls, ETH_P_IP);
    rtnl_tc_set_parent(TC_CAST(cls), TC_HANDLE(1, 0)); // parent 1:

   // offset from start of packet: ETH_HLEN + IPv4 saddr offset
    int off = (int)offsetof(struct iphdr, saddr); // 12
    rtnl_u32_add_key(cls, src_ip_be, 0xffffffffu, off, 0);


    rtnl_u32_set_classid(cls, classid);
    rtnl_u32_set_cls_terminal(cls);

    err = rtnl_cls_add(ctx->sk, cls, NLM_F_CREATE);
    if (err < 0) {
        // ignore duplicates
    }

    rtnl_cls_put(cls);
    return 0;
}

static int ensure_tc_base_nl(struct nl_ctx *ctx, const char *dev) {
    struct rtnl_link *link = nl_link_get(ctx, dev);
    if (!link) {
        fprintf(stderr, "WARN: link not found: %s\n", dev);
        return -1;
    }

    // Root HTB 1:
    if (tc_qdisc_replace_htb_root(ctx, link) != 0) {
        rtnl_link_put(link);
        return -1;
    }

    // Default class 1:0x10 rate=1000mbit (in bytes/s)
    uint64_t rate = mbit_to_bytes_per_sec(1000);
    // burst values: pick something stable (like libnl test uses 25000)
    if (tc_class_replace_htb(ctx, link, 1, 0, 1, 0x10, rate, rate, 25000, 25000, 0) != 0) {
        rtnl_link_put(link);
        return -1;
    }

    // Default leaf netem handle 0x10:
    if (tc_qdisc_replace_netem(ctx, link, 1, 0x10, 0x10, 0, 0) != 0) {
        rtnl_link_put(link);
        return -1;
    }

    rtnl_link_put(link);
    return 0;
}

static int ensure_tc_link_nl(struct nl_ctx *ctx, const char *dev, int recv_id, int src_id) {
    struct rtnl_link *link = nl_link_get(ctx, dev);
    if (!link) return -1;

    unsigned minor = make_minor_u16(recv_id, src_id);
    uint64_t rate = mbit_to_bytes_per_sec(1000);

    // class 1:<minor>
    if (tc_class_replace_htb(ctx, link, 1, 0, 1, minor, rate, rate, 25000, 25000, 0) != 0) {
        rtnl_link_put(link);
        return -1;
    }

    // leaf netem parent 1:<minor> handle <minor>:
    if (tc_qdisc_replace_netem(ctx, link, 1, minor, minor, 0, 0) != 0) {
        rtnl_link_put(link);
        return -1;
    }

    // u32 filter: src_ip 10.0.0.<src_id> -> classid 1:<minor>
    struct in_addr a;
    char ipbuf[32];
    snprintf(ipbuf, sizeof(ipbuf), "10.0.0.%d", src_id);
    if (inet_pton(AF_INET, ipbuf, &a) == 1) {
        (void)tc_filter_add_u32_srcip_to_class(ctx, link, 10, a.s_addr, TC_HANDLE(1, minor));
    }

    rtnl_link_put(link);
    return 0;
}

static int apply_tc_params_nl(struct nl_ctx *ctx, const char *dev,
                              int recv_id, int src_id,
                              uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    struct rtnl_link *link = nl_link_get(ctx, dev);
    if (!link) return -1;

    if (rate_mbit == 0) rate_mbit = 1;
    unsigned minor = make_minor_u16(recv_id, src_id);

    uint64_t rate = mbit_to_bytes_per_sec(rate_mbit);

    // Update class rate/ceil
    int rc1 = tc_class_replace_htb(ctx, link, 1, 0, 1, minor, rate, rate, 25000, 25000, 0);

    // Update netem delay/jitter
    int rc2 = tc_qdisc_replace_netem(ctx, link, 1, minor, minor, (int)delay_us, (int)jitter_us);

    rtnl_link_put(link);
    return (rc1 == 0 && rc2 == 0) ? 0 : -1;
}

// ------------------ libbpf tc attach (clsact) ------------------
static int attach_bpf_clsact(const char *dev, enum bpf_tc_attach_point ap, int prog_fd, uint32_t prio, uint32_t handle) {
    struct bpf_tc_hook hook;
    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = if_nametoindex(dev);
    hook.attach_point = ap;

    if (hook.ifindex == 0) {
        fprintf(stderr, "WARN: if_nametoindex failed for %s\n", dev);
        return -1;
    }

    // Ensure clsact exists
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create(%s): %d\n", dev, err);
        return -1;
    }

    struct bpf_tc_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.prog_fd = prog_fd;
    opts.priority = prio;
    opts.handle = handle;

    // Replace attach if exists
    err = bpf_tc_attach(&hook, &opts);
    if (err == -EEXIST) {
        (void)bpf_tc_detach(&hook, &opts);
        err = bpf_tc_attach(&hook, &opts);
    }
    if (err) {
        fprintf(stderr, "bpf_tc_attach(%s): %d\n", dev, err);
        return -1;
    }
    return 0;
}

// ------------------ BPF map key/value ------------------
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

static int update_map_one(struct nl_ctx *nl,
                          int map_fd, const char *dev, const char *src_ip_str,
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
        .src_ip  = a.s_addr,
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

    // src_id from src_ip last octet
    uint32_t ip_host = ntohl(a.s_addr);
    int src_id = (int)(ip_host & 0xff);

    int recv_id = parse_recv_id_from_dev(dev);
    if (recv_id < 0) {
        fprintf(stderr, "WARN: cannot infer recv_id from dev '%s'. Skip tc apply.\n", dev);
        return 0;
    }
    if (src_id <= 0 || src_id > 254 || src_id == recv_id) {
        return 0;
    }

    (void)apply_tc_params_nl(nl, dev, recv_id, src_id, delay_us, jitter_us, rate_mbit);

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

    // open pinned prog fd (for clsact attach)
    int prog_fd = bpf_obj_get(pinned_prog);
    if (prog_fd < 0) {
        perror("bpf_obj_get(pinned_prog)");
        fprintf(stderr, "Failed to open pinned prog: %s\n", pinned_prog);
        return 1;
    }

    // netlink init
    struct nl_ctx nl;
    if (nl_ctx_init(&nl) != 0) {
        fprintf(stderr, "Failed to init libnl\n");
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

        if (ensure_tc_base_nl(&nl, dev) != 0) {
            fprintf(stderr, "TC base setup failed on %s\n", dev);
            continue;
        }

        // create per-src rules for all other nodes
        for (int k = 0; k < node_cnt; k++) {
            int src_id = nodes[k];
            if (src_id == recv_id) continue;
            (void)ensure_tc_link_nl(&nl, dev, recv_id, src_id);
        }

        enum bpf_tc_attach_point ap = BPF_TC_EGRESS;
        if (strcmp(dir, "ingress") == 0) ap = BPF_TC_INGRESS;

        // prio=1, handle=1 (arbitrary stable numbers)
        if (attach_bpf_clsact(dev, ap, prog_fd, 1, 1) != 0) {
            fprintf(stderr, "BPF attach failed on %s\n", dev);
            return 1;
        }

        printf("Dev ready: %s (recv_id=%d), bpf(pinned)=%s, map=%s\n", dev, recv_id, pinned_prog, pinned_map);
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
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);

        struct timeval timeout = {1, 0};
        int ret = select(s + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (g_stop) break;

        if (FD_ISSET(s, &readfds)) {
            char buf[65535];
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

                if (update_map_one(&nl, map_fd, dev, t_src, loss, delay_us, jitter_us, rate_mbit) == 0) {
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
    close(prog_fd);
    nl_ctx_destroy(&nl);

    printf("Agent exit.\n");
    return 0;
}
