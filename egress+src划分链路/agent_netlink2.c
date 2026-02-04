// agent_expend_nl_opt.c
// Optimized for burst updates (e.g., 100 nodes -> 9900 directional links)
//
// Changes vs your agent_expend_nl.c:
// 1) recvmsg() + MSG_TRUNC detection (avoid “half updates”)
// 2) Bigger SO_RCVBUF + optional SO_RXQ_OVFL drop counter
// 3) RX thread only parses/enqueues, worker thread does map+tc work
// 4) Cache dev -> {ifindex, recv_id, rtnl_link*}
// 5) u32 offset for "protocol ip": offsetof(struct iphdr, saddr) (from IP header start)
// 6) Ensure-on-demand for per-(dev,src_id) tc rules (avoid missing rules)
//
// Build:
//   gcc -O2 -Wall agent_expend_nl_opt.c -o agent_expend_nl_opt 
//       -lbpf -lnl-3 -lnl-route-3 -lpthread
//
// Run:
//   sudo ./agent_expend_nl_opt ebpf.o classifier egress 9000 /sys/fs/bpf/lsdb 
//        $(ls /sys/class/net | grep -E '^veth[0-9a-f]+\.0\.1$' | sort -V)

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
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
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

static void setup_signal(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

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
    return (uint64_t)mbit * 1000000ULL / 8ULL;
}

static uint32_t clamp100_u32(uint32_t v) { return (v > 100) ? 100 : v; }

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

// ------------------ TC via libnl ------------------
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

    err = rtnl_htb_set_defcls(q, TC_HANDLE(1, 0x10));
    if (err < 0) {
        fprintf(stderr, "rtnl_htb_set_defcls: %s\n", nl_geterror(err));
        rtnl_qdisc_put(q);
        return -1;
    }

    rtnl_htb_set_rate2quantum(q, 1);

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

    // keep your approach: some libnl builds expose only 32-bit setters
    if (rate_Bps) (void)rtnl_htb_set_rate(cl, (uint32_t)rate_Bps);
    if (ceil_Bps) (void)rtnl_htb_set_ceil(cl, (uint32_t)ceil_Bps);

    if (burst_bytes) (void)rtnl_htb_set_rbuffer(cl, burst_bytes);
    if (cburst_bytes) (void)rtnl_htb_set_cbuffer(cl, cburst_bytes);

    err = rtnl_class_add(ctx->sk, cl, NLM_F_CREATE);
    if (err < 0) {
        // In burst mode, treat duplicates as non-fatal
        // fprintf(stderr, "rtnl_class_add(htb): %s\n", nl_geterror(err));
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

    rtnl_netem_set_delay(q, delay_us);
    rtnl_netem_set_jitter(q, jitter_us);

    (void)rtnl_qdisc_delete(ctx->sk, q);
    err = rtnl_qdisc_add(ctx->sk, q, NLM_F_CREATE);
    if (err < 0) {
        // fprintf(stderr, "rtnl_qdisc_add(netem): %s\n", nl_geterror(err));
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

    // protocol ip: offset from start of IP header
    int off = (int)offsetof(struct iphdr, saddr);
    rtnl_u32_add_key(cls, src_ip_be, 0xffffffffu, off, 0);

    rtnl_u32_set_classid(cls, classid);
    rtnl_u32_set_cls_terminal(cls);

    err = rtnl_cls_add(ctx->sk, cls, NLM_F_CREATE);
    (void)err; // ignore duplicates

    rtnl_cls_put(cls);
    return 0;
}

static int ensure_tc_base_link(struct nl_ctx *ctx, struct rtnl_link *link) {
    if (tc_qdisc_replace_htb_root(ctx, link) != 0) return -1;

    uint64_t rate = mbit_to_bytes_per_sec(1000);
    if (tc_class_replace_htb(ctx, link, 1, 0, 1, 0x10, rate, rate, 25000, 25000, 0) != 0) return -1;

    if (tc_qdisc_replace_netem(ctx, link, 1, 0x10, 0x10, 0, 0) != 0) return -1;
    return 0;
}

static int ensure_tc_link_rules(struct nl_ctx *ctx, struct rtnl_link *link, int recv_id, int src_id) {
    unsigned minor = make_minor_u16(recv_id, src_id);
    uint64_t rate = mbit_to_bytes_per_sec(1000);

    (void)tc_class_replace_htb(ctx, link, 1, 0, 1, minor, rate, rate, 25000, 25000, 0);
    (void)tc_qdisc_replace_netem(ctx, link, 1, minor, minor, 0, 0);

    // u32 filter: match src ip 10.0.0.<src_id> -> classid 1:<minor>
    struct in_addr a;
    char ipbuf[32];
    snprintf(ipbuf, sizeof(ipbuf), "10.0.0.%d", src_id);
    if (inet_pton(AF_INET, ipbuf, &a) == 1) {
        (void)tc_filter_add_u32_srcip_to_class(ctx, link, 10, a.s_addr, TC_HANDLE(1, minor));
    }
    return 0;
}

static int apply_tc_params_link(struct nl_ctx *ctx, struct rtnl_link *link,
                                int recv_id, int src_id,
                                uint32_t delay_us, uint32_t jitter_us, uint32_t rate_mbit) {
    if (rate_mbit == 0) rate_mbit = 1;
    unsigned minor = make_minor_u16(recv_id, src_id);
    uint64_t rate = mbit_to_bytes_per_sec(rate_mbit);

    int rc1 = tc_class_replace_htb(ctx, link, 1, 0, 1, minor, rate, rate, 25000, 25000, 0);
    int rc2 = tc_qdisc_replace_netem(ctx, link, 1, minor, minor, (int)delay_us, (int)jitter_us);
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

// ------------------ dev cache ------------------
struct dev_state {
    char dev[IF_NAMESIZE];
    uint32_t ifindex;
    int recv_id;
    struct rtnl_link *link; // held ref
};

static int dev_state_find(struct dev_state *ds, int n, const char *dev) {
    for (int i = 0; i < n; i++) {
        if (strncmp(ds[i].dev, dev, IF_NAMESIZE) == 0) return i;
    }
    return -1;
}

// ------------------ bounded queue RX -> worker ------------------
struct upd_item {
    uint16_t dev_idx;
    uint16_t src_id;
    uint32_t src_ip_be;
    uint32_t loss;
    uint32_t delay_us;
    uint32_t jitter_us;
    uint32_t rate_mbit;
};

#ifndef UPD_Q_CAP
#define UPD_Q_CAP 32768
#endif

struct upd_queue {
    struct upd_item buf[UPD_Q_CAP];
    uint32_t head, tail, count;
    uint64_t dropped;
    pthread_mutex_t mu;
    pthread_cond_t  cv_nonempty;
};

static void updq_init(struct upd_queue *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->cv_nonempty, NULL);
}

static void updq_destroy(struct upd_queue *q) {
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->cv_nonempty);
}

static void updq_push(struct upd_queue *q, const struct upd_item *it) {
    pthread_mutex_lock(&q->mu);
    if (q->count == UPD_Q_CAP) {
        q->dropped++;
        pthread_mutex_unlock(&q->mu);
        return;
    }
    q->buf[q->tail] = *it;
    q->tail = (q->tail + 1) % UPD_Q_CAP;
    q->count++;
    pthread_cond_signal(&q->cv_nonempty);
    pthread_mutex_unlock(&q->mu);
}

static int updq_pop(struct upd_queue *q, struct upd_item *out) {
    pthread_mutex_lock(&q->mu);
    while (q->count == 0 && !g_stop) {
        pthread_cond_wait(&q->cv_nonempty, &q->mu);
    }
    if (q->count == 0 && g_stop) {
        pthread_mutex_unlock(&q->mu);
        return 0;
    }
    *out = q->buf[q->head];
    q->head = (q->head + 1) % UPD_Q_CAP;
    q->count--;
    pthread_mutex_unlock(&q->mu);
    return 1;
}

// ------------------ worker context ------------------
struct worker_ctx {
    int map_fd;
    struct nl_ctx *nl;
    struct dev_state *devs;
    int dev_cnt;
    struct upd_queue *q;

    // ensured rules: ensured[dev_idx][src_id] (src_id 0..255)
    uint8_t *ensured; // size = dev_cnt * 256

    // stats
    uint64_t map_ok, map_fail;
    uint64_t tc_ok, tc_fail;
    uint64_t ensure_cnt;
};

static inline uint8_t *ensured_cell(struct worker_ctx *w, int dev_idx, int src_id) {
    return &w->ensured[(size_t)dev_idx * 256u + (size_t)(src_id & 0xff)];
}

static void *worker_thread(void *arg) {
    struct worker_ctx *w = (struct worker_ctx *)arg;
    struct upd_item it;

    while (!g_stop) {
        if (!updq_pop(w->q, &it)) break;
        if (it.dev_idx >= (uint16_t)w->dev_cnt) continue;

        struct dev_state *ds = &w->devs[it.dev_idx];

        // ---- map update (fast) ----
        struct topo_key key = {
            .ifindex = ds->ifindex,
            .src_ip  = it.src_ip_be,
        };
        struct topo_params val = {
            .loss_percent = clamp100_u32(it.loss),
            .delay_us = it.delay_us,
            .jitter_us = it.jitter_us,
            .rate_mbit = it.rate_mbit,
        };

        if (bpf_map_update_elem(w->map_fd, &key, &val, BPF_ANY) != 0) {
            w->map_fail++;
        } else {
            w->map_ok++;
        }

        // ---- tc apply ----
        int recv_id = ds->recv_id;
        int src_id  = (int)it.src_id;

        if (recv_id > 0 && src_id > 0 && src_id <= 254 && src_id != recv_id) {
            // ensure rules once per (dev,src)
            uint8_t *cell = ensured_cell(w, (int)it.dev_idx, src_id);
            if (*cell == 0) {
                (void)ensure_tc_link_rules(w->nl, ds->link, recv_id, src_id);
                *cell = 1;
                w->ensure_cnt++;
            }

            if (apply_tc_params_link(w->nl, ds->link, recv_id, src_id,
                                     it.delay_us, it.jitter_us, it.rate_mbit) == 0) {
                w->tc_ok++;
            } else {
                w->tc_fail++;
            }
        }
    }
    return NULL;
}

// ------------------ RX thread context ------------------
struct rx_ctx {
    int sock;
    struct dev_state *devs;
    int dev_cnt;
    struct upd_queue *q;

    int enable_rxq_ovfl;
    uint32_t last_rxq_drops;
};

static uint32_t parse_src_id_from_be(uint32_t src_ip_be) {
    uint32_t h = ntohl(src_ip_be);
    return (uint32_t)(h & 0xff);
}

static void *rx_thread(void *arg) {
    struct rx_ctx *r = (struct rx_ctx *)arg;

    static char buf[65536];

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);

        struct iovec iov = {
            .iov_base = buf,
            .iov_len  = sizeof(buf) - 1,
        };

        char cbuf[256];
        memset(cbuf, 0, sizeof(cbuf));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &peer;
        msg.msg_namelen = peerlen;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        ssize_t n = recvmsg(r->sock, &msg, 0);
        if (n < 0) {
            if (errno == EINTR) continue;            // 被信号打断
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // 超时
            perror("recvmsg");
            continue;
        }


        // detect truncation
        if (msg.msg_flags & MSG_TRUNC) {
            fprintf(stderr, "WARN: UDP datagram truncated -> drop this datagram\n");
            continue;
        }

        // read kernel UDP drop counter (if enabled)
        if (r->enable_rxq_ovfl) {
            for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
                    uint32_t drops = *(uint32_t *)CMSG_DATA(cmsg);
                    if (drops != r->last_rxq_drops) {
                        fprintf(stderr, "WARN: kernel UDP drops increased: %u -> %u\n",
                                r->last_rxq_drops, drops);
                        r->last_rxq_drops = drops;
                    }
                }
            }
        }

        buf[n] = '\0';

        char *save = NULL;
        char *tok = strtok_r(buf, " \t\r\n", &save);

        int enq = 0, bad = 0;
        while (tok) {
            char dev[IF_NAMESIZE];
            snprintf(dev, sizeof(dev), "%s", tok);

            char *t_src  = strtok_r(NULL, " \t\r\n", &save);
            char *t_loss = strtok_r(NULL, " \t\r\n", &save);
            char *t_dly  = strtok_r(NULL, " \t\r\n", &save);
            char *t_jit  = strtok_r(NULL, " \t\r\n", &save);
            char *t_rate = strtok_r(NULL, " \t\r\n", &save);

            if (!t_src || !t_loss || !t_dly || !t_jit || !t_rate) {
                bad++;
                break; // incomplete tail
            }

            if (ends_with_p(dev)) { bad++; tok = strtok_r(NULL, " \t\r\n", &save); continue; }

            int di = dev_state_find(r->devs, r->dev_cnt, dev);
            if (di < 0) { bad++; tok = strtok_r(NULL, " \t\r\n", &save); continue; }

            struct in_addr a;
            if (inet_pton(AF_INET, t_src, &a) != 1) { bad++; tok = strtok_r(NULL, " \t\r\n", &save); continue; }

            struct upd_item it;
            memset(&it, 0, sizeof(it));
            it.dev_idx   = (uint16_t)di;
            it.src_ip_be = a.s_addr;
            it.src_id    = (uint16_t)parse_src_id_from_be(a.s_addr);

            it.loss      = (uint32_t)strtoul(t_loss, NULL, 10);
            it.delay_us  = (uint32_t)strtoul(t_dly,  NULL, 10);
            it.jitter_us = (uint32_t)strtoul(t_jit,  NULL, 10);
            it.rate_mbit = (uint32_t)strtoul(t_rate, NULL, 10);

            updq_push(r->q, &it);
            enq++;

            tok = strtok_r(NULL, " \t\r\n", &save);
        }

        char ipbuf[64];
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        printf("From %s:%u bytes=%zd enqueued=%d bad=%d q_drop=%llu\n",
               ipbuf, ntohs(peer.sin_port), n, enq, bad,
               (unsigned long long)r->q->dropped);
        fflush(stdout);
    }

    return NULL;
}

// ------------------ main ------------------
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

    // signal(SIGINT, on_sigint);
    // signal(SIGTERM, on_sigint);
    setup_signal();

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

    int prog_fd = bpf_obj_get(pinned_prog);
    if (prog_fd < 0) {
        perror("bpf_obj_get(pinned_prog)");
        fprintf(stderr, "Failed to open pinned prog: %s\n", pinned_prog);
        return 1;
    }

    struct nl_ctx nl;
    if (nl_ctx_init(&nl) != 0) {
        fprintf(stderr, "Failed to init libnl\n");
        return 1;
    }

    // ---- build dev cache from argv list ----
    int max_devs = argc - 6;
    struct dev_state *devs = calloc((size_t)max_devs, sizeof(*devs));
    if (!devs) {
        fprintf(stderr, "OOM devs\n");
        return 1;
    }

    int dev_cnt = 0;
    for (int i = 6; i < argc; i++) {
        const char *dev = argv[i];

        int recv_id = parse_recv_id_from_dev(dev);
        if (recv_id < 0) {
            fprintf(stderr, "Skip dev '%s' (not host-side veth{hex}.0.{sid})\n", dev);
            continue;
        }

        struct rtnl_link *link = rtnl_link_get_by_name(nl.link_cache, dev);
        if (!link) {
            fprintf(stderr, "WARN: link not found: %s\n", dev);
            continue;
        }

        uint32_t ifindex = (uint32_t)rtnl_link_get_ifindex(link);
        if (ifindex == 0) {
            fprintf(stderr, "WARN: ifindex=0 for %s\n", dev);
            rtnl_link_put(link);
            continue;
        }

        snprintf(devs[dev_cnt].dev, sizeof(devs[dev_cnt].dev), "%s", dev);
        devs[dev_cnt].ifindex = ifindex;
        devs[dev_cnt].recv_id = recv_id;
        devs[dev_cnt].link = link; // keep ref
        dev_cnt++;
    }

    if (dev_cnt <= 0) {
        fprintf(stderr, "No valid host-side veth devs found in args.\n");
        return 1;
    }

    enum bpf_tc_attach_point ap = BPF_TC_EGRESS;
    if (strcmp(dir, "ingress") == 0) ap = BPF_TC_INGRESS;

    // ---- setup base tc + attach bpf for each dev ----
    for (int i = 0; i < dev_cnt; i++) {
        const char *dev = devs[i].dev;

        if (ensure_tc_base_link(&nl, devs[i].link) != 0) {
            fprintf(stderr, "TC base setup failed on %s\n", dev);
            continue;
        }

        if (attach_bpf_clsact(dev, ap, prog_fd, 1, 1) != 0) {
            fprintf(stderr, "BPF attach failed on %s\n", dev);
            return 1;
        }

        printf("Dev ready: %s (recv_id=%d ifindex=%u), bpf=%s, map=%s\n",
               dev, devs[i].recv_id, devs[i].ifindex, pinned_prog, pinned_map);
    }

    printf("Pinned map: %s (key_size=%u, value_size=%u)\n", pinned_map, key_size, value_size);
    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Payload groups: dev src_ip loss delay_us jitter_us rate_mbit\n");

    // ---- UDP socket ----
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    // big receive buffer
    int rcvbuf = 16 * 1024 * 1024; // 16MB
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        perror("setsockopt(SO_RCVBUF)");
    }
    socklen_t optlen = sizeof(rcvbuf);
    if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) == 0) {
        printf("SO_RCVBUF=%d\n", rcvbuf);
    }

    // enable RXQ overflow counter (Linux)
    int enable_rxq_ovfl = 1;
    if (setsockopt(s, SOL_SOCKET, SO_RXQ_OVFL, &enable_rxq_ovfl, sizeof(enable_rxq_ovfl)) != 0) {
        enable_rxq_ovfl = 0; // not fatal
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    // ---- init queue + worker ensured table ----
    struct upd_queue q;
    updq_init(&q);

    struct worker_ctx w;
    memset(&w, 0, sizeof(w));
    w.map_fd = map_fd;
    w.nl = &nl;
    w.devs = devs;
    w.dev_cnt = dev_cnt;
    w.q = &q;

    w.ensured = calloc((size_t)dev_cnt * 256u, 1);
    if (!w.ensured) {
        fprintf(stderr, "OOM ensured\n");
        return 1;
    }

    struct rx_ctx r;
    memset(&r, 0, sizeof(r));
    r.sock = s;
    r.devs = devs;
    r.dev_cnt = dev_cnt;
    r.q = &q;
    r.enable_rxq_ovfl = enable_rxq_ovfl;
    r.last_rxq_drops = 0;

    pthread_t th_rx, th_worker;
    if (pthread_create(&th_worker, NULL, worker_thread, &w) != 0) {
        fprintf(stderr, "pthread_create(worker) failed\n");
        return 1;
    }
    if (pthread_create(&th_rx, NULL, rx_thread, &r) != 0) {
        fprintf(stderr, "pthread_create(rx) failed\n");
        g_stop = 1;
        pthread_cond_broadcast(&q.cv_nonempty);
        pthread_join(th_worker, NULL);
        return 1;
    }

    // main thread: periodic stats
    while (!g_stop) {
        sleep(1);
        static int tick = 0;
        tick++;
        if (tick % 3 == 0) {
            printf("[STAT] map_ok=%llu map_fail=%llu tc_ok=%llu tc_fail=%llu ensure=%llu q_drop=%llu\n",
                   (unsigned long long)w.map_ok,
                   (unsigned long long)w.map_fail,
                   (unsigned long long)w.tc_ok,
                   (unsigned long long)w.tc_fail,
                   (unsigned long long)w.ensure_cnt,
                   (unsigned long long)q.dropped);
            fflush(stdout);
        }
    }

    // shutdown
    pthread_cond_broadcast(&q.cv_nonempty);
    pthread_join(th_rx, NULL);
    pthread_join(th_worker, NULL);

    close(s);
    close(map_fd);
    close(prog_fd);

    updq_destroy(&q);
    free(w.ensured);

    for (int i = 0; i < dev_cnt; i++) {
        if (devs[i].link) rtnl_link_put(devs[i].link);
    }
    free(devs);

    nl_ctx_destroy(&nl);

    printf("Agent exit.\n");
    return 0;
}
