// agent.c: one-click attach tc eBPF + pin map + UDP update map
// Build: gcc -O2 -Wall agent.c -o agent
// Run:   sudo ./agent veth1.0.1 version.o classifier egress 9000 /sys/fs/bpf/lsdb/drop_config

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo) { (void)signo; g_stop = 1; }

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_obj_get_path(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update(int map_fd, const void *key, const void *value, uint64_t flags) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key    = (uint64_t)(uintptr_t)key;
    attr.value  = (uint64_t)(uintptr_t)value;
    attr.flags  = flags;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

// Run a shell command (simple). Return system() exit code.
static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    return rc;
}

// Read command output via popen into buf.
static int read_cmd(const char *cmd, char *buf, size_t buflen) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    size_t n = fread(buf, 1, buflen - 1, fp);
    buf[n] = '\0';
    int rc = pclose(fp);
    (void)rc;
    return 0;
}

// Parse last occurrence of " id N" in tc output.
static int parse_last_prog_id(const char *tc_out) {
    const char *p = tc_out;
    int last = -1;
    while ((p = strstr(p, " id ")) != NULL) {
        int id = -1;
        if (sscanf(p, " id %d", &id) == 1) last = id;
        p += 4;
    }
    return last;
}

// Parse first map id from "map_ids X" or "map_ids X,Y"
static int parse_first_map_id(const char *prog_out) {
    const char *p = strstr(prog_out, "map_ids ");
    if (!p) return -1;
    p += strlen("map_ids ");
    int id = -1;
    if (sscanf(p, "%d", &id) == 1) return id;
    return -1;
}

// One-click: clsact + attach bpf + find prog id + find map id + pin map
static int one_click_attach_and_pin(const char *dev,
                                    const char *obj,
                                    const char *sec,
                                    const char *dir,        // "egress" or "ingress"
                                    const char *pin_path) {
    char cmd[1024];
    char out[8192];

    // 0) bpffs mount + pin dir
    run_cmd("mount | grep -q \"/sys/fs/bpf type bpf\" || mount -t bpf bpf /sys/fs/bpf");
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", "/sys/fs/bpf/lsdb");
    run_cmd(cmd);

    // 1) ensure clsact
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact 2>/dev/null || true", dev);
    run_cmd(cmd);

    // 2) remove old filter on this hook (keep only one)
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s %s 2>/dev/null || true", dev, dir);
    run_cmd(cmd);

    // 3) attach eBPF
    snprintf(cmd, sizeof(cmd),
             "tc filter add dev %s %s bpf direct-action obj %s sec %s",
             dev, dir, obj, sec);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to attach bpf: %s\n", cmd);
        return -1;
    }

    // 4) find prog id from tc
    snprintf(cmd, sizeof(cmd), "tc -s filter show dev %s %s", dev, dir);
    if (read_cmd(cmd, out, sizeof(out)) != 0) {
        fprintf(stderr, "Failed to read tc output\n");
        return -1;
    }
    int prog_id = parse_last_prog_id(out);
    if (prog_id < 0) {
        fprintf(stderr, "Failed to parse prog id from:\n%s\n", out);
        return -1;
    }

    // 5) find map id from bpftool prog show
    snprintf(cmd, sizeof(cmd), "bpftool prog show id %d", prog_id);
    if (read_cmd(cmd, out, sizeof(out)) != 0) {
        fprintf(stderr, "Failed to read bpftool prog output\n");
        return -1;
    }
    int map_id = parse_first_map_id(out);
    if (map_id < 0) {
        fprintf(stderr, "Failed to parse map id from:\n%s\n", out);
        return -1;
    }

    // 6) pin map to stable path
    snprintf(cmd, sizeof(cmd), "rm -f %s", pin_path);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "bpftool map pin id %d %s", map_id, pin_path);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to pin map id %d to %s\n", map_id, pin_path);
        return -1;
    }

    printf("Attached BPF on %s %s: prog_id=%d, map_id=%d, pinned=%s\n",
           dev, dir, prog_id, map_id, pin_path);
    return 0;
}

struct map_value {
    uint32_t drop_percent; // 0..100
    uint32_t classid;      // mark/classid
};

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
            "Usage:\n"
            "  sudo %s <dev> <obj.o> <sec> <egress|ingress> <port> <pin_path>\n"
            "Example:\n"
            "  sudo %s veth1.0.1 version.o classifier egress 9000 /sys/fs/bpf/lsdb/drop_config\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *dev      = argv[1];
    const char *obj      = argv[2];
    const char *sec      = argv[3];
    const char *dir      = argv[4];
    int port             = atoi(argv[5]);
    const char *pin_path = argv[6];

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // 1) one-click attach + pin
    if (one_click_attach_and_pin(dev, obj, sec, dir, pin_path) != 0) {
        return 1;
    }

    // 2) open pinned map
    int map_fd = bpf_obj_get_path(pin_path);
    if (map_fd < 0) {
        perror("bpf_obj_get(pin_path)");
        return 1;
    }

    // 3) UDP server
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

    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Pinned map: %s (array key=0, value={drop_percent,u32; classid,u32})\n", pin_path);
    printf("Payload:\n");
    printf("  8 bytes: !II => drop_percent(0..100), classid(u32)\n");
    printf("  4 bytes: !I  => drop_percent only (classid unchanged)\n");

    uint32_t key = 0;
    struct map_value cur = {.drop_percent = 0, .classid = 0};

    while (!g_stop) {
        uint8_t buf[64];
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);

        ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }

        if (n != 4 && n != 8) {
            // ignore unknown payload
            continue;
        }

        uint32_t net_a = 0, net_b = 0;
        memcpy(&net_a, buf, 4);
        uint32_t drop = ntohl(net_a);
        if (drop > 100) drop = 100;

        cur.drop_percent = drop;

        if (n == 8) {
            memcpy(&net_b, buf + 4, 4);
            uint32_t classid = ntohl(net_b);
            cur.classid = classid; // allow 0
        }

        if (bpf_map_update(map_fd, &key, &cur, BPF_ANY) != 0) {
            perror("bpf_map_update_elem");
            continue;
        }

        char ipbuf[64];
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        printf("Update from %s:%u -> drop=%u, classid=%u\n",
               ipbuf, ntohs(peer.sin_port), cur.drop_percent, cur.classid);
        fflush(stdout);
    }

    close(s);
    close(map_fd);
    printf("Agent exit.\n");
    return 0;
}
