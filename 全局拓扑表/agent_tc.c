// agent_oneclick_topo.c
// One-click: load test.o once (pin progs + pin maps) + attach to multiple devs + UDP update topo map
//
// Build:
//   gcc -O2 -Wall agent_oneclick_topo.c -o agent_topo -lbpf
//
// Run (example):
//   sudo ./agent_topo test.o classifier egress 9000 /sys/fs/bpf/lsdb veth1.0.3 veth2.0.3 veth3.0.3
//
// UDP payload (text):
//   "veth1.0.3 10 veth2.0.3 30 veth3.0.3 0"
// or with classid (only if map value_size == 8):
//   "veth1.0.3 10 1 veth2.0.3 30 2 veth3.0.3 0 0"
//
// Key is ifindex(u32). Value is u32 drop_percent or struct{u32 drop,u32 classid}.

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
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int signo) { (void)signo; g_stop = 1; }

static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    return rc;
}

// Return first regular entry path under dir (skip . and ..). Store into out.
// ... existing code ...
// Return first regular entry path under dir (skip . and ..). Store into out.
static int first_entry_path(const char *dir, char *out, size_t outlen) {
    DIR *d = opendir(dir);
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        // accept any (file pinned in bpffs looks like file)
        int ret = snprintf(out, outlen, "%s/%s", dir, de->d_name);
        if (ret < 0 || (size_t)ret >= outlen) {
            closedir(d);
            return -1; // Buffer too small or error
        }
        closedir(d);
        return 0;
    }
    closedir(d);
    return -1;
}
// ... existing code ...


// Ensure bpffs mounted and pin dirs exist
static int ensure_bpffs_and_dirs(const char *pin_root) {
    run_cmd("mount | grep -q \"/sys/fs/bpf type bpf\" || mount -t bpf bpf /sys/fs/bpf");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", pin_root);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(cmd, sizeof(cmd), "mkdir -p %s/progs %s/maps", pin_root, pin_root);
    if (run_cmd(cmd) != 0) return -1;

    return 0;
}

// Load object once, pin programs to pin_root/progs, pin maps to pin_root/maps
static int load_once_pin_all(const char *obj, const char *pin_root) {
    char cmd[1024];

    // Clear old pins (optional, keep minimal & deterministic)
    snprintf(cmd, sizeof(cmd), "rm -rf %s/progs/* %s/maps/* 2>/dev/null || true", pin_root, pin_root);
    run_cmd(cmd);

    // bpftool prog loadall <obj> <dir> pinmaps <maps_dir>
    // This pins all programs under <dir> and all maps under <maps_dir>.
    snprintf(cmd, sizeof(cmd),
             "bpftool prog loadall %s %s/progs pinmaps %s/maps",
             obj, pin_root, pin_root);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed: %s\n", cmd);
        return -1;
    }
    return 0;
}

// Attach pinned program to dev hook via tc
static int attach_pinned_to_dev(const char *dev, const char *dir, const char *pinned_prog_path) {
    char cmd[1024];

    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s clsact", dev);
    run_cmd(cmd);

    // replace to keep only one filter
    snprintf(cmd, sizeof(cmd), "tc filter replace dev %s %s bpf direct-action pinned %s",
             dev, dir, pinned_prog_path);

    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "Failed to attach on %s %s using pinned prog %s\n", dev, dir, pinned_prog_path);
        return -1;
    }
    return 0;
}

struct map_value8 {
    uint32_t drop_percent; // 0..100
    uint32_t classid;      // optional
};

static int clamp100(int v) {
    if (v < 0) return 0;
    if (v > 100) return 100;
    return v;
}

static int get_map_value_size(int map_fd, uint32_t *value_size, uint32_t *key_size) {
    struct bpf_map_info info;
    __u32 len = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (bpf_obj_get_info_by_fd(map_fd, &info, &len) != 0) return -1;
    *value_size = info.value_size;
    *key_size = info.key_size;
    return 0;
}

static int update_map_for_dev(int map_fd, uint32_t value_size, const char *dev, int drop, uint32_t classid, int has_classid) {
    unsigned ifindex = if_nametoindex(dev);
    if (ifindex == 0) {
        fprintf(stderr, "WARN: unknown dev '%s'\n", dev);
        return -1;
    }
    uint32_t key = (uint32_t)ifindex;

    drop = clamp100(drop);

    if (value_size == 4) {
        uint32_t val = (uint32_t)drop;
        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            perror("bpf_map_update_elem(value4)");
            return -1;
        }
        printf("Update: dev=%s ifindex=%u drop=%u\n", dev, ifindex, (unsigned)val);
        return 0;
    } else if (value_size == 8) {
        struct map_value8 val;
        val.drop_percent = (uint32_t)drop;
        // classid only changed if provided; otherwise keep 0 (simple minimal behavior)
        val.classid = has_classid ? classid : 0;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            perror("bpf_map_update_elem(value8)");
            return -1;
        }
        printf("Update: dev=%s ifindex=%u drop=%u classid=%u\n",
               dev, ifindex, val.drop_percent, val.classid);
        return 0;
    } else {
        fprintf(stderr, "Unsupported map value_size=%u (need 4 or 8)\n", value_size);
        return -1;
    }
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
            "Usage:\n"
            "  sudo %s <obj.o> <sec_name> <egress|ingress> <port> <pin_root> <dev1> [dev2 ...]\n"
            "Example:\n"
            "  sudo %s test.o classifier egress 9000 /sys/fs/bpf/lsdb veth1.0.3 veth2.0.3 veth3.0.3\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *obj      = argv[1];  // you want: test.o
    const char *sec      = argv[2];  // usually "classifier"
    const char *dir      = argv[3];  // "egress" or "ingress"
    int port             = atoi(argv[4]);
    const char *pin_root = argv[5];

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // 1) bpffs + dirs
    if (ensure_bpffs_and_dirs(pin_root) != 0) {
        fprintf(stderr, "Failed to setup bpffs/dirs\n");
        return 1;
    }

    // 2) load once + pin all progs/maps
    if (load_once_pin_all(obj, pin_root) != 0) {
        fprintf(stderr, "Failed to load/pin %s\n", obj);
        return 1;
    }

    // 3) determine pinned program path from sec name
    char pinned_prog[512];
    snprintf(pinned_prog, sizeof(pinned_prog), "%s/progs/%s", pin_root, sec);

    // 4) find first pinned map path (assume only one map in obj for minimal implementation)
    char maps_dir[512], pinned_map[512];
    snprintf(maps_dir, sizeof(maps_dir), "%s/maps", pin_root);
    if (first_entry_path(maps_dir, pinned_map, sizeof(pinned_map)) != 0) {
        fprintf(stderr, "No pinned maps found under %s (does your obj define a map?)\n", maps_dir);
        return 1;
    }

    // 5) attach to each dev
    for (int i = 6; i < argc; i++) {
        const char *dev = argv[i];
        if (attach_pinned_to_dev(dev, dir, pinned_prog) != 0) {
            return 1;
        }
        printf("Attached pinned prog %s on %s %s\n", pinned_prog, dev, dir);
    }

    // 6) open pinned map + check sizes
    int map_fd = bpf_obj_get(pinned_map);
    if (map_fd < 0) {
        perror("bpf_obj_get(pinned_map)");
        fprintf(stderr, "Failed to open pinned map: %s\n", pinned_map);
        return 1;
    }

    uint32_t value_size = 0, key_size = 0;
    if (get_map_value_size(map_fd, &value_size, &key_size) != 0) {
        perror("bpf_obj_get_info_by_fd(map)");
        return 1;
    }
    if (key_size != 4) {
        fprintf(stderr, "WARN: map key_size=%u (expected 4 for ifindex u32)\n", key_size);
    }

    printf("Pinned map: %s (key_size=%u, value_size=%u)\n", pinned_map, key_size, value_size);
    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Text payload:\n");
    printf("  value_size=4 :  \"dev drop\" pairs\n");
    printf("  value_size=8 :  \"dev drop classid\" triples (classid optional)\n");
    printf("Example:\n");
    printf("  echo -n \"veth1.0.3 10 veth2.0.3 30 veth3.0.3 0\" | nc -u -w1 127.0.0.1 %d\n", port);

    // 7) UDP server
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
        char buf[2048];
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);

        ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        buf[n] = '\0';

        // Parse tokens
        // value_size=4 => pairs: dev drop
        // value_size=8 => triples: dev drop classid (classid optional; if missing -> 0)
        char *save = NULL;
        char *tok = strtok_r(buf, " \t\r\n", &save);
        int updates = 0;

        while (tok) {
            char dev[IF_NAMESIZE];
            snprintf(dev, sizeof(dev), "%s", tok);

            char *tok_drop = strtok_r(NULL, " \t\r\n", &save);
            if (!tok_drop) break;
            int drop = atoi(tok_drop);

            uint32_t classid = 0;
            int has_classid = 0;

            if (value_size == 8) {
                // peek next token: if it looks like a number, treat as classid; else leave 0
                char *tok_c = strtok_r(NULL, " \t\r\n", &save);
                if (tok_c) {
                    // If next token starts with digit, accept as classid
                    if ((tok_c[0] >= '0' && tok_c[0] <= '9')) {
                        classid = (uint32_t)strtoul(tok_c, NULL, 10);
                        has_classid = 1;
                    } else {
                        // not a number => interpret as next dev name: push back is hard with strtok.
                        // minimal behavior: ignore (user should send triples in this mode).
                        fprintf(stderr, "WARN: value_size=8 expects triples: dev drop classid\n");
                    }
                } else {
                    // missing classid => leave 0
                }
            }

            if (update_map_for_dev(map_fd, value_size, dev, drop, classid, has_classid) == 0) {
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
