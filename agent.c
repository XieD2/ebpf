// agent.c: UDP server -> update pinned BPF map (drop_config[0] = drop_percent)
//
// UDP payload: 4-byte uint32 in network byte order (big-endian), value 0..100

#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

//退出控制
static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

int main(int argc, char **argv) {
    const char *map_path = "/sys/fs/bpf/lsdb/drop_config";//默认参数
    int port = 9000;//默认参数

    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) map_path = argv[2];

    // Open pinned map
    int map_fd = bpf_obj_get(map_path);//根据路径打开对象，并返回一个fd
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned map: %s\n", map_path);
        perror("bpf_obj_get");
        return 1;
    }

    // Create UDP server socket
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(s);
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    printf("UDP agent listening on 0.0.0.0:%d\n", port);
    printf("Updating pinned map: %s (key=0)\n", map_path);
    printf("Payload: 4-byte uint32 (network order), value 0..100\n");

    while (!g_stop) {
        uint32_t net_drop = 0;
        struct sockaddr_in peer;//对端信息，网络字节序，大端
        socklen_t peerlen = sizeof(peer);//缓冲区
        ssize_t n = recvfrom(s, &net_drop, sizeof(net_drop), 0,
                             (struct sockaddr *)&peer, &peerlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        if (n != (ssize_t)sizeof(net_drop)) {
            // Ignore unexpected payload size
            continue;
        }

        uint32_t drop = ntohl(net_drop);
        if (drop > 100) drop = 100;

        uint32_t key = 0;
        uint32_t val = drop;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {//写入bpf map
            perror("bpf_map_update_elem");
            continue;
        }

        char ipbuf[64];
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        printf("Update from %s:%u -> drop_percent=%u\n",
               ipbuf, ntohs(peer.sin_port), drop);
        fflush(stdout);
    }

    printf("Exiting...\n");
    close(s);
    close(map_fd);
    return 0;
}
