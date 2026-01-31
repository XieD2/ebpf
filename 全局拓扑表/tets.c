#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

static void *(*bpf_map_lookup_elem)(void *, void *) = (void *) BPF_FUNC_map_lookup_elem;
static unsigned long long (*bpf_get_prandom_u32)(void) = (void *) BPF_FUNC_get_prandom_u32;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

struct topo_params {
    __u32 loss_percent; // 0..100
    __u32 delay_us;     // store only (applied by tc)
    __u32 jitter_us;    // store only (applied by tc)
    __u32 rate_mbit;    // store only (applied by tc)
};

// key = ifindex(u32), value = topo_params(16 bytes)
struct bpf_map_def SEC("maps") topo_drop = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct topo_params),
    .max_entries = 1024,
};

SEC("classifier")
int drop_packets(struct __sk_buff *skb)
{
    __u32 key = skb->ifindex;
    struct topo_params *p = bpf_map_lookup_elem(&topo_drop, &key);
    if (!p) return TC_ACT_OK;

    __u32 loss = p->loss_percent;
    if (loss == 0) return TC_ACT_OK;
    if (loss >= 100) return TC_ACT_SHOT;

    __u32 rand_val = (unsigned int)(bpf_get_prandom_u32() % 100);
    if (rand_val < loss) return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
