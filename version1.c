#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// 定义一些基本类型，避免对复杂头文件的依赖
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

// iproute2/tc 兼容的 map 描述结构
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

// 声明辅助函数
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *) BPF_FUNC_map_lookup_elem;
static __u32 (*bpf_get_prandom_u32)(void) = (void *) BPF_FUNC_get_prandom_u32;

// map value：丢包率 + tc 分类用的 mark（classid）
struct link_val {
    __u32 drop_percent;  // 0..100
    __u32 classid;       // 写入 skb->mark，给 tc fw filter 用
};

// 现在仍然做"全局一条配置"：key=0
struct bpf_elf_map SEC("maps") drop_config = {
    .type       = 2, // BPF_MAP_TYPE_ARRAY
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct link_val),
    .max_elem   = 1,
    .flags      = 0,
};

SEC("classifier")
int drop_packets(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct link_val *cfg = bpf_map_lookup_elem(&drop_config, &key);
    if (!cfg) {
        return TC_ACT_OK;
    }

    // 1) 给后续 tc 使用：根据配置设置 mark（用于分类到不同 class/qdisc）
    //    如果 classid=0，也没事，相当于不分类（走 default）
    skb->mark = cfg->classid;

    // 2) 保留丢包逻辑
    if (cfg->drop_percent == 0) {
        return TC_ACT_OK;
    }
    if (cfg->drop_percent >= 100) {
        return TC_ACT_SHOT;
    }

    __u32 r = bpf_get_prandom_u32() % 100;
    if (r < cfg->drop_percent) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";