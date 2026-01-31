#include <linux/bpf.h>
#include <linux/pkt_cls.h>

// 定义SEC宏
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// 声明bpf辅助函数
static void *(*bpf_map_lookup_elem)(void *, void *) = (void *) BPF_FUNC_map_lookup_elem;
static unsigned long long (*bpf_get_prandom_u32)(void) = (void *) BPF_FUNC_get_prandom_u32;

// 定义bpf_map_def结构体
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

// 定义丢包概率(0-100)
struct bpf_map_def SEC("maps") drop_config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned int),
    .max_entries = 1,
};

SEC("classifier")
int drop_packets(struct __sk_buff *skb)
{
    unsigned int key = 0;
    unsigned int *drop_percent = bpf_map_lookup_elem(&drop_config, &key);
    
    // 如果没有配置或配置为0，则不丢包
    if (!drop_percent || *drop_percent == 0) {
        return TC_ACT_OK;
    }
    
    // 生成随机数并判断是否丢包
    unsigned int rand_val = bpf_get_prandom_u32() % 100;
    if (rand_val < *drop_percent) {
        return TC_ACT_SHOT;  // 丢包
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";