#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <stdint.h>

// 定义SEC宏
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// 声明bpf辅助函数
static void *(*bpf_map_lookup_elem)(void *, void *) = (void *) BPF_FUNC_map_lookup_elem;

// 定义bpf_map_def结构体
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// 定义MAC地址长度
#define ETH_ALEN 6

// 定义一个map来存储要阻止的MAC地址
struct bpf_map_def SEC("maps") block_list = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = sizeof(uint8_t),
    .max_entries = 100,
};

SEC("classifier")
int mac_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // 检查是否有足够的数据来容纳以太网头部
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    uint8_t *src_mac = eth->h_source;
    
    // 检查源MAC地址是否在阻止列表中
    uint8_t *blocked = bpf_map_lookup_elem(&block_list, src_mac);
    
    // 如果找到匹配项，则丢弃数据包
    if (blocked) {
        return TC_ACT_SHOT;
    }
    
    // 默认情况下允许数据包通过
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";