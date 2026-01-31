/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * eBPF程序用于在tc（traffic control）中实现基于拓扑的丢包功能
 * 该程序通过查找映射表来决定是否丢弃特定源IP的数据包
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

static void *(*bpf_map_lookup_elem)(void *, void *) = (void *)BPF_FUNC_map_lookup_elem;//BPF_FUNC_map_lookup_elem 是 eBPF 提供的内置函数，用于查找 BPF 哈希映射（map）中的元素。
static unsigned long long (*bpf_get_prandom_u32)(void) = (void *)BPF_FUNC_get_prandom_u32;//BPF_FUNC_get_prandom_u32 是 eBPF 内置的函数，用于生成一个伪随机数。

/**
 * @brief 将主机字节序转换为网络字节序的16位整数
 * 
 * @param x 输入的16位整数
 * @return 转换后的网络字节序整数
 */
static __u16 bpf_htons(__u16 x) { return __builtin_bswap16(x); }

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};

/**
 * @brief 拓扑键结构体，用于查找丢包参数
 * 
 * 包含接口索引和源IP地址作为键值
 */
struct topo_key {
    __u32 ifindex;     // 收端挂载点 ifindex
    __u32 src_ip;      // IPv4 源地址（网络序）
};

/**
 * @brief 拓扑参数结构体，定义了网络质量参数
 * 
 * 定义了丢包率、延迟、抖动和带宽等参数
 */
struct topo_params {
    __u32 loss_percent; // 0..100（由 eBPF 执行丢包）
    __u32 delay_us;     // 仅存储（由 tc 执行）
    __u32 jitter_us;    // 仅存储（由 tc 执行）
    __u32 rate_mbit;    // 仅存储（由 tc 执行）
};

// 定义BPF映射表，用于存储拓扑参数,映射表名称: topo_drop
struct bpf_map_def SEC("maps") topo_drop = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct topo_key),
    .value_size = sizeof(struct topo_params),
    .max_entries = 4096,
};

/**
 * @brief 数据包丢包处理函数
 * 
 * 该函数检查数据包的协议类型，然后根据源IP和接口索引查找对应的丢包参数，
 * 并根据丢包率随机决定是否丢弃数据包。
 * 
 * @param skb 指向socket缓冲区的指针
 * @return 返回TC_ACT_SHOT表示丢弃数据包，返回TC_ACT_PIPE表示继续处理
 */
SEC("classifier")
int drop_packets(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 解析以太网头部
    struct ethhdr *eth = data;
    // eth指向以太网头部的起始地址
    // eth + 1 指向的是紧接在以太网头部之后的内存地址
    // eth + 1 并不是尾地址，而是尾部之后的第一个字节的地址

    if ((void *)(eth + 1) > data_end) return TC_ACT_PIPE;           // 先不对非法包进行处理，返回TC_ACT_PIPE表示包继续进入下个流程

    // 检查是否为IPv4协议
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_PIPE;    

    // 解析IP头部
    struct iphdr *ip = (void *)eth + sizeof(*eth);//以太网头后面就是ip头
    if ((void *)(ip + 1) > data_end) return TC_ACT_PIPE;            

    // 构建用于查找拓扑参数的键
    struct topo_key key = {
        .ifindex = skb->ifindex,//ifindex是接口索引，例如网口veth1.0.1，但这里是他的索引，veth1.0.1 接口可能对应 ifindex = 1
        .src_ip  = ip->saddr,
    };

    // 根据键查找对应的拓扑参数
    struct topo_params *p = bpf_map_lookup_elem(&topo_drop, &key);
    if (!p) return TC_ACT_PIPE;                                     // 继续跑 flower

    // 获取丢包百分比并进行判断
    __u32 loss = p->loss_percent;
    if (loss == 0) return TC_ACT_PIPE;                              // 不丢包但继续
    if (loss >= 100) return TC_ACT_SHOT;

    // 生成随机数并比较以决定是否丢弃数据包
    __u32 r = (unsigned int)(bpf_get_prandom_u32() % 100);
    if (r < loss) return TC_ACT_SHOT;

    return TC_ACT_PIPE;                                             // 关键：继续后续分类/排队
}

char _license[] SEC("license") = "GPL";