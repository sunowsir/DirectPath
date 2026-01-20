/*
 * File     : tc_direct_accel.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-20 21:39:23
*/


#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 直连流量标记 */
#define DIRECT_MARK 0x88

/* * 注意：不再手动定义 struct bpf_lpm_trie_key，直接使用系统定义的：
 * struct bpf_lpm_trie_key {
 * __u32 prefixlen;
 * __u8  data[0];
 * };
 */

/* 定义 Map 时，key 的大小需要包含 prefixlen(4) + IPv4(4) = 8 字节 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(key_size, 8); 
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map SEC(".maps");

SEC("classifier")
int tc_direct_accel(struct __sk_buff *skb) {
    // 1. 协议解析（仅处理 IPv4）
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    // 2. 构造 LPM 查找 Key
    // 必须严格匹配内核定义的 8 字节结构：4字节前缀 + 4字节IP
    struct {
        __u32 prefixlen;
        __u32 ipv4;
    } key;

    key.prefixlen = 32;
    key.ipv4 = iph->daddr;

    // 3. 查找 Map
    __u32 *is_direct = bpf_map_lookup_elem(&direct_ip_map, &key);
    if (is_direct) {
        // 命中直连名单，打上加速标记
        skb->mark = DIRECT_MARK;
        // 打印调试信息 (正式使用时可注释)
        bpf_trace_printk("Direct path: IP %pI4 hit!\n", sizeof("Direct path: IP %pI4 hit!\n"), &iph->daddr);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
