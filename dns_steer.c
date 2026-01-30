/*
 * File     : dns_steer.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-29 10:51:35
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NORMAOL_DNS_PORT        53
#define DIRECT_DNS_SERVER_PORT  15301

#define DOMAIN_MAX_LEN          64
#define DOMAIN_MAP_SIZE         10485760

typedef struct domain_key {
    __u32 prefixlen;
    char domain[DOMAIN_MAX_LEN];
} domain_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DOMAIN_MAP_SIZE);
    __type(key, domain_key_t);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} domestic_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, domain_key_t);
} domestic_domains_key SEC(".maps");

/* 私网检查函数 */
static __always_inline int is_private_ip(__u32 *ip) {
    if ((bpf_ntohl(*ip) & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((bpf_ntohl(*ip) & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((bpf_ntohl(*ip) & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

static __always_inline int do_lookup(struct __sk_buff *skb, struct iphdr *ip, void *data_end) {
    if (unlikely(NULL == skb || NULL == ip || NULL == data_end)) return TC_ACT_OK;


    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) return TC_ACT_OK;
    if (unlikely(NULL == udp)) return TC_ACT_OK;

    if (is_private_ip(&(ip->daddr)) && udp->dest == bpf_htons(NORMAOL_DNS_PORT)) {
        unsigned char *dns_hdr = (void *)udp + sizeof(*udp);
        if (unlikely((void *)dns_hdr + 12 > data_end)) return TC_ACT_OK;

        unsigned char *cursor = dns_hdr + 12;
        unsigned char *ptr = cursor;

        __u32 kkey = 0;
        domain_key_t *key = bpf_map_lookup_elem(&domestic_domains_key, &kkey);
        if (unlikely(!key)) return TC_ACT_OK;
        __builtin_memset(key, 0, sizeof(domain_key_t));

        bpf_probe_read_kernel_str(key->domain, sizeof(key->domain), cursor);

        __u32 len = 0;
        #pragma unroll
        for (; len < DOMAIN_MAX_LEN; len++) {
            if ((void *)ptr + 1 > data_end) break;
            if (*ptr == 0) break;
            key->domain[len] = *ptr;
            ptr++;
        }

        if (unlikely(len == 0 || len > DOMAIN_MAX_LEN)) return TC_ACT_OK;
        key->prefixlen = (len & (DOMAIN_MAX_LEN - 1)) * 8;

        #pragma unroll
        for (int i = 0; i < DOMAIN_MAX_LEN / 2; i++) {
            int j = len - 1 - i;
            if (i >= j || j >= DOMAIN_MAX_LEN) break;
        
            char t = key->domain[i];
            key->domain[i] = key->domain[j];
            key->domain[j] = t;
        }

        // 4. 匹配
        __u32 *val = bpf_map_lookup_elem(&domestic_domains, key);
        if (unlikely(!val)) return TC_ACT_OK;

        __u16 check_val = udp->check;

        // 1. 修改端口
        // 使用固定偏移量，避免指针计算误差
        __be16 old_dport = udp->dest;
        __be16 new_dport = bpf_htons(DIRECT_DNS_SERVER_PORT);
        __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, dest);
        bpf_skb_store_bytes(skb, offset, &new_dport, sizeof(new_dport), 0);

        // 增量修正校验和
        if (unlikely(check_val != 0)) {
            offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, offset, old_dport, new_dport, sizeof(new_dport));
        }

        // bpf_printk("DNS Ingress Direct path session: %pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
        // bpf_printk("Ingress %s AFTER: %d -> %d\n", key->domain, bpf_ntohs(old_dport), new_dport);
    } 

    // 回程包
    else if (is_private_ip(&(ip->saddr)) && udp->source == bpf_htons(DIRECT_DNS_SERVER_PORT)) {
        __u16 check_val = udp->check;
        __be16 old_sport = udp->source;
        __be16 new_sport = bpf_htons(NORMAOL_DNS_PORT);

        // 1. 修改端口
        // 使用固定偏移量，避免指针计算误差
        __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source);
        bpf_skb_store_bytes(skb, offset, &new_sport, sizeof(new_sport), 0);

        if (unlikely(check_val != 0)) {
            offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, offset, old_sport, new_sport, sizeof(new_sport));
        }

        // bpf_printk("DNS Egress Direct path session: %pI4 -> %pI4\n", &ip->saddr, &ip->daddr);
        // bpf_printk("Egress AFTER: %d -> %d\n", bpf_ntohs(old_sport), bpf_ntohs(new_sport));
    }

    return TC_ACT_OK;
}

SEC("classifier")
int dns_port_steer(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // --- 解析头部 (省略重复代码，确保与原版一致) ---
    struct ethhdr *eth = data;
    if (unlikely((void *)eth + sizeof(*eth) > data_end)) return TC_ACT_OK;
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (unlikely((void *)ip + sizeof(*ip) > data_end)) return TC_ACT_OK;
    if (unlikely(ip->protocol != IPPROTO_UDP)) return TC_ACT_OK;

    if (!is_private_ip(&(ip->saddr)) || !is_private_ip(&(ip->daddr)))
        return TC_ACT_OK;

    return do_lookup(skb, ip, data_end);
}

char _license[] SEC("license") = "GPL";
