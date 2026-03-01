/*
 * File     : tc_direct_path.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-01-20 21:39:23
*/


#include "direct_path_kernel.h"

/* 定义 LRU Hash Map 作为缓存 */
hotpath_cache_t hotpath_cache SEC(".maps");

/* 定义 LRU Hash Map 作为预缓存 */
pre_cache_t pre_cache SEC(".maps");

/* 黑名单 (LPM) */
blklist_ip_map_t blklist_ip_map SEC(".maps");

/* 国内 IP 白名单 (LPM) */
direct_ip_map_t direct_ip_map SEC(".maps");


/* 私网检查函数 */
static __always_inline int is_private_ip(__u32 ip) {
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x7F000000) return 1; // 127.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFF000000) == 0x0A000000) return 1; // 10.0.0.0/8
    if ((bpf_ntohl(ip) & 0xFFF00000) == 0xAC100000) return 1; // 172.16.0.0/12
    if ((bpf_ntohl(ip) & 0xFFFF0000) == 0xC0A80000) return 1; // 192.168.0.0/16
    return 0;
}

/* 查找Map */
static __always_inline int do_lookup_map(__u32 *addr) {
    if (unlikely(NULL == addr)) return 0;

    ip_lpm_key_t key = {.prefixlen = 32, .ipv4 = *addr};

    /* 检查黑名单 (源或目的在黑名单则不加速) */
    if (bpf_map_lookup_elem(&blklist_ip_map, &key)) return 0;

    /* 查缓存一级白名单表之前检查地址是否是私网地址是为了防止缓存或国内IP白名单中混入私网地址 
     * 这样设计的目的是，除了黑名单以外，其他任何的缓存名单混入了私网的地址，都不予处理
     * */
    if (is_private_ip(*addr)) return 0;

    /* 检查缓存 */
    if (bpf_map_lookup_elem(&hotpath_cache, addr)) {
        return 1;
    }

    __u64 now = bpf_ktime_get_ns();

    /* 检查预缓存 */
    pre_val_t *pv = NULL;
   if ((pv = bpf_map_lookup_elem(&pre_cache, addr)) != NULL) {
        /* 原子操作，包计数递增 */
        /* __sync_fetch_and_add 返回的是自增前的值，因此需要加1进行判断 */
        /* 加入缓存，判定标准：见过超过 HOTPKG_NUM 个包，且距离第一次见面已经过了 HOTPKG_INV_TIME 秒 */
        if (((__sync_fetch_and_add(&pv->count, 1) + 1) >= HOTPKG_NUM) && ((now - pv->first_seen) > HOTPKG_INV_TIME)) {
            bpf_map_update_elem(&hotpath_cache, addr, &now, BPF_ANY);
        }

        /* 只要命中白名单，无论命中白名单还是哪个缓存，当前包都要加速 */
        return 1; 
    }

    /* 查白名单并更新缓存 */
    if (bpf_map_lookup_elem(&direct_ip_map, &key)) {
        /* 加入到预缓存 */
        pre_val_t first = {.first_seen = now, .count = 1};
        bpf_map_update_elem(&pre_cache, addr, &first, BPF_ANY);
        return 1;
    } 

    return 0;
}

/* 判断是否应当加速 */
static __always_inline int do_lookup(struct iphdr *iph) {
    if (unlikely(NULL == iph)) return 0;

    /* 过滤纯内网互访 */
    if (is_private_ip(iph->saddr) && is_private_ip(iph->daddr)) return 0;

    /* 查询目的IP */
    if (do_lookup_map(&(iph->daddr))) return 1;

    /* 查询源IP */
    if (do_lookup_map(&(iph->saddr))) return 1;

    return 0;
}

static __always_inline int do_lookup_dns(struct __sk_buff *skb, struct iphdr *ip, void *data_end) {
    if (unlikely(NULL == skb || NULL == ip || NULL == data_end)) return TC_ACT_OK;

    if (!is_private_ip(ip->saddr) || !is_private_ip(ip->daddr)) {
        return TC_ACT_OK;
    }

    if (unlikely(ip->protocol != IPPROTO_UDP)) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) return TC_ACT_OK;
    if (unlikely(NULL == udp)) return TC_ACT_OK;

    if (udp->source != bpf_htons(DIRECT_DNS_SERVER_PORT)) return TC_ACT_OK;

    /* 回程包 */
    __u16 check_val = udp->check;
    __be16 old_sport = udp->source;
    __be16 new_sport = bpf_htons(NORMAOL_DNS_PORT);

    /* 修改端口 */
    __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source);
    bpf_skb_store_bytes(skb, offset, &new_sport, sizeof(new_sport), 0);

    if (unlikely(check_val != 0)) {
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check);
        bpf_l4_csum_replace(skb, offset, old_sport, new_sport, sizeof(new_sport));
    }

    return TC_ACT_OK;
}

SEC("classifier")
int tc_direct_path(struct __sk_buff *skb) {
    if (unlikely(NULL == skb)) return TC_ACT_OK;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (void *)(long)skb->data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    if (do_lookup(iph)) skb->mark = bpf_htonl(DIRECT_MARK);

    do_lookup_dns(skb, iph, data_end);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
