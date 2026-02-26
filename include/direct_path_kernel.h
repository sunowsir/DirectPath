/*
 * File     : direct_path_kernel.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-26 21:51:24
*/

#ifndef DIRECT_PATH_KERNEL_H_H
#define DIRECT_PATH_KERNEL_H_H

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "direct_path.h"

/* 定义 LRU Hash Map 作为缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CACHE_IP_MAP_SIZE);
    __uint(key_size, 4);
    __uint(value_size, 8);
} hotpath_cache_t;

/* 定义 LRU Hash Map 作为预缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PRE_CACHE_IP_MAP_SIZE);
    __uint(key_size, 4);
    __uint(value_size, sizeof(pre_val_t)); 
} pre_cache_t;

/* 黑名单 (LPM) */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, BLKLIST_IP_MAP_SIZE);
    __uint(key_size, sizeof(ip_lpm_key_t));
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blklist_ip_map_t;

/* 国内 IP 白名单 (LPM) */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DIRECT_IP_MAP_SIZE);
    __uint(key_size, sizeof(ip_lpm_key_t));
    __uint(value_size, 4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map_t;

/* 定义 LRU Hash Map 作为预缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DOMAINPRE_MAP_SIZE);
    __uint(key_size, sizeof(domain_lpm_key_t));
    __uint(value_size, sizeof(__u32));
} domain_cache_t;

/* 定义国内域名白名单 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DOMAIN_MAP_SIZE);
    __type(key, domain_lpm_key_t);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} domain_map_t;

/* 定义数组，作为域名白名单key */
typedef struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, domain_lpm_key_t);
} domain_map_key_t;

#endif

