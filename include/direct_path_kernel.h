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


/* rfc1035 */

/* RFC1035标准DNS 头部长度 12个字节 */
#define DNS_HEADER_BYTE                 12
/* qdcount 在第 5 - 6 字节 */
#define DNS_HEADER_QDCOUNT_BYTE_OFFSET  4
/* 如果是请求，qr为0 */
#define DNS_HEADER_QR_QUERY             0
/* 如果是响应，qr为1 */
#define DNS_HEADER_QR_RESPONSE          1
/* 如果是标准查询，opcode应当是0 */
#define DNS_HEADER_OPCODE_STANDARD      0
/* RFC3635 标准单个域名标签支持的最大长度 */
#define DNS_LABEL_MAX_LEN               63


/* 标准DNS端口 */
#define NORMAOL_DNS_PORT                53
/* 内网国内专用DNS服务器服务端口 */
#define DIRECT_DNS_SERVER_PORT          15301
/* 总计收发20个包，且距离最开始的数据包的时间超过了 10秒，才被准入到缓存中 */
#define HOTPKG_NUM                      20
#define HOTPKG_INV_TIME                 10000000000ULL

/* 限制 x 防止 x 超过最大值，截断高位 */
#define LIMIT_BY_MASK(x, mask)          ((x) & (mask))


/* 定义 LRU Hash Map 作为缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CACHE_IP_MAP_SIZE);
    __uint(key_size, CACHE_IP_MAP_KEY_SIZE);
    __uint(value_size, CACHE_IP_MAP_VAL_SIZE);
} hotpath_cache_t;

/* 定义 LRU Hash Map 作为预缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PRE_CACHE_IP_MAP_SIZE);
    __uint(key_size, PRE_CACHE_IP_MAP_KEY_SIZE);
    __uint(value_size, PRE_CACHE_IP_MAP_VAL_SIZE); 
} pre_cache_t;

/* 黑名单 (LPM) */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, BLKLIST_IP_MAP_SIZE);
    __uint(key_size, BLKLIST_IP_MAP_KEY_SIZE);
    __uint(value_size, BLKLIST_IP_MAP_VAL_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blklist_ip_map_t;

/* 国内 IP 白名单 (LPM) */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DIRECT_IP_MAP_SIZE);
    __uint(key_size, DIRECT_IP_MAP_KEY_SIZE);
    __uint(value_size, DIRECT_IP_MAP_VAL_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_ip_map_t;

/* 定义 LRU Hash Map 作为国内域名白名单预缓存 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DOMAINPRE_MAP_SIZE);
    __uint(key_size, DOMAINPRE_MAP_KEY_SIZE);
    __uint(value_size, DOMAINPRE_MAP_VAL_SIZE);
} domain_cache_t;

/* 定义国内域名白名单 */
typedef struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DOMAIN_MAP_SIZE);
    __uint(key_size, DOMAIN_MAP_KEY_SIZE);
    __uint(value_size, DOMAIN_MAP_VAL_SIZE);
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

