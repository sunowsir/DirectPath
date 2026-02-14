/*
 * File     : direct_path.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 15:44:49
*/

#ifndef DIRECT_PATH_H_H
#define DIRECT_PATH_H_H


#ifdef EBPF_USER_PROJ
#include <linux/stddef.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#endif

#ifdef EBPF_KERNEL_PROJ
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#endif


/* 各共享内存大小 */

/* 国内IP缓存共享内存大小 */
#define CACHE_IP_MAP_SIZE       65536
/* 国内IP预缓存共享内存大小 */
#define PRE_CACHE_IP_MAP_SIZE   65536
/* 国内IP黑名单共享内存大小 */
#define BLKLIST_IP_MAP_SIZE     8192
/* 国内IP库共享内存大小 */
#define DIRECT_IP_MAP_SIZE      16384
/* 国内域名HASH缓存库共享内存大小 */
#define DOMAINPRE_MAP_SIZE      8192
/* 国内域名库共享内存大小 */
#define DOMAIN_MAP_SIZE         10485760


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
/* RFC3635 标准域名最大长度是255，
 * 然而eBPF 处理循环压力太大，几乎无法加载，减少为64 */
#define DOMAIN_MAX_LEN                  64
/* RFC3635 标准单个域名标签支持的最大长度 */
#define DNS_LABEL_MAX_LEN               63


/* 标准DNS端口 */
#define NORMAOL_DNS_PORT                53
/* 内网国内专用DNS服务器服务端口 */
#define DIRECT_DNS_SERVER_PORT          15301

/* 直连流量标记 */
#define DIRECT_MARK                     0x88

/* 总计收发20个包，且距离最开始的数据包的时间超过了 10秒，才被准入到缓存中 */
#define HOTPKG_NUM                      20
#define HOTPKG_INV_TIME                 10000000000ULL

/* 规则文件单行最大长度 */
#define FILE_LINE_MAXLEN                512
/* 导入类型 域名 */
#define IMPORT_TYPE_DOMAIN              "domain"
/* 导入类型 IP */
#define IMPORT_TYPE_IP                  "ip"
/* 规则导入程序当前设计的，有效的最小参数个数 */
#define IMPORT_ARGS_MIN_VALID_NUM       4
/* 默认导入目标共享内存 */
#define IMPORT_DEFULE_MAP               "/sys/fs/bpf/xdp_progs/domain_map"
/* 默认规则文件 */
#define IMPORT_DEFAULT_RULE_FILE        "/etc/openclash/rule_provider/ChinaMax.yml"
/* ipv4 网段 CIDR格式包含的最少数量数字，1.1.1.1/8 */
#define IPV4_CIDR_NUMS_MIN_NUM          5
/* ipv4 网段 CIDR格式包含的最多数量数字，192.168.122.122/24 */
#define IPV4_CIDR_NUMS_MAX_NUM          14
/* ipv4 包含三个点 */
#define IPV4_ADDR_DOT_MAX_NUM           3
/* ipv4 网段 CIDR格式 包含一个/ */
#define IPV4_CIDR_SEP_MAX_NUM           1
/* 国内ipv4地址规则集标记 */
#define RULE_IP                         "IP-CIDR,"
/* 国内域名规则集标记 */
#define RULE_DOMAIN                     "DOMAIN,"
#define RULE_DOMAIN_KEYWORD             "DOMAIN-KEYWORD,"
#define RULE_DOMAIN_SUFFIX              "DOMAIN-SUFFIX,"

#define EXPORT_PROG_USAGE               "Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ..."


/* TC PROG 预缓存LRU HASH key 结构 */
typedef struct {
    unsigned long long int first_seen; // 第一次见到的纳秒时间戳
    unsigned int count;      // 累计包量
} pre_val_t;

/* LPM Key 结构体
 * 用户程序与内核定义一致  */
typedef struct {
    unsigned int prefixlen;
    unsigned char domain[DOMAIN_MAX_LEN];
} __attribute__((packed)) domain_lpm_key_t;

typedef struct {
    unsigned int prefixlen;
    unsigned int ipv4;
} ip_lpm_key_t;

#endif
