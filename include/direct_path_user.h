/*
 * File     : direct_path_import.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-26 21:48:49
*/

#ifndef DIRECT_PATH_IMPORT_H_H
#define DIRECT_PATH_IMPORT_H_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/stddef.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "direct_path.h"

#ifndef likely
#define likely(x)                       (__builtin_expect(!!(x), 1))
#endif

#ifndef unlikely
#define unlikely(x)                     (__builtin_expect(!!(x), 0))
#endif

/* 国内ipv4地址规则集标记 */
#define RULE_IP                         "IP-CIDR,"
/* 国内域名规则集标记 */
#define RULE_DOMAIN                     "DOMAIN,"
#define RULE_DOMAIN_KEYWORD             "DOMAIN-KEYWORD,"
#define RULE_DOMAIN_SUFFIX              "DOMAIN-SUFFIX,"

#define EXPORT_PROG_USAGE               "Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ..."

/* 规则文件注释符 */
#define RULE_FILE_COMMIT_SEPARATOR      '#'
/* 规则文件单行最大长度 */
#define FILE_LINE_MAXLEN                512
/* 导入类型 域名 */
#define IMPORT_TYPE_DOMAIN              "domain"
/* 导入类型 IP */
#define IMPORT_TYPE_IP                  "ip"
/* 用户态主程序，当前设计最小有效参数个数 */
#define DIRECT_PATH_USER_VALID_ARGS_NUM 1
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
/* 域名分隔符 */
#define DOMAIN_NAME_SEPARATOR           "."

/* 物理网口 */
#define LAN_IF                          "eth1"
#define WAN_IF                          "eth0"

/* eBPF程序 */
#define TC_BPF_OBJ                      "tc_direct_path.o"
#define XDP_BPF_OBJ                     "xdp_direct_path.o"

/* eBPF */
#define TC_BPF_DIR                      "/sys/fs/bpf/tc_progs"
#define XDP_BPF_DIR                     "/sys/fs/bpf/xdp_progs"

/* 程序固定点路径 */
#define TC_PROG_BASE                    TC_BPF_DIR"/tc_accel_prog"
#define XDP_PROG_BASE                   XDP_BPF_DIR"/xdp_accel_prog"

// Map 名称
#define HOTPATH_MAPNAME                 "hotpath_cache"
#define PRE_MAPNAME                     "pre_cache"
#define BLKLIST_MAPNAME                 "blklist_ip_map"
#define DIRECT_MAPNAME                  "direct_ip_map"
#define DOMAINCACHE_MAPNAME             "domain_cache"
#define DOMAIN_MAPNAME                  "domain_map"

/* Map 固定路径 */
#define HOTPATHMAP_PIN                  TC_BPF_DIR"/"HOTPATH_MAPNAME
#define PREMAP_PIN                      TC_BPF_DIR"/"PRE_MAPNAME
#define BLACKMAP_PIN                    TC_BPF_DIR"/"BLKLIST_MAPNAME
#define DIRECTMAP_PIN                   TC_BPF_DIR"/"DIRECT_MAPNAME
#define DOMAINCACHE_PIN                 XDP_BPF_DIR"/"DOMAINCACHE_MAPNAME
#define DOMAINMAP_PIN                   XDP_BPF_DIR"/"DOMAIN_MAPNAME

#define DIRECT_PATH_LOAD_ARGS           "load"
#define DIRECT_PATH_RULE_ARGS           "rule"

#endif

