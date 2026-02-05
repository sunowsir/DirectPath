/*
 * File     : direct_path.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 15:44:49
*/

#ifndef DIRECT_PATH_H_H
#define DIRECT_PATH_H_H


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
#define NORMAOL_DNS_PORT        53
/* 内网国内专用DNS服务器服务端口 */
#define DIRECT_DNS_SERVER_PORT  15301

/* 直连流量标记 */
#define DIRECT_MARK             0x88

/* 总计收发20个包，且距离最开始的数据包的时间超过了 10秒，才被准入到缓存中 */
#define HOTPKG_NUM              20
#define HOTPKG_INV_TIME         10000000000ULL

/* 规则文件单行最大长度 */
#define FILE_LINE_MAXLEN        512
/* 导入类型 域名 */
#define IMPORT_TYPE_DOMAIN      "domain"
/* 导入类型 IP */
#define IMPORT_TYPE_IP          "ip"


#endif
