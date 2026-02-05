/*
 * File     : direct_path.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 15:44:49
*/

#ifndef DIRECT_PATH_H_H
#define DIRECT_PATH_H_H


/* 标准DNS端口 */
#define NORMAOL_DNS_PORT        53
/* 内网国内专用DNS服务器服务端口 */
#define DIRECT_DNS_SERVER_PORT  15301

/* 当前支持的最长的域名长度 */
#define DOMAIN_MAX_LEN          64
/* 单个域名标签支持的最大长度 */
#define DNS_LABEL_MAX_LEN       64

/* 国内域名HASH缓存库共享内存大小 */
#define DOMAINPRE_MAP_SIZE      8192
/* 国内域名库共享内存大小 */
#define DOMAIN_MAP_SIZE         10485760


/* 直连流量标记 */
#define DIRECT_MARK 0x88

/* 各共享内存大小 */
#define CACHE_IP_MAP_SIZE       65536
#define PRE_CACHE_IP_MAP_SIZE   65536
#define BLKLIST_IP_MAP_SIZE     8192
#define DIRECT_IP_MAP_SIZE      16384

/* 总计收发20个包，且距离最开始的数据包的时间超过了 10秒，才被准入到缓存中 */
#define HOTPKG_NUM              20
#define HOTPKG_INV_TIME         10000000000ULL


/* 规则文件单行最大长度 */
#define FILE_LINE_MAXLEN        512

#endif

