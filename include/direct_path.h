/*
 * File     : direct_path.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 15:44:49
*/

#ifndef DIRECT_PATH_H_H
#define DIRECT_PATH_H_H


/* RFC3635 标准域名最大长度是255，
 * 然而eBPF 处理循环压力太大，几乎无法加载，减少为86 */
#define DOMAIN_MAX_LEN                  64

/* 字节转比特 */
#define Byte_to_bit(Byte)               (Byte * 8)
/* 超过最大值，则使用最大值 */
#define USE_LIMIT_MAX(x, max)           (((x) <= (max)) ? (x) : (max))


/* 各共享内存大小 */

/* 国内IP缓存共享内存大小 */
#define CACHE_IP_MAP_SIZE               65536
/* 国内IP预缓存共享内存大小 */
#define PRE_CACHE_IP_MAP_SIZE           65536
/* 国内IP黑名单共享内存大小 */
#define BLKLIST_IP_MAP_SIZE             8192
/* 国内IP库共享内存大小 */
#define DIRECT_IP_MAP_SIZE              16384
/* 国内域名HASH缓存库共享内存大小 */
#define DOMAINPRE_MAP_SIZE              8192
/* 国内域名库共享内存大小 */
#define DOMAIN_MAP_SIZE                 10485760


/* TC PROG 预缓存LRU HASH key 结构 */
typedef struct {
    /* 第一次见到的纳秒时间戳 */
    unsigned long long int first_seen; 
    /* 累计包量 */
    unsigned int count;      
} pre_val_t;

/* 国内域名白名单 LPM Key 结构体
 * 用户程序与内核定义一致  */
typedef struct {
    unsigned int prefixlen;
    unsigned char domain[DOMAIN_MAX_LEN];
} domain_lpm_key_t;

/* 国内IP白名单 LPM Key 结构体
 * 用户程序与内核定义一致  */
typedef struct {
    unsigned int prefixlen;
    unsigned int ipv4;
} ip_lpm_key_t;


/* 各共享内存 key 值大小 */

/* 国内IP缓存共享内存 key 值大小 */
#define CACHE_IP_MAP_KEY_SIZE           (sizeof(unsigned int))
/* 国内IP预缓存共享内存 key 值大小 */
#define PRE_CACHE_IP_MAP_KEY_SIZE       (sizeof(unsigned int))
/* 国内IP黑名单共享内存 key 值大小 */
#define BLKLIST_IP_MAP_KEY_SIZE         (sizeof(ip_lpm_key_t))
/* 国内IP库共享内存 key 值大小 */
#define DIRECT_IP_MAP_KEY_SIZE          (sizeof(ip_lpm_key_t))
/* 国内域名HASH缓存库共享内存 key 值大小 */
#define DOMAINPRE_MAP_KEY_SIZE          (sizeof(domain_lpm_key_t))
/* 国内域名库共享内存 key 值大小 */
#define DOMAIN_MAP_KEY_SIZE             (sizeof(domain_lpm_key_t))


/* 各共享内存 value 值大小 */

/* 国内IP缓存共享内存 key 值大小 */
#define CACHE_IP_MAP_VAL_SIZE           (sizeof(unsigned long long int))
/* 国内IP预缓存共享内存 key 值大小 */
#define PRE_CACHE_IP_MAP_VAL_SIZE       (sizeof(pre_val_t))
/* 国内IP黑名单共享内存 key 值大小 */
#define BLKLIST_IP_MAP_VAL_SIZE         (sizeof(unsigned int))
/* 国内IP库共享内存 key 值大小 */
#define DIRECT_IP_MAP_VAL_SIZE          (sizeof(unsigned int))
/* 国内域名HASH缓存库共享内存 key 值大小 */
#define DOMAINPRE_MAP_VAL_SIZE          (sizeof(unsigned int))
/* 国内域名库共享内存 key 值大小 */
#define DOMAIN_MAP_VAL_SIZE             (sizeof(unsigned int))

/* 直连流量标记 */
#define DIRECT_MARK                     0x88


#endif
