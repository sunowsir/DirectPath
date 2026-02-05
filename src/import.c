/*
 * File     : import.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 14:08:37
*/

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

#include "direct_path.h"

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif


/* 定义与内核一致的 LPM Key 结构体 */

typedef struct {
    uint32_t prefixlen;
    unsigned char domain[DOMAIN_MAX_LEN];
} domain_lpm_key_t;

typedef struct {
    __u32 prefixlen;
    __u32 ipv4;
} ip_lpm_key_t;


/**
 * DNS 编码并反转数据。
 * 例如 "baidu.com" -> \x05baidu\x03com -> 反转 -> \x6d\x6f\x63\x03\x75\x64\x69\x61\x62\x05
 */
bool domain_encode_and_reverse(const char *domain, domain_lpm_key_t *key) {
    int pos = 0;
    char buf[256] = {0};
    uint8_t temp[DOMAIN_MAX_LEN] = {0};

    strncpy(buf, domain, sizeof(buf));

    char *saveptr = NULL;
    char *token = strtok_r(buf, ".", &saveptr);
    while (token != NULL) {
        size_t len = strlen(token);
        if (len == 0 || pos + len + 1 > DOMAIN_MAX_LEN) return false;
        
        temp[pos++] = (uint8_t)len;
        memcpy(&temp[pos], token, len);
        pos += len;
        token = strtok_r(NULL, ".", &saveptr);
    }

    if (0 == pos) return false;

    /* 设置前缀长度 (位) */
    key->prefixlen = pos * 8;
    /* 数据反转填充 */
    memset(key->domain, 0, DOMAIN_MAX_LEN);
    for (int i = 0; i < pos; i++) {
        key->domain[i] = temp[pos - 1 - i];
    }
    return true;
}

bool import_map_domain_by_line(char *line, int map_fd) {
    if (unlikely(NULL == line || map_fd <= 0)) return false;

    if (strstr(line, "payload:") || line[0] == '#') return false;
    if (!strstr(line, "DOMAIN") && !strstr(line, "PROCESS-NAME")) return false;

    domain_lpm_key_t key;
    key.prefixlen = 24;
    memset(key.domain, 0, sizeof(key.domain));

    /* 简易 YAML 解析：提取域名部分 */
    char *ptr = strchr(line, ',');
    char *target = NULL;
    if (ptr) {
        target = strtok(ptr + 1, " \t\n\r\"");
    } else {
        ptr = strchr(line, '-');
        if (ptr) target = strtok(ptr + 1, " \t\n\r\"");
    }

    if (!target || !strchr(target, '.')) return false;
    if (!domain_encode_and_reverse(target, &key)) return false;

    uint32_t value = 1;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret) {
        fprintf(stderr, "[ERROR] [%s] import failed: %d\n", line, ret);
        return false;
    }

    return true;
}

int import_map_domain(FILE *fp, int map_fd, __u32 *rule_num) {
    if (unlikely(NULL == fp || map_fd <= 0 || NULL == rule_num)) return -1;

    /* 特殊处理 .cn */
    /* 编码为 \x02cn，长度 3 字节，前缀 24 位 */
    domain_lpm_key_t key;

    key.prefixlen = 24;
    memset(key.domain, 0, sizeof(key.domain));
    uint32_t value = 1;
    key.domain[0] = 'n'; key.domain[1] = 'c'; key.domain[2] = 2;

    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    /* 逐行解析规则 */
    char line[FILE_LINE_MAXLEN] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (import_map_domain_by_line(line, map_fd)) (*rule_num)++;
    }

    return 0;
}

/**
 * 将 CIDR 字符串解析并填充至 BPF LPM Key
 * @param cidr_raw  输入如 "  192.168.1.0/24 \t"
 * @param key       输出：构造好的 BPF Key 结构体
 * @return          成功返回 true, 失败返回 false
 */
bool parse_cidr_to_lpm_key(const char *cidr_raw, ip_lpm_key_t *key) {
    if (!cidr_raw || !key) return false;

    /* Trim: 去掉前后空白 */
    const char *start = cidr_raw;
    while (isspace((unsigned char)*start)) start++;
    if (*start == '\0') return false;

    char buf[64];
    strncpy(buf, start, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *end_ptr = buf + strlen(buf) - 1;
    while (end_ptr > buf && isspace((unsigned char)*end_ptr)) {
        *end_ptr = '\0';
        end_ptr--;
    }

    /* Split: 分离 IP 和掩码 */
    char *slash = strchr(buf, '/');
    int prefix = 32; // 默认 /32
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    if (prefix < 0 || prefix > 32) return false;

    /* Parse & Fill */
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return false;
    }

    /* LPM Trie 的 prefixlen 必须是位长度 */
    key->prefixlen = (uint32_t)prefix;
    
    /* ipv4 存储的是网络字节序，且通常需要掩掉主机位（虽然内核会处理，但规范做法是清零） */
    uint32_t host_ip = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    key->ipv4 = htonl(host_ip & mask);

    return true;
}

bool import_map_ip_by_line(char *line, int map_fd) {
    if (unlikely(NULL == line || map_fd <= 0)) return false;
    if (line[0] == '#') return false;

    ip_lpm_key_t key;
    if (!parse_cidr_to_lpm_key(line, &key)) return false;

    uint32_t value = 1;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret) {
        fprintf(stderr, "[ERROR] [%s] import failed: %d\n", line, ret);
        return false;
    }

    return true;
}

int import_map_ip(FILE *fp, int map_fd, __u32 *rule_num) {
    if (unlikely(NULL == fp || map_fd <= 0 || NULL == rule_num)) return -1;

    /* 逐行解析规则 */
    __u32 count = 0;
    char line[FILE_LINE_MAXLEN] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (import_map_ip_by_line(line, map_fd)) (*rule_num)++;
    }

    return 0;
}

int import(const char *import_type, const char *map_path, const char *rule_file) {
    if (unlikely(NULL == import_type || NULL == map_path || NULL == rule_file)) return -1;

    /* 获取 Map 的文件描述符 (FD) */
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "[ERROR] 无法获取 BPF Map %s: %s\n", map_path, strerror(errno));
        return -1;
    }

    FILE *fp = fopen(rule_file, "r");
    if (!fp) {
        perror("[ERROR] 无法打开规则文件");
        return -1;
    }

    int ret = 0;
    __u32 rule_num = 0;
    if (!strcmp(import_type, IMPORT_TYPE_DOMAIN)) {
        ret = import_map_domain(fp, map_fd, &rule_num);
    } else if (!strcmp(import_type, IMPORT_TYPE_IP)) {
        ret = import_map_ip(fp, map_fd, &rule_num);
    }

    if (fp != NULL) fclose(fp);

    printf("%s 注入完成！共处理 %d 条规则\n", rule_file, rule_num);

    return ret;
}

int main(int argc, char **argv) {
    if (argc <= 2) {
        const char *rule_file = "/etc/openclash/rule_provider/ChinaMax.yml";
        const char *map_path = "/sys/fs/bpf/xdp_progs/domain_map";

        return import(IMPORT_TYPE_DOMAIN, map_path, rule_file);
    }

    for (int i = 1; i < argc; i++) {
        const char *map_path = argv[i++];
        if (NULL == map_path) {
            perror("[ERROR] 参数错误 map_path，Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ...");
            return -1;
        }

        const char *import_type = argv[i++];
        if (NULL == import_type) {
            perror("[ERROR] 参数错误 import_type NULL，Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ...");
            return -1;
        }

        if (strcmp(import_type, IMPORT_TYPE_DOMAIN) &&
            strcmp(import_type, IMPORT_TYPE_IP)) {
            fprintf(stderr, 
                "[ERROR] 参数错误 import_type argv[%d] = [%s]，"
                "Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ...\n",
                i, import_type);
            return -1;
        }

        __u32 rule_file_num = atoi(argv[i++]);
        if (!rule_file_num) {
            perror("[ERROR] 参数错误 rule file num，Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ...");
            return -1;
        }

        for (int j = i; j < i + rule_file_num; j++) {
            const char *rule_file = argv[j];
            if (NULL == rule_file) {
                perror("[ERROR] 参数错误 rule file NULL，Usage: import [map path] [domain/ip] [rule file num] [file1] [file2] ...");
                return -1;
            }

            int ret = import(import_type, map_path, rule_file);
            if (ret) {
                fprintf(stderr, "[ERROR] import error: %d, import done\n", ret);
                return ret;
            }
        }

        i += rule_file_num - 1;
    }

    return 0;
}
