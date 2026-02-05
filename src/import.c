/*
 * File     : import.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-05 14:08:37
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "direct_path.h"

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* 当前支持的最长的域名长度 */
// #define DOMAIN_MAX_LEN          64


// 定义与内核一致的 LPM Key 结构体
typedef struct lpm_key {
    uint32_t prefixlen;
    unsigned char domain[DOMAIN_MAX_LEN];
} lpm_key_t;

/**
 * DNS 编码并反转数据。
 * 例如 "baidu.com" -> \x05baidu\x03com -> 反转 -> \x6d\x6f\x63\x03\x75\x64\x69\x61\x62\x05
 */
bool domain_encode_and_reverse(const char *domain, struct lpm_key *key) {
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

    // 设置前缀长度 (位)
    key->prefixlen = pos * 8;
    // 数据反转填充
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

    lpm_key_t key;
    key.prefixlen = 24;
    memset(key.domain, 0, sizeof(key.domain));

    // 简易 YAML 解析：提取域名部分
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

int import_map_domain(FILE *fp, int map_fd) {
    if (unlikely(NULL == fp || map_fd <= 0)) return -1;

    // 2. 特殊处理 .cn
    // 编码为 \x02cn，长度 3 字节，前缀 24 位
    struct lpm_key key;

    key.prefixlen = 24;
    memset(key.domain, 0, sizeof(key.domain));
    uint32_t value = 1;
    key.domain[0] = 'n'; key.domain[1] = 'c'; key.domain[2] = 2;

    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    // 3. 逐行解析规则
    __u32 count = 0;
    char line[FILE_LINE_MAXLEN] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (import_map_domain_by_line(line, map_fd)) count++;
    }

    printf("注入完成！共处理 %d 条规则。\n", count);

    return 0;
}

int import(const char *map_path, const char *rule_file) {
    if (unlikely(NULL == map_path || NULL == rule_file)) return -1;

    // 1. 获取 Map 的文件描述符 (FD)
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

    int ret = import_map_domain(fp, map_fd);

    if (fp != NULL) fclose(fp);

    return 0;
}

int main(int argc, char **argv) {
    const char *rule_file = "/etc/openclash/rule_provider/ChinaMax.yml";
    const char *map_path = "/sys/fs/bpf/xdp_progs/domain_map";

    return import(map_path, rule_file);
}
