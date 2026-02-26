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

#include "direct_path.h"
#include "direct_path_user.h"

static __always_inline void del_head_space_char(char *line, char **res) {
    if (unlikely(NULL == line || NULL == res)) return ;
    *res = NULL;

    char *start = line;
    while (isspace((unsigned char)*start)) start++;
    *res = start;

    return ;
}

/**
 * DNS 编码并反转数据。
 * 例如 "baidu.com" -> \x05baidu\x03com -> 反转 -> \x6d\x6f\x63\x03\x75\x64\x69\x61\x62\x05
 */
bool domain_encode_and_reverse(const char *domain, domain_lpm_key_t *key) {
    int pos = 0;
    char buf[FILE_LINE_MAXLEN] = {0};
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

    /* 去掉前面空白字符 */
    char *start = NULL;
    del_head_space_char(line, &start);
    if ('\0' == *start) return false;

    if (strstr(start, "payload:") || line[0] == '#') return false;
    if (!strstr(start, RULE_DOMAIN) && 
        !strstr(start, RULE_DOMAIN_KEYWORD) && 
        !strstr(start, RULE_DOMAIN_SUFFIX)) return false;

    domain_lpm_key_t key;
    key.prefixlen = 24;
    memset(key.domain, 0, sizeof(key.domain));

    /* 简易 YAML 解析：提取域名部分 */
    char *ptr = strchr(start, ',');
    char *target = NULL;
    if (ptr) {
        target = strtok(ptr + 1, " \t\n\r\"");
    } else {
        ptr = strchr(start, '-');
        if (ptr) target = strtok(ptr + 1, " \t\n\r\"");
    }

    if (!target) return false;

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

bool ipv4_cidr_check(char *buf) {
    if (unlikely(NULL == buf)) return false;

    __u8 nums_num = 0;
    __u8 dot_num = 0;
    __u8 separator_num = 0;

    for (char *p = buf; *p != '\0'; p++) {
        if (NULL == p) return false;

        if (*p >= '0' && *p <= '9') nums_num++;
        else if (*p == '.') dot_num++;
        else if (*p == '/') separator_num++;
        else { *p = '\0'; break; }
    }

    if (nums_num < IPV4_CIDR_NUMS_MIN_NUM || nums_num > IPV4_CIDR_NUMS_MAX_NUM) return false;
    if (dot_num != IPV4_ADDR_DOT_MAX_NUM) return false;
    if (separator_num != IPV4_CIDR_SEP_MAX_NUM) return false;

    return true;
}

/**
 * 将 CIDR 字符串解析并填充至 BPF LPM Key
 * @param cidr_raw  输入如 "  192.168.1.0/24 \t"
 * @param key       输出：构造好的 BPF Key 结构体
 * @return          成功返回 true, 失败返回 false
 */
bool parse_cidr_to_lpm_key(char *cidr_raw, ip_lpm_key_t *key) {
    if (!cidr_raw || !key) return false;

    /* 去掉前面空白字符 */
    char *start = NULL;
    del_head_space_char(cidr_raw, &start);
    if ('\0' == *start) return false;

    char buf[FILE_LINE_MAXLEN] = {0};
    strncpy(buf, start, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* 去掉尾部空白字符 */
    char *end_ptr = buf + strlen(buf) - 1;
    while (end_ptr > buf && isspace((unsigned char)*end_ptr)) {
        *end_ptr = '\0';
        end_ptr--;
    }

    if (!ipv4_cidr_check(buf)) return false;

    /*  分离 IP 和掩码 */
    char *slash = strchr(buf, '/');
    if (!slash) return false;

    *slash = '\0';
    key->prefixlen = atoi(slash + 1);
    if (key->prefixlen < 0 || key->prefixlen > 32) return false;

    /* Parse & Fill */
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return false;
    
    /* ipv4 存储的是网络字节序，且通常需要掩掉主机位（虽然内核会处理，但规范做法是清零） */
    uint32_t host_ip = ntohl(addr.s_addr);
    uint32_t mask = (key->prefixlen == 0) ? 0 : (~0U << (32 - key->prefixlen));
    key->ipv4 = htonl(host_ip & mask);

    return true;
}

bool import_map_ip_by_line(char *line, int map_fd) {
    if (unlikely(NULL == line || map_fd <= 0)) return false;
    if (line[0] == '#') return false;

    char *start_line = strstr(line, RULE_IP);
    if (NULL == start_line) start_line = line;
    else {
        start_line = strchr(line, ',');
        start_line++;
    }

    ip_lpm_key_t key;
    if (!parse_cidr_to_lpm_key(start_line, &key)) return false;

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
    if (!strcmp(import_type, IMPORT_TYPE_DOMAIN)) 
        ret = import_map_domain(fp, map_fd, &rule_num);
    else if (!strcmp(import_type, IMPORT_TYPE_IP)) 
        ret = import_map_ip(fp, map_fd, &rule_num);

    if (fp != NULL) fclose(fp);

    printf("%s 注入完成！共处理 %d 条规则\n", rule_file, rule_num);

    return ret;
}

int args_parse(int argc, char **argv) {
    if (argc < IMPORT_ARGS_MIN_VALID_NUM) 
        return import(IMPORT_TYPE_DOMAIN, IMPORT_DEFULE_MAP, IMPORT_DEFAULT_RULE_FILE);

    for (int i = 1; i < argc; i++) {
        const char *map_path = argv[i++];
        if (NULL == map_path) {
            perror("[ERROR] 参数错误 map_path，" EXPORT_PROG_USAGE);
            return -1;
        }

        const char *import_type = argv[i++];
        if (NULL == import_type) {
            perror("[ERROR] 参数错误 import_type NULL，" EXPORT_PROG_USAGE);
            return -1;
        }

        if (strcmp(import_type, IMPORT_TYPE_DOMAIN) &&
            strcmp(import_type, IMPORT_TYPE_IP)) {
            fprintf(stderr, 
                "[ERROR] 参数错误 import_type argv[%d] = [%s]，"
                EXPORT_PROG_USAGE, i, import_type);
            return -1;
        }

        __u32 rule_file_num = atoi(argv[i++]);
        if (!rule_file_num) {
            perror("[ERROR] 参数错误 rule file num，" EXPORT_PROG_USAGE);
            return -1;
        }

        for (int j = i; j < i + rule_file_num; j++) {
            const char *rule_file = argv[j];
            if (NULL == rule_file) {
                perror("[ERROR] 参数错误 rule file NULL，" EXPORT_PROG_USAGE);
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

int main(int argc, char **argv) {
    return args_parse(argc, argv);
}
