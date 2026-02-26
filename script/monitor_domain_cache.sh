#!/bin/bash
#
# File     : monitor_domain_cache.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-02-04 15:44:04
#


MAP_PATH="/sys/fs/bpf/xdp_progs/domain_cache"

function all_info() {
    echo -e "\033[32mDumping Domain Cache (Multi-line Mode)...\033[0m"
    echo -e "----------------------------------------------------------------------"
    printf "%-40s | %-10s | %-5s\n" "DOMAIN (RAW/REVERSED)" "PREFIX_LEN" "VALUE"
    echo -e "----------------------------------------------------------------------"
    
    bpftool map dump pinned "${MAP_PATH}" | awk '
    function h2d(h,   i, n, d, c) {
        if (!h) return 0
        n = length(h)
        d = 0
        for (i = 1; i <= n; i++) {
            c = tolower(substr(h, i, 1))
            d = d * 16 + (index("0123456789abcdef", c) - 1)
        }
        return d
    }
    
    BEGIN { mode = "" }
    
    {
        if ($1 == "key:") {
            mode = "KEY"
            k_idx = 0
            delete k_all
            next
        }
        if ($1 == "value:") {
            mode = "VALUE"
            v_idx = 0
            delete v_all
            next
        }
    
        # 收集十六进制字节
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9a-fA-F]{2}$/) {
                if (mode == "KEY") k_all[++k_idx] = $i
                if (mode == "VALUE") v_all[++v_idx] = $i
            }
        }
    
        # 当收集完 value 后（通常 value 只有一行），进行解析打印
        if (mode == "VALUE" && v_idx >= 1) {
            # 解析 prefixlen (前 4 字节，小端序)
            plen = h2d(k_all[1]) + (h2d(k_all[2]) * 256) + (h2d(k_all[3]) * 65536) + (h2d(k_all[4]) * 16777216)
            
            # 解析域名 (第 5 字节开始)
            domain = ""
            for (i = 5; i <= k_idx; i++) {
                # 遇到 00 停止，或者达到 prefixlen 对应的字符长度停止
                # 注意：LPM Trie 的 key 后面通常补 0，我们要过滤掉
                if (k_all[i] == "00") break
                
                char_code = h2d(k_all[i])
                if (char_code >= 32 && char_code <= 126)
                    domain = domain sprintf("%c", char_code)
                else if (i + 1 <= k_idx && k_all[i + 1] != "00")
                    domain = domain "."
            }
    
            # 解析 value (前 4 字节，小端序)
            val = h2d(v_all[1]) + (h2d(v_all[2]) * 256)
    
            domain_len = length(domain)
            reversed_domain = ""
            for (i = domain_len; i >= 1; i--) {
                reversed_domain = reversed_domain substr(domain, i, 1)
            }
            domain = reversed_domain
    
            if (plen > 0) {
                printf "%-40s | %-10d | %-5d\n", domain, plen, val
                count++
            }
            
            # 重置状态，防止重复打印
            mode = ""
        }
    }
    
    END {
        print "----------------------------------------------------------------------"
        printf "Total entries: %d\n", count
    }'
}

function total_info() {
    # 获取最大容量
    MAX=$(bpftool map show pinned "${MAP_PATH}" | grep -oE "max_entries [0-9]+" | awk '{print $2}')
    
    # 获取当前条目数 (通过查找 key 关键字)
    CUR=$(bpftool map dump pinned "${MAP_PATH}" | grep -c "key:")
    
    # 计算百分比
    # OpenWrt 默认只有基本的 awk，我们可以用它做浮点运算
    USAGE=$(awk -v c="${CUR}" -v m="${MAX}" 'BEGIN { printf "%.2f", (c/m)*100 }')
    
    echo "---------------------------------------"
    echo "缓存库状态监控 (DirectPath LRU Cache)"
    echo "当前条目: ${CUR}"
    echo "最大容量: ${MAX}"
    echo "占用比例: ${USAGE}%"
    echo "---------------------------------------"
    
    # 诊断建议
    if [[ "${CUR}" -eq "${MAX}" ]]; then
        echo "警告: 缓存已满！虽然 LRU 会自动淘汰旧数据，但如果"
        echo "      占用率长期 100%，建议将 max_entries 调大。"
    elif [[ "${CUR}" -gt $((MAX * 8 / 10)) ]]; then
        echo "提示: 缓存压力较大 (已超过 80%)。"
    else
        echo "状态: 缓存运行良好。"
    fi
}


function main() {
    if [[ ! -f "${MAP_PATH}" ]]; then
        echo -e "\033[31mError:\033[0m Map path ${MAP_PATH} not found."
        exit 1
    fi

    if [[ $1 == "-a" ]]; then 
        all_info "${@}" || exit $?
    fi

    total_info "${@}" || exit $?
}

main "${@}"
