#!/bin/bash
#
# File     : load_rules.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

# 定义路径
IP_MAP_PATH="/sys/fs/bpf/tc_progs/direct_ip_map"
DOMAIN_MAP_PATH="/sys/fs/bpf/xdp_progs/domain_map"

function import_ip () {
    curl -s https://ispip.clang.cn/all_cn.html | tr -d ' ' | grep -v '^[<#&]' > /tmp/all_cn.html
    wget -q https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt -O /tmp/CN-ip-cidr.txt
    wget -q https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt  -O /tmp/CN-ip-cidr1.txt

    ./import "${IP_MAP_PATH}" "ip" "4" "/etc/openclash/china_ip_route.ipset" "/tmp/all_cn.html" "/tmp/CN-ip-cidr.txt" "/tmp/CN-ip-cidr1.txt" \
        "${DOMAIN_MAP_PATH}" "domain" "1" "/etc/openclash/rule_provider/ChinaMax.yml"

    rm -rf /tmp/all_cn.html
    rm -rf /tmp/CN-ip-cidr.txt
    rm -rf /tmp/CN-ip-cidr1.txt 
}

import_ip 
