#!/bin/bash
#
# File     : deploy_direct_path.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 14:24:02
#

set -euo pipefail

# --- 配置参数 -- 确保与eBPF程序一致 ---

# 物理网口
LAN_IF="eth1"
WAN_IF="eth0"

# eBPF程序
TC_BPF_OBJ="${TC_BPF_OBJ:-tc_direct_path.o}"
XDP_BPF_OBJ="${XDP_BPF_OBJ:-xdp_direct_path.o}"

# eBPF
TC_BPF_DIR="${TC_BPF_DIR:-/sys/fs/bpf/tc_progs}"
XDP_BPF_DIR="${XDP_BPF_DIR:-/sys/fs/bpf/xdp_progs}"

# 程序固定点路径
TC_PROG_BASE="${TC_BPF_DIR}/tc_accel_prog"
XDP_PROG_BASE="${XDP_BPF_DIR}/xdp_accel_prog"

# Map 名称
HOTPATH_MAPNAME="${HOTPATH_MAPNAME:-hotpath_cache}"
PRE_MAPNAME="${PRE_MAPNAME:-pre_cache}"
BLKLIST_MAPNAME="${BLKLIST_MAPNAME:-blklist_ip_map}"
DIRECT_MAPNAME="${DIRECT_MAPNAME:-direct_ip_map}"
DOMAINCACHE_MAPNAME="${DOMAINCACHE_MAPNAME:-domain_cache}"
DOMAIN_MAPNAME="${DOMAIN_MAPNAME:-domain_map}"

# Map 固定路径
HOTPATHMAP_PIN="${TC_BPF_DIR}/${HOTPATH_MAPNAME}"
PREMAP_PIN="${TC_BPF_DIR}/${PRE_MAPNAME}"
BLACKMAP_PIN="${TC_BPF_DIR}/${BLKLIST_MAPNAME}"
DIRECTMAP_PIN="${TC_BPF_DIR}/${DIRECT_MAPNAME}"
DOMAINCACHE_PIN="${XDP_BPF_DIR}/${DOMAINCACHE_MAPNAME}"
DOMAINMAP_PIN="${XDP_BPF_DIR}/${DOMAIN_MAPNAME}"

# eBPF共享内存大小
HOTMAP_SIZE=${HOTMAP_SIZE:-65536}
PREMAP_SIZE=${PREMAP_SIZE:-65536}
BLACKMAP_SIZE=${BLACKMAP_SIZE:-8192}
DIRECTMAP_SIZE=${DIRECTMAP_SIZE:-16384}
DOMAINCACHE_SIZE=${DOMAINCACHE_SIZE:-8192}
DOMAINMAP_SIZE=${DOMAINMAP_SIZE:-10485760}

# 加速mark标记
DIRECT_PATH_MARK="${DIRECT_PATH_MARK:-0x88000000}"

# nft 优先级配置
# 抢在 OpenClash (-150/-100) 之前
BYPASS_PRIORITY="-151" 
BPF_ACCEL_FORWARD_PRIORITY="1"
BPF_ACCEL_INPUT_PRIORITY="1"
BPF_ACCEL_OUTPUT_PRIORITY="-151"

# 必需命令列表
readonly REQUIRED_CMDS=(bpftool tc nft mount umount ip)

# --- 辅助函数 ---
function info() { echo -e "\033[32mINFO:\033[0m $*"; }
function err()  { echo -e "\033[31mERROR:\033[0m $*" >&2; }

# 搜索指定目录下的eBPF共享内存
function get_pin_path() {
    if [[ -z "${1}" ]]; then 
        return ;
    fi

    local path
    path=$(find "${1}" -maxdepth 1 -type f -print -quit 2>/dev/null)
    echo "$path"
}

# 创建共享内存
function do_create_map() {
    bpftool map create "${1}" type "${2}" key "${3}" value "${4}" entries "${5}" name "${6}" flags "${7:-0}"
}

# TC 挂载程序清理
function tc_pin_clean() {
    tc qdisc del dev "${LAN_IF}" clsact 2>/dev/null || true
    tc qdisc del dev "${WAN_IF}" clsact 2>/dev/null || true
}

# XDP 挂载程序清理
function xdp_pin_clean() {
    ip link set dev "${LAN_IF}" xdp off 2>/dev/null || true
    bpftool net detach xdpgeneric dev "${LAN_IF}"
}

# --- 环境检查 ---
function env_check() {
    info "环境检查..."
    if [[ $(id -u) -ne 0 ]]; then err "该脚本必须以 root 运行"; exit 1; fi
    
    for cmd in "${REQUIRED_CMDS[@]}"; do
        command -v "${cmd}" >/dev/null 2>&1 || { err "未找到必需命令: ${cmd}"; exit 2; }
    done
}

# 创建tc共享内存
function create_tc_map() {
    info "创建 TC eBPF Maps..."
    
    tc_pin_clean

    if mountpoint -q "${TC_BPF_DIR}" 2>/dev/null || [[ -d "${TC_BPF_DIR}" ]]; then
        umount -f "${TC_BPF_DIR}" 2>/dev/null || true
        rm -rf "${TC_BPF_DIR}"
    fi

    mkdir -p "${TC_BPF_DIR}"

    mount -t bpf bpf "${TC_BPF_DIR}" || { err "挂载 ${TC_BPF_DIR} bpffs 失败"; exit 1; }

    do_create_map "${HOTPATHMAP_PIN}" lru_hash 4 8 "${HOTMAP_SIZE}" "${HOTPATH_MAPNAME}"
    do_create_map "${PREMAP_PIN}" lru_hash 4 16 "${PREMAP_SIZE}" "${PRE_MAPNAME}"
    do_create_map "${BLACKMAP_PIN}" lpm_trie 8 4 "${BLACKMAP_SIZE}" "${BLKLIST_MAPNAME}" 1
    do_create_map "${DIRECTMAP_PIN}" lpm_trie 8 4 "${DIRECTMAP_SIZE}" "${DIRECT_MAPNAME}" 1
}

# 创建xdp共享内存
function create_xdp_map() {
    info "创建 XDP eBPF Maps..."

    xdp_pin_clean

    if mountpoint -q "${XDP_BPF_DIR}" 2>/dev/null || [[ -d "${XDP_BPF_DIR}" ]]; then
        umount -f "${XDP_BPF_DIR}" 2>/dev/null || true
        rm -rf "${XDP_BPF_DIR}"
    fi

    mkdir -p "${XDP_BPF_DIR}"

    mount -t bpf bpf "${XDP_BPF_DIR}" || { err "挂载 ${XDP_BPF_DIR} bpffs 失败"; exit 1; }

    do_create_map "${DOMAINCACHE_PIN}" lru_hash 68 4 "${DOMAINCACHE_SIZE}" "${DOMAINCACHE_MAPNAME}" 
    do_create_map "${DOMAINMAP_PIN}" lpm_trie 68 4 "${DOMAINMAP_SIZE}" "${DOMAIN_MAPNAME}" 1
}

# 挂载TC共享内存
function load_tc_ebpf_prog() {
    info "挂载TC共享内存"

    # 加载 TC
    bpftool prog loadall "${TC_BPF_OBJ}" "${TC_PROG_BASE}" \
        map name "${HOTPATH_MAPNAME}" pinned "${HOTPATHMAP_PIN}" \
        map name "${PRE_MAPNAME}" pinned "${PREMAP_PIN}" \
        map name "${DIRECT_MAPNAME}" pinned "${DIRECTMAP_PIN}" \
        map name "${BLKLIST_MAPNAME}" pinned "${BLACKMAP_PIN}"

    local pin_path
    pin_path=$(get_pin_path "${TC_PROG_BASE}")
    if [[ -z "${pin_path}" ]]; then
        err "${TC_PROG_BASE} 下找不到已加载的 TC BPF 程序固定点，加载失败"
        exit 9
    fi
}

# 挂载XDP共享内存
function load_xdp_ebpf_prog() {
    info "挂载XDP共享内存"

    # 加载 XDP
    bpftool prog loadall "${XDP_BPF_OBJ}" "${XDP_PROG_BASE}" \
        type xdp \
        map name "${DOMAINCACHE_MAPNAME}" pinned "${DOMAINCACHE_PIN}" \
        map name "${DOMAIN_MAPNAME}" pinned "${DOMAINMAP_PIN}"

    pin_path=$(get_pin_path "${XDP_PROG_BASE}")
    if [[ -z "${pin_path}" ]]; then
        err "${XDP_PROG_BASE} 下找不到已加载的 XDP BPF 程序固定点，加载失败"
        exit 9
    fi
}

# 挂载TC程序
function tc_pinning() {
    info "挂载 TC 过滤器至 ${LAN_IF} 和 ${WAN_IF}..."

    tc_pin_clean

    local pin_path
    pin_path=$(get_pin_path "${TC_PROG_BASE}")
    
    if [[ -z "${pin_path}" ]]; then
        err "找不到已加载的 BPF 程序固定点，请先执行 load_tc_ebpf_prog"
        exit 9
    fi

    tc qdisc add dev "${LAN_IF}" clsact
    tc filter add dev "${LAN_IF}" ingress bpf da pinned "${pin_path}"
    tc filter add dev "${LAN_IF}" egress bpf da pinned "${pin_path}"

    tc qdisc add dev "${WAN_IF}" clsact
    tc filter add dev "${WAN_IF}" ingress bpf da pinned "${pin_path}"
    tc filter add dev "${WAN_IF}" egress bpf da pinned "${pin_path}"
}

# 挂载XDP程序
function xdp_pinning() {
    info "挂载 XDP 过滤器至 ${LAN_IF}..."

    xdp_pin_clean

    local pin_path
    pin_path=$(get_pin_path "${XDP_PROG_BASE}")
    
    if [[ -z "${pin_path}" ]]; then
        err "找不到已加载的 BPF 程序固定点，请先执行 load_xdp_ebpf_prog"
        exit 9
    fi

    bpftool net attach xdpgeneric pinned "${pin_path}" dev "${LAN_IF}"
}

# 添加nft规则
function nft_rule_set() {
    info "5. 配置 nftables 联动..."
    
    nft delete table inet bpf_accel 2>/dev/null || true
    nft add table inet bpf_accel
    
    # 定义 Flowtable (加速双向流量)
    nft "add flowtable inet bpf_accel ft { hook ingress priority 0; devices = { ${LAN_IF}, ${WAN_IF} }; }"
    
    # 定义计数器
    nft add counter inet bpf_accel bypass_clash_cnt
    nft add counter inet bpf_accel local_accel_in
    
    # 创建核心链
    nft "add chain inet bpf_accel early_bypass { type filter hook prerouting priority ${BYPASS_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel forward { type filter hook forward priority ${BPF_ACCEL_FORWARD_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel input { type filter hook input priority ${BPF_ACCEL_INPUT_PRIORITY}; policy accept; }"
    nft "add chain inet bpf_accel output { type filter hook output priority ${BPF_ACCEL_OUTPUT_PRIORITY}; policy accept; }"
    
    # --- 规则下发 ---
    
    # A. BYPASS 逻辑
    # 通过标记在 Prerouting 顶端截击
    # 这里的 accept 能够确保包跳过同一个 hook 点后面所有的表 
    nft "add rule inet bpf_accel early_bypass meta mark & 0xff000000 == ${DIRECT_PATH_MARK} counter name bypass_clash_cnt accept"
    
    # B. Forward 链：注册 Flowtable 实现真正的“内核旁路”
    # 当首包被绕过 OpenClash 正常路由后，后续包通过 flowtable 极速转发
    nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established flow add @ft"
    nft "add rule inet bpf_accel forward meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established accept"
    
    # C. 本地流量 (Input/Output)
    nft "add rule inet bpf_accel input meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established counter name local_accel_in accept"
    nft "add rule inet bpf_accel output meta mark & 0xff000000 == ${DIRECT_PATH_MARK} ct state established accept"
}

function start {
    env_check
    create_tc_map 
    create_xdp_map
    load_tc_ebpf_prog 
    load_xdp_ebpf_prog
    tc_pinning
    xdp_pinning
    nft_rule_set

    info "---------------------------------------"
    info "部署完成！使用以下命令监控截流情况："
    info "watch -n 1 'nft list counters inet bpf_accel'"
    info "---------------------------------------"
}

function clean_all() {
    env_check

    info "清理挂载程序"
    tc_pin_clean  
    xdp_pin_clean 

    info "删除MAP"
    if mountpoint -q "${TC_BPF_DIR}" 2>/dev/null || [[ -d "${TC_BPF_DIR}" ]]; then
        umount -f "${TC_BPF_DIR}" 2>/dev/null || true
        rm -rf "${TC_BPF_DIR}"
    fi

    if mountpoint -q "${XDP_BPF_DIR}" 2>/dev/null || [[ -d "${XDP_BPF_DIR}" ]]; then
        umount -f "${XDP_BPF_DIR}" 2>/dev/null || true
        rm -rf "${XDP_BPF_DIR}"
    fi

    info "删除nft规则"
    nft delete table inet bpf_accel 2>/dev/null || true

    info "清理完成"
}

case "${1:-start}" in
    "start") start ;;
    "stop")  clean_all ;;
    *) err "usage: $0 start|stop" ;;
esac


