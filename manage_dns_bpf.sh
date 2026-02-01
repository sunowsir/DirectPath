#!/bin/bash
#
# File     : manage_dns_bpf.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-29 11:30:25
#

#!/bin/bash
set -euo pipefail

LAN_IF="eth1"

BPF_OBJ="dns_steer.o"

BPF_DIR="/sys/fs/bpf/dns_steer"

# 固定点路径
MAP_NAME="domain_map"
MAP_PIN="${BPF_DIR}/${MAP_NAME}"
XDP_PROG_PIN="${BPF_DIR}/dns_prog"

DOMAIN_MAP_SIZE=10485760

# 必需命令
readonly REQUIRED_CMDS=(bpftool mountpoint mount umount)

# --- 辅助函数 ---
function info() { echo -e "\033[32mINFO:\033[0m $*"; }
function err()  { echo -e "\033[31mERROR:\033[0m $*" >&2; }

function clean_all() {
    echo "清理 XDP 程序..."
    ip link set dev "${LAN_IF}" xdp off 2>/dev/null || true
    bpftool net detach xdpgeneric dev "${LAN_IF}"

    # 卸载并删除整个目录
    if mountpoint -q "${BPF_DIR}"; then
        umount -l "${BPF_DIR}" || true
    fi
    rm -rf "${BPF_DIR}"

    info "清理完成"
}

function init_env() {
    info "检查环境与挂载 bpffs..."
    for cmd in "${REQUIRED_CMDS[@]}"; do
        command -v "${cmd}" >/dev/null 2>&1 || { err "找不到命令: ${cmd}"; exit 1; }
    done

    if [[ ! -f "${BPF_OBJ}" ]]; then
        err "找不到 BPF 文件: ${BPF_OBJ}"
        exit 1
    fi

    mkdir -p "${BPF_DIR}"
    mount -t bpf bpf "${BPF_DIR}" || { err "挂载 bpffs 失败"; exit 1; }
}

function start() {
    clean_all
    init_env

    # 1. 创建 Map
    bpftool map create "${MAP_PIN}" type lpm_trie key 68 value 4 entries ${DOMAIN_MAP_SIZE} name ${MAP_NAME} flags 1

    # 2. 加载 XDP
    bpftool prog load "${BPF_OBJ}" "${XDP_PROG_PIN}" \
        type xdp \
        map name domain_map pinned "${MAP_PIN}"
    
    bpftool net attach xdpgeneric pinned "${XDP_PROG_PIN}" dev "${LAN_IF}"
    info "XDP Ingress 部署成功！"
}

case "${1:-start}" in
    "start") start ;;
    "stop")  clean_all ;;
    "log")   cat /sys/kernel/debug/tracing/trace_pipe ;;
esac
