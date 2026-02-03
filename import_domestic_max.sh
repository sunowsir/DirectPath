#!/bin/bash
#
# File     : import_domestic.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-29 14:27:19
#

set -euo pipefail

# --- 配置 ---
RULE_FILE="/etc/openclash/rule_provider/ChinaMax.yml"
MAP_PATH="/sys/fs/bpf/xdp_progs/domain_map"
BATCH_CHUNK_SIZE=10000
MAX_LEN=64

if [ ! -f "$RULE_FILE" ]; then
   echo "错误: 找不到文件 $RULE_FILE"
   exit 1
fi

echo "正在分批注入规则并处理 .cn 后缀..."

# 提升锁定内存限制
# ulimit -l unlimited || true

python3 - <<EOF
import struct
import os
import subprocess

rule_file = "$RULE_FILE"
map_path = "$MAP_PATH"
max_len = $MAX_LEN
chunk_size = $BATCH_CHUNK_SIZE
tmp_batch = "/tmp/dns_chunk.txt"

def get_hex_cmd_raw(dns_encoded):
    """通用编码转换函数"""
    rev_data = dns_encoded[::-1]
    prefix_bits = len(rev_data) * 8
    prefix_bytes = struct.pack('<I', prefix_bits)
    domain_bytes = rev_data.ljust(max_len, b'\x00')
    key_hex = " ".join(f"{b:02x}" for b in (prefix_bytes + domain_bytes))
    return f"map update pinned {map_path} key hex {key_hex} value hex 01 00 00 00"

def get_hex_cmd_from_domain(target):
    parts = target.lower().strip('.').split('.')
    dns_encoded = b''
    for part in parts:
        if not part: continue
        dns_encoded += struct.pack('B', len(part)) + part.encode()
    if not dns_encoded or len(dns_encoded) > max_len:
        return None
    return get_hex_cmd_raw(dns_encoded)

def run_batch(commands):
    if not commands: return
    with open(tmp_batch, 'w') as f:
        f.write("\n".join(commands) + "\n")
    subprocess.run(["bpftool", "batch", "file", tmp_batch], capture_output=True)

count = 0
current_chunk = []

try:
    # 1. 先注入特殊的 .cn 规则
    # .cn 的 DNS 编码是 \x02 c n
    cn_root_cmd = get_hex_cmd_raw(b'\x02cn')
    current_chunk.append(cn_root_cmd)

    # 2. 处理规则文件
    with open(rule_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or 'payload:' in line:
                continue
            if 'DOMAIN' not in line and 'PROCESS-NAME' not in line:
                continue

            clean_line = line.lstrip('- ').strip()
            parts = clean_line.split(',')
            target = parts[1].strip() if len(parts) > 1 else parts[0].strip()

            if '.' not in target:
                continue

            cmd = get_hex_cmd_from_domain(target)
            if cmd:
                current_chunk.append(cmd)
                count += 1

            if len(current_chunk) >= chunk_size:
                run_batch(current_chunk)
                current_chunk = []
                print(f"已处理 {count} 条...")

    if current_chunk:
        run_batch(current_chunk)

except Exception as e:
    print(f"处理过程中出错: {e}")

if os.path.exists(tmp_batch):
    os.remove(tmp_batch)

print(f"注入完成！共处理 {count} 条规则 + .cn 全局规则。")
EOF
