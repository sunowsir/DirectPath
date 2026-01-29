#!/bin/bash
#
# File     : import_domestic.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-29 14:27:19
#

#!/bin/bash
set -euo pipefail

RULE_FILE="/etc/openclash/rule_provider/ChinaMax.yml"
MAP_PATH="/sys/fs/bpf/dns_steer/domestic_domains"
# 确保这里匹配你 bpftool map show 看到的 key 68B (4字节prefix + 64字节domain)
MAX_LEN=64

if [ ! -f "$RULE_FILE" ]; then
   echo "错误: 找不到文件 $RULE_FILE"
   exit 1
fi

echo "正在逐条注入规则 (兼容老旧版本 bpftool)..."

# 提升锁定内存限制
ulimit -l unlimited

python3 - <<EOF
import struct
import os
import subprocess

rule_file = "$RULE_FILE"
map_path = "$MAP_PATH"
max_len = $MAX_LEN

def update_map(target):
    # 1. DNS 编码
    parts = target.lower().strip('.').split('.')
    dns_encoded = b''
    for part in parts:
        if not part: continue
        dns_encoded += struct.pack('B', len(part)) + part.encode()

    if not dns_encoded or len(dns_encoded) > max_len:
        return

    # 2. 逻辑处理 (翻转 + 填充)
    rev_data = dns_encoded[::-1]
    prefix_bits = len(rev_data) * 8

    # 3. 构造带空格的 HEX 字符串 (最兼容格式)
    # Prefix (4字节小端)
    prefix_bytes = struct.pack('<I', prefix_bits)
    # Domain (填充到 MAX_LEN)
    domain_bytes = rev_data.ljust(max_len, b'\x00')

    # 合并并转为带空格的 hex: "08 00 00 00 aa bb cc..."
    full_hex = " ".join(f"{b:02x}" for b in (prefix_bytes + domain_bytes))

    # 直接调用单条指令更新
    cmd = ["bpftool", "map", "update", "pinned", map_path, "key", "hex"] + full_hex.split() + ["value", "hex", "01", "00", "00", "00"]

    # 这种方式不依赖文件读取，也不依赖 batch 缓冲区
    subprocess.run(cmd, check=False, capture_output=True)

count = 0
try:
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

            update_map(target)
            count += 1
            if count % 500 == 0:
                print(f"已处理 {count} 条...")

except Exception as e:
    print(f"处理出错: {e}")

print(f"注入完成，共 {count} 条。")
EOF
