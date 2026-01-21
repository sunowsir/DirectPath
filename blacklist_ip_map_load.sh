#!/bin/bash
#
# File     : blacklist_ip_map_load.sh
# Author   : sun.wang
# Mail     : sunowsir@163.com
# Github   : github.com/sunowsir
# Creation : 2026-01-21 17:25:46
#

MAP_PATH="/sys/fs/bpf/tc_progs/blacklist_ip_map"

eval "$(printf "bpftool map update pinned %s key hex %02x 00 00 00 %02x %02x %02x %02x value hex 00 00 00 00" "${MAP_PATH}" 24 10 0 0 0)"
