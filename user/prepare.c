/*
 * File     : prepare.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 10:53:49
*/

#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include<stdlib.h>

#include <net/if.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "direct_path_user.h"
#include "direct_path_prepare.h"

/* 卸载 TC clsact qdisc */
bool tc_clean(const char *ifname) {
    if (unlikely(NULL == ifname)) return false;

    int ifindex = if_nametoindex(ifname);
    if (unlikely(0 == ifindex)) return false;

    char cmd[SYSTEM_CMD_MAX_LEN] = {0};
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    system(cmd);  // 忽略返回值，无论是否存在都继续

    /* 待解决，如下代码无法释放TC */
    // DECLARE_LIBBPF_OPTS(bpf_tc_hook, ingress_tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    // DECLARE_LIBBPF_OPTS(bpf_tc_hook, egress_tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
    // 
    // /* 销毁hook会同时清理关联的filter */
    // bpf_tc_hook_destroy(&ingress_tc_hook); 
    // bpf_tc_hook_destroy(&egress_tc_hook); 

    // int tc_prog_fd = bpf_obj_get(TC_PROG_BASE);

    // DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = tc_prog_fd, .handle = 1, .priority = 1);

    // bpf_tc_detach(&ingress_tc_hook, &tc_opts);
    // bpf_tc_detach(&egress_tc_hook, &tc_opts);

    return true;
}

/* 卸载 XDP 程序 */
bool xdp_clean(int ifindex) {
    if (unlikely(0 == ifindex)) return false;

    /* 卸载主XDP程序 */

    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_HW_MODE, NULL);
    
    return true;
}

bool umount_bpf_fs(const char *dir) {
    if (unlikely(NULL == dir)) return false;

    umount2(dir, MNT_FORCE);
    remove(dir);

    return true;
}

bool mount_bpf_fs(const char *dir) {
    if (unlikely(NULL == dir)) return false;

    if (mkdir(dir, 0755) != 0) {
        perror("创建目录失败");
        return false;
    }

    if (mount("bpf", dir, "bpf", 0, NULL) != 0) {
        perror("挂载失败");
        return false;
    }

    return true;
}

bool create_map(const char *map_name, 
    const char *map_path, enum bpf_map_type map_type, 
    int key_size, int value_size, int max_entries, 
    struct bpf_map_create_opts *opts) {

    int map_fd = bpf_map_create(map_type, map_name, key_size, value_size, max_entries, opts);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to create BPF map: %s\n", strerror(errno));
        return false;
    }
    
    /* Pin the map to the specified path */
    if (bpf_obj_pin(map_fd, map_path) < 0) {
        fprintf(stderr, "Failed to pin BPF map to path: %s\n", strerror(errno));
        close(map_fd);
        return false;
    }

    printf("[INFO] map %s 已创建\n", map_path);
    close(map_fd);

    return true;
}

bool umount_map_all() {
    if (!tc_clean(LAN_IF)) return false;
    if (!tc_clean(WAN_IF)) return false;

    if (!xdp_clean(if_nametoindex(LAN_IF))) return false;

    printf("[INFO] 程序已卸载\n");

    if (!umount_bpf_fs(TC_BPF_DIR)) return false;
    if (!umount_bpf_fs(XDP_BPF_DIR)) return false;

    printf("[INFO] map 已清理\n");

    return true;
}

bool mount_map_all() {

    if (!mount_bpf_fs(TC_BPF_DIR)) return false;
    if (!mount_bpf_fs(XDP_BPF_DIR)) return false;

    return true;
}

bool create_map_all() {
    umount_map_all();

    bool ret = mount_map_all();
    if (!ret) return ret;

    struct bpf_map_create_opts opts = {
        .sz = sizeof(opts),
        .map_flags = BPF_F_NO_PREALLOC,  // 必须设置此标志
        .btf_key_type_id = 0,
        .btf_value_type_id = 0,
        .btf_fd = 0,
        .inner_map_fd = 0,
        .map_extra = 0
    };

    ret = create_map(HOTPATH_MAPNAME, HOTPATHMAP_PIN, BPF_MAP_TYPE_LRU_HASH, 
        CACHE_IP_MAP_KEY_SIZE, CACHE_IP_MAP_VAL_SIZE, CACHE_IP_MAP_SIZE, 0);
    if (!ret) return ret;

    ret = create_map(PRE_MAPNAME, PREMAP_PIN, BPF_MAP_TYPE_LRU_HASH, 
        PRE_CACHE_IP_MAP_KEY_SIZE, PRE_CACHE_IP_MAP_VAL_SIZE, PRE_CACHE_IP_MAP_SIZE, 0);
    if (!ret) return ret;

    ret = create_map(BLKLIST_MAPNAME, BLACKMAP_PIN, BPF_MAP_TYPE_LPM_TRIE, 
        BLKLIST_IP_MAP_KEY_SIZE, BLKLIST_IP_MAP_VAL_SIZE, BLKLIST_IP_MAP_SIZE, &opts);
    if (!ret) return ret;

    ret = create_map(DIRECT_MAPNAME, DIRECTMAP_PIN, BPF_MAP_TYPE_LPM_TRIE, 
        DIRECT_IP_MAP_KEY_SIZE, DIRECT_IP_MAP_VAL_SIZE, DIRECT_IP_MAP_SIZE, &opts);
    if (!ret) return ret;

    ret = create_map(DOMAINCACHE_MAPNAME, DOMAINCACHE_PIN, BPF_MAP_TYPE_LRU_HASH, 
        DOMAINPRE_MAP_KEY_SIZE, DOMAINPRE_MAP_VAL_SIZE, DOMAINPRE_MAP_SIZE, 0);
    if (!ret) return ret;

    ret = create_map(DOMAIN_MAPNAME, DOMAINMAP_PIN, BPF_MAP_TYPE_LPM_TRIE, 
        DOMAIN_MAP_KEY_SIZE, DOMAIN_MAP_VAL_SIZE, DOMAIN_MAP_SIZE, &opts);
    if (!ret) return ret;

    return ret;
}
