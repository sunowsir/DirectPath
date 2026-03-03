/*
 * File     : prog_load.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 15:27:32
*/

#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "direct_path_user.h"
#include "direct_path_prog_load.h"

bool load_and_pin_bpf_prog(const char *prog_file, const char *bpf_dir, const char *pin_dir, 
    struct bpf_object **obj, int *prog_fd) {
    
    *obj = bpf_object__open_file(prog_file, NULL);
    if (libbpf_get_error(*obj)) return false;

    /* Map 复用 */
    struct bpf_map *map;
    bpf_object__for_each_map(map, *obj) {
        const char *map_name = bpf_map__name(map);
        char map_pin_path[MAP_PIN_PATH_MAXLEN] = {0};
        
        /* 构造对应的 Map 固定路径 */
        snprintf(map_pin_path, sizeof(map_pin_path) - 1, "%s/%s", bpf_dir, map_name);

        /* 尝试获取已经存在的 Map FD */
        int pinned_fd = bpf_obj_get(map_pin_path);
        if (pinned_fd < 0) continue;

        /* 告诉 libbpf 这个 map 不要创建新的，直接用这个 FD */
        if (bpf_map__reuse_fd(map, pinned_fd)) {
            fprintf(stderr, "[ERROR] 无法复用 Map %s\n", map_name);
            close(pinned_fd);
            return false;
        }

        close(pinned_fd); 
    }
    
    if (bpf_object__load(*obj)) return false;

    /* 核心修改：动态获取内核程序名 */
    struct bpf_program *prog = bpf_object__next_program(*obj, NULL);
    if (!prog) return false;

    const char *actual_name = bpf_program__name(prog); // 获取 "tc_direct_path"
    *prog_fd = bpf_program__fd(prog);

    /* 构造路径：/sys/fs/bpf/tc_progs/tc_direct_path/tc_direct_path */
    char final_dir[256];
    snprintf(final_dir, sizeof(final_dir), "%s/%s", pin_dir, actual_name);

    /* 1. 创建子目录 (类似 bpftool 的行为) */
    char mkdir_cmd[300];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", pin_dir);
    system(mkdir_cmd);

    /* 2. Pin 到这个正确的路径 */
    unlink(final_dir); 
    if (bpf_obj_pin(*prog_fd, final_dir)) {
        fprintf(stderr, "Pin 失败到路径: %s\n", final_dir);
        return false;
    }

    printf("[INFO] 程序已根据内核入口名固定至: %s\n", final_dir);
    return true;
}

bool tc_prog_hook_create(struct bpf_object *tc_obj, int ifindex) {
    if (unlikely(0 == ifindex)) return false;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);

    /* 创建TC钩子 */
    int err = bpf_tc_hook_create(&tc_hook);
    if (err) {
        fprintf(stderr, "创建TC钩子失败: %d\n", err);
        bpf_object__close(tc_obj);
        return false;
    }

    return true;
}

bool attach_tc_prog_by_if(struct bpf_object *tc_obj, int tc_prog_fd, 
    int ifindex, enum bpf_tc_attach_point attach_point) {
    if (unlikely(0 == ifindex)) return false;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex, .attach_point = attach_point);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .prog_fd = tc_prog_fd, .handle = 1, .priority = 1);

    /* 附加BPF程序到TC钩子 */
    if (bpf_tc_attach(&tc_hook, &tc_opts)) {
        fprintf(stderr, "附加TC程序失败\n");
        bpf_object__close(tc_obj);
        return false;
    }

    return true;
}

/* 附加TC程序到接口 */
bool attach_tc_prog(int tc_prog_fd, struct bpf_object *tc_obj) {
    if (unlikely(NULL == tc_obj)) return false;

    bool ret = tc_prog_hook_create(tc_obj, if_nametoindex(LAN_IF));
    if (!ret) return ret;

    ret = attach_tc_prog_by_if(tc_obj, tc_prog_fd, if_nametoindex(LAN_IF), BPF_TC_INGRESS);
    if (!ret) return ret;

    ret = attach_tc_prog_by_if(tc_obj, tc_prog_fd, if_nametoindex(LAN_IF), BPF_TC_EGRESS);
    if (!ret) return ret;

    ret = tc_prog_hook_create(tc_obj, if_nametoindex(WAN_IF));
    if (!ret) return ret;

    ret = attach_tc_prog_by_if(tc_obj, tc_prog_fd, if_nametoindex(WAN_IF), BPF_TC_INGRESS);
    if (!ret) return ret;

    ret = attach_tc_prog_by_if(tc_obj, tc_prog_fd, if_nametoindex(WAN_IF), BPF_TC_EGRESS);
    if (!ret) return ret;

    return ret;
}

/* 附加XDP程序到接口 */
bool attach_xdp_prog(int xdp_prog_fd, struct bpf_object *xdp_obj) {
    if (unlikely(NULL == xdp_obj)) return false;

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;  // 标志位
    
    if (bpf_xdp_attach(if_nametoindex(LAN_IF), xdp_prog_fd, flags, NULL)) {
        fprintf(stderr, "附加XDP程序失败\n");
        bpf_object__close(xdp_obj);
        return false;
    }

    return true;
}

bool load_and_pin_bpf_all() {
    int tc_prog_fd;
    struct bpf_object *tc_obj = NULL;
    bool ret = load_and_pin_bpf_prog(TC_BPF_OBJ, TC_BPF_DIR, TC_PROG_BASE, &tc_obj, &tc_prog_fd);
    if (!ret) return false;

    if (!attach_tc_prog(tc_prog_fd, tc_obj)) return false;

    printf("[INFO] TC 程序 %s 挂载成功\n", TC_BPF_OBJ);

    int xdp_prog_fd;
    struct bpf_object *xdp_obj = NULL;
    ret = load_and_pin_bpf_prog(XDP_BPF_OBJ, XDP_BPF_DIR, XDP_PROG_BASE, &xdp_obj, &xdp_prog_fd);
    if (!ret) return false;

    if (!attach_xdp_prog(xdp_prog_fd, xdp_obj)) return false;

    printf("[INFO] XDP 程序 %s 挂载成功\n", XDP_BPF_OBJ);

    return ret;
}
