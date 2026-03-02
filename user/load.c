/*
 * File     : load.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 17:42:11
*/

#include <stdio.h>
#include <stdbool.h>

#include "direct_path_load.h"
#include "direct_path_prepare.h"
#include "direct_path_prog_load.h"
#include "direct_path_nft_rule.h"

int load_main(int argc, char **argv) {
    if (!create_map_all()) {
        umount_map_all();
        fprintf(stderr, "[ERRO] create_map_all failed\n");
        return -1; 
    }

    if(!load_and_pin_bpf_all()) return false;

    if (!setup_nft_rules()) {
        cleanup_nft_rules();
        fprintf(stderr, "[ERRO] setup_nft_rules failed\n");
        return -1;
    }
    
    return 0;
}
