/*
 * File     : load.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 17:42:11
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "direct_path_prepare.h"
#include "direct_path_prog_load.h"

#include "direct_path_load.h"

int load_install(int argc, char **argv) {
    if (!create_map_all()) {
        umount_map_all();
        fprintf(stderr, "[ERRO] create_map_all failed\n");
        return -1; 
    }

    if(!load_and_pin_bpf_all()) return false;

    return 0;
}

int load_uninstall(int argc, char **argv) {
    if (!umount_map_all()) return -1;
    return 0;
}

int load_args_parse(int argc, char **argv) {
    if (argc < LOAD_ARGS_MIN_NUM) return -1;

    if (!strcmp(argv[2], LOAD_ARGS_INSTALL)) return load_install(argc, argv);
    else if (!strcmp(argv[2], LOAD_ARGS_UNINSTALL)) return load_uninstall(argc, argv);

    return 0;
}

int load_main(int argc, char **argv) {
    return load_args_parse(argc, argv);
}
