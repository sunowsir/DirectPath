/*
 * File     : direct_path.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 17:35:00
*/

#include "direct_path_user.h"
#include "direct_path_load.h"
#include "direct_path_rule.h"

int direct_path_args_parse(int argc, char **argv) {
    if (argc < DIRECT_PATH_USER_VALID_ARGS_NUM) return -1;

    if (!strcmp(argv[1], DIRECT_PATH_LOAD_ARGS)) return load_main(argc, argv);
    else if (!strcmp(argv[1], DIRECT_PATH_RULE_ARGS)) return rule_main(argc, argv);

    return 0;
}

int main(int argc, char **argv) {
    return direct_path_args_parse(argc, argv);
}
