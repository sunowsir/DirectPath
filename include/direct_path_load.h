/*
 * File     : direct_path_load.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 17:40:28
*/

#ifndef DIRECT_PATH_LOAD_H_H
#define DIRECT_PATH_LOAD_H_H

/* 安装所有 */
#define LOAD_ARGS_INSTALL          "install"

/* 卸载所有 */
#define LOAD_ARGS_UNINSTALL        "uninstall"

/* load 参数最少数量 */
#define LOAD_ARGS_MIN_NUM           2

int load_main(int argc, char **argv);

#endif

