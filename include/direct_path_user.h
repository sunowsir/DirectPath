/*
 * File     : direct_path_import.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-02-26 21:48:49
*/

#ifndef DIRECT_PATH_IMPORT_H_H
#define DIRECT_PATH_IMPORT_H_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <linux/stddef.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#ifndef likely
#define likely(x)      (__builtin_expect(!!(x), 1))
#endif

#ifndef unlikely
#define unlikely(x)    (__builtin_expect(!!(x), 0))
#endif

#endif

