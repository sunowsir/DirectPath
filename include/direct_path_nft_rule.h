/*
 * File     : direct_path_nft_rule.h
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 20:44:59
*/

#ifndef DIRECT_PATH_NFT_RULE_H_H
#define DIRECT_PATH_NFT_RULE_H_H

#include <stdbool.h>

/*nft 优先级配置 */
/* 抢在 OpenClash (-150/-100) 之前，也就是 mangle 之前，mangle - 1 */
#define BYPASS_PRIORITY                 -151
#define BPF_ACCEL_FORWARD_PRIORITY      1
#define BPF_ACCEL_INPUT_PRIORITY        1
#define BPF_ACCEL_OUTPUT_PRIORITY       -151

#define NFT_CMD_BUF_MAXLEN              2048

bool setup_nft_rules();
bool cleanup_nft_rules();

#endif

