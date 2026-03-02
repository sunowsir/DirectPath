/*
 * File     : nft_rule.c
 * Author   : sun.wang
 * Mail     : sunowsir@163.com
 * Github   : github.com/sunowsir
 * Creation : 2026-03-02 20:44:32
*/

#include <nftables/libnftables.h>

#include "direct_path_user.h"
#include "direct_path_nft_rule.h"

/* * 清理函数：对应脚本中的 clean_all 部分
 */
void cleanup_nft_rules() {
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return ;

    /* 抑制输出，我们只关心返回值，不想让查询失败的错误信息污染屏幕 */
    nft_ctx_buffer_error(ctx);
    nft_ctx_buffer_output(ctx);

    nft_run_cmd_from_buffer(ctx, "delete table inet bpf_accel");
    nft_ctx_free(ctx);

    printf("[INFO] nftables 规则已清理\n");

    return ;
}

/* * 动态构造并执行 nft 命令
 * 模拟脚本中的 nft_rule_set 函数
 */
bool setup_nft_rules() {
    cleanup_nft_rules();

    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) {
        fprintf(stderr, "Failed to create nftables context\n");
        return false;
    }

    // 捕获错误信息到缓冲区以便调试
    nft_ctx_buffer_error(ctx);

    /* * 使用 snprintf 构造整套规则。
     * 逻辑说明：
     * 1. 删除旧表
     * 2. 创建新表、Flowtable 和 计数器
     * 3. 按照脚本中的优先级配置 hook 点
     */
    char cmd_buf[NFT_CMD_BUF_MAXLEN] = {0};
    snprintf(cmd_buf, sizeof(cmd_buf),
        "add table inet bpf_accel\n"
        
        // Flowtable: 绑定 LAN 和 WAN 接口
        "add flowtable inet bpf_accel ft { hook ingress priority 0; devices = { %s, %s }; }\n"
        
        // 计数器
        "add counter inet bpf_accel bypass_clash_cnt\n"
        "add counter inet bpf_accel local_accel_in\n"
        
        // 链定义 (使用脚本中的优先级)
        "add chain inet bpf_accel early_bypass { type filter hook prerouting priority %d; policy accept; }\n"
        "add chain inet bpf_accel forward      { type filter hook forward    priority %d; policy accept; }\n"
        "add chain inet bpf_accel input        { type filter hook input      priority %d; policy accept; }\n"
        "add chain inet bpf_accel output       { type filter hook output     priority %d; policy accept; }\n"
        
        // 规则 A: BYPASS 逻辑
        "add rule inet bpf_accel early_bypass meta mark & 0xff000000 == %u counter name bypass_clash_cnt accept\n"
        
        // 规则 B: Forward 链联动 Flowtable
        "add rule inet bpf_accel forward meta mark & 0xff000000 == %u ct state established flow add @ft\n"
        "add rule inet bpf_accel forward meta mark & 0xff000000 == %u ct state established accept\n"
        
        // 规则 C: 本地流量
        "add rule inet bpf_accel input  meta mark & 0xff000000 == %u ct state established counter name local_accel_in accept\n"
        "add rule inet bpf_accel output meta mark & 0xff000000 == %u ct state established accept\n",
        
        LAN_IF, WAN_IF,
        BYPASS_PRIORITY, BPF_ACCEL_FORWARD_PRIORITY, BPF_ACCEL_INPUT_PRIORITY, BPF_ACCEL_OUTPUT_PRIORITY,
        DIRECT_MARK, // early_bypass
        DIRECT_MARK, // forward flow add
        DIRECT_MARK, // forward accept
        DIRECT_MARK, // input
        DIRECT_MARK  // output
    );

    // 执行命令
    int res = nft_run_cmd_from_buffer(ctx, cmd_buf);

    if (res != 0) {
        fprintf(stderr, "[ERROR] nft 规则下发失败:\n%s", nft_ctx_get_error_buffer(ctx));
        nft_ctx_free(ctx);
        return false;
    }

    printf("[INFO] nftables 规则联动配置成功\n");
    nft_ctx_free(ctx);
    return true;
}
