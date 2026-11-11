/*
 * webauthd - Web authentication daemon
 * Copyright (C) 2021-2026  MonkFish <5747844@qq.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * nft_recovery.h - NFT 规则恢复模块头文件
 *
 * 用于程序启动时从 NFT 规则重建 session 或清理残留规则
 */

#ifndef NFT_RECOVERY_H
#define NFT_RECOVERY_H

#include "instance.h"

// NFT 恢复模式
#define NFT_RECOVERY_MODE_NONE   0   // 禁用恢复
#define NFT_RECOVERY_MODE_SCAN   1   // 扫描 NFT 规则重建 session
#define NFT_RECOVERY_MODE_FLUSH  2   // 清空 NFT 规则（更安全但影响可用性）

// 从 NFT 规则恢复的会话信息
typedef struct {
    uint32_t ip;
    uint64_t src_handle;
    uint64_t dest_handle;
    uint64_t in_bytes;
    uint64_t out_bytes;
    int invalid;              /* duplicate/ambiguous rules must not be restored */
} recovered_nft_rule_t;

/**
 * 执行 NFT 恢复流程
 * @param inst 实例指针
 * @param mode 恢复模式（NONE/SCAN/FLUSH）
 * @return 0=成功, -1=失败
 */
int nft_recovery_init(struct inst_t* inst, int mode);

/**
 * 扫描 NFT filter.forward 链，提取所有认证规则
 * @param nft NFT 上下文
 * @param rules_out 返回的规则数组
 * @param count_out 返回的规则数量
 * @return 0=成功, -1=失败
 */
int scan_nft_authed_rules(void* nft, recovered_nft_rule_t** rules_out, int* count_out);

/**
 * 清理残留的 NFT 规则（用于 FLUSH 模式）
 * @param nft NFT 上下文
 * @return 0=成功, -1=失败
 */
int flush_nft_authed_rules(void* nft);

#endif /* NFT_RECOVERY_H */
