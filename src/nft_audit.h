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
 * nft_audit.h - NFT 规则审计模块头文件
 *
 * 用于定期验证 session 的 NFT handle 是否仍然存在，
 * 检测外部程序删除 NFT 规则导致的不一致
 */

#ifndef NFT_AUDIT_H
#define NFT_AUDIT_H

#include "instance.h"

// 默认审计间隔（秒）
#define NFT_AUDIT_DEFAULT_INTERVAL  60

/**
 * 启动 NFT 审计定时器
 * @param inst 实例指针
 * @param interval_sec 审计间隔（秒），0 使用默认值
 * @return 0=成功, -1=失败
 */
int start_nft_audit_timer(struct inst_t* inst, int interval_sec);

/**
 * 停止 NFT 审计定时器
 * @param inst 实例指针
 * @return 0=成功, -1=失败
 */
int stop_nft_audit_timer(struct inst_t* inst);

/**
 * 执行一次 NFT 审计（可手动调用）
 * @param inst 实例指针
 * @return 发现的不一致数量
 */
int nft_audit_run(struct inst_t* inst);

/**
 * 验证单个 NFT handle 是否仍然存在
 * @param nft NFT 上下文
 * @param family 协议族
 * @param table 表名
 * @param chain 链名
 * @param handle 规则 handle
 * @return 1=存在, 0=不存在, -1=错误
 */
int verify_nft_handle_exists(void* nft, uint32_t family,
                              const char* table, const char* chain,
                              uint64_t handle);

#endif /* NFT_AUDIT_H */
