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
 * nft_audit.c - NFT 规则审计模块实现
 *
 * 用于定期验证 session 的 NFT handle 是否仍然存在，
 * 检测外部程序删除 NFT 规则导致的不一致
 */

#include "nft_audit.h"
#include "nft.h"

#include <arpa/inet.h>
#include <event.h>
#include <linux/netfilter.h>
#include <nftables/libnftables.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_events.h"
#include "cJSON.h"
#include "log.h"
#include "session.h"

/**
 * 验证单个 NFT handle 是否仍然存在
 *
 * 返回值:
 *    1 - 规则存在
 *    0 - 查询成功但确认该 handle 不存在(规则确已被外部删除)
 *   -1 - 查询/解析过程出错(libnftables 失败等), 调用方不得据此下线用户
 *
 * 注意: 不能用 strstr(output, "\"handle\":N") 这类裸子串匹配, 因为不同
 * nftables 版本的 JSON 可能是 "handle":N 或 "handle": N(冒号后带空格),
 * 一旦匹配失败会把仍然存在的规则误判为丢失。这里与建规则时
 * (get_rule_handle_by_ip_and_direction)保持一致, 使用 cJSON 精确解析。
 */
int verify_nft_handle_exists(void* nft_ctx, uint32_t family,
                              const char* table, const char* chain,
                              uint64_t handle) {
    struct nft_ctx* nft = (struct nft_ctx*)nft_ctx;
    char cmd[256];
    char* output = NULL;
    size_t output_size = 0;
    int result = -1; /* 默认按"查询出错"处理, 避免误下线 */

    (void)family;

    if (!nft || !table || !chain || handle == 0) {
        return -1;
    }

    FILE* mem_stream = open_memstream(&output, &output_size);
    if (!mem_stream) {
        return -1;
    }

    nft_ctx_set_output(nft, mem_stream);
    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);

    snprintf(cmd, sizeof(cmd), "list chain ip %s %s", table, chain);

    int run_rc = nft_run_cmd_from_buffer(nft, cmd);
    fflush(mem_stream);  /* open_memstream 缓冲区须 flush 后才更新 output */
    if (run_rc == 0 && output) {
        cJSON* root = cJSON_Parse(output);
        if (root) {
            /* 命令执行且 JSON 解析成功, 默认未找到(确认不存在) */
            result = 0;
            cJSON* nftables = cJSON_GetObjectItem(root, "nftables");
            if (nftables && (nftables->type == cJSON_Array)) {
                for (cJSON* item = nftables->child; item; item = item->next) {
                    cJSON* rule = item ? cJSON_GetObjectItem(item, "rule") : NULL;
                    cJSON* table_field = NULL;
                    cJSON* chain_field = NULL;
                    cJSON* handle_field = NULL;

                    if (!rule) {
                        continue;
                    }

                    table_field = cJSON_GetObjectItem(rule, "table");
                    chain_field = cJSON_GetObjectItem(rule, "chain");
                    handle_field = cJSON_GetObjectItem(rule, "handle");

                    if (table_field && chain_field && handle_field &&
                        (table_field->type == cJSON_String) &&
                        (chain_field->type == cJSON_String) &&
                        (handle_field->type == cJSON_Number) &&
                        strcmp(table_field->valuestring, table) == 0 &&
                        strcmp(chain_field->valuestring, chain) == 0 &&
                        (uint64_t)handle_field->valuedouble == handle) {
                        result = 1;
                        break;
                    }
                }
            }
            cJSON_Delete(root);
        }
    }

    nft_ctx_set_output(nft, stdout);
    fclose(mem_stream);
    if (output) {
        free(output);
    }

    return result;
}

/**
 * NFT 审计定时器回调函数
 */
static void nft_audit_timer_cb(const int fd, const short event, void* arg) {
    struct inst_t* inst = (struct inst_t*)arg;
    nft_audit_run(inst);
}

/**
 * 执行一次 NFT 审计
 */
int nft_audit_run(struct inst_t* inst) {
    if (!inst) {
        return 0;
    }

    struct nft_ctx* nft = init_nft_ctx();
    if (!nft) {
        log_error("nft_audit_run: failed to init nft context");
        return 0;
    }

    int mismatch_count = 0;

    // 定义回调函数，遍历所有会话进行审计
    void audit_user(struct user_session_t* user, void* ctx) {
        struct nft_ctx* nft_ctx = (struct nft_ctx*)ctx;
        int* count = &mismatch_count; // 捕获局部变量

        // 检查用户有效性
        if (!user_is_valid(user)) {
            return;
        }

        // 仅审计 ACTIVE 状态的 NFT 规则
        if (user->nft_rules_state != NFT_RULES_ACTIVE) {
            return;
        }

        // 验证 handle 是否存在。返回 -1 表示查询/解析出错
        int src_exists = verify_nft_handle_exists(nft_ctx, NFPROTO_IPV4, NFT_TABLE_FILTER, "forward",
                                                   user->nft_src_handle);
        int dest_exists = verify_nft_handle_exists(nft_ctx, NFPROTO_IPV4, NFT_TABLE_FILTER, "forward",
                                                    user->nft_dest_handle);

        // 任一查询出错都不能据此下线(可能是 libnftables 瞬时失败), 跳过本轮
        if (src_exists == -1 || dest_exists == -1) {
            struct in_addr ip_addr;
            ip_addr.s_addr = user->ip;
            log_warn("nft_audit_run: query error for %s (src=%d, dest=%d), skip this round",
                     inet_ntoa(ip_addr), src_exists, dest_exists);
            return;
        }

        if (src_exists == 0 || dest_exists == 0) {
            struct in_addr ip_addr;
            ip_addr.s_addr = user->ip;
            char* ip_str = inet_ntoa(ip_addr);

            /*
             * handle 漂移兜底: nft 表被外部 reload / mwan3 restart 全量重建 /
             * 或规则被其他程序 delete+add 后, 内核会重新分配 handle,
             * 但规则本身还在。session 里存的旧 handle 就查不到。
             * 此时若直接用旧 handle 判定"规则丢失"会误下线在线用户,
             * 出现"会话被删但 nft 规则残留"的不一致。
             *
             * 修复: handle 找不到时, 用 IP + 方向再查一次 ——
             *   查到 → 仅 handle 漂移, 回填新 handle, 跳过下线
             *   查不到 → 规则真丢失, 走正常下线流程
             */
            uint64_t new_src = 0, new_dest = 0;
            if (src_exists == 0) {
                new_src = get_rule_handle_by_ip_and_direction(
                    nft_ctx, NFT_TABLE_FILTER, "forward", ip_str, "saddr");
            }
            if (dest_exists == 0) {
                new_dest = get_rule_handle_by_ip_and_direction(
                    nft_ctx, NFT_TABLE_FILTER, "forward", ip_str, "daddr");
            }

            int src_ok  = (src_exists  == 1) || (new_src  != 0);
            int dest_ok = (dest_exists == 1) || (new_dest != 0);

            if (src_ok && dest_ok) {
                if (new_src  != 0) user->nft_src_handle  = new_src;
                if (new_dest != 0) user->nft_dest_handle = new_dest;
                log_info(
                    "nft_audit_run: %s handle drifted, refreshed "
                    "(src=%llu dest=%llu), keep session",
                    ip_str, (unsigned long long)user->nft_src_handle,
                    (unsigned long long)user->nft_dest_handle);
                return;
            }

            log_warn(
                "nft_audit_run: rule confirmed missing for %s "
                "(src_exists=%d new_src=%llu, dest_exists=%d new_dest=%llu)",
                ip_str, src_exists, (unsigned long long)new_src, dest_exists,
                (unsigned long long)new_dest);

            (*count)++;

            /*
             * 不能只把 status 直接置成 DROPPING: 那样既不发 Accounting-Stop,
             * 也不删 nft 规则/会话, 用户会一直挂在 DROPPING —— 周期计费更新
             * (只在 AUTHED 状态发送)会被永久跳过, 表现为"不发记账更新报文"。
             * 确认规则丢失时, 对在线(AUTHED/FREE)会话走统一的关闭流程:
             * 置 DROPPING -> RADIUS 有效则发 Stop -> 删规则 -> 删会话。
             */
            if (user->status == USER_STATE_AUTHED ||
                user->status == USER_STATE_FREE) {
                process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
            }
            /* 关闭流程可能释放该 user, 之后不再解引用 */
            return;
        }
    }

    for_each_user_session(audit_user, nft);

    nft_ctx_free(nft);

    if (mismatch_count > 0) {
        log_warn("nft_audit_run: found %d sessions with mismatched NFT rules", mismatch_count);
    }

    return mismatch_count;
}

/**
 * 启动 NFT 审计定时器
 */
int start_nft_audit_timer(struct inst_t* inst, int interval_sec) {
    if (!inst || !inst->base) {
        return -1;
    }

    int interval = interval_sec > 0 ? interval_sec : NFT_AUDIT_DEFAULT_INTERVAL;

    struct timeval tv;
    tv.tv_sec = interval;
    tv.tv_usec = 0;

    inst->ev_nft_audit_timer = event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                                          nft_audit_timer_cb, (void*)inst);
    if (!inst->ev_nft_audit_timer) {
        log_error("start_nft_audit_timer: failed to create timer");
        return -1;
    }

    if (event_add(inst->ev_nft_audit_timer, &tv) < 0) {
        log_error("start_nft_audit_timer: failed to add timer");
        event_free(inst->ev_nft_audit_timer);
        inst->ev_nft_audit_timer = NULL;
        return -1;
    }

    log_info("start_nft_audit_timer: started (interval=%ds)", interval);
    return 0;
}

/**
 * 停止 NFT 审计定时器
 */
int stop_nft_audit_timer(struct inst_t* inst) {
    if (!inst) {
        return -1;
    }

    if (inst->ev_nft_audit_timer) {
        event_del(inst->ev_nft_audit_timer);
        event_free(inst->ev_nft_audit_timer);
        inst->ev_nft_audit_timer = NULL;
        log_info("stop_nft_audit_timer: stopped");
    }

    return 0;
}
