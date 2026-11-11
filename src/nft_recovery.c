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
 * nft_recovery.c - NFT 规则恢复模块实现
 *
 * 用于程序启动时从 NFT 规则重建 session 或清理残留规则
 */

#include "nft_recovery.h"
#include "nft.h"

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nftables/libnftables.h>

#include "cJSON.h"
#include "config.h"
#include "log.h"
#include "session.h"
#include "timer.h"
#include "utensils.h"
#include "app_events.h"

/**
 * 验证字符串是否是有效的 IP 地址格式
 * @param str 输入字符串
 * @return 1=有效, 0=无效
 */
static int is_valid_ip_string(const char* str) {
    struct in_addr addr;
    return inet_pton(AF_INET, str, &addr) == 1;
}

/**
 * 从 comment 字符串中提取 IP 地址
 * comment 格式可能是 "192.168.1.100" 或 "192.168.1.100_daddr"
 * @param comment comment 字符串
 * @param ip_out 输出的 IP 地址
 * @return 0=成功, -1=失败
 */
static int extract_ip_from_comment(const char* comment, uint32_t* ip_out) {
    if (!comment || !ip_out) {
        return -1;
    }

    // 直接尝试解析
    if (is_valid_ip_string(comment)) {
        struct in_addr addr;
        inet_pton(AF_INET, comment, &addr);
        *ip_out = addr.s_addr;
        return 0;
    }

    // 尝试去除 "_daddr" 后缀
    size_t len = strlen(comment);
    const size_t suffix_len = strlen("_daddr");
    if (len > suffix_len &&
        strcmp(comment + len - suffix_len, "_daddr") == 0) {
        char ip_str[64];
        if (len - suffix_len >= sizeof(ip_str)) {
            return -1;
        }
        memcpy(ip_str, comment, len - suffix_len);
        ip_str[len - suffix_len] = '\0';

        if (is_valid_ip_string(ip_str)) {
            struct in_addr addr;
            inet_pton(AF_INET, ip_str, &addr);
            *ip_out = addr.s_addr;
            return 0;
        }
    }

    return -1;
}

/**
 * 扫描 NFT filter.forward 链，提取所有认证规则
 */
int scan_nft_authed_rules(void* nft_ctx, recovered_nft_rule_t** rules_out, int* count_out) {
    struct nft_ctx* nft = (struct nft_ctx*)nft_ctx;
    char* output = NULL;
    size_t output_size = 0;
    recovered_nft_rule_t* rules = NULL;
    int count = 0;
    int capacity = 64;
    int parse_error = 0;

    if (!nft || !rules_out || !count_out) {
        return -1;
    }

    rules = (recovered_nft_rule_t*)calloc(capacity, sizeof(recovered_nft_rule_t));
    if (!rules) {
        log_error("scan_nft_authed_rules: failed to allocate rules array");
        return -1;
    }

    FILE* mem_stream = open_memstream(&output, &output_size);
    if (!mem_stream) {
        free(rules);
        return -1;
    }

    nft_ctx_set_output(nft, mem_stream);
    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);

    // 列出 webauthd_filter forward 链的规则
    int ret = nft_run_cmd_from_buffer(nft, "list chain ip " NFT_TABLE_FILTER " forward");
    fflush(mem_stream);
    nft_ctx_set_output(nft, stdout);
    fclose(mem_stream);

    if (ret != 0 || !output) {
        log_warn("scan_nft_authed_rules: failed to list chain or empty output");
        free(rules);
        if (output) free(output);
        return -1;
    }

    // 解析 JSON
    cJSON* root = cJSON_Parse(output);
    if (!root) {
        log_error("scan_nft_authed_rules: failed to parse JSON");
        free(rules);
        free(output);
        return -1;
    }

    // 遍历 nftables 数组，查找规则
    cJSON* nftables = cJSON_GetObjectItem(root, "nftables");
    if (nftables && nftables->type == cJSON_Array) {
        for (cJSON* item = nftables->child; item; item = item->next) {
            cJSON* rule = cJSON_GetObjectItem(item, "rule");
            if (!rule) continue;

            // 检查是否有 comment（认证规则用 IP 作为 comment）
            cJSON* comment = cJSON_GetObjectItem(rule, "comment");
            if (!comment || comment->type != cJSON_String) continue;

            const char* comment_str = comment->valuestring;

            // 解析 IP 地址
            uint32_t ip;
            if (extract_ip_from_comment(comment_str, &ip) != 0) {
                continue;  // 不是有效的认证规则 comment
            }

            // 获取 handle
            cJSON* handle_obj = cJSON_GetObjectItem(rule, "handle");
            if (!handle_obj || handle_obj->type != cJSON_Number) continue;
            uint64_t handle = (uint64_t)handle_obj->valuedouble;

            // 查找或创建规则记录
            int found = -1;
            for (int j = 0; j < count; j++) {
                if (rules[j].ip == ip) {
                    found = j;
                    break;
                }
            }

            if (found < 0) {
                // 新规则
                if (count >= capacity) {
                    capacity *= 2;
                    recovered_nft_rule_t* new_rules = (recovered_nft_rule_t*)realloc(rules,
                        capacity * sizeof(recovered_nft_rule_t));
                    if (!new_rules) {
                        log_error("scan_nft_authed_rules: failed to realloc rules array");
                        cJSON_Delete(root);
                        free(rules);
                        free(output);
                        return -1;
                    }
                    rules = new_rules;
                }
                rules[count].ip = ip;
                rules[count].src_handle = 0;
                rules[count].dest_handle = 0;
                rules[count].in_bytes = 0;
                rules[count].out_bytes = 0;
                rules[count].invalid = 0;
                found = count++;
            }

            // 判断是 src 还是 dest 规则。正常 nft JSON 结构为
            // expr[].match.left.payload，而不是 expr[].payload。
            cJSON* expr_array = cJSON_GetObjectItem(rule, "expr");
            if (expr_array && expr_array->type == cJSON_Array) {
                const char* direction = NULL;
                uint64_t counter_bytes = 0;
                for (cJSON* expr = expr_array->child; expr; expr = expr->next) {
                    cJSON* match = cJSON_GetObjectItem(expr, "match");
                    cJSON* left = match ? cJSON_GetObjectItem(match, "left") : NULL;
                    cJSON* payload = left ? cJSON_GetObjectItem(left, "payload") : NULL;
                    if (payload && match) {
                        cJSON* field = cJSON_GetObjectItem(payload, "field");
                        cJSON* right = cJSON_GetObjectItem(match, "right");
                        if (field && field->type == cJSON_String && right &&
                            right->type == cJSON_String &&
                            ((strcmp(field->valuestring, "saddr") == 0) ||
                             (strcmp(field->valuestring, "daddr") == 0)) &&
                            is_valid_ip_string(right->valuestring)) {
                            struct in_addr right_addr;
                            inet_pton(AF_INET, right->valuestring, &right_addr);
                            if (right_addr.s_addr == ip) {
                                direction = field->valuestring;
                            }
                        }
                    }
                    cJSON* counter = cJSON_GetObjectItem(expr, "counter");
                    if (counter) {
                        cJSON* bytes_obj = cJSON_GetObjectItem(counter, "bytes");
                        if (bytes_obj && bytes_obj->type == cJSON_Number) {
                            counter_bytes = (uint64_t)bytes_obj->valuedouble;
                        }
                    }
                }
                if (direction && strcmp(direction, "saddr") == 0) {
                    if (rules[found].src_handle != 0) {
                        log_warn("scan_nft_authed_rules: duplicate saddr rule for comment %s",
                                 comment_str);
                        rules[found].invalid = 1;
                    }
                    rules[found].src_handle = handle;
                    rules[found].out_bytes = counter_bytes;
                } else if (direction && strcmp(direction, "daddr") == 0) {
                    if (rules[found].dest_handle != 0) {
                        log_warn("scan_nft_authed_rules: duplicate daddr rule for comment %s",
                                 comment_str);
                        rules[found].invalid = 1;
                    }
                    rules[found].dest_handle = handle;
                    rules[found].in_bytes = counter_bytes;
                } else {
                    log_error("scan_nft_authed_rules: rule with IP comment %s "
                              "has no matching IPv4 saddr/daddr expression",
                              comment_str);
                    parse_error = 1;
                }
            }
        }
    }

    cJSON_Delete(root);
    free(output);

    if (parse_error) {
        free(rules);
        return -1;
    }

    *rules_out = rules;
    *count_out = count;

    log_info("scan_nft_authed_rules: found %d authed rules in NFT", count);
    return 0;
}

/**
 * 清理残留的 NFT 规则（用于 FLUSH 模式）
 */
int flush_nft_authed_rules(void* nft_ctx) {
    struct nft_ctx* nft = (struct nft_ctx*)nft_ctx;
    if (!nft) {
        return -1;
    }

    log_warn("flush_nft_authed_rules: clearing all authed rules from NFT");

    // 清空 NAT authed 集合
    if (nft_run_cmd_from_buffer(nft, "flush set ip " NFT_TABLE_NAT " authed") != 0) {
        log_error("flush_nft_authed_rules: failed to flush NAT authed set");
        return -1;
    }

    // 注意：不清空 filter.forward 链，因为白名单规则可能也在里面
    // 需要通过扫描规则精确删除

    /* A scan groups rules by IP.  Re-scan after each pass so duplicate rules
     * (which share an IP/direction) are all removed rather than only the last
     * handle seen.  The finite bound prevents malformed output from looping. */
    for (int pass = 0; pass < 1024; pass++) {
        recovered_nft_rule_t* rules = NULL;
        int count = 0;
        int deleted = 0;

        if (scan_nft_authed_rules(nft, &rules, &count) != 0) {
            return -1;
        }
        if (count == 0) {
            free(rules);
            return 0;
        }

        for (int i = 0; i < count; i++) {
            char cmd[256];
            if (rules[i].src_handle != 0) {
                snprintf(cmd, sizeof(cmd), "delete rule ip " NFT_TABLE_FILTER
                         " forward handle %llu",
                         (unsigned long long)rules[i].src_handle);
                if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
                    free(rules);
                    return -1;
                }
                deleted++;
            }
            if (rules[i].dest_handle != 0) {
                snprintf(cmd, sizeof(cmd), "delete rule ip " NFT_TABLE_FILTER
                         " forward handle %llu",
                         (unsigned long long)rules[i].dest_handle);
                if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
                    free(rules);
                    return -1;
                }
                deleted++;
            }
        }
        free(rules);
        if (deleted == 0) {
            log_error("flush_nft_authed_rules: scan found rules but no deletable handles");
            return -1;
        }
    }

    log_error("flush_nft_authed_rules: duplicate-rule cleanup exceeded safety bound");
    return -1;
}

/**
 * 执行 NFT 恢复流程
 */
int nft_recovery_init(struct inst_t* inst, int mode) {
    int result = 0;

    if (!inst) {
        return -1;
    }

    if (mode == NFT_RECOVERY_MODE_NONE) {
        log_info("nft_recovery_init: recovery disabled, skipping");
        return 0;
    }

    // 创建临时 NFT 上下文
    struct nft_ctx* nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        log_error("nft_recovery_init: failed to create NFT context");
        return -1;
    }

    if (mode == NFT_RECOVERY_MODE_FLUSH) {
        log_warn("nft_recovery_init: FLUSH mode - clearing all authed rules");
        if (flush_nft_authed_rules(nft) != 0) {
            nft_ctx_free(nft);
            return -1;
        }
    } else if (mode == NFT_RECOVERY_MODE_SCAN) {
        log_info("nft_recovery_init: SCAN mode - rebuilding sessions from NFT rules");

        recovered_nft_rule_t* rules = NULL;
        int count = 0;

        if (scan_nft_authed_rules(nft, &rules, &count) != 0) {
            result = -1;
        } else {
            /* Validate the entire snapshot before mutating any session.  A
             * partial or duplicate pair is ambiguous and must fail closed. */
            for (int i = 0; i < count; i++) {
                if (rules[i].invalid || rules[i].src_handle == 0 ||
                    rules[i].dest_handle == 0) {
                    struct in_addr bad_addr;
                    bad_addr.s_addr = rules[i].ip;
                    log_error("nft_recovery_init: ambiguous/incomplete rules for %s",
                              inet_ntoa(bad_addr));
                    result = -1;
                    break;
                }
            }

            if (result == 0 && count > 0) {
                log_info("nft_recovery_init: found %d complete rule pairs", count);
                for (int i = 0; i < count; i++) {
                    uint8_t mac[6] = {0};
                    struct user_session_t* user = find_user(inst, rules[i].ip, mac);
                    if (!user) {
                        user = create_user(inst, rules[i].ip, mac);
                    }
                    if (!user) {
                        log_error("nft_recovery_init: failed to allocate recovered session");
                        result = -1;
                        break;
                    }

                    user->nft_src_handle = rules[i].src_handle;
                    user->nft_dest_handle = rules[i].dest_handle;
                    user->nft_rules_state = NFT_RULES_ACTIVE;
                    user->inbytes = rules[i].in_bytes;
                    user->outbytes = rules[i].out_bytes;
                    /* 与 nft.c update_session 的增量累加基线保持一致:
                     * 恢复的计数是规则当前原始采样值, 会话累计值从该值起算 */
                    user->prev_inbytes = rules[i].in_bytes;
                    user->prev_outbytes = rules[i].out_bytes;
                    user->status = USER_STATE_AUTHED;

                    /*
                     * 重启后无法从 nft 规则还原用户身份(Acct-Session-Id /
                     * User-Name 均为空), 因此该会话:
                     *   1) 时长锚点置为当前时间, 避免后续 now-0 计算出
                     *      天文数字的在线时长;
                     *   2) acct_enable 清零, 关闭时不再以空身份向 RADIUS
                     *      发 Accounting-Stop(否则产生垃圾账务记录);
                     *   3) 按本地配置的空闲超时接管生命周期, 避免恢复出来
                     *      的会话永久放行、无任何超时约束。
                     */
                    user->acct_start_time = get_now_time();
                    user->start_time = user->acct_start_time;
                    user->acct_enable = 0;
                    user->idle_timeout =
                        (inst->config->idle_timeout > 0)
                            ? (long)inst->config->idle_timeout
                            : 0;
                    if (start_idle_check_timer(user) != 0) {
                        struct in_addr rec_addr;
                        rec_addr.s_addr = rules[i].ip;
                        log_warn("nft_recovery_init: idle timer start failed for %s",
                                 inet_ntoa(rec_addr));
                    }
                }
            }
            free(rules);
        }
    } else {
        log_error("nft_recovery_init: invalid recovery mode=%d", mode);
        result = -1;
    }

    nft_ctx_free(nft);
    return result;
}
