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
#include "nft.h"

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>
#include <nftables/libnftables.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "cJSON.h"
#include "app_events.h"
#include "config.h"
#include "instance.h"
#include "log.h"
#include "session.h"

struct nft_ctx* init_nft_ctx(void) {
  struct nft_ctx* nft;

  nft = nft_ctx_new(NFT_CTX_DEFAULT);
  if (!nft) {
    fprintf(stderr, "Failed to initialize nftables context: %s\n",
            strerror(errno));
    return NULL;
  }

  // 设置输出为 JSON 格式（可选）
  // nft_ctx_output_set_json(nft, 0);

  return nft;
}

int check_and_add_whitelist_rules(struct nft_ctx* nft) {
  const char* check_cmd = "list table ip " NFT_TABLE_FILTER;
  char* output = NULL;
  size_t output_size = 0;
  int ret;

  FILE* mem_stream = open_memstream(&output, &output_size);  // 内存流
  if (!mem_stream) {
    perror("open_memstream failed");
    return -1;
  }

  nft_ctx_set_output(nft, mem_stream);

  nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_TERSE);
  // 执行 list 命令获取当前规则
  ret = nft_run_cmd_from_buffer(nft, check_cmd);
  fflush(mem_stream);
  nft_ctx_set_output(nft, stdout);
  fclose(mem_stream);
  if (ret != 0) {
    //  fprintf(stderr, "Failed to list nftables rules: %s\n",
    //  nft_ctx_get_error(nft));
    free(output);
    return -1;
  }

  if (!output) {
    fprintf(stderr, "Error: n");
    return -1;
  }

  // printf("+nft ruleset ++++++++++++++++++++++++++++++++++%s\n",output);
  // 检查规则是否存在
  int daddr_rule_exists = 0;
  int saddr_rule_exists = 0;

  if (strstr(output, "ip daddr @white_list accept") != NULL) {
    daddr_rule_exists = 1;
  }
  if (strstr(output, "ip saddr @white_list accept") != NULL) {
    saddr_rule_exists = 1;
  }
  free(output);
  // free(output);

  // 如果两条规则都存在，直接返回
  if (daddr_rule_exists && saddr_rule_exists) {
    return 0;
  }

  // 构建添加规则的命令
  const char* add_cmd_template =
      "add rule ip " NFT_TABLE_FILTER " forward ip %s @white_list accept";

  if (daddr_rule_exists == 0) {
    char add_cmd[256];
    snprintf(add_cmd, sizeof(add_cmd), add_cmd_template, "daddr");

    ret = nft_run_cmd_from_buffer(nft, add_cmd);
    if (ret != 0) {
      // fprintf(stderr, "Failed to add daddr rule: %s\n",
      // nft_ctx_get_error(nft));
      return -1;
    }
  }

  if (saddr_rule_exists == 0) {
    char add_cmd[256];
    snprintf(add_cmd, sizeof(add_cmd), add_cmd_template, "saddr");

    ret = nft_run_cmd_from_buffer(nft, add_cmd);
    if (ret != 0) {
      //  fprintf(stderr, "Failed to add saddr rule: %s\n",
      //  nft_ctx_get_error(nft));
      return -1;
    }
  }

  return 0;
}

static int add_rule(struct nft_ctx* nft, const char* table_name,
                    const char* chain_name, uint32_t family, const char* match,
                    const char* target) {
  char cmd[1024];
  const char* family_str;

  switch (family) {
    case NFPROTO_IPV4:
      family_str = "ip";
      break;
    case NFPROTO_IPV6:
      family_str = "ip6";
      break;
    case NFPROTO_INET:
      family_str = "inet";
      break;
    case NFPROTO_BRIDGE:
      family_str = "bridge";
      break;
    case NFPROTO_NETDEV:
      family_str = "netdev";
      break;
    default:
      family_str = "ip";
      break;
  }

  snprintf(cmd, sizeof(cmd), "add rule %s %s %s %s %s", family_str, table_name,
           chain_name, match, target);

  if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
    fprintf(stderr, "Failed to add rule: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int add_elements_to_set(struct nft_ctx* nft, const char* table_name,
                               const char* set_name, uint32_t family,
                               const char* elements) {
  char cmd[1024];
  const char* family_str;

  switch (family) {
    case NFPROTO_IPV4:
      family_str = "ip";
      break;
    case NFPROTO_IPV6:
      family_str = "ip6";
      break;
    case NFPROTO_INET:
      family_str = "inet";
      break;
    case NFPROTO_BRIDGE:
      family_str = "bridge";
      break;
    case NFPROTO_NETDEV:
      family_str = "netdev";
      break;
    default:
      family_str = "ip";
      break;
  }

  snprintf(cmd, sizeof(cmd), "add element %s %s %s { %s }", family_str,
           table_name, set_name, elements);

  if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
    fprintf(stderr, "Failed to add elements to set %s: %s\n", set_name,
            strerror(errno));
    return -1;
  }

  return 0;
}


/**
 * 查找指定 comment 的规则对应的 handle
 * @param json_str 输入的 JSON 字符串
 * @param target_comment 要查找的 comment 内容
 * @param handles 返回的 handle 数组
 * @param max_handles 最大返回的 handle 数量
 * @return 实际找到的 handle 数量
 */

 #if 0
int find_handles_by_comment(const char *json_str, const char *target_comment, 
                           int *handles, int max_handles) {
    if (!json_str || !target_comment || !handles || max_handles <= 0) {
        return 0;
    }

    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        printf("JSON 解析失败\n");
        return 0;
    }

    cJSON *nftables = cJSON_GetObjectItem(root, "nftables");
    if (!nftables || !cJSON_IsArray(nftables)) {
        printf("未找到 nftables 数组\n");
        cJSON_Delete(root);
        return 0;
    }

    int found_count = 0;
    cJSON *item = NULL;
    
    cJSON_ArrayForEach(item, nftables) {
        if (found_count >= max_handles) {
            break;
        }

        // 查找 rule 对象
        cJSON *rule = cJSON_GetObjectItem(item, "rule");
        if (!rule) {
            continue;
        }

        // 查找 comment 字段
        cJSON *comment = cJSON_GetObjectItem(rule, "comment");
        if (!comment || !cJSON_IsString(comment)) {
            continue;
        }

        // 比较 comment 内容
        if (strcmp(comment->valuestring, target_comment) == 0) {
            // 查找 handle 字段
            cJSON *handle = cJSON_GetObjectItem(rule, "handle");
            if (handle && cJSON_IsNumber(handle)) {
                handles[found_count++] = handle->valueint;
            }
        }
    }

    cJSON_Delete(root);
    return found_count;
}
  
static int rule_exists_by_handle(struct nft_ctx* nft, const char* table_name,
                                const char* chain_name, uint32_t family,
                                uint64_t handle) {
  char cmd[256];
  char* output = NULL;
  size_t output_size = 0;
  int exists = 0;

  FILE* mem_stream = open_memstream(&output, &output_size);
  if (!mem_stream) {
    return -1;
  }

  nft_ctx_set_output(nft, mem_stream);
  // 使用 JSON 输出格式以提高准确性
  nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);
  nft_ctx_output_set_debug(nft, 0);

  const char* family_str;
  switch (family) {
    case NFPROTO_IPV4:
      family_str = "ip";
      break;
    case NFPROTO_IPV6:
      family_str = "ip6";
      break;
    default:
      family_str = "ip";
      break;
  }

  snprintf(cmd, sizeof(cmd), "list chain %s %s %s", family_str, table_name, chain_name);
  log_debug("rule exists by handle cmd: %s", cmd);
  
  int ret = nft_run_cmd_from_buffer(nft, cmd);
  nft_ctx_set_output(nft, stdout);
  fclose(mem_stream);
  
  if (ret == 0 && output) {
    // 在 JSON 输出中精确查找特定 handle
    char handle_pattern[64];
    snprintf(handle_pattern, sizeof(handle_pattern), "\"handle\":%llu",
             (unsigned long long)handle);
    
    if (strstr(output, handle_pattern) != NULL) {
      exists = 1;
    }
  }

  if (output) {
    free(output);
  }

  return exists;
}
 
 
 #endif
 

static int delete_rule_by_handle(struct nft_ctx* nft, const char* table_name,
                                 const char* chain_name, uint32_t family,
                                 uint64_t handle) {
  char cmd[256];
  const char* family_str;

  switch (family) {
    case NFPROTO_IPV4:
      family_str = "ip";
      break;
    case NFPROTO_IPV6:
      family_str = "ip6";
      break;
    case NFPROTO_INET:
      family_str = "inet";
      break;
    case NFPROTO_BRIDGE:
      family_str = "bridge";
      break;
    case NFPROTO_NETDEV:
      family_str = "netdev";
      break;
    default:
      family_str = "ip";
      break;
  }

  snprintf(cmd, sizeof(cmd), "delete rule %s %s %s handle %llu", family_str,
           table_name, chain_name, (unsigned long long)handle);
log_debug("delete rule by handle cmd: %s", cmd);
  if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
      log_error("Delete rule by handle failed: %s", cmd);
      return -1;
  }

  return 0;
}

static int find_rule_handle_by_ip_and_direction(
    struct nft_ctx* nft, const char* table_name, const char* chain_name,
    const char* ip_addr, const char* direction, uint64_t* handle_out);

/*
 * 按 IP + 方向(saddr/daddr) 删除 filter.forward 链中的规则。
 * nft 的 delete rule 只支持按 handle 删除, 没有按匹配条件删除的语法,
 * 因此先通过 JSON list 查出 handle 再按 handle 删; 循环清理同一 IP
 * 可能残留的多条重复规则, 查不到即结束。
 * 返回实际删除的规则条数。
 */
static int delete_rules_by_ip_direction(struct nft_ctx* nft, const char* ip_addr,
                                        const char* direction) {
  int deleted = 0;

  /* 上限防异常死循环; 正常情况下同一 IP 同方向只有 1 条规则 */
  for (int i = 0; i < 32; i++) {
    uint64_t handle = 0;
    int found = find_rule_handle_by_ip_and_direction(
        nft, NFT_TABLE_FILTER, "forward", ip_addr, direction, &handle);
    if (found < 0) {
      return -1;
    }
    if (found == 0) break;
    if (delete_rule_by_handle(nft, NFT_TABLE_FILTER, "forward",
                              NFPROTO_IPV4, handle) != 0) {
      return -1;
    }
    deleted++;
  }

  if (deleted == 32) {
    uint64_t remaining = 0;
    int found = find_rule_handle_by_ip_and_direction(
        nft, NFT_TABLE_FILTER, "forward", ip_addr, direction, &remaining);
    if (found != 0) {
      log_error("Too many or unqueryable duplicate nft rules for %s/%s",
                ip_addr, direction);
      return -1;
    }
  }

  return deleted;
}

static int json_contains_string(cJSON* node, const char* value) {
  cJSON* child;

  if (!node || !value) return 0;
  if (node->type == cJSON_String && node->valuestring &&
      strcmp(node->valuestring, value) == 0) {
    return 1;
  }
  for (child = node->child; child; child = child->next) {
    if (json_contains_string(child, value)) return 1;
  }
  return 0;
}

/* 1=存在，0=查询成功且不存在，-1=查询/解析失败。 */
static int nft_set_contains_element(struct nft_ctx* nft,
                                    const char* table_name,
                                    const char* set_name,
                                    const char* element) {
  char cmd[256];
  char* output = NULL;
  size_t output_size = 0;
  int result = -1;
  FILE* mem_stream = open_memstream(&output, &output_size);
  if (!mem_stream) return -1;

  nft_ctx_set_output(nft, mem_stream);
  nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);
  snprintf(cmd, sizeof(cmd), "list set ip %s %s", table_name, set_name);
  if (nft_run_cmd_from_buffer(nft, cmd) == 0) {
    fflush(mem_stream);
    if (output) {
      cJSON* root = cJSON_Parse(output);
      if (root) {
        cJSON* nftables = cJSON_GetObjectItem(root, "nftables");
        result = 0;
        if (nftables && nftables->type == cJSON_Array) {
          cJSON* item;
          for (item = nftables->child; item; item = item->next) {
            cJSON* set = cJSON_GetObjectItem(item, "set");
            cJSON* table;
            cJSON* name;
            cJSON* elem;
            if (!set) continue;
            table = cJSON_GetObjectItem(set, "table");
            name = cJSON_GetObjectItem(set, "name");
            if (!table || table->type != cJSON_String || !name ||
                name->type != cJSON_String ||
                strcmp(table->valuestring, table_name) != 0 ||
                strcmp(name->valuestring, set_name) != 0) {
              continue;
            }
            elem = cJSON_GetObjectItem(set, "elem");
            result = json_contains_string(elem, element) ? 1 : 0;
            break;
          }
        }
        cJSON_Delete(root);
      }
    }
  }
  nft_ctx_set_output(nft, stdout);
  fclose(mem_stream);
  free(output);
  return result;
}

static int delete_elements_from_set(struct nft_ctx* nft, const char* table_name,
                                    const char* set_name, uint32_t family,
                                    const char* elements) {
  char cmd[1024];
  const char* family_str;

  switch (family) {
    case NFPROTO_IPV4:
      family_str = "ip";
      break;
    case NFPROTO_IPV6:
      family_str = "ip6";
      break;
    case NFPROTO_INET:
      family_str = "inet";
      break;
    case NFPROTO_BRIDGE:
      family_str = "bridge";
      break;
    case NFPROTO_NETDEV:
      family_str = "netdev";
      break;
    default:
      family_str = "ip";
      break;
  }

  {
    int present = nft_set_contains_element(nft, table_name, set_name, elements);
    if (present < 0) {
      log_error("Query set %s/%s failed", table_name, set_name);
      return -1;
    }
    if (present == 0) {
      return 0;
    }
  }

  snprintf(cmd, sizeof(cmd), "delete element %s %s %s { %s }", family_str,
           table_name, set_name, elements);
 log_debug("delete elements from set cmd: %s", cmd);
  int ret = nft_run_cmd_from_buffer(nft, cmd);
  if (ret != 0) {
    log_debug("delete element %s %s %s { %s } failed: %s (may already deleted)",
              family_str, table_name, set_name, elements,
              strerror(errno));
    return -1;
  }

  return 0;
}

int run_nft_rule(char* cmd) {
  struct nft_ctx* ctx;
  int err;
  char ruleset[512] = {0};
  snprintf(ruleset, 512, "%s;", cmd);

  log_debug("cmd=%s",ruleset);
  ctx = nft_ctx_new(0);
  if (!ctx) {
    perror("cannot allocate nft context");
    return EXIT_FAILURE;
  }

  /* create ruleset: all commands in the buffer are atomically applied */
  err = nft_run_cmd_from_buffer(ctx, ruleset);
  if (err != 0) log_error("failed to run nftables command:%s\n", cmd);

  nft_ctx_free(ctx);

  return err != 0 ? -1 : 0;
}


int remove_authed_ip(struct user_session_t* user) {
  struct in_addr ip;
  ip.s_addr = user->ip;
  char* user_ip = inet_ntoa(ip);

  struct nft_ctx* nft;
  
  // 检查user有效性（风险7修复：防止访问已损坏的user）
  if (!user_is_valid(user)) {
    log_error("remove_authed_ip: user %p is invalid", user);
    return -1;
  }

  // 初始化 NFT 上下文
  nft = init_nft_ctx();
  if (!nft) {
    log_error("Failed to initialize NFT context\n");
    return EXIT_FAILURE;
  }

  /*
   * nft 的 delete rule 只支持按 handle 删除, 没有按匹配条件删除的语法。
   * 统一走 "按 IP+方向查 handle、按 handle 删" 的循环路径:
   * 不依赖会话里保存的 handle (可能因表被外部 reload/重建而漂移失效),
   * 同时清掉同一 IP 可能残留的重复规则。
   */
  user->nft_rules_state = NFT_RULES_DELETING;
  int src_rc = delete_rules_by_ip_direction(nft, user_ip, "saddr");
  int dest_rc = delete_rules_by_ip_direction(nft, user_ip, "daddr");

  // 删除 NAT authed set 元素
  int set_rc = delete_elements_from_set(nft, NFT_TABLE_NAT, "authed",
                                        NFPROTO_IPV4, user_ip);

  int whitelist_rc = check_and_add_whitelist_rules(nft);

  nft_ctx_free(nft);

  if (src_rc < 0 || dest_rc < 0 || set_rc < 0 || whitelist_rc < 0) {
    log_error("Failed to fully revoke nft access for user (ip=%s): "
              "src=%d dest=%d set=%d whitelist=%d",
              user_ip, src_rc, dest_rc, set_rc, whitelist_rc);
    return -1;
  }

  user->nft_src_handle = 0;
  user->nft_dest_handle = 0;
  user->nft_rules_state = NFT_RULES_NONE;

  log_debug("Successfully removed nft rules for user (ip=%s)\n", user_ip);
  return 0;
}




#if 0
static uint64_t get_rule_handle_by_ip(struct nft_ctx* nft, const char* table_name,
                                      const char* chain_name, const char* ip_addr) {
    struct mnl_socket* nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh;
    struct nftnl_rule* r;
    uint32_t portid, seq;
    uint64_t handle = 0;
    
    seq = time(NULL);
    nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_IPV4, 
                                NLM_F_ACK, seq);
    
    r = nftnl_rule_alloc();
    if (!r) {
        return 0;
    }
    
    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table_name);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain_name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
    
    nftnl_rule_nlmsg_build_payload(nlh, r);
    
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        nftnl_rule_free(r);
        return 0;
    }
    
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        nftnl_rule_free(r);
        return 0;
    }
    
    portid = mnl_socket_get_portid(nl);
    
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        mnl_socket_close(nl);
        nftnl_rule_free(r);
        return 0;
    }
    
    // 处理响应并查找匹配IP的规则句柄
    int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        // 这里需要实现回调函数来处理每个规则并匹配IP地址
        ret = mnl_cb_run(buf, ret, seq, portid, find_rule_by_ip_cb, &handle);
        if (ret <= 0) break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }
    
    mnl_socket_close(nl);
    nftnl_rule_free(r);
    
    return handle;
}

#endif
static int find_rule_handle_by_ip_and_direction(
    struct nft_ctx* nft, const char* table_name, const char* chain_name,
    const char* ip_addr, const char* direction, uint64_t* handle_out) {
    char cmd[512];
    char* output = NULL;
    size_t output_size = 0;
    uint64_t handle = 0;
    int result = -1;

    if (!nft || !table_name || !chain_name || !ip_addr || !direction ||
        !handle_out) {
      return -1;
    }
    *handle_out = 0;
    
    FILE* mem_stream = open_memstream(&output, &output_size);
    if (!mem_stream) {
      return -1;
    }
    
    nft_ctx_set_output(nft, mem_stream);
    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_JSON);
    
    snprintf(cmd, sizeof(cmd), "list chain ip %s %s", table_name, chain_name);
    
    int run_rc = nft_run_cmd_from_buffer(nft, cmd);
    fflush(mem_stream);  /* open_memstream 缓冲区须 flush 后才更新 output */
    if (run_rc == 0 && output) {
        cJSON* root = cJSON_Parse(output);
        if (root) {
            result = 0;
            // 遍历 nftables 数组
            cJSON* nftables = cJSON_GetObjectItem(root, "nftables");
            if (nftables && (nftables->type == cJSON_Array)) {
                for (cJSON* item = nftables->child; item; item = item->next) {
                    if (item) {
                        // 检查是否是规则对象
                        cJSON* rule = cJSON_GetObjectItem(item, "rule");
                        if (rule) {
                            // 检查表名和链名是否匹配
                            cJSON* table_field = cJSON_GetObjectItem(rule, "table");
                            cJSON* chain_field = cJSON_GetObjectItem(rule, "chain");
                            
                            if (table_field && chain_field && 
                                (table_field->type == cJSON_String) && (chain_field->type == cJSON_String) &&
                                strcmp(table_field->valuestring, table_name) == 0 &&
                                strcmp(chain_field->valuestring, chain_name) == 0) {
                                
                                // 检查表达式中的匹配条件
                                cJSON* expr_array = cJSON_GetObjectItem(rule, "expr");
                                if (expr_array && (expr_array->type == cJSON_Array)) {
                                    for (cJSON* expr = expr_array->child; expr; expr = expr->next) {
                                        if (expr) {
                                            cJSON* match = cJSON_GetObjectItem(expr, "match");
                                            if (match) {
                                                cJSON* left = cJSON_GetObjectItem(match, "left");
                                                if (left) {
                                                    cJSON* payload = cJSON_GetObjectItem(left, "payload");
                                                    if (payload) {
                                                        cJSON* field = cJSON_GetObjectItem(payload, "field");
                                                        if (field && (field->type == cJSON_String)) {
                                                            // 检查是否匹配指定的方向 (saddr 或 daddr) 和 IP 地址
                                                            if (strcmp(field->valuestring, direction) == 0) {
                                                                cJSON* right = cJSON_GetObjectItem(match, "right");
                                                                if (right && (right->type == cJSON_String) &&
                                                                    strcmp(right->valuestring, ip_addr) == 0) {
                                                                    cJSON* handle_obj = cJSON_GetObjectItem(rule, "handle");
                                                                    if (handle_obj && (handle_obj->type == cJSON_Number)) {
                                                                        handle = (uint64_t)handle_obj->valuedouble;
                                                                        result = 1;
                                                                        break;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (handle != 0) break;  // 如果已经找到handle就退出外层循环
                }
            }
            cJSON_Delete(root);
        }
    }
    
    nft_ctx_set_output(nft, stdout);
    fclose(mem_stream);
    if (output) free(output);
    
    *handle_out = handle;
    return result;
}

uint64_t get_rule_handle_by_ip_and_direction(struct nft_ctx* nft,
                                              const char* table_name,
                                              const char* chain_name,
                                              const char* ip_addr,
                                              const char* direction) {
  uint64_t handle = 0;
  return find_rule_handle_by_ip_and_direction(
             nft, table_name, chain_name, ip_addr, direction, &handle) == 1
             ? handle
             : 0;
}


int insert_authed_ip(struct user_session_t* user) {
    struct in_addr ip;
    ip.s_addr = user->ip;
    char cmd[512] = {0};
    char* user_ip = inet_ntoa(ip);
    uint32_t burst = 0;
    
    struct nft_ctx* nft = init_nft_ctx();
    if (!nft) {
        log_error("Failed to initialize NFT context\n");
        return EXIT_FAILURE;
    }

    // 标记：NFT 规则正在添加中
    user->nft_rules_state = NFT_RULES_ADDING;

    // 添加源地址规则
    if (user->out_rate > 0) {
        burst = user->out_rate / 10;
        snprintf(cmd, 512,
                 "add rule ip " NFT_TABLE_FILTER " forward ip saddr %s limit rate %u "
                 "bytes/second burst %u bytes counter accept comment \"%s\"",
                 user_ip, user->out_rate, burst, user_ip);
    } else {
        snprintf(cmd, 512,
                 "add rule ip " NFT_TABLE_FILTER " forward ip saddr %s counter accept comment \"%s\"",
                 user_ip, user_ip);
    }
    
    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        log_error("Failed to add source rule for %s", user_ip);
        nft_ctx_free(nft);
        user->nft_rules_state = NFT_RULES_NONE;
        return -1;
    }
    
    // 获取刚添加的源地址规则的句柄
    uint64_t new_src_handle = get_rule_handle_by_ip_and_direction(nft, NFT_TABLE_FILTER, "forward", user_ip, "saddr");
    if (new_src_handle == 0) {
        int cleanup_rc;
        log_error("Failed to get src handle for %s, NFT rule may exist but orphaned", user_ip);
        // 规则已添加但无法获取 handle，按 IP 查 handle 后删除残留规则
        cleanup_rc = delete_rules_by_ip_direction(nft, user_ip, "saddr");
        nft_ctx_free(nft);
        user->nft_rules_state = cleanup_rc >= 0 ? NFT_RULES_NONE
                                                : NFT_RULES_DELETING;
        return -1;
    }
    user->nft_src_handle = new_src_handle;
    log_debug("Source rule handle for %s: %llu", user_ip,
              (unsigned long long)user->nft_src_handle);

    // 添加目标地址规则
    memset(cmd, 0, 512);
    if (user->in_rate > 0) {
        burst = user->in_rate / 10;
        snprintf(cmd, 512,
                 "add rule ip " NFT_TABLE_FILTER " forward ip daddr %s limit rate %u "
                 "bytes/second burst %u bytes counter accept comment \"%s_daddr\"",
                 user_ip, user->in_rate, burst, user_ip);
    } else {
        snprintf(cmd, 512,
                 "add rule ip " NFT_TABLE_FILTER " forward ip daddr %s counter accept comment \"%s_daddr\"",
                 user_ip, user_ip);
    }
    
    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        int cleanup_rc;
        log_error("Failed to add destination rule for %s", user_ip);
        // 删除已添加的源规则
        cleanup_rc = delete_rule_by_handle(nft, NFT_TABLE_FILTER, "forward",
                                           NFPROTO_IPV4,
                                           user->nft_src_handle);
        nft_ctx_free(nft);
        if (cleanup_rc == 0) {
            user->nft_src_handle = 0;
            user->nft_rules_state = NFT_RULES_NONE;
        } else {
            user->nft_rules_state = NFT_RULES_DELETING;
        }
        return -1;
    }
    
    // 获取刚添加的目标地址规则的句柄
    uint64_t new_dest_handle = get_rule_handle_by_ip_and_direction(nft, NFT_TABLE_FILTER, "forward", user_ip, "daddr");
    if (new_dest_handle == 0) {
        int src_cleanup;
        int dest_cleanup;
        log_error("Failed to get dest handle for %s, NFT rule may exist but orphaned", user_ip);
        // 删除已添加的规则
        src_cleanup = delete_rule_by_handle(nft, NFT_TABLE_FILTER, "forward",
                                            NFPROTO_IPV4,
                                            user->nft_src_handle);
        dest_cleanup = delete_rules_by_ip_direction(nft, user_ip, "daddr");
        nft_ctx_free(nft);
        if (src_cleanup == 0 && dest_cleanup >= 0) {
            user->nft_src_handle = 0;
            user->nft_dest_handle = 0;
            user->nft_rules_state = NFT_RULES_NONE;
        } else {
            user->nft_rules_state = NFT_RULES_DELETING;
        }
        return -1;
    }
    user->nft_dest_handle = new_dest_handle;
    log_debug("Destination rule handle for %s: %llu", user_ip,
              (unsigned long long)user->nft_dest_handle);

    // 添加到 NAT authed set（prerouting 用它让已认证客户端跳过 portal 引导）
    memset(cmd, 0, 512);
    snprintf(cmd, 512, "add element ip " NFT_TABLE_NAT " authed {%s}", user_ip);
    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        int src_cleanup;
        int dest_cleanup;
        log_error("Failed to add NAT authed element for %s", user_ip);
        src_cleanup = delete_rules_by_ip_direction(nft, user_ip, "saddr");
        dest_cleanup = delete_rules_by_ip_direction(nft, user_ip, "daddr");
        nft_ctx_free(nft);
        if (src_cleanup >= 0 && dest_cleanup >= 0) {
            user->nft_src_handle = 0;
            user->nft_dest_handle = 0;
            user->nft_rules_state = NFT_RULES_NONE;
        } else {
            user->nft_rules_state = NFT_RULES_DELETING;
        }
        return -1;
    }

    nft_ctx_free(nft);
    
    // 标记：NFT 规则已激活
    user->nft_rules_state = NFT_RULES_ACTIVE;
    
    log_debug("Successfully added NFT rules for user %s "
              "(src_handle=%llu, dest_handle=%llu)",
              user_ip, (unsigned long long)user->nft_src_handle,
              (unsigned long long)user->nft_dest_handle);
    return 0;
}

struct user_session_t* update_session(struct inst_t* inst, uint32_t userip,
                                      uint8_t* usermac,
                                      struct nftnl_expr_counter* in,
                                      struct nftnl_expr_counter* out) {
  struct user_session_t* session = find_user(inst, userip, usermac);
  struct user_address_t user_address;
  if (session) {
    // 检查用户有效性（风险：访问可能已释放的user）
    if (!user_is_valid(session)) {
      log_debug("update_session: user %p is invalid, skip update", session);
      return NULL;
    }
    
    if (session->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
      log_debug("update_session: user %p is not active (state=%d), skip update", 
                session, session->lifecycle_state);
      return NULL;
    }
    
    /* 流量计费单调性防护:
     * nft counter 是内核侧绝对值, 规则被外部 reload / mwan3 重建 / 删除后
     * 重新插入时计数器会归零。若直接把采样值覆盖写入 session->inbytes,
     * 上报给 RADIUS 的累计流量会回退, 造成少计费; 本地认证源也会因为
     * "水位回退"丢失这段流量。
     * 这里改为增量累加: prev_inbytes 保存上一次原始采样值, 正常情况累加
     * 差值; 采样值回退时把新值整体视为增量(即计数器重建后产生的流量),
     * 保证会话累计值只增不减。 */
    if (in) {
      uint64_t raw_in = in->bytes;
      uint64_t delta_in;

      if (raw_in >= session->prev_inbytes) {
        delta_in = raw_in - session->prev_inbytes;
      } else {
        struct in_addr reset_addr;
        reset_addr.s_addr = session->ip;
        log_warn("update_session: in counter reset for %s "
                 "(%llu -> %llu), treat new value as delta",
                 inet_ntoa(reset_addr),
                 (unsigned long long)session->prev_inbytes,
                 (unsigned long long)raw_in);
        delta_in = raw_in;
      }
      session->inbytes += delta_in;
      session->prev_inbytes = raw_in;
      session->inpackets = in->pkts;
    }
    // printf("src  handle=%u\n",session->nft_src_handle );

    if (out) {
      uint64_t raw_out = out->bytes;
      uint64_t delta_out;

      if (raw_out >= session->prev_outbytes) {
        delta_out = raw_out - session->prev_outbytes;
      } else {
        struct in_addr reset_addr;
        reset_addr.s_addr = session->ip;
        log_warn("update_session: out counter reset for %s "
                 "(%llu -> %llu), treat new value as delta",
                 inet_ntoa(reset_addr),
                 (unsigned long long)session->prev_outbytes,
                 (unsigned long long)raw_out);
        delta_out = raw_out;
      }
      session->outbytes += delta_out;
      session->prev_outbytes = raw_out;
      session->outpackets = out->pkts;
    }

    //  printf("dest  handle=%u\n",session->nft_dest_handle );

    if (session->quota_data > 0) {
      if (session->outbytes + session->inbytes >= session->quota_data) {
        user_address.ip = session->ip;
        memcpy(user_address.mac, session->mac, 6);
        log_debug("total data=%" PRIu64 " session data=%" PRIu64 "\n",
                  session->outbytes + session->inbytes, session->quota_data);
        process_server_events(EV_CLOSE_SESSION, &user_address, (void*)session);
      }
    }
  } else {
    session = NULL;
  }

  return session;
}
static int table_cb(const struct nlmsghdr* nlh, void* data) {
  //   int offset = 0;
  struct nftnl_expr* ex;

  //  char buf[4096];
  struct inst_t* inst = (struct inst_t*)data;

  struct nftnl_expr_iter* iter_a = NULL;
  struct nftnl_expr* rule_a = NULL;
  struct nftnl_expr2* expr2;

  struct nftnl_expr_counter* in = NULL;
  struct nftnl_expr_counter* out = NULL;
  uint64_t handle = 0;
  uint8_t mac[6] = {0};
  uint8_t addr = 0;
  struct nftnl_rule* t;
  //  struct nftnl_rule2* tt=(nftnl_rule2*)t;
  // uint32_t *type = 0;
  uint32_t len = 0;
  uint32_t payload_offset = 0;
  struct user_session_t* session = NULL;
  //  struct user_address_t user_address;
  struct in_addr tmp_ip;
  memset(&tmp_ip, 0, sizeof(tmp_ip));
  // uint64_t in_bytes = 0;
  // uint64_t out_bytes = 0;

  t = nftnl_rule_alloc();
  if (t == NULL) {
    perror("OOM");
    goto err;
  }
  //   struct nftnl_rule2* tt = (struct nftnl_rule2*) t;
  if (nftnl_rule_nlmsg_parse(nlh, t) < 0) {
    perror("nftnl_rule_nlmsg_parse");
    goto err_free;
  }

  //  uint32_t tmp_data = 0;

  iter_a = nftnl_expr_iter_create(t);
  if (iter_a == NULL) {
    perror("OOM");
    goto err_free;
  }

  rule_a = nftnl_expr_iter_next(iter_a);
  if (rule_a == NULL) {
    perror("OOM");
    goto err_free;
  }

  const char* set_name;
  const void* h = nftnl_rule_get_data(t, NFTNL_RULE_HANDLE, &len);
  if (!h || len < sizeof(uint32_t)) {
    goto err_free;
  }
  if (len >= sizeof(uint64_t)) {
    memcpy(&handle, h, sizeof(handle));
  } else {
    uint32_t handle32 = 0;
    memcpy(&handle32, h, sizeof(handle32));
    handle = handle32;
  }

  do {
    // int ret = nftnl_expr_snprintf(buf, remain, rule_a, *type, 0);
    set_name = nftnl_expr_get(rule_a, NFTNL_EXPR_NAME, &len);

    if (set_name) {
      //  printf("name=%s\n",set_name);
      expr2 = (struct nftnl_expr2*)rule_a;
      //     cmp = ( struct nftnl_expr_cmp *)(expr2->data);

      if (strncmp(set_name, "payload", 8) == 0) {
        /* 用 libnftnl 官方接口读取 payload 偏移(IPv4 saddr=12/daddr=16),
         * 避免按内部结构 expr2->data[12] 硬编码在不兼容版本下读错字段 */
        payload_offset = nftnl_expr_get_u32(rule_a, NFTNL_EXPR_PAYLOAD_OFFSET);
        addr = (payload_offset == 12) ? 12 : (payload_offset == 16) ? 16 : 0;
      }

      if (strncmp(set_name, "cmp", 3) == 0) {
        // expr2 = (struct nftnl_expr2*) rule_a;
        // inet_ntoa();
        memcpy((uint8_t*)(&tmp_ip.s_addr), expr2->data, 4);
        // printf("ip=%s  ", inet_ntoa(tmp_ip) );
      }

      if (strncmp(set_name, "counter", 7) == 0) {
        if (addr == 12) {
          /* saddr（源地址）= 用户发出 = 上行，对应 RADIUS Acct-Input-Octets */
          in = nftnl_expr_data(expr2);

          session = update_session(inst, tmp_ip.s_addr, mac, in, NULL);
          if (session) {
            // 仅当 session 不存在或 NFT 规则状态不是 ACTIVE 时，才用 NFT 数据初始化 handle
            // 防止覆盖已激活的正确 handle
            if (session->nft_rules_state != NFT_RULES_ACTIVE) {
              session->nft_src_handle = handle;
              // 如果是从 NFT 发现的规则，标记为 ACTIVE
              if (session->nft_src_handle != 0 && session->nft_dest_handle != 0) {
                session->nft_rules_state = NFT_RULES_ACTIVE;
              }
            }
          }
        }
        if (addr == 16) {
          /* daddr（目的地址）= 用户接收 = 下行，对应 RADIUS Acct-Output-Octets */
          out = nftnl_expr_data(expr2);

          session = update_session(inst, tmp_ip.s_addr, mac, NULL, out);
          if (session) {
            // 仅当 session 不存在或 NFT 规则状态不是 ACTIVE 时，才用 NFT 数据初始化 handle
            // 防止覆盖已激活的正确 handle
            if (session->nft_rules_state != NFT_RULES_ACTIVE) {
              session->nft_dest_handle = handle;
              // 如果是从 NFT 发现的规则，标记为 ACTIVE
              if (session->nft_src_handle != 0 && session->nft_dest_handle != 0) {
                session->nft_rules_state = NFT_RULES_ACTIVE;
              }
            }
          }
        }
      }
    }
    rule_a = nftnl_expr_iter_next(iter_a);

    if (len < 1 || rule_a == NULL) {
      break;
    }

    // SNPRINTF_BUFFER_SIZE(ret, remain, rule_a = nftnl_expr_iter_next(iter_a);
    // offset);
  } while (1);

  //  printf("handle=%u ip=%s addr=%u  \n", handle, inet_ntoa(tmp_ip), addr);
  /*
     struct user_session_t* session = find_user(inst, (tmp_ip.s_addr), mac);
      if (session) {
         // printf("counter  addr=%d\n",addr);
         if (strncmp(set_name, "counter", 7) == 0) {
          if (addr == 12) {
              if(in){
              session->inbytes = in->bytes;
             session->inpackets = in->pkts;
              session->nft_src_handle = handle;

              }
              // printf("src  handle=%u\n",session->nft_src_handle );
          }
          if (addr == 16) {
              if(out){
                  session->outbytes = out->bytes;
                  session->outpackets = out->pkts;
                  session->nft_src_handle = handle;
              }

              //  printf("dest  handle=%u\n",session->nft_dest_handle );
          }
      }
          if (session->quota_data > 0) {

              if (session->outbytes + session->inbytes >= session->quota_data) {
                  user_address.ip = session->ip;
                  memcpy(user_address.mac, session->mac, 6);
                  log_debug("total data=%"PRIu64" session data=%"PRIu64"\n",
     session->outbytes + session->inbytes, session->quota_data);
                  process_server_events(EV_CLOSE_SESSION, &user_address, (void*)
     session);
              }
          }
      }


  */

err_free:
  if (iter_a) {
    nftnl_expr_iter_destroy(iter_a);
  }
  nftnl_rule_free(t);
err:
  return MNL_CB_OK;
}

static struct nftnl_rule* setup_rule(uint8_t family, const char* table,
                                     const char* chain, const char* handle) {
  struct nftnl_rule* r;
  uint64_t handle_num;

  r = nftnl_rule_alloc();
  if (r == NULL) return NULL;

  if (table != NULL) nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table);
  if (chain != NULL) nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

  nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);

  if (handle != NULL) {
    handle_num = atoll(handle);
    nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
  }

  return r;
}

// int get_nft_rule(int argc, char *argv[]) {

int get_nft_rule(uint8_t family, char* table, char* chain, void* data) {
  struct mnl_socket* nl;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh;
  uint32_t portid, seq;
  // type = 0;
  // const char *table = NULL, *chain = NULL;
  struct nftnl_rule* r;
  int ret;
  // family;

  seq = time(NULL);
  nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family, NLM_F_DUMP, seq);

  r = setup_rule(family, table, chain, NULL);
  if (!r) {
    perror("setup_rule");
    return -1;
  }
  nftnl_rule_nlmsg_build_payload(nlh, r);
  nftnl_rule_free(r);  /* rule 对象已序列化进 nlmsg 缓冲, 释放 */

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL) {
    perror("mnl_socket_open");
    return -1;
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    perror("mnl_socket_bind");
    mnl_socket_close(nl);
    return -1;
  }
  portid = mnl_socket_get_portid(nl);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    perror("mnl_socket_send");
    mnl_socket_close(nl);
    return -1;
  }

  ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portid, table_cb, data);

    if (ret <= 0) break;
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret == -1) {
    perror("error");
    mnl_socket_close(nl);
    return -1;
  }
  mnl_socket_close(nl);

  return EXIT_SUCCESS;
}

void flush_sessions_timer_cb(const int fd, const short event, void* arg) {
  // struct user_session_t* user = (struct user_session_t*) arg;

  /* 时钟跳变检测（无 RTC 设备 NTP 校准防护）：随 5s 全局扫描驱动，
   * 检测到墙钟步进跳变时平移所有活跃会话的时间锚点，防止在线时长虚增 */
  clock_jump_check();

  get_nft_rule(NFPROTO_IPV4, NFT_TABLE_FILTER, "forward", arg);
}

int start_flush_sessions_timer(struct inst_t* inst) {
  struct timeval tv;

  tv.tv_sec = 5;
  tv.tv_usec = 0;

  inst->ev_flush_session_timer =
      event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                flush_sessions_timer_cb, (void*)inst);

  if (inst->ev_flush_session_timer) {
    event_add(inst->ev_flush_session_timer, &tv);

    log_debug("Start flush sessions  timer .Timeout=5s ");
  } else {
    log_debug("Start flush sessions timer failed.");
  }

  return 0;
}

int stop_flush_sessions_timer(struct inst_t* inst) {
  if (!inst) {
    return -1;
  }
  if (inst->ev_flush_session_timer) {
    event_del(inst->ev_flush_session_timer);
    event_free(inst->ev_flush_session_timer);
    inst->ev_flush_session_timer = NULL;
  }
  return 0;
}

