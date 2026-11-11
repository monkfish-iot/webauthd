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
#include "app_events.h"

#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "config.h"
#include "http_auth.h"
#include "http_service.h"
#include "instance.h"
#include "local_auth.h"
#include "nft.h"
#include "portal_server.h"
#include "radius.h"
#include "session.h"
#include "timer.h"
#include "utensils.h"
#include "ws_users.h"

int ev_update_config(struct user_address_t* user_address, void* arg) {
  int* config_name = (int*)arg;
  struct inst_t* inst = get_inst();
  struct config_t* config = inst->config;
  int rc = 0;
  int inst_enable = inst->config->enabled;

  if (reload_all_configs(inst) < 0) {
    return -1;
  }

  /* reload_all_configs 已释放旧配置对象, 必须重新指向新对象后再使用,
   * 否则 config 为悬空指针(UAF) */
  config = inst->config;

  if (inst_enable != inst->config->enabled) {
    destroy_inst();
    exit(0);
  }

  switch (*config_name) {
    case CONFIG_GENERIC:
      restart_init(inst);
      break;
    case CONFIG_PORTAL:
      break;
    case CONFIG_RADIUS:
      update_radius_config(inst);

      break;
    case CONFIG_HTTP_AUTH:
      /* reload_all_configs 已整体置换 inst->config; HTTP 认证为
       * 每请求读取配置的无状态客户端, 无需重建, 仅记录生效值 */
      log_info("HTTP auth config reloaded: auth_url=%s acct_url=%s "
               "tls_verify=%d timeout=%d",
               config->http_auth_url,
               config->http_acct_url[0] ? config->http_acct_url : "(disabled)",
               config->http_tls_verify, config->http_timeout);
      break;
    case CONFIG_WHITLIST:
      /* reload_all_configs 已统一重建白名单，避免重复刷新 NFT 集合。 */
      break;
    default:
      rc = -1;
  }

  return rc;
}

int ev_new_user(struct user_address_t* user_address, void* arg) {
  struct inst_t* inst = user_address->inst;

  struct user_session_t* user =
      create_user(inst, user_address->ip, user_address->mac);
  if (!user) {
    log_error("Can NOT create user");
    // send_http_reply(req, HTTP_REPLY_USER_NOTEXIST, NULL);
    return -2;
  }

  log_debug("user mac %02x:%02x:%02x:%02x:%02x:%02x\n", user->mac[0],
         user_address->mac[1], user_address->mac[2], user_address->mac[3],
         user_address->mac[4], user_address->mac[5]);
  *(struct user_session_t**)arg = user;
  ;

  //  printf("++++++++++++++++++++++\n");
  user->status = USER_STATE_INIT;
  // user->pushed_portal = 0;
  user->ip = user_address->ip;
  memcpy(user->mac, user_address->mac, 6);
  user->inst = inst;

  user->last_auth = get_now_time();
  /* 为新建会话安排未认证回收定时器: 仅打开门户页但从不提交登录的客户端
   * 会在超时后被清理, 避免 256 个固定槽位被静默占满 */
  start_unauthed_timer(user);
  if (user->authtype == USER_AUTH_TYPE_MAC) {
    if (inst->config->auth_source == AUTH_SOURCE_LOCAL) {
      /* 本地认证源: MAC 已绑定且用户开启 mac_auth 时免密放行,
       * 否则回退 PORTAL(此时返回 0 让本次请求继续弹出 portal 页) */
      int rc = local_mac_auth(inst, user);
      log_debug("Local MAC auth %s.", (rc == 0) ? "passed" : "fallback");
      return (rc == 0) ? -1 : 0;
    }
    if (inst->config->auth_source == AUTH_SOURCE_HTTP) {
      /* HTTP 认证源: MAC 免密异步认证。已派发返回 -1 让本次请求挂起
       * (ws_portal_redirected 会 cancel), 失败回退 PORTAL 后返回 0
       * 立即弹 portal 页 */
      int rc = http_mac_auth(inst, user);
      log_debug("HTTP MAC auth %s.", (rc == 0) ? "dispatched" : "fallback");
      return (rc == 0) ? -1 : 0;
    }
    mac_radius_auth(inst, user);
    log_debug("Start MAC radius auth.");
    // evhttp_cancel_request(req);
    // send_http_reply(req, 0, NULL);
    return -1;
  }

  return 0;



}

static void complete_portal_auth_reply(struct user_session_t* user, int code,
                                       char* body) {
  struct evhttp_request* req = user->req;

  user->req = NULL;
  if (req) {
    /* HTTP 认证源失败时 reply_msg 携带服务器返回的 msg, 原样透传给
     * portal 页; 其它路径 reply_msg 为空, 按码表取默认文案 */
    if (user->reply_msg[0] != '\0') {
      send_http_reply_ex(req, code, body, user->reply_msg);
      user->reply_msg[0] = '\0';
    } else {
      send_http_reply(req, code, body);
    }
  } else {
    log_debug("Portal authentication completed without pending HTTP request");
  }
}

int ev_auth_accept(struct user_address_t* user_address, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;
  // printf("+++++++++++++++++5\n");
  int status = user->status;
  uint64_t data_quota = user->quota_giga_bytes;
  data_quota = data_quota << 32;
  data_quota += user->quota_bytes;

  cJSON* root = NULL;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  uint64_t quota_data;
  uint64_t in_rate;
  uint64_t out_rate;
  char* response_data = NULL;
  char* user_ip = NULL;
  struct in_addr ip;

  print_user_info(user);

  // printf("+++++++++++s++++++++++++nas_ip=%s\n", user->inst->config->nas_ip);

  switch (status) {
    case USER_STATE_AUTHING:
      stop_auth_timer(user);
      /*
       * 撤销「等待认证」60s 兜底定时器(MAC fallback/拒绝/超时路径挂载)。
       * 用户已在本回调中认证成功, 该定时器若不撤销, 会在挂载 60s 后
       * 触发 EV_CLOSE_SESSION 把已上线会话误踢下线(表现为登录后
       * 恰好在线不足 60s 即被下线并删除 nft 放行规则)。
       */
      stop_waiting_auth_timer(user);
      if (generate_acct_id(user->acct_session_id, 32)) {
        log_error("generate user acctount  session Id error");
        complete_portal_auth_reply(user, PORTAL_START_RAD_ERROR, NULL);
        user->status = USER_STATE_INIT;
        return -1;
      }
      log_info(
          "Auth accept: user='%s' ip=%s session-timeout=%u idle-timeout=%u "
          "acct-session-id='%s'",
          user->user_name, inet_ntoa(tmp), user->session_timeout,
          user->idle_timeout, user->acct_session_id);
      /* 凭据通过不等于正式在线。先建立完整的数据面授权（双向 filter
       * 规则 + NAT authed 集合），成功后才发布 AUTHED 和登录成功。 */
      if (insert_authed_ip(user) != 0) {
        log_error("Auth accepted but NFT activation failed, user='%s' ip=%s",
                  user->user_name, inet_ntoa(tmp));
        complete_portal_auth_reply(user, PORTAL_NFT_APPLY_ERROR, NULL);
        user->local_pending_login = 0;
        if (user->nft_rules_state == NFT_RULES_NONE) {
          user->status = USER_STATE_INIT;
        } else {
          user->status = USER_STATE_DROPPING;
          if (start_nft_revoke_retry(user, 1) != 0) {
            log_error("Unable to schedule cleanup for partial NFT activation");
          }
        }
        return -1;
      }
      user->status = USER_STATE_AUTHED;
      user->acct_start_time = get_now_time();
      //   if (user->inst->config->mode == WEBAUTH_MODE) {

      ip.s_addr = user->ip;
      user_ip = inet_ntoa(ip);
      // insert_authed_ip(user);
      //  }
      log_debug("user->authtype=%u\n", user->authtype);
      if (user->authtype == USER_AUTH_TYPE_PORTAL) {
        quota_data = user->quota_giga_bytes;
        quota_data = quota_data << 32 | user->quota_bytes;
        user->quota_data = quota_data;
        in_rate = user->in_giga_rate;
        in_rate = in_rate << 32 | user->in_rate;
        out_rate = user->out_giga_rate;
        out_rate = out_rate << 32 | user->out_rate;
        root = cJSON_CreateObject();
        //   printf("++++++++++++++++++++0\n");
        if (!root) {
          complete_portal_auth_reply(user, HTTP_REPLY_JSON_IS_ERROR, NULL);
          user->status = USER_STATE_DROPPING;
          if (remove_authed_ip(user) != 0) {
            start_nft_revoke_retry(user, 1);
          } else {
            user->status = USER_STATE_INIT;
          }
          return -1;
        }
        //  printf("++++++++++++++++++++1\n");
        do {
          cJSON_AddNumberToObject(root, "Session-Timeout",
                                  user->session_timeout);
          //  if (user->inst->config->mode == WEBAUTH_MODE) {
          cJSON_AddStringToObject(root, "User-IP", inet_ntoa(tmp));
          //  }
          cJSON_AddNumberToObject(root, "In-Rate", in_rate);
          cJSON_AddNumberToObject(root, "Out-Rate", out_rate);
          cJSON_AddNumberToObject(root, "Quota-Data", quota_data);
          response_data = cJSON_Print(root);
        } while (0);

        if (!response_data) {
          cJSON_Delete(root);
          complete_portal_auth_reply(user, HTTP_REPLY_JSON_IS_ERROR, NULL);
          user->status = USER_STATE_DROPPING;
          if (remove_authed_ip(user) != 0) {
            start_nft_revoke_retry(user, 1);
          } else {
            user->status = USER_STATE_INIT;
          }
          return -1;
        }

        log_info("Send http_login success reply to user='%s' ip=%s",
                 user->user_name, inet_ntoa(tmp));
        complete_portal_auth_reply(user, 0, response_data);
        free(response_data);
        cJSON_Delete(root);
      }

      if (user->inst->config->auth_source == AUTH_SOURCE_LOCAL) {
        /*
         * 本地认证源(auth_source=local): 完全旁路 RADIUS 记账。
         * nft 放行规则与 RADIUS 路径"Accounting-Start 应答后"的时机等价,
         * 这里在 accept 时立即生效; 会话超时定时器同样立即启动。
         * 用量/在线时长的持久化基准在此初始化。
         */
        user->local_flushed_bytes = 0;
        user->local_flush_mark = get_now_time();
        start_session_timer(user);
        log_info("Local auth session started (no RADIUS accounting), "
                 "user='%s' ip=%s",
                 user->user_name, inet_ntoa(tmp));
      } else if (user->inst->config->auth_source == AUTH_SOURCE_HTTP) {
      /*
       * HTTP(S) 认证源: 认证通过即放行 + 启动会话超时定时器(时机同
       * local 源); 记账 Start 仅异步通知、不等应答——记账服务器不可达
       * 不影响已认证用户上线。Interim 周期定时器立即启动(无需等
       * Accounting 应答), acct_url 未配置时完全不记账。
       */
      start_session_timer(user);

      if (user->inst->config->http_acct_url[0] != '\0') {
        http_send_acct(user, HTTP_ACCT_START);
        /*
         * Interim 周期取值: 服务器 acct_update_interval 已在应答解析时
         * 写入 user->acct_interval(>0 优先); 否则用本地 UCI
         * webauthd.radius.acct_interval(create_user 已预填);
         * 两者都异常(<=0)时兜底 300s。
         */
        if (user->acct_interval <= 0) {
          user->acct_interval =
              user->inst->config->acct_interval > 0
                  ? (uint32_t)user->inst->config->acct_interval
                  : 300;
        }
        start_update_accounting_timer(user);
      }
      log_info("HTTP auth session started: user='%s' ip=%s acct=%s "
               "interim=%us",
               user->user_name, inet_ntoa(tmp),
               user->inst->config->http_acct_url[0] ? "on" : "off",
               user->acct_interval);
      } else {
      if (send_start_acct(user) < 0) {
        log_error("send start acct error, user='%s' ip=%s\n",
                  user->user_name, inet_ntoa(tmp));
      } else {
        log_info("send start acct success, user='%s' ip=%s\n",
                 user->user_name, inet_ntoa(tmp));
      }

      start_waitting_acct_response_timer(user);

      /*
       * 计费更新(Interim/Alive)发送间隔取值:
       *   1. RADIUS Access-Accept 携带 Acct-Interim-Interval(属性85,>0)时,
       *      parse_radpkg 已写入 user->acct_interval, 以服务器值为准;
       *   2. 否则使用本地 UCI webauthd.radius.acct_interval
       *      (config.c 默认 300, 现网配置为 60), create_user 已预填;
       *   3. 两者都异常(<=0)时兜底 300s, 避免周期为 0 使持久定时器空转。
       * 实际的更新定时器在收到 Accounting-Start 应答后才启动
       * (radacct_response_cb -> start_update_accounting_timer)。
       */
      if (user->acct_interval <= 0) {
        user->acct_interval =
            user->inst->config->acct_interval > 0
                ? (uint32_t)user->inst->config->acct_interval
                : 300;
      }
      log_info(
          "Accounting interim interval for user='%s' ip=%s: effective=%us "
          "(uci acct_interval=%d; RADIUS attr85 overrides when present)",
          user->user_name, inet_ntoa(tmp), user->acct_interval,
          user->inst->config->acct_interval);
      } /* end of RADIUS accounting branch (local source skips it) */

      /*
       * 空闲下线超时(连续无流量时长)取值优先级:
       *   1. 本地 UCI 显式配置 webauthd.generic.idle_timeout (>0),
       *      管理员策略最优先, 保证现场配置的 120s 一定生效;
       *   2. RADIUS Access-Accept 下发的 Idle-Timeout(属性28),
       *      仅在本地未配置(=0)时兜底;
       *   3. 两者都为 0 则不启用空闲下线。
       * 流量字节由全局每 5s 的 nft counter 扫描独立刷新, 与计费周期无关。
       */
      long radius_idle = user->idle_timeout;  // parse_radpkg 已从 RADIUS 填充
      long eff_idle = 0;
      const char* idle_src = "disabled";
      if (user->inst->config->idle_timeout > 0) {
        eff_idle = (long)user->inst->config->idle_timeout;
        idle_src = "local-uci";
      } else if (radius_idle > 0) {
        eff_idle = radius_idle;
        idle_src = "radius";
      }

      /*
       * 不再按计费更新周期钳制空闲超时: 空闲判定的流量字节来自全局每 5s
       * 一次的 nft forward counter 扫描(update_session), 与 RADIUS 记账
       * Interim 周期相互独立, 因此本地配置的 idle_timeout(如 120s)应精确
       * 生效, 不能因服务器下发较大的 Acct-Interim-Interval 而被放大。
       */

      user->idle_timeout = eff_idle;
      log_info(
          "Idle timeout for user='%s' ip=%s: effective=%lds source=%s "
          "(local-uci=%u, radius Idle-Timeout=%ld)",
          user->user_name, inet_ntoa(tmp), eff_idle, idle_src,
          user->inst->config->idle_timeout, radius_idle);

      start_idle_check_timer(user);
      // start_session_timer(user);

      // start_update_accounting_timer(user);

      break;
  }

  log_debug("User(%s) auth accept(status=%d)\n", inet_ntoa(tmp), user->status);
  return 0;
}

int ev_auth_reject(struct user_address_t* user_address, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;

  //  stop_auth_timer(user);
  int status = user->status;
  struct in_addr tmp;
  tmp.s_addr = user->ip;

  switch (status) {
    case USER_STATE_AUTHING:
      log_warn(
          "Auth reject: user='%s' ip=%s authtype=%d http_reply_code=%d",
          user->user_name, inet_ntoa(tmp), user->authtype,
          user->http_reply_code);

      if (user->authtype == USER_AUTH_TYPE_PORTAL) {
        complete_portal_auth_reply(user, user->http_reply_code, NULL);
      }
      //
      user->nft_src_handle = 0;
user->nft_dest_handle = 0;
user->status = USER_STATE_INIT;
// 清理所有定时器
close_session_all_timers(user);

      user->status = USER_STATE_INIT;
      if (user->authtype == USER_AUTH_TYPE_MAC) {
        user->authtype = USER_AUTH_TYPE_PORTAL;

       // break;
      }
      start_waiting_auth_timer(user);
      //   user->status = USER_STATE_DROPPING;

      break;
  }

  log_debug("User(%s) auth reject(status:%d)\n", inet_ntoa(tmp), status);
  return 0;
}

#if 0 

int ev_idle_check_timer(struct user_address_t* user_address, void* arg) {
    struct user_session_t* user = (struct user_session_t*) arg;

    char* user_ip = NULL;
    struct in_addr tmp;

    switch (user->status) {
        case USER_STATE_AUTHED:
        case USER_STATE_FREE:
            //  case USER_STATE_FREE:
            tmp.s_addr = user->ip;
            user_ip = inet_ntoa(tmp);

            log_debug(
                    "Check idle timer! ip=%s last sum bytes=%llu current sum bytes=%llu",
                    user_ip, user->last_sum_bytes, user->inbytes + user->outbytes);

            if (user->last_sum_bytes == user->inbytes + user->outbytes) {
                process_server_events(EV_CLOSE_SESSION, NULL, user);
                // printf("+++++++++++++++++11\n");
                // close_session_all_timers(user);

                // user->status = USER_STATE_DROPPING;
                // user->acct_status_type = PW_STATUS_STOP;
                // if (!user->ev_waitting_acct_response_timer) {
                //   if (send_stop_acct(user) > 0) {
                //     start_waitting_acct_response_timer(user);
                //   }
                // } else {
                //   start_delay_acct_stop_timer(user);
                //   return -1;
                // }

            } else {
                user->last_sum_bytes = user->inbytes + user->outbytes;
            }

            break;
        default:

            break;
    }

    return 0;
}
#endif

int ev_recv_CoA(struct user_address_t* user_address, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;
  uint32_t old_status;

  (void)user_address;
  if (!user || !user_is_valid(user) || !user->rad_pkg ||
      !user->rad_server_addr) {
    return -1;
  }
  old_status = user->status;
  log_info("RADIUS Disconnect-Request for user='%s' ip=%0x status=%u",
           user->user_name, user->ip, user->status);

  switch (user->status) {
    case USER_STATE_AUTHED:
    case USER_STATE_FREE:
      if (remove_authed_ip(user) != 0) {
        /* 明确返回 NAK，同时保留会话与重试责任，不能先报 ACK/删会话。 */
        user->status = USER_STATE_DROPPING;
        reply_CoA(user, PW_DISCONNECT_NAK, user->rad_pkg->identifier,
                  user->rad_server_addr);
        if (user->inst->config->auth_source == AUTH_SOURCE_RADIUS &&
            send_stop_acct(user) >= 0) {
          start_waitting_acct_response_timer(user);
        } else {
          start_nft_revoke_retry(user, 1);
        }
        return -1;
      }

      close_session_all_timers(user);
      user->status = USER_STATE_DROPPING;
      if (reply_CoA(user, PW_DISCONNECT_ACK, user->rad_pkg->identifier,
                    user->rad_server_addr) != 0) {
        log_error("Send Disconnect-ACK failed for user='%s'", user->user_name);
      }
      if (user->inst->config->auth_source == AUTH_SOURCE_RADIUS &&
          user->acct_enable && user->user_name[0] != '\0' &&
          user->acct_session_id[0] != '\0') {
        if (send_stop_acct(user) < 0) {
          log_error("send stop acct error after DM; access is already revoked");
          del_user(user->inst, user);
        } else {
          start_waitting_acct_response_timer(user);
        }
      } else {
        log_info("Disconnect-Request: no accounting identity, revoke only "
                 "user='%s' ip=%0x", user->user_name, user->ip);
        del_user(user->inst, user);
      }
      return 0;
    case USER_STATE_AUTHING:
    case USER_STATE_INIT:
    case USER_STATE_DROPPING:
      reply_CoA(user, PW_DISCONNECT_NAK, user->rad_pkg->identifier,
                user->rad_server_addr);
      return -1;
    default:
      user->status = old_status;
      reply_CoA(user, PW_DISCONNECT_NAK, user->rad_pkg->identifier,
                user->rad_server_addr);
      return -1;
  }
}

int ev_close_session(struct user_address_t* user_address, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;
  if (!user) {
    log_error("Not foud any user.");
    return -1;
  }
  
  // 检查用户有效性
  if (!user_is_valid(user)) {
    log_error("User is invalid in ev_close_session");
    return -1;
  }

  log_debug("Close session  ip=%0x status=%d lifecycle_state=%d\n", 
            user->ip, user->status, user->lifecycle_state);
  
  // 防止重复关闭
  if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
    log_debug("Session already closing or closed, skip");
    return 0;
  }

  /* 注意: 不能在此处无条件清零 acct_enable。
   * acct_enable=0 表示该会话没有可用的记账身份(NFT 恢复出的会话),
   * 下面 RADIUS 关闭分支用它决定是否发 Accounting-Stop;
   * 若在这里清零, 所有正常在线会话都会跳过 Stop, 造成整段账务丢失。 */

  char close_ip_str[INET_ADDRSTRLEN] = {0};
  struct in_addr close_addr;
  close_addr.s_addr = user->ip;
  inet_ntop(AF_INET, &close_addr, close_ip_str, sizeof(close_ip_str));

  switch (user->status) {
    case USER_STATE_AUTHED:
    case USER_STATE_FREE:
      user->status = USER_STATE_DROPPING;
      close_session_all_timers(user);
      if (user->inst->config->auth_source == AUTH_SOURCE_LOCAL) {
        /*
         * 本地认证源: 无 RADIUS Stop。先把本会话增量流量/在线时长
         * 终算落盘, 再删 nft 放行规则并立即销毁会话。
         */
        log_info(
            "Close session(local): user='%s' ip=%s -> flush usage and cleanup",
            user->user_name, close_ip_str);
        {
          int flush_rc = local_auth_flush_session(user, 1);
          if (remove_authed_ip(user) != 0) {
            log_error("Close session(local): NFT revoke failed, keep session "
                      "for retry ip=%s", close_ip_str);
            user->local_flush_final_pending = (flush_rc != 0);
            start_nft_revoke_retry(user, flush_rc == 0);
            return -1;
          }
          if (flush_rc != 0) {
            log_warn("Close session(local): usage save pending, keep retry "
                     "record ip=%s", close_ip_str);
            user->local_flush_final_pending = 1;
            return -1;
          }
        }
        del_user(user->inst, user);
      } else if (user->inst->config->auth_source == AUTH_SOURCE_HTTP) {
        /*
         * HTTP(S) 认证源: 记账 Stop 异步 fire-and-forget(不等待应答),
         * 随即删 nft 放行规则并销毁会话。
         */
        log_info(
            "Close session(http): user='%s' ip=%s -> send acct Stop and "
            "cleanup",
            user->user_name, close_ip_str);
        http_send_acct(user, HTTP_ACCT_STOP);
        if (remove_authed_ip(user) != 0) {
          log_error("Close session(http): NFT revoke failed, keep session "
                    "for retry ip=%s", close_ip_str);
          start_nft_revoke_retry(user, 1);
          return -1;
        }
        del_user(user->inst, user);
      } else if (user->acct_enable && user->user_name[0] != '\0' &&
                 user->acct_session_id[0] != '\0') {
        log_info(
            "Close session: user='%s' ip=%s status=%d -> DROPPING, "
            "send stop accounting",
            user->user_name, close_ip_str, user->status);
        send_stop_acct(user);
        start_waitting_acct_response_timer(user);
      } else {
        /* 无有效记账身份(如 NFT 恢复出的会话): 发 Accounting-Stop 只会
         * 产生 User-Name/Acct-Session-Id 为空的垃圾账务记录, 且服务器无法
         * 关联到原会话。这里只撤权并释放会话。 */
        log_warn(
            "Close session: no accounting identity (acct_enable=%d "
            "user='%s' session-id='%s'), revoke only ip=%s",
            user->acct_enable, user->user_name, user->acct_session_id,
            close_ip_str);
        if (remove_authed_ip(user) != 0) {
          log_error("Close session: NFT revoke failed, keep session for retry "
                    "ip=%s", close_ip_str);
          start_nft_revoke_retry(user, 1);
          return -1;
        }
        del_user(user->inst, user);
      }
      // remove_authed_ip(user);
      break;
    case USER_STATE_INIT:
      user->status = USER_STATE_DROPPING;
      close_session_all_timers(user);
      del_user(user->inst, user);
      break;
    case USER_STATE_AUTHING:

      break;
    case USER_STATE_DROPPING:

      break;

    default:

      del_user(user->inst, user);
      break;
  }

  return 0;
}

int ev_auth_timeout(struct user_address_t* user_address, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;
  uint8_t index = user->rad_id;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_warn(
      "Auth timeout(20s): user='%s' ip=%s auth_source=%d rad id=%u "
      "authtype=%d",
      user->user_name, inet_ntoa(tmp), user->inst->config->auth_source, index,
      user->authtype);
  //   uint16_t offset = 0;
  //   uint8_t payload[PAYLOAD_SIZE] = {0};
  //  int pid = getpid();
  stop_auth_timer(user);

  /* HTTP 认证源: 清理在途 curl 请求(20s 兜底触发时 curl 自身超时未生效) */
  http_auth_cancel_auth(user);

  if (user->ev_rad_auth) {
    event_del(user->ev_rad_auth);
    event_free(user->ev_rad_auth);
    user->ev_rad_auth = NULL;
  }
  if (user->rad_auth_fd >= 0) {
    close(user->rad_auth_fd);
    user->rad_auth_fd = -1;
  }
  user->status = USER_STATE_INIT;

  if (user->authtype == USER_AUTH_TYPE_PORTAL) {
    if (user->inst->config->auth_source == AUTH_SOURCE_HTTP) {
      complete_portal_auth_reply(user, PORTAL_HTTP_AUTH_TIMEOUT, NULL);
    } else {
      complete_portal_auth_reply(user, PORTAL_AUTH_TIMEOUT, NULL);
    }
  } else {
    user->authtype = USER_AUTH_TYPE_PORTAL;
  }

  log_debug("Auth timeout . Close session  ip=%0x status=%d\n", user->ip,
            user->status);
  start_waiting_auth_timer(user);

  
  //process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
  return 0;


}

int ev_rep_account(struct user_address_t* user_address, void* arg) { return 0; }

static struct ev_act_t action_events[] = {
    {EV_NEW_USER, ev_new_user},
    {EV_AUTH_ACCEPT, ev_auth_accept},
    {EV_AUTH_REJECT, ev_auth_reject},
    {EV_AUTH_TIMEOUT, ev_auth_timeout},
    {EV_UPDATE_CONFIG, ev_update_config},

    {EV_CLOSE_SESSION, ev_close_session},
    {EV_RECV_COA, ev_recv_CoA},
    //  {EV_IDLE_CHECK_TIMER, ev_idle_check_timer},

};

int process_server_events(int event, struct user_address_t* user_address,
                          void* arg) {
  int i;
  int rc = -1;
  int len = sizeof(action_events) / sizeof(action_events[0]);
  // printf("event=%d\n",event);
  for (i = 0; i < len; i++) {
    if (action_events[i].event == event) {
      rc = action_events[i].events_func(user_address, arg);
      break;
    }
  }
  return rc;
}

