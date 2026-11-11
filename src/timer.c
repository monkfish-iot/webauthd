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
#include "timer.h"

#include <arpa/inet.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "uci_config.h"

// #include "nacStationDB.h"
#include "app_events.h"
#include "session.h"

// #include "database.h"
#include "config.h"
#include "nft.h"
#include "http_auth.h"
#include "http_client.h"
#include "nft.h"
#include "portal_server.h"
#include "radius.h"
#include "session.h"




int is_out_account_time(uint32_t hours_rule) {
  time_t now;
  struct tm* t;
  uint32_t now_hour = 0;
  time(&now);
  t = localtime(&now);
  now_hour = 1 << (t->tm_hour);
  // printf("hour=%d now_hour=%u hours_rule=%u\n", t->tm_hour, now_hour,
  // hours_rule);
  if (now_hour & hours_rule) {
    return 0;
  }
  return -1;
}

/* 延迟释放 event: libevent 禁止在事件回调中直接 event_free 当前正在执行的
 * 事件(use-after-free)。stop_xxx 既可能在外部下线路径被调用, 也可能在该
 * event 自身的回调内(经 EV_CLOSE_SESSION -> close_session_all_timers)被调用,
 * 统一把真正的 event_free 推迟到本轮回调结束后的下一次事件循环,
 * 由 event_base_once 触发(该一次性事件由 libevent 自动释放)。 */
static void defer_event_free_cb(evutil_socket_t fd, short what, void* arg) {
  struct event* ev = (struct event*)arg;
  (void)fd;
  (void)what;
  if (ev) {
    event_free(ev);
  }
}

static void defer_event_free(struct event* ev, struct event_base* base) {
  struct timeval zero;

  if (!ev) {
    return;
  }
  zero.tv_sec = 0;
  zero.tv_usec = 0;
  /* base 不可用或排程失败时只能立即释放(极端退化路径) */
  if (!base ||
      event_base_once(base, -1, EV_TIMEOUT, defer_event_free_cb, ev, &zero) <
          0) {
    event_free(ev);
  }
}

static void bypass_timeout_cb(const int fd, const short event, void* arg) {
  struct inst_t* inst = (struct inst_t*)arg;

  // db_syn_users(inst);
  inst->inst_status = INST_MASTER;
  log_debug("Close bypass timer");
}

static void update_accounting_timeout_cb(const int fd, const short event,
                                         void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  struct in_addr tmp;

  if (!user) {
    log_error("User is NULL or invalid in update_accounting callback.");
    return;
  }
  
  // 额外检查：确保用户处于ACTIVE状态
  if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
    log_debug("User %p is in lifecycle_state=%d (not ACTIVE), skipping update_accounting", 
              user, user->lifecycle_state);
    user_put(user);
    return;
  }

  struct inst_t* inst = user->inst;
  tmp.s_addr = user->ip;

  if (user->status == USER_STATE_AUTHED) {
    log_debug("%s accounting . status=%d portal type=%d", inet_ntoa(tmp),
              user->status, inst->config->portal_type);
    if (inst->config->portal_type == LOCAL_PORTAL ||
        inst->config->portal_type == EXTERNAL_PORTAL ||
        inst->config->portal_type == CLOUD_PORTAL) {
      //  start_acct_timer(user);

      int rc;
      if (inst->config->auth_source == AUTH_SOURCE_HTTP) {
        /* HTTP 认证源: Interim 更新走 HTTP 记账(fire-and-forget) */
        rc = http_send_acct(user, HTTP_ACCT_INTERIM);
        if (rc < 0) {
          log_error(
              "Send HTTP interim accounting failed! user='%s' ip=%s",
              user->user_name, inet_ntoa(tmp));
        } else {
          log_debug("HTTP interim accounting dispatched: user='%s' ip=%s, "
                    "next in %us",
                    user->user_name, inet_ntoa(tmp), user->acct_interval);
        }
        user_put(user);
        return;
      }
      rc = send_update_acct(user);
      if (rc < 0) {
        log_error(
            "Send RADIUS interim(Alive) accounting failed! user='%s' ip=%s",
            user->user_name, inet_ntoa(tmp));
        //  stop_acct_timer(user);
      } else {
        log_info(
            "RADIUS interim(Alive) accounting sent: user='%s' ip=%s "
            "bytes=%d, next in %us",
            user->user_name, inet_ntoa(tmp), rc, user->acct_interval);
      }
    } else {
      log_warn(
          "Skip interim accounting for user='%s' ip=%s: portal_type=%d "
          "unsupported",
          user->user_name, inet_ntoa(tmp), inst->config->portal_type);
    }
  } else {
    /* 在线用户若不是 AUTHED(例如被异常置为 DROPPING), 周期更新会被静默
       跳过; 这里用 warn 明确暴露, 便于定位"不发记账更新"问题 */
    log_warn(
        "Skip interim accounting for user='%s' ip=%s: status=%u is not "
        "AUTHED",
        user->user_name, inet_ntoa(tmp), user->status);
  }

  user_put(user);
}

static void idle_check_timer_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  if (!user) {
    log_debug("User is NULL or invalid in idle_check callback.");
    return;
  }

  if (user->idle_timeout == 0) {
    log_debug("Idle check disabled (idle_timeout=0)");
    stop_idle_check_timer(user);
    user_put(user);
    return;
  }

  /* 仅对已认证放行的会话做空闲判定, 避免下线中间态(DROPPING等)重复触发 */
  if (user->status != USER_STATE_AUTHED &&
      user->status != USER_STATE_FREE) {
    struct in_addr skip_ip;
    skip_ip.s_addr = user->ip;
    log_debug(
        "Idle check skip for user='%s' ip=%s: status=%u is not AUTHED/FREE",
        user->user_name, inet_ntoa(skip_ip), user->status);
    /* 非持久定时器已触发完毕, 释放事件对象及它持有的引用(若已被下线
       流程释放则为安全空操作) */
    stop_idle_check_timer(user);
    user_put(user);
    return;
  }

  struct in_addr tmp;
  tmp.s_addr = user->ip;
  uint64_t cur_bytes = user->inbytes + user->outbytes;

  if (user->last_sum_bytes == cur_bytes) {
    /* 连续 idle_timeout 秒 nft counter 字节数无增长 -> 空闲下线。
       ev_close_session 会置 DROPPING 并在 RADIUS 可用时发送
       Accounting-Stop, 之后由应答回调或 5s 兜底定时器删除 nft 规则 */
    log_info(
        "Idle timeout(%lds) reached, no traffic for user='%s' ip=%s "
        "(in+out=%llu), closing session and sending RADIUS Stop",
        (long)user->idle_timeout, user->user_name, inet_ntoa(tmp),
        (unsigned long long)cur_bytes);
    process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
    user_put(user);
    return;
  }

  log_debug(
      "Idle check: user='%s' ip=%s still active, bytes %llu -> %llu, "
      "rearm idle timer in %lds",
      user->user_name, inet_ntoa(tmp),
      (unsigned long long)user->last_sum_bytes,
      (unsigned long long)cur_bytes, (long)user->idle_timeout);
  user->last_sum_bytes = cur_bytes;
  start_idle_check_timer(user);

  user_put(user);
}

static void session_timeout_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  //  printf("+++++++++ip=%0x\n",ip);
  if (!user) {
    log_debug("User is NULL or invalid in session_timeout callback.");
    return;
  }
  if (user->session_timeout == 0) {
    log_error("session timeout = 0");
    user_put(user);
    return;
  }

  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_debug("%s's session is timeout.ip=%s \n", user->user_name,
            inet_ntoa(tmp));
  // drop_user(user);

  process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
  user_put(user);
  //  process_server_events(EV_USER_DROP_USER, NULL, (void*) user);
}

int start_update_accounting_timer(struct user_session_t* user) {
  struct timeval tv;

  struct in_addr tmp;
  tmp.s_addr = user->ip;

  if (user->acct_interval == 0) {
    user->acct_interval = user->inst->config->acct_interval;
  }
  log_debug("Start update accounting timer.Interval=%d", user->acct_interval);
  tv.tv_sec = user->acct_interval;
  tv.tv_usec = 0;

  /* 防重入: 已存在计时更新定时器时先释放, 避免 event_new 覆盖指针泄漏 */
  if (user->ev_update_accounting) {
    stop_update_accounting_timer(user);
  }

  // 定时器持有引用
  user_get(user);
  
  user->ev_update_accounting =
      event_new(user->inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                update_accounting_timeout_cb, (void*)user);
  if (user->ev_update_accounting) {
    if (event_add(user->ev_update_accounting, &tv) != 0) {
      log_error("Failed to add update accounting timer");
      event_free(user->ev_update_accounting);
      user->ev_update_accounting = NULL;
      user_put(user);  // 失败时释放引用
      return -1;
    }

    log_info(
        "Accounting interim timer armed: user='%s' ip=%s period=%us",
        user->user_name, inet_ntoa(tmp), user->acct_interval);
  } else {
    log_error(
        "Start update accounting timer failed. period=%us ip=%s",
        user->acct_interval, inet_ntoa(tmp));
    user_put(user);  // 失败时释放引用
    return -1;
  }

  return 0;
}

int stop_update_accounting_timer(struct user_session_t* user) {
  struct in_addr tmp;
  if (!user) {
    return -1;
  }
  tmp.s_addr = user->ip;
  log_debug("Close update accounting-timer.ip=%s,status=%u ", inet_ntoa(tmp),
            user->status);
  // printf("+++++++++++unauth_timer:%u\n", sta.unauthed_timer);
  if (user->ev_update_accounting) {
    // 对于持久化定时器，确保使用event_del移除它
    int ret = event_del(user->ev_update_accounting);
    if (ret != 0) {
      log_error("Failed to delete update_accounting timer for ip=%s", inet_ntoa(tmp));
    }
    event_free(user->ev_update_accounting);
    user->ev_update_accounting = NULL;
    user_put(user);  // 释放定时器持有的引用
    log_debug("Successfully stopped update_accounting timer for ip=%s", inet_ntoa(tmp));
  } else {
    log_debug("update_accounting timer already NULL for ip=%s", inet_ntoa(tmp));
  }
  return 0;
}

int start_session_timer(struct user_session_t* user) {
  struct timeval tv;
  log_debug("Start session-timeout timer.Session-timeout=%d",
            user->session_timeout);
  if (user->session_timeout == 0) {
    return 0;
  }
  tv.tv_sec = (user->session_timeout > MAX_SESSION_TIMEOUT) ? MAX_SESSION_TIMEOUT : user->session_timeout;
  tv.tv_usec = 0;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  
  /* 防重入: 已存在会话超时定时器时先释放, 避免 event_new 覆盖指针泄漏 */
  if (user->session_timer) {
    stop_session_timer(user);
  }

  // 定时器持有引用
  user_get(user);
  
  user->session_timer = event_new(user->inst->base, -1, EV_TIMEOUT,
                                  session_timeout_cb, (void*)user);
  if (user->session_timer) {
      if (event_add(user->session_timer, &tv) != 0) {
      log_error("Failed to add session timer for ip=%s", inet_ntoa(tmp));
      event_free(user->session_timer);
      user->session_timer = NULL;
      user_put(user);  // 失败时释放引用
      return -1;
    }

    log_debug("Start session-timeout timer .Timeout=%u ip=%s",
              user->session_timeout, inet_ntoa(tmp));

  } else {
    log_debug("Start session-timeout timer failed.Timeout=%u ip=%s",
              user->session_timeout, inet_ntoa(tmp));
    user_put(user);  // 失败时释放引用
    return -1;
  }
  return 0;
}

void droping_timer_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;

  if (!user) {
    log_error("dropping timer failed!\n");
    return;
  }
  struct in_addr tmp;
  if (user->ip == 0) {
    log_debug("Invalid IP address!\n");
    return;
  }
  tmp.s_addr = user->ip;
  log_debug("droping timer callback.ip=%s\n", inet_ntoa(tmp));

  //  del_user(user->inst, user);
}

int start_droping_timer(struct user_session_t* user) {
  struct timeval tv;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  event_base_once(user->inst->base, -1, EV_TIMEOUT, droping_timer_cb,
                  (void*)user, &tv);
}

int start_auth_timer(struct inst_t* inst, struct user_session_t* user) {
  struct timeval tv;

  tv.tv_sec = 20;
  tv.tv_usec = 0;
  log_debug("Start auth timer");
  
  // 定时器持有引用
  user_get(user);
  
  user->ev_auth_timer =
      event_new(inst->base, -1, EV_TIMEOUT, auth_timeout_cb, (void*)user);
  if (!user->ev_auth_timer) {
    log_error("Failed to create auth timer");
    user_put(user);  // 失败时释放引用
    return -1;
  }
  if (event_add(user->ev_auth_timer, &tv) != 0) {
    log_error("Failed to add auth timer");
    event_free(user->ev_auth_timer);
    user->ev_auth_timer = NULL;
    user_put(user);  // 失败时释放引用
    return -1;
  }
  return 0;

  //        start_rad_session(inst, user);
}

int stop_auth_timer(struct user_session_t* user) {
  if (!user) {
    log_error("stop_auth_timer   failed!\n");
    return -1;
  }
  if (user->ev_auth_timer) {
    struct event* ev = user->ev_auth_timer;
    event_del(ev);
    user->ev_auth_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
    defer_event_free(ev, user->inst->base);
  }

  return 0;
  //  return stop_rad_session(user);
}

void unauthed_timer_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  struct user_address_t user_address = {0};
  struct in_addr tmp;

  if (!user) {
    log_debug("User is NULL or invalid in unauthed_timer callback.");
    return;
  }

  tmp.s_addr = user->ip;
  log_debug("unauthed timer callback.ip=%s\n", inet_ntoa(tmp));
  user->send_stop_msg = 0;
  //  process_server_events(EV_USER_DROP_USER, NULL, (void*) user);

  if (user->status == USER_STATE_AUTHED || user->status == USER_STATE_FREE) {
    /* 认证已成功: 该定时器只负责回收"未认证"会话, 立即停止并返回,
     * 不能继续走下面的 5 分钟回收逻辑, 否则在线会话会被误删 */
    stop_unauthed_timer(user);
    user_put(user);
    return;
  }

  if (user->last_auth > 0) {
    if (get_now_time() - user->last_auth > 300) {
      user_address.ip = user->ip;
      memcpy(user_address.mac, user->mac, 6);
      process_server_events(EV_CLOSE_SESSION, &user_address, (void*)user);
    }
  }
  // drop_user(user);
  log_debug("%0x(status=%d) unauthed is timeout ", user->ip, user->status);
  user_put(user);
}

int start_unauthed_timer(struct user_session_t* user) {
  struct timeval tv;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  struct inst_t* inst = user->inst;

  /* 已存在则不重复创建, 避免重复持引用/覆盖事件指针 */
  if (user->unauthed_timer) {
    return 0;
  }

  tv.tv_sec = 60;  // inst->config->idle_timeout;
  tv.tv_usec = 0;
  
  // 定时器持有引用
  user_get(user);
  
  user->unauthed_timer =
      event_new(user->inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                unauthed_timer_cb, (void*)user);
  if (user->unauthed_timer) {
      if (event_add(user->unauthed_timer, &tv) != 0) {
          log_error("Failed to add unauthed timer for ip=%s", inet_ntoa(tmp));
          event_free(user->unauthed_timer);
          user->unauthed_timer = NULL;
          user_put(user);  // 失败时释放引用
          return -1;
      }
      log_debug("Start unauthed-timer .Timeout=%d ip=%s", tv.tv_sec, inet_ntoa(tmp));
  } else {
      log_error("Failed to create unauthed timer for ip=%s", inet_ntoa(tmp));
      user_put(user);  // 失败时释放引用
      return -1;
  }
  return 0;
}

int stop_unauthed_timer(struct user_session_t* user) {
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_debug("Close unauthed-timer.ip=%s,status=%u ", inet_ntoa(tmp),
            user->status);
  // printf("+++++++++++unauth_timer:%u\n", sta.unauthed_timer);
  if (user->unauthed_timer) {
    event_del(user->unauthed_timer);
    /* 本函数可能在该事件自身的回调中被调用, 采用延迟释放 */
    defer_event_free(user->unauthed_timer, user->inst->base);
    user->unauthed_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
  }
  return 0;
}

int stop_session_timer(struct user_session_t* user) {
  if (!user) {
    log_error("stop_session_timer error!");
    return -1;
  }
  if (user->session_timeout > 0) {
    // printf("+++++++++++session_timer:%u\n", user->session_timer);
    if (user->session_timer == NULL) {
      return 0;
    }

    struct in_addr tmp;
    tmp.s_addr = user->ip;

    if (user->session_timer) {
      struct event* ev = user->session_timer;
      event_del(ev);
      user->session_timer = NULL;
      user_put(user);  // 释放定时器持有的引用
      defer_event_free(ev, user->inst->base);
      log_debug("Close session-timer.ip=%s,status=%u ", inet_ntoa(tmp),
                user->status);
    } else {
      log_debug("Close session-timer failed.ip=%s,status=%u ", inet_ntoa(tmp),
                user->status);
    }
  }
  return 0;
}

int start_bypass_timer(struct inst_t* inst) {
  struct timeval tv;
  tv.tv_sec = 30;
  tv.tv_usec = 0;

  if (event_base_once(inst->base, -1, EV_TIMEOUT, bypass_timeout_cb,
                      (void*)inst, &tv) < 0) {
    log_debug("Start bypass timer failed. ");

    return -1;
  }
  log_debug("Start bypass timer .");
  return 0;
}

int start_idle_check_timer(struct user_session_t* user) {
  struct timeval tv;

  if(!user){
    log_error("start_idle_check_timer error!");
    return -1;
  }
  if (user->idle_timeout == 0) {
    log_debug("Don't start idle-timeout timer.");
    return 0;
  } 
  struct in_addr tmp;
  tmp.s_addr = user->ip;

if (user->ev_idle_timer) {
    // 如果已经存在定时器，先删除再创建新的
    struct event* old_ev = user->ev_idle_timer;
    event_del(old_ev);
    user->ev_idle_timer = NULL;
    user_put(user);  // 释放旧定时器的引用
    defer_event_free(old_ev, user->inst->base);
}




  log_debug("Start idle-timeout timer.Timeout=%ld ip=%s", user->idle_timeout,inet_ntoa(tmp));
  tv.tv_sec = user->idle_timeout;
  tv.tv_usec = 0;

  /* 以启动时刻的累计字节数作为本轮空闲判定基准,
     语义为"从此刻起 idle_timeout 秒内字节数无增长则下线"。
     nft counter 由全局 5s 扫描任务(update_session)持续刷新 */
  user->last_sum_bytes = user->inbytes + user->outbytes;

  // 新定时器持有引用
  user_get(user);
  
  user->ev_idle_timer = event_new(user->inst->base, -1, EV_TIMEOUT ,
                                  idle_check_timer_cb, (void*)user);
  if (user->ev_idle_timer) {
    if (event_add(user->ev_idle_timer, &tv) != 0) {
      log_error("Failed to add idle timer");
      event_free(user->ev_idle_timer);
      user->ev_idle_timer = NULL;
      user_put(user);  // 失败时释放引用
      return -1;
    }
    user->idle_update_time = get_now_time();
    log_info(
        "Idle timer armed: user='%s' ip=%s timeout=%lds base-bytes=%llu",
        user->user_name, inet_ntoa(tmp), (long)user->idle_timeout,
        (unsigned long long)user->last_sum_bytes);

  } else {
    log_debug("Start idle-timeout timer failed.Timeout=%ld ip=%s",
              user->idle_timeout, inet_ntoa(tmp));
    user_put(user);  // 失败时释放引用
    return -1;
  }
  return 0;
}

int stop_idle_check_timer(struct user_session_t* user) {
  // printf("++++++++++++++++++++++++Close idle-timer.\n");

  if (!user) {
    log_error("stop_idle_timer error!");
    return -1;
  }

  struct in_addr tmp;
  tmp.s_addr = user->ip;

  if (user->ev_idle_timer) {
    struct event* ev = user->ev_idle_timer;
    event_del(ev);
    user->ev_idle_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
    defer_event_free(ev, user->inst->base);
    log_debug("Close idle-timer.ip=%s,status=%u ", inet_ntoa(tmp),
              user->status);
  } else {
    log_debug("Close idle-timer failed.ip=%s,status=%u ", inet_ntoa(tmp),
              user->status);
  }

  return 0;
}

/* 释放延时会话释放定时器(dropping_timer)。
 * 自 del_user 改用 event_base_once 调度 delayed_free_user_cb 后,
 * dropping_timer 恒为 NULL(event_base_once 由 libevent 自动释放),
 * 此函数仅作防御性清理: 若存在则 event_del + event_free, 不调用 user_put。 */
static void stop_dropping_timer(struct user_session_t* user) {
  if (!user || !user->dropping_timer) {
    return;
  }
  event_del(user->dropping_timer);
  event_free(user->dropping_timer);
  user->dropping_timer = NULL;
}

static void nft_revoke_retry_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  int delete_on_success;
  (void)fd;
  (void)event;

  if (!user) {
    return;
  }
  if (remove_authed_ip(user) != 0) {
    log_warn("NFT revoke retry still pending for user='%s'", user->user_name);
    user_put(user);
    return;
  }

  delete_on_success = user->nft_revoke_delete_on_success;
  stop_nft_revoke_retry(user);
  if (delete_on_success && !user->local_flush_final_pending) {
    del_user(user->inst, user);
  }
  user_put(user);
}

int start_nft_revoke_retry(struct user_session_t* user,
                           int delete_on_success) {
  struct timeval tv = {5, 0};

  if (!user || !user_is_valid(user)) {
    return -1;
  }
  if (delete_on_success) {
    user->nft_revoke_delete_on_success = 1;
  }
  if (user->ev_nft_revoke_retry) {
    return 0;
  }
  user_get(user); /* timer ownership */
  user->ev_nft_revoke_retry =
      event_new(user->inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                nft_revoke_retry_cb, user);
  if (!user->ev_nft_revoke_retry ||
      event_add(user->ev_nft_revoke_retry, &tv) != 0) {
    if (user->ev_nft_revoke_retry) {
      event_free(user->ev_nft_revoke_retry);
      user->ev_nft_revoke_retry = NULL;
    }
    user_put(user);
    return -1;
  }
  return 0;
}

int stop_nft_revoke_retry(struct user_session_t* user) {
  struct event* ev;
  if (!user || !user->ev_nft_revoke_retry) {
    return 0;
  }
  ev = user->ev_nft_revoke_retry;
  event_del(ev);
  user->ev_nft_revoke_retry = NULL;
  user_put(user); /* release timer ownership */
  defer_event_free(ev, user->inst->base);
  return 0;
}

int close_session_all_timers(struct user_session_t* user) {
  if (!user) {
    log_error("close all timers error!");
    return -1;
  }
  
  log_debug("Closing all timers for %s...",user->user_name);
  stop_waiting_auth_timer(user);
  stop_idle_check_timer(user);
  stop_session_timer(user);
  stop_auth_timer(user);
  stop_unauthed_timer(user);
  stop_update_accounting_timer(user);
  //stop_delay_acct_stop_timer(user);
  stop_waitting_acct_response_timer(user);
  stop_check_data_timer(user);
  stop_nft_revoke_retry(user);
  /* delayed_free_timer 也是一次性事件, 需要显式释放, 否则每次删会话泄漏一个 event */
  stop_dropping_timer(user);
  log_debug("Closed all timers!");
  return 0;
}

int stop_waitting_acct_response_timer(struct user_session_t* user) {
  if (!user) {
    log_error("stop waitting account response timer error!");
    return -1;
  }
  log_debug("stop waitting account response timer! user status=%u username=%s acct_status_type=%u",
    user->status,user->user_name,user->acct_status_type );
  if (user->ev_waitting_acct_response_timer) {
    struct event* ev = user->ev_waitting_acct_response_timer;
    event_del(ev);
    user->ev_waitting_acct_response_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
    defer_event_free(ev, user->inst->base);
  }

  return 0;
}

static void waitting_acct_response_timeout_cb(const int fd, const short event,
                                              void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  if (!user) {
    log_error("account timeout.Not found user!");
    return;
  }
  {
    struct in_addr acct_to_addr;
    char acct_to_ip[INET_ADDRSTRLEN] = {0};
    acct_to_addr.s_addr = user->ip;
    inet_ntop(AF_INET, &acct_to_addr, acct_to_ip, sizeof(acct_to_ip));
    log_warn(
        "RADIUS accounting response timeout(5s): acct-type=%u(1=Start "
        "2=Stop 3=Alive) user='%s' ip=%s session-id='%s'",
        user->acct_status_type, user->user_name, acct_to_ip,
        user->acct_session_id);
  }
  // printf("+++++++++++++++++12\n");
  stop_waitting_acct_response_timer(user);

  if (user->ev_rad_acct) {
    log_debug("free acct event");

    event_del(user->ev_rad_acct);
    event_free(user->ev_rad_acct);
    user->ev_rad_acct = NULL;
  }

  if (user->rad_acct_fd) {
    log_debug("close acct socket");
    close(user->rad_acct_fd);
    user->rad_acct_fd = -1;
  }
  // 下线中的会话必须确认撤权成功后才能销毁；失败保留重试责任。
  if(user->status == USER_STATE_DROPPING){
      if (remove_authed_ip(user) != 0) {
          start_nft_revoke_retry(user, 1);
          user_put(user);
          return;
      }
  }

  del_user(user->inst, user);
  user_put(user);

 // process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);

  return;
}

int start_waitting_acct_response_timer(struct user_session_t* user) {
  struct timeval tv;

  tv.tv_sec = 5;
  tv.tv_usec = 0;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  
  // 定时器持有引用
  user_get(user);
  
  user->ev_waitting_acct_response_timer =
      event_new(user->inst->base, -1, EV_TIMEOUT,
                waitting_acct_response_timeout_cb, (void*)user);
  if (user->ev_waitting_acct_response_timer) {
    if (event_add(user->ev_waitting_acct_response_timer, &tv) != 0) {
      log_error("Failed to add waitting_acct_response timer");
      event_free(user->ev_waitting_acct_response_timer);
      user->ev_waitting_acct_response_timer = NULL;
      user_put(user);  // 失败时释放引用
      return -1;
    }
    user->idle_update_time = get_now_time();
    log_debug("Start acct-timeout timer .Timeout=%d ip=%s", tv.tv_sec,
              inet_ntoa(tmp));

  } else {
    log_debug("Start acct-timeout timer failed.Timeout=%d ip=%s", tv.tv_sec,
              inet_ntoa(tmp));
    user_put(user);  // 失败时释放引用
    return -1;
  }
  return 0;
}

void waiting_auth_timeout_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  if (!user) {
    log_error("waiting auth timeout.Not found user!");
    return;
  }
  stop_waiting_auth_timer(user);
  process_server_events(  EV_CLOSE_SESSION, NULL,(void*)user);
  user_put(user);
}

int start_waiting_auth_timer(struct user_session_t* user) {
  struct timeval tv;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  struct inst_t* inst = user->inst;
  tv.tv_sec = 60;
  tv.tv_usec = 0;
  
  /* 防重入: 已存在等待认证定时器时先释放, 避免 event_new 覆盖指针导致
   * 旧事件与其引用计数泄漏——多次拒绝/超时后会话槽位会永久占用 */
  if (user->ev_waiting_auth_timer) {
    stop_waiting_auth_timer(user);
  }

  // 定时器持有引用
  user_get(user);
  
  user->ev_waiting_auth_timer =
      event_new(inst->base, -1, EV_TIMEOUT, waiting_auth_timeout_cb, (void*)user);
  if (user->ev_waiting_auth_timer) {
      if (event_add(user->ev_waiting_auth_timer, &tv) != 0) {
          log_error("Failed to add waiting-auth timer for ip=%s", inet_ntoa(tmp));
          event_free(user->ev_waiting_auth_timer);
          user->ev_waiting_auth_timer = NULL;
          user_put(user);  // 失败时释放引用
          return -1;
      }
      log_debug("Start waiting auth timer .  ip=%s", inet_ntoa(tmp));
  } else {
      log_error("Failed to create waiting-auth timer for ip=%s", inet_ntoa(tmp));
      user_put(user);  // 失败时释放引用
      return -1;
  }
  return 0;
}

int stop_waiting_auth_timer(struct user_session_t* user) {
  if (!user) {
    log_error("User is  NULL!");
    return -1;
  }
  if (user->ev_waiting_auth_timer) {
    struct event* ev = user->ev_waiting_auth_timer;
    event_del(ev);
    user->ev_waiting_auth_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
    defer_event_free(ev, user->inst->base);
  }
  log_debug("Stop waiting auth timer . ");
  return 0;
}
void check_data_timer_cb(const int fd, const short event, void* arg) {}

int start_check_data_timer(struct user_session_t* user) {
  struct timeval tv;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  struct inst_t* inst = user->inst;
  tv.tv_sec = 5;  // inst->config->idle_timeout;
  tv.tv_usec = 0;
  
  // 定时器持有引用
  user_get(user);
  
  user->ev_check_data_timer = event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                                        check_data_timer_cb, (void*)user);
  if (user->ev_check_data_timer) {
      if (event_add(user->ev_check_data_timer, &tv) != 0) {
          log_error("Failed to add check-data timer for ip=%s", inet_ntoa(tmp));
          event_free(user->ev_check_data_timer);
          user->ev_check_data_timer = NULL;
          user_put(user);  // 失败时释放引用
          return -1;
      }
      log_debug("Start check-data-timer .  ip=%s", inet_ntoa(tmp));
  } else {
      log_error("Failed to create check-data timer for ip=%s", inet_ntoa(tmp));
      user_put(user);  // 失败时释放引用
      return -1;
  }
  return 0;
}

int stop_check_data_timer(struct user_session_t* user) {
  if (!user) {
    log_error("stop check data timer error!");
    return -1;
  }
  if (user->ev_check_data_timer) {
    event_del(user->ev_check_data_timer);
    event_free(user->ev_check_data_timer);
    user->ev_check_data_timer = NULL;
    user_put(user);  // 释放定时器持有的引用
  }

  return 0;
}

#if 0
void delay_acct_stop_timer_cb(const int fd, const short event, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;
  if (!user) {
    log_error("delay account stop timeout.Not found user!");

    return;
  }
  log_debug("delay account stop timeout.acct-type=%u", user->acct_status_type);
  if (!user->ev_waitting_acct_response_timer) {
    send_stop_acct(user);
    start_waitting_acct_response_timer(user);
  }
}

int start_delay_acct_stop_timer(struct user_session_t* user) {
  struct timeval tv;
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  struct inst_t* inst = user->inst;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  user->ev_delay_acct_stop_timer =
      event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                delay_acct_stop_timer_cb, (void*)user);
  event_add(user->ev_delay_acct_stop_timer, &tv);
  log_debug("Start check-data-timer .  ip=%s", inet_ntoa(tmp));
  return 0;
}

int stop_delay_acct_stop_timer(struct user_session_t* user) {
  if (!user) {
    log_error("stop delay acct stop timer error!");
    return -1;
  }
  if (user->ev_delay_acct_stop_timer) {
    event_del(user->ev_delay_acct_stop_timer);
    event_free(user->ev_delay_acct_stop_timer);
    user->ev_delay_acct_stop_timer = NULL;
  }

  return 0;
}
#endif
