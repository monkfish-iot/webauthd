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
 * session.c - 用户会话管理主文件
 *
 * 使用固定大小的哈希数组实现会话管理：
 * - 数组大小为 INST_USER_MAX (256)
 * - 通过 userip 的最低一个字节 (ip & 0xFF) 定位索引
 * - 若索引冲突，使用拉链（双向链表）解决
 */

#include "session.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <event.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include "app_events.h"
#include "config.h"
#include "http_auth.h"
#include "http_service.h"
#include "log.h"
#include "radius.h"
#include "timer.h"
#include "utensils.h"

// 用户会话池：固定大小数组
static struct user_session_t g_user_pool[INST_USER_MAX];
// 空闲位图：0 表示空闲，1 表示占用
static uint8_t g_user_used[INST_USER_MAX];
// 哈希桶头指针数组（拉链表头）
static struct user_session_t *g_user_head[INST_USER_MAX];
// 已使用的会话数
static int g_used_count = 0;

// ==================== 引用计数管理函数 ====================

int user_is_valid(struct user_session_t* user) {
  if (!user) {
    return 0;
  }
  if (user->magic != USER_MAGIC_VALID) {
    log_error("Invalid user magic: 0x%08x (expected 0x%08x)", user->magic, USER_MAGIC_VALID);
    return 0;
  }
  if (user->lifecycle_state == USER_LIFECYCLE_ZOMBIE) {
    log_debug("User %p is in ZOMBIE state", user);
    return 0;
  }
  return 1;
}

struct user_session_t* user_get(struct user_session_t* user) {
  if (!user_is_valid(user)) {
    log_error("Attempt to get reference to invalid user %p", user);
    return NULL;
  }

  if (user->lifecycle_state == USER_LIFECYCLE_CLOSING) {
    log_debug("User %p is closing, deny new reference", user);
    return NULL;
  }

  user->ref_count++;
  log_debug("user_get: %p ref_count++ = %d (ip=0x%08x)", user, user->ref_count, user->ip);
  return user;
}

void user_put(struct user_session_t* user) {
  if (!user) {
    return;
  }

  if (user->magic != USER_MAGIC_VALID) {
    log_error("Attempt to put reference to invalid user %p (magic=0x%08x)", user, user->magic);
    return;
  }

  user->ref_count--;
  log_debug("user_put: %p ref_count-- = %d (ip=0x%08x)", user, user->ref_count, user->ip);

  if (user->ref_count < 0) {
    log_error("BUG: user %p ref_count is negative: %d", user, user->ref_count);
    user->ref_count = 0;
  }

  if (user->ref_count == 0 && user->lifecycle_state == USER_LIFECYCLE_ZOMBIE) {
    log_debug("user_put: ref_count=0 and ZOMBIE, freeing user %p (ip=0x%08x)", user, user->ip);
    free_session((void*)user);
  }
}

// ==================== 会话管理 ====================

int init_sessions(struct inst_t* inst) {
  (void)inst; // 保留参数一致性，但不需要

  memset(g_user_pool, 0, sizeof(g_user_pool));
  memset(g_user_used, 0, sizeof(g_user_used));
  memset(g_user_head, 0, sizeof(g_user_head));
  g_used_count = 0;

  log_info("Static user session pool initialized: max_users=%d", INST_USER_MAX);
  return 0;
}

int close_session_all_timers(struct user_session_t* user);
static uint32_t user_ip_hash(uint32_t ip);

// 从拉链中移除节点
static void remove_from_chain(struct user_session_t* user) {
  uint32_t index = user_ip_hash(user->ip);

  /* 幂等保护: user 已不在链表上时直接返回, 避免 free_session 二次调用
   * 误执行 g_user_head[index] = user->next(NULL) 清空整桶头指针,
   * 导致同桶其余在线用户失联。
   * 判定依据: prev/next 均为 NULL 且桶头 != user 说明 user 已被摘链;
   * 唯一例外是 user 为桶内唯一节点(prev==next==NULL 但 g_user_head==user)。 */
  if (!user->prev && !user->next && g_user_head[index] != user) {
    return;
  }

  if (user->prev) {
    user->prev->next = user->next;
  } else {
    g_user_head[index] = user->next;
  }

  if (user->next) {
    user->next->prev = user->prev;
  }

  user->next = NULL;
  user->prev = NULL;
}

void free_session(void* data) {
  if (!data) {
    return;
  }

  struct user_session_t* user = (struct user_session_t*)data;

  int index = user - g_user_pool;
  if (index < 0 || index >= INST_USER_MAX) {
    log_error("free_session: User %p is not in static pool", user);
    return;
  }

  if (!g_user_used[index]) {
    log_error("free_session: User %p (index=%d) is already freed", user, index);
    return;
  }

  user->magic = USER_MAGIC_FREED;

  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_debug("free_session: Freeing user %p (index=%d, ip=%s, ref_count=%d)",
            user, index, inet_ntoa(tmp), user->ref_count);

  // 先从拉链中移除
  remove_from_chain(user);

  close_session_all_timers(user); // 忽略返回值，因为我们正在释放用户

  /* HTTP 认证源: 取消在途认证请求, 防止 curl 完成回调触到已释放会话 */
  http_auth_cancel_user(user);

  if (user->req) {
    user->req = NULL;
  }
  if (user->repBuf) {
    evbuffer_free(user->repBuf);
    user->repBuf = NULL;
  }

  if (user->ev_rad_auth) {
    event_free(user->ev_rad_auth);
    user->ev_rad_auth = NULL;
  }
  if (user->ev_rad_acct) {
    event_free(user->ev_rad_acct);
    user->ev_rad_acct = NULL;
  }
  if (user->rad_auth_fd > 0) {
    close(user->rad_auth_fd);
    user->rad_auth_fd = -1;
  }
  if (user->rad_acct_fd > 0) {
    close(user->rad_acct_fd);
    user->rad_acct_fd = -1;
  }

  if (user->rad_pkg) {
    free(user->rad_pkg);
    user->rad_pkg = NULL;
  }

  if (user->rad_server_addr) {
    free(user->rad_server_addr);
    user->rad_server_addr = NULL;
  }
  if (user->rad_session) {
    free(user->rad_session);
    user->rad_session = NULL;
  }

  log_debug("free_session: User %p freed completely", user);

  g_user_used[index] = 0;
  g_used_count--;

  memset(user, 0, sizeof(struct user_session_t));
}

int destroy_sessions(struct inst_t* inst) {
  (void)inst;
  /* 按槽位遍历而不是只沿拉链遍历: ZOMBIE/CLOSING 会话可能已从拉链摘除,
   * 但仍有定时器引用挂在 event base 上。必须先注销这些定时器, 否则
   * memset 完成后回调仍会访问已清零的会话对象。 */
  for (int i = 0; i < INST_USER_MAX; i++) {
    struct user_session_t* user = &g_user_pool[i];

    if (!g_user_used[i] || user->magic != USER_MAGIC_VALID) {
      continue;
    }

    close_session_all_timers(user);

    /* close_session_all_timers 释放引用后可能已回收该槽位 */
    if (!g_user_used[i] || user->magic != USER_MAGIC_VALID) {
      continue;
    }

    // 强制释放所有资源
    http_auth_cancel_user(user);
    if (user->repBuf) evbuffer_free(user->repBuf);
    if (user->ev_rad_auth) event_free(user->ev_rad_auth);
    if (user->ev_rad_acct) event_free(user->ev_rad_acct);
    if (user->rad_auth_fd > 0) close(user->rad_auth_fd);
    if (user->rad_acct_fd > 0) close(user->rad_acct_fd);
    if (user->rad_pkg) free(user->rad_pkg);
    if (user->rad_server_addr) free(user->rad_server_addr);
    if (user->rad_session) free(user->rad_session);
  }

  memset(g_user_pool, 0, sizeof(g_user_pool));
  memset(g_user_used, 0, sizeof(g_user_used));
  memset(g_user_head, 0, sizeof(g_user_head));
  g_used_count = 0;

  log_debug("Free sessions \t\tOK!");
  return 0;
}

static int find_free_slot(void) {
  for (int i = 0; i < INST_USER_MAX; i++) {
    if (!g_user_used[i]) {
      return i;
    }
  }
  return -1;
}

/* 把 IP 的高位也混入桶索引: 只用最低字节会让 10.0.x.y 这类地址
 * 在同一个 /24 内的前 8 位完全相同, 大量会话挤进同一拉链 */
static uint32_t user_ip_hash(uint32_t ip) {
  ip ^= ip >> 16;
  ip ^= ip >> 8;
  return ip & (INST_USER_MAX - 1);
}

struct user_session_t* create_user(struct inst_t* inst, uint32_t userip, uint8_t usermac[]) {
  int index = find_free_slot();
  if (index < 0) {
    log_error("No free user slot available (max=%d, used=%d)", INST_USER_MAX, g_used_count);
    return NULL;
  }

  struct user_session_t* new_user = &g_user_pool[index];
  g_user_used[index] = 1;
  g_used_count++;

  memset(new_user, 0, sizeof(struct user_session_t));

  new_user->magic = USER_MAGIC_VALID;
  new_user->ref_count = 1;
  new_user->lifecycle_state = USER_LIFECYCLE_ACTIVE;

  new_user->status = USER_STATE_INIT;
  new_user->rad_auth_fd = -1;
  new_user->rad_acct_fd = -1;
  snprintf(new_user->called_station_id, 128, "%02x:%02x:%02x:%02x:%02x:%02x",
           inst->dev_mac[0], inst->dev_mac[1], inst->dev_mac[2],
           inst->dev_mac[3], inst->dev_mac[4], inst->dev_mac[5]);

  new_user->create_time = get_now_time();

  new_user->ip = userip;
  memcpy(new_user->mac, usermac, 6);
  new_user->inst = inst;
  new_user->last_auth = get_now_time();
  new_user->start_time = get_now_time();
  new_user->acct_interval = inst->config->acct_interval;
  new_user->ev_delay_acct_stop_timer = NULL;

  if (inst->config->mac_auth_enabled == RAD_MAC_AUTH_ENABLED) {
    new_user->authtype = USER_AUTH_TYPE_MAC;
  } else {
    new_user->authtype = USER_AUTH_TYPE_PORTAL;
  }

  new_user->acct_enable = 1;

  // 将新会话插入哈希桶（头插法）
  uint32_t hash_index = user_ip_hash(userip);
  new_user->next = g_user_head[hash_index];
  new_user->prev = NULL;
  if (g_user_head[hash_index]) {
    g_user_head[hash_index]->prev = new_user;
  }
  g_user_head[hash_index] = new_user;

  log_debug("Created user %p (index=%d, ip=%s, used=%d/%d)",
            new_user, index, inet_ntoa(*(struct in_addr*)&userip), g_used_count, INST_USER_MAX);

  return new_user;
}

struct user_session_t* find_user(struct inst_t* inst, uint32_t userip, uint8_t usermac[]) {
  (void)inst;
  uint32_t index = user_ip_hash(userip);

  struct user_session_t* user = g_user_head[index];
  while (user) {
    if (user->ip == userip) {
      if (usermac) {
        memcpy(usermac, user->mac, 6);
      }
      return user;
    }
    user = user->next;
  }

  return NULL;
}

int set_user_status(struct inst_t* inst, uint32_t userip, uint8_t usermac[], int status) {
  log_debug("set_user_status");
  struct user_session_t* session = find_user(inst, userip, usermac);
  if (session) {
    session->status = status;
    return 0;
  } else {
    struct in_addr tmp;
    tmp.s_addr = userip;
    log_error("Not found user %s (%s)", inet_ntoa(tmp), __func__);
  }
  return -1;
}

void auth_timeout_cb(const int fd, const short event, void *arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  if (user == NULL) {
    log_error("auth timeout. Not found auth session .");
    return;
  }

  process_server_events(EV_AUTH_TIMEOUT, NULL, arg);

  user_put(user);
  return;
}

static void delayed_free_user_cb(evutil_socket_t fd, short what, void* arg) {
  struct user_session_t* user = (struct user_session_t*)arg;

  if (!user) {
    log_error("delayed_free_user_cb: user is NULL");
    return;
  }

  if (user->magic != USER_MAGIC_VALID) {
    log_error("delayed_free_user_cb: Invalid magic 0x%08x, already freed?", user->magic);
    return;
  }

  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_debug("delayed_free_user_cb: Delayed free timer triggered for user %s (ip=0x%08x, ref_count=%d)",
            inet_ntoa(tmp), user->ip, user->ref_count);

  user_put(user);

  log_debug("delayed_free_user_cb: Released create reference");
}

int del_user(struct inst_t* inst, struct user_session_t* user) {
  if (!user) {
    return -1;
  }

  if (user->magic != USER_MAGIC_VALID) {
    log_error("del_user: Invalid user magic 0x%08x", user->magic);
    return -1;
  }

  int index = user - g_user_pool;
  if (index < 0 || index >= INST_USER_MAX) {
    log_error("del_user: User %p is not in static pool", user);
    return -1;
  }

  if (!g_user_used[index]) {
    log_error("del_user: User %p (index=%d) is already freed", user, index);
    return -1;
  }

  struct in_addr tmp;
  tmp.s_addr = user->ip;
  log_debug("del_user: Start deleting user %s (index=%d, ip=0x%08x, ref_count=%d, state=%d)",
            inet_ntoa(tmp), index, user->ip, user->ref_count, user->lifecycle_state);

  if (user->lifecycle_state == USER_LIFECYCLE_CLOSING ||
      user->lifecycle_state == USER_LIFECYCLE_ZOMBIE) {
    log_debug("del_user: User already in closing/zombie state, skip");
    return 0;
  }

  // 先临时标记为 CLOSING 并从拉链中移除，防止并发访问
  // 这里不移除拉链，让 free_session 在 ref_count 归零时处理。
  // 但为了 find_user 找不到它（避免重复创建），我们先移除拉链。
  remove_from_chain(user);

  user->lifecycle_state = USER_LIFECYCLE_CLOSING;

  /* 关闭所有尚未触发的会话定时器, 释放它们持有的引用/owns事件。
   * 否则如 Start 应答超时后 idle 定时器仍持有引用, 会话会永久停留在
   * ZOMBIE 状态占住静态槽位, 且该事件对象也不会被释放 */
  close_session_all_timers(user);

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  /* 改用 event_base_once: 一次性事件由 libevent 在回调结束后自动释放,
   * 避免在 delayed_free_user_cb 内经 free_session -> close_session_all_timers
   * -> stop_dropping_timer 对"正在执行的 event"做 event_free 的 use-after-free 风险 */
  if (event_base_once(inst->base, -1, EV_TIMEOUT, delayed_free_user_cb,
                      (void*)user, &tv) < 0) {
    log_error("del_user: Failed to schedule delayed free timer");
    free_session(user);
    return 0;
  }

  user->lifecycle_state = USER_LIFECYCLE_ZOMBIE;

  log_debug("del_user: User %s scheduled for delayed free (5 seconds)", inet_ntoa(tmp));
  return 0;
}

int get_all_user(struct user_session_t* table, int page, int page_size) {
  return g_used_count;
}

int db_check_sessions(struct inst_t* inst) {
  return 0;
}

int db_stop_sessions(struct inst_t* inst, uint32_t user_ip, int auth_type) {
  return 0;
}

char* get_status_string(int status) {
  switch (status) {
    case USER_STATE_NONE: return "NONE";
    case USER_STATE_INIT: return "INIT";
    case USER_STATE_AUTHING: return "AUTHING";
    case USER_STATE_AUTHED: return "AUTHED";
    case USER_STATE_FREE: return "FREE";
    case USER_STATE_DROPPING: return "DROPPING";
    default: return "UNKNOWN";
  }
}

int restore_user(struct inst_t* inst) {
  return 0;
}

static void cleanup_auth_attempt(struct user_session_t* user) {
  if (!user) {
    return;
  }

  stop_auth_timer(user);

  if (user->ev_rad_auth) {
    event_del(user->ev_rad_auth);
    event_free(user->ev_rad_auth);
    user->ev_rad_auth = NULL;
  }

  if (user->rad_auth_fd >= 0) {
    close(user->rad_auth_fd);
    user->rad_auth_fd = -1;
  }
}

static void fail_auth_start(struct user_session_t* user, int reply_code) {
  struct evhttp_request* req = user->req;

  log_error("Start portal authentication failed, reply_code=%d", reply_code);
  cleanup_auth_attempt(user);
  user->req = NULL;
  user->status = USER_STATE_INIT;
  user->http_reply_code = reply_code;

  if (req) {
    send_http_reply(req, reply_code, NULL);
  }
}

/* 按 mac_auth_format 把二进制 MAC 格式化成 RADIUS 认证用的字符串 */
static void format_mac_for_auth(const struct user_session_t* user, int style,
                                char* out, size_t outsz) {
  const uint8_t* m = user->mac;

  switch (style) {
    case 0:  /* 小写无分隔符 */
      snprintf(out, outsz, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3],
               m[4], m[5]);
      break;
    case 2:  /* 大写带冒号 */
      snprintf(out, outsz, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2],
               m[3], m[4], m[5]);
      break;
    case 3:  /* 大写无分隔符 */
      snprintf(out, outsz, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3],
               m[4], m[5]);
      break;
    case 1:  /* 小写带冒号(默认) */
    default:
      snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2],
               m[3], m[4], m[5]);
      break;
  }
}

/*
 * MAC 无感知认证: 以 MAC 作为 User-Name / User-Password(明文, 由
 * generate_pap_passwd 做 PAP 编码), CALLING-STATION-ID 由 send_radius_pkg
 * 的 add_attr 取 user->mac。
 *
 * 该路径没有 HTTP 请求, 因此不能复用 do_user_auth(它要求 user->req 非空),
 * 这里自行置状态、起 20s 单次认证定时器并发送 Access-Request。
 * 启动失败时回退为 PORTAL, 使后续请求仍能弹出 portal 页面。
 */
int mac_radius_auth(struct inst_t* inst, struct user_session_t* user) {
  char mac_str[32] = {0};
  char ip_str[INET_ADDRSTRLEN] = {0};
  struct in_addr user_addr;

  if (!inst || !user || !inst->config) {
    log_error("mac_radius_auth: invalid argument");
    return -1;
  }

  user_addr.s_addr = user->ip;
  inet_ntop(AF_INET, &user_addr, ip_str, sizeof(ip_str));

  format_mac_for_auth(user, inst->config->mac_auth_format, mac_str,
                      sizeof(mac_str));

  memset(user->user_name, 0, sizeof(user->user_name));
  memset(user->user_password, 0, sizeof(user->user_password));
  snprintf(user->user_name, sizeof(user->user_name), "%s", mac_str);
  snprintf(user->user_password, sizeof(user->user_password), "%s", mac_str);

  user->authtype = USER_AUTH_TYPE_MAC;
  user->status = USER_STATE_AUTHING;
  user->http_reply_code = PORTAL_START_RAD_ERROR;

  log_info("MAC auth begin: mac=%s ip=%s format=%d", mac_str, ip_str,
           inst->config->mac_auth_format);

  if (start_auth_timer(inst, user) < 0) {
    log_error("Start RADIUS auth timer failed, mac=%s ip=%s", mac_str, ip_str);
    user->status = USER_STATE_INIT;
    user->authtype = USER_AUTH_TYPE_PORTAL;
    return -1;
  }

  if (send_rad_auth(user) <= 0) {
    log_error("Send RADIUS Access-Request failed, mac=%s ip=%s", mac_str,
              ip_str);
    cleanup_auth_attempt(user);
    user->status = USER_STATE_INIT;
    user->authtype = USER_AUTH_TYPE_PORTAL;
    return -1;
  }

  log_info(
      "MAC RADIUS Access-Request dispatched, waiting for reply, mac=%s ip=%s",
      mac_str, ip_str);
  return 0;
}

int do_user_auth(struct user_session_t* user) {
  char ip_str[INET_ADDRSTRLEN] = {0};
  struct in_addr user_addr;

  if (!user || !user->inst || !user->inst->base || !user->req) {
    log_error("Invalid user or event base/request when starting auth");
    return -1;
  }

  user_addr.s_addr = user->ip;
  inet_ntop(AF_INET, &user_addr, ip_str, sizeof(ip_str));

  if (user->status != USER_STATE_AUTHING) {
    log_error("Can not start auth, user status=%u", user->status);
    return -1;
  }

  log_info("Portal auth begin: user='%s' ip=%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
           user->user_name, ip_str, user->mac[0], user->mac[1], user->mac[2],
           user->mac[3], user->mac[4], user->mac[5]);

  cleanup_auth_attempt(user);

  user->authtype = USER_AUTH_TYPE_PORTAL;
  user->http_reply_code = PORTAL_START_RAD_ERROR;

  if (start_auth_timer(user->inst, user) < 0) {
    log_error("Start RADIUS auth timer failed, user='%s' ip=%s",
              user->user_name, ip_str);
    fail_auth_start(user, PORTAL_START_RAD_ERROR);
    return -1;
  }
  log_debug("RADIUS auth timer started (20s), user='%s' ip=%s",
            user->user_name, ip_str);

  if (send_rad_auth(user) <= 0) {
    log_error("Send RADIUS Access-Request failed, user='%s' ip=%s",
              user->user_name, ip_str);
    fail_auth_start(user, PORTAL_SEND_RAD_ERROR);
    return -1;
  }

  log_info("RADIUS Access-Request dispatched, waiting for reply, user='%s' ip=%s",
           user->user_name, ip_str);
  return 0;
}

// 外部辅助函数：遍历所有会话，供 ws_users 和 nft_audit 使用
// 遍历所有哈希桶，对每个活跃会话调用回调
void for_each_user_session(void (*callback)(struct user_session_t* user, void* ctx), void* ctx) {
  if (!callback) return;

  for (int i = 0; i < INST_USER_MAX; i++) {
    struct user_session_t* user = g_user_head[i];
    while (user) {
      struct user_session_t* next = user->next; // 保存下一个节点防止回调中释放
      if (user_is_valid(user)) {
        callback(user, ctx);
      }
      user = next;
    }
  }
}

/* ------------------------------------------------------------------------ */
/* 时钟跳变检测（无 RTC 设备的 NTP 校准防护）                                 */
/*                                                                           */
/* 板子无 RTC，开机时系统时钟为 sysfixtime 保存的旧时间，NTP 同步后时钟会     */
/* 一次性前跳数小时。会话的 acct_start_time / start_time / local_flush_mark  */
/* 均以墙钟记录，若不修正：在线时长(now - acct_start_time) 与本地认证落盘    */
/* 增量(now - local_flush_mark) 会被一次性虚增（表现为用户刚上线几分钟后     */
/* portal-users 页显示在线数小时）。                                         */
/*                                                                           */
/* 这里由 nft.c 的 5s 全局扫描定时器驱动：对比墙钟与 CLOCK_MONOTONIC 的      */
/* 增量，偏差超过阈值即判定为校时跳变，把所有活跃会话的时间锚点按跳变量      */
/* 平移，各处 now - anchor 的口径即恢复正确。                                */
/* ------------------------------------------------------------------------ */

long mono_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)ts.tv_sec;
}

typedef struct {
  long jump; /* 墙钟相对单调钟的跳变量（正=前跳） */
} clock_rebase_ctx_t;

static void clock_rebase_cb(struct user_session_t* user, void* ctx) {
  long jump = ((clock_rebase_ctx_t*)ctx)->jump;

  if (user->acct_start_time > 0)
    user->acct_start_time += jump;
  if (user->start_time > 0)
    user->start_time += jump;
  if (user->local_flush_mark > 0)
    user->local_flush_mark += jump;
}

void clock_jump_check(void) {
  static long last_wall = 0; /* 上次检查的墙钟时刻（CLOCK_REALTIME） */
  static long last_mono = 0; /* 上次检查的单调钟时刻 */
  long wall = (long)time(NULL);
  long mono = mono_now();
  long jump;
  clock_rebase_ctx_t ctx;

  if (last_wall == 0) {
    last_wall = wall;
    last_mono = mono;
    return;
  }

  jump = (wall - last_wall) - (mono - last_mono);
  last_wall = wall;
  last_mono = mono;

  /* 5s 周期内墙钟与单调钟的增量应基本一致；±30s 阈值容忍普通漂移与
   * NTP 微调（slew），超出即为 ntpd 步进校时等引起的跳变 */
  if (jump > -30 && jump < 30)
    return;

  ctx.jump = jump;
  for_each_user_session(clock_rebase_cb, &ctx);
  log_info("Clock jump detected: %+lds (wall vs monotonic), "
           "session time anchors rebased",
           jump);
}

