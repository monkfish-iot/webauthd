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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * ubus_service.c - webauthd 的 ubus 服务端框架
 *
 * 设计要点:
 *   1. 条件编译 WEBAUTHD_ENABLE_UBUS, 默认开启;
 *   2. 主进程使用 libevent, 因此不使用 uloop_run(), 而是把 ubus socket
 *      挂到 libevent 上, 可读时调用 ubus_handle_event();
 *   3. 连接 ubusd 失败/断线时仅告警并定时重连, portal/RADIUS 主业务不受影响;
 *   4. drop_user 复用 HTTP /v1/drop_user 同一条 EV_CLOSE_SESSION 流程:
 *      RADIUS 在线发 Accounting-Stop, 5 秒兜底删 nft 规则并销毁会话;
 *      list_users 口径与 HTTP /v1/get_online_users 一致并支持分页(page/page_size);
 *   5. "登录后才能访问"由 rpcd 会话与 ACL(/usr/share/rpcd/acl.d/webauthd.json)
 *      保证: LuCI 登录后携带有效 session 经 rpcd 调用才会被放行;
 *      本机 root 直接 `ubus call` 是 OpenWrt 设计上的固有通道, 不做拦截。
 */
#ifdef WEBAUTHD_ENABLE_UBUS

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include <event.h>
#include <libubox/blobmsg.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "app_events.h"
#include "config.h"
#include "instance.h"
#include "local_auth.h"
#include "log.h"
#include "session.h"
#include "ubus_service.h"
#include "utensils.h"

#define UBUS_OBJECT_NAME "webauthd.session"
#define UBUS_METHOD_DROP "drop_user"
#define UBUS_METHOD_LIST "list_users"
#define UBUS_METHOD_CONTROL_STATUS "control_status"
#define UBUS_USER_OBJECT_NAME "webauthd.user"
#define UUSER_METHOD_LIST "list"
#define UUSER_METHOD_GET "get"
#define UUSER_METHOD_ADD "add"
#define UUSER_METHOD_DEL "del"
#define UUSER_METHOD_SET "set"
#define UBUS_RECONNECT_INTERVAL_SEC 3

/* list_users 分页参数: page 从 1 开始; page_size 缺省 20, 最大钳制 100 */
#define UBUS_LIST_DEFAULT_PAGE 1
#define UBUS_LIST_DEFAULT_PAGE_SIZE 20
#define UBUS_LIST_MAX_PAGE_SIZE 100

/* 个别 libubus 版本未在头文件导出默认 socket 路径宏, 做兜底 */
#ifndef UBUS_UNIX_SOCKET
#define UBUS_UNIX_SOCKET "/var/run/ubus/ubus.sock"
#endif

/* drop_user 方法的返回码(放在响应 body 中, 语义化正数;
 * ubus 层状态码仍返回标准 UBUS_STATUS_*) */
#define UBUS_DROP_CODE_OK 0
#define UBUS_DROP_CODE_INVALID_ARG 400
#define UBUS_DROP_CODE_NOT_FOUND 404
#define UBUS_DROP_CODE_INTERNAL 500

/* drop_user 入参(全部可选, 但至少给一个; 给多个为 AND) */
enum {
  DROP_ARG_USERNAME,
  DROP_ARG_IP,
  DROP_ARG_MAC,
  DROP_ARG_SESSION_ID,
  __DROP_ARG_MAX
};

static const struct blobmsg_policy drop_policy[__DROP_ARG_MAX] = {
    [DROP_ARG_USERNAME] = {.name = "username", .type = BLOBMSG_TYPE_STRING},
    [DROP_ARG_IP] = {.name = "ip", .type = BLOBMSG_TYPE_STRING},
    [DROP_ARG_MAC] = {.name = "mac", .type = BLOBMSG_TYPE_STRING},
    [DROP_ARG_SESSION_ID] =
        {.name = "session_id", .type = BLOBMSG_TYPE_STRING},
};

/* 归一化后的查询条件 */
struct drop_cond {
  int has_username;
  const char* username;
  int has_ip;
  uint32_t ip; /* 网络字节序, 与 user->ip 一致 */
  int has_mac;
  uint8_t mac[6];
  int has_session_id;
  const char* session_id;
  /* 回显用原始字符串, 用于错误信息 */
  const char* raw_ip;
  const char* raw_mac;
};

/* 遍历会话时的上下文 */
struct find_ctx {
  const struct drop_cond* cond;
  struct user_session_t* matched; /* 第一个命中者, 持有引用 */
};

static struct ubus_context* s_ctx = NULL;
static struct event* s_ubus_ev = NULL;
static struct event* s_retry_ev = NULL;
static struct inst_t* s_inst = NULL;

/* ------------------------------------------------------------------------ */
/* 工具函数                                                                 */
/* ------------------------------------------------------------------------ */

/*
 * 灵活解析 MAC: 兼容
 *   EE:94:3D:69:26:55 / ee-94-3d-69-26-55 / EE943D692655
 * 忽略大小写, 允许 '.' 和空白作为分隔符。
 * 成功返回 0。
 */
static int parse_mac_str(const char* s, uint8_t out[6]) {
  char hex[13];
  int n = 0;
  int i;

  if (!s || !out) {
    return -1;
  }

  for (; *s != '\0'; ++s) {
    unsigned char c = (unsigned char)*s;
    if (c == ':' || c == '-' || c == '.' || c == ' ') {
      continue;
    }
    if (!isxdigit(c)) {
      return -1;
    }
    if (n >= 12) {
      return -1;
    }
    hex[n++] = (char)tolower(c);
  }
  hex[n] = '\0';

  if (n != 12) {
    return -1;
  }

  for (i = 0; i < 6; ++i) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    char* endp = NULL;
    unsigned long v = strtoul(pair, &endp, 16);
    if (endp != pair + 2 || v > 0xFF) {
      return -1;
    }
    out[i] = (uint8_t)v;
  }
  return 0;
}

static void mac_to_str(const uint8_t mac[6], char* buf, size_t bufsz) {
  snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
}

/* 条件与单个会话是否同时满足(AND); 只匹配在线已认证用户 */
static int session_matches(const struct user_session_t* user,
                           const struct drop_cond* cond) {
  if (!user_is_valid((struct user_session_t*)user)) {
    return 0;
  }
  if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
    return 0;
  }
  if (user->status != USER_STATE_AUTHED &&
      user->status != USER_STATE_FREE) {
    return 0;
  }

  if (cond->has_username && strcmp(user->user_name, cond->username) != 0) {
    return 0;
  }
  if (cond->has_ip && user->ip != cond->ip) {
    return 0;
  }
  if (cond->has_mac && memcmp(user->mac, cond->mac, 6) != 0) {
    return 0;
  }
  if (cond->has_session_id &&
      strcmp(user->acct_session_id, cond->session_id) != 0) {
    return 0;
  }

  return 1;
}

static void find_first_cb(struct user_session_t* user, void* arg) {
  struct find_ctx* fc = (struct find_ctx*)arg;

  /* 已找到第一个, 后续跳过 */
  if (fc->matched) {
    return;
  }
  if (session_matches(user, fc->cond)) {
    /* 持有引用, 防止遍历结束后会话被其它事件释放 */
    fc->matched = user_get(user);
  }
}

/* 组装通用响应 */
static void send_reply(struct ubus_context* ctx, struct ubus_request_data* req,
                       int code, const char* msg,
                       const struct user_session_t* user) {
  /* 必须零初始化: 新版 libubox 的 blob_buf_init() 不再 memset, 而是复用
   * 结构体里已有的 grow/buflen/buf 状态(buf->buf 为 NULL 时才 realloc)。
   * 未初始化的栈变量会带着垃圾 grow 函数指针/长度, 直接 SIGSEGV。 */
  struct blob_buf buf = {0};

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", (uint32_t)code);
  if (msg) {
    blobmsg_add_string(&buf, "msg", msg);
  }

  if (code == UBUS_DROP_CODE_OK && user) {
    char mac_str[18] = {0};
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN] = {0};

    blobmsg_add_u32(&buf, "dropped", 1);

    ip_addr.s_addr = user->ip;
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
    mac_to_str(user->mac, mac_str, sizeof(mac_str));

    void* u = blobmsg_open_table(&buf, "user");
    blobmsg_add_string(&buf, "username", user->user_name);
    blobmsg_add_string(&buf, "ip", ip_str);
    blobmsg_add_string(&buf, "mac", mac_str);
    blobmsg_add_string(&buf, "session_id", user->acct_session_id);
    blobmsg_close_table(&buf, u);
  }

  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
}

/* ------------------------------------------------------------------------ */
/* drop_user 方法                                                           */
/* ------------------------------------------------------------------------ */

static int ubus_drop_user(struct ubus_context* ctx, struct ubus_object* obj,
                          struct ubus_request_data* req, const char* method,
                          struct blob_attr* msg) {
  struct blob_attr* tb[__DROP_ARG_MAX] = {0};
  struct drop_cond cond;
  struct find_ctx fc;
  struct user_address_t user_address;
  struct in_addr ip_addr;
  char ip_str[INET_ADDRSTRLEN] = {0};
  char mac_str[18] = {0};
  const char* cond_desc = "";
  int param_count = 0;

  (void)obj;
  (void)method;

  memset(&cond, 0, sizeof(cond));
  memset(&fc, 0, sizeof(fc));
  fc.cond = &cond;

  log_debug("[ubus] recv '%s' invoke, msg_len=%d", UBUS_METHOD_DROP,
            msg ? (int)blobmsg_len(msg) : -1);

  if (blobmsg_parse(drop_policy, __DROP_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
               "参数解析失败, 支持 username/ip/mac/session_id (string)", NULL);
    return UBUS_STATUS_INVALID_ARGUMENT;
  }

  if (tb[DROP_ARG_USERNAME]) {
    cond.has_username = 1;
    cond.username = blobmsg_get_string(tb[DROP_ARG_USERNAME]);
    if (cond.username[0] == '\0') {
      send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
                 "username 不能为空字符串", NULL);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    param_count++;
  }

  if (tb[DROP_ARG_IP]) {
    cond.raw_ip = blobmsg_get_string(tb[DROP_ARG_IP]);
    if (inet_pton(AF_INET, cond.raw_ip, &ip_addr) != 1) {
      send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
                 "ip 格式非法, 应为点分十进制 IPv4", NULL);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    cond.has_ip = 1;
    cond.ip = ip_addr.s_addr;
    param_count++;
  }

  if (tb[DROP_ARG_MAC]) {
    cond.raw_mac = blobmsg_get_string(tb[DROP_ARG_MAC]);
    if (parse_mac_str(cond.raw_mac, cond.mac) != 0) {
      send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
                 "mac 格式非法, 支持 AA:BB:CC:DD:EE:FF / AA-BB-... / AABBCCDDEEFF",
                 NULL);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    cond.has_mac = 1;
    param_count++;
  }

  if (tb[DROP_ARG_SESSION_ID]) {
    cond.has_session_id = 1;
    cond.session_id = blobmsg_get_string(tb[DROP_ARG_SESSION_ID]);
    if (cond.session_id[0] == '\0') {
      send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
                 "session_id 不能为空字符串", NULL);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    param_count++;
  }

  if (param_count == 0) {
    send_reply(ctx, req, UBUS_DROP_CODE_INVALID_ARG,
               "至少需要一个条件参数: username / ip / mac / session_id; "
               "给多个时需同时满足(AND)",
               NULL);
    return UBUS_STATUS_INVALID_ARGUMENT;
  }

  /* 仅下线第一个匹配的在线用户 */
  for_each_user_session(find_first_cb, &fc);

  if (!fc.matched) {
    /* 拼接条件回显, 便于调用方核对 */
    char desc[512];
    snprintf(desc, sizeof(desc),
             "没有同时满足所给条件的在线(已认证)用户 [username=%s ip=%s "
             "mac=%s session_id=%s]",
             cond.has_username ? cond.username : "-",
             cond.has_ip ? cond.raw_ip : "-",
             cond.has_mac ? cond.raw_mac : "-",
             cond.has_session_id ? cond.session_id : "-");
    log_warn("ubus drop_user: %s", desc);
    send_reply(ctx, req, UBUS_DROP_CODE_NOT_FOUND, desc, NULL);
    return UBUS_STATUS_NOT_FOUND;
  }

  ip_addr.s_addr = fc.matched->ip;
  inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
  mac_to_str(fc.matched->mac, mac_str, sizeof(mac_str));
  cond_desc = "matched first online user";

  log_info(
      "ubus drop_user: force disconnect user='%s' ip=%s mac=%s session_id='%s' "
      "(%s)",
      fc.matched->user_name, ip_str, mac_str, fc.matched->acct_session_id,
      cond_desc);

  /* 先应答(受理成功), 再复用统一关闭流程:
   * DROPPING -> RADIUS Stop -> 应答或 5s 兜底删 nft 规则/会话。
   * 与 HTTP /v1/drop_user 行为一致, 属于异步处理。 */
  send_reply(ctx, req, UBUS_DROP_CODE_OK, "ok", fc.matched);

  memset(&user_address, 0, sizeof(user_address));
  user_address.ip = fc.matched->ip;
  memcpy(user_address.mac, fc.matched->mac, 6);
  if (process_server_events(EV_CLOSE_SESSION, &user_address, fc.matched) < 0) {
    log_error("ubus drop_user: EV_CLOSE_SESSION failed for user='%s' ip=%s",
              fc.matched->user_name, ip_str);
  }

  user_put(fc.matched);
  return UBUS_STATUS_OK;
}

/* ------------------------------------------------------------------------ */
/* list_users 方法                                                          */
/* ------------------------------------------------------------------------ */

/* list_users 入参(全部可选; 不传走默认分页) */
enum {
  LIST_ARG_PAGE,
  LIST_ARG_PAGE_SIZE,
  __LIST_ARG_MAX
};

static const struct blobmsg_policy list_policy[__LIST_ARG_MAX] = {
    [LIST_ARG_PAGE] = {.name = "page", .type = BLOBMSG_TYPE_INT32},
    [LIST_ARG_PAGE_SIZE] =
        {.name = "page_size", .type = BLOBMSG_TYPE_INT32},
};

/* 遍历会话时的分页收集上下文。
 * 用户口径与 HTTP /v1/get_online_users 一致: for_each_user_session
 * 回调的所有 magic 有效会话(含认证中/下线中)均计入 total。 */
struct list_ctx {
  uint32_t start; /* 0 基, 含 */
  uint32_t end;   /* 0 基, 不含 */
  uint32_t total;
  uint32_t authed;
  int page_count;
  /* 仅持有当前页内会话的引用, 防止应答构造期间被其它事件释放;
   * 页大小被钳制在 UBUS_LIST_MAX_PAGE_SIZE, 数组按会话池上限开足 */
  struct user_session_t* page_users[INST_USER_MAX];
};

static void list_collect_cb(struct user_session_t* user, void* arg) {
  struct list_ctx* lc = (struct list_ctx*)arg;
  uint32_t idx = lc->total; /* 当前会话的 0 基序号 */

  lc->total++;
  if (user->status == USER_STATE_AUTHED) {
    lc->authed++;
  }

  if (idx >= lc->start && idx < lc->end &&
      lc->page_count < INST_USER_MAX) {
    lc->page_users[lc->page_count++] = user_get(user);
  }
}

static int ubus_list_users(struct ubus_context* ctx, struct ubus_object* obj,
                           struct ubus_request_data* req, const char* method,
                           struct blob_attr* msg) {
  struct blob_attr* tb[__LIST_ARG_MAX] = {0};
  struct list_ctx lc;
  /* 同 send_reply: 新版 libubox 的 blob_buf_init() 要求结构体为已初始化
   * (零值)状态, 否则会调用未初始化的 grow 指针导致 SIGSEGV。 */
  struct blob_buf buf = {0};
  uint32_t page = UBUS_LIST_DEFAULT_PAGE;
  uint32_t page_size = UBUS_LIST_DEFAULT_PAGE_SIZE;
  int i;

  (void)obj;
  (void)method;

  log_debug("[ubus] recv '%s' invoke, msg_len=%d", UBUS_METHOD_LIST,
            msg ? (int)blobmsg_len(msg) : -1);

  if (blobmsg_parse(list_policy, __LIST_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    blob_buf_init(&buf, 0);
    blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_INVALID_ARG);
    blobmsg_add_string(&buf, "msg",
                       "参数解析失败, 支持 page/page_size (int32)");
    ubus_send_reply(ctx, req, buf.head);
    blob_buf_free(&buf);
    return UBUS_STATUS_INVALID_ARGUMENT;
  }

  if (tb[LIST_ARG_PAGE]) {
    page = (uint32_t)blobmsg_get_u32(tb[LIST_ARG_PAGE]);
    if (page < 1) {
      blob_buf_init(&buf, 0);
      blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_INVALID_ARG);
      blobmsg_add_string(&buf, "msg", "page 必须 >= 1 (从 1 开始)");
      ubus_send_reply(ctx, req, buf.head);
      blob_buf_free(&buf);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
  }
  if (tb[LIST_ARG_PAGE_SIZE]) {
    page_size = (uint32_t)blobmsg_get_u32(tb[LIST_ARG_PAGE_SIZE]);
    if (page_size < 1) {
      blob_buf_init(&buf, 0);
      blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_INVALID_ARG);
      blobmsg_add_string(&buf, "msg", "page_size 必须 >= 1");
      ubus_send_reply(ctx, req, buf.head);
      blob_buf_free(&buf);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    if (page_size > UBUS_LIST_MAX_PAGE_SIZE) {
      page_size = UBUS_LIST_MAX_PAGE_SIZE;
    }
  }

  memset(&lc, 0, sizeof(lc));
  /* 会话池上限 INST_USER_MAX: 起始偏移超出池上限的页必然为空。
   * 先防 (page-1)*page_size 乘法溢出, 再把 start 抬到池上限;
   * end = start + page_size 最大为 256+100, 无 u32 溢出风险 */
  if (page - 1 > (INST_USER_MAX - 1) / page_size) {
    lc.start = INST_USER_MAX;
  } else {
    lc.start = (page - 1) * page_size;
  }
  lc.end = lc.start + page_size;

  /* 单次遍历完成计数与当前页引用收集; 持引用保证应答期间会话不被释放 */
  for_each_user_session(list_collect_cb, &lc);

  log_debug("[ubus] list_users: collected total=%u authed=%u page_items=%d, "
            "building reply ...",
            lc.total, lc.authed, lc.page_count);

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  blobmsg_add_u32(&buf, "total", lc.total);
  blobmsg_add_u32(&buf, "authed_users", lc.authed);
  blobmsg_add_u32(&buf, "page", page);
  blobmsg_add_u32(&buf, "page_size", page_size);
  blobmsg_add_u32(&buf, "count", (uint32_t)lc.page_count);

  void* arr = blobmsg_open_array(&buf, "users");
  long now_t = get_now_time();
  for (i = 0; i < lc.page_count; ++i) {
    struct user_session_t* user = lc.page_users[i];
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN] = {0};
    char mac_str[18] = {0};
    /* 元素名必须非空: 旧版 libubox 的 blobmsg_create_field 无条件
     * strlen(name), 传 NULL 会 SIGSEGV。array 元素的 name 在解析端被
     * 忽略(按字段长度步进), 给序号名不影响对外的数组 JSON 形态,
     * 且与 drop_user 已验证的带名 open_table 走同一条库路径。 */
    char elem_name[16];

    ip_addr.s_addr = user->ip;
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
    mac_to_str(user->mac, mac_str, sizeof(mac_str));

    snprintf(elem_name, sizeof(elem_name), "%d", i);
    void* u = blobmsg_open_table(&buf, elem_name);
    blobmsg_add_string(&buf, "username", user->user_name);
    blobmsg_add_u32(&buf, "status", user->status);
    blobmsg_add_string(&buf, "ip", ip_str);
    blobmsg_add_string(&buf, "mac", mac_str);
    blobmsg_add_string(&buf, "session_id", user->acct_session_id);
    /* session_time 字段仅在 RADIUS 记账(Interim/Stop)路径被回写, 本地认证源
     * 完全旁路 RADIUS 导致该字段恒为 0; 这里与 HTTP /v1/get_online_users
     * (ws_users.c)口径一致, 按 acct_start_time 即时计算在线时长 */
    long sess_time =
        (user->acct_start_time > 0 && now_t > user->acct_start_time)
            ? now_t - user->acct_start_time
            : 0;
    blobmsg_add_u32(&buf, "session_time", (uint32_t)sess_time);
    blobmsg_add_u32(&buf, "in_rate", user->in_rate);
    blobmsg_add_u32(&buf, "out_rate", user->out_rate);
    /* 流量字节可能超过 4GB, 必须用 u64 */
    blobmsg_add_u64(&buf, "in_bytes", user->inbytes);
    blobmsg_add_u64(&buf, "out_bytes", user->outbytes);
    /* 流量配额(字节, u64 拼接自 quota_giga_bytes/quota_bytes); 0 = 不限流量,
     * 供前端展示配额与剩余流量 */
    blobmsg_add_u64(&buf, "quota_bytes", user->quota_data);
    blobmsg_close_table(&buf, u);
  }
  blobmsg_close_array(&buf, arr);

  log_debug("[ubus] list_users: reply built, sending ...");

  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);

  for (i = 0; i < lc.page_count; ++i) {
    user_put(lc.page_users[i]);
  }

  log_debug("[ubus] list_users: page=%u page_size=%u total=%u returned=%d",
            page, page_size, lc.total, lc.page_count);
  return UBUS_STATUS_OK;
}

/* ------------------------------------------------------------------------ */
/* webauthd.user 对象: 本地用户库管理(local 认证源)                          */
/* ------------------------------------------------------------------------ */

/*
 * 五个方法 list/get/add/del/set 共用一条 blobmsg policy 超集,
 * 各方法只取所需子集, 因此所有参数均不设 REQUIRED 标志。
 *
 * 鉴权: config 的 api_secret 非空时, 每个方法必须携带相同的 secret 参数,
 * 否则 403; api_secret 为空表示不启用共享密钥(本机 root / 经 rpcd ACL
 * 的 LuCI 会话仍受系统访问控制保护)。
 *
 * body 业务码: 0=成功 400=参数非法 403=密钥不匹配 404=用户不存在
 *              409=冲突(重名/超 max_users) 500=文件读写等内部错误。
 * ubus 层状态码尽量镜像(body 409 映射 UBUS_STATUS_INVALID_ARGUMENT)。
 */
#define UUSER_CODE_OK          0
#define UUSER_CODE_INVALID   400
#define UUSER_CODE_FORBIDDEN 403
#define UUSER_CODE_NOT_FOUND 404
#define UUSER_CODE_CONFLICT  409
#define UUSER_CODE_INTERNAL  500

/* 响应中密码字段固定掩码(散列也绝不回传) */
#define UUSER_PW_MASK "******"
/* add/set 的明文密码长度限制(散列前); 上限 63 与会话缓冲
 * user_password[64](含 NUL)一致, 保证 portal 登录路径不会截断 */
#define UUSER_PW_MAX  63
/* page 合法上限, 防止 (page-1)*page_size 在 int 上溢出 */
#define UUSER_PAGE_MAX 1000000

enum {
  UUSER_ARG_SECRET,
  UUSER_ARG_USERNAME,
  UUSER_ARG_PASSWORD,
  UUSER_ARG_STATUS,
  UUSER_ARG_EXPIRE_TIME,
  UUSER_ARG_PAGE,
  UUSER_ARG_PAGE_SIZE,
  UUSER_ARG_MAC_AUTH,
  UUSER_ARG_MAX_MAC_BIND,
  UUSER_ARG_MAC_BIND_UPDATE_POLICY,
  UUSER_ARG_MAX_ONLINE,
  UUSER_ARG_ONLINE_CONFLICT_POLICY,
  UUSER_ARG_IN_SPEED,
  UUSER_ARG_OUT_SPEED,
  UUSER_ARG_DATA_QUOTA,
  UUSER_ARG_MACS,
  __UUSER_ARG_MAX
};

static const struct blobmsg_policy user_policy[__UUSER_ARG_MAX] = {
    [UUSER_ARG_SECRET] = {.name = "secret", .type = BLOBMSG_TYPE_STRING},
    [UUSER_ARG_USERNAME] = {.name = "username", .type = BLOBMSG_TYPE_STRING},
    [UUSER_ARG_PASSWORD] = {.name = "password", .type = BLOBMSG_TYPE_STRING},
    [UUSER_ARG_STATUS] = {.name = "status", .type = BLOBMSG_TYPE_STRING},
    [UUSER_ARG_EXPIRE_TIME] =
        {.name = "expire_time", .type = BLOBMSG_TYPE_STRING},
    [UUSER_ARG_PAGE] = {.name = "page", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_PAGE_SIZE] = {.name = "page_size", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_MAC_AUTH] = {.name = "mac_auth", .type = BLOBMSG_TYPE_BOOL},
    [UUSER_ARG_MAX_MAC_BIND] =
        {.name = "max_mac_bind", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_MAC_BIND_UPDATE_POLICY] =
        {.name = "mac_bind_update_policy", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_MAX_ONLINE] = {.name = "max_online", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_ONLINE_CONFLICT_POLICY] =
        {.name = "online_conflict_policy", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_IN_SPEED] = {.name = "in_speed", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_OUT_SPEED] = {.name = "out_speed", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_DATA_QUOTA] = {.name = "data_quota", .type = BLOBMSG_TYPE_INT32},
    [UUSER_ARG_MACS] = {.name = "macs", .type = BLOBMSG_TYPE_ARRAY},
};

/* ---------------------------- 通用小工具 ------------------------------- */

/* 把可读错误写入 err 缓冲(本地用户库返回码回显用) */
static void uuser_set_err(char* err, size_t errsz, const char* fmt, ...) {
  va_list ap;

  if (!err || errsz == 0) {
    return;
  }
  va_start(ap, fmt);
  vsnprintf(err, errsz, fmt, ap);
  va_end(ap);
}

static void uuser_reply_code(struct ubus_context* ctx,
                             struct ubus_request_data* req, int code,
                             const char* msg) {
  /* 必须零初始化, 原因同 send_reply 注释 */
  struct blob_buf buf = {0};

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", (uint32_t)code);
  if (msg) {
    blobmsg_add_string(&buf, "msg", msg);
  }
  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
}

/* api_secret 校验: 未配置(空串)直接放行; 配置后用常量时间比较防时序侧信道。
 * 返回 0 通过, -1 拒绝。 */
static int uuser_secret_check(struct blob_attr** tb) {
  const char* want;
  const char* got;
  size_t n, i;
  volatile unsigned char diff = 0;

  if (!s_inst || !s_inst->config) {
    return -1;
  }
  want = s_inst->config->api_secret;
  if (want[0] == '\0') {
    return 0;
  }
  got = tb[UUSER_ARG_SECRET] ? blobmsg_get_string(tb[UUSER_ARG_SECRET]) : NULL;
  if (!got || strlen(got) != strlen(want)) {
    return -1;
  }
  n = strlen(want);
  for (i = 0; i < n; ++i) {
    diff |= (unsigned char)want[i] ^ (unsigned char)got[i];
  }
  return diff ? -1 : 0;
}

/* status 字符串 -> 结构体枚举: "active"/"1" -> 1, "disabled"/"0" -> 0,
 * 其它 -1(忽略大小写) */
static int uuser_parse_status(const char* s) {
  if (!s) {
    return -1;
  }
  if (strcasecmp(s, "active") == 0 || strcmp(s, "1") == 0) {
    return LOCAL_USER_STATUS_ACTIVE;
  }
  if (strcasecmp(s, "disabled") == 0 || strcmp(s, "0") == 0) {
    return LOCAL_USER_STATUS_DISABLED;
  }
  return -1;
}

/* expire_time 合法性: 空 = 永不过期(合法); 非空必须精确匹配
 * "YYYY-MM-DD HH:MM:SS"(本地时区) */
static int uuser_expire_valid(const char* s) {
  struct tm tm;

  if (!s) {
    return 0;
  }
  if (s[0] == '\0') {
    return 1;
  }
  memset(&tm, 0, sizeof(tm));
  return strptime(s, "%Y-%m-%d %H:%M:%S", &tm) != NULL;
}

/* 把请求中的 "macs" 字符串数组整体替换为该用户的 MAC 绑定文件。
 * 归一化为小写冒号格式, bind_time 填当前时间; 空数组 = 清空绑定。
 * 成功返回 0, 失败返回 -1 且 err 已写。 */
static int uuser_replace_macs(const char* username, struct blob_attr* macs,
                              char* err, size_t errsz) {
  struct local_mac_bind_t binds[LOCAL_MAC_BIND_MAX];
  struct blob_attr* pos;
  size_t rem;
  int cnt = 0;
  uint8_t mac[6];

  memset(binds, 0, sizeof(binds));
  rem = macs ? blobmsg_data_len(macs) : 0;
  pos = rem ? (struct blob_attr*)blobmsg_data(macs) : NULL;

  for (; pos && rem > 0; rem -= blob_pad_len(pos), pos = blob_next(pos)) {
    const char* s;

    if (rem < blob_pad_len(pos)) {
      break;
    }
    if (blob_id(pos) != BLOBMSG_TYPE_STRING) {
      uuser_set_err(err, errsz, "macs 数组元素必须是字符串(MAC 地址)");
      return -1;
    }
    if (cnt >= LOCAL_MAC_BIND_MAX) {
      uuser_set_err(err, errsz, "macs 数量超过上限 %d", LOCAL_MAC_BIND_MAX);
      return -1;
    }
    s = blobmsg_get_string(pos);
    if (local_mac_parse(s, mac) != 0) {
      uuser_set_err(err, errsz, "macs 元素 '%s' 不是合法 MAC 地址", s);
      return -1;
    }
    local_mac_to_str(mac, binds[cnt].mac, sizeof(binds[cnt].mac));
    local_time_format(get_now_time(), binds[cnt].bind_time,
                      sizeof(binds[cnt].bind_time));
    cnt++;
  }
  return local_mac_save(username, binds, cnt, err, errsz);
}

/* 组装单个用户条目(不含 macs 数组); online 为当前在线会话数 */
static void uuser_fill_user(struct blob_buf* buf,
                            const struct local_user_t* lu, int online) {
  blobmsg_add_string(buf, "username", lu->username);
  blobmsg_add_string(buf, "password", UUSER_PW_MASK);
  blobmsg_add_string(buf, "status",
                     (lu->status == LOCAL_USER_STATUS_ACTIVE) ? "active"
                                                              : "disabled");
  blobmsg_add_u8(buf, "mac_auth", lu->mac_auth ? 1 : 0);
  blobmsg_add_u32(buf, "max_mac_bind", (uint32_t)lu->max_mac_bind);
  blobmsg_add_u32(buf, "mac_bind_update_policy",
                  (uint32_t)lu->mac_bind_update_policy);
  blobmsg_add_u32(buf, "max_online", (uint32_t)lu->max_online);
  blobmsg_add_u32(buf, "online_conflict_policy",
                  (uint32_t)lu->online_conflict_policy);
  blobmsg_add_string(buf, "register_time", lu->register_time);
  blobmsg_add_string(buf, "last_login_time", lu->last_login_time);
  blobmsg_add_string(buf, "expire_time", lu->expire_time);
  blobmsg_add_u32(buf, "in_speed", lu->in_speed);
  blobmsg_add_u32(buf, "out_speed", lu->out_speed);
  blobmsg_add_u32(buf, "data_quota", lu->data_quota);
  blobmsg_add_u32(buf, "current_data", lu->current_data);
  blobmsg_add_u32(buf, "online_time", lu->online_time);
  blobmsg_add_u32(buf, "login_count", lu->login_count);
  blobmsg_add_u32(buf, "online_sessions", (uint32_t)online);
}

/* add/set 共用的整型参数合法性检查(全部要求 >= 0; 策略类只允许 0/1;
 * max_mac_bind 允许 0~LOCAL_MAC_BIND_MAX)。合法返回 0。 */
static int uuser_check_int_args(struct blob_attr** tb, char* err,
                                size_t errsz) {
  int i;

  static const struct {
    int arg;
    const char* name;
  } nonneg[] = {
      {UUSER_ARG_MAX_MAC_BIND, "max_mac_bind"},
      {UUSER_ARG_MAX_ONLINE, "max_online"},
      {UUSER_ARG_IN_SPEED, "in_speed"},
      {UUSER_ARG_OUT_SPEED, "out_speed"},
      {UUSER_ARG_DATA_QUOTA, "data_quota"},
  };

  for (i = 0; i < (int)(sizeof(nonneg) / sizeof(nonneg[0])); ++i) {
    if (tb[nonneg[i].arg] && blobmsg_get_u32(tb[nonneg[i].arg]) > 0x7FFFFFFF) {
      uuser_set_err(err, errsz, "%s 必须在 0~2147483647 之间", nonneg[i].name);
      return -1;
    }
  }
  if (tb[UUSER_ARG_MAX_MAC_BIND]) {
    int v = blobmsg_get_u32(tb[UUSER_ARG_MAX_MAC_BIND]);
    if (v > LOCAL_MAC_BIND_MAX) {
      uuser_set_err(err, errsz, "max_mac_bind 必须在 0~%d 之间", LOCAL_MAC_BIND_MAX);
      return -1;
    }
  }
  if (tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY]) {
    int v = blobmsg_get_u32(tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY]);
    if (v != 0 && v != 1) {
      uuser_set_err(err, errsz, "mac_bind_update_policy 只能为 0 或 1");
      return -1;
    }
  }
  if (tb[UUSER_ARG_ONLINE_CONFLICT_POLICY]) {
    int v = blobmsg_get_u32(tb[UUSER_ARG_ONLINE_CONFLICT_POLICY]);
    if (v != 0 && v != 1) {
      uuser_set_err(err, errsz, "online_conflict_policy 只能为 0 或 1");
      return -1;
    }
  }
  return 0;
}

/* ------------------------------ list 方法 ------------------------------ */

static int ubus_user_list(struct ubus_context* ctx, struct ubus_object* obj,
                          struct ubus_request_data* req, const char* method,
                          struct blob_attr* msg) {
  struct blob_attr* tb[__UUSER_ARG_MAX] = {0};
  struct blob_buf buf = {0};
  /* 复用 list_users 的分页钳制: page_size <= UBUS_LIST_MAX_PAGE_SIZE */
  char names[UBUS_LIST_MAX_PAGE_SIZE][LOCAL_USERNAME_MAX + 1];
  struct local_user_t lu;
  char err[256] = {0};
  uint32_t page = UBUS_LIST_DEFAULT_PAGE;
  uint32_t page_size = UBUS_LIST_DEFAULT_PAGE_SIZE;
  int total = 0, cnt, i;

  (void)obj;
  (void)method;

  if (blobmsg_parse(user_policy, __UUSER_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "参数解析失败");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_secret_check(tb) != 0) {
    log_warn("[ubus] user list: secret check failed");
    uuser_reply_code(ctx, req, UUSER_CODE_FORBIDDEN,
                     "secret 缺失或与 api_secret 不匹配");
    return UBUS_STATUS_PERMISSION_DENIED;
  }
  if (tb[UUSER_ARG_PAGE]) {
    int32_t v = blobmsg_get_u32(tb[UUSER_ARG_PAGE]);
    if (v < 1 || v > UUSER_PAGE_MAX) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "page 必须 >= 1 且 <= 1000000");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    page = (uint32_t)v;
  }
  if (tb[UUSER_ARG_PAGE_SIZE]) {
    int32_t v = blobmsg_get_u32(tb[UUSER_ARG_PAGE_SIZE]);
    if (v < 1) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "page_size 必须 >= 1");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    page_size = (uint32_t)v;
    if (page_size > UBUS_LIST_MAX_PAGE_SIZE) {
      page_size = UBUS_LIST_MAX_PAGE_SIZE;
    }
  }

  cnt = local_user_list((int)page, (int)page_size, names,
                        UBUS_LIST_MAX_PAGE_SIZE, &total, err, sizeof(err));
  if (cnt < 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, err);
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UUSER_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  blobmsg_add_u32(&buf, "total", (uint32_t)total);
  blobmsg_add_u32(&buf, "page", page);
  blobmsg_add_u32(&buf, "page_size", page_size);
  blobmsg_add_u32(&buf, "count", (uint32_t)cnt);

  void* arr = blobmsg_open_array(&buf, "users");
  for (i = 0; i < cnt; ++i) {
    char elem_name[16];
    void* u;

    /* 用户文件可能在分页后被删除, 单个读取失败就跳过该条 */
    if (local_user_load(names[i], &lu, err, sizeof(err)) != 0) {
      log_warn("[ubus] user list: load '%s' failed: %s", names[i], err);
      continue;
    }
    snprintf(elem_name, sizeof(elem_name), "%d", i);
    u = blobmsg_open_table(&buf, elem_name);
    uuser_fill_user(&buf, &lu, local_count_online_sessions(names[i], NULL));
    blobmsg_close_table(&buf, u);
  }
  blobmsg_close_array(&buf, arr);

  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------ get 方法 ------------------------------- */

static int ubus_user_get(struct ubus_context* ctx, struct ubus_object* obj,
                         struct ubus_request_data* req, const char* method,
                         struct blob_attr* msg) {
  struct blob_attr* tb[__UUSER_ARG_MAX] = {0};
  struct blob_buf buf = {0};
  struct local_user_t lu;
  struct local_mac_bind_t binds[LOCAL_MAC_BIND_MAX];
  char err[256] = {0};
  const char* username;
  int mcnt = 0, j;

  (void)obj;
  (void)method;

  if (blobmsg_parse(user_policy, __UUSER_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "参数解析失败");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_secret_check(tb) != 0) {
    log_warn("[ubus] user get: secret check failed");
    uuser_reply_code(ctx, req, UUSER_CODE_FORBIDDEN,
                     "secret 缺失或与 api_secret 不匹配");
    return UBUS_STATUS_PERMISSION_DENIED;
  }
  username = tb[UUSER_ARG_USERNAME] ? blobmsg_get_string(tb[UUSER_ARG_USERNAME])
                                    : NULL;
  if (!username || username[0] == '\0') {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "缺少 username 参数");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (local_user_load(username, &lu, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_NOT_FOUND, err);
    return UBUS_STATUS_NOT_FOUND;
  }
  /* 无绑定文件 = 无绑定, local_mac_load 返回 0 且 cnt=0; 读失败按无绑定
   * 继续(主文件存在时不应因绑定文件异常看不到用户) */
  if (local_mac_load(username, binds, &mcnt, err, sizeof(err)) != 0) {
    log_warn("[ubus] user get: mac load failed: %s", err);
    mcnt = 0;
  }

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UUSER_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  void* u = blobmsg_open_table(&buf, "user");
  uuser_fill_user(&buf, &lu, local_count_online_sessions(username, NULL));
  blobmsg_close_table(&buf, u);

  void* marr = blobmsg_open_array(&buf, "macs");
  for (j = 0; j < mcnt; ++j) {
    char elem_name[16];
    void* m;

    snprintf(elem_name, sizeof(elem_name), "%d", j);
    m = blobmsg_open_table(&buf, elem_name);
    blobmsg_add_string(&buf, "mac", binds[j].mac);
    blobmsg_add_string(&buf, "bind_time", binds[j].bind_time);
    blobmsg_close_table(&buf, m);
  }
  blobmsg_close_array(&buf, marr);

  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------ add 方法 ------------------------------- */

static int ubus_user_add(struct ubus_context* ctx, struct ubus_object* obj,
                         struct ubus_request_data* req, const char* method,
                         struct blob_attr* msg) {
  struct blob_attr* tb[__UUSER_ARG_MAX] = {0};
  struct blob_buf buf = {0};
  struct local_user_t nu;
  struct local_user_t probe;
  char err[256] = {0};
  char hash[LOCAL_PW_HASH_MAX] = {0};
  const char* username;
  const char* password;
  const char* expire;
  int count = 0;
  int status;
  int max_users;

  (void)obj;
  (void)method;

  if (blobmsg_parse(user_policy, __UUSER_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "参数解析失败");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_secret_check(tb) != 0) {
    log_warn("[ubus] user add: secret check failed");
    uuser_reply_code(ctx, req, UUSER_CODE_FORBIDDEN,
                     "secret 缺失或与 api_secret 不匹配");
    return UBUS_STATUS_PERMISSION_DENIED;
  }
  username = tb[UUSER_ARG_USERNAME] ? blobmsg_get_string(tb[UUSER_ARG_USERNAME])
                                    : NULL;
  password = tb[UUSER_ARG_PASSWORD] ? blobmsg_get_string(tb[UUSER_ARG_PASSWORD])
                                    : NULL;
  if (!username || username[0] == '\0') {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "缺少 username 参数");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (!password || password[0] == '\0') {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "缺少 password 参数");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (!local_username_valid(username)) {
    uuser_reply_code(
        ctx, req, UUSER_CODE_INVALID,
        "username 非法: 1~32 字符, 仅限 [A-Za-z0-9_.@-], 不得以 _mac 结尾");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (strlen(password) > UUSER_PW_MAX) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                     "password 过长(明文不超过 64 字符)");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (tb[UUSER_ARG_STATUS]) {
    status = uuser_parse_status(blobmsg_get_string(tb[UUSER_ARG_STATUS]));
    if (status < 0) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "status 只能是 active/disabled(或 1/0)");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
  } else {
    status = LOCAL_USER_STATUS_ACTIVE;
  }
  expire = tb[UUSER_ARG_EXPIRE_TIME]
               ? blobmsg_get_string(tb[UUSER_ARG_EXPIRE_TIME])
               : "";
  if (!uuser_expire_valid(expire)) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                     "expire_time 必须为空(永不过期)或 'YYYY-MM-DD HH:MM:SS'");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_check_int_args(tb, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, err);
    return UBUS_STATUS_INVALID_ARGUMENT;
  }

  /* 查重与上限本地先判, 给出精确业务码; local_user_add 内部还会兜底复查 */
  if (local_user_load(username, &probe, err, sizeof(err)) == 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_CONFLICT, "用户已存在");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (s_inst && s_inst->config) {
    max_users = (s_inst->config->max_users > 0) ? s_inst->config->max_users
                                                : 256;
    local_user_count(&count);
    if (count >= max_users) {
      char msgbuf[128];
      snprintf(msgbuf, sizeof(msgbuf), "用户数已达上限 (max_users=%d)",
               max_users);
      uuser_reply_code(ctx, req, UUSER_CODE_CONFLICT, msgbuf);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
  }

  if (local_hash_password(password, hash, sizeof(hash)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, "密码散列失败");
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  memset(&nu, 0, sizeof(nu));
  snprintf(nu.username, sizeof(nu.username), "%s", username);
  snprintf(nu.password_hash, sizeof(nu.password_hash), "%s", hash);
  nu.status = status;
  nu.mac_auth = tb[UUSER_ARG_MAC_AUTH] ? (blobmsg_get_u8(tb[UUSER_ARG_MAC_AUTH]) ? 1 : 0) : 0;
  nu.max_mac_bind = tb[UUSER_ARG_MAX_MAC_BIND]
                        ? (int)blobmsg_get_u32(tb[UUSER_ARG_MAX_MAC_BIND])
                        : 4; /* 需求默认值 */
  nu.mac_bind_update_policy =
      tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY]
          ? (int)blobmsg_get_u32(tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY])
          : 0;
  nu.max_online = tb[UUSER_ARG_MAX_ONLINE]
                      ? (int)blobmsg_get_u32(tb[UUSER_ARG_MAX_ONLINE])
                      : 1; /* 需求默认值 */
  nu.online_conflict_policy =
      tb[UUSER_ARG_ONLINE_CONFLICT_POLICY]
          ? (int)blobmsg_get_u32(tb[UUSER_ARG_ONLINE_CONFLICT_POLICY])
          : 0;
  snprintf(nu.expire_time, sizeof(nu.expire_time), "%s", expire);
  nu.in_speed = tb[UUSER_ARG_IN_SPEED]
                    ? blobmsg_get_u32(tb[UUSER_ARG_IN_SPEED])
                    : 0;
  nu.out_speed = tb[UUSER_ARG_OUT_SPEED]
                     ? blobmsg_get_u32(tb[UUSER_ARG_OUT_SPEED])
                     : 0;
  nu.data_quota = tb[UUSER_ARG_DATA_QUOTA]
                      ? blobmsg_get_u32(tb[UUSER_ARG_DATA_QUOTA])
                      : 0;
  /* register_time 由 local_user_add 自动填写 */

  if (local_user_add(&nu, err, sizeof(err)) != 0) {
    /* 重名/超限/写文件失败在兜底复查时区分业务码 */
    if (strstr(err, "exists") || strstr(err, "limit")) {
      uuser_reply_code(ctx, req, UUSER_CODE_CONFLICT, err);
    } else if (strstr(err, "invalid")) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID, err);
    } else {
      uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, err);
    }
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  /* 可选: 创建时直接下发 MAC 绑定(整体替换语义) */
  if (tb[UUSER_ARG_MACS]) {
    if (uuser_replace_macs(username, tb[UUSER_ARG_MACS], err, sizeof(err)) !=
        0) {
      log_error("[ubus] user add: '%s' created but mac save failed: %s",
                username, err);
      uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, err);
      return UBUS_STATUS_UNKNOWN_ERROR;
    }
  }

  log_info("[ubus] user add: created user='%s' status=%s mac_auth=%d",
           username, (status == LOCAL_USER_STATUS_ACTIVE) ? "active"
                                                          : "disabled",
           nu.mac_auth);
  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UUSER_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  blobmsg_add_string(&buf, "username", username);
  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------ del 方法 ------------------------------- */

static int ubus_user_del(struct ubus_context* ctx, struct ubus_object* obj,
                         struct ubus_request_data* req, const char* method,
                         struct blob_attr* msg) {
  struct blob_attr* tb[__UUSER_ARG_MAX] = {0};
  struct blob_buf buf = {0};
  struct local_user_t probe;
  char err[256] = {0};
  const char* username;

  (void)obj;
  (void)method;

  if (blobmsg_parse(user_policy, __UUSER_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "参数解析失败");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_secret_check(tb) != 0) {
    log_warn("[ubus] user del: secret check failed");
    uuser_reply_code(ctx, req, UUSER_CODE_FORBIDDEN,
                     "secret 缺失或与 api_secret 不匹配");
    return UBUS_STATUS_PERMISSION_DENIED;
  }
  username = tb[UUSER_ARG_USERNAME] ? blobmsg_get_string(tb[UUSER_ARG_USERNAME])
                                    : NULL;
  if (!username || username[0] == '\0') {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "缺少 username 参数");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (local_user_load(username, &probe, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_NOT_FOUND, err);
    return UBUS_STATUS_NOT_FOUND;
  }

  /* 先踢在线会话(下线终算会写用户 JSON, 因此必须在删文件之前),
   * 再删主文件与 MAC 绑定文件 */
  local_kick_user_sessions(username);
  if (local_user_del(username, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, err);
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  log_info("[ubus] user del: deleted user='%s' (online sessions kicked)",
           username);
  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UUSER_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  blobmsg_add_string(&buf, "username", username);
  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------ set 方法 ------------------------------- */

static int ubus_user_set(struct ubus_context* ctx, struct ubus_object* obj,
                         struct ubus_request_data* req, const char* method,
                         struct blob_attr* msg) {
  struct blob_attr* tb[__UUSER_ARG_MAX] = {0};
  struct blob_buf buf = {0};
  struct local_user_t lu;
  char err[256] = {0};
  char hash[LOCAL_PW_HASH_MAX] = {0};
  const char* username;
  const char* expire;
  int new_status; /* load 后初始化为当前 status */

  (void)obj;
  (void)method;

  if (blobmsg_parse(user_policy, __UUSER_ARG_MAX, tb, blobmsg_data(msg),
                    blobmsg_len(msg)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "参数解析失败");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (uuser_secret_check(tb) != 0) {
    log_warn("[ubus] user set: secret check failed");
    uuser_reply_code(ctx, req, UUSER_CODE_FORBIDDEN,
                     "secret 缺失或与 api_secret 不匹配");
    return UBUS_STATUS_PERMISSION_DENIED;
  }
  username = tb[UUSER_ARG_USERNAME] ? blobmsg_get_string(tb[UUSER_ARG_USERNAME])
                                    : NULL;
  if (!username || username[0] == '\0') {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, "缺少 username 参数");
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (local_user_load(username, &lu, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_NOT_FOUND, err);
    return UBUS_STATUS_NOT_FOUND;
  }
  new_status = lu.status;

  /* 部分更新: 只处理请求中实际出现的字段 */
  if (tb[UUSER_ARG_PASSWORD]) {
    const char* password = blobmsg_get_string(tb[UUSER_ARG_PASSWORD]);
    if (password[0] == '\0') {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "password 不能为空(如需禁用请改 status)");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    if (strlen(password) > UUSER_PW_MAX) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "password 过长(明文不超过 64 字符)");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    if (local_hash_password(password, hash, sizeof(hash)) != 0) {
      uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, "密码散列失败");
      return UBUS_STATUS_UNKNOWN_ERROR;
    }
    snprintf(lu.password_hash, sizeof(lu.password_hash), "%s", hash);
  }
  if (tb[UUSER_ARG_STATUS]) {
    int v = uuser_parse_status(blobmsg_get_string(tb[UUSER_ARG_STATUS]));
    if (v < 0) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "status 只能是 active/disabled(或 1/0)");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    lu.status = v;
    new_status = v;
  }
  if (tb[UUSER_ARG_MAC_AUTH]) {
    lu.mac_auth = blobmsg_get_u8(tb[UUSER_ARG_MAC_AUTH]) ? 1 : 0;
  }
  if (uuser_check_int_args(tb, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INVALID, err);
    return UBUS_STATUS_INVALID_ARGUMENT;
  }
  if (tb[UUSER_ARG_MAX_MAC_BIND]) {
    lu.max_mac_bind = (int)blobmsg_get_u32(tb[UUSER_ARG_MAX_MAC_BIND]);
  }
  if (tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY]) {
    lu.mac_bind_update_policy =
        (int)blobmsg_get_u32(tb[UUSER_ARG_MAC_BIND_UPDATE_POLICY]);
  }
  if (tb[UUSER_ARG_MAX_ONLINE]) {
    lu.max_online = (int)blobmsg_get_u32(tb[UUSER_ARG_MAX_ONLINE]);
  }
  if (tb[UUSER_ARG_ONLINE_CONFLICT_POLICY]) {
    lu.online_conflict_policy =
        (int)blobmsg_get_u32(tb[UUSER_ARG_ONLINE_CONFLICT_POLICY]);
  }
  if (tb[UUSER_ARG_IN_SPEED]) {
    lu.in_speed = blobmsg_get_u32(tb[UUSER_ARG_IN_SPEED]);
  }
  if (tb[UUSER_ARG_OUT_SPEED]) {
    lu.out_speed = blobmsg_get_u32(tb[UUSER_ARG_OUT_SPEED]);
  }
  if (tb[UUSER_ARG_DATA_QUOTA]) {
    lu.data_quota = blobmsg_get_u32(tb[UUSER_ARG_DATA_QUOTA]);
  }
  if (tb[UUSER_ARG_EXPIRE_TIME]) {
    expire = blobmsg_get_string(tb[UUSER_ARG_EXPIRE_TIME]);
    if (!uuser_expire_valid(expire)) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID,
                       "expire_time 必须为空(永不过期)或 'YYYY-MM-DD HH:MM:SS'");
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
    snprintf(lu.expire_time, sizeof(lu.expire_time), "%s", expire);
  }

  if (local_user_save(&lu, err, sizeof(err)) != 0) {
    uuser_reply_code(ctx, req, UUSER_CODE_INTERNAL, err);
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  /* MAC 绑定整体替换(空数组 = 清空); 手工 API 设置不受 max_mac_bind
   * 策略约束(该策略作用于登录时自动绑定), 但受硬上限 LOCAL_MAC_BIND_MAX */
  if (tb[UUSER_ARG_MACS]) {
    if (uuser_replace_macs(username, tb[UUSER_ARG_MACS], err, sizeof(err)) !=
        0) {
      uuser_reply_code(ctx, req, UUSER_CODE_INVALID, err);
      return UBUS_STATUS_INVALID_ARGUMENT;
    }
  }

  /* 立即生效: 置为 disabled 时踢掉该用户全部在线会话
   * (其它字段(限速/过期等)由 60s 巡检与下次登录自然生效, 不主动踢线) */
  if (new_status == LOCAL_USER_STATUS_DISABLED) {
    local_kick_user_sessions(username);
    log_info("[ubus] user set: '%s' disabled, online sessions kicked",
             username);
  }

  log_info("[ubus] user set: updated user='%s'", username);
  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UUSER_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");
  blobmsg_add_string(&buf, "username", username);
  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------------------------------------------------ */
/* control_status 方法（排错用：查看当前运行配置与控制面状态）               */
/* ------------------------------------------------------------------------ */

static const char* ubus_auth_source_name(int v) {
  switch (v) {
    case AUTH_SOURCE_LOCAL:
      return "local";
    case AUTH_SOURCE_RADIUS:
      return "radius";
    case AUTH_SOURCE_HTTP:
      return "http";
    case AUTH_SOURCE_LDAP:
      return "ldap";
    default:
      return "unknown";
  }
}

static int ubus_control_status(struct ubus_context* ctx,
                               struct ubus_object* obj,
                               struct ubus_request_data* req,
                               const char* method, struct blob_attr* msg) {
  struct blob_buf buf = {0};
  struct inst_t* inst = s_inst;
  struct config_t* cfg;
  struct control_state_t* c;
  time_t now;
  void* t;

  (void)obj;
  (void)method;
  (void)msg;

  if (!inst || !inst->config) {
    blob_buf_init(&buf, 0);
    blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_INTERNAL);
    blobmsg_add_string(&buf, "msg", "webauthd 实例未就绪");
    ubus_send_reply(ctx, req, buf.head);
    blob_buf_free(&buf);
    return UBUS_STATUS_UNKNOWN_ERROR;
  }

  cfg = inst->config;
  c = &inst->control;
  now = time(NULL);

  blob_buf_init(&buf, 0);
  blobmsg_add_u32(&buf, "code", UBUS_DROP_CODE_OK);
  blobmsg_add_string(&buf, "msg", "ok");

  /* 控制通道状态 */
  t = blobmsg_open_table(&buf, "control");
  blobmsg_add_string(&buf, "schema", CONTROL_SCHEMA);
  blobmsg_add_string(&buf, "source", c->source[0] ? c->source : "baseline");
  blobmsg_add_string(&buf, "profile", c->profile[0] ? c->profile : "standalone");
  blobmsg_add_u32(&buf, "managed", c->managed ? 1 : 0);
  blobmsg_add_u64(&buf, "generation", c->last_applied);
  blobmsg_add_u64(&buf, "effective_generation", c->effective_generation);
  blobmsg_add_u32(&buf, "pending_restart", c->pending_restart ? 1 : 0);
  blobmsg_add_u32(&buf, "last_error_code", (uint32_t)c->last_error_code);
  blobmsg_add_string(&buf, "last_error_msg", c->last_error_msg);
  blobmsg_add_u32(&buf, "lease_remaining_sec",
                  c->lease_deadline > now
                      ? (uint32_t)(c->lease_deadline - now)
                      : 0);
  blobmsg_close_table(&buf, t);

  /* 当前生效配置（内存中的 effective 值，已包含控制面 overlay） */
  t = blobmsg_open_table(&buf, "effective");
  blobmsg_add_u32(&buf, "portal_type", (uint32_t)cfg->portal_type);
  blobmsg_add_string(&buf, "portal_url", cfg->portal_url);
  blobmsg_add_string(&buf, "portal_server", cfg->portal_server);
  blobmsg_add_u32(&buf, "portal_port", (uint32_t)cfg->portal_port);
  blobmsg_add_string(&buf, "auth_source",
                     ubus_auth_source_name(cfg->auth_source));
  blobmsg_add_u32(&buf, "local_radius_client",
                  cfg->local_radius_client ? 1 : 0);
  blobmsg_add_string(&buf, "primary_auth_server", cfg->primary_auth_server);
  blobmsg_add_u32(&buf, "primary_auth_port",
                  (uint32_t)cfg->primary_auth_port);
  blobmsg_add_string(&buf, "primary_acct_server", cfg->primary_acct_server);
  blobmsg_add_u32(&buf, "primary_acct_port",
                  (uint32_t)cfg->primary_acct_port);
  blobmsg_add_string(&buf, "nas_ip", cfg->nas_ip);
  blobmsg_add_string(&buf, "tenant_org_id", cfg->tenant_org_id);
  blobmsg_add_string(&buf, "radius_source",
                     cfg->local_radius_client == 1 ? "local" : "cloud");
  blobmsg_close_table(&buf, t);

  ubus_send_reply(ctx, req, buf.head);
  blob_buf_free(&buf);
  return UBUS_STATUS_OK;
}

/* ------------------------------------------------------------------------ */
/* ubus object 定义与 libevent 集成                                         */
/* ------------------------------------------------------------------------ */

static struct ubus_method s_methods[] = {
    UBUS_METHOD(UBUS_METHOD_DROP, ubus_drop_user, drop_policy),
    UBUS_METHOD(UBUS_METHOD_LIST, ubus_list_users, list_policy),
    UBUS_METHOD_NOARG(UBUS_METHOD_CONTROL_STATUS, ubus_control_status),
};

static struct ubus_object_type s_obj_type =
    UBUS_OBJECT_TYPE(UBUS_OBJECT_NAME, s_methods);

static struct ubus_object s_obj = {
    .name = UBUS_OBJECT_NAME,
    .type = &s_obj_type,
    .methods = s_methods,
    .n_methods = ARRAY_SIZE(s_methods),
};

/* webauthd.user: 本地用户库管理(见上方 webauthd.user 小节) */
static struct ubus_method s_user_methods[] = {
    UBUS_METHOD(UUSER_METHOD_LIST, ubus_user_list, user_policy),
    UBUS_METHOD(UUSER_METHOD_GET, ubus_user_get, user_policy),
    UBUS_METHOD(UUSER_METHOD_ADD, ubus_user_add, user_policy),
    UBUS_METHOD(UUSER_METHOD_DEL, ubus_user_del, user_policy),
    UBUS_METHOD(UUSER_METHOD_SET, ubus_user_set, user_policy),
};

static struct ubus_object_type s_user_obj_type =
    UBUS_OBJECT_TYPE(UBUS_USER_OBJECT_NAME, s_user_methods);

static struct ubus_object s_user_obj = {
    .name = UBUS_USER_OBJECT_NAME,
    .type = &s_user_obj_type,
    .methods = s_user_methods,
    .n_methods = ARRAY_SIZE(s_user_methods),
};

static void ubus_teardown_and_schedule_retry(void) {
  log_warn("[ubus] connection lost, teardown and retry in %d seconds",
           UBUS_RECONNECT_INTERVAL_SEC);
  if (s_ubus_ev) {
    event_del(s_ubus_ev);
    event_free(s_ubus_ev);
    s_ubus_ev = NULL;
  }
  ubus_free(s_ctx);
  s_ctx = NULL;
  /* ubus_free 已注销 object, 重连后需要重新 add */
  if (s_retry_ev && s_inst) {
    struct timeval tv = {UBUS_RECONNECT_INTERVAL_SEC, 0};
    event_add(s_retry_ev, &tv);
  }
}

/*
 * 不依赖 ubus_handle_event() 的返回值探测连接活性:
 * 该函数在部分 libubus 版本(如 OpenWrt 25.12)返回 void。
 * ubusd 已关闭/重置时, 对其 unix stream socket 做 1 字节 MSG_PEEK:
 *   r == 0                 -> 对端有序关闭
 *   r < 0 且非 EAGAIN/EINTR -> 连接出错(如 ECONNRESET)
 *   其余(EAGAIN / r > 0)    -> 连接存活
 * 用 MSG_DONTWAIT 保证绝不阻塞主事件循环。
 */
static int ubus_connection_alive(void) {
  char ch;
  ssize_t r;

  if (!s_ctx || s_ctx->sock.fd < 0) {
    return 0;
  }

  r = recv(s_ctx->sock.fd, &ch, 1, MSG_PEEK | MSG_DONTWAIT);
  if (r == 0) {
    return 0;
  }
  if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
    return 0;
  }
  return 1;
}

static void ubus_fd_cb(evutil_socket_t fd, short events, void* arg) {
  (void)fd;
  (void)events;
  (void)arg;

  if (!s_ctx) {
    return;
  }

  /* 处理收到的 ubus 消息(含方法调用); 该函数在本工具链返回 void,
   * 不能用其返回值判断断线, 改由下面的 socket 活性探测决定是否重连 */
  ubus_handle_event(s_ctx);

  if (!ubus_connection_alive()) {
    ubus_teardown_and_schedule_retry();
  }
}

static int ubus_connect_register(void) {
  const char* sock_path = UBUS_UNIX_SOCKET;
  int ret;

  if (!s_inst || !s_inst->base) {
    log_error("[ubus] register aborted: inst/event base is NULL");
    return -1;
  }

  /* 步骤1: 连接 ubusd。NULL 表示默认 unix socket (/var/run/ubus/ubus.sock),
   * 失败常见于 ubusd 尚未启动; errno 经 ubus 内部日志不一定可见, 这里补充 */
  log_debug("[ubus] step1/3 connecting ubusd at '%s' ...", sock_path);
  s_ctx = ubus_connect(sock_path);
  if (!s_ctx) {
    log_debug("[ubus] step1/3 ubus_connect('%s') failed (ubusd not ready?)",
              sock_path);
    return -1;
  }
  log_debug("[ubus] step1/3 connected to ubusd, fd=%d", s_ctx->sock.fd);

  /* 步骤2: 注册 object。同进程重复注册同名 object 或参数非法会失败 */
  log_debug("[ubus] step2/3 adding object '%s' (%d method%s) ...",
            UBUS_OBJECT_NAME, (int)ARRAY_SIZE(s_methods),
            ARRAY_SIZE(s_methods) > 1 ? "s" : "");
  ret = ubus_add_object(s_ctx, &s_obj);
  if (ret != UBUS_STATUS_OK) {
    log_error("[ubus] step2/3 ubus_add_object('%s') failed, ret=%d",
              UBUS_OBJECT_NAME, ret);
    ubus_free(s_ctx);
    s_ctx = NULL;
    return -1;
  }
  log_debug("[ubus] step2/3 object '%s' registered, methods '%s,%s' available",
            UBUS_OBJECT_NAME, UBUS_METHOD_DROP, UBUS_METHOD_LIST);

  ret = ubus_add_object(s_ctx, &s_user_obj);
  if (ret != UBUS_STATUS_OK) {
    log_error("[ubus] step2/3 ubus_add_object('%s') failed, ret=%d",
              UBUS_USER_OBJECT_NAME, ret);
    ubus_free(s_ctx);
    s_ctx = NULL;
    return -1;
  }
  log_debug(
      "[ubus] step2/3 object '%s' registered, methods '%s,%s,%s,%s,%s' "
      "available",
      UBUS_USER_OBJECT_NAME, UUSER_METHOD_LIST, UUSER_METHOD_GET,
      UUSER_METHOD_ADD, UUSER_METHOD_DEL, UUSER_METHOD_SET);

  /* 步骤3: 把 ubus socket 挂到主进程 libevent(不使用 uloop) */
  log_debug("[ubus] step3/3 attach ubus fd=%d to libevent ...",
            s_ctx->sock.fd);
  s_ubus_ev = event_new(s_inst->base, s_ctx->sock.fd, EV_READ | EV_PERSIST,
                        ubus_fd_cb, NULL);
  if (!s_ubus_ev) {
    log_error("[ubus] step3/3 event_new for ubus socket failed: %s",
              strerror(errno));
    ubus_free(s_ctx);
    s_ctx = NULL;
    return -1;
  }
  if (event_add(s_ubus_ev, NULL) != 0) {
    log_error("[ubus] step3/3 event_add for ubus socket failed: %s",
              strerror(errno));
    event_free(s_ubus_ev);
    s_ubus_ev = NULL;
    ubus_free(s_ctx);
    s_ctx = NULL;
    return -1;
  }

  log_info("[ubus] service ready: object='%s' methods='%s,%s' + "
           "object='%s' methods='%s,%s,%s,%s,%s' fd=%d",
           UBUS_OBJECT_NAME, UBUS_METHOD_DROP, UBUS_METHOD_LIST,
           UBUS_USER_OBJECT_NAME, UUSER_METHOD_LIST, UUSER_METHOD_GET,
           UUSER_METHOD_ADD, UUSER_METHOD_DEL, UUSER_METHOD_SET,
           s_ctx->sock.fd);
  return 0;
}

static void ubus_retry_cb(evutil_socket_t fd, short events, void* arg) {
  (void)fd;
  (void)events;
  (void)arg;

  log_debug("[ubus] retry: trying to register ...");
  if (ubus_connect_register() == 0) {
    log_info("[ubus] reconnected and registered successfully");
    return;
  }

  log_debug("[ubus] retry failed, next attempt in %d seconds",
            UBUS_RECONNECT_INTERVAL_SEC);
  if (s_retry_ev) {
    struct timeval tv = {UBUS_RECONNECT_INTERVAL_SEC, 0};
    event_add(s_retry_ev, &tv);
  }
}

int ubus_service_start(struct inst_t* inst) {
  if (!inst || !inst->base) {
    log_error("[ubus] start aborted: invalid inst/event base, skip");
    return -1;
  }
  s_inst = inst;

  log_info("[ubus] initializing ubus service (conditional build enabled)");

  s_retry_ev = event_new(inst->base, -1, 0, ubus_retry_cb, NULL);
  if (!s_retry_ev) {
    log_error("[ubus] create reconnect timer failed: %s", strerror(errno));
    return -1;
  }

  if (ubus_connect_register() == 0) {
    return 0;
  }

  /* ubusd 尚未就绪: 降级运行, 主业务(portal/RADIUS)不受影响, 后台重连 */
  log_warn("[ubus] ubusd unavailable now, service degraded (portal/RADIUS "
           "unaffected), auto-retry every %ds",
           UBUS_RECONNECT_INTERVAL_SEC);
  {
    struct timeval tv = {UBUS_RECONNECT_INTERVAL_SEC, 0};
    event_add(s_retry_ev, &tv);
  }
  return 0;
}

void ubus_service_stop(void) {
  if (s_retry_ev) {
    event_del(s_retry_ev);
    event_free(s_retry_ev);
    s_retry_ev = NULL;
  }
  if (s_ubus_ev) {
    event_del(s_ubus_ev);
    event_free(s_ubus_ev);
    s_ubus_ev = NULL;
  }
  if (s_ctx) {
    ubus_free(s_ctx);
    s_ctx = NULL;
  }
  log_info("[ubus] service stopped");
}

#endif /* WEBAUTHD_ENABLE_UBUS */
