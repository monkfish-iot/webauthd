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
 * http_auth.c - HTTP(S) 认证源客户端
 *
 * 异步模型(与 RADIUS 的"发请求 + 20s auth_timer 兜底"对齐):
 *   - curl multi 接口通过 CURLMOPT_SOCKETFUNCTION/TIMERFUNCTION 挂接
 *     libevent 主循环, 认证请求全程不阻塞;
 *   - 认证完成回调里按结果推进 EV_AUTH_ACCEPT / EV_AUTH_REJECT,
 *     由既有事件流统一回复 portal / 放行 / 回收;
 *   - 20s auth_timer 兜底超时走 EV_AUTH_TIMEOUT, ev_auth_timeout 中
 *     调 http_auth_cancel_auth() 清理在途 curl 请求;
 *   - 记账报文 fire-and-forget, 应答不推进任何事件, 失败仅记日志。
 *
 * sign 算法(与服务器端约定, 详见 开发需求.md):
 *   除 sign 外全部字段按字段名字典序升序拼 key=value, 字段间以 & 连接,
 *   末尾追加 &key=<shared_secret>, 对整串做 MD5 取小写 hex。
 *   参与签名的值为 JSON 转义前的原始值; org_id 仅在非空时携带(此时
 *   JSON 报文与签名字符串都包含该字段)。
 */
#include "http_auth.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app_events.h"
#include "cJSON.h"
#include "config.h"
#include "http_service.h"
#include "log.h"
#include "timer.h"
#include "utensils.h"

/* 请求类别: 认证(推进事件) / 记账(fire-and-forget) */
#define HTTP_REQ_KIND_AUTH 1
#define HTTP_REQ_KIND_ACCT 0

/* 应答体上限, 超过直接断流按"应答格式错误"处理 */
#define HTTP_RESP_MAX (64 * 1024)

struct http_req_ctx {
    CURL* eh;                       /* easy 句柄 */
    struct curl_slist* headers;     /* Content-Type 头, 完成时释放 */
    struct evbuffer* resp;          /* 应答体 */
    struct user_session_t* user;    /* 仅认证请求非空(不持引用, 靠
                                     * http_auth_cancel_user 在 free_session
                                     * 前摘除, 保证回调不会触到已释放会话) */
    int kind;                       /* HTTP_REQ_KIND_* */
    int acct_status;                /* 记账: HTTP_ACCT_* */
    char label[96];                 /* 日志标识: 'username' ip */
};

/* 每个 curl socket 对应一个持久 event, 挂主循环监听读写 */
struct http_sock_ev {
    curl_socket_t fd;
    struct event* ev;
    struct http_sock_ev* next;
};

static CURLM* g_multi = NULL;
static struct event_base* g_base = NULL;
static struct event* g_timer_ev = NULL;          /* multi 超时定时器 */
static struct http_sock_ev* g_sock_evs = NULL;   /* 在监听的 socket 事件链 */

/* 应答体接收回调(定义在本文件后部, 先声明) */
static size_t http_write_cb(char* ptr, size_t size, size_t nmemb,
                            void* userdata);

/* ------------------------------------------------------------------------ */
/* 小工具                                                                    */
/* ------------------------------------------------------------------------ */

static void md5_hex_lower(const char* data, size_t len, char out[33]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int i;

    EVP_Digest(data, len, digest, &dlen, EVP_md5(), NULL);
    for (i = 0; i < (int)dlen && i < 16; i++) {
        sprintf(out + 2 * i, "%02x", digest[i]);
    }
    out[32] = '\0';
}

/* JSON 字符串转义(引号/反斜杠/控制字符), out 至少为 2*strlen(in)+2 */
static size_t json_escape(const char* in, char* out, size_t outsz) {
    size_t n = 0;
    const unsigned char* p = (const unsigned char*)in;

    while (*p && n + 8 < outsz) {
        switch (*p) {
            case '"':  n += snprintf(out + n, outsz - n, "\\\""); break;
            case '\\': n += snprintf(out + n, outsz - n, "\\\\"); break;
            case '\n': n += snprintf(out + n, outsz - n, "\\n"); break;
            case '\r': n += snprintf(out + n, outsz - n, "\\r"); break;
            case '\t': n += snprintf(out + n, outsz - n, "\\t"); break;
            default:
                if (*p < 0x20) {
                    n += snprintf(out + n, outsz - n, "\\u%04x", *p);
                } else {
                    out[n++] = (char)*p;
                }
        }
        p++;
    }
    out[n] = '\0';
    return n;
}

/* 会话 MAC 格式化为小写冒号串(认证/记账报文的 mac 字段固定此格式) */
static void mac_to_str_lower(const uint8_t mac[6], char* out, size_t outsz) {
    snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
             mac[2], mac[3], mac[4], mac[5]);
}

/* 按 mac_auth_format 格式化 MAC(MAC 免密的 username/password) */
static void mac_format_for_auth(const uint8_t m[6], int style, char* out,
                                size_t outsz) {
    switch (style) {
        case 0:
            snprintf(out, outsz, "%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2],
                     m[3], m[4], m[5]);
            break;
        case 2:
            snprintf(out, outsz, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1],
                     m[2], m[3], m[4], m[5]);
            break;
        case 3:
            snprintf(out, outsz, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2],
                     m[3], m[4], m[5]);
            break;
        case 1:
        default:
            snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1],
                     m[2], m[3], m[4], m[5]);
            break;
    }
}

/* nas_ip 取值: 优先 UCI webauthd.radius.nas_ip, 未配置用设备 IP */
static const char* pick_nas_ip(struct inst_t* inst, char* buf, size_t bufsz) {
    if (inst->config->nas_ip[0] != '\0') {
        return inst->config->nas_ip;
    }
    snprintf(buf, bufsz, "%s", inst->dev_ip);
    return buf;
}

/* ------------------------------------------------------------------------ */
/* curl multi <-> libevent 挂接                                              */
/* ------------------------------------------------------------------------ */

static void http_multi_check_completions(void);

static struct http_sock_ev* sock_ev_find(curl_socket_t fd) {
    struct http_sock_ev* p = g_sock_evs;
    while (p) {
        if (p->fd == fd) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

static void sock_ev_remove(struct http_sock_ev* se) {
    struct http_sock_ev** pp = &g_sock_evs;
    while (*pp) {
        if (*pp == se) {
            *pp = se->next;
            break;
        }
        pp = &(*pp)->next;
    }
    if (se->ev) {
        event_del(se->ev);
        event_free(se->ev);
    }
    free(se);
}

static void http_sock_event_cb(evutil_socket_t fd, short what, void* arg) {
    int action = 0;
    int running = 0;
    (void)arg;

    if (what & EV_READ) {
        action |= CURL_CSELECT_IN;
    }
    if (what & EV_WRITE) {
        action |= CURL_CSELECT_OUT;
    }
    curl_multi_socket_action(g_multi, fd, action, &running);
    http_multi_check_completions();
}

/* libcurl 要求关注/停止关注某 socket 时的回调 */
static int http_socket_cb(CURL* easy, curl_socket_t s, int what, void* userp,
                          void* socketp) {
    struct http_sock_ev* se = sock_ev_find(s);
    short ev_what = EV_PERSIST;
    (void)easy;
    (void)userp;
    (void)socketp;

    if (what == CURL_POLL_REMOVE) {
        if (se) {
            sock_ev_remove(se);
        }
        return 0;
    }

    if (what == CURL_POLL_IN) {
        ev_what |= EV_READ;
    } else if (what == CURL_POLL_OUT) {
        ev_what |= EV_WRITE;
    } else if (what == CURL_POLL_INOUT) {
        ev_what |= EV_READ | EV_WRITE;
    } else {
        return 0; /* CURL_POLL_NONE */
    }

    if (!se) {
        se = (struct http_sock_ev*)calloc(1, sizeof(*se));
        if (!se) {
            return -1;
        }
        se->fd = s;
        se->next = g_sock_evs;
        g_sock_evs = se;
    } else {
        if (se->ev) {
            event_del(se->ev);
            event_free(se->ev);
            se->ev = NULL;
        }
    }
    se->ev = event_new(g_base, s, ev_what, http_sock_event_cb, NULL);
    if (!se->ev || event_add(se->ev, NULL) != 0) {
        log_error("HTTP auth: watch socket %d failed", (int)s);
        sock_ev_remove(se);
        return -1;
    }
    return 0;
}

static void http_timer_event_cb(evutil_socket_t fd, short what, void* arg) {
    int running = 0;
    (void)fd;
    (void)what;
    (void)arg;

    curl_multi_socket_action(g_multi, CURL_SOCKET_TIMEOUT, 0, &running);
    http_multi_check_completions();
}

/* libcurl 超时回调: 要求在 timeout_ms 后触发一次 socket_action(TIMEOUT) */
static int http_multi_timer_cb(CURLM* multi, long timeout_ms, void* userp) {
    struct timeval tv;
    (void)multi;
    (void)userp;

    if (!g_timer_ev) {
        return 0;
    }
    evtimer_del(g_timer_ev);
    if (timeout_ms < 0) {
        return 0;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (timeout_ms == 0) {
        tv.tv_usec = 1000; /* 0ms 用 1ms 代替, 避免立即忙转 */
    }
    evtimer_add(g_timer_ev, &tv);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* 请求生命周期                                                              */
/* ------------------------------------------------------------------------ */

static void http_ctx_free(struct http_req_ctx* ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->eh) {
        curl_multi_remove_handle(g_multi, ctx->eh);
        curl_easy_cleanup(ctx->eh);
    }
    if (ctx->headers) {
        curl_slist_free_all(ctx->headers);
    }
    if (ctx->resp) {
        evbuffer_free(ctx->resp);
    }
    free(ctx);
}

/* 认证失败统一出口: 置错误码与透传 msg, 推进 EV_AUTH_REJECT
 * (回复 portal / 复位状态 / 挂等待认证定时器都在事件流里完成) */
static void auth_fail_event(struct user_session_t* user, int code,
                            const char* msg) {
    struct in_addr tmp;
    tmp.s_addr = user->ip;

    user->http_reply_code = code;
    if (msg && msg[0]) {
        snprintf(user->reply_msg, sizeof(user->reply_msg), "%s", msg);
    } else {
        user->reply_msg[0] = '\0';
    }
    log_warn("HTTP auth failed: user='%s' ip=%s code=%d msg='%s'",
             user->user_name, inet_ntoa(tmp), code,
             user->reply_msg[0] ? user->reply_msg : "-");
    process_server_events(EV_AUTH_REJECT, NULL, (void*)user);
}

/* 认证应答 body 参数映射到会话(对应 RADIUS Access-Accept 属性解析) */
static void auth_apply_accept_body(struct user_session_t* user, cJSON* body) {
    cJSON* item;
    uint64_t quota;
    int64_t v;

    if (!body || body->type != cJSON_Object) {
        return;
    }
    item = cJSON_GetObjectItem(body, "session_timeout");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        user->session_timeout = (uint32_t)item->valuedouble;
    }
    item = cJSON_GetObjectItem(body, "idle_timeout");
    if (item && item->type == cJSON_Number && item->valuedouble >= 0) {
        /* 服务器值兜底: 本地 UCI idle_timeout 优先( ev_auth_accept 通用段 ) */
        user->idle_timeout = (long)item->valuedouble;
    }
    item = cJSON_GetObjectItem(body, "data_quota");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        quota = (uint64_t)item->valuedouble * 1048576ULL; /* MB -> 字节 */
        user->quota_giga_bytes = (uint32_t)(quota >> 32);
        user->quota_bytes = (uint32_t)(quota & 0xFFFFFFFFULL);
        user->quota_data = quota;
    }
    /* 速率方向与 RADIUS 一致: up_rate(用户上行) -> out_rate,
     * down_rate(用户下行) -> in_rate, Mbps x125000 转 bytes/s */
    item = cJSON_GetObjectItem(body, "up_rate");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        v = (int64_t)item->valuedouble;
        if (v > 34359) { /* 防 uint32 溢出 */
            v = 34359;
        }
        user->out_rate = (uint32_t)v * 125000u;
        user->out_giga_rate = 0;
    }
    item = cJSON_GetObjectItem(body, "down_rate");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        v = (int64_t)item->valuedouble;
        if (v > 34359) {
            v = 34359;
        }
        user->in_rate = (uint32_t)v * 125000u;
        user->in_giga_rate = 0;
    }
    item = cJSON_GetObjectItem(body, "acct_update_interval");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        user->acct_interval = (uint32_t)item->valuedouble;
    }
    item = cJSON_GetObjectItem(body, "max_online");
    if (item && item->type == cJSON_Number && item->valuedouble > 0) {
        user->max_parallel = (uint32_t)item->valuedouble;
    }
    item = cJSON_GetObjectItem(body, "online_conflict_policy");
    if (item && item->type == cJSON_Number) {
        user->parallel_policy =
            (item->valuedouble == 1) ? DROP_FIRST_POLICY : DENY_AUTH_POLICY;
    }
    item = cJSON_GetObjectItem(body, "user_ip");
    if (item && item->type == cJSON_String && item->valuestring) {
        /* 与 RADIUS 现行行为一致: 仅记日志, 不覆盖用户真实源 IP */
        log_info("HTTP auth server-assigned user_ip=%s (log only)",
                 item->valuestring);
    }
}

/* 认证应答处理: 解析 JSON, 按 error_code 推进事件 */
static void auth_handle_response(struct http_req_ctx* ctx, long http_code) {
    struct user_session_t* user = ctx->user;
    size_t len = evbuffer_get_length(ctx->resp);
    char* text = NULL;
    cJSON* root = NULL;
    cJSON* item;
    int error_code = 0;
    int has_code = 0;
    const char* msg = NULL;

    if (http_code != 200) {
        char m[64];
        snprintf(m, sizeof(m), "HTTP status %ld", http_code);
        auth_fail_event(user, PORTAL_HTTP_AUTH_BAD_REPLY, m);
        return;
    }
    text = (char*)malloc(len + 1);
    if (!text) {
        auth_fail_event(user, PORTAL_HTTP_AUTH_BAD_REPLY, "out of memory");
        return;
    }
    evbuffer_remove(ctx->resp, text, len);
    text[len] = '\0';

    root = cJSON_Parse(text);
    if (root && root->type == cJSON_Object) {
        item = cJSON_GetObjectItem(root, "error_code");
        if (item && item->type == cJSON_Number) {
            error_code = item->valueint;
            has_code = 1;
        }
        item = cJSON_GetObjectItem(root, "msg");
        if (item && item->type == cJSON_String) {
            msg = item->valuestring;
        }
    }
    if (!has_code) {
        log_warn("HTTP auth reply is not valid JSON or missing error_code: "
                 "'%.120s'", text);
        auth_fail_event(user, PORTAL_HTTP_AUTH_BAD_REPLY,
                        "invalid auth reply");
        free(text);
        if (root) {
            cJSON_Delete(root);
        }
        return;
    }

    if (error_code == 0) {
        struct in_addr tmp;
        tmp.s_addr = user->ip;
        user->http_reply_code = 0;
        user->reply_msg[0] = '\0';
        auth_apply_accept_body(user, cJSON_GetObjectItem(root, "body"));
        log_info("HTTP auth accept: user='%s' ip=%s msg='%s' "
                 "session_timeout=%u idle=%ld quota=%llu in=%u out=%u "
                 "acct_interval=%u",
                 user->user_name, inet_ntoa(tmp), msg ? msg : "ok",
                 user->session_timeout, user->idle_timeout,
                 (unsigned long long)user->quota_data, user->in_rate,
                 user->out_rate, user->acct_interval);
        process_server_events(EV_AUTH_ACCEPT, NULL, (void*)user);
    } else {
        /* 认证失败: 服务器返回的 error_code 与 msg 原样透传给 portal 页 */
        auth_fail_event(user, error_code, msg);
    }

    free(text);
    if (root) {
        cJSON_Delete(root);
    }
}

/* 请求完成回调(成功/失败/超时都从这里进) */
static void http_req_done(struct http_req_ctx* ctx, CURLcode result) {
    struct user_session_t* user = ctx->user;
    long http_code = 0;

    curl_easy_getinfo(ctx->eh, CURLINFO_RESPONSE_CODE, &http_code);
    /* 先摘除句柄, 保证后续事件处理(reject 会复位会话)不再触碰 curl */
    curl_multi_remove_handle(g_multi, ctx->eh);
    curl_easy_cleanup(ctx->eh);
    ctx->eh = NULL;

    if (ctx->kind == HTTP_REQ_KIND_ACCT) {
        if (result != CURLE_OK) {
            log_warn("HTTP acct(status=%d) failed: %s, %s", ctx->acct_status,
                     curl_easy_strerror(result), ctx->label);
        } else if (http_code != 200) {
            log_warn("HTTP acct(status=%d) got HTTP %ld, %s",
                     ctx->acct_status, http_code, ctx->label);
        } else {
            log_info("HTTP acct(status=%d) delivered, %s", ctx->acct_status,
                     ctx->label);
        }
        http_ctx_free(ctx);
        return;
    }

    /* 认证请求 */
    if (user) {
        if (user->http_req == ctx) {
            user->http_req = NULL;
        }
        /* 会话已被回收(如 20s 兜底超时先触发)或状态已迁移, 丢弃应答 */
        if (!user_is_valid(user) || user->status != USER_STATE_AUTHING) {
            log_warn("HTTP auth reply dropped: session not authing, %s",
                     ctx->label);
            http_ctx_free(ctx);
            return;
        }
        if (result == CURLE_OPERATION_TIMEDOUT) {
            auth_fail_event(user, PORTAL_HTTP_AUTH_TIMEOUT,
                            "HTTP auth request timeout");
        } else if (result == CURLE_WRITE_ERROR) {
            /* 应答体超过 64KB 被接收回调断流, 归为应答格式错误 */
            auth_fail_event(user, PORTAL_HTTP_AUTH_BAD_REPLY,
                            "auth reply too large");
        } else if (result != CURLE_OK) {
            /* 透传 curl 描述进日志; 对 portal 回复统一用码表文案 —— 部分平台
             * 的 libcurl(如 8.19.0) 对拒连返回的 strerror 仅为 "Error",
             * 用户不可读, 且固定文案便于服务器端开发手册对齐 */
            log_warn("HTTP auth curl error: %s, %s", ctx->label,
                     curl_easy_strerror(result));
            auth_fail_event(user, PORTAL_HTTP_AUTH_UNREACHABLE, NULL);
        } else {
            auth_handle_response(ctx, http_code);
        }
    }
    http_ctx_free(ctx);
}

static void http_multi_check_completions(void) {
    CURLMsg* msg;
    int left = 0;

    while ((msg = curl_multi_info_read(g_multi, &left)) != NULL) {
        struct http_req_ctx* ctx = NULL;
        if (msg->msg != CURLMSG_DONE) {
            continue;
        }
        if (curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &ctx) !=
                CURLE_OK ||
            !ctx) {
            continue;
        }
        http_req_done(ctx, msg->data.result);
    }
}

/* 按当前配置设置 TLS 选项 */
static void http_setup_tls(CURL* eh, const char* url) {
    struct config_t* cfg = get_inst()->config;

    if (strncmp(url, "https://", 8) != 0) {
        return;
    }
    if (!cfg->http_tls_verify) {
        /* 仅在显式配置 tls_verify=0 时关闭证书校验(默认开启) */
        log_warn("HTTP auth: tls_verify=0, certificate verification disabled");
        curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 0L);
    } else if (access(HTTP_AUTH_CA_FILE, R_OK) == 0) {
        curl_easy_setopt(eh, CURLOPT_CAINFO, HTTP_AUTH_CA_FILE);
    } else {
        /* 未部署私有 CA 时回落到系统 CA, 仍然校验证书 */
        log_warn("HTTP auth: tls_verify=1 but %s missing, "
                 "fallback to system CA", HTTP_AUTH_CA_FILE);
    }
    /* 双向 TLS: 客户端证书与私钥成对存在才启用 */
    if (access(HTTP_AUTH_CLIENT_CRT, R_OK) == 0 &&
        access(HTTP_AUTH_CLIENT_KEY, R_OK) == 0) {
        curl_easy_setopt(eh, CURLOPT_SSLCERT, HTTP_AUTH_CLIENT_CRT);
        curl_easy_setopt(eh, CURLOPT_SSLKEY, HTTP_AUTH_CLIENT_KEY);
    }
}

/* 派发一个 POST JSON 请求; body 由 curl 拷贝(COPYPOSTFIELDS) */
static struct http_req_ctx* http_dispatch(struct user_session_t* user,
                                          int kind, int acct_status,
                                          const char* url, const char* body,
                                          const char* label) {
    struct config_t* cfg = get_inst()->config;
    struct http_req_ctx* ctx = NULL;
    long timeout = cfg->http_timeout;

    if (!g_multi || !url || url[0] == '\0') {
        return NULL;
    }
    ctx = (struct http_req_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->resp = evbuffer_new();
    ctx->eh = curl_easy_init();
    if (!ctx->resp || !ctx->eh) {
        http_ctx_free(ctx);
        return NULL;
    }
    ctx->kind = kind;
    ctx->acct_status = acct_status;
    ctx->user = user;
    snprintf(ctx->label, sizeof(ctx->label), "%s", label ? label : "");

    if (timeout < 1 || timeout > 60) {
        timeout = 5;
    }
    ctx->headers = curl_slist_append(ctx->headers,
                                     "Content-Type: application/json");
    curl_easy_setopt(ctx->eh, CURLOPT_URL, url);
    curl_easy_setopt(ctx->eh, CURLOPT_POST, 1L);
    curl_easy_setopt(ctx->eh, CURLOPT_COPYPOSTFIELDS, body);
    curl_easy_setopt(ctx->eh, CURLOPT_HTTPHEADER, ctx->headers);
    curl_easy_setopt(ctx->eh, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(ctx->eh, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
    curl_easy_setopt(ctx->eh, CURLOPT_NOSIGNAL, 1L);
    /* 不设写回调时 libcurl 会把应答体输出到 stdout, 必须挂上接收回调;
     * WRITEDATA 必须传 http_req_ctx 本身, 因为回调按该类型解引用 */
    curl_easy_setopt(ctx->eh, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(ctx->eh, CURLOPT_WRITEDATA, ctx);
    curl_easy_setopt(ctx->eh, CURLOPT_PRIVATE, ctx);
    http_setup_tls(ctx->eh, url);

    if (curl_multi_add_handle(g_multi, ctx->eh) != CURLM_OK) {
        log_error("HTTP auth: curl_multi_add_handle failed, %s", ctx->label);
        http_ctx_free(ctx);
        return NULL;
    }
    return ctx;
}

/* ------------------------------------------------------------------------ */
/* 报文构造                                                                  */
/* ------------------------------------------------------------------------ */

/* 认证请求 JSON + sign。返回堆内存, 调用方释放。 */
static char* build_auth_body(struct user_session_t* user, const char* auth_type,
                             const char* raw_password) {
    struct inst_t* inst = user->inst;
    struct config_t* cfg = inst->config;
    char mac_str[18] = {0};
    char ip_str[INET_ADDRSTRLEN] = {0};
    char nas_ip[32] = {0};
    char esc_user[160] = {0};
    char esc_pass[160] = {0};
    char esc_nasid[160] = {0};
    char esc_org[160] = {0};
    char password[80] = {0};
    char sign_src[2048];
    char sign[33] = {0};
    const char* org = cfg->tenant_org_id;
    long ts = (long)time(NULL);
    struct in_addr ina;
    int n;

    ina.s_addr = user->ip;
    inet_ntop(AF_INET, &ina, ip_str, sizeof(ip_str));
    mac_to_str_lower(user->mac, mac_str, sizeof(mac_str));
    pick_nas_ip(inst, nas_ip, sizeof(nas_ip));

    /* 密码编码: plain=明文, md5=小写 md5hex */
    if (strcasecmp(cfg->http_password_type, "md5") == 0) {
        md5_hex_lower(raw_password, strlen(raw_password), password);
    } else {
        snprintf(password, sizeof(password), "%s", raw_password);
    }

    /* sign: 除 sign 外字段按字典序拼接( org_id 仅非空时携带 ),
     * 字段序: auth_type ip mac nas_id nas_ip [org_id] password
     *         password_type timestamp username */
    n = snprintf(sign_src, sizeof(sign_src),
                 "auth_type=%s&ip=%s&mac=%s&nas_id=%s&nas_ip=%s",
                 auth_type, ip_str, mac_str, inst->device_id, nas_ip);
    if (org[0] != '\0') {
        n += snprintf(sign_src + n, sizeof(sign_src) - n, "&org_id=%s", org);
    }
    n += snprintf(sign_src + n, sizeof(sign_src) - n,
                  "&password=%s&password_type=%s&timestamp=%ld&username=%s",
                  password, cfg->http_password_type, ts, user->user_name);
    if (cfg->http_shared_secret[0] != '\0') {
        snprintf(sign_src + n, sizeof(sign_src) - n, "&key=%s",
                 cfg->http_shared_secret);
        md5_hex_lower(sign_src, strlen(sign_src), sign);
    }

    json_escape(user->user_name, esc_user, sizeof(esc_user));
    json_escape(password, esc_pass, sizeof(esc_pass));
    json_escape(inst->device_id, esc_nasid, sizeof(esc_nasid));
    json_escape(org, esc_org, sizeof(esc_org));

    {
        size_t cap = 2048;
        char* body = (char*)malloc(cap);
        int m;
        if (!body) {
            return NULL;
        }
        m = snprintf(body, cap,
                     "{\"username\":\"%s\",\"password\":\"%s\","
                     "\"password_type\":\"%s\",\"auth_type\":\"%s\","
                     "\"mac\":\"%s\",\"ip\":\"%s\",\"nas_ip\":\"%s\","
                     "\"nas_id\":\"%s\"",
                     esc_user, esc_pass, cfg->http_password_type, auth_type,
                     mac_str, ip_str, nas_ip, esc_nasid);
        if (org[0] != '\0') {
            m += snprintf(body + m, cap - m, ",\"org_id\":\"%s\"", esc_org);
        }
        m += snprintf(body + m, cap - m, ",\"timestamp\":%ld", ts);
        if (sign[0] != '\0') {
            m += snprintf(body + m, cap - m, ",\"sign\":\"%s\"", sign);
        }
        snprintf(body + m, cap - m, "}");
        return body;
    }
}

/* 记账请求 JSON + sign。返回堆内存, 调用方释放。 */
static char* build_acct_body(struct user_session_t* user, int acct_status) {
    struct inst_t* inst = user->inst;
    struct config_t* cfg = inst->config;
    char mac_str[18] = {0};
    char ip_str[INET_ADDRSTRLEN] = {0};
    char nas_ip[32] = {0};
    char esc_user[160] = {0};
    char esc_nasid[160] = {0};
    char esc_org[160] = {0};
    char sign_src[2048];
    char sign[33] = {0};
    const char* org = cfg->tenant_org_id;
    long ts = (long)time(NULL);
    long online;
    uint64_t in_bytes = user->inbytes;
    uint64_t out_bytes = user->outbytes;
    uint64_t acct_data;
    struct in_addr ina;
    int n;

    ina.s_addr = user->ip;
    inet_ntop(AF_INET, &ina, ip_str, sizeof(ip_str));
    mac_to_str_lower(user->mac, mac_str, sizeof(mac_str));
    pick_nas_ip(inst, nas_ip, sizeof(nas_ip));
    online = (user->acct_start_time > 0)
                 ? (long)get_now_time() - user->acct_start_time
                 : 0;
    acct_data = (in_bytes + out_bytes) / 1048576ULL;

    /* 字段序: acct_data acct_online_time acct_status in_bytes ip mac
     *         nas_id nas_ip [org_id] out_bytes session_id timestamp username */
    n = snprintf(sign_src, sizeof(sign_src),
                 "acct_data=%llu&acct_online_time=%ld&acct_status=%d&"
                 "in_bytes=%llu&ip=%s&mac=%s&nas_id=%s&nas_ip=%s",
                 (unsigned long long)acct_data, online, acct_status,
                 (unsigned long long)in_bytes, ip_str, mac_str,
                 inst->device_id, nas_ip);
    if (org[0] != '\0') {
        n += snprintf(sign_src + n, sizeof(sign_src) - n, "&org_id=%s", org);
    }
    n += snprintf(sign_src + n, sizeof(sign_src) - n,
                  "&out_bytes=%llu&session_id=%s&timestamp=%ld&username=%s",
                  (unsigned long long)out_bytes, user->acct_session_id, ts,
                  user->user_name);
    if (cfg->http_shared_secret[0] != '\0') {
        snprintf(sign_src + n, sizeof(sign_src) - n, "&key=%s",
                 cfg->http_shared_secret);
        md5_hex_lower(sign_src, strlen(sign_src), sign);
    }

    json_escape(user->user_name, esc_user, sizeof(esc_user));
    json_escape(inst->device_id, esc_nasid, sizeof(esc_nasid));
    json_escape(org, esc_org, sizeof(esc_org));

    {
        size_t cap = 2048;
        char* body = (char*)malloc(cap);
        int m;
        if (!body) {
            return NULL;
        }
        m = snprintf(body, cap,
                     "{\"username\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\","
                     "\"session_id\":\"%s\",\"acct_status\":%d,"
                     "\"acct_data\":%llu,\"acct_online_time\":%ld,"
                     "\"in_bytes\":%llu,\"out_bytes\":%llu,"
                     "\"nas_ip\":\"%s\",\"nas_id\":\"%s\"",
                     esc_user, ip_str, mac_str, user->acct_session_id,
                     acct_status, (unsigned long long)acct_data, online,
                     (unsigned long long)in_bytes,
                     (unsigned long long)out_bytes, nas_ip, esc_nasid);
        if (org[0] != '\0') {
            m += snprintf(body + m, cap - m, ",\"org_id\":\"%s\"", esc_org);
        }
        m += snprintf(body + m, cap - m, ",\"timestamp\":%ld", ts);
        if (sign[0] != '\0') {
            m += snprintf(body + m, cap - m, ",\"sign\":\"%s\"", sign);
        }
        snprintf(body + m, cap - m, "}");
        return body;
    }
}

/* ------------------------------------------------------------------------ */
/* 对外接口                                                                  */
/* ------------------------------------------------------------------------ */

static size_t http_write_cb(char* ptr, size_t size, size_t nmemb,
                            void* userdata) {
    struct http_req_ctx* ctx = (struct http_req_ctx*)userdata;
    size_t total = size * nmemb;

    if (evbuffer_get_length(ctx->resp) + total > HTTP_RESP_MAX) {
        return 0; /* 断流, 按应答格式错误处理 */
    }
    evbuffer_add(ctx->resp, ptr, total);
    return total;
}

int http_auth_init(struct inst_t* inst) {
    if (!inst || !inst->base) {
        return -1;
    }
    if (inst->config->auth_source != AUTH_SOURCE_HTTP) {
        return 0; /* 非 HTTP 认证源, 不启用 */
    }
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        log_error("HTTP auth: curl_global_init failed");
        return -1;
    }
    g_base = inst->base;
    g_multi = curl_multi_init();
    if (!g_multi) {
        log_error("HTTP auth: curl_multi_init failed");
        return -1;
    }
    curl_multi_setopt(g_multi, CURLMOPT_SOCKETFUNCTION, http_socket_cb);
    curl_multi_setopt(g_multi, CURLMOPT_TIMERFUNCTION, http_multi_timer_cb);

    g_timer_ev = evtimer_new(g_base, http_timer_event_cb, NULL);
    if (!g_timer_ev) {
        log_error("HTTP auth: create multi timer event failed");
        curl_multi_cleanup(g_multi);
        g_multi = NULL;
        return -1;
    }

    if (inst->config->http_auth_url[0] == '\0') {
        log_error("HTTP auth: webauthd.http_auth.auth_url is empty, "
                  "all auth requests will be rejected");
    }
    log_info("HTTP auth source enabled: auth_url=%s acct_url=%s "
             "password_type=%s timeout=%ds tls_verify=%d",
             inst->config->http_auth_url,
             inst->config->http_acct_url[0] ? inst->config->http_acct_url
                                            : "(disabled)",
             inst->config->http_password_type, inst->config->http_timeout,
             inst->config->http_tls_verify);
    return 0;
}

/* 统一的认证派发: 构造 body -> dispatch -> 挂 auth_timer */
static int auth_send(struct user_session_t* user, const char* auth_type,
                     const char* password) {
    struct inst_t* inst = user->inst;
    struct config_t* cfg = inst->config;
    struct http_req_ctx* ctx;
    char* body;
    char label[96];
    char ip_str[INET_ADDRSTRLEN] = {0};
    struct in_addr ina;

    if (!g_multi || cfg->http_auth_url[0] == '\0') {
        return -1;
    }
    body = build_auth_body(user, auth_type, password);
    if (!body) {
        return -1;
    }
    ina.s_addr = user->ip;
    inet_ntop(AF_INET, &ina, ip_str, sizeof(ip_str));
    snprintf(label, sizeof(label), "user='%s' ip=%s", user->user_name,
             ip_str);

    ctx = http_dispatch(user, HTTP_REQ_KIND_AUTH, 0, cfg->http_auth_url, body,
                        label);
    if (!ctx) {
        free(body);
        return -1;
    }
    user->http_req = ctx;
    free(body);

    log_info("HTTP auth request dispatched(%s): user='%s' ip=%s url=%s",
             auth_type, user->user_name, ip_str, cfg->http_auth_url);
    return 0;
}

int http_auth_portal_login(struct user_session_t* user) {
    if (!user || !user->inst) {
        return -1;
    }
    user->http_reply_code = PORTAL_HTTP_AUTH_UNREACHABLE;
    user->reply_msg[0] = '\0';

    if (start_auth_timer(user->inst, user) < 0) {
        log_error("HTTP auth: start auth timer failed, user='%s'",
                  user->user_name);
        auth_fail_event(user, PORTAL_START_RAD_ERROR, "start timer failed");
        return -1;
    }
    if (auth_send(user, "portal", user->user_password) < 0) {
        stop_auth_timer(user);
        auth_fail_event(user, PORTAL_HTTP_AUTH_UNREACHABLE,
                        "HTTP auth server not configured");
        return -1;
    }
    return 0;
}

int http_mac_auth(struct inst_t* inst, struct user_session_t* user) {
    char mac_str[32] = {0};
    char ip_str[INET_ADDRSTRLEN] = {0};
    struct in_addr ina;

    if (!inst || !user || !inst->config) {
        return -1;
    }
    if (!g_multi || inst->config->http_auth_url[0] == '\0') {
        log_warn("HTTP MAC auth: server not configured, fallback to portal");
        return -1;
    }

    ina.s_addr = user->ip;
    inet_ntop(AF_INET, &ina, ip_str, sizeof(ip_str));
    mac_format_for_auth(user->mac, inst->config->mac_auth_format, mac_str,
                        sizeof(mac_str));

    memset(user->user_name, 0, sizeof(user->user_name));
    memset(user->user_password, 0, sizeof(user->user_password));
    snprintf(user->user_name, sizeof(user->user_name), "%s", mac_str);
    snprintf(user->user_password, sizeof(user->user_password), "%s", mac_str);

    user->authtype = USER_AUTH_TYPE_MAC;
    user->status = USER_STATE_AUTHING;
    user->http_reply_code = PORTAL_HTTP_AUTH_UNREACHABLE;
    user->reply_msg[0] = '\0';

    log_info("HTTP MAC auth begin: mac=%s ip=%s format=%d", mac_str, ip_str,
             inst->config->mac_auth_format);

    if (start_auth_timer(inst, user) < 0) {
        log_error("HTTP MAC auth: start auth timer failed, mac=%s", mac_str);
        user->status = USER_STATE_INIT;
        user->authtype = USER_AUTH_TYPE_PORTAL;
        return -1;
    }
    if (auth_send(user, "mac", mac_str) < 0) {
        stop_auth_timer(user);
        user->status = USER_STATE_INIT;
        user->authtype = USER_AUTH_TYPE_PORTAL;
        return -1;
    }
    return 0;
}

int http_send_acct(struct user_session_t* user, int acct_status) {
    struct config_t* cfg;
    char* body;
    char label[96];
    char ip_str[INET_ADDRSTRLEN] = {0};
    struct in_addr ina;
    struct http_req_ctx* ctx;

    if (!user || !user->inst) {
        return -1;
    }
    cfg = user->inst->config;
    if (!g_multi || cfg->http_acct_url[0] == '\0') {
        return 0; /* 记账 URL 未配置 = 不记账 */
    }
    body = build_acct_body(user, acct_status);
    if (!body) {
        return -1;
    }
    ina.s_addr = user->ip;
    inet_ntop(AF_INET, &ina, ip_str, sizeof(ip_str));
    snprintf(label, sizeof(label), "user='%s' ip=%s", user->user_name,
             ip_str);

    /* 记账 fire-and-forget: 数据已全部拷入 body, ctx 不引用会话 */
    ctx = http_dispatch(NULL, HTTP_REQ_KIND_ACCT, acct_status,
                        cfg->http_acct_url, body, label);
    if (!ctx) {
        free(body);
        log_error("HTTP acct(status=%d) dispatch failed, %s", acct_status,
                  label);
        return -1;
    }
    free(body);

    log_info("HTTP acct(status=%d) dispatched: %s online=%lds "
             "in=%llu out=%llu session-id='%s'",
             acct_status, label,
             (user->acct_start_time > 0)
                 ? (long)get_now_time() - user->acct_start_time
                 : 0L,
             (unsigned long long)user->inbytes,
             (unsigned long long)user->outbytes, user->acct_session_id);
    return 0;
}

void http_auth_cancel_auth(struct user_session_t* user) {
    struct http_req_ctx* ctx;

    if (!user) {
        return;
    }
    ctx = (struct http_req_ctx*)user->http_req;
    user->http_req = NULL;
    if (ctx) {
        /* 从 multi 摘除后 libcurl 保证不再回调该句柄 */
        ctx->user = NULL;
        http_ctx_free(ctx);
    }
}

void http_auth_cancel_user(struct user_session_t* user) {
    /* 当前只有认证请求引用会话; 记账请求数据自包含无需处理 */
    http_auth_cancel_auth(user);
}
