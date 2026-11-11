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
#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

/*
 * HTTP(S) 认证源(auth_source=http):
 *   - 认证: POST JSON 到 http_auth.auth_url, 全异步(curl multi 挂 libevent
 *     主循环), 不阻塞其他用户的认证/踢线/redirect;
 *   - 记账: POST JSON 到 http_auth.acct_url(空=不记账), fire-and-forget,
 *     超时/失败仅记日志不重试;
 *   - 报文字段与 sign 算法见 开发需求.md「HTTP(s)认证源」一节。
 */

#include "instance.h"
#include "session.h"

/* 记账报文 acct_status 取值(按需求文档定义, 非 RADIUS 的 1/2/3) */
#define HTTP_ACCT_STOP      0
#define HTTP_ACCT_START     1
#define HTTP_ACCT_INTERIM   2

/* HTTPS 证书 PEM 文件(gw-ui 多行文本框录入后落盘; 目录 0700, 私钥 0600) */
#define HTTP_AUTH_CERT_DIR      "/etc/config/webauthd_http_auth"
#define HTTP_AUTH_CA_FILE       HTTP_AUTH_CERT_DIR "/ca.crt"
#define HTTP_AUTH_CLIENT_CRT    HTTP_AUTH_CERT_DIR "/client.crt"
#define HTTP_AUTH_CLIENT_KEY    HTTP_AUTH_CERT_DIR "/client.key"

/* 初始化 curl multi 并挂接 inst->base; 仅 auth_source=http 时真正启用。
 * 未启用返回 0(空操作); 初始化失败返回 <0(不阻断主流程, 登录时会按
 * "服务器不可达"拒绝)。 */
int http_auth_init(struct inst_t* inst);

/* portal 密码登录入口: 调用前 user->req/user_name/user_password 已填,
 * status=AUTHING, authtype=PORTAL; 异步完成后走 EV_AUTH_ACCEPT/REJECT。
 * 立即失败(未初始化/未配 URL/内存不足)时内部直接走 EV_AUTH_REJECT 回复。 */
int http_auth_portal_login(struct user_session_t* user);

/* MAC 免密入口(对应 mac_radius_auth): 返回 0=已派发异步请求,
 * <0=立即失败(已回退 PORTAL, 调用方应继续弹 portal 页)。 */
int http_mac_auth(struct inst_t* inst, struct user_session_t* user);

/* 发送记账报文(fire-and-forget): acct_status 取 HTTP_ACCT_* 三值。
 * acct_url 未配置时静默返回 0。 */
int http_send_acct(struct user_session_t* user, int acct_status);

/* 取消该用户的在途认证请求(ev_auth_timeout 调用); 无在途请求时为空操作 */
void http_auth_cancel_auth(struct user_session_t* user);

/* 会话释放前回收(free_session 调用): 取消在途认证请求;
 * 记账请求已拷贝全部数据、不引用会话, 无需处理。 */
void http_auth_cancel_user(struct user_session_t* user);

#endif /* HTTP_AUTH_H */
