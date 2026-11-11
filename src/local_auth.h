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
#ifndef LOCAL_AUTH_H
#define LOCAL_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "instance.h"
#include "session.h"

/*
 * local_auth.c - 本地认证源(auth_source=local)
 *
 * 用户存储: /etc/config/webauth_users/ 目录, 一用户一 JSON:
 *   <username>.json       用户主文件(见 struct local_user_t)
 *   <username>_mac.json   MAC 绑定文件
 * 设计动机: 写操作只触碰单个用户文件, 无需全局加载。
 *
 * 认证流程(auth_source=local 时完全旁路 RADIUS, 无认证/记账/CoA):
 *   portal 密码登录 -> local_portal_login()   (portal_server.c 接入)
 *   MAC 免密登录    -> local_mac_auth()       (app_events.c ev_new_user 接入)
 *   accept 路径     -> ev_auth_accept 本地分支(nft 放行 + 会话定时器)
 *   下线路径        -> ev_close_session 本地分支(落盘用量 + 直接清理)
 *
 * 定时器:
 *   巡检(60s)  每个在线 local 会话重读用户 JSON, disabled/过期/配额用尽即踢
 *   兜底(300s) 未下线的会话把增量流量/在线时长落盘(防 flash 磨损, 勿调更频繁)
 */

/* 用户库目录(持久分区) */
#define LOCAL_USERS_DIR             "/etc/config/webauth_users"

/* 用户名: 1~32 字符 [A-Za-z0-9_.@-], 大小写敏感, 文件名即用户名 */
#define LOCAL_USERNAME_MAX          32

/* 密码散列格式:
 * 新格式 pbkdf2$<迭代次数>$<盐hex(32字符)>$<pbkdf2-sha256hex(64字符)>
 * 旧格式 s256$<盐hex>$<sha256hex(盐||密码)> 仅保留校验兼容, 新写入一律用 PBKDF2 */
#define LOCAL_PW_PREFIX             "s256$"
#define LOCAL_PW_PREFIX_PBKDF2      "pbkdf2$"
#define LOCAL_PW_PBKDF2_ITER        100000
#define LOCAL_PW_HASH_MAX           128

/* "YYYY-MM-DD HH:MM:SS"(本地时区) + NUL; expire_time 为空串 = 永不过期 */
#define LOCAL_TIME_STR_LEN          20

/* 单用户 MAC 绑定数的合法上限保护(max_mac_bind 可配 0~该值, 0=禁止绑定) */
#define LOCAL_MAC_BIND_MAX          32

/* 巡检/兜底落盘周期(秒) */
#define LOCAL_INSPECT_INTERVAL      60
#define LOCAL_FLUSH_INTERVAL        300

/* 用户状态(JSON "status") */
#define LOCAL_USER_STATUS_ACTIVE    1
#define LOCAL_USER_STATUS_DISABLED  0

/* 单用户 JSON 字段(与需求文档一一对应) */
struct local_user_t {
    char username[LOCAL_USERNAME_MAX + 1];
    char password_hash[LOCAL_PW_HASH_MAX];  /* 散列, 永不回传明文 */
    int status;                             /* LOCAL_USER_STATUS_* */
    int mac_auth;                           /* 是否允许 MAC 免密 */
    int max_mac_bind;                       /* 最大绑定数 */
    int mac_bind_update_policy;             /* 0=满后拒绝更新, 1=替换最早 */
    int max_online;                         /* 最大在线数, <=0 视为不限 */
    int online_conflict_policy;             /* 0=拒绝新登录, 1=下线最早会话 */
    char register_time[LOCAL_TIME_STR_LEN];
    char last_login_time[LOCAL_TIME_STR_LEN];
    char expire_time[LOCAL_TIME_STR_LEN];   /* ""=永不过期 */
    uint32_t in_speed;                      /* Mbps, 0=不限 */
    uint32_t out_speed;                     /* Mbps, 0=不限 */
    uint32_t data_quota;                    /* MB, 0=不限 */
    uint32_t current_data;                  /* MB, 累计已用流量(持久) */
    uint32_t online_time;                   /* 秒, 累计在线时长(持久) */
    uint32_t login_count;
};

/* MAC 绑定条目(用户名_mac.json 的 mac 数组元素) */
struct local_mac_bind_t {
    char mac[18];                           /* aa:bb:cc:dd:ee:ff 小写冒号 */
    char bind_time[LOCAL_TIME_STR_LEN];
};

/* ------------------------------ 生命周期 ------------------------------ */

/* 启动: 建用户目录(0700), 打印用户数; 失败仅告警不阻塞主业务 */
int local_auth_init(struct inst_t* inst);

/* 挂巡检(60s)与兜底落盘(300s)定时器 */
int local_auth_start_timers(struct inst_t* inst);
void local_auth_stop_timers(void);

/* ------------------------------ 认证入口 ------------------------------ */

/* portal 密码登录(auth_source=local), 同步完成校验/冲突处理/参数映射,
 * 成功走 EV_AUTH_ACCEPT, 失败直接回 HTTP 错误码。 */
void local_portal_login(struct user_session_t* user);

/* MAC 免密登录: MAC 已绑定且用户允许时免密放行(返回 0),
 * 否则回退 PORTAL 认证(返回 -1, authtype 已复位)。 */
int local_mac_auth(struct inst_t* inst, struct user_session_t* user);

/* ------------------------------ 会话持久化 ---------------------------- */

/* 把会话增量流量/在线时长累加到用户 JSON 并保存。
 * final=1 为会话下线终算; final=0 为周期兜底。 */
int local_auth_flush_session(struct user_session_t* user, int final);

/* 遍历所有 local 在线会话执行兜底落盘(定时器回调用) */
void local_auth_flush_all(void);

/* ------------------------- 用户库 CRUD(UBUS 用) -----------------------
 * 所有函数成功返回 0; 失败返回 -1 并把可读原因写入 err(供 UBUS 回显)。
 */

/* 读取单个用户; 不存在返回 -1, err 置 "user not found" */
int local_user_load(const char* username, struct local_user_t* out,
                    char* err, size_t errsz);

/* 保存(新建或覆盖)单个用户; username 不合法/超限返回 -1 */
int local_user_save(const struct local_user_t* u, char* err, size_t errsz);

/* 新增用户: 校验用户名/查重/max_users 上限(register_time 自动填写) */
int local_user_add(const struct local_user_t* u, char* err, size_t errsz);

/* 删除用户: 同时删除主文件与 _mac.json; 建议调用方先踢该用户在线会话 */
int local_user_del(const char* username, char* err, size_t errsz);

/* 用户总数 */
int local_user_count(int* count);

/* 分页列出用户名(按 username 升序), page 从 1 起;
 * 返回本页条数, total 回填总数。max_out 为 usernames 数组容量,
 * 且必须 >= page_size(超出部分不复制) */
int local_user_list(int page, int page_size,
                    char usernames[][LOCAL_USERNAME_MAX + 1], int max_out,
                    int* total, char* err, size_t errsz);

/* 读取/保存 MAC 绑定文件; cnt 为条目数(<= LOCAL_MAC_BIND_MAX) */
int local_mac_load(const char* username, struct local_mac_bind_t* arr,
                   int* cnt, char* err, size_t errsz);
int local_mac_save(const char* username, const struct local_mac_bind_t* arr,
                   int cnt, char* err, size_t errsz);

/* ------------------------------ 工具函数 ------------------------------ */

/* 明文 -> "s256$<盐>$<散列>"; 失败返回 -1 */
int local_hash_password(const char* password, char* out, size_t outsz);

/* 校验明文与存储散列是否匹配 */
int local_verify_password(const char* password, const char* stored);

/* 用户名合法性: 1~32 字符 [A-Za-z0-9_.@-], 拒绝 "." 与 ".." */
int local_username_valid(const char* username);

/* "YYYY-MM-DD HH:MM:SS"(本地时区) -> epoch; 非法返回 0 */
time_t local_time_parse(const char* s);

/* epoch -> "YYYY-MM-DD HH:MM:SS"(本地时区) */
void local_time_format(time_t t, char* out, size_t outsz);

/* 二进制 MAC -> 小写冒号字符串 */
void local_mac_to_str(const uint8_t mac[6], char* out, size_t outsz);

/* 归一化 MAC 字符串(兼容冒号/横线/无分隔, 忽略大小写)到 6 字节; 失败 -1 */
int local_mac_parse(const char* s, uint8_t out[6]);

/* --------------------------- 在线会话辅助 ----------------------------- */

/* 统计某用户名当前 AUTHED 会话数(可排除 self) */
int local_count_online_sessions(const char* username,
                                const struct user_session_t* self);

/* 踢掉某用户名最早的 AUTHED 会话(online_conflict_policy=1 用) */
void local_kick_earliest_session(const char* username);

/* 踢掉某用户名的所有 AUTHED 会话(删除/禁用用户时用) */
void local_kick_user_sessions(const char* username);

#endif /* LOCAL_AUTH_H */
