/*
 * webauthd - Web authentication daemon
 * Copyright (C) 2021-2026  MonkFish <5747844@qq.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#ifndef WEBAUTHD_CONTROL_CLIENT_H
#define WEBAUTHD_CONTROL_CLIENT_H

#include <event.h>
#include <evhttp.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define CONTROL_SCHEMA              "webauthd-control/v1"
#define CONTROL_SOCKET_PATH         "/var/run/xfrpc_loader/webauthd-control.sock"
#define CONTROL_PENDING_DIR         "/var/run/webauthd"
#define CONTROL_PENDING_PATH        "/var/run/webauthd/pending.json"
#define CONTROL_POLL_SEC            5
#define CONTROL_BACKOFF_MAX         30

/* 控制面可以覆盖的字段快照。
 * 未包含的字段继续由本地 UCI 基线管理。 */
struct control_snapshot {
    int portal_type;
    char portal_url[1024];
    char portal_server[16];
    int portal_port;

    int auth_source;
    int local_radius_client;

    char primary_auth_server[24];
    uint16_t primary_auth_port;
    char primary_auth_secret[32];
    char primary_acct_server[24];
    uint16_t primary_acct_port;
    char primary_acct_secret[32];
    char nas_ip[32];
    char tenant_org_id[65];
};

struct control_state_t {
    int initialized;

    struct event *poll_timer;
    struct bufferevent *bev;
    int connecting;
    int awaiting_response;
    int close_after_write;

    char request[512];
    char response[16384];
    size_t response_len;

    int backoff_sec;

    /* 当前生效状态 */
    int have_state;
    uint64_t last_applied;
    uint64_t effective_generation;
    int managed;
    char profile[16];
    char source[16];             /* baseline | control | pending_restart */
    time_t lease_deadline;
    int pending_restart;
    int last_error_code;
    char last_error_msg[128];

    /* 本地基线：启动时从 UCI 加载的值 */
    struct control_snapshot baseline;
};

struct inst_t;

/* 初始化基线快照，必须在 load_all_configs 之后调用。 */
void control_client_init(struct inst_t *inst);

/*
 * 启动前应用 pending.json（冷重启衔接）。
 * 必须在 start_init 之前调用。
 */
void control_client_load_pending(struct inst_t *inst);

/* 启动控制客户端（连接、轮询、租约检查）。 */
void control_client_start(struct inst_t *inst);

/* 停止控制客户端并释放资源。 */
void control_client_stop(struct inst_t *inst);

/* 生成 /v1/control/status 的 JSON 字符串，调用方 free。 */
char *control_client_status_json(struct inst_t *inst);

/* HTTP 状态查询回调。 */
void ws_control_status_v1(struct evhttp_request *req, void *arg);

#endif /* WEBAUTHD_CONTROL_CLIENT_H */
