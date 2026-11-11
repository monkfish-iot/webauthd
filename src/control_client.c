/*
 * webauthd - Web authentication daemon
 * Copyright (C) 2021-2026  MonkFish <5747844@qq.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * webauthd-control/v1 客户端。
 *
 * 职责：
 *   - 从 xfrpc_loader 拉取云端期望状态；
 *   - 以 UCI 基线为底合并 overlay；
 *   - 热字段立即生效，冷字段写 pending 并等待重启；
 *   - 租约过期后回退本地基线；
 *   - 对每次应用结果回 ACK。
 */
#include "control_client.h"
#include "config.h"
#include "instance.h"
#include "log.h"
#include "radius.h"
#include "http_service.h"
#include "cJSON.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <event2/bufferevent.h>

#define CONTROL_RESP_MAX	16000
#define CONTROL_CONNECT_TIMEOUT	5

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

static struct control_state_t *ctl(struct inst_t *inst)
{
    return &inst->control;
}

static const char *jstr(const cJSON *obj, const char *name)
{
    cJSON *item = cJSON_GetObjectItem((cJSON *)obj, name);

    if (!item || item->type != cJSON_String || !item->valuestring)
        return NULL;
    return item->valuestring;
}

static int jint(const cJSON *obj, const char *name, int *out)
{
    cJSON *item = cJSON_GetObjectItem((cJSON *)obj, name);

    if (!item || item->type != cJSON_Number)
        return -1;
    *out = item->valueint;
    return 0;
}

static int jbool(const cJSON *obj, const char *name, int *out)
{
    cJSON *item = cJSON_GetObjectItem((cJSON *)obj, name);

    if (!item)
        return -1;
    if (item->type == cJSON_True)
        *out = 1;
    else if (item->type == cJSON_False)
        *out = 0;
    else
        return -1;
    return 0;
}

static int copy_str(char *dst, size_t dst_size, const char *src,
                    const char *field, int *err, char *errmsg,
                    size_t errmsg_size)
{
    if (!src)
        return 0;
    if (strlen(src) >= dst_size) {
        *err = -1002;
        snprintf(errmsg, errmsg_size, "%s too long", field);
        return -1;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
    return 0;
}

static int valid_url(const char *url)
{
    size_t i;

    if (!url || !url[0])
        return 0;
    if (strncmp(url, "http://", 7) != 0 &&
        strncmp(url, "https://", 8) != 0)
        return 0;
    for (i = 0; url[i]; i++) {
        unsigned char c = (unsigned char)url[i];

        if (!(isalnum(c) || strchr(".:/?[]@!&()*+,=%_~-", c)))
            return 0;
    }
    return 1;
}

static int valid_ipv4(const char *s)
{
    struct in_addr addr;

    return s && s[0] && inet_pton(AF_INET, s, &addr) == 1;
}

/* ------------------------------------------------------------------ */
/* 配置快照                                                            */
/* ------------------------------------------------------------------ */

static void snapshot_from_config(struct inst_t *inst,
                                 struct control_snapshot *s)
{
    struct config_t *cfg = inst->config;

    memset(s, 0, sizeof(*s));
    if (!cfg)
        return;
    s->portal_type = cfg->portal_type;
    strncpy(s->portal_url, cfg->portal_url, sizeof(s->portal_url) - 1);
    strncpy(s->portal_server, cfg->portal_server,
            sizeof(s->portal_server) - 1);
    s->portal_port = cfg->portal_port;

    s->auth_source = cfg->auth_source;
    s->local_radius_client = cfg->local_radius_client;

    strncpy(s->primary_auth_server, cfg->primary_auth_server,
            sizeof(s->primary_auth_server) - 1);
    s->primary_auth_port = cfg->primary_auth_port;
    strncpy(s->primary_auth_secret, cfg->primary_auth_secret,
            sizeof(s->primary_auth_secret) - 1);
    strncpy(s->primary_acct_server, cfg->primary_acct_server,
            sizeof(s->primary_acct_server) - 1);
    s->primary_acct_port = cfg->primary_acct_port;
    strncpy(s->primary_acct_secret, cfg->primary_acct_secret,
            sizeof(s->primary_acct_secret) - 1);
    strncpy(s->nas_ip, cfg->nas_ip, sizeof(s->nas_ip) - 1);
    strncpy(s->tenant_org_id, cfg->tenant_org_id,
            sizeof(s->tenant_org_id) - 1);
}

static void snapshot_to_config(struct inst_t *inst,
                               const struct control_snapshot *s)
{
    struct config_t *cfg = inst->config;

    if (!cfg)
        return;
    cfg->portal_type = s->portal_type;
    snprintf(cfg->portal_url, sizeof(cfg->portal_url), "%s", s->portal_url);
    snprintf(cfg->portal_server, sizeof(cfg->portal_server), "%s",
             s->portal_server);
    cfg->portal_port = s->portal_port;

    cfg->auth_source = s->auth_source;
    cfg->local_radius_client = s->local_radius_client;

    snprintf(cfg->primary_auth_server, sizeof(cfg->primary_auth_server), "%s",
             s->primary_auth_server);
    cfg->primary_auth_port = s->primary_auth_port;
    snprintf(cfg->primary_auth_secret, sizeof(cfg->primary_auth_secret),
             "%s", s->primary_auth_secret);
    snprintf(cfg->primary_acct_server, sizeof(cfg->primary_acct_server), "%s",
             s->primary_acct_server);
    cfg->primary_acct_port = s->primary_acct_port;
    snprintf(cfg->primary_acct_secret, sizeof(cfg->primary_acct_secret),
             "%s", s->primary_acct_secret);
    snprintf(cfg->nas_ip, sizeof(cfg->nas_ip), "%s", s->nas_ip);
    snprintf(cfg->tenant_org_id, sizeof(cfg->tenant_org_id), "%s",
             s->tenant_org_id);
}

static int cold_equal(const struct control_snapshot *a,
                      const struct control_snapshot *b)
{
    return a->portal_type == b->portal_type &&
           a->auth_source == b->auth_source &&
           a->local_radius_client == b->local_radius_client;
}

static int radius_equal(const struct control_snapshot *a,
                        const struct control_snapshot *b)
{
    return strcmp(a->primary_auth_server, b->primary_auth_server) == 0 &&
           a->primary_auth_port == b->primary_auth_port &&
           strcmp(a->primary_auth_secret, b->primary_auth_secret) == 0 &&
           strcmp(a->primary_acct_server, b->primary_acct_server) == 0 &&
           a->primary_acct_port == b->primary_acct_port &&
           strcmp(a->primary_acct_secret, b->primary_acct_secret) == 0 &&
           strcmp(a->nas_ip, b->nas_ip) == 0;
}

static int portal_equal(const struct control_snapshot *a,
                        const struct control_snapshot *b)
{
    return a->portal_type == b->portal_type &&
           strcmp(a->portal_url, b->portal_url) == 0 &&
           strcmp(a->portal_server, b->portal_server) == 0 &&
           a->portal_port == b->portal_port;
}

/* ------------------------------------------------------------------ */
/* nginx Portal 渲染                                                   */
/* ------------------------------------------------------------------ */

static int render_portal_cloud(char *url)
{
    FILE *fp;
    char cache[64] = {0};
    int cache_enable = 0;

    if (get_uci_option("webauthd.portal.cache_enable", cache,
                       sizeof(cache)) > 0)
        cache_enable = atoi(cache);

    fp = fopen("/etc/nginx/conf.d/portal.conf", "w");
    if (!fp) {
        log_error("open portal.conf failed: %s", strerror(errno));
        return -1;
    }

    fprintf(fp, "server{\n");
    fprintf(fp, "    listen 20001;\n");
    fprintf(fp, "    server_name localhost;\n");
    fprintf(fp, "    index login.html;\n\n");
    fprintf(fp, "    location / {\n");
    if (cache_enable) {
        fprintf(fp, "        proxy_cache portal_cache;\n");
        fprintf(fp, "        proxy_cache_valid 200 302 60m;\n");
        fprintf(fp, "        proxy_cache_key \"$scheme$request_method$host$request_uri\";\n");
        fprintf(fp, "        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;\n");
        fprintf(fp, "        proxy_cache_background_update on;\n");
        fprintf(fp, "        proxy_cache_lock on;\n");
    }
    fprintf(fp, "        proxy_pass %s;\n", url);
    fprintf(fp, "        proxy_redirect default;\n");
    fprintf(fp, "        proxy_set_header Host $host;\n");
    fprintf(fp, "        proxy_set_header X-Real-IP $remote_addr;\n");
    fprintf(fp, "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    fprintf(fp, "        proxy_set_header X-Portal-Version 2;\n");
    fprintf(fp, "    }\n\n");
    fprintf(fp, "    location /v1/get_portal_text {\n");
    fprintf(fp, "        proxy_pass http://127.0.0.1:20002/v1/get_portal_text;\n");
    fprintf(fp, "        proxy_redirect default;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    location /v1/login {\n");
    fprintf(fp, "        proxy_pass http://127.0.0.1:20002/v1/http_login;\n");
    fprintf(fp, "        proxy_redirect default;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

static int render_portal_local(void)
{
    FILE *fp = fopen("/etc/nginx/conf.d/portal.conf", "w");

    if (!fp) {
        log_error("open portal.conf failed: %s", strerror(errno));
        return -1;
    }
    fprintf(fp, "server{\n");
    fprintf(fp, "    listen 20001;\n");
    fprintf(fp, "    server_name localhost;\n");
    fprintf(fp, "    root  /usr/local/webauthd/local_portal/html;\n");
    fprintf(fp, "    index login.html;\n\n");
    fprintf(fp, "    location /v1/get_portal_text {\n");
    fprintf(fp, "        proxy_pass http://127.0.0.1:20002/v1/get_portal_text;\n");
    fprintf(fp, "        proxy_redirect default;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    location /v1/login {\n");
    fprintf(fp, "        proxy_pass http://127.0.0.1:20002/v1/http_login;\n");
    fprintf(fp, "        proxy_redirect default;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

static int render_portal(struct inst_t *inst)
{
    struct config_t *cfg = inst->config;
    char url[1024];

    if (!cfg)
        return -1;

    if (cfg->portal_type == 2) {
        unlink("/etc/nginx/conf.d/portal.conf");
        return 0;
    }

    if (cfg->portal_type == 1)
        return render_portal_local();

    /* portal_type == 3: 云端 Portal */
    if (cfg->portal_url[0]) {
        snprintf(url, sizeof(url), "%s", cfg->portal_url);
    } else {
        url[0] = '\0';
        get_uci_option("webauthd.portal.proxy_pass", url, sizeof(url));
    }

    if (!valid_url(url)) {
        log_error("invalid cloud portal url, skip nginx render");
        return -1;
    }
    return render_portal_cloud(url);
}

static void nginx_reload(void)
{
    /* 启动阶段 nginx 可能尚未运行；先 reload，失败再尝试启动。 */
    if (system("nginx -s reload >/dev/null 2>&1") != 0)
        system("nginx >/dev/null 2>&1");
}

/* ------------------------------------------------------------------ */
/* 应用快照                                                            */
/* ------------------------------------------------------------------ */

/*
 * 返回值：
 *   0  已生效
 *   1  存在冷字段差异，需要重启
 *  <0 应用失败
 */
static int apply_snapshot(struct inst_t *inst,
                          const struct control_snapshot *desired,
                          int allow_cold)
{
    struct control_snapshot current;
    struct control_snapshot backup;
    struct config_t *cfg = inst->config;
    int portal_changed;
    int radius_changed;
    int need_init = 0;

    if (!cfg)
        return -1;

    snapshot_from_config(inst, &current);
    backup = current;

    if (!cold_equal(&current, desired) && !allow_cold)
        return 1;

    portal_changed = !portal_equal(&current, desired);
    radius_changed = !radius_equal(&current, desired);

    snapshot_to_config(inst, desired);

    need_init = radius_changed ||
                (cfg->auth_source == AUTH_SOURCE_RADIUS &&
                 cfg->primary_auth_server[0] &&
                 cfg->primary_acct_server[0] &&
                 inst->rad_auth_server == NULL);

    /*
     * allow_cold 只用于启动前应用 pending：
     * 云端模式（local_radius_client=0）由控制面提供参数，start_init
     * 不会初始化 RADIUS，所以这里必须初始化；本地模式交给 start_init，
     * 避免重复初始化。
     */
    if (allow_cold && cfg->local_radius_client == 1)
        need_init = 0;

    if (need_init && cfg->auth_source == AUTH_SOURCE_RADIUS) {
        if (init_radius(inst) != 0) {
            log_error("control: init_radius failed, rollback");
            snapshot_to_config(inst, &backup);
            if (backup.auth_source == AUTH_SOURCE_RADIUS &&
                backup.primary_auth_server[0] &&
                backup.primary_acct_server[0])
                init_radius(inst);
            return -1006;
        }
    }

    if (portal_changed) {
        if (render_portal(inst) != 0) {
            log_error("control: render portal failed, rollback");
            snapshot_to_config(inst, &backup);
            if (backup.auth_source == AUTH_SOURCE_RADIUS &&
                backup.primary_auth_server[0] &&
                backup.primary_acct_server[0])
                init_radius(inst);
            render_portal(inst);
            return -1006;
        }
        nginx_reload();
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* 解析期望状态                                                        */
/* ------------------------------------------------------------------ */

static int map_auth_source(const char *s)
{
    if (!s)
        return -1;
    if (strcmp(s, "local") == 0)
        return AUTH_SOURCE_LOCAL;
    if (strcmp(s, "radius") == 0)
        return AUTH_SOURCE_RADIUS;
    if (strcmp(s, "http") == 0)
        return AUTH_SOURCE_HTTP;
    if (strcmp(s, "ldap") == 0)
        return AUTH_SOURCE_LDAP;
    return -1;
}

static int parse_portal(cJSON *root, struct control_snapshot *s,
                        int *err, char *errmsg, size_t errmsg_size)
{
    cJSON *portal = cJSON_GetObjectItem(root, "portal");
    int v;
    const char *str;

    if (!portal || portal->type != cJSON_Object)
        return 0;

    if (jint(portal, "portal_type", &v) == 0) {
        if (v < 1 || v > 3) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid portal_type");
            return -1;
        }
        s->portal_type = v;
    }
    if (jint(portal, "portal_port", &v) == 0) {
        if (v < 1 || v > 65535) {
            *err = -1001;
            snprintf(errmsg, errmsg_size, "invalid portal_port");
            return -1;
        }
        s->portal_port = v;
    }
    if ((str = jstr(portal, "portal_url")) != NULL) {
        if (copy_str(s->portal_url, sizeof(s->portal_url), str,
                     "portal_url", err, errmsg, errmsg_size) < 0)
            return -1;
        if (!valid_url(s->portal_url)) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid portal_url");
            return -1;
        }
    }
    if ((str = jstr(portal, "portal_server")) != NULL &&
        copy_str(s->portal_server, sizeof(s->portal_server), str,
                 "portal_server", err, errmsg, errmsg_size) < 0)
        return -1;

    return 0;
}

static int parse_auth(cJSON *root, struct control_snapshot *s,
                      int *err, char *errmsg, size_t errmsg_size)
{
    cJSON *auth = cJSON_GetObjectItem(root, "auth");
    cJSON *radius;
    cJSON *item;
    const char *str;
    int v;

    if (!auth || auth->type != cJSON_Object)
        return 0;

    item = cJSON_GetObjectItem(auth, "auth_source");
    if (item) {
        if (item->type == cJSON_String) {
            v = map_auth_source(item->valuestring);
            if (v < 0) {
                *err = -1000;
                snprintf(errmsg, errmsg_size, "invalid auth_source");
                return -1;
            }
            s->auth_source = v;
        } else if (item->type == cJSON_Number) {
            s->auth_source = item->valueint;
        }
    }
    if (jint(auth, "local_radius_client", &v) == 0) {
        if (v != 0 && v != 1) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid local_radius_client");
            return -1;
        }
        s->local_radius_client = v;
    }

    radius = cJSON_GetObjectItem(auth, "radius");
    if (!radius || radius->type != cJSON_Object)
        return 0;

    if ((str = jstr(radius, "auth_server")) != NULL) {
        if (copy_str(s->primary_auth_server,
                     sizeof(s->primary_auth_server), str,
                     "auth_server", err, errmsg, errmsg_size) < 0)
            return -1;
        if (!valid_ipv4(s->primary_auth_server)) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid auth_server");
            return -1;
        }
    }
    if (jint(radius, "auth_port", &v) == 0) {
        if (v < 1 || v > 65535) {
            *err = -1001;
            snprintf(errmsg, errmsg_size, "invalid auth_port");
            return -1;
        }
        s->primary_auth_port = (uint16_t)v;
    }
    if ((str = jstr(radius, "auth_secret")) != NULL &&
        copy_str(s->primary_auth_secret, sizeof(s->primary_auth_secret),
                 str, "auth_secret", err, errmsg, errmsg_size) < 0)
        return -1;
    if ((str = jstr(radius, "acct_server")) != NULL) {
        if (copy_str(s->primary_acct_server,
                     sizeof(s->primary_acct_server), str,
                     "acct_server", err, errmsg, errmsg_size) < 0)
            return -1;
        if (!valid_ipv4(s->primary_acct_server)) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid acct_server");
            return -1;
        }
    }
    if (jint(radius, "acct_port", &v) == 0) {
        if (v < 1 || v > 65535) {
            *err = -1001;
            snprintf(errmsg, errmsg_size, "invalid acct_port");
            return -1;
        }
        s->primary_acct_port = (uint16_t)v;
    }
    if ((str = jstr(radius, "acct_secret")) != NULL &&
        copy_str(s->primary_acct_secret, sizeof(s->primary_acct_secret),
                 str, "acct_secret", err, errmsg, errmsg_size) < 0)
        return -1;
    if ((str = jstr(radius, "nas_ip")) != NULL) {
        if (copy_str(s->nas_ip, sizeof(s->nas_ip), str, "nas_ip",
                     err, errmsg, errmsg_size) < 0)
            return -1;
        if (!valid_ipv4(s->nas_ip)) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "invalid nas_ip");
            return -1;
        }
    }
    if ((str = jstr(radius, "tenant_org_id")) != NULL &&
        copy_str(s->tenant_org_id, sizeof(s->tenant_org_id), str,
                 "tenant_org_id", err, errmsg, errmsg_size) < 0)
        return -1;

    return 0;
}

static int validate_snapshot(const struct control_snapshot *s,
                             int *err, char *errmsg, size_t errmsg_size)
{
    if (s->portal_type < 1 || s->portal_type > 3) {
        *err = -1000;
        snprintf(errmsg, errmsg_size, "invalid portal_type");
        return -1;
    }
    if (s->auth_source < 0 || s->auth_source > AUTH_SOURCE_LDAP) {
        *err = -1000;
        snprintf(errmsg, errmsg_size, "invalid auth_source");
        return -1;
    }
    if (s->local_radius_client != 0 && s->local_radius_client != 1) {
        *err = -1000;
        snprintf(errmsg, errmsg_size, "invalid local_radius_client");
        return -1;
    }
    if (s->portal_url[0] && !valid_url(s->portal_url)) {
        *err = -1000;
        snprintf(errmsg, errmsg_size, "invalid portal_url");
        return -1;
    }
    if (s->portal_type == 3 && !s->portal_url[0]) {
        *err = -1000;
        snprintf(errmsg, errmsg_size, "cloud portal without url");
        return -1;
    }
    if (s->auth_source == AUTH_SOURCE_RADIUS &&
        s->local_radius_client == 0) {
        /*
         * 控制面可能只下发 Portal 而不带 RADIUS overlay（云端还没下发
         * 参数），此时 desired 继承 UCI 基线，基线可能本来就没有 RADIUS
         * 配置。只有出现部分 RADIUS 字段时才视为"下发了不完整的 RADIUS"
         * 并拒绝，完全为空则放行。
         */
        int has_radius = s->primary_auth_server[0] ||
                         s->primary_acct_server[0] ||
                         s->primary_auth_secret[0] ||
                         s->primary_acct_secret[0] ||
                         s->nas_ip[0] ||
                         s->primary_auth_port != 0 ||
                         s->primary_acct_port != 0;

        if (has_radius &&
            (!s->primary_auth_server[0] || !s->primary_acct_server[0] ||
             !s->primary_auth_secret[0] || !s->primary_acct_secret[0] ||
             !s->nas_ip[0] || s->primary_auth_port == 0 ||
             s->primary_acct_port == 0)) {
            *err = -1000;
            snprintf(errmsg, errmsg_size, "incomplete cloud radius");
            return -1;
        }
    }
    return 0;
}

static int parse_state(struct inst_t *inst, cJSON *root,
                       struct control_snapshot *desired,
                       int *managed, uint64_t *generation,
                       int *lease_sec, char *profile, size_t profile_size,
                       int *err, char *errmsg, size_t errmsg_size)
{
    cJSON *item;
    const char *schema;
    const char *p;

    *err = 0;
    errmsg[0] = '\0';

    schema = jstr(root, "schema");
    if (!schema || strcmp(schema, CONTROL_SCHEMA) != 0) {
        *err = -1007;
        snprintf(errmsg, errmsg_size, "unsupported schema");
        return -1;
    }

    item = cJSON_GetObjectItem(root, "generation");
    if (!item || item->type != cJSON_Number) {
        *err = -1003;
        snprintf(errmsg, errmsg_size, "missing generation");
        return -1;
    }
    *generation = (uint64_t)item->valuedouble;

    if (jbool(root, "managed", managed) < 0) {
        *err = -1003;
        snprintf(errmsg, errmsg_size, "missing managed");
        return -1;
    }

    if (jint(root, "lease_sec", lease_sec) < 0) {
        *err = -1003;
        snprintf(errmsg, errmsg_size, "missing lease_sec");
        return -1;
    }

    memset(profile, 0, profile_size);
    p = jstr(root, "profile");
    if (p)
        snprintf(profile, profile_size, "%s", p);

    *desired = ctl(inst)->baseline;
    if (*managed) {
        if (parse_portal(root, desired, err, errmsg, errmsg_size) < 0)
            return -1;
        if (parse_auth(root, desired, err, errmsg, errmsg_size) < 0)
            return -1;
    }

    return validate_snapshot(desired, err, errmsg, errmsg_size);
}

/* ------------------------------------------------------------------ */
/* pending 文件                                                        */
/* ------------------------------------------------------------------ */

static int ensure_pending_dir(void)
{
    if (mkdir(CONTROL_PENDING_DIR, 0700) != 0 && errno != EEXIST) {
        log_error("control: mkdir %s failed: %s", CONTROL_PENDING_DIR,
                  strerror(errno));
        return -1;
    }
    chmod(CONTROL_PENDING_DIR, 0700);
    return 0;
}

static int write_pending(cJSON *state)
{
    char *json;
    char tmp[128];
    int fd;
    size_t len;

    if (ensure_pending_dir() < 0)
        return -1;

    cJSON_AddNumberToObject(state, "saved_at", (double)time(NULL));
    json = cJSON_PrintUnformatted(state);
    if (!json)
        return -1;

    snprintf(tmp, sizeof(tmp), "%s.tmp", CONTROL_PENDING_PATH);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        log_error("control: open %s failed: %s", tmp, strerror(errno));
        free(json);
        return -1;
    }
    len = strlen(json);
    if (write(fd, json, len) != (ssize_t)len) {
        log_error("control: write %s failed: %s", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        free(json);
        return -1;
    }
    close(fd);
    if (rename(tmp, CONTROL_PENDING_PATH) != 0) {
        log_error("control: rename %s failed: %s", CONTROL_PENDING_PATH,
                  strerror(errno));
        unlink(tmp);
        free(json);
        return -1;
    }
    free(json);
    log_info("control: pending state saved");
    return 0;
}

static cJSON *make_fallback_state(struct inst_t *inst, const char *reason)
{
    cJSON *root = cJSON_CreateObject();

    if (!root)
        return NULL;
    cJSON_AddStringToObject(root, "schema", CONTROL_SCHEMA);
    cJSON_AddNumberToObject(root, "generation",
                            (double)ctl(inst)->effective_generation);
    cJSON_AddBoolToObject(root, "managed", 0);
    cJSON_AddNumberToObject(root, "lease_sec", 0);
    cJSON_AddStringToObject(root, "profile", "standalone");
    cJSON_AddStringToObject(root, "reason", reason ? reason : "fallback");
    return root;
}

void control_client_load_pending(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);
    cJSON *root;
    FILE *fp;
    char buf[8192];
    size_t len;
    time_t saved_at = 0;
    int lease_sec = 0;
    int managed = 0;
    uint64_t gen = 0;
    int err = 0;
    char errmsg[128];
    char profile[16];
    struct control_snapshot desired;
    cJSON *item;

    if (!c->initialized)
        return;

    fp = fopen(CONTROL_PENDING_PATH, "r");
    if (!fp)
        return;
    len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';

    root = cJSON_Parse(buf);
    if (!root) {
        log_warn("control: pending JSON invalid, discard");
        unlink(CONTROL_PENDING_PATH);
        return;
    }

    item = cJSON_GetObjectItem(root, "saved_at");
    if (item && item->type == cJSON_Number)
        saved_at = (time_t)item->valuedouble;

    if (parse_state(inst, root, &desired, &managed, &gen, &lease_sec,
                    profile, sizeof(profile), &err, errmsg,
                    sizeof(errmsg)) < 0) {
        log_warn("control: pending rejected (%d %s), discard", err, errmsg);
        cJSON_Delete(root);
        unlink(CONTROL_PENDING_PATH);
        return;
    }

    if (lease_sec > 0 && time(NULL) > saved_at + lease_sec) {
        log_warn("control: pending expired, discard");
        cJSON_Delete(root);
        unlink(CONTROL_PENDING_PATH);
        return;
    }

    if (apply_snapshot(inst, &desired, 1) < 0) {
        log_warn("control: pending apply failed, discard");
        cJSON_Delete(root);
        unlink(CONTROL_PENDING_PATH);
        return;
    }

    c->last_applied = gen;
    c->effective_generation = gen;
    c->managed = managed;
    c->pending_restart = 0;
    snprintf(c->profile, sizeof(c->profile), "%s",
             profile[0] ? profile : (managed ? "cloud" : "standalone"));
    snprintf(c->source, sizeof(c->source), "%s",
             managed ? "control" : "baseline");
    c->have_state = managed;
    c->lease_deadline = (lease_sec > 0) ? saved_at + lease_sec : 0;

    log_info("control: applied pending generation=%llu managed=%d",
             (unsigned long long)gen, managed);
    cJSON_Delete(root);
    unlink(CONTROL_PENDING_PATH);
}

/* ------------------------------------------------------------------ */
/* ACK / 状态查询                                                      */
/* ------------------------------------------------------------------ */

static void maybe_send_ack(struct inst_t *inst, uint64_t generation,
                           const char *status, int err, const char *msg)
{
    struct control_state_t *c = ctl(inst);
    cJSON *root;
    char *json;
    char line[1024];

    if (!c->bev)
        return;

    root = cJSON_CreateObject();
    if (!root)
        return;
    cJSON_AddStringToObject(root, "schema", CONTROL_SCHEMA);
    cJSON_AddStringToObject(root, "op", "ack");
    cJSON_AddNumberToObject(root, "generation", (double)generation);
    cJSON_AddStringToObject(root, "status", status ? status : "applied");
    cJSON_AddNumberToObject(root, "effective_generation",
                            (double)c->effective_generation);
    cJSON_AddBoolToObject(root, "pending_restart", c->pending_restart);
    cJSON_AddNumberToObject(root, "error_code", err);
    cJSON_AddStringToObject(root, "error_msg", msg ? msg : "");

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json)
        return;
    if (strlen(json) + 2 < sizeof(line)) {
        snprintf(line, sizeof(line), "%s\n", json);
        bufferevent_write(c->bev, line, strlen(line));
    }
    free(json);
}

char *control_client_status_json(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);
    cJSON *root = cJSON_CreateObject();
    cJSON *effective;
    char *json;

    if (!root)
        return NULL;
    cJSON_AddStringToObject(root, "schema", CONTROL_SCHEMA);
    cJSON_AddStringToObject(root, "source",
                            c->source[0] ? c->source : "baseline");
    cJSON_AddBoolToObject(root, "managed", c->managed);
    cJSON_AddStringToObject(root, "profile",
                            c->profile[0] ? c->profile : "standalone");
    cJSON_AddNumberToObject(root, "generation", (double)c->last_applied);
    cJSON_AddNumberToObject(root, "effective_generation",
                            (double)c->effective_generation);
    cJSON_AddBoolToObject(root, "pending_restart", c->pending_restart);
    cJSON_AddNumberToObject(root, "last_error_code",
                            c->last_error_code);
    cJSON_AddStringToObject(root, "last_error_msg", c->last_error_msg);
    cJSON_AddNumberToObject(root, "lease_remaining_sec",
                            c->lease_deadline > time(NULL) ?
                            (double)(c->lease_deadline - time(NULL)) : 0);

    effective = cJSON_CreateObject();
    if (effective && inst->config) {
        cJSON_AddNumberToObject(effective, "portal_type",
                                inst->config->portal_type);
        cJSON_AddStringToObject(effective, "portal_url",
                                inst->config->portal_url);
        cJSON_AddStringToObject(effective, "auth_source",
                                inst->config->auth_source == AUTH_SOURCE_RADIUS ?
                                "radius" :
                                inst->config->auth_source == AUTH_SOURCE_HTTP ?
                                "http" :
                                inst->config->auth_source == AUTH_SOURCE_LOCAL ?
                                "local" : "ldap");
        cJSON_AddNumberToObject(effective, "local_radius_client",
                                inst->config->local_radius_client);
        cJSON_AddItemToObject(root, "effective", effective);
    }

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

void ws_control_status_v1(struct evhttp_request *req, void *arg)
{
    struct inst_t *inst = arg;
    char *json = control_client_status_json(inst);

    if (!json) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }
    send_http_reply(req, 0, json);
    free(json);
}

/* ------------------------------------------------------------------ */
/* 状态处理                                                            */
/* ------------------------------------------------------------------ */

static void trigger_self_restart(struct inst_t *inst, const char *reason)
{
    struct control_state_t *c = ctl(inst);
    pid_t pid;

    if (c->pending_restart) {
        log_debug("control: self restart already pending (%s)",
                  reason ? reason : "");
        return;
    }
    c->pending_restart = 1;
    snprintf(c->source, sizeof(c->source), "pending_restart");
    log_warn("control: cold change detected (%s), restarting webauthd",
             reason ? reason : "unknown");

    pid = fork();
    if (pid == 0) {
        setsid();
        execl("/etc/init.d/webauthd", "webauthd", "restart",
              (char *)NULL);
        _exit(127);
    } else if (pid < 0) {
        log_error("control: fork restart failed: %s", strerror(errno));
    }
}

static int handle_state(struct inst_t *inst, cJSON *root)
{
    struct control_state_t *c = ctl(inst);
    struct control_snapshot desired;
    uint64_t gen = 0;
    int managed = 0;
    int lease_sec = 0;
    int err = 0;
    int rc;
    char errmsg[128];
    char profile[16];

    if (parse_state(inst, root, &desired, &managed, &gen, &lease_sec,
                    profile, sizeof(profile), &err, errmsg,
                    sizeof(errmsg)) < 0) {
        c->last_error_code = err;
        snprintf(c->last_error_msg, sizeof(c->last_error_msg), "%s",
                 errmsg);
        log_warn("control: state rejected generation=%llu err=%d msg=%s",
                 (unsigned long long)gen, err, errmsg);
        maybe_send_ack(inst, gen, "rejected", err, errmsg);
        return -1;
    }

    if (gen < c->last_applied) {
        c->last_error_code = -1008;
        snprintf(c->last_error_msg, sizeof(c->last_error_msg),
                 "stale generation");
        log_debug("control: stale generation=%llu last=%llu",
                  (unsigned long long)gen,
                  (unsigned long long)c->last_applied);
        maybe_send_ack(inst, gen, "stale", -1008, "stale generation");
        return -1;
    }

    rc = apply_snapshot(inst, &desired, 0);
    if (rc == 1) {
        cJSON *pending;

        pending = cJSON_Duplicate(root, 1);
        if (pending && write_pending(pending) == 0) {
            c->pending_restart = 1;
            snprintf(c->source, sizeof(c->source), "pending_restart");
            c->last_error_code = 0;
            c->last_error_msg[0] = '\0';
            log_info("control: cold change generation=%llu, restart required",
                     (unsigned long long)gen);
            maybe_send_ack(inst, gen, "restart_required", 0, "");
        } else {
            c->last_error_code = -1010;
            snprintf(c->last_error_msg, sizeof(c->last_error_msg),
                     "write pending failed");
            maybe_send_ack(inst, gen, "rejected", -1010,
                           "write pending failed");
        }
        if (pending)
            cJSON_Delete(pending);
        return rc;
    }
    if (rc < 0) {
        c->last_error_code = rc;
        snprintf(c->last_error_msg, sizeof(c->last_error_msg),
                 "apply failed");
        log_error("control: apply generation=%llu failed rc=%d",
                  (unsigned long long)gen, rc);
        maybe_send_ack(inst, gen, "rejected", rc, "apply failed");
        return rc;
    }

    c->last_applied = gen;
    c->effective_generation = gen;
    c->managed = managed;
    c->pending_restart = 0;
    c->last_error_code = 0;
    c->last_error_msg[0] = '\0';
    snprintf(c->profile, sizeof(c->profile), "%s",
             profile[0] ? profile : (managed ? "cloud" : "standalone"));
    snprintf(c->source, sizeof(c->source), "%s",
             managed ? "control" : "baseline");
    c->have_state = managed;
    c->lease_deadline = (lease_sec > 0) ? time(NULL) + lease_sec : 0;

    log_info("control: applied generation=%llu managed=%d profile=%s",
             (unsigned long long)gen, managed,
             profile[0] ? profile : "-");
    maybe_send_ack(inst, gen, "applied", 0, "");
    return 0;
}

static void revert_to_baseline(struct inst_t *inst, const char *reason)
{
    struct control_state_t *c = ctl(inst);
    int rc;

    if (!c->have_state && c->source[0] &&
        strcmp(c->source, "baseline") == 0)
        return;

    log_warn("control: reverting to baseline (%s)", reason ? reason : "");
    rc = apply_snapshot(inst, &c->baseline, 0);
    if (rc == 1) {
        cJSON *pending = make_fallback_state(inst, reason);

        if (pending) {
            if (write_pending(pending) == 0)
                trigger_self_restart(inst, reason);
            cJSON_Delete(pending);
        }
        return;
    }
    if (rc < 0) {
        log_error("control: baseline rollback failed rc=%d", rc);
        return;
    }

    c->managed = 0;
    c->have_state = 0;
    c->lease_deadline = 0;
    c->pending_restart = 0;
    snprintf(c->source, sizeof(c->source), "baseline");
    snprintf(c->profile, sizeof(c->profile), "standalone");
    c->last_error_code = 0;
    c->last_error_msg[0] = '\0';
}

/* ------------------------------------------------------------------ */
/* 网络事件                                                            */
/* ------------------------------------------------------------------ */

static void schedule_poll(struct inst_t *inst, int seconds);

static void disconnect(struct inst_t *inst, int schedule)
{
    struct control_state_t *c = ctl(inst);

    if (c->bev) {
        bufferevent_free(c->bev);
        c->bev = NULL;
    }
    c->connecting = 0;
    c->awaiting_response = 0;
    c->close_after_write = 0;
    c->response_len = 0;
    if (schedule)
        schedule_poll(inst, c->backoff_sec > 0 ? c->backoff_sec :
                      CONTROL_POLL_SEC);
}

static void send_request(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);
    cJSON *root;
    cJSON *caps;
    char *json;
    char line[768];

    root = cJSON_CreateObject();
    if (!root) {
        disconnect(inst, 1);
        return;
    }
    cJSON_AddStringToObject(root, "schema", CONTROL_SCHEMA);
    cJSON_AddStringToObject(root, "op", "get_state");
    cJSON_AddNumberToObject(root, "last_applied",
                            (double)c->last_applied);

    caps = cJSON_CreateArray();
    if (caps) {
        cJSON_AddItemToArray(caps, cJSON_CreateString("portal"));
        cJSON_AddItemToArray(caps, cJSON_CreateString("auth"));
        cJSON_AddItemToArray(caps, cJSON_CreateString("radius"));
        cJSON_AddItemToArray(caps, cJSON_CreateString("restart"));
        cJSON_AddItemToObject(root, "caps", caps);
    }

    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        disconnect(inst, 1);
        return;
    }
    if (strlen(json) + 2 >= sizeof(line)) {
        free(json);
        disconnect(inst, 1);
        return;
    }
    snprintf(line, sizeof(line), "%s\n", json);
    free(json);

    c->awaiting_response = 1;
    c->close_after_write = 0;
    c->response_len = 0;
    bufferevent_write(c->bev, line, strlen(line));
}

static void on_read(struct bufferevent *bev, void *arg)
{
    struct inst_t *inst = arg;
    struct control_state_t *c = ctl(inst);
    char *nl;
    size_t n;
    int unchanged = 0;

    n = bufferevent_read(bev, c->response + c->response_len,
                         sizeof(c->response) - 1 - c->response_len);
    if (n == 0)
        return;
    c->response_len += n;
    c->response[c->response_len] = '\0';

    if (c->response_len >= sizeof(c->response) - 1) {
        log_warn("control: response too large");
        disconnect(inst, 1);
        return;
    }

    nl = strchr(c->response, '\n');
    if (!nl)
        return;
    *nl = '\0';

    cJSON *root = cJSON_Parse(c->response);
    c->response_len = 0;
    if (!root) {
        log_warn("control: invalid state JSON");
        c->last_error_code = -1003;
        snprintf(c->last_error_msg, sizeof(c->last_error_msg),
                 "invalid JSON");
        maybe_send_ack(inst, c->last_applied, "rejected", -1003,
                       "invalid JSON");
        c->close_after_write = 1;
        return;
    }

    if (jbool(root, "unchanged", &unchanged) == 0 && unchanged) {
        cJSON_Delete(root);
        disconnect(inst, 1);
        return;
    }

    handle_state(inst, root);
    cJSON_Delete(root);

    c->awaiting_response = 0;
    c->close_after_write = 1;

    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
        disconnect(inst, 1);
}

static void on_write(struct bufferevent *bev, void *arg)
{
    struct inst_t *inst = arg;
    struct control_state_t *c = ctl(inst);

    (void)bev;
    if (c->close_after_write &&
        evbuffer_get_length(bufferevent_get_output(c->bev)) == 0)
        disconnect(inst, 1);
}

static void on_event(struct bufferevent *bev, short events, void *arg)
{
    struct inst_t *inst = arg;
    struct control_state_t *c = ctl(inst);

    (void)bev;
    if (events & BEV_EVENT_CONNECTED) {
        c->connecting = 0;
        c->backoff_sec = 0;
        send_request(inst);
        return;
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        if (events & BEV_EVENT_ERROR) {
            c->backoff_sec = c->backoff_sec ? c->backoff_sec * 2 :
                            CONTROL_POLL_SEC;
            if (c->backoff_sec > CONTROL_BACKOFF_MAX)
                c->backoff_sec = CONTROL_BACKOFF_MAX;
            log_warn("control: connect error: %s, retry in %d sec",
                     evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()),
                     c->backoff_sec);
        } else if (events & BEV_EVENT_TIMEOUT) {
            log_debug("control: timeout");
        } else if (events & BEV_EVENT_EOF) {
            log_warn("control: connection closed by peer, retry in %d sec",
                     c->backoff_sec > 0 ? c->backoff_sec : CONTROL_POLL_SEC);
        }
        disconnect(inst, 1);
    }
}

static void on_poll(evutil_socket_t fd, short what, void *arg)
{
    struct inst_t *inst = arg;
    struct control_state_t *c = ctl(inst);
    struct sockaddr_un sun;
    struct stat st;
    struct timeval tv = { CONTROL_CONNECT_TIMEOUT, 0 };

    (void)fd;
    (void)what;

    if (c->have_state && c->managed && c->lease_deadline > 0 &&
        time(NULL) >= c->lease_deadline)
        revert_to_baseline(inst, "lease_expired");

    if (c->bev) {
        disconnect(inst, 0);
    }

    if (lstat(CONTROL_SOCKET_PATH, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        c->backoff_sec = c->backoff_sec ? c->backoff_sec * 2 :
                        CONTROL_POLL_SEC;
        if (c->backoff_sec > CONTROL_BACKOFF_MAX)
            c->backoff_sec = CONTROL_BACKOFF_MAX;
        log_warn("control: socket %s not ready (%s), retry in %d sec",
                 CONTROL_SOCKET_PATH, strerror(errno), c->backoff_sec);
        schedule_poll(inst, c->backoff_sec);
        return;
    }
    if (st.st_uid != 0 || (st.st_mode & 0077) != 0) {
        log_warn("control: socket permission check failed, skip");
        schedule_poll(inst, CONTROL_POLL_SEC);
        return;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", CONTROL_SOCKET_PATH);

    c->bev = bufferevent_socket_new(inst->base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!c->bev) {
        schedule_poll(inst, CONTROL_POLL_SEC);
        return;
    }
    bufferevent_set_timeouts(c->bev, &tv, &tv);
    bufferevent_setcb(c->bev, on_read, on_write, on_event, inst);
    if (bufferevent_socket_connect(c->bev, (struct sockaddr *)&sun,
                                   sizeof(sun)) < 0) {
        log_debug("control: connect schedule failed");
        disconnect(inst, 1);
        return;
    }
    c->connecting = 1;
    c->response_len = 0;
    bufferevent_enable(c->bev, EV_READ | EV_WRITE);
}

static void schedule_poll(struct inst_t *inst, int seconds)
{
    struct control_state_t *c = ctl(inst);
    struct timeval tv;

    if (!c->poll_timer)
        return;
    if (seconds < 1)
        seconds = 1;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    evtimer_add(c->poll_timer, &tv);
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

void control_client_init(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);

    memset(c, 0, sizeof(*c));
    if (!inst->config)
        return;
    snapshot_from_config(inst, &c->baseline);
    c->initialized = 1;
    c->source[0] = '\0';
    snprintf(c->source, sizeof(c->source), "baseline");
    snprintf(c->profile, sizeof(c->profile), "standalone");
}

void control_client_start(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);

    if (!c->initialized)
        return;

    /* 基线本身是云端 RADIUS 时，start_init 不会创建 RADIUS 客户端，
     * 第一次拉取前先按当前配置初始化一次。 */
    if (inst->config && inst->config->auth_source == AUTH_SOURCE_RADIUS &&
        inst->config->local_radius_client == 0 &&
        inst->config->primary_auth_server[0] &&
        inst->config->primary_acct_server[0] &&
        inst->rad_auth_server == NULL)
        init_radius(inst);

    if (c->poll_timer)
        evtimer_del(c->poll_timer);
    else
        c->poll_timer = evtimer_new(inst->base, on_poll, inst);
    if (!c->poll_timer) {
        log_error("control: create poll timer failed");
        return;
    }
    log_info("control: client started, socket=%s", CONTROL_SOCKET_PATH);
    schedule_poll(inst, 0);
}

void control_client_stop(struct inst_t *inst)
{
    struct control_state_t *c = ctl(inst);

    if (c->poll_timer) {
        evtimer_del(c->poll_timer);
        event_free(c->poll_timer);
        c->poll_timer = NULL;
    }
    if (c->bev) {
        bufferevent_free(c->bev);
        c->bev = NULL;
    }
    c->initialized = 0;
}
