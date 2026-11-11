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
#include <stdio.h>
#include <strings.h>
#include <uci.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <unistd.h>

#include "log.h"
#include "uci_config.h"
#include "session.h"
#include "config.h"
#include "control_client.h"
#include "cJSON.h"
#include "http_service.h"
#include "utensils.h"
#include "instance.h"
#include "app_events.h"
#include "radius.h"
#include <event2/buffer.h>

//char webauth_generic_enabled[]="webauthd.generic.enabled";


struct config_tpl_t config_tpl[] = {
    {"webauthd.generic.enabled", CONF_OFFSET(TYPE_INTEGER, struct config_t, enabled), "1"},
    // {"webauthd.generic.mode", CONF_OFFSET(TYPE_INTEGER, struct config_t, mode), "0"},
    /* 认证源: 0=local(默认), 1=radius, 2=http(占位), 3=ldap(占位); 切换后重启生效 */
    {"webauthd.generic.auth_source", CONF_OFFSET(TYPE_INTEGER, struct config_t, auth_source), "0"},
    {"webauthd.generic.max_users", CONF_OFFSET(TYPE_INTEGER, struct config_t, max_users), "256"},
    {"webauthd.generic.api_secret", CONF_OFFSET(TYPE_STRING, struct config_t, api_secret), ""},
    {"webauthd.generic.layer2_ifname", CONF_OFFSET(TYPE_STRING, struct config_t, layer2_ifname), "eth0"},
    {"webauthd.generic.layer3_ifname", CONF_OFFSET(TYPE_STRING, struct config_t, layer3_ifname), "br-lan"},
    {"webauthd.generic.portal_ip", CONF_OFFSET(TYPE_STRING, struct config_t, portal_ip), ""},
    {"webauthd.generic.capture_dns", CONF_OFFSET(TYPE_INTEGER, struct config_t, capture_dns), "1"},
    {"webauthd.generic.auth_type", CONF_OFFSET(TYPE_INTEGER, struct config_t, auth_type), "1"},
    {"webauthd.generic.idle_timeout", CONF_OFFSET(TYPE_INTEGER, struct config_t, idle_timeout), "120"},
    {"webauthd.generic.mac_auth", CONF_OFFSET(TYPE_INTEGER, struct config_t, mac_auth_enabled), "0"},
    {"webauthd.generic.mac_auth_format", CONF_OFFSET(TYPE_INTEGER, struct config_t, mac_auth_format), "1"},
    {"webauthd.generic.layer", CONF_OFFSET(TYPE_INTEGER, struct config_t, layer), "3"},

    {"webauthd.portal.portal_type", CONF_OFFSET(TYPE_INTEGER, struct config_t, portal_type), "1"},
    {"webauthd.portal.http_portal_auth", CONF_OFFSET(TYPE_INTEGER, struct config_t, http_portal_auth), "1"},
    {"webauthd.portal.hw_portal_auth", CONF_OFFSET(TYPE_INTEGER, struct config_t, hw_portal_auth), "0"},

    {"webauthd.portal.login_title", CONF_OFFSET(TYPE_STRING, struct config_t, login_title), "Welcome to Portal"},
    {"webauthd.portal.login_topic", CONF_OFFSET(TYPE_STRING, struct config_t, login_topic), "Welcome"},
    {"webauthd.portal.login_footer", CONF_OFFSET(TYPE_STRING, struct config_t, login_footer), "WebAuth"},
    {"webauthd.portal.success_title", CONF_OFFSET(TYPE_STRING, struct config_t, success_title), "Welcome to use Portal System"},
    {"webauthd.portal.success_topic", CONF_OFFSET(TYPE_STRING, struct config_t, success_topic), "Login Success"},
    {"webauthd.portal.success_footer", CONF_OFFSET(TYPE_STRING, struct config_t, success_footer), "Copyright"},

    {"webauthd.portal.login_bg_color", CONF_OFFSET(TYPE_STRING, struct config_t, login_bg_color), ""},
    {"webauthd.portal.login_btn_color", CONF_OFFSET(TYPE_STRING, struct config_t, login_btn_color), ""},
    {"webauthd.portal.login_bg_image", CONF_OFFSET(TYPE_STRING, struct config_t, login_bg_image), ""},
    {"webauthd.portal.login_logo_image", CONF_OFFSET(TYPE_STRING, struct config_t, login_logo_image), ""},
    {"webauthd.portal.success_bg_color", CONF_OFFSET(TYPE_STRING, struct config_t, success_bg_color), ""},
    {"webauthd.portal.success_bg_image", CONF_OFFSET(TYPE_STRING, struct config_t, success_bg_image), ""},
    {"webauthd.portal.success_banner_image", CONF_OFFSET(TYPE_STRING, struct config_t, success_banner_image), ""},


    {"webauthd.portal.failed_title", CONF_OFFSET(TYPE_STRING, struct config_t, failed_title), "Login failed"},
    {"webauthd.portal.failed_topic", CONF_OFFSET(TYPE_STRING, struct config_t, failed_topic), "Login failed"},

    {"webauthd.portal.portal_url", CONF_OFFSET(TYPE_STRING, struct config_t, portal_url), ""},
    {"webauthd.portal.portal_server", CONF_OFFSET(TYPE_STRING, struct config_t, portal_server), ""},
    {"webauthd.portal.portal_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, portal_port), "9091"},

    {"webauthd.redirect.device_ip", CONF_OFFSET(TYPE_STRING, struct config_t, url_device_ip), "wlanacip"},
    {"webauthd.redirect.device_id", CONF_OFFSET(TYPE_STRING, struct config_t, url_device_id), "devid"},
    {"webauthd.redirect.userip", CONF_OFFSET(TYPE_STRING, struct config_t, url_userip), "wlanuserip"},
    {"webauthd.redirect.usermac", CONF_OFFSET(TYPE_STRING, struct config_t, url_usermac), "wlanusermac"},
    {"webauthd.redirect.firsturl", CONF_OFFSET(TYPE_STRING, struct config_t, url_firsturl), "wlanuserfirsturl"},
    {"webauthd.redirect.ssid_name", CONF_OFFSET(TYPE_STRING, struct config_t, url_ssid_name), "ssid"},
    {"webauthd.redirect.device_mac", CONF_OFFSET(TYPE_STRING, struct config_t, url_device_mac), "devmac"},
    {"webauthd.redirect.mac_style", CONF_OFFSET(TYPE_INTEGER, struct config_t, url_mac_style), "2"},
    {"webauthd.redirect.extra", CONF_OFFSET(TYPE_STRING, struct config_t, url_extra), "aaa=2344&sss=456"},



    {"webauthd.radius.primary_auth_server", CONF_OFFSET(TYPE_STRING, struct config_t, primary_auth_server), ""},
    {"webauthd.radius.primary_auth_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, primary_auth_port), "1812"},
    {"webauthd.radius.primary_auth_secret", CONF_OFFSET(TYPE_STRING, struct config_t, primary_auth_secret), "testing123"},
    {"webauthd.radius.primary_acct_server", CONF_OFFSET(TYPE_STRING, struct config_t, primary_acct_server), ""},
    {"webauthd.radius.primary_acct_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, primary_acct_port), "1813"},
    {"webauthd.radius.primary_acct_secret", CONF_OFFSET(TYPE_STRING, struct config_t, primary_acct_secret), "testing123"},

    // 0=RADIUS 参数从云端获取(默认), 1=使用本地 UCI 配置
    {"webauthd.radius.local_radius_client", CONF_OFFSET(TYPE_INTEGER, struct config_t, local_radius_client), "0"},
    {"webauthd.radius.tenant_org_id", CONF_OFFSET(TYPE_STRING, struct config_t, tenant_org_id), ""},

    {"webauthd.radius.second_auth_server", CONF_OFFSET(TYPE_STRING, struct config_t, second_auth_server), ""},
    {"webauthd.radius.second_auth_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, second_auth_port), "1812"},
    {"webauthd.radius.second_auth_secret", CONF_OFFSET(TYPE_STRING, struct config_t, second_auth_secret), "testing123"},
    {"webauthd.radius.second_acct_server", CONF_OFFSET(TYPE_STRING, struct config_t, second_acct_server), ""},
    {"webauthd.radius.second_acct_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, second_acct_port), "1813"},
    {"webauthd.radius.second_acct_secret", CONF_OFFSET(TYPE_STRING, struct config_t, second_acct_secret), "testing123"},
    {"webauthd.radius.nas_ip", CONF_OFFSET(TYPE_STRING, struct config_t, nas_ip), ""},
    {"webauthd.radius.nas_if", CONF_OFFSET(TYPE_STRING, struct config_t, nas_if), ""},

    {"webauthd.radius.force_acctstart", CONF_OFFSET(TYPE_INTEGER, struct config_t, force_acctstart), "0"},
    {"webauthd.radius.coa_port", CONF_OFFSET(TYPE_INTEGER, struct config_t, coa_port), "3799"},
    {"webauthd.radius.coa_secret", CONF_OFFSET(TYPE_STRING, struct config_t, coa_secret), "testing123"},

    {"webauthd.radius.acct_interval", CONF_OFFSET(TYPE_INTEGER, struct config_t, acct_interval), "300"},
    {"webauthd.radius.every_hour_acct", CONF_OFFSET(TYPE_INTEGER, struct config_t, every_hour_acct), "0"},

    /* HTTP(S) 认证源(auth_source=http), 详见 http_auth.c */
    {"webauthd.http_auth.auth_url", CONF_OFFSET(TYPE_STRING, struct config_t, http_auth_url), ""},
    {"webauthd.http_auth.acct_url", CONF_OFFSET(TYPE_STRING, struct config_t, http_acct_url), ""},
    {"webauthd.http_auth.shared_secret", CONF_OFFSET(TYPE_STRING, struct config_t, http_shared_secret), ""},
    {"webauthd.http_auth.password_type", CONF_OFFSET(TYPE_STRING, struct config_t, http_password_type), "plain"},
    {"webauthd.http_auth.timeout", CONF_OFFSET(TYPE_INTEGER, struct config_t, http_timeout), "5"},
    {"webauthd.http_auth.tls_verify", CONF_OFFSET(TYPE_INTEGER, struct config_t, http_tls_verify), "1"},

    // NFT 规则恢复和审计配置
    {"webauthd.nft.recovery_mode", CONF_OFFSET(TYPE_INTEGER, struct config_t, nft_recovery_mode), "1"},  // 默认 scan 模式
    {"webauthd.nft.audit_interval", CONF_OFFSET(TYPE_INTEGER, struct config_t, nft_audit_interval), "60"},  // 默认 60 秒

    {"webauthd.white_list.src_ip", CONF_OFFSET(TYPE_LIST, struct config_t, white_list_src_ip), ""},
    {"webauthd.white_list.src_mac", CONF_OFFSET(TYPE_LIST, struct config_t, white_list_src_mac), ""},
    {"webauthd.white_list.dest_ip", CONF_OFFSET(TYPE_LIST, struct config_t, white_list_dest_ip), ""},
};

static void release_config_object(struct config_t* config) {
    if (!config) {
        return;
    }
    free(config->white_list_src_ip);
    free(config->white_list_src_mac);
    free(config->white_list_dest_ip);
    free(config);
}

int load_all_configs(struct inst_t *inst) {
    size_t len = sizeof (config_tpl) / sizeof (struct config_tpl_t);
    int i = 0;
    int int_value = 0;
    char buf[MAX_BUF_SIZE] = {0};
    ssize_t size = 0;
    char* p = NULL;
    char dev_ip[24] = {0};
    struct config_t* config = (struct config_t*) malloc(sizeof (struct config_t));
    if (!config) {
        log_error("Allocate config failed");
        return -1;
    }
    memset(config, 0, sizeof (struct config_t));
    config->white_list_dest_ip = NULL;
    config->white_list_src_ip = NULL;
    config->white_list_src_mac = NULL;

    // printf("++++++config=%p\n",config);
    for (i = 0; i < len; i++) {
        memset(buf, 0, MAX_BUF_SIZE);
        //  printf("[%d]%s(%d) = \n", i, config_tpl[i].key, strlen(config_tpl[i].key));
        size = get_uci_option(config_tpl[i].key, buf, sizeof(buf));

        if (size < 0) {
            log_error("Read UCI option '%s' failed", config_tpl[i].key);
            release_config_object(config);
            return -1;
        }


        if (size > 0) {
            if (config_tpl[i].value_type == TYPE_INTEGER) {
                int_value = atoi(buf);
                memcpy((void*) config + config_tpl[i].offset, (uint8_t*) (&int_value), sizeof (int));
                //printf("%d+++++++++++++++%0x\n",i,config + config_tpl[i].offset);
            }

            if (config_tpl[i].value_type == TYPE_STRING) {
                /* size 含结尾 NUL; 按字段实际容量截断, 避免长 UCI 值
                 * (最大 MAX_BUF_SIZE) 写入 16~65 字节的小容量字段造成堆越界写,
                 * 并强制 NUL 终止。 */
                size_t cap = config_tpl[i].field_size;
                size_t copy_len = (size_t)size;
                if (cap < 2) {
                    continue;                     /* 无容量字段, 防御性跳过 */
                }
                if (copy_len >= cap) {
                    copy_len = cap - 1;           /* 截断, 预留 NUL */
                }
                memcpy((void*) config + config_tpl[i].offset, buf, copy_len);
                ((char*) config + config_tpl[i].offset)[copy_len] = '\0';
                // printf("%d+++++++++++++++%0x\n",i,config + config_tpl[i].offset);
            }

            if (config_tpl[i].value_type == TYPE_LIST) {
                p = (void*) malloc((size_t)size);
                if (!p) {
                    log_error("Allocate UCI list '%s' failed", config_tpl[i].key);
                    release_config_object(config);
                    return -1;
                }
                memset(p, 0, (size_t)size);
                memcpy(p, buf, (size_t)size);
              //  memcpy((void*) config + config_tpl[i].offset, (uint8_t*) (&p), sizeof (char*));

                char** ptr = (char**)((void*) config + config_tpl[i].offset);
                *ptr = p;
            }


        } else {
            //  log_error("UCI get %s  error.Default value is %s", config_tpl[i].key, config_tpl[i].default_value);
            if (config_tpl[i].value_type == TYPE_INTEGER) {
                int_value = atoi(config_tpl[i].default_value);
                memcpy((void*) config + config_tpl[i].offset, (uint8_t*) (&int_value), sizeof (int));
                // printf("%d+++++++++++++++%0x\n",i,config + config_tpl[i].offset);
            }

            if (config_tpl[i].value_type == TYPE_STRING) {
                size = strlen(config_tpl[i].default_value);
                if (size > 0) {
                    memcpy((char*) config + config_tpl[i].offset, config_tpl[i].default_value, size);
                }
                // printf("%d+++++++++++++++%0x\n",i,config + config_tpl[i].offset);
            }

            if (config_tpl[i].value_type == TYPE_LIST) {
                size = strlen(config_tpl[i].default_value);
                if (size > 0) {
                    memcpy((char*) config + config_tpl[i].offset, config_tpl[i].default_value, size);
                }
                // printf("%d+++++++++++++++%0x\n",i,config + config_tpl[i].offset);
            }
            // printf("%s(default)\n", config_tpl[i].default_value);

        }




    }

    /*
     * auth_source 字符串枚举兼容: 需求文档示例为
     *   option auth_source 'radius'
     * 而模板按整数解析(atoi("radius")=0 会被误读为 local)。
     * 这里对 UCI 原始值再做一次字符串映射, 纯数字配置不受影响;
     * 未知取值保持 atoi 结果(数字或 0=local)。
     */
    if (get_uci_option("webauthd.generic.auth_source", buf, sizeof(buf)) > 0) {
      int src = config->auth_source;
      if (strcasecmp(buf, "local") == 0) {
        src = AUTH_SOURCE_LOCAL;
      } else if (strcasecmp(buf, "radius") == 0) {
        src = AUTH_SOURCE_RADIUS;
      } else if (strcasecmp(buf, "http") == 0 ||
                 strcasecmp(buf, "https") == 0) {
        src = AUTH_SOURCE_HTTP;
      } else if (strcasecmp(buf, "ldap") == 0) {
        src = AUTH_SOURCE_LDAP;
      }
      config->auth_source = src;
      log_info("auth_source = %d (uci raw '%s')", config->auth_source, buf);
    }

    inst->config = config;


    // dev_mac 优先在 init_inst() 中通过 skey get-mac 获取；
    // 仅当 skey 不可用/输出非法（保持全 0）时，回退到 layer3 网卡 ioctl
    int mac_valid = 0;
    for (i = 0; i < 6; i++) {
        if (inst->dev_mac[i] != 0) {
            mac_valid = 1;
            break;
        }
    }
    if (!mac_valid) {
        log_warn("Device MAC from skey unavailable, fallback to interface");
        if (get_local_address(dev_ip, inst->dev_mac) < 0) {
            log_error("Can get local address!");
            return -1;
        }
    }

    // device_id 末尾追加设备 MAC 最后四个字节（8 个小写十六进制字符）
    // char mac_suffix[9];
    // snprintf(mac_suffix, sizeof(mac_suffix), "%02x%02x",
    //          (unsigned)inst->dev_mac[4], (unsigned)inst->dev_mac[5]);
    // size_t device_id_len = strlen(inst->device_id);
    // if (device_id_len >= 8 &&
    //     strcmp(inst->device_id + device_id_len - 8, mac_suffix) == 0) {
    //     // 配置重载时已追加过，保持幂等
    //     log_debug("Device ID already has MAC suffix: %s", inst->device_id);
    // } else if (device_id_len + 8 < sizeof(inst->device_id)) {
    //     snprintf(inst->device_id + device_id_len, 9, "%s", mac_suffix);
    //     log_debug("Device ID with MAC suffix: %s", inst->device_id);
    // } else {
    //     log_error("Device ID is too long to append MAC suffix: %s",
    //               inst->device_id);
    // }



    /*
      printf("++++++++++++++++++++nas_ip=%s\n",config->nas_ip);
        if( config->nas_ip[0]==0){
            memset(config->nas_ip,0,24);
            snprintf(config->nas_ip,24,"%s",dev_ip);
        }
     */
    // printf("++++++++++++++++1  ip=%s\n",inst->dev_ip);
    if (strlen(inst->config->portal_ip) < 7) {
        snprintf(inst->config->portal_ip, 24, "%s", inst->dev_ip);
    }
    return 0;
}

/* Remove every staged-delta search path from a UCI context.  This is the
 * same isolation technique used by rpcd for per-session cursors: the base
 * file remains readable, but /tmp/.uci changes from unrelated processes are
 * not mixed into the committed view. */
static void uci_clear_delta_paths(struct uci_context* ctx) {
    struct uci_element *e, *tmp;

    if (!ctx) {
        return;
    }
    uci_foreach_element_safe(&ctx->delta_path, tmp, e) {
        free(e->name);
        free(e);
    }
    ctx->delta_path.prev = &ctx->delta_path;
    ctx->delta_path.next = &ctx->delta_path;
    ctx->flags &= ~UCI_FLAG_SAVED_DELTA;
}

static ssize_t get_uci_option_internal(const char *arg, char* buf,
                                       size_t buf_size,
                                       int committed_only) {
    struct uci_context *ctx;
    struct uci_ptr ptr;
    char *value;
    char tmp_arg[256] = {0};
    ssize_t result = 0;

    if (!arg || !buf || buf_size == 0 || strlen(arg) >= sizeof(tmp_arg)) {
        return -1;
    }
    buf[0] = '\0';
    snprintf(tmp_arg, sizeof(tmp_arg), "%s", arg);

    struct uci_element *e;
    //char tmp_buf[MAX_BUF_SIZE] = {0};
    size_t len = 0;
    size_t size = 0;
    ctx = uci_alloc_context();
    if (!ctx) {
        log_error("Create UCI context failed!");
        return -1;
    }
    if (committed_only) {
        uci_clear_delta_paths(ctx);
    }
    if (uci_lookup_ptr(ctx, &ptr, tmp_arg, true) != UCI_OK || ptr.o == NULL) {
        /* Missing options are handled by the caller's defaults. */
        uci_free_context(ctx);
        return 0;
    }
    switch (ptr.o->type) {
        case UCI_TYPE_LIST:
            size = 0;

            uci_foreach_element(&(ptr.o->v.list), e) {
                value = e->name;
                if (value) {
                    len = strlen(value);
                    size_t separator = (size > 0) ? 1 : 0;
                    if (size + separator + len + 1 > buf_size) {
                        log_error("UCI list '%s' exceeds destination capacity %zu",
                                  arg, buf_size);
                        result = -1;
                        goto out;
                    }
                    if (separator) {
                        buf[size++] = ' ';
                    }
                    memcpy(buf + size, value, len);
                    size += len;
                    buf[size] = '\0';
                }
            }
            result = size > 0 ? (ssize_t)(size + 1) : 0;
            break;
        case UCI_TYPE_STRING:

            value = ptr.o->v.string;
            if (value) {
                size = strlen(value) + 1;
                if (size > buf_size) {
                    log_error("UCI option '%s' exceeds destination capacity %zu",
                              arg, buf_size);
                    result = -1;
                } else {
                    memcpy(buf, value, size);
                    result = (ssize_t)size;
                }
            }
            break;
        default:
            result = -1;
            break;
    }

out:
    uci_free_context(ctx);
    return result;
}

ssize_t get_uci_option(const char *arg, char* buf, size_t buf_size) {
    return get_uci_option_internal(arg, buf, buf_size, 0);
}

int free_config(struct inst_t* inst) {
    if (inst->config) {
        // 白名单数组内嵌于 inst，无需单独释放；重置计数即可
        inst->white_list.src_ip_count = 0;
        inst->white_list.src_mac_count = 0;
        release_config_object(inst->config);
        inst->config = NULL;
        log_debug("Free config \t\tOK!");
    } else {
        log_error("Free config \t\tERROR!");
        return -1;
    }
    return 0;
}

void ws_status(struct evhttp_request *req, void *arg) {
    struct evkeyvalq params;
    int code = 0;
    const char *uri = NULL;
    const char* name = NULL;
    int config_name = 0;
    struct inst_t* inst = (struct inst_t*) arg;

    if (strncmp(req->remote_host, "127.0.0.1", 9) != 0) {
        evhttp_send_reply(req, HTTP_NOTFOUND, "NOTFOUND", NULL);
        return;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }


    if (inst->called_station_id[0] == 0) {
        snprintf(inst->called_station_id, 128, "%02x:%02x:%02x:%02x:%02x:%02x",
                inst->dev_mac[0], inst->dev_mac[1], inst->dev_mac[2],
                inst->dev_mac[3], inst->dev_mac[4], inst->dev_mac[5]);
    }


    cJSON_AddStringToObject(root, "portal_ip", inst->str_portal_ip);
    cJSON_AddStringToObject(root, "called_station_id", inst->called_station_id);

    if (inst->config) {
        cJSON_AddNumberToObject(root, "http_portal_auth", inst->config->http_portal_auth);
        cJSON_AddNumberToObject(root, "portal_type", inst->config->portal_type);
        cJSON_AddNumberToObject(root, "mac_auth", inst->config->mac_auth_enabled);
        cJSON_AddNumberToObject(root, "mac_auth_format", inst->config->mac_auth_format);
        cJSON_AddNumberToObject(root, "idle_timeout", inst->config->idle_timeout);

        cJSON_AddStringToObject(root, "portal_server", inst->config->portal_server);

        cJSON_AddNumberToObject(root, "portal_port", inst->config->portal_port);
        cJSON_AddStringToObject(root, "portal_url", inst->config->portal_url);
        cJSON_AddStringToObject(root, "primary_auth_server", inst->config->primary_auth_server);
        cJSON_AddStringToObject(root, "primary_auth_secret", inst->config->primary_auth_secret);
        cJSON_AddNumberToObject(root, "primary_auth_port", inst->config->primary_auth_port);

        cJSON_AddStringToObject(root, "primary_acct_server", inst->config->primary_acct_server);
        cJSON_AddStringToObject(root, "primary_acct_secret", inst->config->primary_acct_secret);
        cJSON_AddNumberToObject(root, "primary_acct_port", inst->config->primary_acct_port);


        cJSON_AddStringToObject(root, "nas_ip", inst->config->nas_ip);
    }
    // printf("+++++++++++++++++++++++2\n");
    char *response_data = cJSON_Print(root);
    cJSON_Delete(root);
    if (!response_data) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }
    send_http_reply(req, HTTP_REPLY_OPERATING_SUCCESS, response_data);

    if (response_data) {
        free(response_data);
    }
    // cJSON_Delete(root);

    return;




}

void ws_update_config_v1(struct evhttp_request *req, void *arg) {
    struct evkeyvalq params;
    int err_code = 0;
    const char *uri = NULL;
    const char* name = NULL;
    char name_copy[64] = {0};
    int config_name = 0;
    struct inst_t* inst = (struct inst_t*) arg;

    if (strncmp(req->remote_host, "127.0.0.1", 9) != 0) {
        evhttp_send_reply(req, HTTP_NOTFOUND, "NOTFOUND", NULL);
        return;
    }





    TAILQ_INIT(&params);
    do {
        uri = evhttp_request_get_uri(req);
        if (uri == NULL) {
            log_error("URI 'ws_update_config' : not found URI");
            err_code = HTTP_REPLY_URI_ERROR;
            break;
        }
        log_debug("URI 'show_user_by_name': %s", uri);

        if (evhttp_parse_query(uri, &params) != 0) {
            log_error("URI '%s': parse query string failed", __func__);
            err_code = HTTP_REPLY_URI_ERROR;
            break;
        }
        name = evhttp_find_header(&params, "name");
        if (name == NULL) {
            log_error("URI 'ws_update_config': not found parameter 'name'");
            err_code = HTTP_REPLY_PARAM_ERROR;
            break;
        }

    } while (0);

    if (err_code < 0) {
        evhttp_clear_headers(&params);
        send_http_reply(req, err_code, NULL);
        return;
    }

    /* name 指向参数表内存, 复制后释放查询表, 避免后续返回路径泄漏 */
    snprintf(name_copy, sizeof(name_copy), "%s", name);
    evhttp_clear_headers(&params);
    name = name_copy;

    if (strncmp(name, "generic", 7) == 0) {
        config_name = CONFIG_GENERIC;
    }
    if (strncmp(name, "portal", 6) == 0) {
        config_name = CONFIG_PORTAL;
    }
    if (strncmp(name, "radius", 6) == 0) {
        config_name = CONFIG_RADIUS;
    }
    if (strncmp(name, "http_auth", 9) == 0) {
        config_name = CONFIG_HTTP_AUTH;
    }
    if (strncmp(name, "whitelist", 9) == 0) {
        config_name = CONFIG_WHITLIST;
    }

    process_server_events(EV_UPDATE_CONFIG, NULL, &config_name);
    send_http_reply(req, 0, NULL);

    return;

}

int reload_all_configs(struct inst_t *inst) {
    struct config_t* old_config;
    struct config_t* new_config;
    struct white_list_t old_white_list;

    if (!inst || !inst->config) {
        log_error("Reload config failed: current config is unavailable");
        return -1;
    }
    old_config = inst->config;
    old_white_list = inst->white_list;
    inst->config = NULL;
    if (load_all_configs(inst) < 0) {
        log_error("Load config failed!");
        if (inst->config) {
            release_config_object(inst->config);
        }
        inst->config = old_config;
        inst->white_list = old_white_list;
        return -1;
    }
    new_config = inst->config;
    /* 重新绑定 inst->rad_* 指针到新 config, 避免 free_config 后悬垂指针 */
    if (init_radius(inst) != 0) {
        log_error("Rebind RADIUS config failed after reload");
        release_config_object(new_config);
        inst->config = old_config;
        inst->white_list = old_white_list;
        init_radius(inst);
        return -1;
    }
    /* 所有配置刷新都重建派生白名单，避免刷新无关段后源白名单消失。 */
    if (init_white_list(inst) != 0) {
        log_error("Rebuild whitelist failed after config reload");
        release_config_object(new_config);
        inst->config = old_config;
        inst->white_list = old_white_list;
        init_radius(inst);
        if (init_white_list(inst) != 0) {
            log_error("Rollback whitelist rebuild also failed");
        }
        return -1;
    }
    release_config_object(old_config);
    return 0;
}

/* ===========================================================================
 * 本地配置 HTTP 服务(127.0.0.1:60000)
 *   GET  /v1/config/get?section=radius|generic|portal|all[&show_secret=1]
 *   POST /v1/config/radius/update  JSON body, 部分更新 RADIUS 对接参数
 * GET 返回每个段的双视图与一致性结果:
 *   running     当前运行参数(RADIUS 取 inst->rad_*, 其余取 inst->config)
 *   saved       每次实时读取的 UCI 保存配置(inst->config 会被云端覆写, 不可用)
 *   in_sync     两者是否完全一致
 *   diff_fields 不一致字段名列表
 * 写入规则(热更新优先):
 *   - 外部传入参数先做全量校验, 任一非法则整单拒绝, 不做任何修改;
 *   - 先对运行中的 RADIUS 客户端热更新(改内存 + init_radius 立即生效),
 *     失败则回退旧值并返回 -1006, 此时 UCI 未被触碰;
 *   - 热更新成功(或无需热更新)后与 UCI 保存值比对, 不一致才写入 UCI;
 *   - 传入值与运行值相同则跳过热更新, 但仍会补齐 UCI 差异。
 * =========================================================================*/

#define CONFIG_HTTP_BODY_MAX   4096
#define CONFIG_SECRET_MASK     "******"

#define RADIUS_KIND_STRING     0
#define RADIUS_KIND_PORT       1

/* RADIUS 字段描述符: JSON 字段名 <-> UCI 键 <-> struct config_t 字段 */
struct radius_field_tpl {
    const char* json_name;
    const char* uci_name;
    int         kind;        /* RADIUS_KIND_STRING / RADIUS_KIND_PORT */
    int         must_be_ip;  /* 字符串字段是否必须为合法 IPv4 */
    size_t      buf_size;    /* config 中接收缓冲大小(字符串字段) */
    size_t      offset;      /* 在 struct config_t 中的偏移 */
};

static const struct radius_field_tpl radius_fields[] = {
    {"auth_server", "webauthd.radius.primary_auth_server",
     RADIUS_KIND_STRING, 1,
     sizeof(((struct config_t*)0)->primary_auth_server),
     offsetof(struct config_t, primary_auth_server)},
    {"acct_server", "webauthd.radius.primary_acct_server",
     RADIUS_KIND_STRING, 1,
     sizeof(((struct config_t*)0)->primary_acct_server),
     offsetof(struct config_t, primary_acct_server)},
    {"nas_ip", "webauthd.radius.nas_ip",
     RADIUS_KIND_STRING, 1,
     sizeof(((struct config_t*)0)->nas_ip),
     offsetof(struct config_t, nas_ip)},
    {"auth_secret", "webauthd.radius.primary_auth_secret",
     RADIUS_KIND_STRING, 0,
     sizeof(((struct config_t*)0)->primary_auth_secret),
     offsetof(struct config_t, primary_auth_secret)},
    {"acct_secret", "webauthd.radius.primary_acct_secret",
     RADIUS_KIND_STRING, 0,
     sizeof(((struct config_t*)0)->primary_acct_secret),
     offsetof(struct config_t, primary_acct_secret)},
    {"auth_port", "webauthd.radius.primary_auth_port",
     RADIUS_KIND_PORT, 0, 0,
     offsetof(struct config_t, primary_auth_port)},
    {"acct_port", "webauthd.radius.primary_acct_port",
     RADIUS_KIND_PORT, 0, 0,
     offsetof(struct config_t, primary_acct_port)},
    /* 租户组织ID: 最长 64 字符, 作为 Filter-Id 的值; 非 IPv4, 不参与 init_radius */
    {"tenant_org_id", "webauthd.radius.tenant_org_id",
     RADIUS_KIND_STRING, 0,
     sizeof(((struct config_t*)0)->tenant_org_id),
     offsetof(struct config_t, tenant_org_id)},
};
#define RADIUS_FIELD_COUNT (sizeof(radius_fields) / sizeof(radius_fields[0]))

static int config_is_localhost(struct evhttp_request* req) {
    return req->remote_host &&
           strncmp(req->remote_host, "127.0.0.1", 9) == 0;
}

static int config_is_valid_ipv4(const char* s) {
    struct in_addr addr;

    return (s && s[0] && inet_pton(AF_INET, s, &addr) == 1);
}

static const struct radius_field_tpl* find_radius_field(const char* name) {
    size_t i;

    if (!name) {
        return NULL;
    }
    for (i = 0; i < RADIUS_FIELD_COUNT; i++) {
        if (strcmp(name, radius_fields[i].json_name) == 0) {
            return &radius_fields[i];
        }
    }
    return NULL;
}

static const char* mask_secret(const char* s, int show_secret) {
    if (!s || s[0] == '\0') {
        return "";
    }
    return show_secret ? s : CONFIG_SECRET_MASK;
}

/* 同一 uci 上下文内批量 set, 最后一次性 commit; 任一环节失败即整体放弃 */
struct config_kv {
    const char* key;
    const char* value;
};

static int set_uci_options(const struct config_kv* kv, int count) {
    struct uci_context* ctx = NULL;
    struct uci_ptr ptr;
    struct uci_package* pkg = NULL;
    int i;

    ctx = uci_alloc_context();
    if (!ctx) {
        log_error("UCI alloc context failed");
        return -1;
    }
    /* 使用本服务私有 delta 目录，既不读取也不提交其它进程留在
     * /tmp/.uci 的暂存修改。 */
    uci_clear_delta_paths(ctx);
    if (mkdir("/tmp/.webauthd-uci", 0700) != 0 && errno != EEXIST) {
        log_error("Create private UCI delta dir failed: %s", strerror(errno));
        goto fail;
    }
    unlink("/tmp/.webauthd-uci/webauthd");
    if (uci_set_savedir(ctx, "/tmp/.webauthd-uci") != UCI_OK) {
        log_error("Set private UCI delta dir failed");
        goto fail;
    }

    for (i = 0; i < count; i++) {
        char keybuf[128];
        memset(&ptr, 0, sizeof(ptr));
        /* uci_lookup_ptr 会原地改写 key 字符串(按 '.' 分词写入 '\0'),
         * 传字符串字面量(.rodata)会触发 SIGSEGV, 必须拷贝到可写缓冲 */
        snprintf(keybuf, sizeof(keybuf), "%s", kv[i].key);
        if (uci_lookup_ptr(ctx, &ptr, keybuf, true) != UCI_OK ||
            !ptr.p) {
            log_error("UCI lookup failed: %s", kv[i].key);
            goto fail;
        }
        pkg = ptr.p;
        ptr.value = (char*)kv[i].value;
        if (uci_set(ctx, &ptr) != UCI_OK) {
            log_error("UCI set failed: %s=%s", kv[i].key, kv[i].value);
            goto fail;
        }
    }

    /* commit webauthd 整个包, 保证多次 set 一次性落盘 */
    if (!pkg || uci_commit(ctx, &pkg, false) != UCI_OK) {
        log_error("UCI commit failed for package webauthd");
        goto fail;
    }

    uci_free_context(ctx);
    unlink("/tmp/.webauthd-uci/webauthd");

    /* 用不加载暂存 delta 的新上下文读回，只有真实持久文件与目标值
     * 一致才报告成功。 */
    for (i = 0; i < count; i++) {
        char verify[MAX_BUF_SIZE] = {0};
        if (get_uci_option_internal(kv[i].key, verify, sizeof(verify), 1) <= 0 ||
            strcmp(verify, kv[i].value) != 0) {
            log_error("Committed UCI readback mismatch: %s", kv[i].key);
            return -1;
        }
    }
    return 0;

fail:
    uci_free_context(ctx);
    unlink("/tmp/.webauthd-uci/webauthd");
    return -1;
}

/* ---- GET: 运行参数(running) vs UCI 保存配置(saved) 双视图 + 一致性对比 ---- */

/* 经大缓冲中转读取 UCI 字符串, 避免短缓冲被 get_uci_option 写穿 */
static void uci_read_str(const char* key, char* out, size_t outsz) {
    char tmp[MAX_BUF_SIZE];

    if (outsz == 0) {
        return;
    }
    out[0] = '\0';
    tmp[0] = '\0';
    get_uci_option_internal(key, tmp, sizeof(tmp), 1);
    strncpy(out, tmp, outsz - 1);
    out[outsz - 1] = '\0';
}

/* 读取 UCI 整数; 选项缺失时返回 def */
static int uci_read_int(const char* key, int def) {
    char tmp[MAX_BUF_SIZE];

    tmp[0] = '\0';
    get_uci_option_internal(key, tmp, sizeof(tmp), 1);
    if (tmp[0] == '\0') {
        return def;
    }
    return atoi(tmp);
}

/* RADIUS 参数快照, 用于运行/保存对比 */
struct radius_snapshot {
    char auth_server[24];
    char acct_server[24];
    char nas_ip[32];
    char auth_secret[32];
    char acct_secret[32];
    int  auth_port;
    int  acct_port;
    char tenant_org_id[65];
};

/* 运行参数: 取自 RADIUS 客户端实际使用的 inst->rad_*(云端/本地共用) */
static void radius_running_snapshot(struct inst_t* inst,
                                    struct radius_snapshot* s) {
    memset(s, 0, sizeof(*s));
    if (inst->rad_auth_server) {
        strncpy(s->auth_server, inst->rad_auth_server,
                sizeof(s->auth_server) - 1);
    }
    if (inst->rad_acct_server) {
        strncpy(s->acct_server, inst->rad_acct_server,
                sizeof(s->acct_server) - 1);
    }
    if (inst->nas_ip) {
        strncpy(s->nas_ip, inst->nas_ip, sizeof(s->nas_ip) - 1);
    }
    if (inst->rad_auth_secret) {
        strncpy(s->auth_secret, inst->rad_auth_secret,
                sizeof(s->auth_secret) - 1);
    }
    if (inst->rad_acct_secret) {
        strncpy(s->acct_secret, inst->rad_acct_secret,
                sizeof(s->acct_secret) - 1);
    }
    s->auth_port = inst->rad_auth_port;
    s->acct_port = inst->rad_acct_port;
    /* tenant_org_id 没有对应的 inst->rad_* 字段, 报文构造时直接读
     * inst->config->tenant_org_id, 因此运行值就取 config */
    if (inst->config) {
        strncpy(s->tenant_org_id, inst->config->tenant_org_id,
                sizeof(s->tenant_org_id) - 1);
    }
}

/* 内存配置快照: 热更新前的旧值备份, 用于失败回退。
 * 不用 rad_* 做回退源: 云端模式未初始化时 rad_* 为 NULL, 会把 UCI 值清空 */
static void radius_cfg_snapshot(struct config_t* cfg,
                                struct radius_snapshot* s) {
    memset(s, 0, sizeof(*s));
    strncpy(s->auth_server, cfg->primary_auth_server,
            sizeof(s->auth_server) - 1);
    strncpy(s->acct_server, cfg->primary_acct_server,
            sizeof(s->acct_server) - 1);
    strncpy(s->nas_ip, cfg->nas_ip, sizeof(s->nas_ip) - 1);
    strncpy(s->auth_secret, cfg->primary_auth_secret,
            sizeof(s->auth_secret) - 1);
    strncpy(s->acct_secret, cfg->primary_acct_secret,
            sizeof(s->acct_secret) - 1);
    s->auth_port = cfg->primary_auth_port;
    s->acct_port = cfg->primary_acct_port;
    strncpy(s->tenant_org_id, cfg->tenant_org_id,
            sizeof(s->tenant_org_id) - 1);
}

/* 用快照恢复内存配置(回退), 再由调用方重新 init_radius */
static void restore_cfg_from_snapshot(struct config_t* cfg,
                                      const struct radius_snapshot* s) {
    memset(cfg->primary_auth_server, 0, sizeof(cfg->primary_auth_server));
    memcpy(cfg->primary_auth_server, s->auth_server,
           strlen(s->auth_server));
    memset(cfg->primary_acct_server, 0, sizeof(cfg->primary_acct_server));
    memcpy(cfg->primary_acct_server, s->acct_server,
           strlen(s->acct_server));
    memset(cfg->nas_ip, 0, sizeof(cfg->nas_ip));
    memcpy(cfg->nas_ip, s->nas_ip, strlen(s->nas_ip));
    memset(cfg->primary_auth_secret, 0, sizeof(cfg->primary_auth_secret));
    memcpy(cfg->primary_auth_secret, s->auth_secret,
           strlen(s->auth_secret));
    memset(cfg->primary_acct_secret, 0, sizeof(cfg->primary_acct_secret));
    memcpy(cfg->primary_acct_secret, s->acct_secret,
           strlen(s->acct_secret));
    cfg->primary_auth_port = (uint16_t)s->auth_port;
    cfg->primary_acct_port = (uint16_t)s->acct_port;
    memset(cfg->tenant_org_id, 0, sizeof(cfg->tenant_org_id));
    memcpy(cfg->tenant_org_id, s->tenant_org_id, strlen(s->tenant_org_id));
}

/* 按 radius_fields 固定下标取快照字段, 供 UCI 差异比对使用 */
static const char* snap_string_at(const struct radius_snapshot* s,
                                  size_t idx) {
    switch (idx) {
        case 0: return s->auth_server;
        case 1: return s->acct_server;
        case 2: return s->nas_ip;
        case 3: return s->auth_secret;
        case 4: return s->acct_secret;
        case 7: return s->tenant_org_id;
        default: return NULL;
    }
}

static int snap_port_at(const struct radius_snapshot* s, size_t idx) {
    return (idx == 5) ? s->auth_port : s->acct_port;
}

/* 保存配置: 每次实时读取 UCI(不能用 inst->config, 云端应答会覆写它) */
static void radius_saved_snapshot(struct radius_snapshot* s) {
    memset(s, 0, sizeof(*s));
    uci_read_str("webauthd.radius.primary_auth_server",
                 s->auth_server, sizeof(s->auth_server));
    uci_read_str("webauthd.radius.primary_acct_server",
                 s->acct_server, sizeof(s->acct_server));
    uci_read_str("webauthd.radius.nas_ip", s->nas_ip, sizeof(s->nas_ip));
    uci_read_str("webauthd.radius.primary_auth_secret",
                 s->auth_secret, sizeof(s->auth_secret));
    uci_read_str("webauthd.radius.primary_acct_secret",
                 s->acct_secret, sizeof(s->acct_secret));
    s->auth_port = uci_read_int("webauthd.radius.primary_auth_port", 0);
    s->acct_port = uci_read_int("webauthd.radius.primary_acct_port", 0);
    uci_read_str("webauthd.radius.tenant_org_id", s->tenant_org_id,
                 sizeof(s->tenant_org_id));
}

static cJSON* radius_snapshot_json(const struct radius_snapshot* s,
                                   int show_secret) {
    cJSON* o = cJSON_CreateObject();

    cJSON_AddStringToObject(o, "auth_server", s->auth_server);
    cJSON_AddStringToObject(o, "acct_server", s->acct_server);
    cJSON_AddStringToObject(o, "nas_ip", s->nas_ip);
    cJSON_AddStringToObject(o, "auth_secret",
                            mask_secret(s->auth_secret, show_secret));
    cJSON_AddStringToObject(o, "acct_secret",
                            mask_secret(s->acct_secret, show_secret));
    cJSON_AddNumberToObject(o, "auth_port", s->auth_port);
    cJSON_AddNumberToObject(o, "acct_port", s->acct_port);
    cJSON_AddStringToObject(o, "tenant_org_id", s->tenant_org_id);
    return o;
}

/* radius 视图: state / in_sync / diff_fields / running / saved */
static cJSON* build_radius_view(struct inst_t* inst, int show_secret) {
    struct radius_snapshot run;
    struct radius_snapshot saved;
    cJSON* o = cJSON_CreateObject();
    cJSON* diff = cJSON_CreateArray();

    radius_running_snapshot(inst, &run);
    radius_saved_snapshot(&saved);

    /* 用明文比对密钥, 输出仍受 show_secret 控制 */
    if (strcmp(run.auth_server, saved.auth_server) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("auth_server"));
    }
    if (strcmp(run.acct_server, saved.acct_server) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("acct_server"));
    }
    if (strcmp(run.nas_ip, saved.nas_ip) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("nas_ip"));
    }
    if (strcmp(run.auth_secret, saved.auth_secret) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("auth_secret"));
    }
    if (strcmp(run.acct_secret, saved.acct_secret) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("acct_secret"));
    }
    if (run.auth_port != saved.auth_port) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("auth_port"));
    }
    if (run.acct_port != saved.acct_port) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("acct_port"));
    }
    if (strcmp(run.tenant_org_id, saved.tenant_org_id) != 0) {
        cJSON_AddItemToArray(diff, cJSON_CreateString("tenant_org_id"));
    }

    cJSON_AddStringToObject(o, "state",
                            inst->rad_auth_server ? "initialized"
                                                 : "not_initialized");
    cJSON_AddBoolToObject(o, "in_sync", cJSON_GetArraySize(diff) == 0);
    cJSON_AddItemToObject(o, "diff_fields", diff);
    cJSON_AddItemToObject(o, "running",
                          radius_snapshot_json(&run, show_secret));
    cJSON_AddItemToObject(o, "saved",
                          radius_snapshot_json(&saved, show_secret));
    return o;
}

/* generic / portal 段: 运行参数直接取自 inst->config(业务代码即如此使用),
 * 保存配置实时读 UCI; 两者不一致通常意味着 UCI 被外部改动但尚未 reload */
struct cfg_view_field {
    const char* json_name;
    const char* uci_key;
    int         is_string;
    size_t      offset;   /* 在 struct config_t 中的偏移 */
};

static cJSON* build_config_view(struct config_t* cfg,
                                const struct cfg_view_field* tpl, int n) {
    cJSON* o = cJSON_CreateObject();
    cJSON* running = cJSON_CreateObject();
    cJSON* saved = cJSON_CreateObject();
    cJSON* diff = cJSON_CreateArray();
    /* 最大字段 portal_url[1024], 预留余量 */
    char ubuf[MAX_BUF_SIZE + 64];
    int i;

    for (i = 0; i < n; i++) {
        if (tpl[i].is_string) {
            const char* cur =
                (const char*)((const char*)cfg + tpl[i].offset);
            uci_read_str(tpl[i].uci_key, ubuf, sizeof(ubuf));
            cJSON_AddStringToObject(running, tpl[i].json_name, cur);
            cJSON_AddStringToObject(saved, tpl[i].json_name, ubuf);
            if (strcmp(cur, ubuf) != 0) {
                cJSON_AddItemToArray(diff,
                                     cJSON_CreateString(tpl[i].json_name));
            }
        } else {
            int cur = *(const int*)((const char*)cfg + tpl[i].offset);
            int sv = uci_read_int(tpl[i].uci_key, 0);
            cJSON_AddNumberToObject(running, tpl[i].json_name, cur);
            cJSON_AddNumberToObject(saved, tpl[i].json_name, sv);
            if (cur != sv) {
                cJSON_AddItemToArray(diff,
                                     cJSON_CreateString(tpl[i].json_name));
            }
        }
    }

    cJSON_AddBoolToObject(o, "in_sync", cJSON_GetArraySize(diff) == 0);
    cJSON_AddItemToObject(o, "diff_fields", diff);
    cJSON_AddItemToObject(o, "running", running);
    cJSON_AddItemToObject(o, "saved", saved);
    return o;
}

static const struct cfg_view_field generic_view_fields[] = {
    {"enabled",       "webauthd.generic.enabled",       0,
     offsetof(struct config_t, enabled)},
    {"layer",         "webauthd.generic.layer",         0,
     offsetof(struct config_t, layer)},
    {"layer2_ifname", "webauthd.generic.layer2_ifname", 1,
     offsetof(struct config_t, layer2_ifname)},
    {"layer3_ifname", "webauthd.generic.layer3_ifname", 1,
     offsetof(struct config_t, layer3_ifname)},
    {"portal_ip",     "webauthd.generic.portal_ip",     1,
     offsetof(struct config_t, portal_ip)},
    {"capture_dns",   "webauthd.generic.capture_dns",   0,
     offsetof(struct config_t, capture_dns)},
    {"auth_type",     "webauthd.generic.auth_type",     0,
     offsetof(struct config_t, auth_type)},
    {"idle_timeout",  "webauthd.generic.idle_timeout",  0,
     offsetof(struct config_t, idle_timeout)},
    {"mac_auth",      "webauthd.generic.mac_auth",      0,
     offsetof(struct config_t, mac_auth_enabled)},
    {"mac_auth_format", "webauthd.generic.mac_auth_format", 0,
     offsetof(struct config_t, mac_auth_format)},
};

static const struct cfg_view_field portal_view_fields[] = {
    {"portal_type",      "webauthd.portal.portal_type",      0,
     offsetof(struct config_t, portal_type)},
    {"http_portal_auth", "webauthd.portal.http_portal_auth", 0,
     offsetof(struct config_t, http_portal_auth)},
    {"hw_portal_auth",   "webauthd.portal.hw_portal_auth",   0,
     offsetof(struct config_t, hw_portal_auth)},
    {"portal_server",    "webauthd.portal.portal_server",    1,
     offsetof(struct config_t, portal_server)},
    {"portal_port",      "webauthd.portal.portal_port",      0,
     offsetof(struct config_t, portal_port)},
    {"portal_url",       "webauthd.portal.portal_url",       1,
     offsetof(struct config_t, portal_url)},
};
#define CFG_VIEW_COUNT(t) (sizeof(t) / sizeof((t)[0]))

void ws_config_get_v1(struct evhttp_request* req, void* arg) {
    struct inst_t* inst = (struct inst_t*)arg;
    struct evkeyvalq params;
    const char* uri = evhttp_request_get_uri(req);
    const char* section = NULL;
    const char* show = NULL;
    int show_secret = 0;
    int matched = 1;
    cJSON* body = NULL;
    char* out = NULL;

    if (!config_is_localhost(req)) {
        evhttp_send_reply(req, HTTP_NOTFOUND, "NOTFOUND", NULL);
        return;
    }
    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        evhttp_send_reply(req, HTTP_BADMETHOD, "METHOD NOT ALLOWED", NULL);
        return;
    }

    /* 无 query 串时 evhttp_parse_query 会失败, 直接按缺省处理 */
    if (strchr(uri, '?') && evhttp_parse_query(uri, &params) == 0) {
        section = evhttp_find_header(&params, "section");
        show = evhttp_find_header(&params, "show_secret");
        if (show && strcmp(show, "1") == 0) {
            show_secret = 1;
        }
    }
    if (!section) {
        section = "all";
    }

    body = cJSON_CreateObject();
    if (!body) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }

    cJSON_AddStringToObject(body, "radius_source",
                            inst->config->local_radius_client == 1
                                ? "local"
                                : "cloud");

    if (strcmp(section, "radius") == 0 || strcmp(section, "all") == 0) {
        cJSON_AddItemToObject(body, "radius",
                              build_radius_view(inst, show_secret));
    }
    if (strcmp(section, "generic") == 0 || strcmp(section, "all") == 0) {
        cJSON_AddItemToObject(body, "generic",
                              build_config_view(
                                  inst->config, generic_view_fields,
                                  CFG_VIEW_COUNT(generic_view_fields)));
    }
    if (strcmp(section, "portal") == 0 || strcmp(section, "all") == 0) {
        cJSON_AddItemToObject(body, "portal",
                              build_config_view(
                                  inst->config, portal_view_fields,
                                  CFG_VIEW_COUNT(portal_view_fields)));
    }
    if (strcmp(section, "radius") != 0 && strcmp(section, "generic") != 0 &&
        strcmp(section, "portal") != 0 && strcmp(section, "all") != 0) {
        matched = 0;
    }

    if (!matched) {
        cJSON_Delete(body);
        log_warn("ws_config_get_v1: unknown section '%s'", section);
        send_http_reply(req, HTTP_REPLY_PARAM_ERROR, NULL);
        return;
    }

    out = cJSON_Print(body);
    cJSON_Delete(body);
    if (!out) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }
    send_http_reply(req, HTTP_REPLY_OPERATING_SUCCESS, out);
    free(out);
}

void ws_config_radius_update_v1(struct evhttp_request* req, void* arg) {
    struct inst_t* inst = (struct inst_t*)arg;
    struct config_t* cfg = inst->config;
    struct evbuffer* inbuf = NULL;
    size_t body_len = 0;
    ev_ssize_t removed = 0;
    char* raw = NULL;
    cJSON* root = NULL;
    cJSON* body = NULL;
    char* out = NULL;
    int rc = 0;
    size_t i;

    /* 暂存通过校验的候选值(65 字节足以容纳最长的 tenant_org_id[65]) */
    char str_val[RADIUS_FIELD_COUNT][65];
    uint16_t port_val[RADIUS_FIELD_COUNT];
    int present[RADIUS_FIELD_COUNT];
    int hot_changed[RADIUS_FIELD_COUNT];
    int any_present = 0;
    int hot_count = 0;
    int uci_written = 0;

    memset(str_val, 0, sizeof(str_val));
    memset(port_val, 0, sizeof(port_val));
    memset(present, 0, sizeof(present));
    memset(hot_changed, 0, sizeof(hot_changed));

    if (!config_is_localhost(req)) {
        evhttp_send_reply(req, HTTP_NOTFOUND, "NOTFOUND", NULL);
        return;
    }
    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        evhttp_send_reply(req, HTTP_BADMETHOD, "METHOD NOT ALLOWED", NULL);
        return;
    }

    inbuf = evhttp_request_get_input_buffer(req);
    body_len = evbuffer_get_length(inbuf);
    if (body_len == 0 || body_len > CONFIG_HTTP_BODY_MAX) {
        rc = CONFIG_REPLY_BODY_ERROR;
        goto done;
    }

    raw = (char*)malloc(body_len + 1);
    if (!raw) {
        rc = HTTP_REPLY_JSON_IS_ERROR;
        goto done;
    }
    removed = evbuffer_remove(inbuf, raw, body_len);
    if (removed < 0 || (size_t)removed != body_len) {
        log_error("Read config request body failed: removed=%d expect=%zu",
                  (int)removed, body_len);
        rc = CONFIG_REPLY_BODY_ERROR;
        goto done;
    }
    raw[body_len] = '\0';

    root = cJSON_Parse(raw);
    /* 老版 cJSON 类型值为互斥小整数(0..6), 必须用 == 精确比较,
       位与会把 Object(6) 误判为 Number(3)/String(4) */
    if (!root || root->type != cJSON_Object) {
        log_warn("radius update: body is not a valid JSON object");
        rc = CONFIG_REPLY_BODY_ERROR;
        goto done;
    }

    /* 第一遍: 严格字段名检查, 出现未知字段直接拒绝整单 */
    {
        cJSON* it;
        for (it = root->child; it; it = it->next) {
            if (!find_radius_field(it->string)) {
                log_warn("radius update: unknown field '%s'",
                         it->string ? it->string : "(null)");
                rc = CONFIG_REPLY_UNKNOWN_FIELD;
                goto done;
            }
        }
    }

    /* 第二遍: 类型/值域全量校验, 任一非法则整单拒绝, 不写入任何内容 */
    for (i = 0; i < RADIUS_FIELD_COUNT; i++) {
        const struct radius_field_tpl* f = &radius_fields[i];
        cJSON* item = cJSON_GetObjectItem(root, f->json_name);
        if (!item) {
            continue;
        }
        present[i] = 1;
        any_present = 1;

        if (f->kind == RADIUS_KIND_STRING) {
            size_t slen;
            if (item->type != cJSON_String) {
                log_warn("radius update: field '%s' must be string",
                         f->json_name);
                rc = CONFIG_REPLY_VALUE_INVALID;
                goto done;
            }
            slen = strlen(item->valuestring);
            if (slen >= f->buf_size) {
                log_warn("radius update: field '%s' too long (%zu >= %zu)",
                         f->json_name, slen, f->buf_size);
                rc = CONFIG_REPLY_VALUE_TOO_LONG;
                goto done;
            }
            if (f->must_be_ip && !config_is_valid_ipv4(item->valuestring)) {
                log_warn("radius update: field '%s' invalid IPv4: '%s'",
                         f->json_name, item->valuestring);
                rc = CONFIG_REPLY_VALUE_INVALID;
                goto done;
            }
            strcpy(str_val[i], item->valuestring);  /* 长度已校验, 安全 */
        } else {
            if (item->type != cJSON_Number ||
                item->valuedouble != (double)item->valueint ||
                item->valueint < 1 || item->valueint > 65535) {
                log_warn("radius update: field '%s' must be integer 1..65535",
                         f->json_name);
                rc = CONFIG_REPLY_PORT_INVALID;
                goto done;
            }
            port_val[i] = (uint16_t)item->valueint;
        }
    }

    if (!any_present) {
        log_warn("radius update: no recognizable field in request");
        rc = HTTP_REPLY_PARAM_ERROR;
        goto done;
    }

    /* 第三遍: 与当前生效配置比较, 计算需要热更新的字段 */
    for (i = 0; i < RADIUS_FIELD_COUNT; i++) {
        const struct radius_field_tpl* f = &radius_fields[i];
        if (!present[i]) {
            continue;
        }
        if (f->kind == RADIUS_KIND_STRING) {
            const char* cur = (const char*)((const char*)cfg + f->offset);
            if (strcmp(cur, str_val[i]) != 0) {
                hot_changed[i] = 1;
                hot_count++;
            }
        } else {
            const uint16_t* cur =
                (const uint16_t*)((const char*)cfg + f->offset);
            if (*cur != port_val[i]) {
                hot_changed[i] = 1;
                hot_count++;
            }
        }
    }

    if (hot_count > 0) {
        /* 热更新: 备份旧值 -> 写内存 -> init_radius 立即生效; 失败则回退 */
        struct radius_snapshot old_cfg;
        radius_cfg_snapshot(cfg, &old_cfg);

        for (i = 0; i < RADIUS_FIELD_COUNT; i++) {
            const struct radius_field_tpl* f = &radius_fields[i];
            if (!hot_changed[i]) {
                continue;
            }
            if (f->kind == RADIUS_KIND_STRING) {
                char* dst = (char*)cfg + f->offset;
                memset(dst, 0, f->buf_size);
                memcpy(dst, str_val[i], strlen(str_val[i]));
            } else {
                uint16_t* dst = (uint16_t*)((char*)cfg + f->offset);
                *dst = port_val[i];
            }
        }

        if (init_radius(inst) != 0) {
            log_error(
                "RADIUS hot update failed, rollback to previous values: "
                "auth=%s:%u acct=%s:%u",
                old_cfg.auth_server, old_cfg.auth_port, old_cfg.acct_server,
                old_cfg.acct_port);
            restore_cfg_from_snapshot(cfg, &old_cfg);
            if (init_radius(inst) != 0) {
                log_error(
                    "RADIUS rollback re-init failed, radius client may be "
                    "down!");
            }
            rc = CONFIG_REPLY_HOT_UPDATE_FAILED;
            goto done;
        }

        log_info("RADIUS client hot-updated via local config API, %d "
                 "field(s): auth=%s:%u acct=%s:%u",
                 hot_count, cfg->primary_auth_server, cfg->primary_auth_port,
                 cfg->primary_acct_server, cfg->primary_acct_port);
    }

    /* 第四遍: 热更新已成功(或无需热更新), 与 UCI 保存值比对, 不一致才写盘 */
    {
        struct radius_snapshot saved;
        struct config_kv kv[RADIUS_FIELD_COUNT];
        char port_str[RADIUS_FIELD_COUNT][8];
        int n = 0;

        radius_saved_snapshot(&saved);
        memset(kv, 0, sizeof(kv));
        memset(port_str, 0, sizeof(port_str));
        for (i = 0; i < RADIUS_FIELD_COUNT; i++) {
            const struct radius_field_tpl* f = &radius_fields[i];
            int differs;
            if (!present[i]) {
                continue;
            }
            if (f->kind == RADIUS_KIND_STRING) {
                differs = strcmp(snap_string_at(&saved, i), str_val[i]) != 0;
            } else {
                differs = snap_port_at(&saved, i) != (int)port_val[i];
            }
            if (!differs) {
                continue;
            }
            kv[n].key = f->uci_name;
            if (f->kind == RADIUS_KIND_STRING) {
                kv[n].value = str_val[i];
            } else {
                snprintf(port_str[i], sizeof(port_str[i]), "%u",
                         (unsigned)port_val[i]);
                kv[n].value = port_str[i];
            }
            n++;
        }

        if (n > 0) {
            if (set_uci_options(kv, n) != 0) {
                log_error(
                    "Persist to UCI failed after hot update, runtime keeps "
                    "new values, retry the same request to sync UCI");
                rc = CONFIG_REPLY_UCI_WRITE_FAILED;
                goto done;
            }
            uci_written = 1;
            if (cfg->local_radius_client == 0) {
                log_warn("radius_source=cloud, runtime values may be "
                         "overridden by next cloud reply");
            }
        } else if (hot_count == 0) {
            log_info("RADIUS settings update: all provided values identical, "
                     "skip writing");
        }
    }

    /* 成功应答: 热更新/持久化标志 + 运行/保存双视图(密钥掩码) */
    body = cJSON_CreateObject();
    if (!body) {
        rc = HTTP_REPLY_JSON_IS_ERROR;
        goto done;
    }
    cJSON_AddBoolToObject(body, "changed", hot_count > 0);
    cJSON_AddBoolToObject(body, "uci_persisted", uci_written);
    cJSON_AddItemToObject(body, "radius", build_radius_view(inst, 0));
    out = cJSON_Print(body);
    if (!out) {
        rc = HTTP_REPLY_JSON_IS_ERROR;
        goto done;
    }
    send_http_reply(req, HTTP_REPLY_OPERATING_SUCCESS, out);

done:
    if (rc != 0) {
        send_http_reply(req, rc, NULL);
    }
    if (out) {
        free(out);
    }
    if (body) {
        cJSON_Delete(body);
    }
    if (root) {
        cJSON_Delete(root);
    }
    if (raw) {
        free(raw);
    }
}

int start_config_service(struct inst_t* inst, const char* addr,
                         uint16_t port) {
    struct evhttp* http = NULL;
    struct evhttp_bound_socket* bound = NULL;

    http = evhttp_new(inst->base);
    if (!http) {
        log_error("Create local config evhttp failed");
        return -1;
    }

    evhttp_set_cb(http, "/v1/config/get", ws_config_get_v1, (void*)inst);
    evhttp_set_cb(http, "/v1/config/radius/update",
                  ws_config_radius_update_v1, (void*)inst);
    evhttp_set_cb(http, "/v1/control/status",
                  ws_control_status_v1, (void*)inst);
    evhttp_set_timeout(http, 5);

    bound = evhttp_bind_socket_with_handle(http, addr, port);
    if (!bound) {
        log_error("Bind local config HTTP address failed: %s:%u", addr, port);
        evhttp_free(http);
        return -1;
    }

    inst->http_config_server = http;
    log_info("Listen config HTTP Address = %s, port = %u", addr, port);
    return 0;
}
