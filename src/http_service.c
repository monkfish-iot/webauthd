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
#include <stdlib.h>

#include <string.h>
#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include "http_service.h"
#include "http_service.h"
#include "portal_server.h"

#include "portal_server.h"
#include <sys/socket.h>
#include "ws_users.h"
#include "cJSON.h"
#include "session.h"

// #include "nsap_devid.h"
#include "config.h"

struct http_reply_map_t http_reply_map[] = {
    {HTTP_REPLY_OPERATING_SUCCESS, "Operating success!"},
    {HTTP_REPLY_JSON_IS_NULL, "JSON is NULL!"},
    {HTTP_REPLY_JSON_IS_ERROR, "JSON is error!"},
    {HTTP_REPLY_JSON_TOO_LENGHT, "JSON is too length!"},
    {HTTP_REPLY_JSON_FORMAT_ERROR, "JSON format is error!"},
    {HTTP_REPLY_JSON_QUERY_ERROR, "Query is invalid!"},
    {HTTP_REPLY_JSON_NOT_FOUND_ID, "Not found ID!"},
    {HTTP_REPLY_GET_DB_CONN_FAILED, "Get database connection failed!"},
    {HTTP_REPLY_DB_QUERY_FAILED, "Database query failed!"},
    {HTTP_REPLY_DB_RECORD_IS_NULL, "Record is null!"},
    {HTTP_REPLY_SOCKET_ERROR, "Socket Error!"},
    {HTTP_REPLY_STRING_IS_TOO_LONG, "String is too long"},
    {HTTP_REPLY_STRING_IS_NULL, "String is NULL"},
    {HTTP_REPLY_URI_ERROR, "URL is error!"},
    {HTTP_REPLY_PARAM_ERROR, "The param is error!"},
    {PORTAL_AUTH_ACCEPT, "Request accept!"},
    {PORTAL_NOT_FOUND_USER, "Not found user!"},
    {PORTAL_USER_AUTHED, "User has authorized!"},
    {PORTAL_AUTH_TIMEOUT, "AAA Timeout!"},
    {PORTAL_USER_AUTHING, "User is authorizing!"},
    {PORTAL_USER_DROPPING, "User is dropping!"},
    {PORTAL_AUTH_REJECT, "AAA Request reject!"},
    {PORTAL_START_RAD_ERROR, "Start AAA request failed!"},
    {PORTAL_SEND_RAD_ERROR, "Send AAA request failed!"},
    {PORTAL_WLANUSERIP_ERROR, "wlanuserip error!"},
    {PORTAL_WLANUSERMAC_ERROR, "wlanusermac error!"},
    {PORTAL_WLANAC_ERROR, "wlanacip or wlanacname error!"},
    {PORTAL_WLANUSERNAME_ERROR, "wlanusername error!"},
    {PORTAL_WLANUSERPASSWD_ERROR, "wlanuserpasswd error!"},
    {PORTAL_DEVICE_ID_ERROR, "deviceid error!"},
    {PORTAL_RADIUS_REJECT, "AAA Request reject!"},
    {PORTAL_ORG_ID_MISMATCH, "org_id mismatch with tenant_org_id!"},
    {PORTAL_LOCAL_USER_NOT_FOUND, "Local user not found!"},
    {PORTAL_LOCAL_USER_DISABLED, "Local user is disabled!"},
    {PORTAL_LOCAL_USER_EXPIRED, "Local user is expired!"},
    {PORTAL_LOCAL_PASSWD_ERROR, "Local user password error!"},
    {PORTAL_LOCAL_MAX_ONLINE, "Local user max_online reached!"},
    {PORTAL_HTTP_AUTH_UNREACHABLE, "HTTP auth server unreachable!"},
    {PORTAL_HTTP_AUTH_TIMEOUT, "HTTP auth request timeout!"},
    {PORTAL_HTTP_AUTH_BAD_REPLY, "HTTP auth reply format error!"},
    {PORTAL_NFT_APPLY_ERROR, "Network access rule activation failed!"},
    {PORTAL_LOCAL_QUOTA_EXHAUSTED, "Local user data quota exhausted!"},

  

    {HTTP_REPLY_USER_NOT_FOUND_PRODUCT, "Not found product!"},
    {HTTP_REPLY_USER_USERNAME_ERROR, "Username is invalid!"},
    {HTTP_REPLY_USER_PASSWORD_ERROR, "User Passwrod is invalid!"},
    {HTTP_REPLY_USER_CREATE_FAILED, "Create user is failed!"},
    {HTTP_REPLY_USER_NOT_FOUND_USER, "Not found user!"},
    {HTTP_REPLY_USER_HAS_ORDERS, "User has order.Can not close!"},
    {HTTP_REPLY_USER_HAS_EXISTED, "User has existed!"},
    {HTTP_REPLY_USER_SECRET_ERROR, "Secret is error!"},
    {HTTP_REPLY_DEBUG_FLAG_ERROR, "Debug flag error!"},
    {HTTP_REPLY_USER_STATUS_STOP, "User status is STOP!"},
    {HTTP_REPLY_USER_STATUS_PAUSE, "User status is PAUSE!"},
    {HTTP_REPLY_USER_STATUS_NOT_ACTIVE, "User status is NOT ACTIVE!"},
    {HTTP_REPLY_ORDER_NOT_FOUND_ORDER, "Not found order!"},
    {HTTP_REPLY_ORDER_COUNT_OVERLOAD, "The record of refund is too many!"},
    {HTTP_REPLY_ORDER_IS_NULL, "The order is null!"},
    {HTTP_REPLY_ORDER_NO_PRICE, "No price!"},
    {HTTP_REPLY_ORDER_QUERY_FAILED, "The order query failed!"},
    {HTTP_REPLY_TIME_RULE_NAME_IS_NULL, "Time rule's name is NULL!"},
    {HTTP_REPLY_TIME_RULE_NAME_IS_TOO_LONG, "Time rule's name is too long(<255)!"},
    {HTTP_REPLY_TIME_RULE_HOURS_IS_INVALID, "Time rule's hours is invalid!"},
    {HTTP_REPLY_TIME_RULE_WEEKS_IS_INVALID, "Time rule's weeks is invalid!"},
    {HTTP_REPLY_TIME_RULE_HOURS_IS_NULL, "Time rule's hours is NULL!"},
    {HTTP_REPLY_TIME_RULE_WEEKS_IS_NULL, "Time rule's weeks is NULL!"},
    {HTTP_REPLY_TIME_RULE_IS_USING, "Time rule is using!"},
    {HTTP_REPLY_USER_NOT_FOUND_TIME_RULE, "Not found time rule!"},
    {HTTP_REPLY_USER_IS_DISABLED, "User is disabled!"},
    {HTTP_REPLY_TIME_RULE_HAS_EXISTED, "Time rule has existed!"},
    {HTTP_REPLY_BIND_CALLING_STATION_ID_IS_NULL, "Calling Station ID is NULL"},
    {HTTP_REPLY_BIND_USER_ID_IS_NULL, "User ID is NULL!"},
    {HTTP_REPLY_BIND_DELETE_FAILED, "Bind calling station id delete failed!"},
    {HTTP_REPLY_BIND_FAILED, "Create bind failed!"},
    {HTTP_REPLY_NAS_NAME_IS_NULL, "NAS Name is NULL!"},
    {HTTP_REPLY_NAS_NAME_IS_TOO_LONG, "NAS Name is too long(<128)"},
    {HTTP_REPLY_SHORT_NAME_IS_NULL, "Short name is null!"},
    {HTTP_REPLY_SHORT_NAME_IS_TOO_LONG, "Short name is too long(<32)"},
    {HTTP_REPLY_NAS_IP_IS_NULL, "Nas's ip is null"},
    {HTTP_REPLY_INVALID_NAS_IP, "Invalid nas's ip"},
    {HTTP_REPLY_USER_IP_IS_NULL, "User's ip is null"},
    {HTTP_REPLY_INVALID_USER_IP, "Invalid user's ip"},
    {HTTP_REPLY_DESCRIPTION_IS_TOO_LONG, "The description is too long(<256)"},
    {HTTP_REPLY_NAS_HAS_EXISTED, "NAS has existed!"},
    {HTTP_REPLY_NOT_FOUND_NAS_ID, "Not found NAS"},
    {HTTP_REPLY_NAS_RATE_IS_TOO_LONG, "Rate is too long!"},
    {HTTP_REPLY_PROXY_REALM_HAS_EXISTED, "The realm has existed!"},
    {HTTP_REPLY_PROXY_NO_FOUND_REALM, "No found realm!"},
    {HTTP_REPLY_NO_FOUND_SESSION, "Not found session!"},
    {HTTP_REPLY_DROP_USER_FAILED, "Drop user failed!"},

    /* 本地配置接口(127.0.0.1:60000) */
    {CONFIG_REPLY_VALUE_INVALID, "Config value is invalid!"},
    {CONFIG_REPLY_PORT_INVALID, "Port must be an integer between 1 and 65535!"},
    {CONFIG_REPLY_VALUE_TOO_LONG, "Config string value is too long!"},
    {CONFIG_REPLY_BODY_ERROR, "Request body is empty or not a valid JSON object!"},
    {CONFIG_REPLY_UCI_WRITE_FAILED, "Persist config to UCI failed!"},
    {CONFIG_REPLY_UNKNOWN_FIELD, "Unknown config field!"},
    {CONFIG_REPLY_HOT_UPDATE_FAILED, "RADIUS hot update failed, rolled back!"},
    {0, "\0"},

};

char *get_http_reply_msg(int code) {
    size_t len = 0;
    int i = 0;
    len = sizeof (http_reply_map) / sizeof (struct http_reply_map_t);
    for (i = 0; i < len; i++) {

        if (http_reply_map[i].code == code) {
            return http_reply_map[i].msg;
        }
    }
    return NULL;
}

void http_update_config(struct evhttp_request *req, void *arg);
// extern struct event_base *base;

void* redirect_thread(void* arg) {
    struct inst_t *inst = (struct inst_t*) arg;

     inst->redirect_server_base=event_base_new();
   if(!inst->redirect_server_base){
       log_error("webauthd redirect base initialized failed.");
        return NULL;
       
   }
     
  //  struct evhttp_bound_socket *bound = NULL;

    inst->http_redirct_url_server = evhttp_new(inst->redirect_server_base);
    if (inst->http_redirct_url_server == NULL) {
        log_error("new libevent http server failed");
        return NULL;
    }
    evhttp_set_timeout(inst->http_redirct_url_server, 10);


    if (inst->config->enabled == 1) {
        evhttp_set_gencb(inst->http_redirct_url_server, ws_portal_redirected, (void *) inst);
         evhttp_set_timeout(inst->http_redirct_url_server, 5);
    }

  
    
       if (evhttp_bind_socket(inst->http_redirct_url_server, inst->redirect_server, inst->redirect_server_port) != 0) {
        fprintf(stderr, "Could not bind to port 8080!\n");
        return NULL;
    }
    
    
    log_debug("Listen Redirect Server Address = %s, port = %u", inst->redirect_server, inst->redirect_server_port);


    printf("Thread %d is running\n", inst->redirect_server_tid);
    
    
    event_base_dispatch(inst->redirect_server_base);
    return NULL;
}



int start_ws_service(struct inst_t *inst, const char *addr, uint32_t port) {

    struct evhttp_bound_socket *bound = NULL;

    inst->http_portal_server = evhttp_new(inst->base);
    if (inst->http_portal_server == NULL) {
        log_error("new libevent http server failed");
        return -1;
    }
   
    if (inst->config->enabled == 1) {
        // if (inst->config->mode = WEBAUTH_MODE) {
        /*
                    if (inst->config->http_portal_auth > 0) {
                        evhttp_set_cb(inst->http_portal_server, "/v1/http_login", ws_http_login_v1, (void*) inst);
                    }
         */

        evhttp_set_cb(inst->http_portal_server, "/v1/get_user_by_ip",
                ws_get_user_by_ip_v1, (void *) inst);
        evhttp_set_cb(inst->http_portal_server, "/v1/get_user_by_name",
                ws_get_user_by_name_v1, (void *) inst);

        evhttp_set_cb(inst->http_portal_server, "/v1/get_online_users",  ws_show_online_users_v1, (void *) inst);

        /*
                    if (inst->config->portal_type == LOCAL_PORTAL) {
                        evhttp_set_cb(inst->http_portal_server, "/v1/get_portal_text",
                                ws_get_portal_text_v1, (void*) inst);
                    }
         */

        //  }

        /*
                 if (inst->config->mode = WG_MODE) {
                     evhttp_set_cb(inst->http_portal_server, "/v1/wg_login", ws_wg_login_v1, (void*) inst);

                 }
         */
        /* 用户下线  */
        evhttp_set_cb(inst->http_portal_server, "/v1/drop_user",
                ws_drop_user_v1, (void *) inst);

      evhttp_set_gencb(inst->http_portal_server, ws_portal_redirected, (void *) inst);
    }

    /*更新配置*/
    evhttp_set_cb(inst->http_portal_server, "/v1/update_config",  ws_update_config_v1, (void *) inst);


    evhttp_set_cb(inst->http_portal_server, "/v1/status",  ws_status, (void *) inst);

    evhttp_set_timeout(inst->http_portal_server, 5);
    bound = evhttp_bind_socket_with_handle(inst->http_portal_server, addr, port);
    if (bound == NULL) {
        log_error("libevent http bind socket failed");
        evhttp_free(inst->http_portal_server);
        return -1;
    }
    log_debug("Listen HTTP Address = %s, port = %u", addr, port);

 
    
    return 0;
}

void send_http_reply(struct evhttp_request *req, int code, char *body) {
    send_http_reply_ex(req, code, body, NULL);
}

int http_admin_request_allowed(struct evhttp_request *req,
                               const char *api_secret) {
    const char *peer;
    const char *hdr;
    size_t i;
    size_t secret_len;

    if (!req) {
        return 0;
    }
    peer = req->remote_host;
    if (peer && (strcmp(peer, "127.0.0.1") == 0 ||
                 strcmp(peer, "::1") == 0 ||
                 strcmp(peer, "localhost") == 0)) {
        return 1;
    }
    /* 未配置共享密钥时, 管理接口只允许本机访问 */
    if (!api_secret || api_secret[0] == '\0') {
        return 0;
    }
    hdr = evhttp_find_header(evhttp_request_get_input_headers(req),
                             "X-Api-Secret");
    secret_len = strlen(api_secret);
    if (!hdr || hdr[0] == '\0' || strlen(hdr) != secret_len) {
        return 0;
    }
    /* 定长比较, 降低时序侧信道 */
    for (i = 0; i < secret_len; i++) {
        if (hdr[i] != api_secret[i]) {
            return 0;
        }
    }
    return 1;
}

void send_http_reply_ex(struct evhttp_request *req, int code, char *body,
                        const char *msg) {
    struct evbuffer *retbuff = evbuffer_new();
    char buf[2048];

    if (retbuff == NULL) {
        log_error("line:%d,%s\n", __LINE__, "retbuff is null.");
        return;
    }
    memset(buf, 0, 2048);
    // generate_reply_json(code, buf, body);
    cJSON *root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error_code", code);
    /* 自定义 msg(HTTP 认证源透传服务器提示)优先, 否则按码表取 */
    const char *p = (msg && msg[0]) ? msg : get_http_reply_msg(code);
    if (!p) {
        code = HTTP_REPLY_JSON_IS_ERROR;
    } else {
        cJSON_AddStringToObject(root, "msg", p);
    }
    if (body) {
        cJSON *item = cJSON_Parse(body);
        if (item) {
            cJSON_AddItemToObject(root, "body", item);
        }
    }
    char *response_data = cJSON_Print(root);

    if (response_data == NULL) {
        log_error("send_http_reply_ex: serialize response failed");
        evbuffer_free(retbuff);
        cJSON_Delete(root);
        evhttp_send_reply(req, 500, "Internal Server Error", NULL);
        return;
    }
    /* response_data 是已序列化的 JSON, 可能包含用户可控的 '%' 等字符,
     * 不能作为 printf 格式串; 按字节追加 */
    evbuffer_add(retbuff, response_data, strlen(response_data));
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/html;charset=utf-8");
    evhttp_send_reply(req, HTTP_OK, "Client", retbuff);
    evbuffer_free(retbuff);
    free(response_data);

    cJSON_Delete(root);
}
