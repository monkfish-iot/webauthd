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
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <dirent.h>

#include <unistd.h>
#include "http_service.h"
#include "cJSON.h"

#include "portal_server.h"

#include "timer.h"
#include "uci_config.h"
#include "config.h"

#include "session.h"
//#include "database.h"
#include "app_events.h"
#include "radius.h"
#include "ws_users.h"
#include "utensils.h"
#include "log.h"
#include "session.h"

void ws_drop_user_v1(struct evhttp_request *req, void *arg) {

    int errCode = HTTP_REPLY_OPERATING_SUCCESS;
    struct evkeyvalq params;
    struct user_session_t* user;
    const char *uri = NULL;
    const char *usermac = NULL;
    const char *userip = NULL;
    uint8_t mac[6] = {0};
    struct inst_t* inst = (struct inst_t*) arg;
    //struct user_session_t tmp_user[1];
    struct user_address_t user_address;

    if (!http_admin_request_allowed(req, inst->config->api_secret)) {
        log_warn("URI '/v1/drop_user': rejected unauthorized request");
        evhttp_send_reply(req, 403, "Forbidden", NULL);
        return;
    }

    TAILQ_INIT(&params);
    do {
        uri = evhttp_request_get_uri(req);
        if (uri == NULL) {
            log_error("URI '/v1/drop_user' : not found URI");
            errCode = HTTP_REPLY_URI_ERROR;
            break;
        }
        log_debug("URI '/v1/drop_user': %s", uri);

        if (evhttp_parse_query(uri, &params) != 0) {
            log_error("URI '/v1/drop_user': parse query string failed"
                    );
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }
        userip = evhttp_find_header(&params, "userip");
        if (userip == NULL) {
            log_error("URI '/v1/drop_user': not found parameter 'userip'"
                    );
            evhttp_clear_headers(&params);
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }
        // usermac = evhttp_find_header(&params, "usermac");
        // if (usermac == NULL) {
        //     log_error("URI '/v1/drop_user': not found parameter 'usermac'"
        //             );
        //     evhttp_clear_headers(&params);
        //     errCode = HTTP_REPLY_PARAM_ERROR;
        //     break;
        // }


        // if (xmac_to_byte(usermac, 17, mac, 6) == -1) {
        //     log_error("station MAC parameter error: %s", usermac);
        //     errCode = HTTP_REPLY_PARAM_ERROR;
        //     break;
        // }







        user = find_user(inst, inet_addr(userip), mac);

        if (!user) {
            log_error("URI '/v1/drop_user': not found user '%s' from table", userip);
       

            evhttp_clear_headers(&params);
            send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
            return;

        }
        
        // 检查用户有效性（风险：访问可能已释放的user）
        if (!user_is_valid(user)) {
            log_error("URI '/v1/drop_user': user '%s' is invalid", userip);
            evhttp_clear_headers(&params);
            send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
            return;
        }
        
        if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
            log_error("URI '/v1/drop_user': user '%s' is not active (state=%d)", 
                      userip, user->lifecycle_state);
            evhttp_clear_headers(&params);
            send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
            return;
        }




    } while (0);

    if (errCode < 0) {
        evhttp_clear_headers(&params);
        send_http_reply(req, errCode, NULL);
        return;
    }


    log_debug("http request drop user(%s)!", userip);
    evhttp_clear_headers(&params);
     
    user_address.ip = user->ip;
    memcpy(user_address.mac, user->mac, 6);


  //    send_stop_acct( user);
  //    start_waitting_acct_response_timer(user);
    process_server_events(EV_CLOSE_SESSION, &user_address, (void*) user);

    send_http_reply(req, 0, NULL);


    return;




}

void show_user(void* data, void* items) {


    //  struct proc_session_t proc_user;
    const char* userip;

    char str_mac[32] = {0};

    struct in_addr tmp_ip;


    if (!items) {
        return;

    }




    cJSON* array = (cJSON*) items;



    struct user_session_t* session = (struct user_session_t*) data;
    struct inst_t* inst = session->inst;
    
    //printf("++++++++++ww++++++++++ip=%0x\n",session->ip);
    tmp_ip.s_addr = session->ip;


    userip = inet_ntoa(tmp_ip);
    memset(str_mac, 0, 32);



    snprintf(str_mac, 24, "%02x:%02x:%02x:%02x:%02x:%02x", session->mac[0], session->mac[1], session->mac[2],
            session->mac[3], session->mac[4], session->mac[5]);

    cJSON* user = cJSON_CreateObject();

    if (session->status == USER_STATE_AUTHED) {
        inst->authed_users++;
    }
    inst->total_users++;
    if (session->acct_start_time == 0) {
        session->session_time = 0;
    } else {
        session->session_time = get_now_time() - session->acct_start_time;
    }
    cJSON_AddStringToObject(user, "UserName", session->user_name);
    cJSON_AddNumberToObject(user, "Status", session->status);
    cJSON_AddStringToObject(user, "UserIP", userip);
    cJSON_AddStringToObject(user, "UserMAC", str_mac);
    cJSON_AddNumberToObject(user, "SessionTime", session->session_time);
    cJSON_AddNumberToObject(user, "InRate", session->in_rate);
    cJSON_AddNumberToObject(user, "OutRate", session->out_rate);
    cJSON_AddNumberToObject(user, "OutBytes", session->outbytes);
    cJSON_AddNumberToObject(user, "InBytes", session->inbytes);

    cJSON_AddItemToArray(array, user);



}

void ws_show_online_users_v1(struct evhttp_request *req, void *arg) {
    struct inst_t* inst = (struct inst_t*) arg;

    if (!http_admin_request_allowed(req, inst->config->api_secret)) {
        log_warn("URI '/v1/get_online_users': rejected unauthorized request");
        evhttp_send_reply(req, 403, "Forbidden", NULL);
        return;
    }

    cJSON *root = NULL;
    cJSON* array = NULL;

    char* response_data = NULL;


    root = cJSON_CreateObject();
    if (!root) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }

    array = cJSON_CreateArray();
    if (!array) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }

    inst->total_users=0;
    inst->authed_users=0;

    // 回调函数，用于遍历会话填充数组
    void collect_user(struct user_session_t* session, void* ctx) {
        (void)ctx;
        char str_mac[18] = {0};
        char userip[32] = {0};

        snprintf(str_mac, sizeof(str_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 session->mac[0], session->mac[1], session->mac[2],
                 session->mac[3], session->mac[4], session->mac[5]);
        struct in_addr addr;
        addr.s_addr = session->ip;
        strncpy(userip, inet_ntoa(addr), sizeof(userip) - 1);

        inst->total_users++;
        if (session->status == USER_STATE_AUTHED) {
            inst->authed_users++;
        }

        cJSON* user = cJSON_CreateObject();
        char* name = session->user_name;
        cJSON_AddStringToObject(user, "UserID", name ? name : "unknown");
        cJSON_AddNumberToObject(user, "Status", session->status);
        cJSON_AddStringToObject(user, "UserIP", userip);
        cJSON_AddStringToObject(user, "UserMAC", str_mac);
        cJSON_AddNumberToObject(user, "SessionTime", session->session_time);
        cJSON_AddNumberToObject(user, "InRate", session->in_rate);
        cJSON_AddNumberToObject(user, "OutRate", session->out_rate);
        cJSON_AddNumberToObject(user, "OutBytes", session->outbytes);
        cJSON_AddNumberToObject(user, "InBytes", session->inbytes);
        cJSON_AddItemToArray(array, user);
    }

    for_each_user_session(collect_user, NULL);

    cJSON_AddNumberToObject(root, "total_users", inst->total_users);
    cJSON_AddNumberToObject(root, "authed_users", inst->authed_users);
    cJSON_AddItemToObject(root, "users", array);



    response_data = cJSON_Print(root);


    if (response_data) {
        send_http_reply(req, HTTP_REPLY_OPERATING_SUCCESS, response_data);

        free(response_data);

    } else {
        send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
    }
    if (root) {
        cJSON_Delete(root);
    }


    return;



}

/*
 * 获取所有的在线用户
 */

void ws_get_user_by_name_v1(struct evhttp_request *req, void *arg) {
    int errCode = HTTP_REPLY_OPERATING_SUCCESS;
    struct evkeyvalq params;
    //db_sta_t sta;
    const char *uri = NULL;
    // const char *usermac = NULL;
    const char *username = NULL;
    uint8_t mac[6] = {0};
    struct inst_t* inst = (struct inst_t*) arg;
    struct evbuffer *repBuf = evbuffer_new();
    struct user_session_t* user = NULL;
    struct user_session_t* p = NULL;

    if (!http_admin_request_allowed(req, inst->config->api_secret)) {
        log_warn("URI 'show_user_by_name': rejected unauthorized request");
        if (repBuf) {
            evbuffer_free(repBuf);
        }
        evhttp_send_reply(req, 403, "Forbidden", NULL);
        return;
    }

    if (repBuf == NULL) {
        log_error("URI 'v': new reply buffer");
        return;
    }
    TAILQ_INIT(&params);
    // printf("+++++++++++++\n");
    do {
        uri = evhttp_request_get_uri(req);
        if (uri == NULL) {
            log_error("URI 'show_user_by_name' : not found URI");
            errCode = HTTP_REPLY_URI_ERROR;
            break;
        }
        log_debug("URI 'show_user_by_name': %s", uri);

        if (evhttp_parse_query(uri, &params) != 0) {
            log_error("URI 'show_user_by_name': parse query string failed"
                    );
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }
        username = evhttp_find_header(&params, "username");
        if (username == NULL) {
            log_error("URI 'show_user_by_name': not found parameter 'username'"
                    );
            evhttp_clear_headers(&params);
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }
        /*
                usermac = evhttp_find_header(&params, "usermac");
                if (usermac == NULL) {
                    log_error("URI '%s': not found parameter 'usermac'",
                            HTTP_WEB_MGR_SET_ONLINE_USER_DROP);
                    evhttp_clear_headers(&params);
                    errCode = HTTP_ERRCODE_PARAM_ERROR;
                    break;
                }
         */

    } while (0);

    if (errCode < 0) {
        evbuffer_add_printf(repBuf, "{\"code\":%d}", -1);
        evhttp_send_reply(req, HTTP_OK, "OK", repBuf);
        evhttp_clear_headers(&params);
        evbuffer_free(repBuf);
        return;
    }


    /*
        if (db_get_user_by_name(inst, &user, username) < 0) {
            evbuffer_add_printf(repBuf, "{\"code\":%d}", -1);
            evhttp_send_reply(req, HTTP_OK, "OK", repBuf);
            evhttp_clear_headers(&params);
            evbuffer_free(repBuf);
            return;
        }
     */



    cJSON* root = cJSON_CreateArray();
    if (!root) {
        evbuffer_add_printf(repBuf, "{\"code\":%d}", -1);
        evhttp_send_reply(req, HTTP_OK, "OK", repBuf);
        evhttp_clear_headers(&params);
        evbuffer_free(repBuf);
        return;
    }




    char strmac[24] = {0};
    struct in_addr in;
    p = user;
    while (user) {

        cJSON* body = cJSON_CreateObject();
        if (!body) {
            evbuffer_add_printf(repBuf, "{\"code\":%d}", -1);
            evhttp_send_reply(req, HTTP_OK, "OK", repBuf);
            evhttp_clear_headers(&params);
            evbuffer_free(repBuf);
            if (root) {
                cJSON_Delete(root);
            }
            return;
        }
        if (user->acct_start_time == 0) {
            user->session_time = 0;
        } else {
            user->session_time = get_now_time() - user->acct_start_time;
        }
        in.s_addr = user->ip;
        memset(strmac, 0, 24);
        snprintf(strmac, 24, "%02X:%02X:%02X:%02X:%02X:%02X",
                user->mac[5], user->mac[4], user->mac[3], user->mac[2], user->mac[1], user->mac[0]);
        cJSON_AddStringToObject(body, "UserName", user->user_name);

        cJSON_AddStringToObject(body, "UserIP", inet_ntoa(in));
        cJSON_AddStringToObject(body, "UserMAC", strmac);

        cJSON_AddNumberToObject(body, "SessionTime", user->session_time);
        cJSON_AddNumberToObject(body, "InByte", user->inbytes);
        cJSON_AddNumberToObject(body, "OutByte", user->outbytes);
        cJSON_AddNumberToObject(body, "InSpeed", user->in_rate);
        cJSON_AddNumberToObject(body, "OutSpeed", user->out_rate);

        cJSON_AddItemToArray(root, body);
        user = user->next;
    }
    //    cJSON_AddItemToObject(root, "body", body);
    char* str_json = cJSON_Print(root);
    log_debug("\n%s\n", str_json);

    evbuffer_add_printf(repBuf, "{\"code\":0,\"body\":%s}\n", str_json);
    evhttp_send_reply(req, HTTP_OK, "OK", repBuf);
    evhttp_clear_headers(&params);
    evbuffer_free(repBuf);

    cJSON_Delete(root);
    free(str_json);
    user = p;
    while (user) {
        log_debug("free %s\n", p->user_name);
        p = user->next;

        free(user);
        user = p;
    }
    return;

}

void ws_get_user_by_ip_v1(struct evhttp_request *req, void *arg) {
    int errCode = HTTP_REPLY_OPERATING_SUCCESS;
    struct evkeyvalq params;
    //db_sta_t sta;
    const char *uri = NULL;
    // const char *usermac = NULL;
    const char *userip = NULL;
    char userip_copy[64] = {0};
    uint8_t mac[6] = {0};
    struct inst_t* inst = (struct inst_t*) arg;

    if (!http_admin_request_allowed(req, inst->config->api_secret)) {
        log_warn("URI 'show_user_by_ip': rejected unauthorized request");
        evhttp_send_reply(req, 403, "Forbidden", NULL);
        return;
    }

    // printf("+++++++++++++\n");
    TAILQ_INIT(&params);
    do {
        uri = evhttp_request_get_uri(req);
        if (uri == NULL) {
            log_error("URI 'show_user_by_ip' : not found URI");
            errCode = HTTP_REPLY_URI_ERROR;
            break;
        }
        log_debug("URI 'show_user_by_ip': %s", uri);

        if (evhttp_parse_query(uri, &params) != 0) {
            log_error("URI 'show_user_by_ip': parse query string failed"
                    );
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }
        userip = evhttp_find_header(&params, "userip");
        if (userip == NULL) {
            log_error("URI 'show_user_by_ip': not found parameter 'userip'"
                    );
            evhttp_clear_headers(&params);
            errCode = HTTP_REPLY_PARAM_ERROR;
            break;
        }


    } while (0);

    if (errCode < 0) {
        evhttp_clear_headers(&params);
        send_http_reply(req, errCode, NULL);
        return;
    }
    struct in_addr inp;

    /* userip 指向参数表内部内存, 先把值复制出来再释放参数表 */
    snprintf(userip_copy, sizeof(userip_copy), "%s", userip);
    evhttp_clear_headers(&params);
    userip = userip_copy;

    inet_aton(userip, &inp);
    //  uint32_t ip = inp.s_addr;


    struct user_session_t* user = find_user(inst, inp.s_addr, mac);

    if (!user) {
        send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
        return;
    }
    
    // 检查用户有效性
    if (!user_is_valid(user)) {
        log_error("ws_get_user_by_ip: user is invalid");
        send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
        return;
    }
    
    if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
        log_debug("ws_get_user_by_ip: user is not active (state=%d)", user->lifecycle_state);
        send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
        return;
    }

    // print_user_info(&user);

    cJSON* body = cJSON_CreateObject();
    if (!body) {
        send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
        return;
    }


    char strmac[24] = {0};
    snprintf(strmac, 24, "%02X:%02X:%02X:%02X:%02X:%02X",
            user->mac[0], user->mac[1], user->mac[2], user->mac[3], user->mac[4], user->mac[5]);



    cJSON_AddStringToObject(body, "UserName", user->user_name);
    cJSON_AddStringToObject(body, "UserIP", userip);
    cJSON_AddStringToObject(body, "UserMAC", strmac);
    cJSON_AddNumberToObject(body, "Status", user->status);

    cJSON_AddNumberToObject(body, "SessionTime", user->session_time);

    cJSON_AddNumberToObject(body, "InByte", user->inbytes);
    cJSON_AddNumberToObject(body, "OutByte", user->outbytes);
    cJSON_AddNumberToObject(body, "InSpeed", user->in_rate);

    // cJSON_AddItemToObject(root, "body", body);
    char* str_json = cJSON_Print(body);
    //  printf("1++++++++++++++++\n");
    if (str_json) {
        //   printf("2++++++++++++++++%s\n",str_json);
        send_http_reply(req, 0, str_json);
        //  printf("3++++++++++++++++\n");
        free(str_json);
        //   printf("4++++++++++++++++\n");
        cJSON_Delete(body);
        // printf("5++++++++++++++++\n");
        return;
    }

    if (body) {
        cJSON_Delete(body);
    }
    //  printf("++++++++++++++++\n");
    return;

}

void print_user_info(struct user_session_t* user) {
    struct in_addr in;
    in.s_addr = user->ip;
    uint64_t quota_data = user->quota_giga_bytes;
    quota_data = quota_data << 32 | user->quota_bytes;
    char strmac[24] = {0};
    snprintf(strmac, 24, "%02X:%02X:%02X:%02X:%02X:%02X", user->mac[5], user->mac[4], user->mac[3], user->mac[2], user->mac[1], user->mac[0]);
   
    log_debug("User %s Request Accept! User IP=%s; User Mac=%s;  Status=%d;"
            " Session Timeout=%u;  Session Timeout=%u;  "
            " quota_data=%"PRIu64"; "
            " in_rate=%u,out_rate=%u",
            user->user_name, inet_ntoa(in), strmac,user->status,    
            user->session_timeout, user->session_timeout,
            quota_data,
            user->in_rate, user->out_rate);
 
}
