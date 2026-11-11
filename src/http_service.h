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
#ifndef HTTP_SERVICE_H_
#define HTTP_SERVICE_H_

#include <event.h>
#include <evhttp.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>


 
#include "log.h"
 

#include "session.h"



 


#define PORTAL_AUTH_ACCEPT      0

#define PORTAL_NOT_FOUND_USER    -101
#define PORTAL_USER_AUTHED       -102
#define PORTAL_AUTH_TIMEOUT      -103
#define PORTAL_USER_AUTHING      -104
#define PORTAL_USER_DROPPING     -105
#define PORTAL_AUTH_REJECT       -106
#define PORTAL_START_RAD_ERROR   -107
#define PORTAL_SEND_RAD_ERROR    -108


#define PORTAL_WLANUSERIP_ERROR      -109
#define PORTAL_WLANUSERMAC_ERROR      -110
#define PORTAL_WLANAC_ERROR          -111
#define PORTAL_WLANUSERNAME_ERROR      -112
#define PORTAL_WLANUSERPASSWD_ERROR     -113
#define PORTAL_DEVICE_ID_ERROR        -114

#define PORTAL_RADIUS_REJECT        -115
#define PORTAL_UNKOWN_USER_STATUS    -116
/* 登录页下发的 org_id 与配置里的 tenant_org_id 不一致, 拒绝认证 */
#define PORTAL_ORG_ID_MISMATCH       -117

/* 本地认证源(auth_source=local)登录拒绝码, 从 -118 到 -122 */
#define PORTAL_LOCAL_USER_NOT_FOUND  -118
#define PORTAL_LOCAL_USER_DISABLED   -119
#define PORTAL_LOCAL_USER_EXPIRED    -120
#define PORTAL_LOCAL_PASSWD_ERROR    -121
#define PORTAL_LOCAL_MAX_ONLINE      -122

/* HTTP(S) 认证源网络层自产错误码(服务器有应答时透传服务器的 error_code) */
#define PORTAL_HTTP_AUTH_UNREACHABLE  -123
#define PORTAL_HTTP_AUTH_TIMEOUT      -124
#define PORTAL_HTTP_AUTH_BAD_REPLY    -125
/* 凭据正确但数据面授权未建立，不能向用户报告登录成功。 */
#define PORTAL_NFT_APPLY_ERROR        -126
/* 本地账户累计用量（含在线未落盘部分）已达到额度。 */
#define PORTAL_LOCAL_QUOTA_EXHAUSTED  -127



 

//
//
//#define HTTP_ERRCODE_OK  0
//#define HTTP_ERRCODE_PARAM_ERROR  1
//#define HTTP_ERRCODE_URI_ERROR  2
//#define HTTP_ERRCODE_USER_NOTEXIST 3
//#define HTTP_ERRCODE_DORP_ERROR 4




//所有的操作，只要成功都返回  0
#define HTTP_REPLY_OPERATING_SUCCESS            0
//系统级的错误码   从-1  到 -99
#define HTTP_REPLY_JSON_IS_NULL                 -1
#define HTTP_REPLY_JSON_IS_ERROR                -2
#define HTTP_REPLY_JSON_TOO_LENGHT              -3
#define HTTP_REPLY_JSON_FORMAT_ERROR            -4
#define HTTP_REPLY_JSON_QUERY_ERROR             -5
#define HTTP_REPLY_JSON_NOT_FOUND_ID            -6
#define HTTP_REPLY_GET_DB_CONN_FAILED           -7
#define HTTP_REPLY_DB_QUERY_FAILED              -8
#define HTTP_REPLY_DB_RECORD_IS_NULL               -9
#define HTTP_REPLY_SOCKET_ERROR                 -10
#define HTTP_REPLY_STRING_IS_TOO_LONG          -11
#define HTTP_REPLY_STRING_IS_NULL          -12
#define HTTP_REPLY_URI_ERROR                    -13
#define HTTP_REPLY_PARAM_ERROR                  -14
#define HTTP_REPLY_USER_NOTEXIST                -15


//套餐接口返回码  从-100 到  -199
//#define  HTTP_REPLY_PRODUCT_HAS_SOLD            -100
//#define HTTP_REPLY_PRODUCT_IS_DISABLED          -101
//#define HTTP_REPLY_PRODUCT_HAS_EXISTED           -102
//#define HTTP_REPLY_PRODUCT_QUERY_FAILED           -103

//用户接口返回码  从-200  到  -299
#define HTTP_REPLY_USER_NOT_FOUND_PRODUCT      -200
#define HTTP_REPLY_USER_USERNAME_ERROR            -201
#define HTTP_REPLY_USER_PASSWORD_ERROR     -202
#define HTTP_REPLY_USER_CREATE_FAILED           -203
#define HTTP_REPLY_USER_QUERY_FAILED           -204
#define HTTP_REPLY_USER_NOT_FOUND_USER          -205
#define HTTP_REPLY_USER_HAS_ORDERS              -206
#define HTTP_REPLY_USER_IS_DISABLED          -207
#define HTTP_REPLY_USER_HAS_EXISTED            -208
#define HTTP_REPLY_DEBUG_FLAG_ERROR            -209
#define HTTP_REPLY_USER_STATUS_STOP                -210
#define HTTP_REPLY_USER_STATUS_PAUSE               -211
#define HTTP_REPLY_USER_STATUS_NOT_ACTIVE          -212
#define HTTP_REPLY_USER_SECRET_ERROR          -213




//订单接口返回码  从-300   到 -399
#define HTTP_REPLY_ORDER_NOT_FOUND_ORDER          -300
#define HTTP_REPLY_ORDER_NO_PRICE              -301
#define HTTP_REPLY_ORDER_COUNT_OVERLOAD         -302
#define HTTP_REPLY_ORDER_IS_NULL                -303
#define HTTP_REPLY_ORDER_QUERY_FAILED         -304
//系统接口返回码  从  -400  到   -499
#define HTTP_REPLY_TIME_RULE_NAME_IS_NULL                -400
#define HTTP_REPLY_TIME_RULE_NAME_IS_TOO_LONG                -401
#define HTTP_REPLY_TIME_RULE_HOURS_IS_INVALID             -402
#define HTTP_REPLY_TIME_RULE_WEEKS_IS_INVALID           -403
#define HTTP_REPLY_TIME_RULE_HOURS_IS_NULL              -404
 #define HTTP_REPLY_TIME_RULE_WEEKS_IS_NULL              -405
#define HTTP_REPLY_TIME_RULE_IS_USING              -406
#define HTTP_REPLY_USER_NOT_FOUND_TIME_RULE      -407
#define HTTP_REPLY_TIME_RULE_HAS_EXISTED            -508
//时间策略返回码 从-400 到 -499

//策略接口返回码  从 -500 到  -599
#define HTTP_REPLY_BIND_CALLING_STATION_ID_IS_NULL                -500
#define HTTP_REPLY_BIND_USER_ID_IS_NULL                             -501
#define HTTP_REPLY_BIND_DELETE_FAILED                            -502
#define HTTP_REPLY_BIND_FAILED                            -503

//NAS接口返回码 从 -600 到 -699
#define HTTP_REPLY_NAS_NAME_IS_NULL                     -600
#define HTTP_REPLY_NAS_NAME_IS_TOO_LONG                 -601
#define HTTP_REPLY_SHORT_NAME_IS_NULL                   -602
#define HTTP_REPLY_SHORT_NAME_IS_TOO_LONG              -603
#define HTTP_REPLY_DESCRIPTION_IS_TOO_LONG             -605
#define HTTP_REPLY_NAS_HAS_EXISTED                      -606
#define HTTP_REPLY_NOT_FOUND_NAS_ID                     -607
#define HTTP_REPLY_NAS_RATE_IS_TOO_LONG                     -608
#define HTTP_REPLY_NAS_IP_IS_NULL                     -609
#define HTTP_REPLY_INVALID_NAS_IP                     -610

#define HTTP_REPLY_USER_IP_IS_NULL                     -609
#define HTTP_REPLY_INVALID_USER_IP                     -610

#define  HTTP_REPLY_PROXY_REALM_HAS_EXISTED             -700
#define  HTTP_REPLY_PROXY_NO_FOUND_REALM                -701


//session
#define  HTTP_REPLY_NO_FOUND_SESSION                -800
#define  HTTP_REPLY_DROP_USER_FAILED                -801

#define HTTP_LOG_INVALID_OPERATE_TYPE              -900


/* 本地配置接口(127.0.0.1:60000)返回码, 从 -1000 到 -1099 */
#define CONFIG_REPLY_VALUE_INVALID            -1000
#define CONFIG_REPLY_PORT_INVALID             -1001
#define CONFIG_REPLY_VALUE_TOO_LONG           -1002
#define CONFIG_REPLY_BODY_ERROR               -1003
#define CONFIG_REPLY_UCI_WRITE_FAILED         -1004
#define CONFIG_REPLY_UNKNOWN_FIELD            -1005
#define CONFIG_REPLY_HOT_UPDATE_FAILED        -1006





struct http_reply_map_t{
    int  code;
    char msg[256];
};





//extern struct event_base *Http_base;
//extern struct evhttp *G_http_server;



struct portal_auth_reply_code_t{
    int code;
    char msg[256];
};

int start_ws_service(struct inst_t* inst, const char *addr, uint32_t port);
void send_http_reply(struct evhttp_request *req, int code, char* body) ;
/* msg 非空时优先使用(HTTP 认证源透传服务器提示), 否则按 code 查码表 */
void send_http_reply_ex(struct evhttp_request *req, int code, char *body,
                        const char *msg);
/* 管理类接口访问控制: 回环放行; 非回环必须提供正确的 X-Api-Secret。
 * api_secret 为空时仅允许回环访问, 返回 1 表示放行。 */
int http_admin_request_allowed(struct evhttp_request *req,
                               const char *api_secret);

//int start_redirect_server(struct inst_t *inst, const char *addr, uint32_t port);


 
 
char *get_http_reply_msg(int code);




#endif /* HTTP_SERVICE_H_ */

