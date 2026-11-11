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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <event2/buffer.h>
#include <event2/http.h>

#include "app_events.h"
#include "arp.h"
#include "config.h"
#include "http_auth.h"
#include "http_service.h"
#include "local_auth.h"
#include "log.h"
#include "session.h"
#include "utensils.h"
// #include "database.h"
#include "cJSON.h"
#include "http_client.h"
#include "portal_server.h"
#include "radius.h"





static int hex_value(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/*
 * 对已解析的查询参数做残留 URL 编码兼容。
 * evhttp_parse_query 本身已做一次 %XX 解码; 若上游重复编码(如把
 * EE:94:.. 编成 %25EE%253A 或某些环节再次编码), 值里会残留 %XX,
 * 此处就地再解一层。值中不含 '%' 时原样保留, 因此不会破坏普通值。
 * evhttp 头值是其内部可写副本, 可就地解码。
 */
static void param_decode_residual(struct evkeyvalq *params) {
  struct evkeyval *kv;

  TAILQ_FOREACH (kv, params, next) {
    char *s;
    char *r;
    char *w;
    /* 凭据字段不做二次解码: 密码本身可能含 '%XX' 形态的合法字符,
     * evhttp_parse_query 的标准解码对其已足够, 二次解码会破坏认证 */
    if (kv->key && (strcmp(kv->key, "username") == 0 ||
                    strcmp(kv->key, "userpasswd") == 0)) {
      continue;
    }
    if (!kv->value || strchr(kv->value, '%') == NULL) {
      continue;
    }
    s = kv->value;
    r = s;
    w = s;
    while (*r) {
      /* 只有 '%' 后确实还有两个字符时才解码, 否则把 '%' 当普通字符,
       * 避免 URL 末尾出现残缺百分号时越界读取 r[1]/r[2] */
      if (r[0] == '%' && r[1] != '\0' && r[2] != '\0') {
        int hi = hex_value((unsigned char)r[1]);
        int lo = hex_value((unsigned char)r[2]);
        if (hi >= 0 && lo >= 0) {
          *w++ = (char)((hi << 4) | lo);
          r += 3;
          continue;
        }
      }
      *w++ = *r++;
    }
    *w = '\0';
  }
}

/* 颜色值校验: 仅放行 #rrggbb / #RRGGBB, 非法值返回空串(页面回退内置默认色),
 * 防止 UCI 被篡改后向 login.html 注入任意 CSS/JS */
static const char *portal_color_or_empty(const char *v) {
  size_t i;
  if (!v || strlen(v) != 7 || v[0] != '#') {
    return "";
  }
  for (i = 1; i < 7; i++) {
    char c = v[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return "";
    }
  }
  return v;
}

/* 站内图片路径校验: 仅放行 assets/custom/<字母数字._->, 防路径穿越与属性注入 */
static const char *portal_asset_or_empty(const char *v) {
  const char *p;
  if (!v || strncmp(v, "assets/custom/", 14) != 0) {
    return "";
  }
  p = v + 14;
  if (*p == '\0') {
    return "";
  }
  for (; *p; p++) {
    char c = *p;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
      return "";
    }
  }
  return v;
}

void ws_get_portal_text_v1(struct evhttp_request *req, void *arg) {
  struct inst_t *inst = (struct inst_t *)arg;

  cJSON *root = cJSON_CreateObject();
  if (!root) {
    send_http_reply(req, HTTP_REPLY_JSON_IS_ERROR, NULL);
    return;
  }
  cJSON_AddStringToObject(root, "login_title", inst->config->login_title);
  cJSON_AddStringToObject(root, "login_topic", inst->config->login_topic);
  cJSON_AddStringToObject(root, "login_footer", inst->config->login_footer);
  cJSON_AddStringToObject(root, "success_title", inst->config->success_title);
  cJSON_AddStringToObject(root, "success_topic", inst->config->success_topic);
  cJSON_AddStringToObject(root, "success_footer", inst->config->success_footer);
  cJSON_AddStringToObject(root, "login_bg_color",
                          portal_color_or_empty(inst->config->login_bg_color));
  cJSON_AddStringToObject(root, "login_btn_color",
                          portal_color_or_empty(inst->config->login_btn_color));
  cJSON_AddStringToObject(root, "login_bg_image",
                          portal_asset_or_empty(inst->config->login_bg_image));
  cJSON_AddStringToObject(
      root, "login_logo_image",
      portal_asset_or_empty(inst->config->login_logo_image));
  cJSON_AddStringToObject(root, "success_bg_color",
                          portal_color_or_empty(inst->config->success_bg_color));
  cJSON_AddStringToObject(root, "success_bg_image",
                          portal_asset_or_empty(inst->config->success_bg_image));
  cJSON_AddStringToObject(
      root, "success_banner_image",
      portal_asset_or_empty(inst->config->success_banner_image));
  char *body = cJSON_Print(root);
  //  printf("++++++++++++++++++++++++%s\n",body);
  send_http_reply(req, HTTP_REPLY_OPERATING_SUCCESS, body);

  if (body) {
    free(body);
  }
  /* cJSON_Print 只复制出字符串, JSON 树本身仍需显式释放, 否则每次请求泄漏
   * root 及其全部字符串子节点 */
  cJSON_Delete(root);
}

void ws_http_login_v1(struct evhttp_request *req, void *arg) {
  int code = 0;
  struct evkeyvalq params;
  const char *uri = NULL;
  const char *request_query = NULL;
  char *post_query = NULL;
  const char *username = NULL;
  const char *passwd = NULL;
  const char *portal_ip = NULL;
  const char *userip = NULL;
  const char *org_id = NULL;

  // const char *usersn = NULL;
  const char *usermac = NULL;
  //  const char *ssid = NULL;
  //  const char *devid = NULL;
  struct user_address_t user_address = {0, 0};

  // db_sta_t sta;
  // uint8_t stamac[6] = {0};
  // int ver = 1;
  struct inst_t *inst = (struct inst_t *)arg;
  /*
      struct evbuffer *repBuf = evbuffer_new();
      if (repBuf == NULL) {
          log_error("URI '/v1/login': new reply buffer");
          return;
      }
   */

  TAILQ_INIT(&params);
  do {
    uri = evhttp_request_get_uri(req);
    if (uri == NULL) {
      log_error("URI '/v1/login' : not found URI");
      code = HTTP_REPLY_URI_ERROR;
      break;
    }
    log_debug("URI '/v1/login': %s", uri);

    /* 登录页已改为 POST 提交, 密码不再出现在 URL/访问日志中;
     * 同时保留 GET 查询串解析, 兼容既有外部 Portal 客户端 */
    request_query = uri;
    if (evhttp_request_get_command(req) == EVHTTP_REQ_POST) {
      struct evbuffer *in = evhttp_request_get_input_buffer(req);
      size_t body_len = in ? evbuffer_get_length(in) : 0;
      if (body_len > 8192) {
        log_error("URI '/v1/login': POST body too large (%lu)",
                  (unsigned long)body_len);
        code = HTTP_REPLY_JSON_TOO_LENGHT;
        break;
      }
      if (body_len > 0) {
        post_query = (char *) malloc(body_len + 2);
        if (post_query == NULL) {
          log_error("URI '/v1/login': out of memory for POST body");
          code = HTTP_REPLY_PARAM_ERROR;
          break;
        }
        /* evhttp_parse_query 期望带 '?' 的 URI 形式, 这里补一个前缀 */
        post_query[0] = '?';
        evbuffer_copyout(in, post_query + 1, body_len);
        post_query[body_len + 1] = '\0';
        request_query = post_query;
      }
    }

    if (evhttp_parse_query(request_query, &params) != 0) {
      log_error("URI '/v1/login': parse query string failed");
      code = HTTP_REPLY_PARAM_ERROR;
      break;
    }
    free(post_query);
    post_query = NULL;
    /* 兼容上游重复 URL 编码的参数值 */
    param_decode_residual(&params);
    username = evhttp_find_header(&params, "username");
    if (username == NULL || strlen(username) < 1) {
      log_error("URI '/v1/login': not found parameter 'username'");
      evhttp_clear_headers(&params);
      code = PORTAL_WLANUSERNAME_ERROR;
      break;
    }
    passwd = evhttp_find_header(&params, "userpasswd");
    if (passwd == NULL || strlen(passwd) < 1) {
      log_error("URI '/v1/login': not found parameter 'userpasswd'");
      evhttp_clear_headers(&params);
      code = PORTAL_WLANUSERPASSWD_ERROR;
      break;
    }
    /* 兼容两种字段名: org_id(规范) / orgid(现网 portal 页面实际下发) */
    org_id = evhttp_find_header(&params, "org_id");
    if (org_id == NULL) {
      org_id = evhttp_find_header(&params, "orgid");
    }
  
    portal_ip = evhttp_find_header(&params, inst->config->url_device_ip);
    if (portal_ip == NULL) {
      log_error("URI '/v1/login': not found parameter '%s'",
                (inst->config)->url_device_ip);
      evhttp_clear_headers(&params);
      code = PORTAL_DEVICE_ID_ERROR;
      break;
    }
    userip = evhttp_find_header(&params, inst->config->url_userip);
    if (userip == NULL) {
      log_error("URI '/v1/login': not found parameter '%s'",
                inst->config->url_userip);
      evhttp_clear_headers(&params);
      code = PORTAL_WLANUSERIP_ERROR;
      break;
    }

    usermac = evhttp_find_header(&params, inst->config->url_usermac);
    if (usermac == NULL) {
      log_error("URI '/v1/login': not found parameter '%s'",
                inst->config->url_usermac);
      evhttp_clear_headers(&params);
      code = PORTAL_WLANUSERMAC_ERROR;
      break;
    }

    if (xmac_to_byte(usermac, (int)strlen(usermac), user_address.mac, 6) == -1) {
      log_error("portal station mac error.");
      evhttp_clear_headers(&params);
      code = PORTAL_WLANUSERMAC_ERROR;
      break;
    }
    {
      struct in_addr validated;
      if (inet_pton(AF_INET, userip, &validated) != 1) {
        log_error("portal station IPv4 error: %s", userip);
        evhttp_clear_headers(&params);
        code = PORTAL_WLANUSERIP_ERROR;
        break;
      }
      if (inet_pton(AF_INET, portal_ip, &validated) != 1) {
        log_error("portal device IPv4 error: %s", portal_ip);
        evhttp_clear_headers(&params);
        code = PORTAL_DEVICE_ID_ERROR;
        break;
      }
    }
  } while (0);
  free(post_query);
  post_query = NULL;
  log_debug("http reply=%s (code=%d)", get_http_reply_msg(code), code);
  if (code < 0) {
    evhttp_clear_headers(&params);
    send_http_reply(req, code, NULL);
    return;
  }

  log_info(
      "http_login request: username='%s' userip=%s usermac=%s portal_ip=%s "
      "org_id='%s'",
      username, userip, usermac, portal_ip, org_id ? org_id : "");

  struct in_addr inp;

  if (inet_pton(AF_INET, userip, &inp) != 1) {
    evhttp_clear_headers(&params);
    send_http_reply(req, PORTAL_WLANUSERIP_ERROR, NULL);
    return;
  }
  user_address.ip = inp.s_addr;

  struct user_session_t *user =
      find_user(inst, user_address.ip, user_address.mac);

  if (!user) {
    log_error("portal station not found.ip=%s,mac=%s", userip, usermac);
    evhttp_clear_headers(&params);
    send_http_reply(req, PORTAL_NOT_FOUND_USER, NULL);
    return;
  }

  if (user->status == USER_STATE_AUTHING) {
    log_info("http_login rejected: user is authenticating, user='%s' ip=%s",
             username, userip);
    evhttp_clear_headers(&params);
    send_http_reply(req, PORTAL_USER_AUTHING, NULL);
    return;
  }
  if (user->status == USER_STATE_AUTHED ||
      user->status == USER_STATE_FREE) {
    log_info("http_login rejected: user already authed(status=%d), "
             "user='%s' ip=%s", user->status, username, userip);
    evhttp_clear_headers(&params);
    send_http_reply(req, PORTAL_USER_AUTHED, NULL);
    return;
  }
  if (user->status == USER_STATE_DROPPING) {
    log_info("http_login rejected: user is dropping, user='%s' ip=%s",
             username, userip);
    evhttp_clear_headers(&params);
    send_http_reply(req, PORTAL_USER_DROPPING, NULL);
    return;
  }

  /*
   * org_id 一致性校验: 以配置里的 tenant_org_id 为基准。
   * 登录页下发的 org_id(orgid) 与基准不一致时直接拒绝, 不发送 RADIUS 认证。
   * tenant_org_id 未配置(空)时跳过校验, 保持对旧部署的兼容。
   * 本地 Portal 是单租户场景: 302 URL 不携带 org_id, 登录页也不下发,
   * tenant_org_id 属于云端多租户参数, 本地 Portal 直接跳过校验。
   */
  if (inst->config->portal_type != LOCAL_PORTAL &&
      inst->config->tenant_org_id[0] != '\0') {
    const char *page_org = (org_id && org_id[0]) ? org_id : "";
    if (strcmp(page_org, inst->config->tenant_org_id) != 0) {
      log_error(
          "http_login rejected: org_id '%s' != tenant_org_id '%s', "
          "user='%s' ip=%s",
          page_org, inst->config->tenant_org_id, username, userip);
      evhttp_clear_headers(&params);
      send_http_reply(req, PORTAL_ORG_ID_MISMATCH, NULL);
      return;
    }
  }

  user->login_ver = 1;
  memset(user->user_name, 0, sizeof(user->user_name));
  memset(user->user_password, 0, sizeof(user->user_password));
  snprintf(user->user_name, sizeof(user->user_name), "%s", username);
  snprintf(user->user_password, sizeof(user->user_password), "%s", passwd);
  user->authtype = USER_AUTH_TYPE_PORTAL;
  user->req = req;
  user->status = USER_STATE_AUTHING;
  // user->pushed_portal = 0;
  //  code = process_server_events(EV_AUTH_REQUEST, &user_address, (void*)
  //  user);

  /* 每次登录都先清零, 避免会话复用时残留上次的 org_id;
   * 兼容 org_id / orgid 两种字段名 */
  memset(user->org_id, 0, sizeof(user->org_id));
  if (org_id && org_id[0]) {
    snprintf(user->org_id, sizeof(user->org_id), "%s", org_id);
  }
  {
    struct in_addr portal_addr;
    if (inet_pton(AF_INET, portal_ip, &portal_addr) != 1) {
      user->req = NULL;
      user->status = USER_STATE_INIT;
      send_http_reply(req, PORTAL_DEVICE_ID_ERROR, NULL);
      return;
    }
    user->portal_ip = portal_addr.s_addr;
  }
  /* 参数值已全部复制到会话字段, 及时释放查询表, 避免各异步分支返回时泄漏 */
  evhttp_clear_headers(&params);
  if (inst->config->auth_source == AUTH_SOURCE_LOCAL) {
    /* 本地认证源: 同步完成校验/冲突处理并回复 HTTP, 完全旁路 RADIUS */
    local_portal_login(user);
    return;
  }
  if (inst->config->auth_source == AUTH_SOURCE_HTTP) {
    /* HTTP(S) 认证源: curl multi 异步 POST, 应答回调推进
     * EV_AUTH_ACCEPT/REJECT 后统一回复本请求, 这里保持挂起 */
    http_auth_portal_login(user);
    return;
  }
  if (do_user_auth(user) < 0) {
    return;
  }

  /*
   * RADIUS 已异步发出，这里必须保持 HTTP 请求不立即回复。
   * 最终由 ev_auth_accept/ev_auth_reject/ev_auth_timeout 统一响应。
   */
}

void ws_portal_redirected(struct evhttp_request *req, void *arg) {
  // char* portal_dir[]="/usr/local/webauthd/local_portal/html/";
  struct user_session_t *user = NULL;
  // char portal_url[4096] = {'\0'};
  char real_ip[128];
  unsigned char mac[6] = {0};
  char usermac[32] = {0};
  char devmac[32] = {0};
  int portal_port = 20000;
  char portal_url[2048] = {0};
  char *local_ip = NULL;
  // struct user_address_t user_address;
  uint32_t userip = 0;
  struct user_address_t user_address = {0};
  // memset(&user_address, 0, sizeof(struct user_address_t));
  // struct user_address_t user_address = {0,
  //     {0},
  //     {0}};
  struct inst_t *inst = (struct inst_t *)arg;

  struct evhttp_connection *con = NULL;
  con = evhttp_request_get_connection(req);
  if (con) {
    char *address;
    ev_uint16_t port;
    evhttp_connection_get_peer(con, &address, &port);
    //	printf("address:%s\n",address);
    //	printf("port:%d\n",port);
    memset(real_ip, 0, 128);
    strncpy(real_ip, address, strlen(address));

    if (strncmp(real_ip, "127.0.0.1", 9) == 0) {
      log_debug("The localhost doesn't  push portal!URI=%s",
                evhttp_request_get_uri(req));

      send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
      return;
    }
  }
  userip = inet_addr(real_ip);

  if (get_mac_by_ip(real_ip, mac) < 0) {
    log_error("Can NOT get MAC");
    send_http_reply(req, HTTP_REPLY_USER_NOT_FOUND_USER, NULL);
    return;
  }

  user = find_user(inst, userip, mac);

  if (!user) {
    user_address.ip = userip;
    memcpy(user_address.mac, mac, 6);
    user_address.inst = inst;
    // printf("++++++++++++++++++1\n");
    int rc = process_server_events(EV_NEW_USER, &user_address, &user);
    // if (rc == -1) {
    //   evhttp_cancel_request(req);
    //   return;
    // }
    if (rc == -1) {
      struct evbuffer *hold = evbuffer_new();
      if (hold) {
      evhttp_add_header(evhttp_request_get_output_headers(req),
                      "Connection", "close");
      evhttp_send_reply(req, 204, "No Content", hold);
      evbuffer_free(hold);
    }
  return;
}
    if (rc == -2) {
      send_http_reply(req, HTTP_REPLY_USER_NOTEXIST, NULL);
      return;
    }
    if (!user) {
      log_error("Can NOT create user");
      send_http_reply(req, HTTP_REPLY_USER_NOTEXIST, NULL);
      return;
    }
    // printf("++++++++++++++++++3\n");

  } //
  /*
   * MAC 无感知认证进行中: 不弹 portal 页面, 直接丢弃本次 HTTP 请求,
   * 让客户端自行重试。认证成功时由 nft 规则放行(用户全程无感知);
   * 认证失败/超时后 ev_auth_reject/ev_auth_timeout 会把 authtype 回退为
   * PORTAL, 客户端下一次请求才会真正弹出 portal 页面。
   */
  //if (user->authtype == USER_AUTH_TYPE_MAC &&

  // if(user->status == USER_STATE_AUTHING) {
  //   log_debug("MAC auth in progress, hold HTTP request, ip=%s", real_ip);
  //   evhttp_cancel_request(req);
  //   return;
  // }

  // printf("++++++++++++++++++2\n");
  //   ip.s_addr = user->ip;
  char acip[32] = {0};
  portal_port = 20001;

  struct evkeyvalq *header = evhttp_request_get_output_headers(req);
  struct evbuffer *retbuff = evbuffer_new();
  if (retbuff == NULL) {
    log_error("Failed to create response buffer");
    send_http_reply(req, HTTP_REPLY_PARAM_ERROR, NULL);
    return;
  }

  sprintf(usermac, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0] & 0xFF,
          mac[1] & 0xFF, mac[2] & 0xFF, mac[3] & 0xFF, mac[4] & 0xFF,
          mac[5] & 0xFF);

  snprintf(devmac, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
           (u_int8_t)inst->dev_mac[0], (u_int8_t)inst->dev_mac[1],
           (u_int8_t)inst->dev_mac[2], (u_int8_t)inst->dev_mac[3],
           (u_int8_t)inst->dev_mac[4], (u_int8_t)inst->dev_mac[5]);

  if (strlen(inst->config->nas_ip) < 7) {
    snprintf(acip, 24, "%s", inst->config->portal_ip);
  } else {
    snprintf(acip, 32, "%s", inst->config->nas_ip);
  }

  //   printf("+++++++++++++user->inst->config->nas_ip=%s\n",user->inst->config->nas_ip);
  if (inst->config->nas_ip[0] > 0) {
    strncpy(acip, inst->config->nas_ip, 24);
  } else if (inst->config->nas_if[0] > 0) {
    char *ip = get_if_address(inst->config->nas_if);
    // log_debug("portal interface = %s
    // wlanacip=%s\n",user->inst->config->nas_if,ip);
    if (!ip) {
      //  if (user->pushed_portal == 0) {

      evhttp_send_reply(req, HTTP_NOTFOUND, "Page Not Found", retbuff);
      evhttp_clear_headers(header);
      evbuffer_free(retbuff);
      //}

      return;
    }
    snprintf(acip, 24, "%s", ip);
    free(ip);
  } else {
    snprintf(acip, 24, "%s", inst->config->portal_ip);
  }

  switch (inst->config->portal_type) {
  case LOCAL_PORTAL:
  local_ip = get_if_address("br-lan");
    if (!local_ip) {
      evhttp_send_reply(req, HTTP_NOTFOUND, "Page Not Found", retbuff);
      evhttp_clear_headers(header);
      evbuffer_free(retbuff);
      return;
    }
    snprintf(portal_url, sizeof(portal_url),
             "http://%s:%d/?%s=%s"
             "&%s=%s"
             "&%s=%s"
             "&%s=%s",
             local_ip, portal_port, inst->config->url_userip, real_ip,
             inst->config->url_usermac, usermac, inst->config->url_device_ip,
             acip,
             inst->config->url_device_mac, devmac
    );
    free(local_ip);
    break;
  case CLOUD_PORTAL:
  local_ip = get_if_address("br-lan");
    if (!local_ip) {
      evhttp_send_reply(req, HTTP_NOTFOUND, "Page Not Found", retbuff);
      evhttp_clear_headers(header);
      evbuffer_free(retbuff);
      return;
    }
    snprintf(portal_url, sizeof(portal_url),
             "http://%s:%d/%s/?%s=%s"
             "&%s=%s"
             "&%s=%s"
             "&%s=%s",
             local_ip, portal_port, inst->device_id,inst->config->url_userip, real_ip,
             inst->config->url_usermac, usermac, inst->config->url_device_ip,
             acip,
             inst->config->url_device_mac, devmac
    );
    free(local_ip);
    break;
  case EXTERNAL_PORTAL:
  snprintf(portal_url, sizeof(portal_url),
             "%s/?type=%d&%s=%s"
             "&%s=%s"
             "&%s=%s",
             inst->config->portal_url, inst->config->portal_type,
             inst->config->url_userip, real_ip, inst->config->url_usermac,
             usermac, inst->config->url_device_ip, acip);
    break;

  default:
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type",
                      "text/html;charset=utf-8");
    evhttp_send_reply(req, HTTP_NOTFOUND, "Page Not Found", retbuff);
    evhttp_clear_headers(header);
    evbuffer_free(retbuff);
    return;
  }



  //   struct evkeyvalq *header = evhttp_request_get_output_headers(user->req);
  // if (user->pushed_portal == 0) {
  evhttp_clear_headers(header);

  // header = evhttp_request_get_output_headers(req);
  if (evhttp_add_header(evhttp_request_get_output_headers(req), "Location",
                        portal_url) < 0) {
    send_http_reply(req, HTTP_REPLY_URI_ERROR, NULL);

    evbuffer_free(retbuff);
    //   user->pushed_portal = 1;
    return;
    //  }
  }

  log_debug("Push portal URL %s", portal_url);
  evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type",
                    "text/html;charset=utf-8");
  evhttp_add_header(evhttp_request_get_output_headers(req), "Connection",
                    "close");
  evhttp_send_reply(req, HTTP_MOVETEMP, "Moved Temporarily", retbuff);

  evbuffer_free(retbuff);

  return;
}

static int get_filename(const char *uri, char *filename) {
  int len = strlen(uri);
  int n = 0;

  char *p;
  int i, j;
  if (len < 1) {
    return -1;
  }
  j = 0;
  for (i = 0; i < len; i++) {
    if (uri[i] == '?' || uri[i] == 0) {
      break;
    }
    if (i == 0 && uri[i] == '/') {
      continue;
    }
    filename[j++] = uri[i];
  }
  if (strncmp(filename, "/", strlen(filename)) == 0) {
    strncpy(filename, "login.html", 10);
  }
  // printf("+++++name=%s\n", filename);
  return n;
}

long get_filesize(FILE *stream) {
  long curpos, length;
  curpos = ftell(stream);
  fseek(stream, 0L, SEEK_END);
  length = ftell(stream);
  fseek(stream, curpos, SEEK_SET);
  return length;
}

int start_http_portal_service(struct inst_t *inst, uint32_t port) {
  struct evhttp_bound_socket *bound = NULL;

  if (inst->config->portal_type != LOCAL_PORTAL &&
      inst->config->portal_type != EXTERNAL_PORTAL &&
      inst->config->portal_type != CLOUD_PORTAL) {
    return 0;
  }

  inst->ev_http_portal = evhttp_new(inst->base);
  if (inst->ev_http_portal == NULL) {
    log_error("new libevent http server failed");
    return -1;
  }
  /* RADIUS authentication has a 20s timer; this is only the HTTP safety net. */
  evhttp_set_timeout(inst->ev_http_portal, 25);

  if (inst->config->portal_type == LOCAL_PORTAL) {
    evhttp_set_cb(inst->ev_http_portal, "/v1/get_portal_text",
                  ws_get_portal_text_v1, (void *)inst);
  }
  evhttp_set_cb(inst->ev_http_portal, "/v1/http_login", ws_http_login_v1,
                (void *)inst);
  // evhttp_set_gencb(inst->ev_http_portal, ws_http_portal, (void*) inst);

  bound = evhttp_bind_socket_with_handle(inst->ev_http_portal, "0.0.0.0", port);
  if (bound == NULL) {
    log_error("libevent http  portal_service failed");
    evhttp_free(inst->ev_http_portal);
    return -1;
  }
  log_debug("Listen HTTP Address = 0.0.0.0, port = %u", port);

  return 0;
}
