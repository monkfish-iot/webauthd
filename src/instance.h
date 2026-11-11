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
#ifndef INSTANCE_H
#define INSTANCE_H

#include <inttypes.h>
#include <event.h>
#include <evhttp.h>
//#include <zdb/zdb.h>
//#include <sqlite3.h>
#include <sys/socket.h>
#include <pthread.h>
#include <linux/netlink.h>

#include "session.h"
#include "control_client.h"


#define WEBAUTHD_CONFIG_FILE  "/tmp/webauthd.json"

struct user_address_t {
    uint32_t ip;
    uint8_t mac[6];
    struct inst_t* inst;
    char portal_if[32];
};

#define WHITE_LIST_MAX 128

// 源 IP / 源 MAC 白名单（固定数组实现）
struct white_list_t {
    uint32_t src_ip[WHITE_LIST_MAX];      // 源 IP 白名单（按 inet_aton 得到的原始 32 位值存储）
    int src_ip_count;
    uint8_t src_mac[WHITE_LIST_MAX][6];   // 源 MAC 白名单
    int src_mac_count;
};

struct inst_t {
    struct event_base *base;

    struct event_base *redirect_server_base;
    int redirect_server_tid;
    pthread_t redirect_server_thread;
    char redirect_server[24];
    uint redirect_server_port;
    int inst_status;
    int debug;
    uint32_t dev_session;
    int netlink_fd;
    // int lan_tap_fd;
    //struct event *ev_lan_tap;
    int wan_tap_fd;
    // struct event *ev_wan_tap;
    struct sockaddr_nl nlsaddr;
    struct sockaddr_nl nldaddr;
    // sqlite3 *online_db;
    struct evhttp *http_portal_server;
    struct evhttp *ev_http_portal;
    struct evhttp *http_redirct_url_server;
    struct evhttp *http_config_server;   /* 本地配置接口 127.0.0.1:60000 */
    struct event *ev_netlink;
    //    struct event* ev_radius_auth;
    //    struct event* ev_radius_acct;
    int coa_fd;
    struct event* ev_radius_coa;
    struct event* ev_every_hour_timer;
    struct event* ev_cloud_auth;
    int cloud_auth_fd;

    /* 内置 DNS 劫持服务(capture_dns=1): udp 0.0.0.0:20053 */
    struct evdns_server_port* dns_server_port;
    evutil_socket_t dns_fd;

    // int cfg_acct_interval;
    int online_users;
    // uint32_t unas_ip;
    uint8_t dev_mac[6];
    char dev_ip[24];

 

    char str_portal_ip[32];
    char portal_if[64];
    char called_station_id[128];
    

    struct config_t* config;
    struct white_list_t white_list;
    //struct event* ev_bypass;

    struct sockaddr_in auth_server;
    struct sockaddr_in acct_server;
    //const char* rad_secret;
    // const char* acct_secret;
    // const char* coa_secret;
    // long rad_timeout;


    struct event* scan_sessions_timer;

    struct event* ev_flush_session_timer;
    struct event* ev_nft_audit_timer;       // NFT 规则审计定时器
        int authed_users;
    int total_users;

    uint32_t  session_id;
  
    struct bufferevent *msg_bev;
 
    int msg_reconnect_attempts;
     struct event *msg_timer;

    /* xfrpc_loader 控制面（webauthd-control/v1） */
    struct control_state_t control;


  char* nas_ip;
  char* rad_auth_server;
  char* rad_acct_server;
  char* rad_auth_secret;
  char* rad_acct_secret;

  char* rad_coa_secret;
  uint16_t rad_auth_port;
  uint16_t rad_acct_port;

  char device_id[64];
};


struct inst_t* init_inst();
void destroy_inst();
struct inst_t* get_inst();
int restart_init(struct inst_t* inst);
int start_init(struct inst_t* inst);
//int free_config(struct inst_t* inst);
int init_white_list(struct inst_t* inst);
int check_white_list(struct user_address_t* user_address);
int anydns_server(struct inst_t* inst);
void anydns_stop(struct inst_t* inst);



#endif /* INSTANCE_H */


