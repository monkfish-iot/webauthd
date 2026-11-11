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
#ifndef SESSION_H
#define SESSION_H

#include <inttypes.h>
#include <event.h>
#include <evhttp.h>

// #include <zdb/zdb.h>

#include "instance.h"


#define NAME_SIZE  64
#define PASSWD_SIZE  32

#define INST_USER_MAX 256 // 用户会话池大小


// /* 用户没有状态或者不存在*/
// #define     KRN_USER_STATE_NONE                         0 
// /*  刚发现的新用户  */
// #define     KRN_USER_STATE_INIT                         1
// /*   正在认证中的用户  */
// #define     KRN_USER_STATE_AUTHING                      2  
// /*   授权的用户  */
// #define     KRN_USER_STATE_AUTHED                       3    



#define ETH_ALEN 6


/* 用户没有状态或者不存在*/
#define     USER_STATE_NONE                         0 
/*  刚发现的新用户  */
#define     USER_STATE_INIT                         1
/*   正在认证中的用户  */
#define     USER_STATE_AUTHING                      2  
/*   授权的用户  */
#define     USER_STATE_AUTHED                       3    

#define USER_STATE_FREE                             5 // 白名单用户
#define USER_STATE_DROPPING                         6 // 用户正在下线

// 生命周期状态
#define USER_LIFECYCLE_ACTIVE                       0  // 活跃状态
#define USER_LIFECYCLE_CLOSING                      1  // 正在关闭
#define USER_LIFECYCLE_ZOMBIE                       2  // 等待释放

// NFT 规则状态（用于防止 handle 被意外覆盖）
#define NFT_RULES_NONE                              0  // 无 NFT 规则
#define NFT_RULES_ADDING                            1  // 正在添加中
#define NFT_RULES_ACTIVE                            2  // 规则已激活
#define NFT_RULES_DELETING                          3  // 正在删除中

// 魔数用于检测已释放对象
#define USER_MAGIC_VALID                            0x55534552  // "USER"
#define USER_MAGIC_FREED                            0xDEADBEEF

//#define  USER_STATE_WAITTING_REAUTH              9


//#define USER_STATE_INIT         0  // 未认证用户
//#define USER_STATE_AUTHING         1 // 正在认证的用户
//#define USER_STATE_AUTHED           2  // 认证成功的用户
//#define USER_STATE_OUT_ACCOUNT  3  //结账状态
//
//#define USER_STATE_FREE         5 // 白名单用户
//#define USER_STATE_DROPPING         6 // 用户正在下线


#define USER_AUTH_TYPE_MAC   4 // MAC 无感知认证的用户
#define USER_AUTH_TYPE_PORTAL 5  // portal 认证的用户
 


#define DROP_FIRST_POLICY           1
#define DENY_AUTH_POLICY            0


#define  INST_BYPASS                0
#define  INST_MASTER                1
#define  INST_SLAVE                 2


#define USERNAME_SIZE           32

struct user_session_t {
    uint32_t magic;              // 魔数，用于检测对象有效性
    int ref_count;               // 引用计数
    int lifecycle_state;         // 生命周期状态
    
    struct user_session_t* next;
    struct user_session_t* prev; // 链表指针（双向链表）
    struct inst_t* inst;
    uint8_t mac[6];
    uint32_t ip;
    uint32_t sn;
    uint32_t status;
    
    uint32_t authtype;
    uint32_t prt_proto;
    uint32_t in_rate;
    uint32_t out_rate;
    uint32_t in_giga_rate;
    uint32_t out_giga_rate;
    long create_time;
    long session_time;
    long idle_update_time;
    uint32_t authed_type;
    uint32_t session_timeout;
    long idle_timeout;
    long start_time;
    uint32_t quota_bytes;
    uint32_t quota_giga_bytes;
    uint64_t quota_data;
    int reauth_count;
    long last_auth;
    uint64_t last_sum_bytes; 
   uint64_t inbytes;
  //  uint64_t adjust_inbytes;
    uint64_t inpackets;
    uint64_t outbytes;
  //  uint64_t adjust_outbytes;
    uint64_t outpackets;
    uint64_t prev_inbytes;
    uint64_t prev_outbytes;
    /* 本地认证源(local)配额/在线时长持久化记账基准:
     * local_flushed_bytes 为已累计写入用户 JSON 的会话流量字节,
     * local_flush_mark 为上次落盘时刻, 用于在线时长增量计算 */
    uint64_t local_flushed_bytes;
    long local_flush_mark;
    /* 本地认证源: 待落盘的登录统计(last_login_time 的 epoch + login_count),
     * 登录时置位, 随 300s 兜底/下线终算经 local_auth_flush_session 写盘,
     * 避免每次登录立即写 flash */
    int local_pending_login;
    long local_pending_login_epoch;
    uint32_t local_pending_login_count;
    /* 最终落盘失败后保留会话作为可重试记录；数据面可先撤权，周期
     * flush 成功后再释放会话，避免下线时永久漏记。 */
    int local_flush_final_pending;
    uint32_t hours_rule;
    uint32_t weeks_rule;
    uint32_t name_len;
    uint32_t event_timestamp;
    uint32_t acct_interval;
    uint32_t max_parallel;
    uint32_t parallel_policy;
    long acct_start_time;
    struct event* ev_update_accounting;

    struct event* session_timer;
    struct event* ev_idle_timer;
    struct event* unauthed_timer;
    struct event* dropping_timer;
    struct event* ev_nft_revoke_retry;
    int nft_revoke_delete_on_success;
 
    
    uint8_t rad_id;
    //int rad_acct_code;
    struct rad_session_t* rad_session;

    char user_name[64];
    char user_password[64];
    char acct_session_id[128];
    char acct_multi_session_id[128];
    char reply_msg[128];
    char wg_pubkey[128];
    char org_id[128];
    
    int login_ver;
    uint32_t portal_ip;
    char str_portal_ip[32];
    char portal_if[64];
    char called_station_id[128];
    char essid[64];
    
    struct evhttp_request *req;
    
    struct event* ev_waiting_auth_timer;
  //  struct evhttp_request *req2;
    struct evbuffer *repBuf;

    struct event* ev_auth_timer;
    struct event* ev_acct_timer;

    struct event* ev_waitting_acct_response_timer;

    
    struct event* ev_check_data_timer;
     struct event* ev_delay_acct_stop_timer;
    
    int mac_auth_enabled;
    int http_reply_code;
    int send_stop_msg;
    int acct_enable;

    
    int rad_auth_fd;		
    uint32_t acct_status_type ;  //PW_ACCT_STATUS_TYPE
    struct event* ev_rad_auth;
    int rad_acct_fd;	
    struct event* ev_rad_acct;
    uint8_t rad_authenticator[16];
    struct radius_packet_t* rad_pkg;
    struct sockaddr_in* rad_server_addr;
  //int pushed_portal;
    
    /* nft rule handles are JSON integers and may exceed 32 bits. */
    uint64_t nft_src_handle;
    uint64_t nft_dest_handle;
    uint32_t nft_rules_state;       // NFT 规则状态：NONE/ADDING/ACTIVE/DELETING

    /* HTTP(S) 认证源: 在途认证请求上下文(http_auth.c 内部结构),
     * 仅认证请求登记于此(auth_timer 超时/会话释放时取消);
     * 记账请求数据自包含、不引用会话, 不登记 */
    void* http_req;

};







 


 

int init_sessions(struct inst_t* inst);
int destroy_sessions(struct inst_t* inst);
 
struct user_session_t* create_user(struct inst_t* inst, uint32_t userip,uint8_t usermac[]);
struct user_session_t* find_user(struct inst_t* inst, uint32_t userip, uint8_t usermac[]);
int del_user(struct inst_t* inst, struct user_session_t* user);
 

 
int get_all_user(struct user_session_t* table, int page, int page_size);
 

int db_check_sessions(struct inst_t* inst);
int db_stop_sessions(struct inst_t* inst, uint32_t user_ip, int auth_type);

 
 int mac_radius_auth(struct inst_t* inst, struct user_session_t* user) ;

 
 
char* get_status_string(int status);
int restore_user(struct inst_t* inst);
void auth_timeout_cb(const int fd, const short event, void *arg);

int do_user_auth(struct user_session_t* user);

// 引用计数管理函数
struct user_session_t* user_get(struct user_session_t* user);
void user_put(struct user_session_t* user);
int user_is_valid(struct user_session_t* user);
void free_session(void* data);

// 遍历所有会话的辅助函数
void for_each_user_session(void (*callback)(struct user_session_t* user, void* ctx), void* ctx);

// 时钟跳变检测（无 RTC 设备 NTP 校准防护）：由 5s 全局扫描定时器驱动，
// 检测墙钟步进跳变并把所有活跃会话的时间锚点平移对齐
long mono_now(void);
void clock_jump_check(void);

#endif /* SESSION_H */


