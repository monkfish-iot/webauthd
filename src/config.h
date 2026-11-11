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
#ifndef __CONFIG_H
#define __CONFIG_H
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>


#include "instance.h"


#define TYPE_INTEGER                    0
#define TYPE_STRING                 1
#define TYPE_LIST                    2

//#define WEBAUTH_MODE                0
//#define WG_MODE                     1
//#define N2N_MODE                    2



#define CONFIG_GENERIC              1
#define CONFIG_PORTAL               2
#define CONFIG_RADIUS               3
#define CONFIG_HTTP_AUTH            4
#define CONFIG_WHITLIST             5


#define MAX_BUF_SIZE                1024
#define CONF_OFFSET(_t,_s,_f) _t,offsetof(_s,_f),sizeof(((_s*)0)->_f),NULL

/* 认证源(重启生效, 不做热切换):
 * 0=local(本地用户库, 默认), 1=radius(现网行为), 2=http, 3=ldap(占位未实现) */
#define AUTH_SOURCE_LOCAL               0
#define AUTH_SOURCE_RADIUS              1
#define AUTH_SOURCE_HTTP                2
#define AUTH_SOURCE_LDAP                3

struct config_t {
    int enabled;
   // int mode ;
    int auth_source;                /* 认证源, 见 AUTH_SOURCE_* */
    int max_users;                  /* 本地用户库最大用户数, 默认 256 */
    char api_secret[65];            /* UBUS 用户管理共享密钥, 空=不校验 */
    int layer;
    char layer2_ifname[MAX_BUF_SIZE];
    char layer3_ifname[MAX_BUF_SIZE];
    char portal_ip[24];
    int capture_dns;
    int auth_type;
    uint32_t idle_timeout;
    int mac_auth_enabled;
    /* MAC 无感知认证报文中 User-Name/User-Password 的 MAC 字符串格式:
     * 0=小写无分隔符 aabbccddeeff, 1=小写带冒号 aa:bb:cc:dd:ee:ff(默认),
     * 2=大写带冒号 AA:BB:CC:DD:EE:FF, 3=大写无分隔符 AABBCCDDEEFF */
    int mac_auth_format;


    int portal_enabled;

    char login_title[128];
    char login_topic[128];
    char login_footer[128];
    char success_title[128];
    char success_topic[128];
    char success_footer[128];

    /* 内置 Portal 登录页可视化定制（空 = 用内置默认样式）。
     * 颜色仅放行 #rrggbb；图片为站内相对路径 assets/custom/<文件名>，
     * ws_get_portal_text_v1 下发前会再校验一次，非法值按空串处理。 */
    char login_bg_color[16];     /* 登录卡片背景色 */
    char login_btn_color[16];    /* 登录按钮颜色 */
    char login_bg_image[256];    /* 页面背景图 assets/custom/xxx */
    char login_logo_image[256];  /* 登录卡片 logo 图 assets/custom/xxx */

    /* 内置 Portal 成功页可视化定制（空 = 用内置默认样式），校验规则同上 */
    char success_bg_color[16];       /* 成功页主色（标题头条背景） */
    char success_bg_image[256];      /* 成功页背景图 assets/custom/xxx */
    char success_banner_image[256];  /* 成功页横幅大图（替换 images/bg1.jpg） */

    int http_portal_auth;
    int hw_portal_auth;
    int portal_type;
    int cloud_portal;
    char portal_url[1024];
    char portal_server[16];
    int portal_port;

    char failed_title[128];
    char failed_topic[128];





    char url_device_ip[16];
    char url_device_id[128];
    char url_userip[16];
    char url_usermac[32];
    char url_firsturl[128];
    char url_ssid_name[32];
    char url_device_mac[32];
    int url_mac_style;
    char url_extra[128];



    char primary_auth_server[24];
    char primary_auth_secret[32];
     uint16_t primary_auth_port;

    char primary_acct_server[24];
    char primary_acct_secret[32];
    uint16_t primary_acct_port;

    // 0=RADIUS 参数从云端获取, 1=使用本地 UCI 配置
    int local_radius_client;

    /* 租户组织ID(基准值, 最长 64 字符): 与 RADIUS 参数一起持久化到 UCI;
     * 登录页下发的 org_id 必须与其一致, 不一致则拒绝认证;
     * CLOUD_PORTAL 下作为 Filter-Id(属性11) 的值随认证/记账报文下发 */
    char tenant_org_id[65];

    

    char second_auth_server[16];
    char second_auth_secret[32];
    uint16_t second_auth_port;
    char second_acct_server[24];
    char second_acct_secret[32];
    uint16_t second_acct_port;
    

    char nas_ip[32];
    char nas_if[32];
    
    int force_acctstart;
    int coa_port;
    char coa_secret[32];

    int acct_interval;
    int every_hour_acct;

    /* HTTP(S) 认证源配置(auth_source=http 时生效, 重启加载;
     * 对应 UCI webauthd.http_auth.*) */
    char http_auth_url[512];        /* 认证 URL, 必填 */
    char http_acct_url[512];        /* 记账 URL, 空=不记账 */
    char http_shared_secret[65];    /* 共享密钥(sign 用), 空=不带 sign */
    char http_password_type[8];     /* plain | md5 */
    int http_timeout;               /* 单次请求总超时(秒), 默认 5 */
    int http_tls_verify;            /* 0=忽略证书检查, 1=校验证书(默认) */

    // NFT 规则恢复和审计配置
    int nft_recovery_mode;          // 0=禁用, 1=scan, 2=flush
    int nft_audit_interval;         // 审计间隔（秒），0=禁用
    
    char* white_list_src_ip;
    char* white_list_src_mac;
    char* white_list_dest_ip;

};

struct config_tpl_t {
     char   key[256];
    int value_type;
    size_t offset;
    size_t field_size;   /* 目标字段容量(字节), 字符串赋值据此截断防越界写 */
    void *data;
    char default_value[128];
};



int load_all_configs(struct inst_t *inst);


void ws_update_config_v1(struct evhttp_request *req, void *arg);
/* Read one UCI option into a caller-sized buffer.
 * Returns the stored byte count including the trailing NUL, 0 when the
 * option is absent/empty, and -1 on lookup/parse/capacity errors. */
ssize_t get_uci_option(const char *arg, char *buf, size_t buf_size);
 void ws_status(struct evhttp_request *req, void *arg);
int free_config(struct inst_t* inst);
int reload_all_configs(struct inst_t *inst);

/*
 * 本地配置 HTTP 服务(绑定 127.0.0.1:60000):
 *   GET  /v1/config/get?section=radius|generic|portal|all[&show_secret=1]
 *        返回 running(运行参数)/saved(UCI 保存值)/in_sync/diff_fields
 *   POST /v1/config/radius/update   JSON body, 部分更新 RADIUS 对接参数
 */
int  start_config_service(struct inst_t* inst, const char* addr, uint16_t port);
void ws_config_get_v1(struct evhttp_request *req, void *arg);
void ws_config_radius_update_v1(struct evhttp_request *req, void *arg);
#endif /* __CONFIG_H */


