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
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <unistd.h>


#include <event2/event-config.h>
#include <arpa/inet.h>
#include <sys/types.h>

#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif


#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define u32 ev_uint32_t
#define u8 ev_uint8_t


#include "log.h"

#include "instance.h"
#include "portal_server.h"

#include "config.h"
#include "utensils.h"
#include "session.h"
#include "radius.h"
#include "nft.h"
#include "nft_audit.h"
#include "local_auth.h"


struct inst_t* inst = NULL;

int check_white_list(struct user_address_t* user_address) {
    if (!inst) {
        log_error("Instance is not initialized");
        return -1;
    }

    struct in_addr tmp;
    tmp.s_addr = user_address->ip;
    log_debug("Check white list.userip=%s", inet_ntoa(tmp));

    // 在源 IP 白名单数组中线性查找
    for (int i = 0; i < inst->white_list.src_ip_count; i++) {
        if (inst->white_list.src_ip[i] == user_address->ip) {
            return 0;
        }
    }

    log_error("Not found user(ip) %s in whitelist", inet_ntoa(tmp));
    return -1;
}

/*
 * 通过 /usr/bin/skey get-mac 获取设备 MAC（形如 7C:27:3C:1E:8C:CE）。
 * 成功解析出 6 字节返回 0，否则返回 -1，由调用方决定是否回退。
 */
static int get_skey_mac(uint8_t* mac) {
    FILE* fp = popen("/usr/bin/skey get-mac", "r");
    if (!fp) {
        log_warn("Failed to execute skey command for device MAC");
        return -1;
    }

    char buffer[32];
    int ret = -1;
    if (fgets(buffer, sizeof(buffer), fp)) {
        unsigned int m[6];
        if (sscanf(buffer, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3],
                   &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++) {
                mac[i] = (uint8_t)(m[i] & 0xFF);
            }
            ret = 0;
        } else {
            log_warn("Invalid device MAC format from skey: %s", buffer);
        }
    } else {
        log_warn("Failed to read device MAC from skey");
    }

    pclose(fp);
    return ret;
}

struct inst_t* init_inst() {

    inst = (struct inst_t*) malloc(sizeof (struct inst_t));
    if (inst == NULL) {
        log_error("Init  instance error!");
        return NULL;
    }
    memset(inst, 0, sizeof (struct inst_t));
    inst->inst_status = 0;
    inst->config = NULL;
    /* fd 字段用 -1 表示未打开, memset 后是 0(等于 stdin), 必须显式复位 */
    inst->dns_fd = -1;
 

    // 获取 device_id
    FILE* fp = popen("/usr/bin/skey get-device-id", "r");
    if (fp) {
        char buffer[64];
        if (fgets(buffer, sizeof(buffer), fp)) {
            // 去除可能的换行符
            char* newline = strchr(buffer, '\n');
            if (newline) {
                *newline = '\0';
            }
            // 确保字符串终止
            buffer[sizeof(buffer) - 1] = '\0';
            strncpy(inst->device_id, buffer, sizeof(inst->device_id) - 1);
            log_debug("Device ID initialized: %s", inst->device_id);
        } else {
            log_warn("Failed to read device ID from skey");
            memset(inst->device_id, 0, sizeof(inst->device_id)); // 确保失败时为全0
        }
        pclose(fp);
    } else {
        log_warn("Failed to execute skey command for device ID");
        memset(inst->device_id, 0, sizeof(inst->device_id)); // 确保失败时为全0
    }

    // 获取设备 MAC；skey 失败时保持全 0，由 load_all_configs() 回退到网卡 ioctl
    if (get_skey_mac(inst->dev_mac) == 0) {
        log_debug("Device MAC initialized: %02X:%02X:%02X:%02X:%02X:%02X",
                  inst->dev_mac[0], inst->dev_mac[1], inst->dev_mac[2],
                  inst->dev_mac[3], inst->dev_mac[4], inst->dev_mac[5]);
    } else {
        memset(inst->dev_mac, 0, sizeof(inst->dev_mac));
    }

   
    if ((inst->base = event_base_new()) == NULL) {
        log_error("webauthd libevent initialized failed.");
        free(inst);
        inst = NULL;
        return NULL;
    }
    
  
    return inst;

}

void destroy_inst() {
    //printf("++++++++destroy inst\n");

    /* 先停掉仍注册在 event base 上的全局定时器, 再销毁会话;
     * 顺序反过来会让定时器回调访问已释放的 config/会话对象 */
    stop_flush_sessions_timer(inst);
    stop_nft_audit_timer(inst);
    local_auth_stop_timers();

    /* 停掉内置 DNS 劫持服务, 释放 20053 端口与 evdns 句柄 */
    anydns_stop(inst);



    if (inst->ev_cloud_auth) {
        event_del(inst->ev_cloud_auth);
        event_free(inst->ev_cloud_auth);

        inst->ev_cloud_auth = NULL;
    }
    if (inst->cloud_auth_fd > 0) {
        close(inst->cloud_auth_fd);
        inst->cloud_auth_fd = -1;
    }


   // 清理
    if (inst->msg_bev){
        bufferevent_disable(inst->msg_bev, EV_READ | EV_WRITE);
         bufferevent_free(inst->msg_bev);
        inst->msg_bev = NULL;

    }

  
 
  
    if (inst->msg_timer){
        event_del(inst->msg_timer);
        event_free(inst->msg_timer);
        inst->msg_timer = NULL;
    }  
 


    stop_rad_CoA_server(inst);

    if (inst->http_portal_server) {
        evhttp_free(inst->http_portal_server);
        inst->http_portal_server = NULL;
    }
    if (inst->http_redirct_url_server) {
        evhttp_free(inst->http_redirct_url_server);
        inst->http_redirct_url_server = NULL;
    }
    if (inst->http_config_server) {
        evhttp_free(inst->http_config_server);
        inst->http_config_server = NULL;
    }

    destroy_sessions(inst);

    free_config(inst);

    free(inst);
    inst = NULL;
    log_debug("Free instance \t\tOK!");
}

struct inst_t* get_inst() {
    return inst;
}

int restart_init(struct inst_t* inst) {


}

int start_init(struct inst_t* inst) {



    return 0;
}

int init_white_list(struct inst_t* inst) {
    struct config_t* config = inst->config;

if(!config){
    log_error("Init white list error!config is null");
    return -1;

}

    /* 配置对象保留原始字符串所有权；解析仅操作副本。 */
    char* src_ip = config->white_list_src_ip
                       ? strdup(config->white_list_src_ip) : NULL;
    char* src_mac = config->white_list_src_mac
                        ? strdup(config->white_list_src_mac) : NULL;
    char* dest_ip = NULL;
    struct in_addr tmp_ip;
    char* tmp_str = NULL;
    char cmd[128] = {0};
    char buf[32] = {0};
    uint8_t mac[6];

    log_debug("Init White list...");
    memset(&inst->white_list, 0, sizeof(inst->white_list));
    char *ptr;
    char *p;
    size_t len = 0;



    if (src_ip) {
        ptr = strtok_r(src_ip, " ", &p);
        while (ptr != NULL) {
            // printf("++++++++ip=%s\n", ptr);
            if (inet_pton(AF_INET, ptr, &tmp_ip) != 1) {
                log_error("Invalid white list SRC-IP: %s", ptr);
                ptr = strtok_r(NULL, " ", &p);
                continue;
            }
            // printf("src ip+++++++0x%0x\n", tmp_ip.s_addr);
            if (inst->white_list.src_ip_count < WHITE_LIST_MAX) {
                inst->white_list.src_ip[inst->white_list.src_ip_count++] = tmp_ip.s_addr;
            } else {
                log_error("White list SRC-IP full (max=%d), ignoring %s", WHITE_LIST_MAX, ptr);
            }
            ptr = strtok_r(NULL, " ", &p);
        }
        free(src_ip);
        src_ip = NULL;
    }
    p = NULL;
    if (src_mac) {
        ptr = strtok_r(src_mac, " ", &p);
        while (ptr != NULL) {
            //printf("++++++++mac=%s\n", ptr);
            if (xmac_to_byte(ptr, strlen(ptr), mac, 6) != 0) {
                log_error("Invalid white list SRC-MAC: %s", ptr);
                ptr = strtok_r(NULL, " ", &p);
                continue;
            }
            if (inst->white_list.src_mac_count < WHITE_LIST_MAX) {
                memcpy(inst->white_list.src_mac[inst->white_list.src_mac_count], mac, 6);
                inst->white_list.src_mac_count++;
            } else {
                log_error("White list SRC-MAC full (max=%d), ignoring %s", WHITE_LIST_MAX, ptr);
            }

            ptr = strtok_r(NULL, " ", &p);
        }
        free(src_mac);
        src_mac = NULL;

    }

    p = NULL;


    //  printf("config->portal_type=%d\n",config->portal_type);
    len = config->white_list_dest_ip ? strlen(config->white_list_dest_ip) : 0;
    if (config->portal_type == EXTERNAL_PORTAL ||
        config->portal_type == CLOUD_PORTAL) {
        tmp_str = (char*)calloc(1, len + strlen(config->portal_server) + 2);
        if (!tmp_str) {
            return -1;
        }
        if (len > 0) {
            snprintf(tmp_str, len + strlen(config->portal_server) + 2,
                     "%s %s", config->white_list_dest_ip,
                     config->portal_server);
        } else {
            snprintf(tmp_str, strlen(config->portal_server) + 2, "%s",
                     config->portal_server);
        }
        dest_ip = tmp_str;
    } else if (config->white_list_dest_ip) {
        dest_ip = strdup(config->white_list_dest_ip);
        if (!dest_ip) {
            return -1;
        }
    }




    /* 目的白名单是 webauthd 自有集合；先清空再按新配置重建，确保删除
     * 配置项后不会继续残留放行。 */
    snprintf(cmd, sizeof(cmd), "flush set ip " NFT_TABLE_FILTER " white_list");
    if (run_nft_rule(cmd) != 0) {
        free(dest_ip);
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "flush set ip " NFT_TABLE_NAT " white_list");
    if (run_nft_rule(cmd) != 0) {
        free(dest_ip);
        return -1;
    }

    if (dest_ip) {
        len = strlen(dest_ip);
        if (len > 0) {
            ptr = strtok_r(dest_ip, " ", &p);
            len = 0;
            while (ptr != NULL) {
                // printf("++++++++ip=%s\n", ptr);
                if (inet_pton(AF_INET, ptr, &tmp_ip) != 1) {
                    log_error("Invalid white list DEST-IP: %s", ptr);
                    ptr = strtok_r(NULL, " ", &p);
                    continue;
                }
                // add white list 
                memset(cmd, 0, 128);
                snprintf(cmd, 128, "add element ip " NFT_TABLE_FILTER " white_list {%s};", ptr);
                if (run_nft_rule(cmd) != 0) {
                    free(dest_ip);
                    return -1;
                }

                memset(cmd, 0, 128);
                snprintf(cmd, 128, "add element ip " NFT_TABLE_NAT " white_list {%s};", ptr);
                if (run_nft_rule(cmd) != 0) {
                    free(dest_ip);
                    return -1;
                }
                
                
                ptr = strtok_r(NULL, " ", &p);
                
                
                
                
                // len+=offset;
                //  printf("+++++++++++++tmp_ip=0x%0x\n", tmp_ip.s_addr);
            }

            if (get_dns_server(buf) == 0) {
                if (strlen(buf) > 6) {
                   // printf("+++++++++++++++++++++++++dns=|%s|\n", buf);
                    inet_aton(buf, &tmp_ip);
                    // add white list 
                    memset(cmd, 0, 128);
                    snprintf(cmd, 128, "add element ip " NFT_TABLE_FILTER " white_list {%s};", buf);
                    if (run_nft_rule(cmd) != 0) {
                        free(dest_ip);
                        return -1;
                    }

                    memset(cmd, 0, 128);
                    snprintf(cmd, 128, "add element ip " NFT_TABLE_NAT " white_list {%s};", buf);
                    if (run_nft_rule(cmd) != 0) {
                        free(dest_ip);
                        return -1;
                    }
                    
                }

            }

            if (strlen(config->primary_auth_server) > 6) {
                inet_aton(config->primary_auth_server, &tmp_ip);

             //   printf("+++++++++++++++++++++++++auth server=|%s|\n", config->primary_auth_server);
                // add white list 
                memset(cmd, 0, 128);
                snprintf(cmd, 128, "add element ip " NFT_TABLE_FILTER " white_list {%s};", config->primary_auth_server);
                if (run_nft_rule(cmd) != 0) {
                    free(dest_ip);
                    return -1;
                }

                 memset(cmd, 0, 128);
                snprintf(cmd, 128, "add element ip " NFT_TABLE_NAT " white_list {%s};", config->primary_auth_server);
                if (run_nft_rule(cmd) != 0) {
                    free(dest_ip);
                    return -1;
                }
                
            }


            // printf("+++++++++++++++++%d  %s  %u\n", n, config->white_list_dest_ip, offset);
        }
        free(dest_ip);
        dest_ip = NULL;
    }







    return 0;
}

/* 确定门户 DNS 应应答的地址(设备 LAN 侧地址) */
static uint32_t get_portal_answer_ip(struct inst_t* inst) {
    struct in_addr a;
    char ip[24] = {0};
    char mac[6] = {0};

    if (!inst || !inst->config) {
        return 0;
    }
    if (inst->config->portal_ip[0] != '\0' &&
        inet_pton(AF_INET, inst->config->portal_ip, &a) == 1) {
        return a.s_addr;
    }
    if (inst->config->nas_ip[0] != '\0' &&
        inet_pton(AF_INET, inst->config->nas_ip, &a) == 1) {
        return a.s_addr;
    }
    /* 未显式配置时按门户接口(layer3_ifname, 默认 br-lan)取本机地址 */
    if (get_local_address(ip, mac) == 0 && ip[0] != '\0' &&
        inet_pton(AF_INET, ip, &a) == 1) {
        return a.s_addr;
    }
    return 0;
}

static void
evdns_server_callback(struct evdns_server_request *req, void *data) {
    struct inst_t* inst = (struct inst_t*) data;
    uint32_t answer_ip;
    int i;

    if (!req) {
        return;
    }

    answer_ip = get_portal_answer_ip(inst);
    if (answer_ip == 0) {
        /* 无法确定门户地址时返回 SERVFAIL, 不把客户端指向错误地址 */
        log_error("DNS capture: no portal address available, answer SERVFAIL");
        evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
        return;
    }

    for (i = 0; i < req->nquestions; ++i) {
        struct evdns_server_question* q = req->questions[i];

        if (!q) {
            continue;
        }
        if (q->type == EVDNS_TYPE_A &&
            q->dns_question_class == EVDNS_CLASS_INET) {
            uint32_t reply = answer_ip;   /* 网络字节序 */
            if (evdns_server_request_add_a_reply(req, q->name, 1, &reply, 60) < 0) {
                log_error("DNS capture: add A reply failed: %s", strerror(errno));
            }
        }
        /*
         * 其它类型(AAAA/HTTPS 等)不添加记录, 统一回 NOERROR/NODATA,
         * 由客户端按标准行为回退到 A 查询; 不能返回 NXDOMAIN,
         * 否则部分终端会直接判定"域名不存在"而不弹门户页。
         */
    }

    if (evdns_server_request_respond(req, 0) < 0) {
        log_error("DNS capture: respond failed: %s", strerror(errno));
    }
}

int anydns_server(struct inst_t* inst) {
    struct sockaddr_in my_addr;
    int one = 1;

    if (!inst || !inst->base) {
        return -1;
    }
    if (inst->dns_server_port) {
        return 0; /* 幂等: 已启动 */
    }
    if (!inst->config || inst->config->capture_dns != 1) {
        log_info("DNS capture disabled (capture_dns=%d)",
                 inst->config ? inst->config->capture_dns : -1);
        return 0;
    }

    /* 只作为 DNS 服务端应答, 不需要 evdns 解析器/上游 nameserver 状态 */

    inst->dns_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (inst->dns_fd < 0) {
        log_error("DNS capture: socket failed: %s", strerror(errno));
        anydns_stop(inst);
        return -1;
    }
    evutil_make_socket_nonblocking(inst->dns_fd);
    (void)setsockopt(inst->dns_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(20053);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(inst->dns_fd, (struct sockaddr*) &my_addr, sizeof(my_addr)) < 0) {
        log_error("DNS capture: bind 0.0.0.0:20053 failed: %s", strerror(errno));
        anydns_stop(inst);
        return -1;
    }

    /* 句柄必须保存: 用于停服时释放端口/事件, 否则会泄漏 socket 与 evdns 状态 */
    inst->dns_server_port = evdns_add_server_port_with_base(
            inst->base, inst->dns_fd, 0, evdns_server_callback, inst);
    if (!inst->dns_server_port) {
        log_error("DNS capture: evdns_add_server_port_with_base failed");
        anydns_stop(inst);
        return -1;
    }

    {
        struct in_addr a;
        char answer_str[INET_ADDRSTRLEN] = "none";
        uint32_t answer_ip = get_portal_answer_ip(inst);

        if (answer_ip != 0) {
            a.s_addr = answer_ip;
            inet_ntop(AF_INET, &a, answer_str, sizeof(answer_str));
        } else {
            log_warn("DNS capture: no portal address configured, clients will get SERVFAIL");
        }
        log_info("DNS capture: listening on udp 0.0.0.0:20053 (answer=%s)",
                 answer_str);
    }
    return 0;
}

void anydns_stop(struct inst_t* inst) {
    if (!inst) {
        return;
    }
    if (inst->dns_server_port) {
        /* 端口对象持有 socket, 由其释放; 这里只清空句柄避免重复 close */
        evdns_close_server_port(inst->dns_server_port);
        inst->dns_server_port = NULL;
        inst->dns_fd = -1;
    }
    if (inst->dns_fd >= 0) {
        close(inst->dns_fd);
        inst->dns_fd = -1;
    }
}

