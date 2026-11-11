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
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/in.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "control_client.h"
#include "app_events.h"
#include "http_auth.h"
#include "http_service.h"
#include "instance.h"
#include "local_auth.h"
#include "log.h"
#include "portal_server.h"

// #include "uci_config.h"
#include "session.h"
#include "timer.h"
// #include "database.h"
 
#include "nft.h"
#include "nft_recovery.h"
#include "nft_audit.h"
#include "radius.h"
#include "ubus_service.h"
#include "utensils.h"

/*
char nacip[32];


struct interface_t itfs[MAX_IF_COUNT];
 */

// int http302_server(void);
// void httpServerOpen();

// int sock_fd;
// int get_user_mac(char* user_ip, char* user_mac);

// int http302_start(void);
// int anydns_start(void);

// static int S_debug_flag = 0;
const char* short_options = "hvd";

// static char* S_db_path = ":memory:";

const struct option long_options[] = {{"help", 0, NULL, 'h'},
                                      {"version", 0, NULL, 'v'},
                                      {"debug", 0, NULL, 'd'},
                                      {NULL, 0, NULL, 0}};

/*
 * usage
 */
static void usage(void) {
  printf("Usage:\n-h	--help \n");
  printf("-d	--debug \n");
  printf("-v	--version \n");
}

/*
 * 解析启动参数
 */
void parse_main_argv(struct inst_t* inst, int argc, char** argv) {
  int ret = 0;
  while ((ret = getopt_long(argc, argv, short_options, long_options, NULL)) !=
         -1) {
    switch (ret) {
      case 'h':
        usage();
        exit(0);
        break;
      case 'd':
        inst->debug = 1;
        break;
      case 'v':
        printf("4.1.3\n");
        exit(0);
        break;
      default:
        break;
    }
  }
}

void stop_sessions(void* data, void* items) {
  struct user_session_t* session = (struct user_session_t*)data;

  if (session->status == USER_STATE_AUTHED) {
    printf("user ip =%02x\n", session->ip);
    // send_stop_acct(session);
  }
}

/* 致命信号只做异步信号安全的最小动作, 不在信号上下文里做析构/日志 */
static void fatal_signal_handler(int sig) {
  const char msg[] = "webauthd: fatal signal, exiting\n";
  (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
  _exit(128 + sig);
}

/* 退出类信号交给 libevent 事件循环处理, 从而在正常上下文中安全析构 */
static int g_shutting_down = 0;
static int g_shutdown_stop_count = 0;

/* 关机时为在线会话走与正常下线相同的路径:
 *   RADIUS -> 发 Accounting-Stop; local -> 最终用量落盘; http -> 发 Stop
 * 避免进程重启后这些会话在服务器/本地账务中成为永久挂起记录。 */
static void shutdown_close_cb(struct user_session_t* user, void* ctx) {
  (void)ctx;
  if (!user || !user_is_valid(user)) {
    return;
  }
  if (user->lifecycle_state != USER_LIFECYCLE_ACTIVE) {
    return;
  }
  if (user->status != USER_STATE_AUTHED && user->status != USER_STATE_FREE) {
    return;
  }
  g_shutdown_stop_count++;
  process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
}

static void shutdown_finalize_cb(evutil_socket_t fd, short events, void* arg) {
  (void)fd;
  (void)events;
  (void)arg;
  log_warn("shutdown: grace period elapsed, finalize and exit");
  destroy_inst();
  exit(0);
}

static void shutdown_signal_cb(evutil_socket_t sig, short events, void* arg) {
  struct inst_t* cur = NULL;

  (void)events;
  (void)arg;

  if (g_shutting_down) {
    return; /* 重复信号不重复清理 */
  }
  g_shutting_down = 1;
  log_warn("signal = %d, shutting down: close sessions then exit", (int)sig);

  cur = get_inst();
  if (!cur || !cur->base) {
    destroy_inst();
    exit(0);
  }

  g_shutdown_stop_count = 0;
  for_each_user_session(shutdown_close_cb, NULL);

  if (g_shutdown_stop_count > 0) {
    /* 已发出 Accounting-Stop/用量落盘, 给应答与落盘留 2s 窗口后强制退出 */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    event_add(evtimer_new(cur->base, shutdown_finalize_cb, NULL), &tv);
  } else {
    destroy_inst();
    exit(0);
  }
}

void on_exit(void) { printf("exit...!!!\n"); }

int signalsInit(struct event_base* base) {
  atexit(on_exit);

  /* SIGSEGV/SIGILL/SIGFPE 无法安全恢复, 仅记录后立即退出 */
  signal(SIGSEGV, fatal_signal_handler);
  signal(SIGILL, fatal_signal_handler);
  signal(SIGFPE, fatal_signal_handler);

  struct event* ev;
  ev = evsignal_new(base, SIGHUP, shutdown_signal_cb, NULL);
  if (ev) event_add(ev, NULL);
  ev = evsignal_new(base, SIGINT, shutdown_signal_cb, NULL);
  if (ev) event_add(ev, NULL);
  ev = evsignal_new(base, SIGQUIT, shutdown_signal_cb, NULL);
  if (ev) event_add(ev, NULL);
  ev = evsignal_new(base, SIGTERM, shutdown_signal_cb, NULL);
  if (ev) event_add(ev, NULL);

  return 0;
}

int main(int argc, char** argv) {
  struct inst_t* inst = init_inst();
//printf("++++++++++++device_id=%s\n",inst->device_id);
  //  new_tun(inst);

  // 解析argv
  parse_main_argv(inst, argc, argv);
  // 后台运行
  if (inst->debug == 0) {
    // log_init("/tmp/webauthd.log", XYZ_LOG_LEVEL_WARN, 65536);
    daemon(1, 1);
  } else {
    log_init("stdout", XYZ_LOG_LEVEL_DEBUG, 0);
  }

  /* 在 daemon 之后、事件循环启动前注册信号事件 */
  signalsInit(inst->base);

    if (load_all_configs(inst) != 0) {
      log_error("Load configuration failed");
      return -1;
    }

    /*
     * 控制面初始化：先记录 UCI 本地基线，再应用上一次冷重启留下的
     * pending 状态。pending 必须在 start_init 之前应用，才能让
     * portal_type/auth_source 等冷字段从启动时就正确。
     */
    control_client_init(inst);
    control_client_load_pending(inst);
  // printf("+++++++++++++1+++++++++nasip=%s\n",inst->config->nas_ip);
  //   printf("+++++++++++++2+++++++++inst->config->acct_interval=%d\n",inst->config->acct_interval);
  if (inst->config->enabled == 1) {
    init_sessions(inst);
    start_init(inst);

    /*
     * 本地认证源初始化: 建立用户目录(0700)并预热默认 UCI 配置。
     * 依赖 config 已加载(auth_source/max_users/api_secret), 放在
     * load_all_configs 之后。失败不阻断主流程(目录异常仅告警,
     * local 源登录时仍会按需读文件报错)。
     */
    if (local_auth_init(inst) < 0) {
      log_warn("Local auth source init failed, local login unavailable");
    }

    /*
     * HTTP(S) 认证源初始化: curl multi 挂接主循环。仅 auth_source=http
     * 时真正启用; 失败不阻断主流程(登录按"服务器不可达"拒绝)。
     */
    if (http_auth_init(inst) < 0) {
      log_warn("HTTP auth source init failed, http login unavailable");
    }

    // if (update_radius_config(inst) < 0) {
    //   log_debug("Can NOT update config!");
    // }
    /*
             event_base_dispatch(inst->base);

        return 0;
     */
 
    /*
     * RADIUS 客户端参数来源:
     *   local_radius_client == 1: 使用本地 UCI 配置, 不连接云端
     *   local_radius_client == 0: 从云端获取, 本地配置不生效,
     *                             云端应答到达后由 read_cb() 调 init_radius()
     */
    if (inst->config->local_radius_client == 1) {
      log_info(
          "RADIUS client mode=local, use UCI settings: auth=%s:%u acct=%s:%u",
          inst->config->primary_auth_server, inst->config->primary_auth_port,
          inst->config->primary_acct_server, inst->config->primary_acct_port);
    } else {
      log_info(
          "RADIUS client mode=cloud, fetch settings from cloud (local UCI "
          "radius settings ignored)");
     
    }


 


    if (init_white_list(inst) != 0) {
      log_error("Initialize whitelist failed");
      destroy_sessions(inst);
      return -1;
    }
#if 0
        start_radius(inst);
        init_rad_session_table();
#endif
//printf("++++++++++++3+++++++++start radius\n");
    if (inst->config->local_radius_client == 1) {
      // 仅本地模式在启动时按 UCI 配置初始化; 云端模式等云端应答后再初始化
      init_radius(inst);
    }
  //  printf("++++++++++++4+++++++++start radius\n");
    //   if (inst->config->mode = WEBAUTH_MODE) {

    /*
     * DNS 劫持: capture_dns=1 时启动内置 DNS 服务(udp 20053),
     * 把未认证客户端的 A 查询应答为门户地址。
     * 对应的 nft 重定向规则由 webauthd.init 在加载 nft 表后下发,
     * 这里只负责监听; 启动失败不阻断主流程(HTTP 重定向仍可用)。
     */
    if (inst->config->capture_dns == 1) {
      if (anydns_server(inst) != 0) {
        log_error("Failed to start DNS capture service on udp :20053");
      }
    }

    start_flush_sessions_timer(inst);

    // NFT 规则恢复：程序启动时从 NFT 规则重建 session 或清理残留规则
    if (inst->config->nft_recovery_mode > 0) {
      log_info("Starting NFT recovery (mode=%d)", inst->config->nft_recovery_mode);
      if (nft_recovery_init(inst, inst->config->nft_recovery_mode) != 0) {
        log_error("NFT recovery failed; refusing to start with ambiguous data-plane state");
        destroy_sessions(inst);
        return -1;
      }
    }

    // NFT 规则审计：定期验证 session 的 NFT handle 是否仍然存在
    if (inst->config->nft_audit_interval > 0) {
      log_info("Starting NFT audit timer (interval=%ds)", inst->config->nft_audit_interval);
      start_nft_audit_timer(inst, inst->config->nft_audit_interval);
    }

    // restore_user(inst);
  } else {
    destroy_sessions(inst);

    return 0;
  }
  if (inst->config->portal_type == LOCAL_PORTAL ||
      inst->config->portal_type == EXTERNAL_PORTAL) {
    if (start_rad_CoA_server(inst) < 0) {
      log_error("Can't start CoA service!");
    }
    /* 成功后句柄由 inst->ev_radius_coa / inst->coa_fd 持有, 供停服时关闭;
     * 不能在此清空, 否则 socket 和 event 将永久泄漏 */

  } else {
    inst->coa_fd = -1;
    inst->ev_radius_coa = NULL;
  }

  if (inst->config->portal_type == CLOUD_PORTAL) {
    if (cloud_loacal_auth_service(inst) < 0) {
      log_error("Can't start local auth service!");
      destroy_sessions(inst);
      return -1;
    }
    /* 句柄由 inst->ev_cloud_auth / inst->cloud_auth_fd 持有 */
    log_debug("Start local auth service.");

  } else {
    inst->ev_cloud_auth = NULL;
    inst->cloud_auth_fd = -1;
  }

 

  // 本地配置接口, 仅绑定回环; 绑定失败只告警, 不影响主服务
  if (start_config_service(inst, "127.0.0.1", 60000) < 0) {
    log_error("Can't start local config service on 127.0.0.1:60000");
  }

  if(start_ws_service(inst, "0.0.0.0", 20080)<0){
    log_error("Can't start ws service!");
    return -1;
  }

  //    start_redirect_server(inst, "0.0.0.0", 20089);

  if(start_http_portal_service(inst, 20002)<0) {
      log_error("Can't start http portal service!");
      return -1;
  }

  /* ubus 服务(条件编译, 默认开启): ubusd 不可用时内部降级重试, 不影响主业务 */
  ubus_service_start(inst);

  /* 本地认证源定时器: 巡检踢下线(60s) + 用量/在线时长兜底落盘(300s),
   * 仅在 auth_source=local 时实际启动(内部判断) */
  local_auth_start_timers(inst);

  /* xfrpc_loader 控制通道：webauthd 主动拉取期望状态，失败自动重试 */
  control_client_start(inst);

  event_base_dispatch(inst->base);

  control_client_stop(inst);
  local_auth_stop_timers();
  ubus_service_stop();

  return 0;
}

