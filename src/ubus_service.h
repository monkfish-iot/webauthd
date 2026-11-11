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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef UBUS_SERVICE_H
#define UBUS_SERVICE_H

#include "instance.h"
#include "log.h"
/*
 * UBUS 服务框架（条件编译，默认开启：WEBAUTHD_ENABLE_UBUS=1）。
 *
 * - 注册 ubus object "webauthd.session"，提供 drop_user / list_users 方法；
 * - ubus socket 挂在主进程 libevent 上监听，不引入 uloop；
 * - ubusd 不可用时降级运行，不影响 portal/RADIUS 主业务，并后台定时重连；
 * - 访问鉴权由 rpcd 会话 + ACL 完成（见 /usr/share/rpcd/acl.d/webauthd.json），
 *   本机 root 直接 ubus call 按 OpenWrt 惯例放行。
 */
#ifdef WEBAUTHD_ENABLE_UBUS

/* 启动 ubus 服务（连接 ubusd + 注册 object + 挂接 libevent）。
 * 返回 0 表示已启动或已安排后台重试（不阻塞主业务启动）。 */
int ubus_service_start(struct inst_t* inst);

/* 停止 ubus 服务并释放资源（进程退出时调用）。 */
void ubus_service_stop(void);

#else /* !WEBAUTHD_ENABLE_UBUS */

static inline int ubus_service_start(struct inst_t* inst) {
  log_info("[ubus] service disabled, skip start");
 
  (void)inst;
  return 0;
}

static inline void ubus_service_stop(void) {}

#endif /* WEBAUTHD_ENABLE_UBUS */

#endif /* UBUS_SERVICE_H */
