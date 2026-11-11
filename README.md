# webauthd

**Web Authentication Daemon for OpenWrt / Embedded Linux**

[![中文](https://img.shields.io/badge/lang-中文-red.svg)](./README.md)
[![English](https://img.shields.io/badge/lang-English-blue.svg)](./README.en.md)

> 许可证：GPL-3.0-or-later（见 [COPYING](./COPYING)）

`webauthd` 是 MonkFish IoT 生态中跑在 OpenWrt 设备上的 **Portal 认证守护进程**。
它负责：

- 给未认证客户端下发 nftables 重定向规则，强跳 Portal 页面；
- 管理每个客户端的在线会话（状态机、空闲/计费超时、并发上限）；
- 通过 RADIUS / 本地用户库 / HTTP 接口对用户进行身份认证；
- 认证成功后在 nftables 中放行，可选下发速率限制、流量配额、会话时长；
- 运行 LuCI / 脚本通过 **ubus** 总线查询在线用户与强制下线；
- 在与 `xfrpc_loader` 共存时，通过 **webauthd-control/v1** 本机控制通道接收云端下发的 Portal/RADIUS 覆盖配置。

---

## 目录  |  Table of Contents

- [功能特性](#功能特性)
- [架构概览](#架构概览)
- [目录结构](#目录结构)
- [构建](#构建)
- [运行时](#运行时)
- [关键 UCI 配置](#关键-uci-配置)
- [webauthd-control/v1 控制协议](#webauthd-controlv1-控制协议)
- [API 概览](#api-概览)
- [依赖库](#依赖库)
- [相关文档  |  Related Documentation](#相关文档-related-documentation)
- [许可证](#许可证)

---

## 功能特性

| 能力 | 说明 |
|---|---|
| Portal 类型 | 本地 Portal（`portal_type=1`）、外部 Portal（`portal_type=2`）、云端 Portal + nginx 反代缓存（`portal_type=3`） |
| 认证源 | RADIUS、本地 UCI 用户库、HTTP(S) 远程接口；同一版本可通过 `auth_source` 切换 |
| 认证层级 | 二层（bridge-netfilter + `brdnft.conf`）/ 三层（`rednft.conf`）；桥接模式可由 `/etc/bridge.mode` 强制覆盖 |
| DNS 劫持 | `capture_dns=1` 时内置 DNS 服务器（udp/20053）拦截未认证客户端的 A 查询，配合 nft prerouting 规则 |
| 会话管理 | 空闲超时、计费间隔、每小时计费、MAC 无感知认证（多种 MAC 格式）、白名单免认证 |
| NFT 运维 | 规则恢复（冷启动重建 session）、定期审计（handle 仍在）、残留规则清理 |
| 优雅关机 | `SIGTERM/SIGINT/SIGQUIT/SIGHUP` 时走与正常下线相同的 Accounting-Stop/用量落盘路径 |
| ubus 总线 | `webauthd.session` 对象：`list_users`（分页）、`drop_user`（多条件 AND）；`WEBAUTHD_UBUS=0` 可关闭 |
| 控制协议 | 与 `xfrpc_loader` 通过 Unix socket 交换 overlay 状态，支持代际、租约、热/冷字段分离 |

---

## 架构概览

```
                   ┌──────────────────────────────────────┐
   Client  ──→  未认证 ──→ nftables (webauthd_nat/filter) ──→ 放行到 Internet
                    │
                    │  首次 HTTP → 302 跳 portal
                    ▼
            ┌───────┴─────────────────┐
            │  nginx / uhttpd          │  ← 20001/20443 处理 Portal 静态页与 /v1/* API 反代
            └───────┬─────────────────┘
                    │ proxy_pass http://127.0.0.1:20002/v1/http_login
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     webauthd (event loop, libevent)             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │ Portal HTTP  │  │   Session    │  │      Auth Sources      │ │
│  │ Service :20002│→ │   Manager    │→ │ radius / local / http  │ │
│  └──────────────┘  └──────┬───────┘  └───────────┬───────────┘ │
│                           │                      │             │
│                           ▼                      │             │
│                    ┌──────────────┐              │             │
│                    │  nftables    │              │             │
│                    │  Manager     │              │             │
│                    └──────┬───────┘              │             │
│                           │                      │             │
│     ┌───────────┐  ┌─────┴───────┐   ┌──────────┴───────────┐  │
│     │ ubus 总线 │  │ Control     │   │ Local Config Service │  │
│     │ (会话查询) │  │ Client      │   │ (127.0.0.1:60000)    │  │
│     └───────────┘  │ (xfrpc_loader│   └──────────────────────┘  │
│                    │  overlay)    │                              │
│                    └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
                           │ 动态下发规则
                           ▼
                  ┌──────────────────┐
                  │    nftables      │  webauthd_filter / webauthd_nat
                  └──────────────────┘
```

事件循环由 **libevent2** 驱动；所有模块共享同一个 `struct inst_t` 上下文。

---

## 目录结构

```
webauthd/
├── Makefile                   # OpenWrt 包定义（DEPENDS、install 规则）
├── src/
│   ├── Makefile               # 交叉编译入口；WEBAUTHD_UBUS 编译开关
│   ├── main.c                 # 入口：解析参数、加载 UCI、启动各服务、事件循环、信号处理
│   ├── config.{c,h}           # UCI 配置加载 + 控制协议 overlay 合并
│   ├── instance.{c,h}         # 全局上下文 inst_t 生命周期
│   ├── session.{c,h}          # 会话池（上限 256）、状态机、遍历回调
│   ├── timer.{c,h}            # 空闲超时 / 计费 / 审计定时器
│   ├── portal_server.{c,h}    # /v1/http_login、/v1/get_online_users、/v1/drop_user 等 HTTP 接口
│   ├── http_service.{c,h}     # 通用 HTTP 服务器框架（端口 20002）
│   ├── http_auth.{c,h}        # HTTP(S) 认证源（curl multi 挂事件循环）
│   ├── local_auth.{c,h}       # 本地 UCI 用户库 + 巡检踢下线 + 用量落盘
│   ├── radius.{c,h}           # RADIUS 客户端（认证 + 计费 + CoA）
│   ├── nft.{c,h}              # nftables 规则下发 / 删除
│   ├── nft_recovery.{c,h}     # 冷启动从 nft 规则重建 session
│   ├── nft_audit.{c,h}        # 定期校验 handle 是否仍存在
│   ├── arp.{c,h}              # ARP 表查询（IP→MAC）
│   ├── app_events.{c,h}       # 跨模块事件通道（EV_CLOSE_SESSION 等）
│   ├── control_client.{c,h}   # webauthd-control/v1 拉取 + pending 应用
│   ├── ubus_service.{c,h}     # webauthd.session ubus 对象
│   ├── ws_users.{c,h}         # 在线用户结构与计算
│   ├── http_client.{c,h}      # curl wrapper
│   ├── utensils.{c,h}         # 杂项工具
│   ├── log.{c,h}              # 日志
│   └── cJSON.{c,h}            # 内嵌第三方 JSON 库（MIT）
│
└── files/
    ├── webauthd.conf         # 默认 UCI 配置模板 → 安装到 /etc/config/webauthd
    ├── webauthd.init          # OpenWrt procd init 脚本（START=97）
    ├── webauthd.acl.json      # rpcd ACL → /usr/share/rpcd/acl.d/webauthd.json
    ├── rednft.conf           # 三层模式 nft 表模板（webauthd_filter/nat）
    ├── brdnft.conf           # 二层模式 nft 表模板
    ├── defnft.conf           # 关闭服务时的空表清理
    ├── portal.conf           # nginx 配置（随 init 动态重建）
    ├── https/                 # uhttpd HTTPS Portal 资产
    ├── local_portal/          # 本地 Portal HTML/CSS/JS（Bootstrap + avalon.js）
    ├── upload_portal/         # 上传 Portal + Lua CGI
    ├── www/                   # Web UI 静态资源
    ├── find_essid.sh          # /usr/sbin 下的辅助脚本
    └── helpme.sh              # /sbin 下的辅助脚本
```

---

## 构建

### 方式一：OpenWrt SDK 内（推荐）

```sh
# 在 OpenWrt buildroot 根目录
make package/webauthd/compile V=s
```

依赖 OpenWrt 工具链（`TARGET_CC`、`STAGING_DIR`），自动交叉编译并打包 IPK。

### 方式二：独立交叉编译

```sh
cd webauthd/src
CC=mipsel-openwrt-linux-gcc make clean
CC=mipsel-openwrt-linux-gcc make
```

产物 `webauthd` 可执行文件。

### 编译开关

| 开关 | 默认 | 说明 |
|---|---|---|
| `WEBAUTHD_UBUS` | `1` | 编译 `ubus_service.c` 并链接 `-lubus -lubox`。设为 `0` 关闭 ubus 总线功能，可裁掉 ~几 KB 二进制 |
| `-DWEBAUTHD_ENABLE_UBUS=1` | — | 通过 `src/Makefile` 的 `override CFLAGS` 自动附加；与 `WEBAUTHD_UBUS=1` 联动 |

独立编译关闭 ubus：

```sh
make WEBAUTHD_UBUS=0
```

---

## 运行时

### 启动的服务与端口

webauthd 进程本身在后台运行（`daemon(1, 1)`），默认端口：

| 端口 | 协议 | 用途 |
|---|---|---|
| `20001` | HTTP | nginx 反代：Portal 静态页 + `/v1/get_portal_text` + `/v1/login` |
| `20443` | HTTPS | uhttpd（`-s 0.0.0.0:20443`）处理 HTTPS Portal |
| `20002` | HTTP | **webauthd 内置 HTTP 服务**（所有 `/v1/*` 认证/查询 API 实际监听端口） |
| `20080` | HTTP | 在线用户 WebSocket（`start_ws_service`） |
| `20053` | UDP | DNS 劫持（`capture_dns=1` 时启用） |
| `60000` | HTTP | **本地配置接口**（仅 `127.0.0.1` 绑定） |
| `/var/run/xfrpc_loader/webauthd-control.sock` | Unix socket | `webauthd-control/v1` 本机控制通道 |

> init 脚本在 START=97 时先配置 nginx（本地/云端 Portal 二选一、可选反代缓存），再加载 nft 表模板（二层或三层），最后 `exec /sbin/webauthd`。

### 依赖的系统组件

| 组件 | 作用 |
|---|---|
| **nftables** | 规则下发与查询；依赖内核模块 `kmod-br-netfilter`（二层） |
| **nginx** | 反代 Portal（`portal_type=1` 或 `3`）；init 脚本自动 reload |
| **uhttpd** | HTTPS Portal（`-s 0.0.0.0:20443`） |
| **ubusd** | ubus 总线守护进程；不可用时 webauthd 降级运行，不影响主业务 |
| **libcurl** | HTTP 认证源（`auth_source=http`） |
| **dnsmasq** | 可选（桥接二层 DNS 场景） |

### 信号处理

| 信号 | 行为 |
|---|---|
| `SIGTERM / SIGINT / SIGQUIT / SIGHUP` | 走优雅关机：为每个在线 AUTHED/FREE 会话发 RADIUS Accounting-Stop → 等待 2s 应答窗口 → 销毁会话并退出 |
| `SIGSEGV / SIGILL / SIGFPE` | 只做异步安全的最小动作（写 stderr）后 `_exit`，不尝试析构 |

停止服务：

```sh
/etc/init.d/webauthd stop       # 优雅关机 + 清理 nginx/uhttpd/nft
/etc/init.d/webauthd restart
```

---

## 关键 UCI 配置

**路径：** `/etc/config/webauthd`
**格式：** OpenWrt UCI

最小可用片段：

```text
config base 'generic'
    option enabled '1'
    option layer '3'                   # '2'=二层 / '3'=三层
    option portal_interface 'br-lan'
    option capture_dns '1'
    option idle_timeout '120'          # 空闲超时（秒）
    option mac_auth '1'                # MAC 无感知认证
    option auth_source 'radius'        # radius / local / http

config portal 'portal'
    option portal_type '3'             # 1=本地 / 2=外部 / 3=云端+反代
    option portal_port '9091'
    option proxy_pass 'http://127.0.0.1:9091'
    option cache_enable '1'

config radius 'radius'
    option local_radius_client '1'     # '1'=使用本地参数 / '0'=等云端下发
    option primary_auth_server '127.0.0.1'
    option primary_auth_port '1812'
    option primary_auth_secret 'testing123'
```

> 完整配置项说明见 `Documents/webauthd/config/WEBAUTHD_CONF.md`。

---

## webauthd-control/v1 控制协议

当设备上存在 `xfrpc_loader` 时，它通过 Unix socket (`/var/run/xfrpc_loader/webauthd-control.sock`)
向下发 overlay 状态，webauthd 主动拉取、校验、合并，最终生效配置 = `UCI baseline` ← `control overlay`。

- **热字段**（运行时可更新）：`auth.radius.*`、`portal.portal_url/server/port` — 即时刷新内存参数 / nginx 配置
- **冷字段**（需重启）：`portal.portal_type`、`auth.auth_source`、`auth.local_radius_client`、`generic.enabled` — 写入 `/var/run/webauthd/pending.json`，ACK 带 `restart_required`
- **租约保护**：超过 `lease_sec` 未成功拉取 → 清除 overlay，回退 baseline

详见 `Documents/接口规范/webauthd控制协议.md`。

---

## API 概览

### HTTP API（webauthd 内置，端口 20002）

| 接口 | 方法 | 说明 |
|---|---|---|
| `/v1/http_login` | GET / POST | Portal 认证主入口（支持用户名+密码，或 MAC 无感知） |
| `/v1/get_portal_text` | GET | Portal 页面文本/标题动态读取 |
| `/v1/get_online_users` | GET | 在线用户完整列表（无分页，ubus 版可分页） |
| `/v1/drop_user` | GET | 强制下线（按 ip/mac/username 任一匹配） |
| `/v1/get_user_by_ip` | GET | 按 IP 查询会话 |
| `/v1/get_user_by_name` | GET | 按用户名查询会话 |

> 错误码体系（0=成功，负数=失败）见 `Documents/webauthd/api/PORTAL_AUTH_API.md`。

### ubus 对象：`webauthd.session`

| 方法 | 参数 | 说明 |
|---|---|---|
| `list_users` | `page`, `page_size`（可选） | 分页查询在线用户 |
| `drop_user` | `username` / `ip` / `mac` / `session_id`（至少一个） | 强制下线（异步） |

```sh
ubus call webauthd.session list_users '{"page":1,"page_size":20}'
ubus call webauthd.session drop_user  '{"ip":"192.168.1.100"}'
```

> 调用前需确保 `/usr/share/rpcd/acl.d/webauthd.json` 中的 ACL 组已授予当前会话（read + write 均可）。
> 详细字段、响应结构、错误处理见 `Documents/webauthd/api/UBUS_API.md`。

### 本地配置接口（仅 127.0.0.1:60000）

UCI 写入 + 立即生效（部分字段需重启）。详见 `Documents/webauthd/config/local_config_http_api.md`。

---

## 依赖库

### 编译时链接

| 库 | 许可证 | 用途 |
|---|---|---|
| `libnftnl` / `libnftables` | GPL-2.0-or-later | nftables netlink API |
| `libuci` | **LGPL-2.1** | OpenWrt UCI 配置 |
| `libnl` / `libmnl` | **LGPL-2.1** | netlink helpers |
| `libevent` (libevent2) | BSD-3-Clause | 事件循环 |
| `libcurl` | MIT-style | HTTP 客户端（HTTP 认证源） |
| `libsodium` | ISC | 密码学 |
| `libuuid` | BSD-3-Clause | UUID |
| `zlib` | zlib | 压缩 |
| `libopenssl` | Apache-2.0 | MD5（EVP MD5） |
| `libubus` / `libubox` | LGPL-2.1 | ubus 总线（条件编译） |

### 运行时内核模块

- `kmod-br-netfilter`（二层认证必需）

### 内嵌源码

| 组件 | 许可证 | 位置 |
|---|---|---|
| cJSON | MIT | `src/cJSON.c / cJSON.h` |

### 内嵌前端资源（`files/` 下）

- Bootstrap（MIT）、avalon.js（MIT）、mmPromise.js / mmRequest.js（MIT）、dkjson Lua（MIT）

完整第三方归属与 LGPL-2.1 替换说明见 [NOTICE](./NOTICE) 和 `Documents/webauthd/README.md`。

---

## 相关文档  |  Related Documentation

> 文档网站 **http://monkfish.cn**
> Official documentation site: **http://monkfish.cn**

### 中文

以下为随仓库附带的 webauthd 主题文档摘要，全部位于 `Documents/` 目录。

| 主题 | 摘要 |
|---|---|
| 包总览（webauthd/README） | 许可证体系总览（GPL-3.0-or-later + 内嵌 MIT）、LGPL-2.1 动态链接替换声明、第三方库完整归属表、仓库布局说明。 |
| UCI 配置详解（WEBAUTHD_CONF） | `/etc/config/webauthd` 每个配置项的类型、默认值、可取值范围；含 `generic`/`portal`/`radius`/`redirect`/`white_list` 全字段表；LuCI Lua 读写示例和服务重启方式。 |
| HTTP 本地配置接口（local_config_http_api） | 绑定 `127.0.0.1:60000` 的配置写入接口，说明哪些字段可热更新、哪些字段写入 `pending.json` 后需重启生效；字段级错误码 `-1000~-1010` 定义。 |
| Portal 认证 API（PORTAL_AUTH_API） | `/v1/http_login`、`/v1/get_online_users`、`/v1/drop_user` 等 HTTP 接口的请求/响应结构、错误码（0 ~ -73）、前端对接建议（错误处理、会话信息解析、状态轮询）。 |
| UBUS API（UBUS_API） | `webauthd.session.list_users`（分页查询在线用户，默认 page_size=20）与 `drop_user`（username/ip/mac/session_id 多条件 AND，异步关闭）的完整调用手册、rpcd ACL 授权步骤、HTTP 经 rpcd 调用示例、常见故障排查。 |
| LuCI API（LUCI_API） | LuCI 页面通过 UCI + rpcd 调用 webauthd 的方式，`webauthd-params.html` 等页面的集成点。 |
| 控制协议（webauthd-control/v1） | 与 `xfrpc_loader` 之间的本机 Unix socket 协议：overlay 合并模型（effective = baseline ← overlay）、代际 `generation` 防乱序、租约 `lease_sec` 失联回退、热/冷字段分离、RADIUS 密钥不出现在日志/UCI 的安全要求。 |
| NFT 会话同步设计（NFT_SESSION_SYNC） | 冷启动从 nftables 规则反向重建 session 的恢复模式（mode 0/1/2）、定期审计（验证 handle 仍在）与残留规则清理逻辑的设计说明。 |
| 静态审计与修复报告（reports/） | 静态审计评估（正确性/可靠性/泄漏）、段错误根因分析、2026-10-24 修复清单、NFT 规则清理修复、重构总结等工程化记录。 |

### English

The following documents ship with the repository under `Documents/`. Summaries are
provided here for quick navigation.

| Topic | Summary |
|---|---|
| Package overview (webauthd/README) | Complete license map (GPL-3.0-or-later + bundled MIT), full LGPL-2.1 dynamic-link replacement statement, third-party attribution table, repository layout walkthrough. |
| UCI configuration reference (WEBAUTHD_CONF) | Type / default / allowed-values table for every key under `generic`, `portal`, `radius`, `redirect`, `white_list`; LuCI Lua read/write examples; service restart procedure. |
| Local config HTTP API (local_config_http_api) | `127.0.0.1:60000` write interface; which fields are hot-updatable vs. written to `pending.json` and need a restart; field-level error codes `-1000~-1010`. |
| Portal auth API (PORTAL_AUTH_API) | Request/response shapes, error codes (0 ~ -73), and frontend integration notes for `/v1/http_login`, `/v1/get_online_users`, `/v1/drop_user`, etc. Covers error handling, session-info parsing, and optional status polling. |
| UBUS API (UBUS_API) | Full call manual for `webauthd.session.list_users` (paginated online-user query, default page_size=20) and `drop_user` (username/ip/mac/session_id multi-field AND, async close); rpcd ACL setup steps; HTTP-via-rpcd examples; troubleshooting table. |
| LuCI API (LUCI_API) | How LuCI pages drive webauthd through UCI + rpcd, including integration points for `webauthd-params.html`. |
| Control protocol (webauthd-control/v1) | Unix-socket protocol between webauthd and `xfrpc_loader`: overlay merge model (`effective = baseline ← overlay`), `generation` anti-reorder, `lease_sec` fallback, hot/cold field split, security rules that keep RADIUS secrets out of logs/UCI. |
| NFT session sync design (NFT_SESSION_SYNC) | Cold-start nftables→session recovery modes (0/1/2), periodic handle-liveness audit, and orphan-rule cleanup design notes. |
| Static audit & fix reports (reports/) | Static-audit assessments (correctness / reliability / leaks), segfault root-cause analysis, 2026-10-24 fix list, NFT rule-cleanup fix, refactoring summary, and other engineering records. |

---

## 许可证

Copyright (C) 2021-2026 MonkFish <5747844@qq.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the **GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version** (GPL-3.0-or-later).

See [COPYING](./COPYING) for the full license text, [NOTICE](./NOTICE)
for third-party attribution, and [AUTHORS](./AUTHORS) for contributors.
