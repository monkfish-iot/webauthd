# webauthd

**Web Authentication Daemon for OpenWrt / Embedded Linux**

[![中文](https://img.shields.io/badge/lang-中文-red.svg)](./README.md)
[![English](https://img.shields.io/badge/lang-English-blue.svg)](./README.en.md)

> License: GPL-3.0-or-later (see [COPYING](./COPYING))

`webauthd` is a **Portal authentication daemon** that runs on OpenWrt devices in the
MonkFish IoT ecosystem. Its responsibilities include:

- Pushing nftables redirect rules for unauthenticated clients, forcing a jump to the
  Portal page;
- Managing per-client online sessions (state machine, idle / accounting timeout,
  concurrent-user cap);
- Authenticating users via RADIUS, a local user database, or an HTTP interface;
- Once authenticated, lifting traffic in nftables and optionally enforcing per-user
  rate limits, traffic quotas, and session duration;
- Exposing online-user queries and force-disconnect over the **ubus** bus so LuCI
  pages and scripts can drive them;
- When co-located with `xfrpc_loader`, receiving cloud-supplied Portal / RADIUS
  overlay configuration over the **webauthd-control/v1** local control channel.

---

## Table of Contents  |  目录

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Repository Layout](#repository-layout)
- [Building](#building)
- [Runtime](#runtime)
- [Key UCI Configuration](#key-uci-configuration)
- [webauthd-control/v1 Control Protocol](#webauthd-controlv1-control-protocol)
- [API Overview](#api-overview)
- [Dependencies](#dependencies)
- [Related Documentation  \|  相关文档](#related-documentation--相关文档)
- [License](#license)

---

## Features

| Capability | Description |
|---|---|
| Portal types | Local Portal (`portal_type=1`), external Portal (`portal_type=2`), cloud Portal + nginx reverse-proxy cache (`portal_type=3`) |
| Auth sources | RADIUS, local UCI user database, HTTP(S) remote endpoint; switchable per build via `auth_source` |
| Auth layer | Layer 2 (bridge-netfilter + `brdnft.conf`) / Layer 3 (`rednft.conf`); bridge mode can be force-overridden by `/etc/bridge.mode` |
| DNS redirection | Built-in DNS server (udp/20053) intercepts unauthenticated clients' A queries when `capture_dns=1`, paired with an nft prerouting rule |
| Session management | Idle timeout, accounting interval, hourly accounting, MAC-based zero-touch auth (multiple MAC formats), whitelist bypass |
| NFT housekeeping | Rule recovery (session rebuild on cold start), periodic audit (handle liveness), orphan rule cleanup |
| Graceful shutdown | `SIGTERM/SIGINT/SIGQUIT/SIGHUP` go through the same Accounting-Stop / usage-flush path as a normal logout |
| ubus bus | `webauthd.session` object: `list_users` (paginated), `drop_user` (multi-field AND); disabled with `WEBAUTHD_UBUS=0` |
| Control protocol | Exchanges overlay state with `xfrpc_loader` over a Unix socket; supports generation, lease, hot / cold field split |

---

## Architecture Overview

```
                   ┌──────────────────────────────────────┐
   Client  ──→  Unauth ──→ nftables (webauthd_nat/filter) ──→ Allowed to Internet
                    │
                    │  First HTTP → 302 → Portal
                    ▼
            ┌───────┴─────────────────┐
            │  nginx / uhttpd          │  ← 20001/20443 serve Portal static pages
            └───────┬─────────────────┘      and reverse-proxy /v1/* API
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
│     │ ubus bus  │  │ Control     │   │ Local Config Service │  │
│     │ (query)   │  │ Client      │   │ (127.0.0.1:60000)    │  │
│     └───────────┘  │ (xfrpc_loader│   └──────────────────────┘  │
│                    │  overlay)    │                              │
│                    └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
                           │ dynamic rule injection
                           ▼
                  ┌──────────────────┐
                  │    nftables      │  webauthd_filter / webauthd_nat
                  └──────────────────┘
```

The event loop is driven by **libevent2**; every module shares a single
`struct inst_t` context.

---

## Repository Layout

```
webauthd/
├── Makefile                   # OpenWrt package definition (DEPENDS, install rules)
├── src/
│   ├── Makefile               # Cross-compile entry point; WEBAUTHD_UBUS switch
│   ├── main.c                 # Entry point: arg parsing, UCI load, service start,
│   │                          #   event loop, signal handling
│   ├── config.{c,h}           # UCI config load + control-protocol overlay merge
│   ├── instance.{c,h}         # Global inst_t lifecycle
│   ├── session.{c,h}          # Session pool (cap 256), state machine, walk callbacks
│   ├── timer.{c,h}            # Idle / accounting / audit timers
│   ├── portal_server.{c,h}    # /v1/http_login, /v1/get_online_users,
│   │                          #   /v1/drop_user and other HTTP handlers
│   ├── http_service.{c,h}     # Generic HTTP server framework (port 20002)
│   ├── http_auth.{c,h}        # HTTP(S) auth source (curl multi tied to event loop)
│   ├── local_auth.{c,h}       # Local UCI user DB + patrol kick + usage flush
│   ├── radius.{c,h}           # RADIUS client (auth + accounting + CoA)
│   ├── nft.{c,h}              # nftables rule add / delete
│   ├── nft_recovery.{c,h}     # Rebuild sessions from nft rules on cold start
│   ├── nft_audit.{c,h}        # Periodic handle-liveness check
│   ├── arp.{c,h}              # ARP table lookup (IP → MAC)
│   ├── app_events.{c,h}       # Cross-module event channel (EV_CLOSE_SESSION, etc.)
│   ├── control_client.{c,h}   # webauthd-control/v1 pull + pending apply
│   ├── ubus_service.{c,h}     # webauthd.session ubus object
│   ├── ws_users.{c,h}         # Online-user structs and calculations
│   ├── http_client.{c,h}      # curl wrapper
│   ├── utensils.{c,h}         # Misc helpers
│   ├── log.{c,h}              # Logging
│   └── cJSON.{c,h}            # Bundled third-party JSON parser (MIT)
│
└── files/
    ├── webauthd.conf         # Default UCI config template → /etc/config/webauthd
    ├── webauthd.init          # OpenWrt procd init script (START=97)
    ├── webauthd.acl.json      # rpcd ACL → /usr/share/rpcd/acl.d/webauthd.json
    ├── rednft.conf           # Layer-3 nft table template (webauthd_filter/nat)
    ├── brdnft.conf           # Layer-2 nft table template
    ├── defnft.conf           # Empty table cleanup on service shutdown
    ├── portal.conf           # nginx config (rebuilt dynamically by init)
    ├── https/                 # uhttpd HTTPS Portal assets
    ├── local_portal/          # Local Portal HTML/CSS/JS (Bootstrap + avalon.js)
    ├── upload_portal/         # Upload Portal + Lua CGI
    ├── www/                   # Web UI static assets
    ├── find_essid.sh          # Helper script installed under /usr/sbin
    └── helpme.sh              # Helper script installed under /sbin
```

---

## Building

### Option 1: Inside the OpenWrt SDK (recommended)

```sh
# from the OpenWrt buildroot root
make package/webauthd/compile V=s
```

Cross-compiles against the OpenWrt toolchain (`TARGET_CC`, `STAGING_DIR`)
and produces an IPK automatically.

### Option 2: Standalone cross-compile

```sh
cd webauthd/src
CC=mipsel-openwrt-linux-gcc make clean
CC=mipsel-openwrt-linux-gcc make
```

The product is the `webauthd` executable.

### Compile-time switches

| Switch | Default | Description |
|---|---|---|
| `WEBAUTHD_UBUS` | `1` | Compiles `ubus_service.c` and links `-lubus -lubox`. Set to `0` to drop the ubus bus (~a few KB off the binary) |
| `-DWEBAUTHD_ENABLE_UBUS=1` | — | Auto-appended via `override CFLAGS` in `src/Makefile`; tied to `WEBAUTHD_UBUS=1` |

Standalone build without ubus:

```sh
make WEBAUTHD_UBUS=0
```

---

## Runtime

### Services and ports

The `webauthd` process itself runs in the background (`daemon(1, 1)`). Default
endpoints it exposes:

| Port | Protocol | Purpose |
|---|---|---|
| `20001` | HTTP | nginx reverse proxy: Portal static pages + `/v1/get_portal_text` + `/v1/login` |
| `20443` | HTTPS | uhttpd (`-s 0.0.0.0:20443`) serves the HTTPS Portal |
| `20002` | HTTP | **webauthd's own HTTP service** (all `/v1/*` auth / query APIs actually listen here) |
| `20080` | HTTP | Online-user WebSocket (`start_ws_service`) |
| `20053` | UDP | DNS redirection (only when `capture_dns=1`) |
| `60000` | HTTP | **Local config interface** (bound to `127.0.0.1` only) |
| `/var/run/xfrpc_loader/webauthd-control.sock` | Unix socket | `webauthd-control/v1` local control channel |

> The init script (START=97) first configures nginx (pick local vs. cloud Portal,
> optional reverse-proxy cache), then loads the nft table template (Layer 2 or 3),
> and finally `exec /sbin/webauthd`.

### System components it depends on

| Component | Role |
|---|---|
| **nftables** | Rule push / query; kernel module `kmod-br-netfilter` required for Layer 2 |
| **nginx** | Reverse-proxy Portal (`portal_type=1` or `3`); the init script reloads it |
| **uhttpd** | HTTPS Portal (`-s 0.0.0.0:20443`) |
| **ubusd** | ubus bus daemon; if missing, webauthd degrades gracefully without touching mainline auth |
| **libcurl** | HTTP auth source (`auth_source=http`) |
| **dnsmasq** | Optional (Layer-2 bridge DNS scenarios) |

### Signal handling

| Signal | Behavior |
|---|---|
| `SIGTERM / SIGINT / SIGQUIT / SIGHUP` | Graceful shutdown: send RADIUS Accounting-Stop for each online AUTHED / FREE session → wait up to 2 s for replies → tear down sessions and exit |
| `SIGSEGV / SIGILL / SIGFPE` | Minimal async-safe action only (write to stderr), then `_exit`; no attempt at cleanup |

Stopping the service:

```sh
/etc/init.d/webauthd stop       # graceful shutdown + nginx/uhttpd/nft cleanup
/etc/init.d/webauthd restart
```

---

## Key UCI Configuration

**Path:** `/etc/config/webauthd`
**Format:** OpenWrt UCI

Minimal working snippet:

```text
config base 'generic'
    option enabled '1'
    option layer '3'                   # '2' = Layer 2 / '3' = Layer 3
    option portal_interface 'br-lan'
    option capture_dns '1'
    option idle_timeout '120'          # idle timeout in seconds
    option mac_auth '1'                # MAC zero-touch auth
    option auth_source 'radius'        # radius / local / http

config portal 'portal'
    option portal_type '3'             # 1 = local / 2 = external / 3 = cloud + proxy
    option portal_port '9091'
    option proxy_pass 'http://127.0.0.1:9091'
    option cache_enable '1'

config radius 'radius'
    option local_radius_client '1'     # '1' = use local parameters / '0' = wait for cloud
    option primary_auth_server '127.0.0.1'
    option primary_auth_port '1812'
    option primary_auth_secret 'testing123'
```

> For every configuration key with type, default, and allowed-values, see
> `Documents/webauthd/config/WEBAUTHD_CONF.md`.

---

## webauthd-control/v1 Control Protocol

When `xfrpc_loader` is present on the device, it pushes overlay state over a
Unix socket (`/var/run/xfrpc_loader/webauthd-control.sock`). webauthd actively
pulls, validates, and merges it. The final effective configuration is
`UCI baseline` ← `control overlay`.

- **Hot fields** (runtime-applicable): `auth.radius.*`, `portal.portal_url/server/port` —
  memory parameters / nginx config refreshed on the fly.
- **Cold fields** (require a restart): `portal.portal_type`, `auth.auth_source`,
  `auth.local_radius_client`, `generic.enabled` — written to
  `/var/run/webauthd/pending.json`, ACK carries `restart_required`.
- **Lease protection**: if no successful pull within `lease_sec`, clear the
  overlay and fall back to the baseline.

Details in `Documents/接口规范/webauthd控制协议.md`.

---

## API Overview

### HTTP API (built into webauthd, port 20002)

| Endpoint | Method | Description |
|---|---|---|
| `/v1/http_login` | GET / POST | Main Portal auth entry (username + password, or MAC zero-touch) |
| `/v1/get_portal_text` | GET | Read Portal page text / titles dynamically |
| `/v1/get_online_users` | GET | Complete online-user list (no pagination; the ubus variant paginates) |
| `/v1/drop_user` | GET | Force disconnect (match on any of ip / mac / username) |
| `/v1/get_user_by_ip` | GET | Query session by IP |
| `/v1/get_user_by_name` | GET | Query session by username |

> For the error-code scheme (0 = success, negative = failure), see
> `Documents/webauthd/api/PORTAL_AUTH_API.md`.

### ubus object: `webauthd.session`

| Method | Parameters | Description |
|---|---|---|
| `list_users` | `page`, `page_size` (optional) | Paginated online-user query |
| `drop_user` | `username` / `ip` / `mac` / `session_id` (at least one) | Force disconnect (async) |

```sh
ubus call webauthd.session list_users '{"page":1,"page_size":20}'
ubus call webauthd.session drop_user  '{"ip":"192.168.1.100"}'
```

> Before calling, make sure the ACL group in
> `/usr/share/rpcd/acl.d/webauthd.json` is granted to the current session
> (read for queries, write for drop).
> For field details, response shape, and error handling see
> `Documents/webauthd/api/UBUS_API.md`.

### Local config interface (127.0.0.1:60000 only)

UCI writes take effect immediately (some fields need a restart). See
`Documents/webauthd/config/local_config_http_api.md`.

---

## Dependencies

### Link-time libraries

| Library | License | Purpose |
|---|---|---|
| `libnftnl` / `libnftables` | GPL-2.0-or-later | nftables netlink API |
| `libuci` | **LGPL-2.1** | OpenWrt UCI config |
| `libnl` / `libmnl` | **LGPL-2.1** | netlink helpers |
| `libevent` (libevent2) | BSD-3-Clause | Event loop |
| `libcurl` | MIT-style | HTTP client (HTTP auth source) |
| `libsodium` | ISC | Cryptography |
| `libuuid` | BSD-3-Clause | UUID generation |
| `zlib` | zlib | Compression |
| `libopenssl` | Apache-2.0 | MD5 (EVP MD5) |
| `libubus` / `libubox` | LGPL-2.1 | ubus bus (conditionally compiled) |

### Runtime kernel modules

- `kmod-br-netfilter` (required for Layer-2 auth)

### Bundled source code

| Component | License | Location |
|---|---|---|
| cJSON | MIT | `src/cJSON.c / cJSON.h` |

### Bundled front-end assets (under `files/`)

- Bootstrap (MIT), avalon.js (MIT), mmPromise.js / mmRequest.js (MIT),
  dkjson Lua (MIT)

For the complete third-party attribution and the LGPL-2.1 replacement
statement, see [NOTICE](./NOTICE) and `Documents/webauthd/README.md`.

---

## Related Documentation  |  相关文档

> 文档网站 **http://monkfish.cn**
> Official documentation site: **http://monkfish.cn**

The summary table below covers all webauthd-themed documents that ship in
`Documents/` inside this repository.

| Topic | Summary |
|---|---|
| Package overview (webauthd/README) | Full license map (GPL-3.0-or-later + bundled MIT), complete LGPL-2.1 dynamic-link replacement statement, third-party attribution table, and repository layout walkthrough. |
| UCI configuration reference (WEBAUTHD_CONF) | Type / default / allowed-values table for every key under `generic`, `portal`, `radius`, `redirect`, `white_list`; LuCI Lua read/write examples; service restart procedure. |
| Local config HTTP API (local_config_http_api) | `127.0.0.1:60000` write interface; which fields are hot-updatable vs. written to `pending.json` and need a restart; field-level error codes `-1000~-1010`. |
| Portal auth API (PORTAL_AUTH_API) | Request / response shapes, error codes (0 ~ -73), and frontend integration notes for `/v1/http_login`, `/v1/get_online_users`, `/v1/drop_user`, etc. Covers error handling, session-info parsing, and optional status polling. |
| UBUS API (UBUS_API) | Full call manual for `webauthd.session.list_users` (paginated online-user query, default page_size=20) and `drop_user` (username/ip/mac/session_id multi-field AND, async close); rpcd ACL setup steps; HTTP-via-rpcd examples; troubleshooting table. |
| LuCI API (LUCI_API) | How LuCI pages drive webauthd through UCI + rpcd, including integration points for `webauthd-params.html`. |
| Control protocol (webauthd-control/v1) | Unix-socket protocol between webauthd and `xfrpc_loader`: overlay merge model (`effective = baseline ← overlay`), `generation` anti-reorder, `lease_sec` fallback, hot/cold field split, security rules that keep RADIUS secrets out of logs/UCI. |
| NFT session sync design (NFT_SESSION_SYNC) | Cold-start nftables→session recovery modes (0/1/2), periodic handle-liveness audit, and orphan-rule cleanup design notes. |
| Static audit & fix reports (reports/) | Static-audit assessments (correctness / reliability / leaks), segfault root-cause analysis, 2026-10-24 fix list, NFT rule-cleanup fix, refactoring summary, and other engineering records. |

---

## License

Copyright (C) 2021-2026 MonkFish <5747844@qq.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the **GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version** (GPL-3.0-or-later).

See [COPYING](./COPYING) for the full license text, [NOTICE](./NOTICE)
for third-party attribution, and [AUTHORS](./AUTHORS) for contributors.
