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
#ifndef PORTAL_SERVER_H
#define PORTAL_SERVER_H

#include "session.h"


#define HTTP_PORTAL_AUTH_ENABLED                    1
#define HW_PORTAL_AUTH_ENABLED                      2

#define LOCAL_PORTAL                        1

#define EXTERNAL_PORTAL                     2
#define CLOUD_PORTAL                        3


#define CMCC_PORTAL_PORT 2000




void ws_http_login_v1(struct evhttp_request *req, void *arg);
void ws_portal_redirected(struct evhttp_request* req, void* arg);
void ws_get_portal_text_v1(struct evhttp_request *req, void *arg);
// int push_portal_url(struct user_session_t* user);
int start_http_portal_service(struct inst_t* inst,   uint32_t port);
#endif /* PORTAL_SERVER_H */


