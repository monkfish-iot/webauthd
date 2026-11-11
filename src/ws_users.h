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
#ifndef WS_USERS_H
#define WS_USERS_H
#include <event2/http.h>
#include <event2/http_struct.h>
void ws_get_user_by_ip_v1(struct evhttp_request *req, void *arg);
void ws_get_user_by_name_v1(struct evhttp_request *req, void *arg);

void ws_show_online_users_v1(struct evhttp_request *req, void *arg);
void ws_drop_user_v1(struct evhttp_request *req,void *arg);

void print_user_info(struct user_session_t* user);


#endif /* WS_USERS_H */


