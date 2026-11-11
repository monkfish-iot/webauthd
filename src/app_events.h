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
#ifndef MY_EVENTS_H
#define MY_EVENTS_H

 
#include "session.h"


#define         EV_NEW_USER                 100
//#define         EV_USER_DROP_USER           101
//#define         EV_SESSION_TIMEOUT          102
#define         EV_AUTH_TIMEOUT             103
// #define         EV_AUTH_REQUEST             104
#define         EV_AUTH_ACCEPT              105
#define         EV_AUTH_REJECT              106
// #define         EV_UNAUTH_TIMEOUT           107
//#define         EV_ACCT_STOP                108
#define         EV_ACCOUNT_INTERVAL         109
// #define         EV_RECV_ACCT_UPDATE              110
// #define         EV_PUSH_PORTAL              112
#define         EV_UPDATE_CONFIG            113
 
#define         EV_CLOSE_SESSION            115
//#define         EV_REPLY_USER_STATUS        116
#define         EV_CLOSE_SESSION_ACK            117
// #define         EV_WAITTING_AUTH_TIMEOUT            118
#define         EV_RECV_COA                        119
// #define         EV_DELETE_USER                  120
// #define         EV_IDLE_CHECK_TIMER                  121


struct ev_act_t {
    int event;
    int (*events_func)(struct user_address_t* user_address, void* arg);
};


int process_server_events(int event, struct user_address_t* user_address, void* arg);
#endif /* EVENTS_H */


