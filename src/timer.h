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
#ifndef TIMER_H
#define TIMER_H
#include "session.h"
#include "utensils.h"


struct unauthed_timer_t {
    struct event timer;
    char session_id[128];
};


int start_unauthed_timer(struct user_session_t* user);
int stop_unauthed_timer(struct user_session_t* user);
int stop_session_timer(struct user_session_t* user);
int start_session_timer(struct user_session_t* user);
int start_update_accounting_timer(struct user_session_t* user);
int stop_update_accounting_timer(struct user_session_t* user);
int start_droping_timer(struct user_session_t* user);
int start_nft_revoke_retry(struct user_session_t* user, int delete_on_success);
int stop_nft_revoke_retry(struct user_session_t* user);

int start_bypass_timer(struct inst_t* inst) ;

int start_auth_timer(struct inst_t* inst, struct user_session_t* user);
int stop_auth_timer(  struct user_session_t* user);


int start_idle_check_timer(struct user_session_t* user);
int stop_idle_check_timer(struct user_session_t* user) ;

int stop_unauthed_timer(struct user_session_t * user);
int close_session_all_timers(struct user_session_t* user);

int start_waitting_acct_response_timer(struct user_session_t * user);
int stop_waitting_acct_response_timer(struct user_session_t * user);

int start_check_data_timer(struct user_session_t * user);
int stop_check_data_timer(struct user_session_t * user);

//int start_delay_acct_stop_timer(struct user_session_t * user);
//int stop_delay_acct_stop_timer(struct user_session_t * user);

int stop_waiting_auth_timer(struct user_session_t* user);
int start_waiting_auth_timer(struct user_session_t* user) ;
int start_check_data_timer(struct user_session_t* user);
//int start_test_timer( struct inst_t* inst);
#endif /* TIMER_H */


