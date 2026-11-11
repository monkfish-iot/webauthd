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
#ifndef UTENSILS_H__
#define UTENSILS_H__

#include <stdint.h>

#include "session.h"

#define XMAC_BLEN 6
#define XMAC_SLEN 17
#define MAX_ESSID_LENGTH 32  // 假设 SSID 的最大长度为 32


int generate_acct_id(char *buf, int size);


int get_rand(size_t len, unsigned char* value);

uint64_t mac_8_to_64(uint8_t mac[]);
void mac_64_to_8(uint64_t u64_mac, uint8_t u8_mac[]);

uint32_t get_now_hour_timestamp();






uint32_t get_next_local_hour();
//  将二进制的MAC地址转换为字符串形式
int xmac_to_str(unsigned char *b, int len, char *s, int size);
long get_now_time();
int xmac_to_byte(const char *s, int len, unsigned char *b, int size);

int get_all_if();
int set_portal_address(struct user_session_t* user, const char* portal_if);
int get_local_address(char* ip,char* mac);
char* get_if_address(char* if_name);

uint32_t get_next_hour_interval();
int find_essid(const char* user_mac, char* essid);

uint32_t get_now_timestamp();
int set_nonblock(int fd);
int  get_dns_server(char* buf) ;
 
#endif /* UTENSILS_H__ */

