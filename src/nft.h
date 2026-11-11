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
#ifndef NFT_H
#define NFT_H

#include <linux/netfilter/nf_tables.h>
#include "instance.h"
#include "session.h"

/* webauthd 专属 nft 命名空间：只在这两张表内工作，启动时仅 destroy 自有表，
 * 绝不 flush 全局 ruleset，与 inet mwan3 / ip wrthub / ip wrthub_qos 解耦共存 */
#define NFT_TABLE_FILTER "webauthd_filter"
#define NFT_TABLE_NAT    "webauthd_nat"


union nftnl_data_reg {
	struct {
		uint32_t	val[64 / sizeof(uint32_t)];
		uint32_t	len;
	};
	struct {
		uint32_t	verdict;
		const char	*chain;
		uint32_t	chain_id;
	};
};


struct nftnl_expr_cmp {
	union nftnl_data_reg	data;
	enum nft_registers	sreg;
	enum nft_cmp_ops	op;
};

struct nftnl_expr_counter {
	uint64_t	pkts;
	uint64_t	bytes;
};

union nftnl_data_reg2 {

    struct {
        uint32_t val[NFT_DATA_VALUE_MAXLEN / sizeof (uint32_t)];
        uint32_t len;
    };

    struct {
        uint32_t verdict;
        const char *chain;
        uint32_t chain_id;
    };
};






#define SNPRINTF_BUFFER_SIZE(ret, remain, offset) \
        if (ret < 0)     \
                ret = 0;    \
        offset += ret;     \
        if (ret > remain)    \
                ret = remain;    \
        remain -= ret;     \
        

struct list_head2 {
    struct list_head2 *next, *prev;
};

struct expr_ops2 {
    const char *name;

};

struct nftnl_expr2 {
    struct list_head2 head;
    uint32_t flags;
    struct expr_ops2 *ops;
    uint8_t data[];
};

struct nftnl_rule2 {
    struct list_head2 head;

    uint32_t flags;
    uint32_t family;
    const char *table;
    const char *chain;
    uint64_t handle;
    uint64_t position;
    uint32_t id;
    uint32_t position_id;

    struct {
        void *data;
        uint32_t len;
    } user;

    struct {
        uint32_t flags;
        uint32_t proto;
    } compat;

    struct list_head2 expr_list;
};

 #define nftnl_expr_data(ops) (void *)ops->data

int remove_authed_ip(struct user_session_t* user);
 int insert_authed_ip(struct user_session_t* user);
 int start_flush_sessions_timer(struct inst_t* inst);
int stop_flush_sessions_timer(struct inst_t* inst);
 int run_nft_rule(char* cmd);
 struct nft_ctx* init_nft_ctx(void);

/* 按 IP + 方向(saddr/daddr) 在指定表/链中查规则 handle, 找不到返回 0。
 * 用于 nft_audit 在 handle 过期漂移时兜底重查, 以及修复 handle 字段。 */
uint64_t get_rule_handle_by_ip_and_direction(struct nft_ctx* nft,
                                              const char* table_name,
                                              const char* chain_name,
                                              const char* ip_addr,
                                              const char* direction);
#endif /* NFT_H */


