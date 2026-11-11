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
#include "radius.h"

#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>
#include <fcntl.h>  // for open
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>  // for close

#include "app_events.h"
#include "cJSON.h"
#include "config.h"
#include "instance.h"
#include "log.h"
#include <openssl/md5.h>
#include "nft.h"
#include "portal_server.h"
#include "http_service.h"
#include "session.h"
#include "timer.h"
#include "utensils.h"

int init_radius(struct inst_t* inst) {
  if (!inst->config) {
    return -1;
  }
  inst->rad_auth_port = inst->config->primary_auth_port;
  inst->auth_server.sin_family = AF_INET;
  inst->auth_server.sin_port = htons(inst->rad_auth_port);
  inst->rad_auth_server = inst->config->primary_auth_server;
  if (inet_pton(AF_INET, inst->rad_auth_server,
                &inst->auth_server.sin_addr.s_addr) != 1) {
    log_error("Invalid auth server IP address: %s", inst->rad_auth_server);
    return -1;
  }
  inst->rad_auth_secret = inst->config->primary_auth_secret;

  inst->rad_acct_port = inst->config->primary_acct_port;
  inst->acct_server.sin_family = AF_INET;
  inst->acct_server.sin_port = htons(inst->rad_acct_port);
  inst->rad_acct_server = inst->config->primary_acct_server;
  if (inet_pton(AF_INET, inst->rad_acct_server,
                &inst->acct_server.sin_addr.s_addr) != 1) {
    log_error("Invalid accounting server IP address: %s",
              inst->rad_acct_server);
    return -1;
  }
  log_debug("acct server =%s:%u", inst->rad_acct_server, inst->rad_acct_port);
  inst->rad_acct_secret = inst->config->primary_acct_secret;
  /* 共享密钥属于凭据, 不得写入日志; 仅记录是否已配置及其长度 */
  log_debug("radius secrets: auth=%s(%zu bytes) acct=%s(%zu bytes)",
            inst->rad_auth_secret[0] ? "set" : "empty",
            strlen(inst->rad_auth_secret),
            inst->rad_acct_secret[0] ? "set" : "empty",
            strlen(inst->rad_acct_secret));
inst->nas_ip = inst->config->nas_ip;
  inst->rad_coa_secret = inst->config->coa_secret;
  return 0;
}

uint32_t get_u32_value(struct attributes_t* attr) {
  uint8_t* p = attr->value;
  uint32_t v = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
               (uint32_t)p[2] << 8 | (uint32_t)p[3];
  return v;
}

size_t set_u32_value(struct attributes_t* attr, uint32_t u32_value) {
  uint32_t* p = (uint32_t*)attr->value;
  attr->length = 6;
  *p = u32_value;
  return 4;
}

size_t set_string_value(struct attributes_t* attr, char* str_value,
                        size_t len) {
  memset(attr->value, 0, MAX_ATTR_SIZE);

  memcpy(attr->value, str_value, len);
  attr->length = len + 2;
  //   printf("len=%d id=%s\n", len, (char*) attr->value);
  return len;
}

int parse_vendor_attr(struct user_session_t* user,
                      struct attributes_t* vattrs) {
  uint8_t p = 6; /* outer type+len(2) + Vendor-Id(4) */
  uint8_t length;
  uint32_t vendor_id;
  uint32_t in_rate, out_rate, quota_bytes, quota_giga;
  uint32_t max_parallel, parallel_policy, hours_rule, weeks_rule;

  if (!user || !vattrs || vattrs->length < 8) {
    log_error("Invalid vendor attribute header");
    return -1;
  }
  length = vattrs->length;
  vendor_id = (uint32_t)vattrs->value[0] << 24 |
              (uint32_t)vattrs->value[1] << 16 |
              (uint32_t)vattrs->value[2] << 8 |
              (uint32_t)vattrs->value[3];

  /* Parse into candidates first.  A malformed later subattribute must not
   * leave a partially-applied VSA while the packet is reported successful. */
  in_rate = user->in_rate;
  out_rate = user->out_rate;
  quota_bytes = user->quota_bytes;
  quota_giga = user->quota_giga_bytes;
  max_parallel = user->max_parallel;
  parallel_policy = user->parallel_policy;
  hours_rule = user->hours_rule;
  weeks_rule = user->weeks_rule;

  while (p < length) {
    struct attributes_t* attr;
    uint8_t attr_len;
    uint32_t value;

    if ((uint16_t)p + 2 > length) {
      return -1;
    }
    attr = (struct attributes_t*)((uint8_t*)vattrs + p);
    attr_len = attr->length;
    if (attr_len < 2 || (uint16_t)p + attr_len > length) {
      log_error("Malformed vendor subattribute: vendor=%u offset=%u len=%u",
                vendor_id, p, attr_len);
      return -1;
    }

    if (vendor_id == MONKFISH_VENDOR_ID) {
      switch (attr->type) {
        case MONKFISH_INPUT_AVERAGE_RATE:
        case MONKFISH_OUTPUT_AVERAGE_RATE:
        case MONKFISH_QUOTA_DATA:
        case MONKFISH_QUOTA_GIGA_DATA:
        case MONKFISH_MAX_PARALLEL:
        case MONKFISH_PARALLEL_POLICY:
        case MONKFISH_HOURS_RULE:
        case MONKFISH_WEEKS_RULE:
          if (attr_len != 6) {
            log_error("Vendor integer subattribute has invalid len=%u",
                      attr_len);
            return -1;
          }
          break;
        default:
          break;
      }
    } else if (vendor_id == HUAWEI &&
               (attr->type == HUAWEI_INPUT_AVERAGE_RATE ||
                attr->type == HUAWEI_OUTPUT_AVERAGE_RATE) &&
               attr_len != 6) {
      log_error("Huawei rate subattribute has invalid len=%u", attr_len);
      return -1;
    }

    value = attr_len == 6 ? get_u32_value(attr) : 0;
    if (vendor_id == MONKFISH_VENDOR_ID) {
      switch (attr->type) {
        case MONKFISH_INPUT_AVERAGE_RATE: in_rate = value; break;
        case MONKFISH_OUTPUT_AVERAGE_RATE: out_rate = value; break;
        case MONKFISH_QUOTA_DATA: quota_bytes = value; break;
        case MONKFISH_QUOTA_GIGA_DATA: quota_giga = value; break;
        case MONKFISH_MAX_PARALLEL: max_parallel = value; break;
        case MONKFISH_PARALLEL_POLICY: parallel_policy = value; break;
        case MONKFISH_HOURS_RULE: hours_rule = value; break;
        case MONKFISH_WEEKS_RULE: weeks_rule = value; break;
        default: break;
      }
    } else if (vendor_id == HUAWEI) {
      /* Huawei uses the inner TLV type, not the outer Type 26. */
      if (attr->type == HUAWEI_OUTPUT_AVERAGE_RATE) {
        in_rate = value;   /* download */
      } else if (attr->type == HUAWEI_INPUT_AVERAGE_RATE) {
        out_rate = value;  /* upload */
      }
    }
    p = (uint8_t)(p + attr_len);
  }

  user->in_rate = in_rate;
  user->out_rate = out_rate;
  user->quota_bytes = quota_bytes;
  user->quota_giga_bytes = quota_giga;
  user->max_parallel = max_parallel;
  user->parallel_policy = parallel_policy;
  user->hours_rule = hours_rule;
  user->weeks_rule = weeks_rule;
  return 0;
}

int parse_radpkg(struct user_session_t* user, struct radius_packet_t* rad_pkg) {
  // uint32_t *tmp_u32;

  char* tmp_str;
  //   uint8_t *a = NULL;
  // uint8_t code = rad_pkg->code;
  uint16_t pkg_len = ntohs(rad_pkg->length);
  uint16_t attr_len_total;
  uint16_t p = 0;
  uint8_t attr_len;
  uint32_t tmp_u32;
  struct attributes_t* attr;

  /* 报文长度合法性: RADIUS 头固定 20 字节; 本端 recvfrom 缓冲为
   * MAX_ATTRIB_SIZE, length 超过即被恶意构造或截断, 拒绝解析防越界读。 */
  if (pkg_len < 20 || pkg_len > MAX_ATTRIB_SIZE) {
    log_error("parse_radpkg: invalid pkg_len=%u", pkg_len);
    return -1;
  }
  attr_len_total = pkg_len - 20;
  attr = (struct attributes_t*)(rad_pkg->attributes);
  /*
      if (code != PW_AUTHENTICATION_ACK) {
          return -1;
      }
   */
  //   printf("++++pkg len=%u  type=%u len=%u\n", pkg_len, attr->type,
  //   attr->length);
  while (p + 2 <= attr_len_total) {
    attr = (struct attributes_t*)(rad_pkg->attributes + p);
    attr_len = attr->length;
    /* 属性至少需 type+length 两字节, 且不得越过属性区末尾 */
    if (attr_len < 2 || p + attr_len > attr_len_total) {
      log_error("parse_radpkg: bad attr_len=%u at p=%u", attr_len, p);
      return -1;
    }
    //  printf("type=%u attr_len=%u p =%u\n", attr->type, attr_len, p);
    switch (attr->type) {
      case PW_SESSION_TIMEOUT:
        if (attr_len != 6) {
          return -1;
        }
        tmp_u32 = get_u32_value(attr);
        if (tmp_u32 > 0) {
          user->session_timeout = (tmp_u32 > MAX_SESSION_TIMEOUT) ? MAX_SESSION_TIMEOUT : tmp_u32;
        }

        break;
      case PW_ACCT_SESSION_ID: {
        size_t cp = attr_len - 2;
        if (cp > sizeof(user->acct_session_id) - 1) {
          cp = sizeof(user->acct_session_id) - 1;   /* 防止长属性越界写 */
        }
        tmp_str = (char*)attr->value;
        memset(user->acct_session_id, 0, sizeof(user->acct_session_id));
        memcpy(user->acct_session_id, tmp_str, cp);
        break;
      }
      case PW_FRAMED_IP_ADDRESS:
        /* Portal 认证场景下 user->ip 是用户真实源 IP，
         * 用于 nft 规则匹配、会话查找和计费 Framed-IP，
         * 绝不能被 RADIUS 返回的 Framed-IP-Address 覆盖，
         * 否则 nft 规则会写到错误的 IP（如网关）上导致用户无法上网。
         * 这里仅记录日志，便于排查 RADIUS 侧是否下发了该属性。 */
        if (attr_len != 6) {
          return -1;
        }
        tmp_u32 = get_u32_value(attr);
        if (tmp_u32 > 0) {
          struct in_addr framed_ip;
          framed_ip.s_addr = tmp_u32;
          log_debug(
              "RADIUS returned Framed-IP-Address=%s, ignored (keep user "
              "real ip)",
              inet_ntoa(framed_ip));
        }
        break;
      case PW_CALLED_STATION_ID:
        /* 需含 type+length+6 字节 value, 否则 value 越界读 */
        if (attr_len >= 8) {
          memcpy(user->called_station_id, attr->value, 6);
        }
        break;
      case PW_CALLING_STATION_ID:
        if (attr_len >= 8) {
          memcpy(user->mac, attr->value, 6);
        }
        break;

      case PW_IDLE_TIMEOUT:
        if (attr_len != 6) {
          return -1;
        }
        tmp_u32 = get_u32_value(attr);
        if (tmp_u32 > 0) {
          user->idle_timeout = tmp_u32;
        }
        /*
                        if (attr_len != 6) {
                            log_error("The length of attribute(%d)=%d is
         invalid", PW_IDLE_TIMEOUT, attr_len - 2); } else {

                            a = (uint8_t *) attr->value;
         *tmp_u32 = a[0] << 24 | a[1] << 16 | a[2] << 8 | a[3];
                            user->idle_timeout = *tmp_u32;
                        }
         */

        break;
      case PW_ACCT_INTERIM_INTERVAL:
        if (attr_len != 6) {
          return -1;
        }
        tmp_u32 = get_u32_value(attr);
        if (tmp_u32 > 0) {
          user->acct_interval = tmp_u32;
          log_info(
              "RADIUS Access-Accept provided Acct-Interim-Interval=%us, "
              "use it as the accounting update period",
              tmp_u32);
        } else {
          log_debug(
              "RADIUS Access-Accept Acct-Interim-Interval=0, keep local "
              "acct_interval=%d",
              user->inst->config->acct_interval);
        }
        break;
      case PW_USER_NAME: {
         //printf("+++++++++++++++++++++user->authtype=%d\n",user->authtype);
          tmp_str = (char*)attr->value;
          size_t cp = attr_len - 2;
          if (cp > sizeof(user->user_name) - 1) {
            cp = sizeof(user->user_name) - 1;   /* 防止长属性越界写 */
          }
          memset(user->user_name, 0, sizeof(user->user_name));
          memcpy(user->user_name, tmp_str, cp);
          break;
      }
      case PW_REPLY_MESSAGE:
        break;
      case PW_VENDOR_SPECIFIC:
        if (parse_vendor_attr(user, attr) != 0) {
          return -1;
        }

        break;
      default:
        break;
    }

    p = p + attr_len;
    // printf("p=%u pkg_len=%u\n", p, pkg_len);
  }

  if (p != attr_len_total) {
    log_error("parse_radpkg: truncated trailing attribute bytes");
    return -1;
  }

  /*
      printf("+++++\n session_timeout=%u  idle_timeout=%ld interval=%u
     \n++++\n", user->session_timeout, user->idle_timeout, user->acct_interval);
   */

  return 0;
}

size_t generate_pap_passwd(struct user_session_t* user,
                           const char* userpassword, size_t len,
                           uint8_t* pap_password) {
  struct inst_t* inst = user->inst;
  const char* secret = inst->config->primary_auth_secret;
  size_t secretlen = strlen(secret);
  MD5_CTX ctx;
  uint8_t md5[16] = {0};
  size_t pap_len = 0;

  int pos = 0;
  int i = 0;
  if (len % 16 != 0) {
    pap_len = (len / 16) * 16 + 16;
  } else {
    pap_len = len;
  }

  memcpy(md5, user->rad_authenticator, 16);

  for (pos = 0; pos < pap_len; pos += 16) {
    MD5_Init(&ctx);
    MD5_Update(&ctx, secret, secretlen);
    MD5_Update(&ctx, md5, MD5_DIGEST_LENGTH);
    MD5_Final(md5, &ctx);
    for (i = 0; i < 16; i++) {
      /* 按字节判断是否仍在明文范围内, 避免最后一个非整块时
       * 对 userpassword 越界读 */
      if (pos + i < len) {
        pap_password[pos + i] = (md5[i] ^= userpassword[pos + i]);
      } else {
        pap_password[pos + i] = (md5[i] ^= 0);
      }
    }
  }

  return pap_len;
}

size_t add_attr(struct user_session_t* user, struct attributes_t* attr,
                uint8_t type, size_t offset) {
  size_t len = 0;
  uint32_t l_u32;
  uint32_t h_u32;
  struct in_addr dev_ip;
  struct inst_t* inst = user->inst;
  struct attributes_t* a = (void*)attr + offset;
  memset(a, 0, sizeof(struct attributes_t));
  char str_mac[96] = {0};
  a->type = type;
  switch (type) {
    case PW_ACCT_STATUS_TYPE:
      len = set_u32_value(a, htonl(user->acct_status_type));
      break;
    case PW_USER_NAME:
      len = strlen(user->user_name);
      a->length = (uint8_t)len + 2;
      memcpy(a->value, user->user_name, len);
      break;
    case PW_USER_PASSWORD:
      len = generate_pap_passwd(user, user->user_password,
                                strlen(user->user_password), a->value);
      a->length = len + 2;
      break;
    case PW_FRAMED_IP_ADDRESS:
      a->length = 6;
      len = set_u32_value(a, user->ip);
      break;
    case PW_CALLING_STATION_ID:
      memset(str_mac, 0, 20);
      snprintf(str_mac, 20, "%02X:%02X:%02X:%02X:%02X:%02X", user->mac[0],
               user->mac[1], user->mac[2], user->mac[3], user->mac[4],
               user->mac[5]);
      len = strlen(str_mac);
      a->length = (uint8_t)len + 2;
      memcpy(a->value, str_mac, len);
      break;
    case PW_CALLED_STATION_ID:
      memset(str_mac, 0, 96);

      if (user->essid[0] > 0) {
        snprintf(str_mac, 96, "%02X:%02X:%02X:%02X:%02X:%02X:%s",
                 (u_int8_t)inst->dev_mac[0], (u_int8_t)inst->dev_mac[1],
                 (u_int8_t)inst->dev_mac[2], (u_int8_t)inst->dev_mac[3],
                 (u_int8_t)inst->dev_mac[4], (u_int8_t)inst->dev_mac[5],
                 user->essid);
      } else {
        snprintf(str_mac, 20, "%02X:%02X:%02X:%02X:%02X:%02X",
                 (u_int8_t)inst->dev_mac[0], (u_int8_t)inst->dev_mac[1],
                 (u_int8_t)inst->dev_mac[2], (u_int8_t)inst->dev_mac[3],
                 (u_int8_t)inst->dev_mac[4], (u_int8_t)inst->dev_mac[5]);
      }
      len = strlen(str_mac);
      a->length = (uint8_t)len + 2;
      memcpy(a->value, str_mac, len);
      break;
    case PW_FILTER_ID: {
      /* 取值来自配置里的 tenant_org_id(基准值), 不再是登录页下发的 org_id */
      len = strlen(inst->config->tenant_org_id);
      if (len == 0) {
        // tenant_org_id 为空时跳过该属性
        return 0;
      }
      if (len > 253) {
        len = 253;  // RADIUS 单属性 value 上限
      }
      a->length = (uint8_t)len + 2;
      memcpy(a->value, inst->config->tenant_org_id, len);
      break;
    }
    case PW_NAS_IDENTIFIER  :
      len = strlen(inst->device_id);
      a->length = (uint8_t)len + 2;
      memcpy(a->value, inst->device_id, len);
      break;
    case PW_NAS_IP_ADDRESS:

      if (user->inst->config->nas_ip[0] > 0) {
        inet_aton(user->inst->config->nas_ip, &dev_ip);
      } else if (user->inst->config->nas_if[0] > 0) {
        char* ip = get_if_address(user->inst->config->nas_if);
        if (!ip) {
          return 0;
        }
        // printf("++++++++++++++++if=%s++++++++ip=%s\n",user->inst->config->nas_if,ip);
        inet_aton(ip, &dev_ip);
        free(ip); // 释放内存，避免泄漏
      } else {
        inet_aton(user->inst->dev_ip, &dev_ip);
      }
      len = set_u32_value(a, dev_ip.s_addr);

      break;
    case PW_ACCT_SESSION_ID:
      len = strlen(user->acct_session_id);
      a->length = (uint8_t)len + 2;
      memcpy(a->value, user->acct_session_id, len);

      break;

    case PW_ACCT_SESSION_TIME:
      uint32_t session_time = (user->session_time);
      len = set_u32_value(a, htonl(session_time));

      break;
    case PW_ACCT_INPUT_OCTETS:
      l_u32 = user->inbytes & 0XFFFFFFFF;

      // printf("user->inbytes=%"PRIu64" h=%u
      // l=%u\n",user->inbytes,h_u32,l_u32);
      len = set_u32_value(a, htonl(l_u32));
      break;
    case PW_ACCT_OUTPUT_OCTETS:
      l_u32 = user->outbytes & 0XFFFFFFFF;
      len = set_u32_value(a, htonl(l_u32));
      break;
    case PW_ACCT_INPUT_GIGAWORDS:
      h_u32 = (user->inbytes >> 32) & 0XFFFFFFFF;
      len = set_u32_value(a, htonl(h_u32));
      break;
    case PW_ACCT_OUTPUT_GIGAWORDS:
      h_u32 = (user->outbytes >> 32) & 0XFFFFFFFF;
      len = set_u32_value(a, htonl(h_u32));
      break;

    default:
      break;
  }
  offset = offset + len + 2;
  return offset;
}

static const char* rad_code_name(uint8_t code);
static const char* acct_status_name(uint32_t status);
static int verify_response_authenticator(struct user_session_t* user,
                                         struct radius_packet_t* rad_pkg,
                                         ssize_t rn, const char* secret);

void print_radpkg(struct radius_packet_t* rad_pkg) {
  log_debug("code=%d id=%u \n", rad_pkg->code, rad_pkg->identifier);
}

void radacct_response_cb(int fd, short what, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  struct radius_packet_t rad_pkg = {0};
  //printf("+++++++++++++++++10\n");
  ssize_t rn = recvfrom(fd, (void*)&rad_pkg, MAX_ATTRIB_SIZE, 0, NULL, 0);
if(!user){
  log_error("radacct_response_cb not found user");
    return;
}
  char ip_str[INET_ADDRSTRLEN] = {0};
  struct in_addr tmp;
  tmp.s_addr = user->ip;
  inet_ntop(AF_INET, &tmp, ip_str, sizeof(ip_str));
  log_info(
      "RADIUS accounting response recv: code=%u(%s) id=%u bytes=%zd, "
      "acct-type=%s user='%s' ip=%s",
      rad_pkg.code, rad_code_name(rad_pkg.code), rad_pkg.identifier, rn,
      acct_status_name(user->acct_status_type), user->user_name, ip_str);

  /* 校验 identifier 与本端发出的请求一致, 并校验 Response Authenticator,
   * 防止伪造/重放应答被误当成合法状态推进。 */
  if (rad_pkg.identifier != user->rad_id) {
    log_error("RADIUS accounting response id mismatch: got=%u expect=%u",
              rad_pkg.identifier, user->rad_id);
    user_put(user);
    return;
  }
  if (rad_pkg.code != PW_ACCOUNTING_RESPONSE) {
    log_error("Unexpected RADIUS accounting response code=%u, discard",
              rad_pkg.code);
    user_put(user);
    return;
  }
  if (verify_response_authenticator(user, &rad_pkg, rn,
                                    user->inst->rad_acct_secret) != 0) {
    log_error("RADIUS accounting response authenticator invalid, discard");
    user_put(user);
    return;
  }

  stop_waitting_acct_response_timer(user);
 
  // stop_waitting_acct_response_timer(user);
//process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
  // recvfrom(fd, (void*) &rad_pkg, MAX_ATTRIB_SIZE, 0, NULL, 0);
  //   recvfrom(user->rad_acct_fd, (void*) &rad_pkg, MAX_ATTRIB_SIZE, 0, NULL,
  //   0);

  log_debug("account(type=%u) response", user->acct_status_type);

  if (user->ev_rad_acct) {
    event_del(user->ev_rad_acct);
    event_free(user->ev_rad_acct);
    user->ev_rad_acct = NULL;
  }

  close(user->rad_acct_fd);
  user->rad_acct_fd = -1;
// printf("+++++++++++++++user->acct_status_type=%d\n", user->acct_status_type);
  if (user->acct_status_type == PW_STATUS_START) {
    // stop_waitting_acct_response_timer(user);
    //  start_idle_timer(user);
    log_info(
        "RADIUS accounting Start acknowledged, open access for user='%s' ip=%s",
        user->user_name, ip_str);

    if (user->nft_rules_state != NFT_RULES_ACTIVE) {
      log_error("Accounting Start acknowledged without active NFT rules, "
                "user='%s' ip=%s", user->user_name, ip_str);
      user_put(user);
      return;
    }
    start_session_timer(user);

    start_update_accounting_timer(user);
    user_put(user);
    return;
  }

  if (user->acct_status_type == PW_STATUS_STOP) {
    //    stop_stop_acct_timer(user);
    stop_waitting_acct_response_timer(user);
    log_info(
        "RADIUS accounting Stop acknowledged, delete user='%s' ip=%s "
        "session-id='%s'",
        user->user_name, ip_str, user->acct_session_id);

//close_session_all_timers(user);
// 只有在用户曾经认证成功且handle已设置时才删除nft规则
if (remove_authed_ip(user) != 0) {
    log_error("Accounting Stop acknowledged but NFT revoke failed, keep "
              "session for retry ip=%s", ip_str);
    start_nft_revoke_retry(user, 1);
    user_put(user);
    return;
}
 del_user(user->inst, user);
    // process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
    //   user->acct_enable = 0;
    //  start_droping_timer(  user);
    // if (user->status == USER_STATE_DROPPING) {
    //   if (remove_authed_ip(user) == 0) {
    //   //  printf("++++++++++++2\n");
    //     stop_delay_acct_stop_timer(user);
    //     del_user(user->inst, user);
    //   }
    // }

    //   del_user(user->inst, user);

    //  process_server_events(EV_CLOSE_SESSION, NULL, (void *)user);

    //  printf("++++++++++++++stop acct\n");
  }
  user_put(user);
}

void radauth_response_cb(int fd, short what, void* arg) {
  struct user_session_t* user = user_get((struct user_session_t*)arg);
  struct radius_packet_t rad_pkg = {0};
  if (!user) {
    log_error("radauth_response_cb not found user");
    recvfrom(fd, (void*)&rad_pkg, MAX_ATTRIB_SIZE, 0, NULL, 0);
    return;
  }


 // printf("++++++++++++++\n");
  ssize_t rn = recvfrom(fd, (void*)&rad_pkg, MAX_ATTRIB_SIZE, 0, NULL, 0);

  // recvfrom(user->rad_auth_fd, (void*) &rad_pkg, MAX_ATTRIB_SIZE, 0, NULL, 0);
  {
    char ip_str[INET_ADDRSTRLEN] = {0};
    struct in_addr tmp;
    tmp.s_addr = user->ip;
    inet_ntop(AF_INET, &tmp, ip_str, sizeof(ip_str));
    log_info(
        "RADIUS auth response recv: code=%u(%s) id=%u bytes=%zd, "
        "user='%s' ip=%s",
        rad_pkg.code, rad_code_name(rad_pkg.code), rad_pkg.identifier, rn,
        user->user_name, ip_str);
  }

  /* 校验 identifier 与本端发出的请求一致, 并校验 Response Authenticator,
   * 防止伪造/重放应答被误当成合法状态推进。 */
  if (rad_pkg.identifier != user->rad_id) {
    log_error("RADIUS auth response id mismatch: got=%u expect=%u",
              rad_pkg.identifier, user->rad_id);
    user_put(user);
    return;
  }
  if (rad_pkg.code != PW_AUTHENTICATION_ACK &&
      rad_pkg.code != PW_AUTHENTICATION_REJECT) {
    log_error("Unexpected RADIUS authentication response code=%u, discard",
              rad_pkg.code);
    user_put(user);
    return;
  }
  if (verify_response_authenticator(user, &rad_pkg, rn,
                                    user->inst->rad_auth_secret) != 0) {
    log_error("RADIUS auth response authenticator invalid, discard");
    user_put(user);
    return;
  }

  close(user->rad_auth_fd);
  user->rad_auth_fd = -1;

  stop_auth_timer(user);

  if (user->ev_rad_auth) {
    event_del(user->ev_rad_auth);
    event_free(user->ev_rad_auth);
    user->ev_rad_auth = NULL;
  }

  if (parse_radpkg(user, &rad_pkg) < 0) {
    log_error("RADIUS auth response parse failed, id=%u user='%s'",
              rad_pkg.identifier, user->user_name);
      user->http_reply_code= PORTAL_SEND_RAD_ERROR;
    process_server_events(EV_AUTH_REJECT, NULL, (void*)user);
  } else {
    print_radpkg(&rad_pkg);
    if (rad_pkg.code == PW_AUTHENTICATION_ACK) {
      log_info("RADIUS Access-Accept(id=%u) for user='%s'",
               rad_pkg.identifier, user->user_name);
      if (process_server_events(EV_AUTH_ACCEPT, NULL, (void*)user) < 0) {
           user->http_reply_code= PORTAL_WLANUSERPASSWD_ERROR;
        process_server_events(EV_AUTH_REJECT, NULL, (void*)user);
      }
    } else {
      log_warn("RADIUS Access-Reject/non-ACK(code=%u id=%u) for user='%s'",
               rad_pkg.code, rad_pkg.identifier, user->user_name);
        user->http_reply_code= PORTAL_WLANUSERPASSWD_ERROR;
      process_server_events(EV_AUTH_REJECT, NULL, (void*)user);
    }
  }
  user_put(user);
}

static void generate_authenticator(struct user_session_t* user, void* buf,
                                   size_t len) {
  MD5_CTX ctx;
  // unsigned char md5[16] = {0};

  MD5_Init(&ctx);
  MD5_Update(&ctx, buf, len);
  MD5_Update(&ctx, user->inst->rad_acct_secret,
            strlen(user->inst->rad_acct_secret));
  MD5_Final(user->rad_authenticator, &ctx);

  // memcpy(&(m->buf[POS_AUTH]), md5, MD5_DIGEST_LENGTH);
}

/* 校验 RADIUS 响应报文(Access-Accept/Reject、Accounting-Response)的
 * Response Authenticator: MD5(code+id+len + RequestAuthenticator + attrs + secret)。
 * user->rad_authenticator 保存本端请求的 Request Authenticator:
 *   认证请求为随机值, 记账请求为 generate_authenticator 计算的 MD5。
 * 返回 0=通过, -1=非法长度或校验失败。 */
static int verify_response_authenticator(struct user_session_t* user,
                                         struct radius_packet_t* rad_pkg,
                                         ssize_t rn, const char* secret) {
  uint16_t pkg_len = ntohs(rad_pkg->length);
  uint8_t md5[16] = {0};
  MD5_CTX ctx;

  /* 长度合法性: 至少 RADIUS 头(20), 且不得超实际收包与本端缓冲区,
   * 防止 length 字段被恶意构造导致 MD5_Update 越界读。 */
  if (pkg_len < 20 || rn < 20 || pkg_len > (uint16_t)rn ||
      pkg_len > MAX_ATTRIB_SIZE + 20) {
    log_error("RADIUS response invalid length: pkg_len=%u rn=%zd", pkg_len, rn);
    return -1;
  }

  MD5_Init(&ctx);
  MD5_Update(&ctx, rad_pkg, 4);                        /* Code+Identifier+Length */
  MD5_Update(&ctx, user->rad_authenticator, 16);       /* Request Authenticator */
  MD5_Update(&ctx, rad_pkg->attributes, pkg_len - 20); /* Attributes */
  MD5_Update(&ctx, secret, strlen(secret));            /* Shared Secret */
  MD5_Final(md5, &ctx);

  if (memcmp(md5, rad_pkg->authenticator, 16) != 0) {
    log_error("RADIUS response authenticator mismatch (id=%u)",
              rad_pkg->identifier);
    return -1;
  }
  return 0;
}

static const char* rad_code_name(uint8_t code) {
  switch (code) {
    case PW_AUTHENTICATION_REQUEST:
      return "Access-Request";
    case PW_AUTHENTICATION_ACK:
      return "Access-Accept";
    case PW_AUTHENTICATION_REJECT:
      return "Access-Reject";
    case PW_ACCOUNTING_REQUEST:
      return "Accounting-Request";
    case PW_ACCOUNTING_RESPONSE:
      return "Accounting-Response";
    default:
      return "Unknown";
  }
}

static const char* acct_status_name(uint32_t status) {
  switch (status) {
    case PW_STATUS_START:
      return "Start";
    case PW_STATUS_STOP:
      return "Stop";
    case PW_STATUS_ALIVE:
      return "Alive";
    case PW_STATUS_ACCOUNTING_ON:
      return "Accounting-On";
    case PW_STATUS_ACCOUNTING_OFF:
      return "Accounting-Off";
    default:
      return "Unknown";
  }
}

int send_radius_pkg(struct user_session_t* user, uint8_t code) {
  struct radius_packet_t rad_auth = {0};
  struct inst_t* inst = user->inst;
  size_t offset = 0;
  uint16_t pkg_len = 0;

if(!user){
  log_error("send_radius_pkg not found user");
  return -1;

}
    if (!user->inst) {
        log_error("send_radius_pkg user->inst is NULL");
        return -1;
    }
  int n = 0;
  if (code != PW_AUTHENTICATION_REQUEST && code != PW_ACCOUNTING_REQUEST) {
    log_error("code(%d) is invalid", code);
    return -1;
  }
  if (init_radius(inst) < 0) {
    log_error("Initialize RADIUS settings failed");
    return -1;
  }

  if (code == PW_AUTHENTICATION_REQUEST) {
    if (user->rad_auth_fd < 1) {
      user->rad_auth_fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (user->rad_auth_fd < 1) {
        log_error("radius sock is NULL");
        return -1;
      }
      set_nonblock(user->rad_auth_fd);
    }
  }

  if (code == PW_ACCOUNTING_REQUEST) {
    /*
     * 正常情况下 radacct_response_cb 收到应答后会释放 ev_rad_acct 并关闭
     * rad_acct_fd。若上一个计费(Start/Alive/Stop)请求的应答丢失, 旧的读
     * 事件和 socket 可能仍残留; 这里先清理, 避免 event_new 覆盖指针造成
     * 事件泄漏、同一 fd 重复注册, 保证后续 Alive 周期都能正常发出。
     * 注意: rad_acct_fd 初值为 -1, 只有 >0 才是有效 fd, 绝不能用 >=0,
     * 否则首次计费时会误 close(0) 关闭标准输入。
     */
    if (user->ev_rad_acct) {
      event_del(user->ev_rad_acct);
      event_free(user->ev_rad_acct);
      user->ev_rad_acct = NULL;
    }
    if (user->rad_acct_fd > 0) {
      close(user->rad_acct_fd);
    }
    user->rad_acct_fd = -1;

    log_debug("New accounting socket");
    user->rad_acct_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (user->rad_acct_fd < 0) {
      log_error("create accounting socket failed: %s", strerror(errno));
      return -1;
    }
    //   set_nonblock(user->rad_acct_fd);
  }

  memset(user->rad_authenticator, 0, 16);
  if (code == PW_AUTHENTICATION_REQUEST) {
    /* Access-Request 的 Request Authenticator 必须为随机值(RFC2865 §3),
     * 需在生成 User-Password(PAP) 之前设置作为 MD5 加密种子, 并全程保留
     * 供 radauth_response_cb 校验 Response Authenticator。 */
    get_rand(16, user->rad_authenticator);
  }

  struct attributes_t* attr = (struct attributes_t*)rad_auth.attributes;
  if (code == PW_ACCOUNTING_REQUEST) {
    offset = add_attr(user, attr, PW_ACCT_STATUS_TYPE, offset);
  }
  if (code == PW_AUTHENTICATION_REQUEST || code == PW_ACCOUNTING_REQUEST) {
    offset = add_attr(user, attr, PW_USER_NAME, offset);
  }
  if (code == PW_AUTHENTICATION_REQUEST) {
    offset = add_attr(user, attr, PW_USER_PASSWORD, offset);
  }
  if (code == PW_AUTHENTICATION_REQUEST || code == PW_ACCOUNTING_REQUEST) {
    offset = add_attr(user, attr, PW_FRAMED_IP_ADDRESS, offset);
    offset = add_attr(user, attr, PW_CALLING_STATION_ID, offset);
    offset = add_attr(user, attr, PW_CALLED_STATION_ID, offset);
    offset = add_attr(user, attr, PW_NAS_IP_ADDRESS, offset);
    /*
     * NAS-Identifier(属性32) 的取值是 inst->device_id (见 add_attr):
     *   - HTTP LOGIN 流程: org_id(组织ID) 非空时携带;
     *   - MAC 无感知认证: 没有 org_id, 但云端 Portal(portal_type=CLOUD_PORTAL)
     *     需要 NAS-Identifier 才能识别设备/路由请求, 缺失会导致报文被丢弃,
     *     因此 CLOUD_PORTAL 下无条件携带。
     */
    int has_org = (user->org_id && strlen(user->org_id) > 0);
    if (has_org || inst->config->portal_type == CLOUD_PORTAL) {
      log_debug("Add NAS-Identifier(32)='%s', user='%s'", inst->device_id,
                user->user_name);
      offset = add_attr(user, attr, PW_NAS_IDENTIFIER, offset);
    }
    /*
     * Filter-Id(属性11) 的值取配置里的 tenant_org_id(基准值, 见 add_attr),
     * 仅 CLOUD_PORTAL 下随认证/记账报文下发; tenant_org_id 为空时不下发。
     */
    if (inst->config->portal_type == CLOUD_PORTAL &&
        inst->config->tenant_org_id[0] != '\0') {
      log_debug("Add Filter-Id(11)='%s', user='%s'",
                inst->config->tenant_org_id, user->user_name);
      offset = add_attr(user, attr, PW_FILTER_ID, offset);
    }
  }
  if (code == PW_ACCOUNTING_REQUEST) {
    offset = add_attr(user, attr, PW_ACCT_SESSION_ID, offset);
    offset = add_attr(user, attr, PW_ACCT_SESSION_TIME, offset);
    offset = add_attr(user, attr, PW_ACCT_INPUT_OCTETS, offset);
    offset = add_attr(user, attr, PW_ACCT_OUTPUT_OCTETS, offset);
    offset = add_attr(user, attr, PW_ACCT_INPUT_GIGAWORDS, offset);
    offset = add_attr(user, attr, PW_ACCT_OUTPUT_GIGAWORDS, offset);
    // Acct-Input-Gigawords
  }

  rad_auth.code = code;
  rad_auth.identifier = 0;

  get_rand(1, &rad_auth.identifier);
  memcpy(rad_auth.authenticator, user->rad_authenticator, 16);
  user->rad_id = rad_auth.identifier;
  pkg_len = offset + 20;
 //  printf("+++++++++++++++++++++++%u\n", pkg_len);

  rad_auth.length = htons(pkg_len);

  {
    char ip_str[INET_ADDRSTRLEN] = {0};
    struct in_addr user_addr;
    user_addr.s_addr = user->ip;
    inet_ntop(AF_INET, &user_addr, ip_str, sizeof(ip_str));

    if (code == PW_AUTHENTICATION_REQUEST) {
      log_info(
          "RADIUS Access-Request(id=%u len=%u) -> %s:%u, user='%s' ip=%s",
          rad_auth.identifier, pkg_len, inst->rad_auth_server,
          inst->rad_auth_port, user->user_name, ip_str);
    } else {
      log_info(
          "RADIUS Accounting-Request(%s id=%u len=%u) -> %s:%u, "
          "user='%s' ip=%s session-id='%s' session-time=%ld in=%llu out=%llu",
          acct_status_name(user->acct_status_type), rad_auth.identifier,
          pkg_len, inst->rad_acct_server, inst->rad_acct_port,
          user->user_name, ip_str, user->acct_session_id, user->session_time,
          (unsigned long long)user->inbytes, (unsigned long long)user->outbytes);
    }
  }

  if (code == PW_AUTHENTICATION_REQUEST) {
    user->ev_rad_auth = event_new(inst->base, user->rad_auth_fd,
                                  EV_READ | EV_PERSIST,
                                  radauth_response_cb, (void*)user);

    if (event_add(user->ev_rad_auth, NULL) < 0) {
      log_error("Add radius auth event failed!");
      event_free(user->ev_rad_auth);
      user->ev_rad_auth = NULL;
      close(user->rad_auth_fd);
      user->rad_auth_fd = -1;
      return -1;
    }
    n = sendto(user->rad_auth_fd, (void*)&rad_auth, pkg_len, 0,
               (struct sockaddr*)(&(inst->auth_server)),
               sizeof(inst->auth_server));
    // printf("+++++++++++++++++++++++%d\n", n);
  }
  if (code == PW_ACCOUNTING_REQUEST) {
    generate_authenticator(user, (void*)&rad_auth, pkg_len);
    memcpy(rad_auth.authenticator, user->rad_authenticator, 16);
    user->ev_rad_acct = event_new(inst->base, user->rad_acct_fd,
                                  EV_READ | EV_PERSIST,
                                  radacct_response_cb, (void*)user);

    if (event_add(user->ev_rad_acct, NULL) < 0) {
      log_error("Add radius accounting event failed!");
      event_free(user->ev_rad_acct);
      user->ev_rad_acct = NULL;
      close(user->rad_acct_fd);
      user->rad_acct_fd = -1;
      return -1;
    }

    n = sendto(user->rad_acct_fd, (void*)&rad_auth, pkg_len, 0,
               (struct sockaddr*)(&(inst->acct_server)),
               sizeof(inst->acct_server));
  }

  if (n > 0) {
    log_debug("RADIUS %s(id=%u) sent, %d bytes", rad_code_name(code),
              rad_auth.identifier, n);
  } else {
    log_error("RADIUS %s(id=%u) sendto failed: %s", rad_code_name(code),
              rad_auth.identifier, strerror(errno));
  }

  // close(user->rad_fd);
  return n;
}

int send_rad_auth(struct user_session_t* user) {
  //  user->status = USER_STATE_AUTHING;

  return send_radius_pkg(user, PW_AUTHENTICATION_REQUEST);
}

int send_start_acct(struct user_session_t* user) {
  // user->status = USER_STATE_AUTHING;
  char ip_str[INET_ADDRSTRLEN] = {0};
  struct in_addr ip;

  ip.s_addr = user->ip;
  inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
  log_info(
      "RADIUS accounting Start begin: user='%s' ip=%s session-id='%s'",
      user->user_name, ip_str, user->acct_session_id);

  user->acct_status_type = PW_STATUS_START;
  user->acct_start_time = get_now_time();
  return send_radius_pkg(user, PW_ACCOUNTING_REQUEST);
}

int send_stop_acct(struct user_session_t* user) {
  struct in_addr ip;

  ip.s_addr = user->ip;
  //  char* userip = inet_ntoa(ip);
  // printf("++++++++++++++++++ip=%s\n", userip);
  int n = 0;
  if (user->status != USER_STATE_DROPPING) {
    log_error("user status is not dropping, can not send stop accounting");
    return -1;
  }
  //  printf("proc_user.in_bytes=%"PRIu64" \n", proc_user.in_bytes);
  user->session_time = get_now_time() - user->acct_start_time;
  user->acct_status_type = PW_STATUS_STOP;

  log_info(
      "RADIUS accounting Stop begin: user='%s' ip=%s session-id='%s' "
      "online=%lds in=%llu out=%llu",
      user->user_name, inet_ntoa(ip), user->acct_session_id,
      user->session_time, (unsigned long long)user->inbytes,
      (unsigned long long)user->outbytes);

  n = send_radius_pkg(user, PW_ACCOUNTING_REQUEST);
  if (n > 0) {
    log_debug("send stop accounting pkg success.len=%d", n);
  } else {
    log_error("send stop accounting pkg failed!");
  }

  return n;
}

int send_update_acct(struct user_session_t* user) {
  //  struct proc_session_t proc_user;
  struct in_addr ip;
  ip.s_addr = user->ip;
 // printf("++++++++++++++++++++++user->status=%d\n ", user->status);
  if (user->status == USER_STATE_AUTHED || user->status == USER_STATE_FREE) {
    user->acct_status_type = PW_STATUS_ALIVE;
    user->session_time = get_now_time() - user->acct_start_time;

    log_debug(
        "RADIUS accounting Alive begin: user='%s' ip=%s session-id='%s' "
        "online=%lds in=%llu out=%llu",
        user->user_name, inet_ntoa(ip), user->acct_session_id,
        user->session_time, (unsigned long long)user->inbytes,
        (unsigned long long)user->outbytes);

    return send_radius_pkg(user, PW_ACCOUNTING_REQUEST);
  } else {
    log_error(
        "user status is not authed and free, can not send update accounting");
    return -1;
  }
  return 0;
}

static int reply_CoA_packet(struct inst_t* inst, struct user_session_t* user,
                            uint8_t code, uint8_t id,
                            const uint8_t request_authenticator[16],
                            struct sockaddr_in* peer_addr) {
  struct radius_packet_t rad_auth = {0};
  uint8_t md5sum[16] = {0};
  size_t offset = 0;
  struct attributes_t attr = {0};
  uint16_t pkg_len = 0;
  ssize_t sent;

  if (!inst || !peer_addr || !request_authenticator ||
      (code != PW_DISCONNECT_ACK && code != PW_DISCONNECT_NAK)) {
    return -1;
  }
  memcpy(rad_auth.authenticator, request_authenticator, 16);

  rad_auth.code = code;
  rad_auth.identifier = id;

  if (user && user->user_name[0]) {
    offset = add_attr(user, &attr, PW_USER_NAME, offset);
  }

  pkg_len = offset + 20;

  rad_auth.length = htons(pkg_len);
  if (offset > 0) {
    memcpy(rad_auth.attributes, &attr, offset);
  }
  MD5_CTX ctx;

  MD5_Init(&ctx);
  MD5_Update(&ctx, (void*)&rad_auth, pkg_len);
  MD5_Update(&ctx, inst->config->coa_secret,
            strlen(inst->config->coa_secret));
  MD5_Final(md5sum, &ctx);

  memcpy(rad_auth.authenticator, md5sum, 16);
  sent = sendto(inst->coa_fd, (void*)&rad_auth, pkg_len, 0,
                (struct sockaddr*)peer_addr, sizeof(*peer_addr));
  return sent == pkg_len ? 0 : -1;
}

int reply_CoA(struct user_session_t* user, uint8_t code, uint8_t id,
              struct sockaddr_in* peer_addr) {
  if (!user) {
    return -1;
  }
  return reply_CoA_packet(user->inst, user, code, id,
                          user->rad_authenticator, peer_addr);
}

void rad_CoA_cb(int fd, short event, void* arg) {
  MD5_CTX ctx;
  struct inst_t* inst = (struct inst_t*)arg;
  struct radius_packet_t rad_pkg = {0};
  uint8_t authenticator[16] = {0};
  uint8_t md5sum[16] = {0};
  struct sockaddr_in peer_addr;
  socklen_t len = sizeof(peer_addr);
  struct user_address_t user_address;
  ssize_t rn = recvfrom(fd, (void*)&rad_pkg, MAX_ATTRIB_SIZE, 0,
                        (struct sockaddr*)&peer_addr, &len);

  uint8_t code = rad_pkg.code;
  uint16_t pkg_len = ntohs(rad_pkg.length);
  uint16_t attr_len_total;
  uint16_t p = 0;
  int attr_parse_error = 0;

  /* 报文长度合法性: 本端 recvfrom 缓冲为 MAX_ATTRIB_SIZE, 超过即被恶意
   * 构造或截断; 且须在 MD5 校验前限制, 防止 MD5_Update 越界读。 */
  if (rn < 20 || pkg_len < 20 || pkg_len > MAX_ATTRIB_SIZE ||
      pkg_len > (uint16_t)rn) {
    log_error("rad_CoA_cb: invalid pkg_len=%u received=%zd", pkg_len, rn);
    return;
  }
  attr_len_total = pkg_len - 20;

  uint8_t attr_len;
  // uint32_t tmp_u32;
  uint8_t mac[6] = {0};
  uint32_t ip_u32 = 0;   /* 避免无 PW_FRAMED_IP_ADDRESS 属性时使用未初始化值 */
  char* tmp_str = NULL;
  char* str_ip;
  char user_name[64] = {0};
  struct in_addr ip;
  struct attributes_t* attr = (struct attributes_t*)(rad_pkg.attributes);

  // printf("CoA code=%d\n",code);
  if (code != PW_DISCONNECT_REQUEST) {
    return;
  }

  memcpy(authenticator, rad_pkg.authenticator, 16);
  memset(rad_pkg.authenticator, 0, 16);

  MD5_Init(&ctx);
  MD5_Update(&ctx, (void*)&rad_pkg, pkg_len);
  MD5_Update(&ctx, inst->config->coa_secret, strlen(inst->config->coa_secret));
  MD5_Final(md5sum, &ctx);
  if (memcmp(md5sum, authenticator, 16) != 0) {
    log_error("Invalid CoA package!");
    return;
  }

  // printf("++++pkg len=%u  type=%u len=%u\n", pkg_len, attr->type,
  // attr->length);
  while (p + 2 <= attr_len_total) {
    attr = (struct attributes_t*)(rad_pkg.attributes + p);
    attr_len = attr->length;
    if (attr_len < 2 || p + attr_len > attr_len_total) {
      attr_parse_error = 1;
      break;
    }
    // printf("type=%u attr_len=%u p =%u\n", attr->type, attr_len, p);
    switch (attr->type) {
      case PW_FRAMED_IP_ADDRESS:
        if (attr_len != 6) {
          attr_parse_error = 1;
          break;
        }
        ip_u32 = get_u32_value(attr);
        ip.s_addr = ntohl(ip_u32);
        str_ip = inet_ntoa(ip);
        //   printf("++++++++++++++++ip=%s\n",str_ip);

        break;
      case PW_USER_NAME: {
        size_t cp = attr_len - 2;
        if (cp > sizeof(user_name) - 1) {
          cp = sizeof(user_name) - 1;   /* 防止长属性越界写 */
        }
        tmp_str = (char*)attr->value;
        memcpy(user_name, tmp_str, cp);
        break;
      }
      case PW_REPLY_MESSAGE:

        break;
      default:
        break;
    }

    p = p + attr_len;
  }

  if (attr_parse_error || ip_u32 == 0) {
    log_error("rad_CoA_cb: malformed request attributes or missing Framed-IP");
    reply_CoA_packet(inst, NULL, PW_DISCONNECT_NAK, rad_pkg.identifier,
                     authenticator, &peer_addr);
    return;
  }

  struct user_session_t* user = find_user(inst, ntohl(ip_u32), mac);

  if (user) {
    //  printf("DM drop user +++++ status=%u\n",user->status);
    /*
            if (user->status == USER_STATE_AUTHED) {
                memcpy(user->rad_authenticator, authenticator, 16);
                reply_CoA(user, PW_DISCONNECT_ACK, rad_pkg.identifier,
       &peer_addr); drop_user(user);
            }
     */

    user_address.ip = user->ip;
    memcpy(user_address.mac, user->mac, 6);
    
    // Allocate memory for rad_server_addr and rad_pkg to avoid dangling pointers
    if (user->rad_server_addr == NULL) {
        user->rad_server_addr = malloc(sizeof(struct sockaddr_in));
        if (user->rad_server_addr == NULL) {
            log_error("Failed to allocate memory for rad_server_addr");
            return;
        }
    }
    memcpy(user->rad_server_addr, &peer_addr, sizeof(struct sockaddr_in));
    
    if (user->rad_pkg == NULL) {
        user->rad_pkg = malloc(sizeof(struct radius_packet_t));
        if (user->rad_pkg == NULL) {
            log_error("Failed to allocate memory for rad_pkg");
            return;
        }
    }
    memcpy(user->rad_pkg, &rad_pkg, sizeof(struct radius_packet_t));
    
    memcpy(user->rad_authenticator, authenticator, 16);
    user_address.inst = inst;
    process_server_events(EV_RECV_COA, &user_address, (void*)user);
  } else {
    reply_CoA_packet(inst, NULL, PW_DISCONNECT_NAK, rad_pkg.identifier,
                     authenticator, &peer_addr);
  }

  return;
}

int start_rad_CoA_server(struct inst_t* inst) {
  int rc = 0;
  int opt = 1;
  struct sockaddr_in coa_addr;

  if ((inst->coa_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    log_error("Create socket failed!");
    return -1;
  }

  int ret =
      setsockopt(inst->coa_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (ret) {
    return -1;
  }

  ret = setsockopt(inst->coa_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
  if (ret) {
    return -1;
  }

  int flags = fcntl(inst->coa_fd, F_GETFL, 0);
  flags |= O_NONBLOCK;
  fcntl(inst->coa_fd, F_SETFL, flags);

  bzero(&coa_addr, sizeof(coa_addr));
  coa_addr.sin_family = PF_INET;
  coa_addr.sin_port = htons(inst->config->coa_port);
  coa_addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(inst->coa_fd, (struct sockaddr*)&coa_addr,
           sizeof(struct sockaddr)) == -1) {
    perror("bind");
    return -1;
  } else {
    log_debug("IP bind OK\n");
  }

  // 注册回调函数： 接收DM下线报文
  inst->ev_radius_coa = event_new(
      inst->base, inst->coa_fd, EV_READ | EV_PERSIST, rad_CoA_cb, (void*)inst);

  event_add(inst->ev_radius_coa, NULL);
  return rc;
}

void stop_rad_CoA_server(struct inst_t* inst) {
  if (inst->ev_radius_coa) {
    event_del(inst->ev_radius_coa);
    event_free(inst->ev_radius_coa);
    inst->ev_radius_coa = NULL;
  }
  if (inst->coa_fd > 0) {
    close(inst->coa_fd);
    inst->coa_fd = -1;
  }
}

int get_cloud_u32_value(struct msg_t* msg, int type, uint32_t* value) {
  struct msg_t* p = msg;
  if (!p) {
    log_error("Invalid message pointer");
    return -1;
  }

  int len;
  int offset = 0;
  int msg_type = ntohs(p->type);
  while (msg_type != TYPE_NULL) {
    /* 读取 p->len 前确保 4 字节头(type+len)未越界 */
    if (offset + 4 > MAX_MSG_SIZE) {
      return -1;
    }
    len = ntohs(p->len);
    /* 消息项最小头 4 字节(type+len); len==0 会导致死循环,
     * 且不得越过 MAX_MSG_SIZE, 防止越界读 */
    if (len < 4 || offset + len > MAX_MSG_SIZE) {
      log_error("get_cloud_u32_value: bad len=%d offset=%d", len, offset);
      return -1;
    }
    if (msg_type == type) {
      /* 读取 u32 需 4 字节 data(len 至少为 8) */
      if (len < 8) {
        log_error("get_cloud_u32_value: len=%d too short for u32", len);
        return -1;
      }
      *value = ntohl(p->data.u32);
      return 0;
    }
    p = (struct msg_t*)(((void*)p) + len);
    offset += len;
    /* 读取下一项 p->type 前确保 4 字节头未越界 */
    if (offset + 4 > MAX_MSG_SIZE) {
      return -1;
    }
    msg_type = ntohs(p->type);
  }

  return 0;
}

int get_cloud_bin_value(struct msg_t* msg, int type, uint8_t* value, size_t cap) {
  struct msg_t* p = msg;
  if (!p || cap == 0) {
    log_error("Invalid message pointer or zero capacity");
    return -1;
  }

  int len;
  int offset = 0;
  int msg_type = ntohs(p->type);

  while (msg_type != TYPE_NULL) {
    /* 读取 p->len 前确保 4 字节头(type+len)未越界 */
    if (offset + 4 > MAX_MSG_SIZE) {
      return -1;
    }
    len = ntohs(p->len);
    /* 消息项最小头 4 字节(type+len); len<4 时 len-4 下溢导致越界写,
     * len==0 会导致死循环, 且不得越过 MAX_MSG_SIZE */
    if (len < 4 || offset + len > MAX_MSG_SIZE) {
      log_error("get_cloud_bin_value: bad len=%d offset=%d", len, offset);
      return -1;
    }
    if (msg_type == type) {
      size_t cp = (size_t)(len - 4);
      if (cp > cap) {
        cp = cap;   /* 按目标容量截断, 防止越界写 */
      }
      memcpy(value, p->data.u8, cp);
      return 0;
    }
    p = (struct msg_t*)(((void*)p) + len);
    offset += len;
    /* 读取下一项 p->type 前确保 4 字节头未越界 */
    if (offset + 4 > MAX_MSG_SIZE) {
      return -1;
    }
    msg_type = ntohs(p->type);
  }
  return 0;
}

// 回调函数，处理接收到的UDP数据包

static void udp_event_cb(struct bufferevent* bev, short events, void* ctx) {
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    log_error("UDP connection closed or encountered an error.\n");

    // 关闭连接
    bufferevent_free(bev);
  }
}

// 回调函数，处理UDP连接请求

#if 0
static void udp_conn_cb(evutil_socket_t fd, short events, void* arg) {
    struct inst_t* inst = (struct inst_t*) arg;
    struct event_base* base = inst->base;

    // 创建一个UDP bufferevent
    struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        log_error("Error constructing bufferevent!");
        event_base_loopbreak(base);
        return;
    }

    // 设置回调函数，处理读取和错误事件
    bufferevent_setcb(bev, udp_read_cb, NULL, udp_event_cb, arg);

    // 启用读取事件
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

#endif
// void cloud_auth_read_cb(struct bufferevent *bev, void *arg) {

void cloud_auth_read_cb(int fd, short event, void* arg) {
  // struct sockaddr_storage ss;
  // socklen_t slen = sizeof(ss);
  struct inst_t* inst = (struct inst_t*)arg;
  uint8_t buffer[MAX_MSG_SIZE] = {0};
  ssize_t n;
  uint32_t cmd_type = 0;
  uint32_t user_ip = 0;
  uint8_t user_mac[6] = {0};
  uint32_t task_id = 0;
  struct in_addr ip;

  uint8_t rad_buf[2048] = {0};
  struct sockaddr_in ss;
  socklen_t slen = sizeof(ss);
  struct radius_packet_t* rad_pkg = NULL;
  struct user_session_t* user = NULL;
  struct user_session_t tmp_user = {0};
  // 使用 recvfrom 读取 UDP 数据包

  // printf("++++++++++read buf \n");

  n = recvfrom(fd, &buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&ss,
               &slen);
  // printf("++++++++++read buf n=%d \n", n);

  if (n > 0) {
    // printf("Received %zd bytes: %s\n", n, buffer);

    /*
            printf("%0x %0x %0x %0x %0x %0x %0x %0x \n",
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4],
       buffer[5], buffer[6], buffer[7]);
     */
    struct msg_t* msg = (struct msg_t*)buffer;
    //  struct pkg_t *pkg = (struct pkg_t *) buffer;

    get_cloud_u32_value(msg, CLOUD_AUTH_CMD_TYPE, &cmd_type);

    log_debug("cloud command type=%u", cmd_type);

    switch (cmd_type) {
      case CLOUD_AUTH_ACCEPT:
        get_cloud_u32_value(msg, USER_IP, &user_ip);
        get_cloud_u32_value(msg, TASK_ID, &task_id);
        // printf("user ip =%0x\n", user_ip);
        get_cloud_bin_value(msg, USER_MAC, user_mac, sizeof(user_mac));
        ip.s_addr = user_ip;

        //   printf("++++++task id=%0x  ip=%s\n", task_id, inet_ntoa(ip));

        /*
                        printf("user MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
                                user_mac[0], user_mac[1], user_mac[2],
           user_mac[3], user_mac[4], user_mac[5]);
         */

        user = find_user(inst, user_ip, user_mac);
        if (!user) {
          log_error("Unable to find user based on cloud command.type=%d",
                    cmd_type);
          return;
        }

        if (user->status == USER_STATE_INIT ||
            user->status == USER_STATE_AUTHING) {
          user->status = USER_STATE_AUTHING;
        } else {
          return;
        }

        memset(user->user_name, 0, sizeof(user->user_name));
        get_cloud_bin_value(msg, USER_NAME, (void*)user->user_name,
                            sizeof(user->user_name) - 1);
        get_cloud_bin_value(msg, CLOUD_AUTH_REPLY, (void*)rad_buf,
                            sizeof(rad_buf));

        if (parse_radpkg(user, (struct radius_packet_t*)rad_buf) != 0) {
          log_error("Malformed RADIUS payload in cloud auth accept");
          user->http_reply_code = PORTAL_SEND_RAD_ERROR;
          process_server_events(EV_AUTH_REJECT, NULL, (void*)user);
          break;
        }
        // user->status = USER_STATE_AUTHING;
        process_server_events(EV_AUTH_ACCEPT, NULL, (void*)user);
        break;
      case CLOUD_AUTH_DENY:
        break;
      case CLOUD_DROP_USER:
        get_cloud_bin_value(msg, CLOUD_DM_REQUEST, (void*)rad_buf,
                            sizeof(rad_buf));
        get_cloud_u32_value(msg, USER_IP, &user_ip);
        get_cloud_u32_value(msg, TASK_ID, &task_id);

        rad_pkg = (struct radius_packet_t*)rad_buf;
        // printf("++++++3333++++++code=%u\n",rad_pkg->code);

        ip.s_addr = user_ip;
        //  parse_radpkg(&tmp_user, rad_pkg);
     //   printf("++++userip=%s\n", inet_ntoa(ip));
        user = find_user(inst, user_ip, user_mac);
        if (!user) {
          ip.s_addr = user_ip;
          log_error("Unable to find user(%s).Response STOP accouting",
                    inet_ntoa(ip));
          //   struct user_session_t* user = (struct user_session_t*)
          //   malloc(sizeof (struct user_session_t));
          // if (!user) {

          //     return;
          //   }
          //   memset(user, 0, sizeof (struct user_session_t));
          // user->session_time = 0;
          //  user->rad_acct_fd = -1;
          // user->acct_status_type = PW_STATUS_STOP;
          //   user->inst = inst;
          //   user->ip = user_ip;
          //   send_stop_acct(user);

          //  free(user);
          //  user = NULL;
          return;
        }

        process_server_events(EV_CLOSE_SESSION, NULL, (void*)user);
        break;

      case CLOUD_UPDATE_CONFIG:
        update_radius_config(inst);
        break;

      default:
        log_error("Invalid cloud command!");
    }
  }
  //  printf("+++++++++++++++++++++++++cloud_auth_read_cb++++++++\n");
  // 继续监听下一个数据包
  // bufferevent_enable(bev, EV_READ);
}

/*
void cloud_auth_error_cb(struct bufferevent *bev, short what, void *arg) {
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        printf("UDP error occurred!\n");
        bufferevent_free(bev);
    }
}
 */
// 事件回调函数

void udp_event_callback(struct bufferevent* bev, short events, void* ctx) {
  if (events & BEV_EVENT_ERROR) {
    perror("Error from bufferevent");
  }
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    bufferevent_free(bev);
  }
}

int cloud_loacal_auth_service(struct inst_t* inst) {
  struct sockaddr_in sin;
  if (!inst->base) {
    perror("Could not initialize libevent!");
    return -1;
  }

  // 创建一个UDP监听器，监听在本地8888端口
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  inet_aton("127.0.0.1", &sin.sin_addr);
  sin.sin_port = htons(3798);

  evutil_socket_t udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket == -1) {
    perror("socket");
    return -1;
  }
  if (bind(udp_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
    perror("bind");
    close(udp_socket);
    return 1;
  }

  // 创建UDP连接监听事件
  struct event* udp_event =
      event_new(inst->base, udp_socket, EV_READ | EV_PERSIST,
                cloud_auth_read_cb, (void*)inst);
  if (!udp_event) {
    close(udp_socket);
    return -1;
  }
  event_add(udp_event, NULL);

  /* 保存句柄, 供 destroy_inst 关闭, 避免 socket/event 泄漏 */
  inst->cloud_auth_fd = udp_socket;
  inst->ev_cloud_auth = udp_event;

  return 0;
}

int update_radius_config(struct inst_t* inst) {
  FILE* pf = NULL;
  cJSON* root = NULL;
  cJSON* radius = NULL;
  char buf[1024] = {0};
  log_debug("update config...");
  if (inst->config->portal_type != CLOUD_PORTAL) {
    log_error("Portal type is %d", inst->config->portal_type);
    return -1;
  }

  pf = fopen(WEBAUTHD_CONFIG_FILE, "r");

  if (!pf) {
    log_error("Can not open %s", WEBAUTHD_CONFIG_FILE);
    return -1;
  }

  if (fread((void*)buf, 1, sizeof(buf) - 1, pf) < 1) {
    log_error("Read file error!");
    fclose(pf);
    return -1;
  }
  fclose(pf);
  pf = NULL;

  log_debug("radius config reloaded from %s", WEBAUTHD_CONFIG_FILE);
  root = cJSON_Parse(buf);
  if (!root) {
    log_error("\n%s\n is NOT json!");
    return -1;
  }

  radius = cJSON_GetObjectItem(root, "radius");
  if (!radius) {
    log_error("no 'radius' object in config");
    cJSON_Delete(root);
    root = NULL;
    return -1;   /* 缺少 radius 对象时不能继续, 否则下面解引用 NULL */
  }

  cJSON* acct_proxy_secret = cJSON_GetObjectItem(radius, "acct_proxy_secret");
  cJSON* acct_proxy_server = cJSON_GetObjectItem(radius, "acct_proxy_server");
  cJSON* acct_proxy_port = cJSON_GetObjectItem(radius, "acct_proxy_port");

  cJSON* auth_proxy_secret = cJSON_GetObjectItem(radius, "auth_proxy_secret");
  cJSON* auth_proxy_server = cJSON_GetObjectItem(radius, "auth_proxy_server");
  cJSON* auth_proxy_port = cJSON_GetObjectItem(radius, "auth_proxy_port");

  cJSON* nas_ip = cJSON_GetObjectItem(radius, "nas_ip");

  /* 注意: root 必须保持有效到所有字段读取完成, 之前在此处 cJSON_Delete
   * 之后再访问 acct_proxy_server->valuestring 等节点属于 use-after-free */

  if (acct_proxy_port && acct_proxy_server && acct_proxy_secret &&
      acct_proxy_port->type == cJSON_Number &&
      acct_proxy_server->type == cJSON_String &&
      acct_proxy_server->valuestring &&
      acct_proxy_secret->type == cJSON_String &&
      acct_proxy_secret->valuestring) {
    inst->config->primary_acct_port = (uint16_t)acct_proxy_port->valueint;
    memset(inst->config->primary_acct_server, 0, 24);
    snprintf(inst->config->primary_acct_server, 24, "%s",
             acct_proxy_server->valuestring);
    memset(inst->config->primary_acct_secret, 0, 32);
    snprintf(inst->config->primary_acct_secret, 32, "%s",
             acct_proxy_secret->valuestring);
    // inst->acct_secret = inst->config->primary_acct_secret;
  }
  if (auth_proxy_port && auth_proxy_server && auth_proxy_secret &&
      auth_proxy_port->type == cJSON_Number &&
      auth_proxy_server->type == cJSON_String &&
      auth_proxy_server->valuestring &&
      auth_proxy_secret->type == cJSON_String &&
      auth_proxy_secret->valuestring) {
    inst->config->primary_auth_port = (uint16_t)auth_proxy_port->valueint;

    //    printf("inst->config->primary_auth_port=%u\n",inst->config->primary_auth_port);
    memset(inst->config->primary_auth_server, 0, 24);
    snprintf(inst->config->primary_auth_server, 24, "%s",
             auth_proxy_server->valuestring);
    memset(inst->config->primary_auth_secret, 0, 32);
    snprintf(inst->config->primary_auth_secret, 32, "%s",
             auth_proxy_secret->valuestring);
    // inst->rad_secret = inst->config->primary_auth_secret;
  }

  if (nas_ip && nas_ip->type == cJSON_String && nas_ip->valuestring) {
    if (strlen(nas_ip->valuestring) > 6) {
      memset(inst->config->nas_ip, 0, 32);
      snprintf(inst->config->nas_ip, 32, "%s", nas_ip->valuestring);
    }
  } else {
    memset(inst->config->nas_ip, 0, 32);
    snprintf(inst->config->nas_ip, 32, "%s", inst->config->primary_auth_server);
  }

  log_debug("radius auth server = %s:%u (secret %s)",
            inst->config->primary_auth_server, inst->config->primary_auth_port,
            inst->config->primary_auth_secret[0] ? "set" : "empty");
  log_debug("radius acct server = %s:%u (secret %s) nas ip=%s",
            inst->config->primary_acct_server, inst->config->primary_acct_port,
            inst->config->primary_acct_secret[0] ? "set" : "empty",
            inst->config->nas_ip);

  cJSON_Delete(root);
  return 0;
}
