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

/*
 * local_auth.c - 本地认证源(auth_source=local)
 *
 * 完全旁路 RADIUS(无 Access-Request/记账/CoA), 用户数据保存在
 * /etc/config/webauth_users/ 下一户一 JSON 文件(写操作不全局加载)。
 *
 * 登录链路:
 *   portal 密码: ws_http_login_v1 -> local_portal_login(同步校验,
 *                成功走 EV_AUTH_ACCEPT, 失败直接回 HTTP 错误码)
 *   MAC 免密:    ev_new_user -> local_mac_auth(绑定且用户开启才放行,
 *                否则回退 PORTAL 弹窗认证)
 *   accept:      ev_auth_accept 本地分支(nft 放行 + 会话超时定时器,
 *                跳过 send_start_acct/interim)
 *   下线:        ev_close_session 本地分支(用量落盘 + 直接清理,
 *                跳过 Accounting-Stop)
 *
 * 定时器: 巡检 60s(重读用户 JSON, disabled/过期/配额用尽即踢),
 *         兜底落盘 300s(在线会话增量流量/在线时长写回, 防 flash 磨损)。
 */

#include "local_auth.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "app_events.h"
#include "cJSON.h"
#include "config.h"
#include "http_service.h"
#include "log.h"
#include "timer.h"
#include "utensils.h"

#define ONE_MB 1048576ULL

/* ------------------------------------------------------------------------ */
/* 小工具                                                                    */
/* ------------------------------------------------------------------------ */

static void set_err(char* err, size_t errsz, const char* fmt, ...) {
  va_list ap;
  if (!err || errsz == 0) {
    return;
  }
  va_start(ap, fmt);
  vsnprintf(err, errsz, fmt, ap);
  va_end(ap);
}

void local_mac_to_str(const uint8_t mac[6], char* out, size_t outsz) {
  if (!out || outsz == 0) {
    return;
  }
  snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

int local_mac_parse(const char* s, uint8_t out[6]) {
  char hex[13];
  int n = 0;
  int i;

  if (!s || !out) {
    return -1;
  }
  for (; *s != '\0'; ++s) {
    unsigned char c = (unsigned char)*s;
    if (c == ':' || c == '-' || c == '.' || c == ' ') {
      continue;
    }
    if (!isxdigit(c) || n >= 12) {
      return -1;
    }
    hex[n++] = (char)tolower(c);
  }
  hex[n] = '\0';
  if (n != 12) {
    return -1;
  }
  for (i = 0; i < 6; ++i) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    char* endp = NULL;
    unsigned long v = strtoul(pair, &endp, 16);
    if (endp != pair + 2 || v > 0xFF) {
      return -1;
    }
    out[i] = (uint8_t)v;
  }
  return 0;
}

int local_username_valid(const char* username) {
  size_t len, i;

  if (!username) {
    return 0;
  }
  len = strlen(username);
  if (len < 1 || len > LOCAL_USERNAME_MAX) {
    return 0;
  }
  if (strcmp(username, ".") == 0 || strcmp(username, "..") == 0) {
    return 0;
  }
  /* "_mac" 后缀保留给绑定文件(<username>_mac.json), 用户名不得占用,
   * 否则与用户主文件名冲突 */
  if (len >= 4 && strcmp(username + len - 4, "_mac") == 0) {
    return 0;
  }
  for (i = 0; i < len; ++i) {
    unsigned char c = (unsigned char)username[i];
    if (!(isalnum(c) || c == '_' || c == '.' || c == '@' || c == '-')) {
      return 0;
    }
  }
  return 1;
}

time_t local_time_parse(const char* s) {
  struct tm tm;
  if (!s || s[0] == '\0') {
    return 0;
  }
  memset(&tm, 0, sizeof(tm));
  if (strptime(s, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
    return 0;
  }
  tm.tm_isdst = -1;
  return mktime(&tm);
}

void local_time_format(time_t t, char* out, size_t outsz) {
  struct tm tm;
  if (!out || outsz == 0) {
    return;
  }
  localtime_r(&t, &tm);
  strftime(out, outsz, "%Y-%m-%d %H:%M:%S", &tm);
}

/* ------------------------------------------------------------------------ */
/* 密码散列: s256$<盐hex(32)>$<sha256hex(盐||密码)(64)>                      */
/* ------------------------------------------------------------------------ */

static void bytes_to_hex(const unsigned char* in, size_t inlen, char* out,
                         size_t outsz) {
  static const char hex_tab[] = "0123456789abcdef";
  size_t i;
  if (outsz < inlen * 2 + 1) {
    return;
  }
  for (i = 0; i < inlen; ++i) {
    out[i * 2] = hex_tab[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex_tab[in[i] & 0xF];
  }
  out[inlen * 2] = '\0';
}

static int hex_to_bytes(const char* hex, unsigned char* out, size_t outlen) {
  size_t i;
  if (strlen(hex) != outlen * 2) {
    return -1;
  }
  for (i = 0; i < outlen; ++i) {
    char pair[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    char* endp = NULL;
    unsigned long v = strtoul(pair, &endp, 16);
    if (endp != pair + 2) {
      return -1;
    }
    out[i] = (unsigned char)v;
  }
  return 0;
}

static int ct_memcmp(const unsigned char* a, const unsigned char* b,
                     size_t n) {
  unsigned char diff = 0;
  size_t i;
  for (i = 0; i < n; ++i) {
    diff |= (unsigned char)(a[i] ^ b[i]);
  }
  return diff == 0 ? 0 : -1;
}

int local_hash_password(const char* password, char* out, size_t outsz) {
  unsigned char salt[16];
  unsigned char md[32];
  char salt_hex[33] = {0};
  char md_hex[65] = {0};

  if (!password || password[0] == '\0' || !out || outsz < LOCAL_PW_HASH_MAX) {
    return -1;
  }
  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    return -1;
  }
  /* PBKDF2-HMAC-SHA256: 把单轮 SHA-256 提升为带迭代次数的慢哈希 */
  if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt,
                        (int)sizeof(salt), LOCAL_PW_PBKDF2_ITER, EVP_sha256(),
                        (int)sizeof(md), md) != 1) {
    return -1;
  }

  bytes_to_hex(salt, sizeof(salt), salt_hex, sizeof(salt_hex));
  bytes_to_hex(md, sizeof(md), md_hex, sizeof(md_hex));
  snprintf(out, outsz, "%s%d$%s$%s", LOCAL_PW_PREFIX_PBKDF2,
           LOCAL_PW_PBKDF2_ITER, salt_hex, md_hex);
  return 0;
}

/* 兼容校验旧 s256$ 格式(历史用户文件), 新写入使用 PBKDF2 */
static int local_verify_password_legacy(const char* password,
                                        const char* stored) {
  const char* p;
  const char* dollar;
  const char* stored_md_hex;
  char salt_hex[33] = {0};
  unsigned char salt[16];
  unsigned char md[SHA256_DIGEST_LENGTH];
  char md_hex[65] = {0};
  SHA256_CTX ctx;

  if (strncmp(stored, LOCAL_PW_PREFIX, strlen(LOCAL_PW_PREFIX)) != 0) {
    return -1;
  }
  p = stored + strlen(LOCAL_PW_PREFIX);
  dollar = strchr(p, '$');
  if (!dollar || (dollar - p) != 32) {
    return -1;
  }
  memcpy(salt_hex, p, 32);
  stored_md_hex = dollar + 1;
  if (strlen(stored_md_hex) != SHA256_DIGEST_LENGTH * 2) {
    return -1;
  }
  if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0) {
    return -1;
  }
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, salt, sizeof(salt));
  SHA256_Update(&ctx, password, strlen(password));
  SHA256_Final(md, &ctx);
  bytes_to_hex(md, sizeof(md), md_hex, sizeof(md_hex));

  /* 存储侧统一小写 hex, 直接比较 */
  return (strcmp(md_hex, stored_md_hex) == 0) ? 0 : -1;
}

int local_verify_password(const char* password, const char* stored) {
  const char* p;
  const char* dollar;
  char salt_hex[33] = {0};
  unsigned char salt[16];
  unsigned char md[32];
  unsigned char expected[32];
  long iter;
  char* endp = NULL;

  if (!password || !stored) {
    return -1;
  }

  if (strncmp(stored, LOCAL_PW_PREFIX_PBKDF2,
              strlen(LOCAL_PW_PREFIX_PBKDF2)) != 0) {
    return local_verify_password_legacy(password, stored);
  }

  p = stored + strlen(LOCAL_PW_PREFIX_PBKDF2);
  iter = strtol(p, &endp, 10);
  if (!endp || *endp != '$' || iter < 1000 || iter > 1000000) {
    return -1;
  }
  p = endp + 1;
  if (strlen(p) != 32 + 1 + 64) {
    return -1;
  }
  dollar = p + 32;
  if (*dollar != '$') {
    return -1;
  }
  memcpy(salt_hex, p, 32);
  if (hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0) {
    return -1;
  }
  if (strlen(dollar + 1) != 64 ||
      hex_to_bytes(dollar + 1, expected, sizeof(expected)) != 0) {
    return -1;
  }
  if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt,
                        (int)sizeof(salt), (int)iter, EVP_sha256(),
                        (int)sizeof(md), md) != 1) {
    return -1;
  }
  return ct_memcmp(md, expected, sizeof(md));
}

/* ------------------------------------------------------------------------ */
/* 文件读写                                                                  */
/* ------------------------------------------------------------------------ */

static void build_user_path(const char* username, char* out, size_t outsz) {
  snprintf(out, outsz, "%s/%s.json", LOCAL_USERS_DIR, username);
}

static void build_mac_path(const char* username, char* out, size_t outsz) {
  snprintf(out, outsz, "%s/%s_mac.json", LOCAL_USERS_DIR, username);
}

static char* read_file_all(const char* path) {
  FILE* fp = NULL;
  long len = 0;
  char* buf = NULL;

  fp = fopen(path, "rb");
  if (!fp) {
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 ||
      fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    return NULL;
  }
  if (len > 64 * 1024) { /* 单用户文件上限保护 */
    fclose(fp);
    return NULL;
  }
  buf = (char*)malloc((size_t)len + 1);
  if (!buf) {
    fclose(fp);
    return NULL;
  }
  if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
    free(buf);
    fclose(fp);
    return NULL;
  }
  buf[len] = '\0';
  fclose(fp);
  return buf;
}

static int write_file_atomic(const char* path, const char* data, size_t len) {
  char tmp[560];
  int fd = -1;
  size_t off = 0;

  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    log_error("local_auth: open '%s' failed: %s", tmp, strerror(errno));
    return -1;
  }
  while (off < len) {
    ssize_t w = write(fd, data + off, len - off);
    if (w < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      unlink(tmp);
      log_error("local_auth: write '%s' failed: %s", tmp, strerror(errno));
      return -1;
    }
    off += (size_t)w;
  }
  /* 掉电/崩溃防护: rename 前先 fsync, 确保数据与元数据落盘 */
  if (fsync(fd) != 0) {
    close(fd);
    unlink(tmp);
    log_error("local_auth: fsync '%s' failed: %s", tmp, strerror(errno));
    return -1;
  }
  close(fd);
  if (rename(tmp, path) != 0) {
    log_error("local_auth: rename '%s' -> '%s' failed: %s", tmp, path,
              strerror(errno));
    unlink(tmp);
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------------ */
/* 用户 JSON <-> struct local_user_t                                         */
/* ------------------------------------------------------------------------ */

static const char* jstr(const cJSON* obj, const char* key, const char* def) {
  const cJSON* it = cJSON_GetObjectItem((cJSON*)obj, key);
  if (it && it->type == cJSON_String && it->valuestring) {
    return it->valuestring;
  }
  return def;
}

static int jint(const cJSON* obj, const char* key, int def) {
  const cJSON* it = cJSON_GetObjectItem((cJSON*)obj, key);
  if (it && it->type == cJSON_Number) {
    return it->valueint;
  }
  return def;
}

/* 旧版 cJSON 无 cJSON_IsBool: True/False 是独立 type, valueint 1/0 */
static int jbool(const cJSON* obj, const char* key, int def) {
  const cJSON* it = cJSON_GetObjectItem((cJSON*)obj, key);
  if (!it) {
    return def;
  }
  if (it->type == cJSON_True) {
    return 1;
  }
  if (it->type == cJSON_False) {
    return 0;
  }
  if (it->type == cJSON_Number) {
    return it->valueint ? 1 : 0;
  }
  return def;
}

static void local_user_from_json(const cJSON* root, struct local_user_t* u) {
  const char* status = jstr(root, "status", "active");

  memset(u, 0, sizeof(*u));
  snprintf(u->username, sizeof(u->username), "%s", jstr(root, "username", ""));
  snprintf(u->password_hash, sizeof(u->password_hash), "%s",
           jstr(root, "password", ""));
  u->status = (strcmp(status, "active") == 0) ? LOCAL_USER_STATUS_ACTIVE
                                              : LOCAL_USER_STATUS_DISABLED;
  u->mac_auth = jbool(root, "mac_auth", 0);
  u->max_mac_bind = jint(root, "max_mac_bind", 4);
  u->mac_bind_update_policy = jint(root, "mac_bind_update_policy", 0);
  u->max_online = jint(root, "max_online", 1);
  u->online_conflict_policy = jint(root, "online_conflict_policy", 0);
  snprintf(u->register_time, sizeof(u->register_time), "%s",
           jstr(root, "register_time", ""));
  snprintf(u->last_login_time, sizeof(u->last_login_time), "%s",
           jstr(root, "last_login_time", ""));
  snprintf(u->expire_time, sizeof(u->expire_time), "%s",
           jstr(root, "expire_time", ""));
  u->in_speed = (uint32_t)jint(root, "in_speed", 0);
  u->out_speed = (uint32_t)jint(root, "out_speed", 0);
  u->data_quota = (uint32_t)jint(root, "data_quota", 0);
  u->current_data = (uint32_t)jint(root, "current_data", 0);
  u->online_time = (uint32_t)jint(root, "online_time", 0);
  u->login_count = (uint32_t)jint(root, "login_count", 0);
}

static cJSON* local_user_to_json(const struct local_user_t* u) {
  cJSON* root = cJSON_CreateObject();
  if (!root) {
    return NULL;
  }
  cJSON_AddStringToObject(root, "username", u->username);
  cJSON_AddStringToObject(root, "password", u->password_hash);
  cJSON_AddStringToObject(root, "status",
                          (u->status == LOCAL_USER_STATUS_ACTIVE) ? "active"
                                                                  : "disabled");
  cJSON_AddBoolToObject(root, "mac_auth", u->mac_auth ? 1 : 0);
  cJSON_AddNumberToObject(root, "max_mac_bind", u->max_mac_bind);
  cJSON_AddNumberToObject(root, "mac_bind_update_policy",
                          u->mac_bind_update_policy);
  cJSON_AddNumberToObject(root, "max_online", u->max_online);
  cJSON_AddNumberToObject(root, "online_conflict_policy",
                          u->online_conflict_policy);
  cJSON_AddStringToObject(root, "register_time", u->register_time);
  cJSON_AddStringToObject(root, "last_login_time", u->last_login_time);
  cJSON_AddStringToObject(root, "expire_time", u->expire_time);
  cJSON_AddNumberToObject(root, "in_speed", (double)u->in_speed);
  cJSON_AddNumberToObject(root, "out_speed", (double)u->out_speed);
  cJSON_AddNumberToObject(root, "data_quota", (double)u->data_quota);
  cJSON_AddNumberToObject(root, "current_data", (double)u->current_data);
  cJSON_AddNumberToObject(root, "online_time", (double)u->online_time);
  cJSON_AddNumberToObject(root, "login_count", (double)u->login_count);
  return root;
}

/* ------------------------------------------------------------------------ */
/* 用户库 CRUD                                                               */
/* ------------------------------------------------------------------------ */

int local_user_load(const char* username, struct local_user_t* out, char* err,
                    size_t errsz) {
  char path[512];
  char* text = NULL;
  cJSON* root = NULL;

  if (!username || !out) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  if (!local_username_valid(username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  build_user_path(username, path, sizeof(path));
  text = read_file_all(path);
  if (!text) {
    set_err(err, errsz, "user not found");
    return -1;
  }
  root = cJSON_Parse(text);
  free(text);
  if (!root) {
    set_err(err, errsz, "user file corrupted");
    return -1;
  }
  local_user_from_json(root, out);
  cJSON_Delete(root);
  /* 以文件名为准, 防止文件内容 username 字段被手工改乱 */
  snprintf(out->username, sizeof(out->username), "%s", username);
  return 0;
}

int local_user_save(const struct local_user_t* u, char* err, size_t errsz) {
  char path[512];
  char* text = NULL;
  cJSON* root = NULL;
  struct local_user_t v;

  if (!u) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  if (!local_username_valid(u->username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  if ((strncmp(u->password_hash, LOCAL_PW_PREFIX, strlen(LOCAL_PW_PREFIX)) != 0 &&
       strncmp(u->password_hash, LOCAL_PW_PREFIX_PBKDF2,
               strlen(LOCAL_PW_PREFIX_PBKDF2)) != 0) ||
      strlen(u->password_hash) >= LOCAL_PW_HASH_MAX) {
    /* 拒绝写入明文/非法散列, 保证文件里只能是受支持的散列格式 */
    set_err(err, errsz, "password must be pbkdf2$ or s256$ hash");
    return -1;
  }

  /* 字段防御性归一化 */
  v = *u;
  snprintf(v.username, sizeof(v.username), "%s", u->username);
  if (v.max_mac_bind < 0) {
    v.max_mac_bind = 0;
  }
  if (v.max_mac_bind > LOCAL_MAC_BIND_MAX) {
    v.max_mac_bind = LOCAL_MAC_BIND_MAX;
  }
  if (v.mac_bind_update_policy != 0 && v.mac_bind_update_policy != 1) {
    v.mac_bind_update_policy = 0;
  }
  if (v.max_online < 0) {
    v.max_online = 0;
  }
  if (v.online_conflict_policy != 0 && v.online_conflict_policy != 1) {
    v.online_conflict_policy = 0;
  }

  root = local_user_to_json(&v);
  if (!root) {
    set_err(err, errsz, "out of memory");
    return -1;
  }
  text = cJSON_Print(root);
  cJSON_Delete(root);
  if (!text) {
    set_err(err, errsz, "json render failed");
    return -1;
  }
  build_user_path(v.username, path, sizeof(path));
  if (write_file_atomic(path, text, strlen(text)) != 0) {
    free(text);
    set_err(err, errsz, "write user file failed");
    return -1;
  }
  free(text);
  return 0;
}

int local_user_count(int* count) {
  DIR* dir = NULL;
  struct dirent* de = NULL;
  int n = 0;

  if (!count) {
    return -1;
  }
  dir = opendir(LOCAL_USERS_DIR);
  if (!dir) {
    *count = 0;
    return 0;
  }
  while ((de = readdir(dir)) != NULL) {
    const char* name = de->d_name;
    size_t len = strlen(name);
    char base[LOCAL_USERNAME_MAX + 1];
    size_t blen;

    if (len < 6 || strcmp(name + len - 5, ".json") != 0) {
      continue;
    }
    blen = len - 5;
    if (blen > LOCAL_USERNAME_MAX) {
      continue;
    }
    if (blen >= 4 && memcmp(name + len - 9, "_mac", 4) == 0) {
      continue; /* 绑定文件 <username>_mac.json */
    }
    memcpy(base, name, blen);
    base[blen] = '\0';
    if (local_username_valid(base)) {
      n++;
    }
  }
  closedir(dir);
  *count = n;
  return 0;
}

static int cmp_username(const void* a, const void* b) {
  return strcmp((const char*)a, (const char*)b);
}

int local_user_list(int page, int page_size,
                    char usernames[][LOCAL_USERNAME_MAX + 1], int max_out,
                    int* total, char* err, size_t errsz) {
  DIR* dir = NULL;
  struct dirent* de = NULL;
  char (*names)[LOCAL_USERNAME_MAX + 1] = NULL;
  int cap = 64, n = 0;
  int start, copied = 0, i;

  if (!usernames || !total || page < 1 || page_size < 1 || max_out < 0) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  names = (char (*)[LOCAL_USERNAME_MAX + 1])malloc(
      (size_t)cap * (LOCAL_USERNAME_MAX + 1));
  if (!names) {
    set_err(err, errsz, "out of memory");
    return -1;
  }
  dir = opendir(LOCAL_USERS_DIR);
  if (!dir) {
    *total = 0;
    free(names);
    return 0;
  }
  while ((de = readdir(dir)) != NULL) {
    const char* name = de->d_name;
    size_t len = strlen(name);
    size_t blen;
    char base[LOCAL_USERNAME_MAX + 1];

    if (len < 6 || strcmp(name + len - 5, ".json") != 0) {
      continue;
    }
    blen = len - 5;
    if (blen > LOCAL_USERNAME_MAX) {
      continue;
    }
    if (blen >= 4 && memcmp(name + len - 9, "_mac", 4) == 0) {
      continue;
    }
    memcpy(base, name, blen);
    base[blen] = '\0';
    if (!local_username_valid(base)) {
      continue;
    }
    if (n >= cap) {
      int new_cap = cap * 2;
      char (*grown)[LOCAL_USERNAME_MAX + 1] = (char (*)[LOCAL_USERNAME_MAX + 1])
          realloc(names, (size_t)new_cap * (LOCAL_USERNAME_MAX + 1));
      if (!grown) {
        continue;
      }
      names = grown;
      cap = new_cap;
    }
    memcpy(names[n], base, blen + 1);
    n++;
  }
  closedir(dir);

  qsort(names, (size_t)n, LOCAL_USERNAME_MAX + 1, cmp_username);
  *total = n;

  start = (page - 1) * page_size;
  for (i = start; i < n && copied < max_out; ++i, ++copied) {
    memcpy(usernames[copied], names[i], LOCAL_USERNAME_MAX + 1);
  }
  free(names);
  return copied;
}

int local_user_add(const struct local_user_t* u, char* err, size_t errsz) {
  struct inst_t* inst = get_inst();
  int max_users;
  int count = 0;
  char path[512];
  struct local_user_t v;

  if (!u) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  if (!local_username_valid(u->username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  if (u->password_hash[0] == '\0') {
    set_err(err, errsz, "password required");
    return -1;
  }
  max_users = (inst && inst->config && inst->config->max_users > 0)
                  ? inst->config->max_users
                  : 256;
  local_user_count(&count);
  if (count >= max_users) {
    set_err(err, errsz, "user limit reached (max_users=%d)", max_users);
    return -1;
  }
  build_user_path(u->username, path, sizeof(path));
  if (access(path, F_OK) == 0) {
    set_err(err, errsz, "user already exists");
    return -1;
  }

  v = *u;
  if (v.register_time[0] == '\0') {
    local_time_format(time(NULL), v.register_time, sizeof(v.register_time));
  }
  return local_user_save(&v, err, errsz);
}

int local_user_del(const char* username, char* err, size_t errsz) {
  char path[512];
  char mac_path[512];

  if (!local_username_valid(username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  build_user_path(username, path, sizeof(path));
  if (access(path, F_OK) != 0) {
    set_err(err, errsz, "user not found");
    return -1;
  }
  if (unlink(path) != 0) {
    set_err(err, errsz, "delete user file failed: %s", strerror(errno));
    return -1;
  }
  build_mac_path(username, mac_path, sizeof(mac_path));
  if (unlink(mac_path) != 0 && errno != ENOENT) {
    log_warn("local_auth: delete mac bind file '%s' failed: %s", mac_path,
             strerror(errno));
  }
  return 0;
}

/* ------------------------------------------------------------------------ */
/* MAC 绑定                                                                  */
/* ------------------------------------------------------------------------ */

int local_mac_load(const char* username, struct local_mac_bind_t* arr, int* cnt,
                   char* err, size_t errsz) {
  char path[512];
  char* text = NULL;
  cJSON* root = NULL;
  cJSON* mac_arr = NULL;
  int i, n = 0;

  if (!username || !arr || !cnt) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  *cnt = 0;
  if (!local_username_valid(username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  build_mac_path(username, path, sizeof(path));
  text = read_file_all(path);
  if (!text) {
    return 0; /* 无绑定文件 = 无绑定 */
  }
  root = cJSON_Parse(text);
  free(text);
  if (!root) {
    set_err(err, errsz, "mac bind file corrupted");
    return -1;
  }
  mac_arr = cJSON_GetObjectItem(root, "mac");
  if (mac_arr && mac_arr->type == cJSON_Array) {
    n = cJSON_GetArraySize(mac_arr);
    if (n > LOCAL_MAC_BIND_MAX) {
      n = LOCAL_MAC_BIND_MAX;
    }
    for (i = 0; i < n; ++i) {
      cJSON* it = cJSON_GetArrayItem(mac_arr, i);
      if (!it || it->type != cJSON_Object) {
        continue;
      }
      snprintf(arr[*cnt].mac, sizeof(arr[*cnt].mac), "%s",
               jstr(it, "mac", ""));
      snprintf(arr[*cnt].bind_time, sizeof(arr[*cnt].bind_time), "%s",
               jstr(it, "bind_time", ""));
      if (arr[*cnt].mac[0] != '\0') {
        (*cnt)++;
      }
    }
  }
  cJSON_Delete(root);
  return 0;
}

int local_mac_save(const char* username, const struct local_mac_bind_t* arr,
                   int cnt, char* err, size_t errsz) {
  char path[512];
  char* text = NULL;
  cJSON* root = NULL;
  cJSON* mac_arr = NULL;
  int i;

  if (!username || (cnt > 0 && !arr)) {
    set_err(err, errsz, "invalid argument");
    return -1;
  }
  if (!local_username_valid(username)) {
    set_err(err, errsz, "invalid username");
    return -1;
  }
  if (cnt > LOCAL_MAC_BIND_MAX) {
    set_err(err, errsz, "too many mac bindings (max %d)", LOCAL_MAC_BIND_MAX);
    return -1;
  }
  root = cJSON_CreateObject();
  if (!root) {
    set_err(err, errsz, "out of memory");
    return -1;
  }
  cJSON_AddStringToObject(root, "username", username);
  mac_arr = cJSON_CreateArray();
  if (!mac_arr) {
    cJSON_Delete(root);
    set_err(err, errsz, "out of memory");
    return -1;
  }
  cJSON_AddItemToObject(root, "mac", mac_arr);
  for (i = 0; i < cnt; ++i) {
    cJSON* item = cJSON_CreateObject();
    if (!item) {
      continue;
    }
    cJSON_AddStringToObject(item, "mac", arr[i].mac);
    cJSON_AddStringToObject(item, "bind_time", arr[i].bind_time);
    cJSON_AddItemToArray(mac_arr, item);
  }
  text = cJSON_Print(root);
  cJSON_Delete(root);
  if (!text) {
    set_err(err, errsz, "json render failed");
    return -1;
  }
  build_mac_path(username, path, sizeof(path));
  if (write_file_atomic(path, text, strlen(text)) != 0) {
    free(text);
    set_err(err, errsz, "write mac bind file failed");
    return -1;
  }
  free(text);
  return 0;
}

/* 在绑定文件名(<username>_mac.json)与用户主文件之间, 用户名不允许以
 * "_mac" 结尾(local_username_valid 已拦截), 因此按后缀剥离不会歧义 */
static int local_mac_lookup_owner(const char* mac_str, char* out_username,
                                  size_t outsz) {
  DIR* dir = NULL;
  struct dirent* de = NULL;
  int found = -1;

  dir = opendir(LOCAL_USERS_DIR);
  if (!dir) {
    return -1;
  }
  while ((de = readdir(dir)) != NULL && found != 0) {
    const char* name = de->d_name;
    size_t len = strlen(name);
    size_t blen;
    char owner[LOCAL_USERNAME_MAX + 1];
    struct local_mac_bind_t binds[LOCAL_MAC_BIND_MAX];
    int cnt = 0, i;
    char err[128] = {0};

    if (len < 10 || strcmp(name + len - 9, "_mac.json") != 0) {
      continue;
    }
    blen = len - 9;
    if (blen > LOCAL_USERNAME_MAX) {
      continue;
    }
    memcpy(owner, name, blen);
    owner[blen] = '\0';
    if (!local_username_valid(owner)) {
      continue;
    }
    if (local_mac_load(owner, binds, &cnt, err, sizeof(err)) != 0) {
      continue;
    }
    for (i = 0; i < cnt; ++i) {
      if (strcmp(binds[i].mac, mac_str) == 0) {
        snprintf(out_username, outsz, "%s", owner);
        found = 0;
        break;
      }
    }
  }
  closedir(dir);
  return found;
}

/* ------------------------------------------------------------------------ */
/* 在线会话辅助                                                              */
/* ------------------------------------------------------------------------ */

struct local_session_scan {
  const char* username;
  const struct user_session_t* self;
  int count;
  long earliest_time;
  struct user_session_t* earliest;
  int collect_victims;
  struct user_session_t* victims[INST_USER_MAX];
  int victim_count;
};

static void local_session_scan_cb(struct user_session_t* user, void* arg) {
  struct local_session_scan* s = (struct local_session_scan*)arg;

  if (user->status != USER_STATE_AUTHED) {
    return;
  }
  if (user->user_name[0] == '\0') {
    return;
  }
  if (s->username && strcmp(user->user_name, s->username) != 0) {
    return;
  }
  if (s->self && user == (struct user_session_t*)s->self) {
    return;
  }
  s->count++;
  if (s->earliest == NULL || user->start_time < s->earliest_time) {
    s->earliest = user;
    s->earliest_time = user->start_time;
  }
  if (s->collect_victims && s->victim_count < INST_USER_MAX) {
    s->victims[s->victim_count++] = user;
  }
}

int local_count_online_sessions(const char* username,
                                const struct user_session_t* self) {
  struct local_session_scan s;
  memset(&s, 0, sizeof(s));
  s.username = username;
  s.self = self;
  for_each_user_session(local_session_scan_cb, &s);
  return s.count;
}

void local_kick_earliest_session(const char* username) {
  struct local_session_scan s;
  memset(&s, 0, sizeof(s));
  s.username = username;
  for_each_user_session(local_session_scan_cb, &s);
  if (s.earliest) {
    struct in_addr tmp;
    tmp.s_addr = s.earliest->ip;
    log_info("Local auth: kick earliest online session user='%s' ip=%s",
             username, inet_ntoa(tmp));
    process_server_events(EV_CLOSE_SESSION, NULL, (void*)s.earliest);
  }
}

void local_kick_user_sessions(const char* username) {
  struct local_session_scan s;
  int i;

  memset(&s, 0, sizeof(s));
  s.username = username;
  s.collect_victims = 1;
  for_each_user_session(local_session_scan_cb, &s);
  for (i = 0; i < s.victim_count; ++i) {
    process_server_events(EV_CLOSE_SESSION, NULL, (void*)s.victims[i]);
  }
}

/* ------------------------------------------------------------------------ */
/* 会话参数映射与登录                                                        */
/* ------------------------------------------------------------------------ */

/* 把用户配置映射到会话: 限速(bytes/second)/配额(字节)/过期(秒) */
struct local_usage_scan {
  const char* username;
  const struct user_session_t* self;
  uint64_t unflushed_bytes;
};

static void local_usage_scan_cb(struct user_session_t* session, void* arg) {
  struct local_usage_scan* scan = (struct local_usage_scan*)arg;
  uint64_t bytes;

  if (!session || session == scan->self || session->user_name[0] == '\0' ||
      strcmp(session->user_name, scan->username) != 0) {
    return;
  }
  if (session->status != USER_STATE_AUTHED &&
      session->status != USER_STATE_FREE &&
      session->status != USER_STATE_DROPPING) {
    return;
  }
  bytes = session->inbytes + session->outbytes;
  if (bytes > session->local_flushed_bytes) {
    uint64_t delta = bytes - session->local_flushed_bytes;
    if (UINT64_MAX - scan->unflushed_bytes < delta) {
      scan->unflushed_bytes = UINT64_MAX;
    } else {
      scan->unflushed_bytes += delta;
    }
  }
}

static uint64_t local_account_used_bytes(const struct local_user_t* lu,
                                         const char* username,
                                         const struct user_session_t* self) {
  struct local_usage_scan scan;
  uint64_t persisted = (uint64_t)lu->current_data * ONE_MB;

  memset(&scan, 0, sizeof(scan));
  scan.username = username;
  scan.self = self;
  for_each_user_session(local_usage_scan_cb, &scan);
  if (UINT64_MAX - persisted < scan.unflushed_bytes) {
    return UINT64_MAX;
  }
  return persisted + scan.unflushed_bytes;
}

static int local_quota_remaining(const struct local_user_t* lu,
                                 const struct user_session_t* self,
                                 uint64_t* remaining) {
  uint64_t quota;
  uint64_t used;

  if (!lu || !remaining) {
    return -1;
  }
  if (lu->data_quota == 0) {
    *remaining = 0;
    return 0;
  }
  quota = (uint64_t)lu->data_quota * ONE_MB;
  used = local_account_used_bytes(lu, lu->username, self);
  if (used >= quota) {
    *remaining = 0;
    return -1;
  }
  *remaining = quota - used;
  return 0;
}

static void local_apply_session_params(struct user_session_t* user,
                                       const struct local_user_t* lu,
                                       uint64_t remaining_quota) {
  uint64_t quota = lu->data_quota > 0 ? remaining_quota : 0;

  user->in_rate = (lu->in_speed > 0) ? lu->in_speed * 125000u : 0;
  user->out_rate = (lu->out_speed > 0) ? lu->out_speed * 125000u : 0;
  user->in_giga_rate = 0;
  user->out_giga_rate = 0;

  user->quota_giga_bytes = (uint32_t)(quota >> 32);
  user->quota_bytes = (uint32_t)(quota & 0xFFFFFFFFULL);
  user->quota_data = quota;

  if (lu->expire_time[0] != '\0') {
    time_t exp = local_time_parse(lu->expire_time);
    time_t now = (time_t)get_now_time();
    long remain = (exp > now) ? (long)(exp - now) : 0;
    user->session_timeout = (remain > 0) ? (uint32_t)remain : 0;
  } else {
    user->session_timeout = 0;
  }
  /* 空闲超时由 ev_auth_accept 按本地 UCI webauthd.generic.idle_timeout 统一取值 */
  user->idle_timeout = 0;

  user->local_flushed_bytes = 0;
  user->local_flush_mark = get_now_time();
}

/* 登录成功统计: last_login_time + login_count。
 * 不立即落盘, 改为记录到会话挂起字段, 随 300s 兜底/下线终算的
 * local_auth_flush_session 一并写盘, 减少每次登录对 flash 的写次数。 */
static void local_touch_login_stats(struct user_session_t* user,
                                    struct local_user_t* lu) {
  user->local_pending_login_epoch = (long)time(NULL);
  if (lu->login_count < UINT32_MAX) {
    user->local_pending_login_count = lu->login_count + 1;
  } else {
    user->local_pending_login_count = lu->login_count;
  }
  user->local_pending_login = 1;
}

/* 自动 MAC 绑定: 未绑定时在配额内直接绑; 已满按策略(0 不绑/1 替换最早)。
 * 绑定失败不影响本次登录。 */
static void local_mac_auto_bind(struct local_user_t* lu,
                                const uint8_t mac[6]) {
  char mac_str[18];
  char err[128] = {0};
  struct local_mac_bind_t binds[LOCAL_MAC_BIND_MAX];
  int cnt = 0;
  int i, oldest = -1;

  if (lu->max_mac_bind <= 0) {
    return;
  }
  local_mac_to_str(mac, mac_str, sizeof(mac_str));

  if (local_mac_load(lu->username, binds, &cnt, err, sizeof(err)) != 0) {
    cnt = 0;
  }
  for (i = 0; i < cnt; ++i) {
    if (strcmp(binds[i].mac, mac_str) == 0) {
      return; /* 已绑定 */
    }
  }

  if (cnt >= lu->max_mac_bind) {
    if (lu->mac_bind_update_policy != 1) {
      log_info("Local auth: mac bind full(%d) policy=0, skip bind user='%s' "
               "mac=%s",
               lu->max_mac_bind, lu->username, mac_str);
      return;
    }
    /* bind_time 为 "YYYY-MM-DD HH:MM:SS", 字典序即时间序; 空串视为最早 */
    for (i = 0; i < cnt; ++i) {
      if (oldest < 0 || strcmp(binds[i].bind_time, binds[oldest].bind_time) < 0) {
        oldest = i;
      }
    }
    if (oldest < 0) {
      return;
    }
    snprintf(binds[oldest].mac, sizeof(binds[oldest].mac), "%s", mac_str);
    local_time_format(time(NULL), binds[oldest].bind_time,
                      sizeof(binds[oldest].bind_time));
    log_info("Local auth: replace oldest mac binding user='%s' mac=%s",
             lu->username, mac_str);
  } else {
    snprintf(binds[cnt].mac, sizeof(binds[cnt].mac), "%s", mac_str);
    local_time_format(time(NULL), binds[cnt].bind_time,
                      sizeof(binds[cnt].bind_time));
    cnt++;
    log_info("Local auth: bind mac user='%s' mac=%s (%d/%d)", lu->username,
             mac_str, cnt, lu->max_mac_bind);
  }

  if (local_mac_save(lu->username, binds, cnt, err, sizeof(err)) != 0) {
    log_warn("Local auth: save mac bind failed user='%s' err=%s", lu->username,
             err);
  }
}

/* max_online 冲突: 0=拒绝新登录, 1=下线最早会话后放行。
 * 返回 0 允许继续登录, -1 拒绝。max_online<=0 视为不限。 */
static int local_resolve_online_conflict(const struct local_user_t* lu,
                                         struct user_session_t* self) {
  int online;
  int kick;

  if (lu->max_online <= 0) {
    return 0;
  }
  online = local_count_online_sessions(lu->username, self);
  if (online < lu->max_online) {
    return 0;
  }
  if (lu->online_conflict_policy != 1) {
    return -1;
  }
  kick = online - lu->max_online + 1;
  while (kick-- > 0) {
    local_kick_earliest_session(lu->username);
  }
  return 0;
}

static void local_auth_reject(struct user_session_t* user, int code,
                              const char* reason) {
  struct evhttp_request* req = user->req;
  struct in_addr tmp;
  tmp.s_addr = user->ip;

  log_warn("Local auth reject: user='%s' ip=%s code=%d(%s) reason=%s",
           user->user_name, inet_ntoa(tmp), code,
           get_http_reply_msg(code) ? get_http_reply_msg(code) : "unknown",
           reason);
  user->req = NULL;
  user->status = USER_STATE_INIT;
  user->http_reply_code = code;
  if (req) {
    send_http_reply(req, code, NULL);
  }
  /* 与 ev_auth_reject 一致: 60s 后仍未认证则回收会话 */
  start_waiting_auth_timer(user);
}

void local_portal_login(struct user_session_t* user) {
  struct local_user_t lu;
  char err[128] = {0};
  struct in_addr tmp;
  int code = PORTAL_LOCAL_USER_NOT_FOUND;
  uint64_t remaining_quota = 0;

  if (!user || !user->inst) {
    return;
  }
  tmp.s_addr = user->ip;

  if (local_user_load(user->user_name, &lu, err, sizeof(err)) != 0) {
    local_auth_reject(user, PORTAL_LOCAL_USER_NOT_FOUND, err);
    return;
  }
  if (lu.status != LOCAL_USER_STATUS_ACTIVE) {
    local_auth_reject(user, PORTAL_LOCAL_USER_DISABLED, "user disabled");
    return;
  }
  if (lu.expire_time[0] != '\0') {
    time_t exp = local_time_parse(lu.expire_time);
    if (exp > 0 && (time_t)get_now_time() >= exp) {
      local_auth_reject(user, PORTAL_LOCAL_USER_EXPIRED, "account expired");
      return;
    }
  }
  if (local_verify_password(user->user_password, lu.password_hash) != 0) {
    local_auth_reject(user, PORTAL_LOCAL_PASSWD_ERROR, "wrong password");
    return;
  }
  if (local_quota_remaining(&lu, user, &remaining_quota) != 0) {
    local_auth_reject(user, PORTAL_LOCAL_QUOTA_EXHAUSTED,
                      "data quota exhausted");
    return;
  }
  if (local_resolve_online_conflict(&lu, user) != 0) {
    local_auth_reject(user, PORTAL_LOCAL_MAX_ONLINE,
                      "max_online reached (conflict policy=0)");
    return;
  }

  local_mac_auto_bind(&lu, user->mac);
  local_touch_login_stats(user, &lu);
  local_apply_session_params(user, &lu, remaining_quota);

  log_info(
      "Local auth accept: user='%s' ip=%s in=%uMbps out=%uMbps quota=%uMB "
      "session_timeout=%us",
      user->user_name, inet_ntoa(tmp), lu.in_speed, lu.out_speed, lu.data_quota,
      user->session_timeout);

  if (process_server_events(EV_AUTH_ACCEPT, NULL, (void*)user) < 0) {
    /* accept 内部已回错并复位状态 */
    return;
  }
}

int local_mac_auth(struct inst_t* inst, struct user_session_t* user) {
  char mac_str[18] = {0};
  char username[LOCAL_USERNAME_MAX + 1] = {0};
  struct local_user_t lu;
  char err[128] = {0};
  struct in_addr tmp;
  uint64_t remaining_quota = 0;

  if (!inst || !user || !inst->config) {
    return -1;
  }
  tmp.s_addr = user->ip;
  local_mac_to_str(user->mac, mac_str, sizeof(mac_str));

  /* create_user 仅在全局 mac_auth 开启时才把 authtype 置为 MAC, 双重确认 */
  if (!inst->config->mac_auth_enabled) {
    goto fallback;
  }
  if (local_mac_lookup_owner(mac_str, username, sizeof(username)) != 0) {
    goto fallback;
  }
  if (local_user_load(username, &lu, err, sizeof(err)) != 0) {
    goto fallback;
  }
  if (lu.status != LOCAL_USER_STATUS_ACTIVE) {
    goto fallback;
  }
  if (!lu.mac_auth) {
    goto fallback;
  }
  if (lu.expire_time[0] != '\0') {
    time_t exp = local_time_parse(lu.expire_time);
    if (exp > 0 && (time_t)get_now_time() >= exp) {
      goto fallback;
    }
  }
  if (local_quota_remaining(&lu, user, &remaining_quota) != 0) {
    snprintf(err, sizeof(err), "%s", "data quota exhausted");
    goto fallback;
  }
  if (local_resolve_online_conflict(&lu, user) != 0) {
    log_warn("Local MAC auth: max_online conflict, fallback user='%s' mac=%s",
             username, mac_str);
    goto fallback;
  }

  snprintf(user->user_name, sizeof(user->user_name), "%s", username);
  memset(user->user_password, 0, sizeof(user->user_password));
  local_touch_login_stats(user, &lu);
  local_apply_session_params(user, &lu, remaining_quota);
  user->status = USER_STATE_AUTHING;

  log_info("Local MAC pass-through auth: user='%s' mac=%s ip=%s", username,
           mac_str, inet_ntoa(tmp));
  if (process_server_events(EV_AUTH_ACCEPT, NULL, (void*)user) < 0) {
    user->status = USER_STATE_INIT;
    user->authtype = USER_AUTH_TYPE_PORTAL;
    return -1;
  }
  return 0;

fallback:
  log_info("Local MAC auth fallback to portal: mac=%s ip=%s (%s)", mac_str,
           inet_ntoa(tmp), err[0] ? err : "not bound or not allowed");
  user->authtype = USER_AUTH_TYPE_PORTAL;
  user->status = USER_STATE_INIT;
  return -1;
}

/* ------------------------------------------------------------------------ */
/* 用量/在线时长持久化                                                       */
/* ------------------------------------------------------------------------ */

int local_auth_flush_session(struct user_session_t* user, int final) {
  struct local_user_t lu;
  char err[128] = {0};
  uint64_t session_bytes, delta_bytes;
  uint32_t delta_mb;
  long delta_time = 0, now;
  int had_pending;

  if (!user || !user->inst || !user->inst->config) {
    return -1;
  }
  if (user->inst->config->auth_source != AUTH_SOURCE_LOCAL) {
    return 0;
  }
  if (user->user_name[0] == '\0') {
    return 0;
  }
  if (local_user_load(user->user_name, &lu, err, sizeof(err)) != 0) {
    return -1; /* 用户文件已被删除等, 无法落盘 */
  }

  now = get_now_time();
  session_bytes = user->inbytes + user->outbytes;
  delta_bytes = (session_bytes > user->local_flushed_bytes)
                    ? (session_bytes - user->local_flushed_bytes)
                    : 0;
  delta_mb = (uint32_t)(delta_bytes / ONE_MB);
  if (user->local_flush_mark > 0 && now > user->local_flush_mark) {
    delta_time = now - user->local_flush_mark;
  }

  /* 合并延迟落盘的登录统计: 有挂起时无条件写盘(即使无增量流量/时长) */
  had_pending = user->local_pending_login;
  {
    if (had_pending) {
      if (user->local_pending_login_epoch > 0) {
        local_time_format((time_t)user->local_pending_login_epoch,
                          lu.last_login_time, sizeof(lu.last_login_time));
      }
      lu.login_count = user->local_pending_login_count;
    }
    if (!final && !had_pending && delta_mb == 0 && delta_time == 0) {
      return 0;
    }
  }

  if (delta_mb > 0) {
    if (lu.current_data > UINT32_MAX - delta_mb) {
      lu.current_data = UINT32_MAX;
    } else {
      lu.current_data += delta_mb;
    }
  }
  if (delta_time > 0) {
    if (lu.online_time > UINT32_MAX - (uint32_t)delta_time) {
      lu.online_time = UINT32_MAX;
    } else {
      lu.online_time += (uint32_t)delta_time;
    }
  }
  if (local_user_save(&lu, err, sizeof(err)) != 0) {
    log_warn("Local auth: flush save failed user='%s' err=%s", user->user_name,
             err);
    return -1;
  }

  /* 只有持久化成功后才推进水位和清除 pending；失败可原样重试。 */
  user->local_flushed_bytes += (uint64_t)delta_mb * ONE_MB;
  user->local_flush_mark = now;
  if (had_pending) {
    user->local_pending_login = 0;
  }
  return 0;
}

static void local_flush_cb(struct user_session_t* user, void* arg) {
  (void)arg;
  if (user->status != USER_STATE_AUTHED &&
      !(user->status == USER_STATE_DROPPING &&
        user->local_flush_final_pending)) {
    return;
  }
  if (local_auth_flush_session(user, user->local_flush_final_pending) == 0 &&
      user->local_flush_final_pending) {
    user->local_flush_final_pending = 0;
    if (user->nft_rules_state == NFT_RULES_NONE) {
      del_user(user->inst, user);
    } else {
      user->nft_revoke_delete_on_success = 1;
      start_nft_revoke_retry(user, 1);
    }
  }
}

void local_auth_flush_all(void) {
  struct inst_t* inst = get_inst();
  if (!inst || !inst->config || inst->config->auth_source != AUTH_SOURCE_LOCAL) {
    return;
  }
  for_each_user_session(local_flush_cb, NULL);
}

/* ------------------------------------------------------------------------ */
/* 踢下线巡检(60s)                                                           */
/* ------------------------------------------------------------------------ */

struct local_inspect_ctx {
  struct user_session_t* victims[INST_USER_MAX];
  int victim_count;
};

static void local_inspect_collect_cb(struct user_session_t* user, void* arg) {
  struct local_inspect_ctx* ctx = (struct local_inspect_ctx*)arg;
  struct local_user_t lu;
  char err[128] = {0};
  struct in_addr tmp;
  time_t now;

  if (ctx->victim_count >= INST_USER_MAX) {
    return;
  }
  if (user->status != USER_STATE_AUTHED || user->user_name[0] == '\0') {
    return;
  }
  tmp.s_addr = user->ip;
  now = time(NULL);

  if (local_user_load(user->user_name, &lu, err, sizeof(err)) != 0) {
    log_info("Local inspect: user file missing, kick user='%s' ip=%s",
             user->user_name, inet_ntoa(tmp));
    ctx->victims[ctx->victim_count++] = user;
    return;
  }
  if (lu.status != LOCAL_USER_STATUS_ACTIVE) {
    log_info("Local inspect: user disabled, kick user='%s' ip=%s",
             user->user_name, inet_ntoa(tmp));
    ctx->victims[ctx->victim_count++] = user;
    return;
  }
  if (lu.expire_time[0] != '\0') {
    time_t exp = local_time_parse(lu.expire_time);
    if (exp > 0 && now >= exp) {
      log_info("Local inspect: account expired, kick user='%s' ip=%s",
               user->user_name, inet_ntoa(tmp));
      ctx->victims[ctx->victim_count++] = user;
      return;
    }
  }
  if (lu.data_quota > 0) {
    uint64_t used = local_account_used_bytes(&lu, user->user_name, NULL);
    if (used >= (uint64_t)lu.data_quota * ONE_MB) {
      log_info("Local inspect: data quota used(%lluMB)>=quota(%uMB), kick "
               "user='%s' ip=%s",
               (unsigned long long)(used / ONE_MB), lu.data_quota,
               user->user_name, inet_ntoa(tmp));
      ctx->victims[ctx->victim_count++] = user;
    }
  }
}

static void local_inspect_timer_cb(const int fd, const short event,
                                   void* arg) {
  struct inst_t* inst = (struct inst_t*)arg;
  struct local_inspect_ctx ctx;
  int i;

  (void)fd;
  (void)event;
  if (!inst || !inst->config || inst->config->auth_source != AUTH_SOURCE_LOCAL) {
    return;
  }
  memset(&ctx, 0, sizeof(ctx));
  for_each_user_session(local_inspect_collect_cb, &ctx);
  for (i = 0; i < ctx.victim_count; ++i) {
    process_server_events(EV_CLOSE_SESSION, NULL, (void*)ctx.victims[i]);
  }
}

/* ------------------------------------------------------------------------ */
/* 生命周期                                                                  */
/* ------------------------------------------------------------------------ */

static struct event* s_inspect_ev = NULL;
static struct event* s_flush_ev = NULL;

static void local_flush_timer_cb(const int fd, const short event, void* arg);

int local_auth_init(struct inst_t* inst) {
  int count = 0;

  if (!inst || !inst->config) {
    return -1;
  }
  if (mkdir(LOCAL_USERS_DIR, 0700) != 0 && errno != EEXIST) {
    log_error("local_auth: mkdir '%s' failed: %s", LOCAL_USERS_DIR,
              strerror(errno));
    return -1;
  }
  local_user_count(&count);
  log_info("local_auth: user dir '%s' ready, users=%d, auth_source=%s",
           LOCAL_USERS_DIR, count,
           inst->config->auth_source == AUTH_SOURCE_LOCAL
               ? "local"
               : (inst->config->auth_source == AUTH_SOURCE_RADIUS ? "radius"
                                                                  : "other"));
  return 0;
}

int local_auth_start_timers(struct inst_t* inst) {
  struct timeval tv;

  if (!inst || !inst->base || !inst->config) {
    return -1;
  }
  if (inst->config->auth_source != AUTH_SOURCE_LOCAL) {
    log_info("local_auth: auth_source != local, timers skipped");
    return 0;
  }

  s_inspect_ev = event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                           local_inspect_timer_cb, inst);
  if (!s_inspect_ev) {
    log_error("local_auth: create inspect timer failed");
    return -1;
  }
  tv.tv_sec = LOCAL_INSPECT_INTERVAL;
  tv.tv_usec = 0;
  if (event_add(s_inspect_ev, &tv) != 0) {
    event_free(s_inspect_ev);
    s_inspect_ev = NULL;
    log_error("local_auth: add inspect timer failed");
    return -1;
  }

  s_flush_ev = event_new(inst->base, -1, EV_TIMEOUT | EV_PERSIST,
                         local_flush_timer_cb, inst);
  if (!s_flush_ev) {
    event_del(s_inspect_ev);
    event_free(s_inspect_ev);
    s_inspect_ev = NULL;
    log_error("local_auth: create flush timer failed");
    return -1;
  }
  tv.tv_sec = LOCAL_FLUSH_INTERVAL;
  tv.tv_usec = 0;
  if (event_add(s_flush_ev, &tv) != 0) {
    event_free(s_flush_ev);
    s_flush_ev = NULL;
    event_del(s_inspect_ev);
    event_free(s_inspect_ev);
    s_inspect_ev = NULL;
    log_error("local_auth: add flush timer failed");
    return -1;
  }

  log_info("local_auth: timers started (inspect=%ds, flush=%ds)",
           LOCAL_INSPECT_INTERVAL, LOCAL_FLUSH_INTERVAL);
  return 0;
}

static void local_flush_timer_cb(const int fd, const short event, void* arg) {
  (void)fd;
  (void)event;
  (void)arg;
  local_auth_flush_all();
}

void local_auth_stop_timers(void) {
  if (s_inspect_ev) {
    event_del(s_inspect_ev);
    event_free(s_inspect_ev);
    s_inspect_ev = NULL;
  }
  if (s_flush_ev) {
    event_del(s_flush_ev);
    event_free(s_flush_ev);
    s_flush_ev = NULL;
  }
}
