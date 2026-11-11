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
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#include <uuid/uuid.h>
#include <time.h>
#include "log.h"
#include "utensils.h"
#include "session.h"
#include "config.h"


#define RESOLV_CONF_PATH "/tmp/resolv.conf.d/resolv.conf.auto"  
#define MAX_LINE_LENGTH 1024  

int  get_dns_server(char* buf) {
    FILE *file = fopen(RESOLV_CONF_PATH, "r");

    if (!file) {
        perror("Error opening resolv.conf");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        // 去除行尾的换行符  
        line[strcspn(line, "\n")] = 0;

        // 查找以"nameserver"开头的行  
        if (strncmp(line, "nameserver", 10) == 0) {
            // 跳过"nameserver"和空格  
            char *dns_server = line + 10;
            while (*dns_server == ' ' || *dns_server == '\t') dns_server++;

            // 打印DNS服务器地址  
            // printf("DNS Server: %s\n", dns_server);  
            if(dns_server){
            snprintf(buf, 32, "%.31s", dns_server);
            break;
            }
        }
    }

    fclose(file);
    return 0;
}

int get_rand(size_t len, unsigned char* value) {
    FILE* pf = fopen("/dev/urandom", "r");
    if (!pf) {
        return -1;
    }
    int n = fread(value, 1, len, pf);
    if (n < 0) {
        fclose(pf);
        return -1;
    }
    fclose(pf);
    return 0;
}

void mac_64_to_8(uint64_t u64_mac, uint8_t u8_mac[]) {
    uint8_t* p = (uint8_t*) & u64_mac;
    u8_mac[0] = p[5] & 0xFF;
    u8_mac[1] = p[4] & 0xFF;
    u8_mac[2] = p[3] & 0xFF;
    u8_mac[3] = p[2] & 0xFF;
    u8_mac[4] = p[1] & 0xFF;
    u8_mac[5] = p[0] & 0xFF;



}

uint64_t mac_8_to_64(uint8_t mac[]) {
    uint64_t u64_mac = 0;
    u64_mac = mac[0] & 0xFF;
    u64_mac = u64_mac << 8 | mac[1]& 0xFF;
    u64_mac = u64_mac << 8 | mac[2]& 0xFF;
    u64_mac = u64_mac << 8 | mac[3]& 0xFF;
    u64_mac = u64_mac << 8 | mac[4]& 0xFF;
    u64_mac = u64_mac << 8 | mac[5]& 0xFF;

    return u64_mac;

}

uint32_t get_now_hour_timestamp() {
    time_t now;
    struct tm* t;
    uint32_t now_hour = 0;
    time(&now);
    t = localtime(&now);
    t->tm_min = 0;
    t->tm_sec = 0;
    t->tm_hour = (t->tm_hour++) % 24;
    now_hour = mktime(t);

    //printf("hour=%d now_hour=%u\n", t->tm_hour, now_hour);

    return now_hour;
}

long get_now_time() {
    time_t now;
    struct tm* t;
    time(&now);
    t = localtime(&now);

    return mktime(t);


}

uint32_t get_next_local_hour() {
    time_t now;
    struct tm* t;
    time(&now);
    t = localtime(&now);
    t->tm_hour = (t->tm_hour++) % 23;
    t->tm_sec = 0;
    t->tm_min = 0;
    return mktime(t);


}

/*
 * 将二进制的MAC地址转换为字符串形式
 */
int xmac_to_str(unsigned char *b, int len, char *s, int size) {
    int rc = 0;
    const char *temp = "%02X:%02X:%02X:%02X:%02X:%02X";

    if (!s || len != XMAC_BLEN || !b || size < XMAC_SLEN) {
        return -1;
    }
    rc = snprintf(s, XMAC_SLEN + 1, temp, b[0], b[1], b[2], b[3], b[4], b[5]);
    if (rc != XMAC_SLEN) {
        return -1;
    }
    return 0;
}

/*
 * 获取sessid
 */

 
int generate_acct_id(char *buf, int size) {
    if (!buf || size < 2) {
        log_error("Invalid buffer or size for generate_acct_id");
        return -1;
    }
    
    // 使用包含所有字母和数字的字符集
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int charset_size = sizeof(charset) - 1;
    
    // 直接生成随机字符
    for (int i = 0; i < size - 1; i++) {
        unsigned char random_byte;
        FILE* pf = fopen("/dev/urandom", "r");
        if (pf) {
            if (fread(&random_byte, 1, 1, pf) == 1) {
                buf[i] = charset[random_byte % charset_size];
            } else {
                // 如果读取失败，使用简单方法
                srand(time(NULL) + i);
                buf[i] = charset[rand() % charset_size];
            }
            fclose(pf);
        } else {
            // 如果无法打开/dev/urandom
            srand(time(NULL) + i);
            buf[i] = charset[rand() % charset_size];
        }
    }
    
    buf[size - 1] = '\0';
    return 0;
}


/*
 * 将字符串形式的MAC地址转化为二进制
 */
int xmac_to_byte(const char *s, int len, unsigned char *b, int size) {
    int i;

    if (!s || !b || size < XMAC_BLEN || len != XMAC_SLEN ||
        strlen(s) != XMAC_SLEN) {
        return -1;
    }
    for (i = 0; i < XMAC_BLEN; ++i) {
        int off = i * 3;
        int hi;
        int lo;
        if (i > 0 && s[off - 1] != ':') {
            return -1;
        }
        hi = isxdigit((unsigned char)s[off])
                 ? (isdigit((unsigned char)s[off])
                        ? s[off] - '0'
                        : (tolower((unsigned char)s[off]) - 'a' + 10))
                 : -1;
        lo = isxdigit((unsigned char)s[off + 1])
                 ? (isdigit((unsigned char)s[off + 1])
                        ? s[off + 1] - '0'
                        : (tolower((unsigned char)s[off + 1]) - 'a' + 10))
                 : -1;
        if (hi < 0 || lo < 0) {
            return -1;
        }
        b[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

int get_local_address(char* ip, char* mac) {
    struct ifreq *ifr, *ifend;
    struct inst_t* inst = get_inst();
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[64];
    uint8_t* tmpAddrPtr = NULL;
    // struct ifaddrs *ifa = NULL;
    int sockfd;
    char* str_ip = NULL;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ifc.ifc_len = sizeof (ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        log_error("ioctl(SIOCGIFCONF): %m\n");
        return 0;
    }
    ifend = ifs + (ifc.ifc_len / sizeof (struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
        strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof (ifreq.ifr_name));

        if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
            log_error("ioctl(SIOCGIFFLAGS)(%s): %m\n", ifreq.ifr_name);
            close(sockfd);
            return -1;
        }

        str_ip = inet_ntoa(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr);
        if (memcmp(inst->config->layer3_ifname, ifreq.ifr_name, strlen(ifreq.ifr_name) + 1) == 0) {
            snprintf(ip, 24, "%s", str_ip);

            //  printf("\nIp Address %s\n", ip);
            // printf("+++++family=%d flag=%02x name=%s\n\n", ifr->ifr_addr.sa_family, ifreq.ifr_flags, ifreq.ifr_name);
            /*
                        //strncpy(ifreq.ifr_name, "ens3",sizeof(ifreq.ifr_name));
                        strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
                        if (ioctl (sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
                            printf("SIOCGIFHWADDR(%s): %m/n", ifreq.ifr_name);
                            return 0;
                        }
             */
            break;
        }
    }
    close(sockfd);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr_mac;
    ifr_mac.ifr_addr.sa_family = AF_INET;
    strcpy(ifr_mac.ifr_name, inst->config->layer3_ifname);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr_mac) < 0) {
        close(sockfd);
        return -1;
    }

    close(sockfd);

    tmpAddrPtr = (unsigned char *) ifr_mac.ifr_hwaddr.sa_data;





    memcpy(mac, tmpAddrPtr, 6);







    close(sockfd);
    return 0;
}

int set_portal_address(struct user_session_t* user, const char* portal_if) {
    struct ifreq *ifr, *ifend;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[64];
    int sockfd;
    char* portal_ip = NULL;
    int len = strlen(portal_if);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {

        return -1;
    }
    ifc.ifc_len = sizeof (ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        log_error("ioctl(SIOCGIFCONF): %m\n");
        close(sockfd);
        return -1;
    }
    ifend = ifs + (ifc.ifc_len / sizeof (struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
        if (strncmp(ifr->ifr_name, portal_if, len) != 0 || strlen(ifr->ifr_name) != len) {

            continue;

        }

        strncpy(ifreq.ifr_name, portal_if, sizeof (ifreq.ifr_name));
        // strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifreq) < 0) {
            log_error("SIOCGIFHWADDR(%s): %m\n", ifreq.ifr_name);
            close(sockfd);
            return -1;
        }
        if (ifr->ifr_addr.sa_family == AF_INET) {
            //printf("\nIp Address %s\t", inet_ntoa(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr));
            // printf("\nDevice %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\t", ifreq.ifr_name,
            /*
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[0],
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[1],
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[2],
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[3],
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[4],
                                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[5]);
             */
            portal_ip = inet_ntoa(((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr);
            strncpy(user->str_portal_ip, portal_ip, strlen(portal_ip));
            memcpy(user->called_station_id, ifreq.ifr_name, 6);
        }
        break;

    }
    close(sockfd);
    return 0;



}

char* get_if_address(char* if_name) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;
    char ip_str[INET_ADDRSTRLEN]; // 用于存储IP地址的字符串  

    // 创建一个socket  
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    // 清除ifr结构并设置接口名称  
    memset(&ifr, 0, sizeof (ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    // 使用ioctl获取接口地址  
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        //  perror("ioctl (SIOCGIFADDR)");  
        log_error("ioctl (SIOCGIFADDR). interface name is %s", if_name);
        close(sockfd);
        return NULL;
    }

    // 转换地址到字符串  
    addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof (ip_str)) == NULL) {
        perror("inet_ntop");
        close(sockfd);
        return NULL;
    }

    // 分配内存并复制IP地址字符串  
    char *ip_addr = malloc(strlen(ip_str) + 1); // +1 for the null terminator  
    if (ip_addr == NULL) {
        perror("malloc");
        close(sockfd);
        return NULL;
    }
    strcpy(ip_addr, ip_str);

    close(sockfd);
    return ip_addr;
}

int get_all_if() {
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa = NULL;
    int family, s;
    char host[NI_MAXHOST];
    char mask[NI_MAXHOST];
    struct in_addr uip, umask;

    struct ifreq ifreq;
    int i = 0;

    struct ifconf ifc;
    struct ifreq ifs[64];
    int sockfd;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    ifc.ifc_len = sizeof (ifs);
    ifc.ifc_req = ifs;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        log_error("ioctl(SIOCGIFCONF): %m\n");
        return 0;
    }


    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    i = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {


        family = ifa->ifa_addr->sa_family;
        // printf("family=%d flag=%d name=%s\n",family,ifa->ifa_flags ,ifa->ifa_name);
        strncpy(ifreq.ifr_name, ifa->ifa_name, sizeof (ifreq.ifr_name));
        if (ioctl(sockfd, SIOCGIFFLAGS, &ifreq) < 0) {
            log_error("ioctl(SIOCGIFFLAGS)(%s): %m/n", ifreq.ifr_name);
            break;
        }
        //printf("+++++family=%d flag=%02x name=%s\n\n",ifr->ifr_addr.sa_family ,ifreq.ifr_flags   ,ifreq.ifr_name);

        //   printf("+++++family=%d flag=0x%02x name=%s\n\n", family, ifreq.ifr_flags, ifreq.ifr_name);


        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr,
                    sizeof (struct sockaddr_in),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_error("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }

            s = getnameinfo(ifa->ifa_netmask,
                    sizeof (struct sockaddr_in),
                    mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_error("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }

            log_debug("host=%s name=%s mas=%s\n", host, ifa->ifa_name, mask);

        }
    }

    freeifaddrs(ifaddr);
    return 0;

}

uint32_t get_now_timestamp() {
    time_t now;
    struct tm* t;
    time(&now);
    t = localtime(&now);
    return mktime(t);
}

uint32_t get_next_hour_interval() {
    time_t now;
    struct tm* t;
    uint32_t next_hour = 0;
    uint32_t now_time = get_now_timestamp();
    time(&now);
    t = localtime(&now);
    if (now_time % 3600 == 0) {
        return 3600;
    }
    next_hour = now_time / 3600;
    next_hour = next_hour * 3600;

    next_hour = next_hour + 3600;

    // printf("2+++++++++++now=%u next=%u =%u\n", now_time, next_hour, next_hour - now_time);
    return next_hour - now_time;

}

int set_nonblock(int fd) {
    int flags;

    if (fd < 0) {
        return -1;
    }
    if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
        log_error("fcntl : %s", strerror(errno));
        return -1;
    } else if (fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_ASYNC) != 0) {
        log_error("fcntl : %s", strerror(errno));
        return -1;
    }
    return 0;
}





int find_essid(const char* user_mac, char* essid) {
    // 构造命令字符串
    char command[256];
    snprintf(command, sizeof(command), "/usr/sbin/find_essid.sh %s", user_mac);

    // 使用 popen 执行命令并读取输出
    FILE* fp = popen(command, "r");
    if (!fp) {
        perror("popen failed");
        return -1;
    }

    // 读取脚本的输出
    if (fgets(essid, MAX_ESSID_LENGTH, fp) == NULL) {
        pclose(fp);
        return -1;  // 脚本没有输出
    }

    // 关闭文件指针
    int status = pclose(fp);
    if (status == -1) {
        perror("pclose failed");
        return -1;
    }

    // 检查脚本是否成功执行
    if (WEXITSTATUS(status) != 0) {
        return -1;  // 脚本执行失败
    }

    // 去掉输出中的换行符
    essid[strcspn(essid, "\n")] = '\0';

    // 如果 essid 为空字符串，返回 -1
    if (strlen(essid) == 0) {
        return -1;
    }

    return 0;  // 成功找到 SSID
}
