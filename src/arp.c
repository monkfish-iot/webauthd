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
#include <stdlib.h>  
#include <string.h>  
#include <ctype.h>  
  
int get_mac_by_ip(const char *ip_str, unsigned char mac[6]) {  
    FILE *fp;  
    char line[256];  
    char ip_line[16];  
    char mac_line[20];  
    char *token;  
    int found = 0;  
  
    fp = fopen("/proc/net/arp", "r");  
    if (!fp) {  
        perror("Failed to open /proc/net/arp");  
        return -1;  
    }  
  
    while (fgets(line, sizeof(line), fp)) {  
        // 跳过IP地址字段（包括前面的空白和IP地址本身）  
        token = strtok(line, " ");  
        if (!token) continue;  
        strcpy(ip_line, token);  
  
        // 读取并跳过HW type和Flags字段  
        strtok(NULL, " ");  
        strtok(NULL, " ");  
  
        // 读取并解析HW address字段  
        token = strtok(NULL, " ");  
        if (!token) continue;  
        strcpy(mac_line, token);  
  
        // 检查IP地址是否匹配  
        if (strcmp(ip_line, ip_str) == 0) {  
            // 转换MAC地址字符串到二进制  
            for (int i = 0; i < 6; i++) {  
                sscanf(mac_line + (i * 3), "%2hhx", &mac[i]);  
                if (mac_line[i * 3 + 2] == ':') mac_line[i * 3 + 2] = '\0'; // 移除冒号（可选）  
            }  
            found = 1;  
            break;  
        }  
    }  
  
    fclose(fp);  
  
    return found ? 0 : -1;  
}  
  
 
