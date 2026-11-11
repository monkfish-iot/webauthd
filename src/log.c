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
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>


#include "log.h"

//  控制台输出颜色定义
#define CLR_NONE          "\033[m"
#define CLR_RED           "\033[0;32;31m"
#define CLR_LIGHT_RED     "\033[1;31m"
#define CLR_GREEN         "\033[0;32;32m"
#define CLR_LIGHT_GREEN   "\033[1;32m"
#define CLR_BLUE          "\033[0;32;34m"
#define CLR_LIGHT_BLUE    "\033[1;34m"
#define CLR_GRAY          "\033[0;37m"
#define CLR_DARY_GRAY     "\033[1;30m"
#define CLR_CYAN          "\033[0;36m"
#define CLR_LIGHT_CYAN    "\033[1;36m"
#define CLR_PURPLE        "\033[0;35m"
#define CLR_LIGHT_PURPLE  "\033[1;35m"
#define CLR_BROWN         "\033[0;33m"
#define CLR_YELLOW        "\033[0;33m"
#define CLR_LIGHT_YELLOW  "\033[1;33m"
#define CLR_WHITE         "\033[1;37m"


//   对应颜色选择
static char *__log_colour_array[] = {
    CLR_WHITE,
    CLR_WHITE,
    CLR_WHITE,
    CLR_RED,
    CLR_YELLOW,
    CLR_GREEN,
    CLR_BLUE,
    CLR_GREEN
};

//   对应输出级别选择 
static char *__log_level_string[] = {
    "EMESG",
    "ALERT",
    "CRIT",
    "Error",
    "Warn",
    "Notice",
    "Info",
    "Debug"
};

//  日志级别
volatile int __log_level = XYZ_LOG_LEVEL_EMESG;

 

//  日志输出文件路径
static char S_log_path[1024];

//  日志信息输出文件
static FILE *S_log_file = NULL;

//  文件描述符
static int S_log_fd = 0;

//  标准文件输出标志
static int S_log_out_std = 1;

//  日志文件大小限制
static long int S_log_size_max = 0;

//  当前日志文件大小
static long int S_log_curr_size = 0;

/*
 * 初始化日志输出、级别设置(请注意该路径要具有可写权限)
 * 参数 ：
 * 		file  输出文件路径及名字
 * 		level 输出级别
 */
int log_init(const char *file, unsigned int level, unsigned long int size)
{
	long int flen = 0;
	//  设置日志输出文件
	if (!file) {
		S_log_file = stderr;
	} else {
		if (!strncmp(file, "stdout", 6)) {
			S_log_file = stdout;
		} else if (!strncmp(file, "stderr", 6)) {
			S_log_file = stderr;
		} else {
			FILE *f = fopen(file, "a");
			if (!f) {
				S_log_file = stderr;
				S_log_out_std = 1;
				return -1;
			}
			strncpy(S_log_path, file, 1023);
			S_log_out_std = 0;
			S_log_file = f;
			S_log_fd = fileno(f);
			flen = ftell(f);
			if (flen < 0) {
				S_log_file = stderr;
				S_log_out_std = 1;
				fclose(S_log_file);
				return -1;
			}
			S_log_curr_size = flen;
		}
	}
	//  日志输出级别
	__log_level = level > XYZ_LOG_LEVEL_DEBUG ? XYZ_LOG_LEVEL_DEBUG : level;
	//  日志文件大小限制
	if (size > 0) {
		S_log_size_max = size;
	}
	return 0;
}

/*
 * 关闭日志输出
 */
void log_close(void)
{
	 
	if (0 == S_log_out_std) {
		fclose(S_log_file);
	}
	S_log_file = stderr;
	S_log_out_std = 1;
	__log_level = XYZ_LOG_LEVEL_EMESG;
	 
}

/*
 * 该函数不带颜色输出，适合程序发布时记录运行日志
 */
void __log_base_print(int level, const char *format, ...)
{
	time_t t;
	long int rc = 0;
	time(&t);
	struct tm tm;
	localtime_r((const time_t*) &t, &tm);
	va_list vlist;
	if (S_log_file) {
		 
		rc = fprintf(S_log_file, "%04d-%02d-%02d %02d:%02d:%02d %s : ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, __log_level_string[level]);
		va_start(vlist, format);
		rc += vfprintf(S_log_file, format, vlist);
		va_end(vlist);
		rc += fprintf(S_log_file, "\n");
		fflush(S_log_file);
		//  日志文件大小限制
		if ((0 == S_log_out_std) && (S_log_size_max > 0) && (rc > 0)) {
			if (S_log_curr_size >= (S_log_size_max - rc)) {
				//  清空日志文件
				fclose(S_log_file);
				S_log_file = fopen(S_log_path, "w");
				if (!S_log_file) {
					S_log_file = stderr;
					S_log_out_std = 1;
				}
				S_log_curr_size = 0;
			} else {
				S_log_curr_size += rc;
			}
		}
		 
	}
}

/*
 * 该函数带有颜色的指令输出，适合控制台Debug调试时使用
 */
void __log_base_colour_print(int level, const char *filename, int line, const char *function,const char *format, ...)
{
	long int rc = 0;
	time_t t;
	time(&t);
	struct tm tm;
	localtime_r((const time_t*) &t, &tm);
	va_list vlist;
	if (S_log_file) {
		 
		rc = fprintf(S_log_file, "%s[%04d-%02d-%02d %02d:%02d:%02d] %s %s:%d %s: ",
				__log_colour_array[level], tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, __log_level_string[level],
				filename, line, function);
		va_start(vlist, format);
		rc += vfprintf(S_log_file, format, vlist);
		va_end(vlist);
		rc += fprintf(S_log_file, CLR_NONE"\n");
		fflush(S_log_file);
		//  日志文件大小限制
		if ((0 == S_log_out_std) && (S_log_size_max > 0) && (rc > 0)) {
			if (S_log_curr_size >= (S_log_size_max - rc)) {
				//  清空日志文件
				fclose(S_log_file);
				S_log_file = fopen(S_log_path, "w");
				if (!S_log_file) {
					S_log_file = stderr;
					S_log_out_std = 1;
				}
				S_log_curr_size = 0;
			} else {
				S_log_curr_size += rc;
			}
		}
		 
	}
}

