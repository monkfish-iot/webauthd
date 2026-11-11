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
#ifndef ___XYZ_LOG_H__
#define ___XYZ_LOG_H__

/*
 * 为了避免与其他程序定义的日志函数名重名
 * 特加前缀xyz以示区别
 */

#include <errno.h>

#define XYZ_LOG_LEVEL_EMESG		0	//   致命级
#define XYZ_LOG_LEVEL_ALERT		1	//   警戒级
#define XYZ_LOG_LEVEL_CRIT		2	//   临界级
#define XYZ_LOG_LEVEL_ERROR		3	//   错误级
#define XYZ_LOG_LEVEL_WARN		4	//   告警级
#define XYZ_LOG_LEVEL_NOTICE            5	//   注意级
#define XYZ_LOG_LEVEL_INFO		6	//   通知级
#define XYZ_LOG_LEVEL_DEBUG		7	//   调试级


extern volatile int __log_level;

void __log_base_print(int level, const char *format, ...);
void __log_base_colour_print(int level, const char *filename, int line, const char *function,const char *format, ...);


#define XYZ_LOG_LEVEL(level) XYZ_LOG_LEVEL_##level


/*
 * 编译时请注意定义宏
 */
#ifdef __XYZ_DEBUG__
#define XYZ_LOG_BASE_PRINT(level, format, args...) __log_base_colour_print(XYZ_LOG_LEVEL(level),__FILE__, __LINE__, __FUNCTION__, format, ##args)
#else
#define XYZ_LOG_BASE_PRINT(level, format, args...) __log_base_print(XYZ_LOG_LEVEL(level), format, ##args)
#endif

#define log_debug(format, args...)	((__log_level > XYZ_LOG_LEVEL_INFO) ? XYZ_LOG_BASE_PRINT(DEBUG, format, ##args) : (void)0)

#define log_info(format, args...)	((__log_level > XYZ_LOG_LEVEL_NOTICE) ? XYZ_LOG_BASE_PRINT(INFO, format, ##args) : (void)0)

#define log_warn(format, args...)	((__log_level > XYZ_LOG_LEVEL_ERROR) ? XYZ_LOG_BASE_PRINT(WARN,  format, ##args) : (void)0)

#define log_error(format, args...)	((__log_level > XYZ_LOG_LEVEL_CRIT) ? XYZ_LOG_BASE_PRINT(ERROR, format, ##args) : (void)0)

//  初始化日志输出、级别设置
int log_init(const char *file, unsigned int level, unsigned long int size);

//  关闭日志输出
void log_close(void);

#endif // ___XYZ_LOG_H__

