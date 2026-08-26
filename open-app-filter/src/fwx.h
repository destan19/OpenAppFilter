// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_H___
#define __FWX_H___
#define MIN_INET_ADDR_LEN 7

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <json-c/json.h>
#include "fwx_uci.h"

#define API_CODE_SUCCESS 2000
#define API_CODE_ERROR 4000
#define LOG_FILE_PATH "/tmp/log/fwxd.log"


typedef struct fwx_status {
    
    int internet;
} fwx_status_t;

extern fwx_status_t g_fwx_status;

typedef struct fwx_capability {
    int wireless_support;
} fwx_capability_t;

extern fwx_capability_t g_fwx_capability;

typedef enum {
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARN,
   	LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} LogLevel;

extern int current_log_level;
extern int g_fwxd_debug_mode;

static void af_log(LogLevel level, const char *func, int line, const char *format, ...){
    if (level > current_log_level) 
        return;
    
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    if (!log_file) {
        perror("Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    const char *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO";  break;
        case LOG_LEVEL_WARN:  level_str = "WARN";  break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    fprintf(log_file, "[%s] [%s] %s:%d ", time_str, level_str, func, line);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fclose(log_file);
}

#define LOG_DEBUG(format, ...) af_log(LOG_LEVEL_DEBUG, __func__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...)  af_log(LOG_LEVEL_INFO, __func__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...)  af_log(LOG_LEVEL_WARN, __func__, __LINE__, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) af_log(LOG_LEVEL_ERROR, __func__, __LINE__, format, ##__VA_ARGS__)

#define MAX_TIME_LIST_LEN 1024
#define MAX_TIME_LIST 64
typedef struct af_time
{
    int hour;
    int min;
} af_time_t;


typedef struct time_config{
	af_time_t start_time;
	af_time_t end_time;
}time_config_t;

typedef struct weekday_time_config{
	af_time_t start_time;
	af_time_t end_time;
    unsigned char weekday_map[7]; 
}weekday_time_config_t;

typedef struct fwx_time_config_t{
	int time_mode;
	weekday_time_config_t seg_time;
    int deny_time;
    int allow_time;
    int time_num;
	weekday_time_config_t time_list[MAX_TIME_LIST];
}fwx_time_config_t;


typedef struct fwx_run_time_status{
    int deny_time;
    int allow_time;
    int filter;
    int match_time;
    int enable;
}fwx_run_time_status_t;



void fwx_init_time_status(fwx_run_time_status_t *status);
int fwx_check_time(fwx_time_config_t *t_config, fwx_run_time_status_t *status);
struct json_object *fwx_gen_api_response_data(int code, struct json_object *data_obj);


#endif
