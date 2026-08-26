
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "fwx_user.h"
#include "fwx_netlink.h"
#include "fwx_ubus.h"
#include "fwx_config.h"
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fwx.h"
#include <stdio.h>
#include "fwx_utils.h"



void fwx_init_time_status(fwx_run_time_status_t *status){
    status->filter = 0;
    status->deny_time = 0;
    status->allow_time = 0;
    status->match_time = 0;
}


int fwx_check_time_manual(fwx_time_config_t *t_config, fwx_run_time_status_t *status) {
	int i;
    time_t now = time(NULL);

    struct tm *current_time = localtime(&now);
    int current_minutes = current_time->tm_hour * 60 + current_time->tm_min;
    int current_wday = current_time->tm_wday; // 0=Sunday, 1=Monday, ..., 6=Saturday

    LOG_DEBUG("current time: %02d:%02d, weekday: %d\n", current_time->tm_hour, current_time->tm_min, current_wday);
    for (i = 0; i < t_config->time_num; i++) {

        if (t_config->time_list[i].weekday_map[current_wday] == 0) {
            continue; // Skip if weekday is not enabled
        }
        
        int start_minutes = t_config->time_list[i].start_time.hour * 60 + t_config->time_list[i].start_time.min;
        int end_minutes = t_config->time_list[i].end_time.hour * 60 + t_config->time_list[i].end_time.min;
        LOG_DEBUG("check time: %02d:%02d-%02d:%02d, weekday_map[%d]=%d\n", 
               t_config->time_list[i].start_time.hour, t_config->time_list[i].start_time.min,
               t_config->time_list[i].end_time.hour, t_config->time_list[i].end_time.min,
               current_wday, t_config->time_list[i].weekday_map[current_wday]);
        
        if (current_minutes >= start_minutes && current_minutes <= end_minutes) {
            LOG_DEBUG("current time in time list\n");
            status->match_time = 1;
            return 1;
        }
    }
    status->match_time = 0;
    return 0;
}

int fwx_check_time_dynamic(fwx_time_config_t *t_config, fwx_run_time_status_t *status) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    int current_minutes = current_time->tm_hour * 60 + current_time->tm_min;

    int start_minutes = t_config->seg_time.start_time.hour * 60 + t_config->seg_time.start_time.min;
    int end_minutes = t_config->seg_time.end_time.hour * 60 + t_config->seg_time.end_time.min;
    printf("check seg_time: %02d:%02d-%02d:%02d\n", 
           t_config->seg_time.start_time.hour, t_config->seg_time.start_time.min,
           t_config->seg_time.end_time.hour, t_config->seg_time.end_time.min);
    if (!(current_minutes >= start_minutes && current_minutes <= end_minutes)) {
        printf("current time not in seg_time\n");
        fwx_init_time_status(status);
        return 0; 
    }

    status->match_time = 1;
    if (status->filter == 1) {
        status->deny_time++;
        if (status->deny_time >= t_config->deny_time) {
            status->filter = 0;
            status->deny_time = 0;
            printf("deny time over, filter = 0");
        }
        printf("deny_time: %d\n", status->deny_time);
    } else {
        status->allow_time++;
        if (status->allow_time >= t_config->allow_time) {
            status->filter = 1;
            status->allow_time = 0;
            printf("allow time over, filter = 1");
        }
        printf("allow_time: %d\n", status->allow_time);
    }
    return status->filter;
}

int fwx_check_time(fwx_time_config_t *t_config, fwx_run_time_status_t *status) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    int current_wday = current_time->tm_wday; // 0=Sunday, 1=Monday, ..., 6=Saturday
    LOG_DEBUG("current day: %d\n", current_wday);

    if (t_config->time_mode == 0) {
        LOG_DEBUG("manual mode\n");
        return fwx_check_time_manual(t_config, status);
    } else {
        LOG_DEBUG("dynamic mode\n");

        if (t_config->seg_time.weekday_map[current_wday] == 0) {
            LOG_DEBUG("current day not in configured days\n");
            fwx_init_time_status(status);
            return 0;
        }
        return fwx_check_time_dynamic(t_config, status);
    }
}


struct json_object * fwx_gen_api_response_data(int code, struct json_object *data_obj){
    struct json_object *root_obj = json_object_new_object();
    if (!root_obj)
        return NULL;
    json_object_object_add(root_obj, "code", json_object_new_int(code));
    if (data_obj)
        json_object_object_add(root_obj, "data", data_obj);
    return root_obj;
}
