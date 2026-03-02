/*
Copyright (C) 2020 Derry <destan19@126.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "appfilter_user.h"
#include "appfilter_netlink.h"
#include "appfilter_ubus.h"
#include "appfilter_config.h"
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "appfilter.h"
#include <stdio.h>
#include "utils.h"

#define CMD_GET_LAN_IP_FMT   "ifconfig %s | grep 'inet addr' | awk '{print $2}' | awk -F: '{print $2}'"
#define CMD_GET_LAN_MASK_FMT "ifconfig %s | grep 'inet addr' | awk '{print $4}' | awk -F: '{print $2}'"


int current_log_level = LOG_LEVEL_INFO;
af_run_time_status_t g_af_status;
int g_oaf_config_change = 1;
af_config_t g_af_config;
int g_hnat_init = 0;
int g_feature_update = 0;
int g_feature_update_time = 0;
void oaf_timeout_handler(struct uloop_timeout *t);

void af_init_time_status(void){
    g_af_status.filter = 0;
    g_af_status.deny_time = 0;
    g_af_status.allow_time = 0;
    g_af_status.match_time = 0;
    g_af_status.remain_time = 0;
    g_af_status.used_time = 0;
    g_af_status.period_blocked = 0;
}


void af_init_status(void){
    af_init_time_status();
}
struct uloop_timeout dev_tm = {
    .cb = oaf_timeout_handler};


static struct uloop_fd appfilter_nl_fd = {
    .cb = appfilter_nl_handler,
};


void apply_time_config_to_uci(af_time_config_t *time_config){
	struct uci_context *uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		printf("Failed to allocate UCI context\n");
		return;
	}
	af_uci_set_int_value(uci_ctx, "appfilter.time.time_mode", time_config->time_mode);

	// Build days string from global weekday array (used as fallback)
	char days_str[128] = {0};
	int first = 1;
	int i, j;
	for (i = 0; i < 7; i++) {
		if (time_config->days[i] == 1) {
			if (!first) {
				strcat(days_str, " ");
			}
			char tmp[8];
			snprintf(tmp, sizeof(tmp), "%d", i);
			strcat(days_str, tmp);
			first = 0;
		}
	}
	af_uci_set_value(uci_ctx, "appfilter.time.days", days_str);

	if (time_config->time_mode == 0) {
		// Manual mode: write time_list
		af_uci_delete(uci_ctx, "appfilter.time.time");
		int time_list_len = time_config->time_num;
		for (i = 0; i < time_list_len; i++) {
			char time_str[256] = {0};
			// Build weekday string: "1,2,4,5"
			char weekday_str[64] = {0};
			first = 1;
			for (j = 0; j < 7; j++) {
				if (time_config->time_list[i].days[j] == 1) {
					if (!first) {
						strcat(weekday_str, ",");
					}
					char tmp[8];
					snprintf(tmp, sizeof(tmp), "%d", j);
					strcat(weekday_str, tmp);
					first = 0;
				}
			}
			// Format time: "HH:MM" with zero padding
			char start_time_str[16] = {0};
			char end_time_str[16] = {0};
			snprintf(start_time_str, sizeof(start_time_str), "%02d:%02d", 
					time_config->time_list[i].start_time.hour, 
					time_config->time_list[i].start_time.min);
			snprintf(end_time_str, sizeof(end_time_str), "%02d:%02d", 
					time_config->time_list[i].end_time.hour, 
					time_config->time_list[i].end_time.min);
			
			// Format: "1,2,4,5;00:00-23:59"
			snprintf(time_str, sizeof(time_str), "%s;%s-%s", weekday_str, start_time_str, end_time_str);
			
			printf("time_str: %s\n", time_str);
			af_uci_add_list(uci_ctx, "appfilter.time.time", time_str);
		}
	} else {
		// Dynamic mode: write seg_time, deny_time, allow_time
		af_uci_set_int_value(uci_ctx, "appfilter.time.deny_time", time_config->deny_time);
		af_uci_set_int_value(uci_ctx, "appfilter.time.allow_time", time_config->allow_time);

		char start_time_str[16] = {0};
		char end_time_str[16] = {0};
		// Format time: "HH:MM" with zero padding
		snprintf(start_time_str, sizeof(start_time_str), "%02d:%02d", 
				time_config->seg_time.start_time.hour, 
				time_config->seg_time.start_time.min);
		snprintf(end_time_str, sizeof(end_time_str), "%02d:%02d", 
				time_config->seg_time.end_time.hour, 
				time_config->seg_time.end_time.min);
		
		af_uci_set_value(uci_ctx, "appfilter.time.start_time", start_time_str);
		af_uci_set_value(uci_ctx, "appfilter.time.end_time", end_time_str);
	}
	af_uci_commit(uci_ctx, "appfilter");

	uci_free_context(uci_ctx);
}


int af_load_time_config(af_time_config_t *t_config)
{
    char time_list_buf[MAX_TIME_LIST_LEN] = {0};
    char days_buf[128] = {0};
    char start_time_buf[128] = {0};
    char end_time_buf[128] = {0};
    struct uci_context *ctx = uci_alloc_context();
	int old_ver_config = 0;
    printf("af_load_time_config: start\n");
    if (!ctx)
        return -1;
    memset(t_config, 0, sizeof(af_time_config_t));
    t_config->time_mode = af_uci_get_int_value(ctx, "appfilter.time.time_mode");
    t_config->deny_time = af_uci_get_int_value(ctx, "appfilter.time.deny_time");
    t_config->allow_time = af_uci_get_int_value(ctx, "appfilter.time.allow_time");
    
    af_uci_get_value(ctx, "appfilter.time.start_time", start_time_buf, sizeof(start_time_buf));
    af_uci_get_value(ctx, "appfilter.time.end_time", end_time_buf, sizeof(end_time_buf));
    af_uci_get_value(ctx, "appfilter.time.days", days_buf, sizeof(days_buf));
    sscanf(start_time_buf, "%d:%d", &t_config->seg_time.start_time.hour, &t_config->seg_time.start_time.min);
    sscanf(end_time_buf, "%d:%d", &t_config->seg_time.end_time.hour, &t_config->seg_time.end_time.min);
    t_config->time_num = 0;
    // Parse global days (may be empty, continue even if empty)
    char *saveptr2 = NULL;
    char *p = strtok_r(days_buf, " ", &saveptr2);
    if (p) {
        do {
            t_config->days[atoi(p)] = 1;
            printf("af_load_time_config: day[%d] = 1\n", atoi(p));
            p = strtok_r(NULL, " ", &saveptr2);
        } while (p != NULL);
    }

    af_uci_get_list_value(ctx, "appfilter.time.time", time_list_buf, sizeof(time_list_buf), " ");
    printf("af_load_time_config: time_list_buf from uci: %s\n", time_list_buf);
    
    char time_list_copy[MAX_TIME_LIST_LEN] = {0};
    strncpy(time_list_copy, time_list_buf, sizeof(time_list_copy) - 1);
    
    // Use strtok_r to avoid issues with nested strtok calls
    char *saveptr1 = NULL;
    p = strtok_r(time_list_copy, " ", &saveptr1);
    if (!p) {
        printf("af_load_time_config: no time periods found\n");
        goto EXIT;
    }
    
    int period_idx = 0;
    do
    {
        printf("af_load_time_config: parsing period[%d]: %s\n", period_idx, p);
        
        char *time_part = p;
        // Initialize days array for this time period (use global days as default)
        int i;
        for (i = 0; i < 7; i++) {
            t_config->time_list[t_config->time_num].days[i] = t_config->days[i];
        }
        
        // Check if format is new (with weekdays): "1,2,4,5;00:00-23:59"
        char *semicolon = strchr(p, ';');
        if (semicolon) {
            // New format: parse weekdays and store in this time period's days array
            char weekday_str[64] = {0};
            strncpy(weekday_str, p, semicolon - p);
            weekday_str[semicolon - p] = '\0';
            time_part = semicolon + 1;
            
            printf("af_load_time_config: period[%d] has weekdays: %s, time_part: %s\n", period_idx, weekday_str, time_part);
            
            // Clear days array for this time period first
            for (i = 0; i < 7; i++) {
                t_config->time_list[t_config->time_num].days[i] = 0;
            }
            
            // Parse weekdays: "1,2,4,5" using strtok_r
            char weekday_copy[64] = {0};
            strncpy(weekday_copy, weekday_str, sizeof(weekday_copy) - 1);
            char *saveptr2 = NULL;
            char *wd = strtok_r(weekday_copy, ",", &saveptr2);
            while (wd) {
                int day_val = atoi(wd);
                if (day_val >= 0 && day_val < 7) {
                    t_config->time_list[t_config->time_num].days[day_val] = 1;
                    printf("af_load_time_config: period[%d] set day %d\n", period_idx, day_val);
                }
                wd = strtok_r(NULL, ",", &saveptr2);
            }
        } else {
            LOG_WARN("af_load_time_config: period[%d] no weekdays, using global days\n", period_idx);
			old_ver_config = 1;
        }
        // If no semicolon, use global days (already copied above)
        
        // Parse time: "00:00-23:59" or "1,2,4,5;00:00-23:59" (time_part already points to time part)
        int ret = sscanf(time_part, "%d:%d-%d:%d", &t_config->time_list[t_config->time_num].start_time.hour,
             &t_config->time_list[t_config->time_num].start_time.min, &t_config->time_list[t_config->time_num].end_time.hour, &t_config->time_list[t_config->time_num].end_time.min);
        if (ret != 4) {
            printf("af_load_time_config: period[%d] ERROR: failed to parse time from %s\n", period_idx, time_part);
        } else {
            printf("af_load_time_config: time[%d] %d:%d-%d:%d, days: ", t_config->time_num, t_config->time_list[t_config->time_num].start_time.hour, t_config->time_list[t_config->time_num].start_time.min,
                     t_config->time_list[t_config->time_num].end_time.hour, t_config->time_list[t_config->time_num].end_time.min);
            for (i = 0; i < 7; i++) {
                if (t_config->time_list[t_config->time_num].days[i]) {
                    printf("%d ", i);
                }
            }
            printf("\n");
            t_config->time_num++;
        }
        period_idx++;
    } while (p = strtok_r(NULL, " ", &saveptr1));
    
    printf("af_load_time_config: total periods loaded: %d\n", t_config->time_num);
    
    // Load mode 2 daily limit config (if time_mode is 2)
    if (t_config->time_mode == 2) {
        int weekday;
        for (weekday = 0; weekday < 7; weekday++) {
            char uci_key[64] = {0};
            snprintf(uci_key, sizeof(uci_key), "appfilter.time.daily_limit_%d", weekday);
            
            char daily_limit_str[128] = {0};
            af_uci_get_value(ctx, uci_key, daily_limit_str, sizeof(daily_limit_str));
            
            // Initialize to default values
            t_config->daily_limit[weekday].enable = 0;
            t_config->daily_limit[weekday].am_time = 0;
            t_config->daily_limit[weekday].pm_time = 0;
            
            // Parse format: "enable:am_time:pm_time"
            if (strlen(daily_limit_str) > 0) {
                char *first_colon = strchr(daily_limit_str, ':');
                if (first_colon) {
                    char *second_colon = strchr(first_colon + 1, ':');
                    if (second_colon) {
                        // New format: "enable:am_time:pm_time"
                        t_config->daily_limit[weekday].enable = atoi(daily_limit_str);
                        t_config->daily_limit[weekday].am_time = atoi(first_colon + 1);
                        t_config->daily_limit[weekday].pm_time = atoi(second_colon + 1);
                    } else {
                        // Old format: "am_time:pm_time"
                        t_config->daily_limit[weekday].enable = 1;
                        t_config->daily_limit[weekday].am_time = atoi(daily_limit_str);
                        t_config->daily_limit[weekday].pm_time = atoi(first_colon + 1);
                    }
                } else {
                    t_config->daily_limit[weekday].enable = 1;
                    t_config->daily_limit[weekday].am_time = atoi(daily_limit_str);
                }
            }
            printf("af_load_time_config: daily_limit[%d] enable=%d, am_time=%d, pm_time=%d\n", 
                   weekday, t_config->daily_limit[weekday].enable, 
                   t_config->daily_limit[weekday].am_time, t_config->daily_limit[weekday].pm_time);
        }
    }
    
EXIT:
    uci_free_context(ctx);
    return old_ver_config;
}


void af_load_global_config(af_global_config_t *config){
    int ret = 0;
	char lan_ifname[32] = {0};
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return;
    ret = af_uci_get_int_value(ctx, "appfilter.global.enable");
    if (ret < 0)
        config->enable = 0;
    else
        config->enable = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.record_enable");
    if (ret < 0)
        config->record_enable = 0;
    else
        config->record_enable = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.user_mode");
    if (ret < 0)
        config->user_mode = 0;
    else
        config->user_mode = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.work_mode");
    if (ret < 0)
        config->work_mode = 0;
    else
        config->work_mode = ret;
    ret = af_uci_get_int_value(ctx, "appfilter.global.tcp_rst");
    if (ret < 0)
        config->tcp_rst = 1;
    else
        config->tcp_rst = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.disable_hnat");
    if (ret < 0)
        config->disable_hnat = 1;
    else
        config->disable_hnat = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.auto_load_engine");
    if (ret < 0)
        config->auto_load_engine = 0;
    else
        config->auto_load_engine = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.disable_quic");
    if (ret < 0)
        config->disable_quic = 0;
    else
        config->disable_quic = ret;

    ret = af_uci_get_int_value(ctx, "appfilter.global.app_filter_mode");
    if (ret < 0)
        config->app_filter_mode = 0; // Default to specified apps mode
    else
        config->app_filter_mode = ret;

    ret = af_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname));
	if (ret < 0)
		strncpy(config->lan_ifname, "br-lan", sizeof(config->lan_ifname) - 1);
	else
		strncpy(config->lan_ifname, lan_ifname, sizeof(config->lan_ifname) - 1);

    uci_free_context(ctx);
    LOG_DEBUG("enable=%d, user_mode=%d, work_mode=%d, disable_quic=%d, app_filter_mode=%d\n", config->enable, config->user_mode, config->work_mode, config->disable_quic, config->app_filter_mode);
}

void af_load_config(af_config_t *config){
    memset(config, 0, sizeof(af_config_t));
    af_load_global_config(&config->global);
    if (1 == af_load_time_config(&config->time)){
		apply_time_config_to_uci(&config->time);
	}
}


void update_oaf_proc_value(char *key, char *value){
    char cmd_buf[128] = {0};
    char file_path[128] = {0};
    char old_value[128] = {0};
    sprintf(file_path, "/proc/sys/oaf/%s", key);

    if (af_read_file_value(file_path, old_value, sizeof(old_value)) == -1)
        return;
    if (strcmp(old_value, value) != 0){
        sprintf(cmd_buf, "echo %s >/proc/sys/oaf/%s", value, key);
        system(cmd_buf);
        LOG_DEBUG("update %s %s-->%s\n", key, old_value, value);
    }
}

void update_oaf_proc_u32_value(char *key, u_int32_t value){
    char buf[32] = {0};
    sprintf(buf, "%u", value);
    update_oaf_proc_value(key, buf);
}

void update_lan_ip(void){
    char ip_str[32] = {0};
	char mask_str[32] = {0};
    struct in_addr addr;
	struct in_addr mask_addr;
    char cmd_buf[128] = {0};
    u_int32_t lan_ip = 0;
	u_int32_t lan_mask = 0;
    char lan_ifname[32] = {0};
    char ip_cmd_buf[128] = {0};
    char mask_cmd_buf[128] = {0};
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return;
	
    int ret = af_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
    if (ret != 0){
        strcpy(lan_ifname, "br-lan");
    }
    sprintf(ip_cmd_buf, CMD_GET_LAN_IP_FMT , lan_ifname);
    sprintf(mask_cmd_buf, CMD_GET_LAN_MASK_FMT , lan_ifname);

    exec_with_result_line(ip_cmd_buf, ip_str, sizeof(ip_str));
    if (strlen(ip_str) < MIN_INET_ADDR_LEN){
        update_oaf_proc_u32_value("lan_ip", 0);
    }
    else{
        inet_aton(ip_str, &addr);
        lan_ip = addr.s_addr;
        update_oaf_proc_u32_value("lan_ip", lan_ip);
    }

    exec_with_result_line(mask_cmd_buf, mask_str, sizeof(mask_str));

    if (strlen(mask_str) < MIN_INET_ADDR_LEN){
        update_oaf_proc_u32_value("lan_mask", 0);
    }
    else{
        inet_aton(mask_str, &mask_addr);
        lan_mask = mask_addr.s_addr;
        update_oaf_proc_u32_value("lan_mask", lan_mask);
    }
	uci_free_context(ctx);
}




int af_check_time_manual(af_time_config_t *t_config) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    int current_minutes = current_time->tm_hour * 60 + current_time->tm_min;
    int current_wday = current_time->tm_wday;

    int i;
    for (i = 0; i < t_config->time_num; i++) {
        if (!t_config->time_list[i].days[current_wday]) {
            printf("current day %d not in time[%d] days\n", current_wday, i);
            continue;
        }
        
        int start_minutes = t_config->time_list[i].start_time.hour * 60 + t_config->time_list[i].start_time.min;
        int end_minutes = t_config->time_list[i].end_time.hour * 60 + t_config->time_list[i].end_time.min;
        printf("check time: %02d:%02d-%02d:%02d\n", 
               t_config->time_list[i].start_time.hour, t_config->time_list[i].start_time.min,
               t_config->time_list[i].end_time.hour, t_config->time_list[i].end_time.min);
        
        if (current_minutes >= start_minutes && current_minutes <= end_minutes) {
            printf("current time in time list\n");
            g_af_status.match_time = 1;
            return 1;
        }
    }
    g_af_status.match_time = 0;
    return 0;
}

int af_check_time_dynamic(af_time_config_t *t_config) {
    return g_af_status.filter;
}


int update_dynamic_used_time(af_time_config_t *t_config){
    if (t_config->time_mode != 1) 
		return -1;
	time_t now = time(NULL);
    struct tm *current_time = localtime(&now);

	if (!t_config->days[current_time->tm_wday]) {
	   LOG_DEBUG("current day not in configured days\n");
	   af_init_time_status();
	   return -1;
    }

	
    int current_minutes = current_time->tm_hour * 60 + current_time->tm_min;

    int start_minutes = t_config->seg_time.start_time.hour * 60 + t_config->seg_time.start_time.min;
    int end_minutes = t_config->seg_time.end_time.hour * 60 + t_config->seg_time.end_time.min;
    LOG_DEBUG("check seg_time: %02d:%02d-%02d:%02d\n", 
           t_config->seg_time.start_time.hour, t_config->seg_time.start_time.min,
           t_config->seg_time.end_time.hour, t_config->seg_time.end_time.min);
    if (!(current_minutes >= start_minutes && current_minutes <= end_minutes)) {
        LOG_DEBUG("current time not in seg_time\n");
        af_init_time_status();
        return 0; 
    }

    g_af_status.match_time = 1;
    if (g_af_status.filter == 1) {
        g_af_status.deny_time++;
        if (g_af_status.deny_time >= t_config->deny_time) {
            g_af_status.filter = 0;
            g_af_status.deny_time = 0;
        }
    } else {
        g_af_status.allow_time++;
        if (g_af_status.allow_time >= t_config->allow_time) {
            g_af_status.filter = 1;
            g_af_status.allow_time = 0;
        }
    }
	return 0;
}


int af_check_time_period_limit(af_time_config_t *t_config) {
    int total_active_time = 0;
    int selected_user_count = 0;
    int i;

    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    int current_weekday = current_time->tm_wday; 
    int current_hour = current_time->tm_hour;
    
    LOG_DEBUG("check period limit mode: weekday=%d, hour=%d\n", current_weekday, current_hour);
    
    daily_limit_config_t *daily_limit = &t_config->daily_limit[current_weekday];
    
    if (!daily_limit->enable) {
        LOG_DEBUG("Time limit not enabled for weekday %d\n", current_weekday);
        g_af_status.match_time = 0;
        g_af_status.remain_time = 0;
        g_af_status.used_time = 0;
        g_af_status.period_blocked = 0; 
        return 0;
    }
    
    int max_allowed_time = 0;
    int is_morning = (current_hour < 12);
    
    if (is_morning) {
        max_allowed_time = daily_limit->am_time;
        LOG_DEBUG("Morning period: max_allowed_time=%d\n", max_allowed_time);
    } else {
        max_allowed_time = daily_limit->pm_time;
        LOG_DEBUG("Afternoon period: max_allowed_time=%d\n", max_allowed_time);
    }
    
    if (max_allowed_time <= 0) {
        LOG_DEBUG("No time limit set for current period\n");
        g_af_status.match_time = 0;
        g_af_status.remain_time = 0;
        g_af_status.used_time = 0;
        g_af_status.period_blocked = 0;
        return 0;
    }
    
    check_all_users_period_time();
    
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
        dev_node_t *node = dev_hash_table[i];
        while (node) {
            if (node->is_selected) {
                if (is_morning) {
                    total_active_time += node->today_am_active_time;
                    LOG_DEBUG("Selected user %s (online=%d): today_am_active_time=%d, total=%d\n", 
                             node->mac, node->online, node->today_am_active_time, total_active_time);
                } else {
                    total_active_time += node->today_pm_active_time;
                    LOG_DEBUG("Selected user %s (online=%d): today_pm_active_time=%d, total=%d\n", 
                             node->mac, node->online, node->today_pm_active_time, total_active_time);
                }
                if (node->online) {
                    selected_user_count++;
                }
            }
            node = node->next;
        }
    }
    
    g_af_status.used_time = total_active_time;
    
    int remain_time = max_allowed_time - total_active_time;
    if (remain_time < 0) {
        remain_time = 0;
    }
    g_af_status.remain_time = remain_time;
    
    LOG_DEBUG("Selected users count: %d, total_active_time=%d, max_allowed=%d, remain_time=%d\n", 
             selected_user_count, total_active_time, max_allowed_time, remain_time);
    
    if (total_active_time >= max_allowed_time) {
        g_af_status.match_time = 1;
        g_af_status.period_blocked = 1; 
        LOG_DEBUG("Period limit mode: enable filter (total time exceeded: %d >= %d)\n", 
                 total_active_time, max_allowed_time);
        return 1; 
    } else {
        g_af_status.match_time = 1;
        g_af_status.period_blocked = 0; 
        LOG_DEBUG("Period limit mode: disable filter (total time: %d < %d, remain: %d)\n", 
                 total_active_time, max_allowed_time, remain_time);
        return 0; 
    }
}

int af_check_time_valid(af_time_config_t *t_config) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
	
    if (t_config->time_mode == 0) {
        return af_check_time_manual(t_config);
    } else if (t_config->time_mode == 1) {
		return af_check_time_dynamic(t_config);
    } else if (t_config->time_mode == 2) {
		return af_check_time_period_limit(t_config);
    }else{
		return 0;
	}
}


void update_oaf_status(void){
    int ret = 0;
    int cur_enable = 0;
    if(g_af_config.global.enable == 1){
		ret = af_check_time_valid(&g_af_config.time);
	}
    update_oaf_proc_value("enable", ret == 1 ? "1" : "0");
}

void update_oaf_record_status(void){
    update_oaf_proc_value("record_enable", g_af_config.global.record_enable==1?"1":"0");
}

void update_oaf_disable_quic_status(void){
    update_oaf_proc_value("disable_quic", g_af_config.global.disable_quic==1?"1":"0");
}

void update_oaf_app_filter_mode_status(void){
    update_oaf_proc_value("app_filter_mode", g_af_config.global.app_filter_mode==1?"1":"0");
}


int af_nl_clean_feature(void){
    af_msg_t msg;
    if (appfilter_nl_fd.fd < 0){
        return -1;
    }
    msg.action = AF_MSG_CLEAN_FEATURE;
  
    send_msg_to_kernel(appfilter_nl_fd.fd,(void *)&msg, sizeof(msg));
    return 0;
}

int af_nl_add_feature(char *feature){
    char msg_buf[1024] = {0};
    if (appfilter_nl_fd.fd < 0){
        return -1;
    }
    char *p_data = msg_buf + sizeof(af_msg_t);
    memset(msg_buf, 0, sizeof(msg_buf));

    af_msg_t *hdr = (af_msg_t *)msg_buf;
    hdr->action = AF_MSG_ADD_FEATURE;
    strncpy(p_data, feature, strlen(feature));
    send_msg_to_kernel(appfilter_nl_fd.fd,(void *)msg_buf, sizeof(af_msg_t) + strlen(feature) + 1);
    return 0;
}



int af_load_feature_to_kernel(void){
	char line_buf[MAX_FEATURE_LINE_LEN] = {0};
	FILE *fp = fopen("/tmp/feature.cfg", "r");
	if (!fp)
	{
		printf("open file failed\n");
		return -1;
	}
	if (af_nl_clean_feature() < 0){
        return -1;
    }
	while (fgets(line_buf, sizeof(line_buf), fp))
	{
		str_trim(line_buf);
		if (strlen(line_buf) < 8)
			continue;
		if (strstr(line_buf, "#"))
			continue;
		
		if (strlen(line_buf) >= MAX_FEATURE_LINE_LEN - 1){
			continue;
		}
		af_nl_add_feature(line_buf);
	}
	fclose(fp);
    return 0;
}

int reload_feature(void){
    system("gen_class.sh /tmp/feature.cfg");
    init_app_name_table();
    init_app_class_name_table();
    if (af_load_feature_to_kernel() < 0){
        LOG_ERROR("Failed to load feature to kernel\n");
        return -1;
    }
    clean_invalid_app_records();
    clear_device_app_statistics();
    LOG_WARN("reload feature success\n");
    g_feature_update_time = get_timestamp();
    return 0;
}


void check_date_change(void)
{
    static int last_day = -1;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    int current_day = tm_info->tm_mday;
    if (last_day != current_day )
    {
        LOG_WARN("day changed: %d -> %d\n",last_day, current_day);
        if (last_day != -1){
            clear_device_app_statistics();
            reset_all_users_today_active_time();
			reset_all_users_today_flow();
        }
        last_day = current_day;
    }
}


void oaf_timeout_handler(struct uloop_timeout *t)
{
    static int count = 0;
    if (count % 10 == 0){
        update_dev_list();
		update_oaf_status();
    }
    if (count % 60 == 0){
		LOG_DEBUG("begin check dev count = %d\n", count);
        check_dev_visit_info_expire();
        flush_expire_visit_info();
		update_dynamic_used_time(&g_af_config.time);
		update_oaf_status();
        update_lan_ip();
        if (check_dev_expire()){
            flush_dev_expire_node();
        }
        check_date_change();
        check_all_users_period_time();
        dump_dev_list();
    }
    if (count % 300 == 0 && count > 0 && g_af_config.time.time_mode == 2){
        save_user_time_to_file();
    }
    if (g_oaf_config_change == 1){
		LOG_WARN("config changed\n");
        update_lan_ip();
        af_load_config(&g_af_config);
        update_dev_selected_flag(); 
		update_dynamic_used_time(&g_af_config.time);
        update_oaf_status();
        update_oaf_record_status();
        update_oaf_disable_quic_status();
        update_oaf_app_filter_mode_status();
        g_oaf_config_change = 0;
    }

    if (appfilter_nl_fd.fd < 0 && access("/proc/sys/oaf", F_OK) == 0){
        appfilter_nl_fd.fd = appfilter_nl_init();
        if (appfilter_nl_fd.fd > 0){
            uloop_fd_add(&appfilter_nl_fd, ULOOP_READ);
            system("oaf_rule reload &");
            LOG_INFO("netlink connect success\n");
        }
    }

    if (g_feature_update == 1 && appfilter_nl_fd.fd > 0){
        if (0 == reload_feature()){
            g_feature_update = 0;
        }
    }
    count++;
    uloop_timeout_set(t, 1000);
}

void af_load_engine(void){
    if (g_af_config.global.auto_load_engine == 1){
        if (access("/lib/modules/oaf.ko", F_OK) == 0) {
            system("insmod /lib/modules/oaf.ko");
            LOG_WARN("insmod /lib/modules/oaf.ko");
        } else {
            system("modprobe oaf");
            LOG_WARN("modprobe oaf");
        }
    }
    else{
        LOG_WARN("auto load disabled, not load oaf.ko\n");
    }
}


void handle_sigusr1(int sig) {
    LOG_WARN("Received SIGUSR1 signal\n");
    g_feature_update = 1;
}

void handle_sigusr2(int sig) {
    LOG_INFO("Received SIGUSR2 signal\n");
	if (current_log_level >= LOG_LEVEL_ERROR)
   		current_log_level = LOG_LEVEL_DEBUG;
	else
		current_log_level++;
	LOG_WARN("change log level to %d\n", current_log_level);
}


int main(int argc, char **argv)
{
    int ret = 0;
    LOG_INFO("appfilter start");
    g_feature_update = 1;
    af_load_config(&g_af_config);
    af_load_engine();
    af_init_status();
    uloop_init();
    signal(SIGUSR1, handle_sigusr1);
    signal(SIGUSR2, handle_sigusr2);
    signal(SIGCHLD, SIG_IGN);
    init_dev_node_htable();
    
    load_user_time_from_file();
    
    if (appfilter_ubus_init() < 0)
    {
        LOG_ERROR("Failed to connect to ubus\n");
        return 1;
    }  
    appfilter_nl_fd.fd = -1;
    uloop_timeout_set(&dev_tm, 5000);
    uloop_timeout_add(&dev_tm);
    uloop_run();
    uloop_done();
    return 0;
}
