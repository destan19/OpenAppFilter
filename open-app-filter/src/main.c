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
#include <netinet/in.h>
#include <arpa/inet.h>
#include "appfilter.h"

int current_log_level = LOG_LEVEL_INFO;
af_run_time_status_t g_af_status;
int g_oaf_config_change = 1;
af_config_t g_af_config;

void af_init_time_status(void){
    g_af_status.filter = 0;
    g_af_status.deny_time = 0;
    g_af_status.allow_time = 0;
    g_af_status.match_time = 0;
}


void af_init_status(void){
    af_init_time_status();
}


/** 
config time 'time'
	option time_mode '0'
	option start_time '00:00'
	option end_time '23:59'
	option days '1 2 3 4 5'
	list time '12:00-13:00'
	list time '15:00-16:00'
	list time '18:00-19:00'
	list time '21:00-21:30'
	list time '22:00-23:00'
	list time '23:01-23:30'
	list time '23:50-23:40'
*/

int af_load_time_config(af_time_config_t *t_config)
{
    char time_list_buf[MAX_TIME_LIST_LEN] = {0};
    char days_buf[128] = {0};
    char start_time_buf[128] = {0};
    char end_time_buf[128] = {0};
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    memset(t_config, 0, sizeof(af_time_config_t));
    t_config->time_mode = af_uci_get_int_value(ctx, "appfilter.time.time_mode");
    t_config->deny_time = af_uci_get_int_value(ctx, "appfilter.time.deny_time");
    t_config->allow_time = af_uci_get_int_value(ctx, "appfilter.time.allow_time");
    
    af_uci_get_value(ctx, "appfilter.time.start_time", start_time_buf, sizeof(start_time_buf));
    af_uci_get_value(ctx, "appfilter.time.end_time", end_time_buf, sizeof(end_time_buf));
    af_uci_get_value(ctx, "appfilter.time.days", days_buf, sizeof(days_buf));
    LOG_INFO("mode = %d, start_time: %s, end_time: %s, days: %s", t_config->time_mode, start_time_buf, end_time_buf, days_buf);
    sscanf(start_time_buf, "%d:%d", &t_config->seg_time.start_time.hour, &t_config->seg_time.start_time.min);
    sscanf(end_time_buf, "%d:%d", &t_config->seg_time.end_time.hour, &t_config->seg_time.end_time.min);

    t_config->time_num = 0;
    char *p = strtok(days_buf, " ");
    if (!p)
        goto EXIT;
    do
    {
        t_config->days[atoi(p)] = 1;
    } while (p = strtok(NULL, " "));

    af_uci_get_list_value(ctx, "appfilter.time.time", time_list_buf, sizeof(time_list_buf), " ");
    p = strtok(time_list_buf, " ");
    if (!p)
        goto EXIT;
    do
    {
        sscanf(p, "%d:%d-%d:%d", &t_config->time_list[t_config->time_num].start_time.hour,
             &t_config->time_list[t_config->time_num].start_time.min, &t_config->time_list[t_config->time_num].end_time.hour, &t_config->time_list[t_config->time_num].end_time.min);
        LOG_INFO("time[%d] %d:%d-%d:%d\n", t_config->time_num, t_config->time_list[t_config->time_num].start_time.hour, t_config->time_list[t_config->time_num].start_time.min,
                 t_config->time_list[t_config->time_num].end_time.hour, t_config->time_list[t_config->time_num].end_time.min);
        t_config->time_num++;
    } while (p = strtok(NULL, " "));
EXIT:
    uci_free_context(ctx);
    return 0;
}


void af_load_global_config(af_global_config_t *config){
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return;
    ret = af_uci_get_int_value(ctx, "appfilter.global.enable");
    if (ret < 0)
        config->enable = 0;
    else
        config->enable = ret;

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
    uci_free_context(ctx);
    LOG_INFO("enable=%d, user_mode=%d, work_mode=%d", config->enable, config->user_mode, config->work_mode);
}

void af_load_config(af_config_t *config){
    memset(config, 0, sizeof(af_config_t));
    af_load_global_config(&config->global);
    af_load_time_config(&config->time);
}


void update_lan_ip(void){
    char ip_str[32] = {0};
	char mask_str[32] = {0};
    struct in_addr addr;
	struct in_addr mask_addr;
    char cmd_buf[128] = {0};
    u_int32_t lan_ip = 0;
	u_int32_t lan_mask = 0;
	
    exec_with_result_line(CMD_GET_LAN_IP, ip_str, sizeof(ip_str));
    if (strlen(ip_str) < MIN_INET_ADDR_LEN){
        sprintf(cmd_buf, "echo 0 >/proc/sys/oaf/lan_ip");
    }
    else{
        inet_aton(ip_str, &addr);
        lan_ip = addr.s_addr;
        sprintf(cmd_buf, "echo %u >/proc/sys/oaf/lan_ip", lan_ip);
    }
	system(cmd_buf);
    exec_with_result_line(CMD_GET_LAN_MASK, mask_str, sizeof(mask_str));

    if (strlen(mask_str) < MIN_INET_ADDR_LEN){
        sprintf(cmd_buf, "echo 0 >/proc/sys/oaf/lan_mask");
    }
    else{
        inet_aton(mask_str, &mask_addr);
        lan_mask = mask_addr.s_addr;
        sprintf(cmd_buf, "echo %u >/proc/sys/oaf/lan_mask", lan_mask);
    }
    system(cmd_buf);
}




int af_check_time_manual(af_time_config_t *t_config) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    int current_minutes = current_time->tm_hour * 60 + current_time->tm_min;

    LOG_DEBUG("current time: %02d:%02d\n", current_time->tm_hour, current_time->tm_min);

    for (int i = 0; i < t_config->time_num; i++) {
        int start_minutes = t_config->time_list[i].start_time.hour * 60 + t_config->time_list[i].start_time.min;
        int end_minutes = t_config->time_list[i].end_time.hour * 60 + t_config->time_list[i].end_time.min;
        LOG_DEBUG("check time: %02d:%02d-%02d:%02d\n", 
               t_config->time_list[i].start_time.hour, t_config->time_list[i].start_time.min,
               t_config->time_list[i].end_time.hour, t_config->time_list[i].end_time.min);
        
        if (current_minutes >= start_minutes && current_minutes <= end_minutes) {
            LOG_DEBUG("current time in time list\n");
            g_af_status.match_time = 1;
            return 1;
        }
    }
    g_af_status.match_time = 0;
    return 0;
}

int af_check_time_dynamic(af_time_config_t *t_config) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
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
            LOG_DEBUG("deny time over, filter = 0");
        }
        LOG_DEBUG("deny_time: %d\n", g_af_status.deny_time);
    } else {
        g_af_status.allow_time++;
        if (g_af_status.allow_time >= t_config->allow_time) {
            g_af_status.filter = 1;
            g_af_status.allow_time = 0;
            LOG_DEBUG("allow time over, filter = 1");
        }
        LOG_DEBUG("allow_time: %d\n", g_af_status.allow_time);
    }
    return g_af_status.filter;
}

int af_check_time(af_time_config_t *t_config) {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    LOG_DEBUG("current day: %d\n", current_time->tm_wday);
    if (!t_config->days[current_time->tm_wday]) {
        LOG_DEBUG("current day not in configured days\n");
        af_init_time_status();
        return 0;
    }
    if (t_config->time_mode == 0) {
        LOG_DEBUG("manual mode\n");
        return af_check_time_manual(t_config);
    } else {
        LOG_DEBUG("dynamic mode\n");
        return af_check_time_dynamic(t_config);
    }
}


void update_oaf_status(void){
    int ret = 0;
    int cur_enable = 0;
    ret = af_check_time(&g_af_config.time);
    if (ret == 1){
        system("echo 1 >/proc/sys/oaf/enable");
    }
    else{
        system("echo 0 >/proc/sys/oaf/enable");
    }
}

void update_oaf_record_status(void){
    if(g_af_config.global.record_enable == 1){
        system("echo 1 >/proc/sys/oaf/record_enable");
    }
    else{
        system("echo 0 >/proc/sys/oaf/record_enable");
    }
}


void dev_list_timeout_handler(struct uloop_timeout *t)
{
    static int count = 0;
    count++;
    if (count % 10 == 0){
        update_dev_list();
        dump_dev_list();
    }
    if (count % 60 == 0){
        check_dev_visit_info_expire();
        update_lan_ip();
        if (check_dev_expire()){
            flush_dev_expire_node();
        }
        flush_expire_visit_info();
        update_oaf_status();
    }
    if (g_oaf_config_change == 1){
        update_lan_ip();
        af_load_config(&g_af_config);
        update_oaf_status();
        update_oaf_record_status();
        g_oaf_config_change = 0;
    }
    uloop_timeout_set(t, 1000);
}

struct uloop_timeout dev_tm = {
    .cb = dev_list_timeout_handler};

static struct uloop_fd appfilter_nl_fd = {
    .cb = appfilter_nl_handler,
};




int main(int argc, char **argv)
{
    int ret = 0;
    LOG_INFO("appfilter start");
    af_load_config(&g_af_config);
    af_init_status();
    uloop_init();
    init_dev_node_htable();
    init_app_name_table();
    init_app_class_name_table();
    if (appfilter_ubus_init() < 0)
    {
        LOG_ERROR("Failed to connect to ubus\n");
        return 1;
    }   
    appfilter_nl_fd.fd = appfilter_nl_init();
    uloop_fd_add(&appfilter_nl_fd, ULOOP_READ);
    af_msg_t msg;
    msg.action = AF_MSG_INIT;
    send_msg_to_kernel(appfilter_nl_fd.fd, (void *)&msg, sizeof(msg));
    uloop_timeout_set(&dev_tm, 5000);
    uloop_timeout_add(&dev_tm);
    uloop_run();
    uloop_done();
    return 0;
}
