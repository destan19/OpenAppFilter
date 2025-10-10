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
void dev_list_timeout_handler(struct uloop_timeout *t);

void af_init_time_status(void){
    g_af_status.filter = 0;
    g_af_status.deny_time = 0;
    g_af_status.allow_time = 0;
    g_af_status.match_time = 0;
}


void af_init_status(void){
    af_init_time_status();
}
struct uloop_timeout dev_tm = {
    .cb = dev_list_timeout_handler};

static struct uloop_fd appfilter_nl_fd = {
    .cb = appfilter_nl_handler,
};



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
    LOG_DEBUG("mode = %d, start_time: %s, end_time: %s, days: %s\n", t_config->time_mode, start_time_buf, end_time_buf, days_buf);
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
        LOG_DEBUG("time[%d] %d:%d-%d:%d\n", t_config->time_num, t_config->time_list[t_config->time_num].start_time.hour, t_config->time_list[t_config->time_num].start_time.min,
                 t_config->time_list[t_config->time_num].end_time.hour, t_config->time_list[t_config->time_num].end_time.min);
        t_config->time_num++;
    } while (p = strtok(NULL, " "));
EXIT:
    uci_free_context(ctx);
    return 0;
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


    ret = af_uci_get_value(ctx, "appfilter.global.disable_hnat", lan_ifname, sizeof(lan_ifname));
	if (ret < 0)
		strncpy(config->lan_ifname, "br-lan", sizeof(config->lan_ifname) - 1);
	else
		strncpy(config->lan_ifname, lan_ifname, sizeof(config->lan_ifname) - 1);

    uci_free_context(ctx);
    LOG_DEBUG("enable=%d, user_mode=%d, work_mode=%d\n", config->enable, config->user_mode, config->work_mode);
}

void af_load_config(af_config_t *config){
    memset(config, 0, sizeof(af_config_t));
    af_load_global_config(&config->global);
    af_load_time_config(&config->time);
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
    if(g_af_config.global.enable == 1){
		ret = af_check_time(&g_af_config.time);
	}
    update_oaf_proc_value("enable", ret==1?"1":"0");
}

void update_oaf_record_status(void){
    update_oaf_proc_value("record_enable", g_af_config.global.record_enable==1?"1":"0");
}

void af_hnat_init(void){
    if (g_af_config.global.enable == 0){
        return;
    }
    if (g_hnat_init == 0){
        LOG_DEBUG("disable hnat...\n");
        system("/usr/bin/hnat.sh");
        g_hnat_init = 1;
    }
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
        }
        last_day = current_day;
    }
}


void dev_list_timeout_handler(struct uloop_timeout *t)
{
    static int count = 0;
    count++;
    if (count % 10 == 0){
        update_dev_list();
    }
    if (count % 60 == 0){
		LOG_DEBUG("begin check dev count = %d\n", count);
        check_dev_visit_info_expire();
        flush_expire_visit_info();
        update_lan_ip();
        if (check_dev_expire()){
            flush_dev_expire_node();
        }
        update_oaf_status();
		check_date_change();
        dump_dev_list();
    }
    if (g_oaf_config_change == 1){
        update_lan_ip();
        af_load_config(&g_af_config);
        update_oaf_status();
        update_oaf_record_status();
        g_oaf_config_change = 0;
    }
    if (count > 10){ // delay init
        af_hnat_init();
    }


    if (appfilter_nl_fd.fd < 0 && access("/proc/sys/oaf", F_OK) == 0){
        appfilter_nl_fd.fd = appfilter_nl_init();
        if (appfilter_nl_fd.fd > 0){
            uloop_fd_add(&appfilter_nl_fd, ULOOP_READ);
            system("oaf_rule reload &");
            // /etc/init.d/appfilter reload
            LOG_INFO("netlink connect success\n");
        }
    }

    if (g_feature_update == 1 && appfilter_nl_fd.fd > 0){
        if (0 == reload_feature()){
            g_feature_update = 0;
        }
    }

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
    LOG_INFO("Received SIGUSR1 signal\n");
    g_feature_update = 1;
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
    signal(SIGCHLD, SIG_IGN);
    init_dev_node_htable();
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
