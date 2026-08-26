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
#include "fwx_stat.h"
#include "fwx_config.h"
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <json-c/json.h>
#include <sys/stat.h>
#include "fwx.h"
#include <stdio.h>
#include "fwx_utils.h"
#include "fwx_app_filter.h"
#include "check_main.h"
#include "fwx_feature.h"
#include "fwx_feature_online.h"
#include "fwx_custom_feature.h"

int current_log_level = LOG_LEVEL_WARN;
//int current_log_level = LOG_LEVEL_INFO;
int g_fwxd_debug_mode = 0;

#define CMD_GET_LAN_IP_FMT   "ifconfig %s | grep 'inet addr' | awk '{print $2}' | awk -F: '{print $2}'"
#define CMD_GET_LAN_MASK_FMT "ifconfig %s | grep 'inet addr' | awk '{print $4}' | awk -F: '{print $2}'"
#define CLIENT_BACKUP_SYNC_INTERVAL_SEC 600
int g_fwx_config_chage = 1;
int g_hnat_init = 0;
int g_feature_update = 0;

extern void check_and_cleanup_history_data_by_size(void);
extern void collect_interface_traffic_rate(void);

fwx_status_t g_fwx_status = {
    .internet = 1  
};

fwx_capability_t g_fwx_capability = {
    .wireless_support = 0
};

void fwx_timeout_handler(struct uloop_timeout *t);


struct uloop_timeout fwx_tm = {
    .cb = fwx_timeout_handler};

static struct uloop_fd fwx_nl_fd = {
    .cb = fwx_netlink_handler,
};

#define FEATURE_UPGRADE_SUCCESS 200
#define FEATURE_UPGRADE_FAILED 400

static int write_feature_upgrade_status(int status)
{
    const char *temporary = FWX_FEATURE_UPGRADE_STATUS_PATH ".tmp";
    FILE *fp = fopen(temporary, "w");

    if (!fp)
        return -1;
    if (fprintf(fp, "%d", status) < 0 || fflush(fp) != 0 ||
        fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(temporary);
        return -1;
    }
    if (fclose(fp) != 0 || chmod(temporary, 0644) != 0 ||
        rename(temporary, FWX_FEATURE_UPGRADE_STATUS_PATH) != 0) {
        unlink(temporary);
        return -1;
    }
    return 0;
}

static int write_feature_info_file(void)
{
    const char *feature_data;
    const char *json_text;
    const char *temporary = FWX_FEATURE_INFO_PATH ".tmp";
    size_t feature_len = 0;
    size_t offset = 0;
    char line[1024];
    char version[64] = {0};
    int feature_type = 0;
    int feature_free = 0;
    int type_seen = 0;
    int free_seen = 0;
    struct json_object *info_obj = NULL;
    FILE *fp = NULL;
    int line_ret;
    int ret = -1;

    feature_data = fwx_feature_get_data(&feature_len);
    while (feature_data &&
           (line_ret = fwx_feature_next_line(feature_data, feature_len, &offset,
                                             line, sizeof(line))) != 0) {
        if (line_ret < 0)
            continue;
        if (!strncmp(line, "#version ", 9)) {
            sscanf(line, "#version %63s", version);
        } else if (!strncmp(line, "#type ", 6)) {
            sscanf(line, "#type %d", &feature_type);
            if (feature_type != 0 && feature_type != 1)
                feature_type = 0;
            type_seen = 1;
        } else if (!strncmp(line, "#free ", 6)) {
            sscanf(line, "#free %d", &feature_free);
            feature_free = feature_free ? 1 : 0;
            free_seen = 1;
        }
        if (version[0] && type_seen && free_seen)
            break;
    }
    info_obj = json_object_new_object();
    if (!info_obj)
        return -1;
    json_object_object_add(info_obj, "version", json_object_new_string(version));
    json_object_object_add(info_obj, "type", json_object_new_int(feature_type));
    json_object_object_add(info_obj, "free", json_object_new_int(feature_free));
    json_object_object_add(info_obj, "app_count", json_object_new_int(g_app_count));
    json_object_object_add(info_obj, "format", json_object_new_string("v4.0"));
    json_text = json_object_to_json_string_ext(info_obj, JSON_C_TO_STRING_PLAIN);
    fp = fopen(temporary, "w");
    if (!fp || fwrite(json_text, 1, strlen(json_text), fp) != strlen(json_text) ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        goto out;
    if (fclose(fp) != 0) {
        fp = NULL;
        goto out;
    }
    fp = NULL;
    if (chmod(temporary, 0644) != 0 || rename(temporary, FWX_FEATURE_INFO_PATH) != 0)
        goto out;
    ret = 0;
out:
    if (fp)
        fclose(fp);
    if (ret != 0)
        unlink(temporary);
    json_object_put(info_obj);
    return ret;
}


int fwx_nl_clean_feature(void){
    fwx_nl_msg_t msg;
    if (fwx_nl_fd.fd < 0){
        return -1;
    }
    msg.action = FWX_NL_MSG_CLEAN_FEATURE;
  
    return fwx_nl_send_msg_to_kernel(fwx_nl_fd.fd,(void *)&msg, sizeof(msg));
}

int fwx_nl_add_feature(char *feature){
    char msg_buf[1024] = {0};
    if (fwx_nl_fd.fd < 0){
        return -1;
    }
    char *p_data = msg_buf + sizeof(fwx_nl_msg_t);
    memset(msg_buf, 0, sizeof(msg_buf));

    fwx_nl_msg_t *hdr = (fwx_nl_msg_t *)msg_buf;
    hdr->action = FWX_NL_MSG_ADD_FEATURE;
    strncpy(p_data, feature, strlen(feature));
    return fwx_nl_send_msg_to_kernel(fwx_nl_fd.fd,(void *)msg_buf,
                                     sizeof(fwx_nl_msg_t) + strlen(feature) + 1);
}

int fwx_nl_feature_load_done(void){
    fwx_nl_msg_t msg;
    if (fwx_nl_fd.fd < 0){
        return -1;
    }
    msg.action = FWX_NL_MSG_FEATURE_LOAD_DONE;
    return fwx_nl_send_msg_to_kernel(fwx_nl_fd.fd, (void *)&msg, sizeof(msg));
}



int fwx_load_feature_to_kernel(void){
	char line_buf[MAX_FEATURE_LINE_LEN] = {0};
    int feature_count = 0;
	int custom_count;
	size_t feature_len = 0;
    size_t offset = 0;
    const char *feature_data = fwx_feature_get_data(&feature_len);

	if (!feature_data || feature_len == 0)
		return -1;
	if (fwx_nl_clean_feature() < 0){
        LOG_ERROR("Failed to clean feature\n");
        return -1;
    }
	while (offset < feature_len) {
		int line_ret = fwx_feature_next_line(feature_data, feature_len, &offset,
                                                line_buf, sizeof(line_buf));
		if (line_ret < 0) {
            LOG_ERROR("feature line too long\n");
			continue;
        }
		if (line_ret == 0)
			break;
		str_trim(line_buf);
		if (strlen(line_buf) < 8)
			continue;
		if (strstr(line_buf, "#"))
			continue;
		
		if (strlen(line_buf) >= MAX_FEATURE_LINE_LEN - 1){
            LOG_ERROR("feature line too long: %s\n", line_buf);
			continue;
		}
		if (fwx_nl_add_feature(line_buf) < 0) {
            LOG_ERROR("Failed to send feature to kernel\n");
            return -1;
        }
        feature_count++;
	}
    custom_count = fwx_custom_feature_send_to_kernel(fwx_nl_add_feature);
    if (custom_count < 0) {
        LOG_ERROR("Failed to send custom feature to kernel\n");
        return -1;
    }
    feature_count += custom_count;
    if (fwx_nl_feature_load_done() < 0){
        LOG_ERROR("Failed to notify feature load done\n");
        return -1;
    }
    LOG_INFO("load %d features to kernel\n", feature_count);
    return 0;
}

int reload_feature(void){
    char *feature_data = NULL;
    size_t feature_len = 0;

    if (fwx_feature_decrypt_file(FWX_FEATURE_BIN_PATH, &feature_data, &feature_len) < 0) {
        LOG_ERROR("Failed to decrypt feature file\n");
        if (fwx_feature_restore_backup() < 0) {
            LOG_ERROR("Failed to restore feature backup\n");
            return -1;
        }
        LOG_WARN("Restored feature file from backup\n");
        if (fwx_feature_decrypt_file(FWX_FEATURE_BIN_PATH,
                                     &feature_data, &feature_len) < 0) {
            LOG_ERROR("Failed to decrypt restored feature file\n");
            return -1;
        }
    }
    fwx_feature_replace_data(feature_data, feature_len);
    init_app_name_table();
    init_app_class_name_table();
    if (fwx_custom_feature_reload() < 0)
        return -1;
    if (fwx_custom_feature_add_app_names() < 0) {
        LOG_ERROR("Failed to initialize custom application names\n");
        return -1;
    }
    if (fwx_load_feature_to_kernel() < 0){
        LOG_ERROR("Failed to load feature to kernel\n");
        return -1;
    }
    if (write_feature_info_file() < 0)
        LOG_ERROR("Failed to write feature info file\n");
    LOG_WARN("reload feature success\n");
    return 0;
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
	
    int ret = fwx_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
    if (ret != 0){
        strcpy(lan_ifname, "br-lan");
    }
    sprintf(ip_cmd_buf, CMD_GET_LAN_IP_FMT, lan_ifname);
    sprintf(mask_cmd_buf, CMD_GET_LAN_MASK_FMT , lan_ifname);

    exec_with_result_line(ip_cmd_buf, ip_str, sizeof(ip_str));
    if (strlen(ip_str) < MIN_INET_ADDR_LEN){
        update_fwx_proc_u32_value("lan_ip", 0);
    }
    else{
        inet_aton(ip_str, &addr);
        lan_ip = addr.s_addr;
        update_fwx_proc_u32_value("lan_ip", lan_ip);
    }

    exec_with_result_line(mask_cmd_buf, mask_str, sizeof(mask_str));

    if (strlen(mask_str) < MIN_INET_ADDR_LEN){
        update_fwx_proc_u32_value("lan_mask", 0);
    }
    else{
        inet_aton(mask_str, &mask_addr);
        lan_mask = mask_addr.s_addr;
        update_fwx_proc_u32_value("lan_mask", lan_mask);
    }
	uci_free_context(ctx);
}


void daily_archive_handle(void){
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        static int last_mday = -1;
        int current_mday = tm_info->tm_mday;
        LOG_INFO("current_mday: %d, last_mday: %d\n", current_mday, last_mday);
        
        if (last_mday != -1 && last_mday != current_mday) {
            LOG_INFO("date changed, need to archive\n");
            
            check_and_archive_all_clients();
        }
        else{
            LOG_INFO("date not changed, no need to archive\n");
        }
        
        last_mday = current_mday;
    }
}



void fwx_timeout_handler(struct uloop_timeout *t)
{
    static int count = 0;
    static u_int32_t last_check_date = 0;
    u_int32_t current_time = time(NULL);
    count++;
    if (count % 10 == 0){
        update_client_list();
        move_expired_online_visit_to_offline();
    }
    if (count % 20 == 0){
        daily_archive_handle();
        update_lan_ip();
        if (check_client_expire()){
            flush_expire_client_node();
        }
        dump_client_list();
        cleanup_expired_hourly_stats();
        check_and_cleanup_history_data_by_size();
    }
    if (count % CLIENT_BACKUP_SYNC_INTERVAL_SEC == 0) {
        LOG_INFO("begin save all client to files\n");
        save_all_client_backup_to_files();
    }
    
    if (count % 2 == 0) {  
        collect_interface_traffic_rate();
    }

    if (fwx_nl_fd.fd < 0){
        fwx_nl_fd.fd = fwx_netlink_init();
        if (fwx_nl_fd.fd > 0){
            uloop_fd_add(&fwx_nl_fd, ULOOP_READ);

            system("killall -9 rule_manager");
            LOG_INFO("netlink connect success\n");
        }
    }

    if (g_feature_update == 1 && fwx_nl_fd.fd > 0){
        if (0 == reload_feature()){
            g_feature_update = 0;
        }
    }
	if (count % 5 == 0){
		fwx_session_stat_tick();
	}

    uloop_timeout_set(t, 1000);
}

void init_system_config_to_proc(void) {
    struct uci_context *ctx = uci_alloc_context();
    if (ctx) {
        char lan_ifname[32] = {0};
        int ret = fwx_uci_get_value(ctx, "fwx.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
        if (ret != 0) {
            strcpy(lan_ifname, "br-lan");
        }
        update_fwx_proc_value("lan_ifname", lan_ifname);

        int tcp_rst = fwx_uci_get_int_value(ctx, "fwx.global.tcp_rst");
        if (tcp_rst != 0 && tcp_rst != 1) {
            tcp_rst = 1;
        }
        update_fwx_proc_u32_value("tcp_rst", tcp_rst);

        int work_mode = fwx_uci_get_int_value(ctx, "fwx.network.work_mode");
        if (work_mode < 0) {
            work_mode = 0;
        }
        update_fwx_proc_u32_value("work_mode", work_mode);
        uci_free_context(ctx);
    }
}

void fwx_handle_sigusr1(int sig) {
    char version[64] = {0};
    char format[32] = {0};
    int status_code = FEATURE_UPGRADE_FAILED;
    int process_ret;

    (void)sig;
    LOG_WARN("Received feature upgrade signal, candidate=%s\n",
             FWX_FEATURE_CANDIDATE_PATH);
    if (access(FWX_FEATURE_CANDIDATE_PATH, F_OK) != 0) {
        LOG_ERROR("Feature candidate file does not exist: %s\n",
                  FWX_FEATURE_CANDIDATE_PATH);
        if (write_feature_upgrade_status(FEATURE_UPGRADE_FAILED) < 0)
            LOG_ERROR("Failed to write feature upgrade status: %d\n",
                      FEATURE_UPGRADE_FAILED);
        return;
    }
    process_ret = fwx_feature_process_candidate(version, sizeof(version),
                                                format, sizeof(format),
                                                &status_code, NULL);
    if (process_ret < 0) {
        LOG_ERROR("Feature candidate processing failed, version=%s, format=%s, status=%d\n",
                  version[0] ? version : "--", format[0] ? format : "--",
                  status_code);
        if (write_feature_upgrade_status(status_code) < 0)
            LOG_ERROR("Failed to write feature upgrade status: %d\n", status_code);
        return;
    }
    LOG_WARN("Feature candidate applied, target=%s, backup=%s\n",
             FWX_FEATURE_BIN_PATH, FWX_FEATURE_BACKUP_PATH);
    g_feature_update = 1;
    if (write_feature_upgrade_status(FEATURE_UPGRADE_SUCCESS) < 0) {
        LOG_ERROR("Failed to write feature upgrade status: %d\n",
                  FEATURE_UPGRADE_SUCCESS);
        return;
    }
    LOG_WARN("Feature candidate processing complete, status=%d\n",
             FEATURE_UPGRADE_SUCCESS);
}

void fwx_handle_sigusr2(int sig) {
    LOG_INFO("Received SIGUSR2 signal\n");
	if (current_log_level < LOG_LEVEL_DEBUG)
   		current_log_level++;
	else
		current_log_level = LOG_LEVEL_WARN;

	LOG_WARN("change log level to %d\n", current_log_level);
}

void init_fwx_capability(void) {
    g_fwx_capability.wireless_support = (access("/etc/config/wireless", F_OK) == 0) ? 1 : 0;
    LOG_INFO("init capability: wireless_support=%d\n", g_fwx_capability.wireless_support);
}

static void parse_fwxd_args(int argc, char **argv)
{
    int i = 0;
    if (!argv || argc <= 1)
        return;

    for (i = 1; i < argc; i++) {
        if (!argv[i])
            continue;

        if (strcmp(argv[i], "--debug-mode") == 0 || strcmp(argv[i], "-d") == 0) {
            g_fwxd_debug_mode = 1;
            continue;
        }

        LOG_WARN("Unknown argument ignored: %s\n", argv[i]);
    }
}

int main(int argc, char **argv)
{
    LOG_INFO("fwx start");
    parse_fwxd_args(argc, argv);
    g_feature_update = 1;
    uloop_init();
    signal(SIGUSR1, fwx_handle_sigusr1);	
    signal(SIGUSR2, fwx_handle_sigusr2);
    signal(SIGCHLD, SIG_IGN);
    init_client_list();
    load_app_valid_time_config();
    init_client_visit_db();
    load_client_backup_from_files();
    init_system_config_to_proc();
    init_fwx_capability();

    if (fwx_feature_online_init() < 0)
        LOG_ERROR("Failed to initialize online feature update\n");

    if (fwx_ubus_init() < 0)
    {
        LOG_ERROR("Failed to connect to ubus\n");
        return 1;
    }  

    if (start_check_thread() < 0) {
        LOG_ERROR("Failed to start check_thread\n");
        return 1;
    }

    fwx_nl_fd.fd = -1;
    uloop_timeout_set(&fwx_tm, 5000);
    uloop_timeout_add(&fwx_tm);
    uloop_run();
    stop_check_thread();
    fwx_feature_online_cleanup();
    uloop_done();
    return 0;
}
