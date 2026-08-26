// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <sys/types.h>
#include <libubox/list.h>
#ifndef __FILTER_USER_H__
#define __FILTER_USER_H__
#define MAX_IP_LEN 32
#define MAX_MAC_LEN 32

#define MAX_HOSTNAME_SIZE 64
#define OAF_VISIT_LIST_FILE "/tmp/visit_list"
#define OAF_DEV_LIST_FILE "/tmp/dev_list"
#define MIN_VISIT_TIME 5 // default 5s
#define MAX_APP_STAT_NUM 8
#define MAX_VISITLIST_DUMP_NUM 16
#define MAX_APP_TYPE 16
#define MAX_APP_ID_NUM 128
#define MAX_SUPPORT_DEV_NUM 64
#define SECONDS_PER_DAY (24 * 3600)
#define MAX_NICKNAME_SIZE 64
#define HOURS_PER_DAY 24
#define TOP_APP_PER_HOUR 3
#define MAX_DAILY_STAT_DAYS 30  
#define MAX_TOP_APPS_PER_DAY 10  
#define MAX_RECORD_DAY 30  
#define MAX_RECENT_APPS 5
#define MAX_USER_RECORDS 4096


typedef struct visit_info
{
    int appid;
    u_int32_t first_time;
    u_int32_t latest_time;
    int action;
    int expire; 
    struct list_head visit; 

} visit_info_t;


typedef struct online_offline_record
{
    int type;  
    u_int32_t timestamp;  
    unsigned long long duration;  
    struct list_head record; 
} online_offline_record_t;

typedef struct online_session_stat
{
    unsigned long long up_bytes;
    unsigned long long down_bytes;
    unsigned long long online_duration;
    unsigned long long active_duration;
    int recent_apps[MAX_RECENT_APPS];
    int recent_app_count;
    u_int32_t start_time;
} online_session_stat_t;

typedef struct user_record
{
    int action;  
    u_int32_t timestamp;
    char mac[MAX_MAC_LEN];
    char nickname[MAX_NICKNAME_SIZE];
    char hostname[MAX_HOSTNAME_SIZE];
    unsigned long long up_bytes;
    unsigned long long down_bytes;
    unsigned long long online_duration;
    unsigned long long active_duration;
    int recent_apps[MAX_RECENT_APPS];
    int recent_app_count;
    struct list_head list;
} user_record_t;


typedef struct visit_stat
{
    int appid;  
    unsigned long long total_time;  
    struct list_head list;  
} visit_stat_t;


typedef struct global_app_type_record
{
    int app_type;  
    unsigned long long time_delta;  
    u_int32_t timestamp;  
    struct list_head list;  
} global_app_type_record_t;


typedef struct traffic_stat
{
    unsigned long long up_bytes;    
    unsigned long long down_bytes;  
} traffic_stat_t;


typedef struct daily_hourly_stat
{
    u_int32_t date;  
    int is_today;    
    
    int hourly_top_apps[HOURS_PER_DAY][TOP_APP_PER_HOUR];
    
    traffic_stat_t hourly_traffic[HOURS_PER_DAY];
    
    unsigned long long hourly_online_time[HOURS_PER_DAY];
    unsigned long long hourly_active_time[HOURS_PER_DAY];
} daily_hourly_stat_t;


typedef struct daily_top_apps_stat
{
    u_int32_t date;  
    int is_today;    
    int count;       
    struct {
        int appid;
        unsigned long long total_time;  
    } apps[MAX_TOP_APPS_PER_DAY];
} daily_top_apps_stat_t;


#define MAX_REPORT_URL_LEN 64
typedef struct client_node
{
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char ipv6[128];  
    unsigned int up_rate;  
    unsigned int down_rate;  
    int rssi;
    unsigned int rx_rate;
    unsigned int tx_rate;
    char band[16];
    char wifi_ifname[64];
    int is_wireless;
    int wireless_online;
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    int online;
    int expire;
    u_int32_t offline_time;
    u_int32_t online_time;
    struct list_head online_visit;
    struct list_head visit; 
    struct list_head stat_list; 
    struct list_head online_offline_records; 
    int mf_user_loaded;
    char visiting_url[MAX_REPORT_URL_LEN];
    int visiting_app;
    int active;  
    int last_online_state;
    int session_online_recorded;
    online_session_stat_t online_session;
    
    daily_hourly_stat_t daily_stats; 
    
    daily_top_apps_stat_t daily_top_apps_stats; 
    struct list_head client; 

} client_node_t;

struct app_visit_info
{
    int app_id;
    char app_name[32];
    int total_time;
};

struct app_visit_stat_info
{
    int num;
    struct app_visit_info visit_list[MAX_APP_STAT_NUM];
};
typedef void (*iter_func)(void *arg, client_node_t *client);

extern struct list_head client_list; 
extern struct list_head user_record_list;

int get_timestamp(void);
client_node_t *add_client_node(char *mac);
void init_client_list(void);
void add_debug_test_users(void);
void dump_client_list(void);
void dump_client_visit_list(void);
client_node_t *find_client_node(const char *mac);
void client_foreach(void *arg, iter_func iter);
void add_visit_info_node(struct list_head *visit_list, visit_info_t *node);
void check_client_visit_info_expire(void);
void flush_expire_visit_info(void);
int check_client_expire(void);
void flush_expire_client_node(void);
void move_expired_online_visit_to_offline(void);
void update_client_list(void);
void update_client_nickname(void);
void update_client_visiting_info(void);
void refresh_client_wireless_status(void);
void update_hourly_top_apps(client_node_t *client);
void get_hourly_top_apps(client_node_t *client, int hour, int *appids, int max_count);
int get_hour_from_timestamp(u_int32_t timestamp);
unsigned long long get_visit_duration_in_hour(visit_info_t *visit, int target_hour);
daily_hourly_stat_t *get_today_stat(client_node_t *client);
daily_hourly_stat_t *load_history_stat_from_file(client_node_t *client, u_int32_t date);
void save_daily_stats_to_file(client_node_t *client, u_int32_t date);
void check_and_archive_all_clients(void);
u_int32_t get_today_start_timestamp(void);
void update_daily_top_apps(client_node_t *client);
daily_top_apps_stat_t *get_today_top_apps_stat(client_node_t *client);
daily_top_apps_stat_t *load_history_top_apps_stat_from_file(client_node_t *client, u_int32_t date);
void save_daily_top_apps_stats_to_file(client_node_t *client, u_int32_t date);
void save_client_visit_data_to_file(client_node_t *client, u_int32_t date);
void init_client_visit_db(void);
int add_mock_visit_records_to_db(int record_count, int mac_count, unsigned long long *old_size_bytes, unsigned long long *new_size_bytes);
const char *get_client_data_root_dir(void);
const char *get_history_data_root_dir(void);
const char *get_client_data_base_dir(void);
void reset_client_data_base_dir_cache(void);
void load_client_backup_from_files(void);
void save_client_backup_to_file(client_node_t *client);
void save_all_client_backup_to_files(void);
void load_app_valid_time_config(void);
int get_app_valid_time(void);
void check_and_cleanup_history_data_by_size(void);
void archive_and_save_client_visits(void);
void delete_client_record_files(const char *mac, const char *start_date, const char *end_date, const char *delete_type);
void update_global_app_type_stats(int appid, unsigned long long time_delta);
void cleanup_expired_hourly_stats(void);
void get_global_daily_app_type_stats(unsigned long long *type_time_array);
void get_global_hourly_app_type_stats(unsigned long long *type_time_array);
struct json_object *fwx_api_get_global_app_type_stats(struct json_object *req_obj);
void save_global_traffic_stats_to_file(u_int32_t date);
void get_global_traffic_stats(traffic_stat_t *traffic_array);
struct json_object *fwx_api_get_global_traffic_stats(struct json_object *req_obj);
void reset_online_session_stat(client_node_t *client, u_int32_t start_time);
void update_online_session_flow(client_node_t *client, unsigned long long up_bytes, unsigned long long down_bytes);
void update_online_session_activity(client_node_t *client, int online_seconds, int active_seconds);
void update_online_session_recent_app(client_node_t *client, int appid);
void add_user_record(client_node_t *client, int action, u_int32_t timestamp);

#endif
