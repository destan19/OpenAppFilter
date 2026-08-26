
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <uci.h>
#include "fwx_config.h"
#include "fwx.h"
#include "fwx_user.h"
#include "fwx_utils.h"


LIST_HEAD(client_list);
LIST_HEAD(user_record_list);
int g_cur_user_num = 0;


static int g_app_valid_time = 300; 

unsigned long long g_daily_type_stats[MAX_APP_TYPE] = {0};
u_int32_t g_daily_stat_date = 0;  


LIST_HEAD(global_hourly_records);


traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY] = {{0}};
u_int32_t g_global_traffic_date = 0;  


#define CLIENT_DATA_BASE_DIR_DEFAULT "/tmp/fwx/client_data"
#define MAX_WIRELESS_IFACE_NUM 32
#define MAX_WIRELESS_IFNAME_LEN 64
#define MAX_WIRELESS_BAND_LEN 16

static char g_client_data_base_dir[256] = {0};
static int g_client_data_base_dir_initialized = 0;
static char g_client_data_root_dir[256] = {0};
static int g_client_data_root_dir_initialized = 0;
static char g_history_data_root_dir[256] = {0};
static int g_history_data_root_dir_initialized = 0;

static void mac_to_dirname(const char *mac, char *dirname, size_t len);
static int ensure_dir_exists(const char *path);
static void get_date_string(u_int32_t timestamp, char *date_str, size_t len);
static void format_time_string(u_int32_t timestamp, char *time_str, size_t len);
static void cleanup_old_record_files(void);
static u_int32_t parse_date_string(const char *date_str);
static int extract_date_from_filename(const char *filename, char *date_str, size_t len);
static void get_client_backup_dir(char *dir_path, size_t len);
static void build_client_backup_mac_dir(const char *mac, char *dir_path, size_t len);
static void build_client_backup_base_info_dir(const char *mac, char *dir_path, size_t len);
static void build_client_backup_file_path(const char *mac, char *file_path, size_t len);
static int load_client_backup_from_file(const char *file_path);
static u_int32_t get_today_start_timestamp_from_ts(u_int32_t timestamp);
static void build_client_visit_db_path(char *db_path, size_t len);
static int open_client_visit_db(sqlite3 **db);
static int save_visit_record_to_db(const char *mac, visit_info_t *visit);
static int find_oldest_date_in_visit_db(char *oldest_date, size_t len);
static int delete_visit_records_by_date(const char *date_str);
static int delete_expired_visit_records(u_int32_t expire_timestamp);
static int delete_oldest_visit_records_batch(int batch_count);
static int get_visit_record_count(void);
static int vacuum_visit_db_file(void);
static int delete_visit_records_in_range(const char *mac, u_int32_t start_timestamp, u_int32_t end_timestamp);
static char *get_command_output(const char *cmd);
static struct json_object *get_command_json(const char *cmd);
static void clear_client_wireless_status(void);
static client_node_t *find_client_node_nocase(const char *mac);
static unsigned int get_wireless_rate_value(struct json_object *rate_obj);
static void append_wireless_ifname(char ifnames[][MAX_WIRELESS_IFNAME_LEN], char bands[][MAX_WIRELESS_BAND_LEN], int *if_num, int max_if_num, const char *ifname, const char *band);
static int collect_wireless_ifnames(char ifnames[][MAX_WIRELESS_IFNAME_LEN], char bands[][MAX_WIRELESS_BAND_LEN], int max_if_num);
static void update_client_wireless_status_by_ifname(const char *ifname, const char *band);

static void session_push_recent_app(online_session_stat_t *session, int appid) {
    int i;
    if (!session || appid <= 0)
        return;

    for (i = 0; i < session->recent_app_count; i++) {
        if (session->recent_apps[i] == appid) {
            int j;
            for (j = i; j > 0; j--) {
                session->recent_apps[j] = session->recent_apps[j - 1];
            }
            session->recent_apps[0] = appid;
            return;
        }
    }

    if (session->recent_app_count < MAX_RECENT_APPS) {
        for (i = session->recent_app_count; i > 0; i--) {
            session->recent_apps[i] = session->recent_apps[i - 1];
        }
        session->recent_apps[0] = appid;
        session->recent_app_count++;
    } else {
        for (i = MAX_RECENT_APPS - 1; i > 0; i--) {
            session->recent_apps[i] = session->recent_apps[i - 1];
        }
        session->recent_apps[0] = appid;
    }
}

void reset_online_session_stat(client_node_t *client, u_int32_t start_time) {
    if (!client)
        return;
    memset(&client->online_session, 0, sizeof(client->online_session));
    client->online_session.start_time = start_time;
}

void update_online_session_flow(client_node_t *client, unsigned long long up_bytes, unsigned long long down_bytes) {
    if (!client || !client->online)
        return;
    client->online_session.up_bytes += up_bytes;
    client->online_session.down_bytes += down_bytes;
}

void update_online_session_activity(client_node_t *client, int online_seconds, int active_seconds) {
    if (!client || !client->online)
        return;
    if (online_seconds > 0)
        client->online_session.online_duration += (unsigned long long)online_seconds;
    if (active_seconds > 0)
        client->online_session.active_duration += (unsigned long long)active_seconds;
}

void update_online_session_recent_app(client_node_t *client, int appid) {
    if (!client || !client->online)
        return;
    session_push_recent_app(&client->online_session, appid);
}

void add_user_record(client_node_t *client, int action, u_int32_t timestamp) {
    user_record_t *record = NULL;
    int total = 0;
    struct list_head *pos, *n;
    if (!client)
        return;

    record = (user_record_t *)calloc(1, sizeof(user_record_t));
    if (!record)
        return;

    record->action = action;
    record->timestamp = timestamp;
    strncpy(record->mac, client->mac, sizeof(record->mac) - 1);
    strncpy(record->nickname, client->nickname, sizeof(record->nickname) - 1);
    strncpy(record->hostname, client->hostname, sizeof(record->hostname) - 1);

    if (action == 1) {
        record->up_bytes = client->online_session.up_bytes;
        record->down_bytes = client->online_session.down_bytes;
        record->online_duration = client->online_session.online_duration;
        record->active_duration = client->online_session.active_duration;
        record->recent_app_count = client->online_session.recent_app_count;
        if (record->recent_app_count > MAX_RECENT_APPS) {
            record->recent_app_count = MAX_RECENT_APPS;
        }
        if (record->recent_app_count > 0) {
            memcpy(record->recent_apps, client->online_session.recent_apps,
                   sizeof(int) * record->recent_app_count);
        }
    }

    INIT_LIST_HEAD(&record->list);
    list_add(&record->list, &user_record_list);

    list_for_each(pos, &user_record_list) {
        total++;
    }
    while (total > MAX_USER_RECORDS) {
        user_record_t *last = NULL;
        list_for_each_safe(pos, n, &user_record_list) {
            last = list_entry(pos, user_record_t, list);
        }
        if (!last) {
            break;
        }
        list_del(&last->list);
        free(last);
        total--;
    }
}

const char *get_client_data_root_dir(void) {
    if (!g_client_data_root_dir_initialized) {
        struct uci_context *uci_ctx = uci_alloc_context();
        if (uci_ctx) {
            char base_data_path[256] = {0};
            char terminal_data_path[256] = {0};
            char history_data_path[256] = {0};
            int ret = fwx_uci_get_value(uci_ctx, "fwx.record.base_data_path", base_data_path, sizeof(base_data_path));
            if (ret == 0 && strlen(base_data_path) > 0) {
                strncpy(g_client_data_root_dir, base_data_path, sizeof(g_client_data_root_dir) - 1);
            } else if (fwx_uci_get_value(uci_ctx, "fwx.record.terminal_data_path", terminal_data_path, sizeof(terminal_data_path)) == 0 &&
                       strlen(terminal_data_path) > 0) {
                strncpy(g_client_data_root_dir, terminal_data_path, sizeof(g_client_data_root_dir) - 1);
            } else if (fwx_uci_get_value(uci_ctx, "fwx.record.history_data_path", history_data_path, sizeof(history_data_path)) == 0 &&
                       strlen(history_data_path) > 0) {
                strncpy(g_client_data_root_dir, history_data_path, sizeof(g_client_data_root_dir) - 1);
            } else {
                strncpy(g_client_data_root_dir, "/tmp/fwx", sizeof(g_client_data_root_dir) - 1);
            }
            uci_free_context(uci_ctx);
        } else {
            strncpy(g_client_data_root_dir, "/tmp/fwx", sizeof(g_client_data_root_dir) - 1);
        }
        g_client_data_root_dir[sizeof(g_client_data_root_dir) - 1] = '\0';
        g_client_data_root_dir_initialized = 1;
    }
    return g_client_data_root_dir;
}

const char *get_history_data_root_dir(void) {
    if (!g_history_data_root_dir_initialized) {
        struct uci_context *uci_ctx = uci_alloc_context();
        if (uci_ctx) {
            char history_data_path[256] = {0};
            char base_data_path[256] = {0};
            char terminal_data_path[256] = {0};
            int ret = fwx_uci_get_value(uci_ctx, "fwx.record.history_data_path", history_data_path, sizeof(history_data_path));
            if (ret == 0 && strlen(history_data_path) > 0) {
                strncpy(g_history_data_root_dir, history_data_path, sizeof(g_history_data_root_dir) - 1);
            } else if (fwx_uci_get_value(uci_ctx, "fwx.record.base_data_path", base_data_path, sizeof(base_data_path)) == 0 &&
                       strlen(base_data_path) > 0) {
                strncpy(g_history_data_root_dir, base_data_path, sizeof(g_history_data_root_dir) - 1);
            } else if (fwx_uci_get_value(uci_ctx, "fwx.record.terminal_data_path", terminal_data_path, sizeof(terminal_data_path)) == 0 &&
                       strlen(terminal_data_path) > 0) {
                strncpy(g_history_data_root_dir, terminal_data_path, sizeof(g_history_data_root_dir) - 1);
            } else {
                strncpy(g_history_data_root_dir, "/tmp/fwx", sizeof(g_history_data_root_dir) - 1);
            }
            uci_free_context(uci_ctx);
        } else {
            strncpy(g_history_data_root_dir, "/tmp/fwx", sizeof(g_history_data_root_dir) - 1);
        }
        g_history_data_root_dir[sizeof(g_history_data_root_dir) - 1] = '\0';
        g_history_data_root_dir_initialized = 1;
    }
    return g_history_data_root_dir;
}

const char *get_client_data_base_dir(void) {
    if (!g_client_data_base_dir_initialized) {
        snprintf(g_client_data_base_dir, sizeof(g_client_data_base_dir), "%s/client_data", get_client_data_root_dir());
        g_client_data_base_dir[sizeof(g_client_data_base_dir) - 1] = '\0';
        g_client_data_base_dir_initialized = 1;
    }
    return g_client_data_base_dir;
}

void reset_client_data_base_dir_cache(void) {
    g_client_data_base_dir_initialized = 0;
    g_client_data_base_dir[0] = '\0';
    g_client_data_root_dir_initialized = 0;
    g_client_data_root_dir[0] = '\0';
    g_history_data_root_dir_initialized = 0;
    g_history_data_root_dir[0] = '\0';
}

static void init_daily_stats_default(daily_hourly_stat_t *stat) {
    int i, j;

    if (!stat)
        return;

    for (i = 0; i < HOURS_PER_DAY; i++) {
        stat->hourly_traffic[i].up_bytes = 0;
        stat->hourly_traffic[i].down_bytes = 0;
        stat->hourly_online_time[i] = 0;
        stat->hourly_active_time[i] = 0;
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            stat->hourly_top_apps[i][j] = -1;
        }
    }
}

static void init_daily_top_apps_default(daily_top_apps_stat_t *stat) {
    int i;

    if (!stat)
        return;

    stat->count = 0;
    for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
        stat->apps[i].appid = -1;
        stat->apps[i].total_time = 0;
    }
}

static void reset_client_runtime_fields(client_node_t *client) {
    if (!client)
        return;

    client->up_rate = 0;
    client->down_rate = 0;
    client->rssi = 0;
    client->rx_rate = 0;
    client->tx_rate = 0;
    client->band[0] = '\0';
    client->wifi_ifname[0] = '\0';
    client->wireless_online = 0;
    client->online = 0;
    client->visiting_url[0] = '\0';
    client->visiting_app = 0;
    client->active = 0;
    client->last_online_state = 0;
    client->session_online_recorded = 0;
}

static void get_client_backup_dir(char *dir_path, size_t len) {
    if (!dir_path || len == 0)
        return;

    snprintf(dir_path, len, "%s/client_backup", get_client_data_root_dir());
}

static void build_client_backup_mac_dir(const char *mac, char *dir_path, size_t len) {
    char backup_dir[512] = {0};
    char mac_dirname[64] = {0};

    if (!mac || !dir_path || len == 0)
        return;

    get_client_backup_dir(backup_dir, sizeof(backup_dir));
    mac_to_dirname(mac, mac_dirname, sizeof(mac_dirname));
    snprintf(dir_path, len, "%s/%s", backup_dir, mac_dirname);
}

static void build_client_backup_base_info_dir(const char *mac, char *dir_path, size_t len) {
    char mac_dir[512] = {0};

    if (!mac || !dir_path || len == 0)
        return;

    build_client_backup_mac_dir(mac, mac_dir, sizeof(mac_dir));
    snprintf(dir_path, len, "%s/base_info", mac_dir);
}

static void build_client_backup_file_path(const char *mac, char *file_path, size_t len) {
    char base_info_dir[512] = {0};

    if (!mac || !file_path || len == 0)
        return;

    build_client_backup_base_info_dir(mac, base_info_dir, sizeof(base_info_dir));
    snprintf(file_path, len, "%s/client.json", base_info_dir);
}

static struct json_object *serialize_online_session_stat(const online_session_stat_t *session) {
    int i;
    struct json_object *session_obj = json_object_new_object();
    struct json_object *recent_apps = json_object_new_array();

    if (!session)
        return session_obj;

    json_object_object_add(session_obj, "up_bytes", json_object_new_int64(session->up_bytes));
    json_object_object_add(session_obj, "down_bytes", json_object_new_int64(session->down_bytes));
    json_object_object_add(session_obj, "online_duration", json_object_new_int64(session->online_duration));
    json_object_object_add(session_obj, "active_duration", json_object_new_int64(session->active_duration));
    json_object_object_add(session_obj, "recent_app_count", json_object_new_int(session->recent_app_count));
    json_object_object_add(session_obj, "start_time", json_object_new_int64(session->start_time));

    for (i = 0; i < session->recent_app_count && i < MAX_RECENT_APPS; i++) {
        json_object_array_add(recent_apps, json_object_new_int(session->recent_apps[i]));
    }
    json_object_object_add(session_obj, "recent_apps", recent_apps);

    return session_obj;
}

static struct json_object *serialize_daily_stats(const daily_hourly_stat_t *stat) {
    int i, j;
    struct json_object *stat_obj = json_object_new_object();
    struct json_object *hourly_top_apps = json_object_new_array();
    struct json_object *hourly_traffic = json_object_new_array();
    struct json_object *hourly_online_time = json_object_new_array();
    struct json_object *hourly_active_time = json_object_new_array();

    if (!stat)
        return stat_obj;

    json_object_object_add(stat_obj, "date", json_object_new_int64(stat->date));
    json_object_object_add(stat_obj, "is_today", json_object_new_int(stat->is_today));

    for (i = 0; i < HOURS_PER_DAY; i++) {
        struct json_object *top_apps = json_object_new_array();
        struct json_object *traffic_obj = json_object_new_object();
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            json_object_array_add(top_apps, json_object_new_int(stat->hourly_top_apps[i][j]));
        }
        json_object_array_add(hourly_top_apps, top_apps);

        json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(stat->hourly_traffic[i].up_bytes));
        json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(stat->hourly_traffic[i].down_bytes));
        json_object_array_add(hourly_traffic, traffic_obj);

        json_object_array_add(hourly_online_time, json_object_new_int64(stat->hourly_online_time[i]));
        json_object_array_add(hourly_active_time, json_object_new_int64(stat->hourly_active_time[i]));
    }

    json_object_object_add(stat_obj, "hourly_top_apps", hourly_top_apps);
    json_object_object_add(stat_obj, "hourly_traffic", hourly_traffic);
    json_object_object_add(stat_obj, "hourly_online_time", hourly_online_time);
    json_object_object_add(stat_obj, "hourly_active_time", hourly_active_time);

    return stat_obj;
}

static struct json_object *serialize_daily_top_apps_stats(const daily_top_apps_stat_t *stat) {
    int i;
    struct json_object *stat_obj = json_object_new_object();
    struct json_object *apps = json_object_new_array();

    if (!stat)
        return stat_obj;

    json_object_object_add(stat_obj, "date", json_object_new_int64(stat->date));
    json_object_object_add(stat_obj, "is_today", json_object_new_int(stat->is_today));
    json_object_object_add(stat_obj, "count", json_object_new_int(stat->count));

    for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
        struct json_object *app_obj = json_object_new_object();
        json_object_object_add(app_obj, "appid", json_object_new_int(stat->apps[i].appid));
        if (!app_icon_exists_by_id(stat->apps[i].appid))
            json_object_object_add(app_obj, "icon", json_object_new_int(0));
        json_object_object_add(app_obj, "total_time", json_object_new_int64(stat->apps[i].total_time));
        json_object_array_add(apps, app_obj);
    }

    json_object_object_add(stat_obj, "apps", apps);
    return stat_obj;
}

void save_client_backup_to_file(client_node_t *client) {
    char backup_dir[512] = {0};
    char mac_dir[512] = {0};
    char base_info_dir[512] = {0};
    char file_path[512] = {0};
    struct json_object *json_obj = NULL;
    if (!client)
        return;

    get_client_backup_dir(backup_dir, sizeof(backup_dir));
    if (ensure_dir_exists(backup_dir) != 0) {
        LOG_ERROR("Failed to create client backup directory: %s\n", backup_dir);
        return;
    }

    build_client_backup_mac_dir(client->mac, mac_dir, sizeof(mac_dir));
    if (ensure_dir_exists(mac_dir) != 0) {
        LOG_ERROR("Failed to create client backup mac directory: %s\n", mac_dir);
        return;
    }

    build_client_backup_base_info_dir(client->mac, base_info_dir, sizeof(base_info_dir));
    if (ensure_dir_exists(base_info_dir) != 0) {
        LOG_ERROR("Failed to create client backup base_info directory: %s\n", base_info_dir);
        return;
    }

    build_client_backup_file_path(client->mac, file_path, sizeof(file_path));

    json_obj = json_object_new_object();
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(json_obj, "ip", json_object_new_string(client->ip));
    json_object_object_add(json_obj, "ipv6", json_object_new_string(client->ipv6));
    json_object_object_add(json_obj, "hostname", json_object_new_string(client->hostname));
    json_object_object_add(json_obj, "nickname", json_object_new_string(client->nickname));
    json_object_object_add(json_obj, "expire", json_object_new_int(client->expire));
    json_object_object_add(json_obj, "offline_time", json_object_new_int64(client->offline_time));
    json_object_object_add(json_obj, "online_time", json_object_new_int64(client->online_time));
    json_object_object_add(json_obj, "mf_user_loaded", json_object_new_int(client->mf_user_loaded));
    json_object_object_add(json_obj, "is_wireless", json_object_new_int(client->is_wireless));
    json_object_object_add(json_obj, "online_session", serialize_online_session_stat(&client->online_session));
    json_object_object_add(json_obj, "daily_stats", serialize_daily_stats(&client->daily_stats));
    json_object_object_add(json_obj, "daily_top_apps_stats", serialize_daily_top_apps_stats(&client->daily_top_apps_stats));

    if (json_object_to_file_ext(file_path, json_obj, JSON_C_TO_STRING_PRETTY) != 0) {
        LOG_ERROR("Failed to save client backup to file: %s (errno: %d)\n", file_path, errno);
    }
    LOG_INFO("444 path = %s\n", file_path);
    LOG_INFO("data = %s\n", json_object_get_string(json_obj));

    json_object_put(json_obj);
}

void save_all_client_backup_to_files(void) {
    client_node_t *node = NULL;

    list_for_each_entry(node, &client_list, client) {
        LOG_INFO("begin save %s\n",node->mac);
        save_client_backup_to_file(node);
    }
}

static void load_online_session_stat_from_json(online_session_stat_t *session, struct json_object *session_obj) {
    int i;
    struct json_object *value_obj = NULL;
    struct json_object *recent_apps_obj = NULL;

    if (!session) {
        return;
    }

    memset(session, 0, sizeof(*session));
    if (!session_obj)
        return;

    if (json_object_object_get_ex(session_obj, "up_bytes", &value_obj))
        session->up_bytes = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(session_obj, "down_bytes", &value_obj))
        session->down_bytes = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(session_obj, "online_duration", &value_obj))
        session->online_duration = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(session_obj, "active_duration", &value_obj))
        session->active_duration = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(session_obj, "recent_app_count", &value_obj))
        session->recent_app_count = json_object_get_int(value_obj);
    if (json_object_object_get_ex(session_obj, "start_time", &value_obj))
        session->start_time = json_object_get_int64(value_obj);

    if (session->recent_app_count < 0)
        session->recent_app_count = 0;
    if (session->recent_app_count > MAX_RECENT_APPS)
        session->recent_app_count = MAX_RECENT_APPS;

    if (json_object_object_get_ex(session_obj, "recent_apps", &recent_apps_obj) &&
        json_object_get_type(recent_apps_obj) == json_type_array) {
        int count = json_object_array_length(recent_apps_obj);
        if (count > session->recent_app_count)
            count = session->recent_app_count;
        for (i = 0; i < count; i++) {
            session->recent_apps[i] = json_object_get_int(json_object_array_get_idx(recent_apps_obj, i));
        }
    }
}

static void load_daily_stats_from_json(daily_hourly_stat_t *stat, struct json_object *stat_obj) {
    int i, j;
    struct json_object *value_obj = NULL;
    struct json_object *top_apps_obj = NULL;
    struct json_object *traffic_obj = NULL;
    struct json_object *online_time_obj = NULL;
    struct json_object *active_time_obj = NULL;

    if (!stat)
        return;

    memset(stat, 0, sizeof(*stat));
    init_daily_stats_default(stat);
    if (!stat_obj)
        return;

    if (json_object_object_get_ex(stat_obj, "date", &value_obj))
        stat->date = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(stat_obj, "is_today", &value_obj))
        stat->is_today = json_object_get_int(value_obj);

    if (json_object_object_get_ex(stat_obj, "hourly_top_apps", &top_apps_obj) &&
        json_object_get_type(top_apps_obj) == json_type_array) {
        int hour_count = json_object_array_length(top_apps_obj);
        if (hour_count > HOURS_PER_DAY)
            hour_count = HOURS_PER_DAY;
        for (i = 0; i < hour_count; i++) {
            struct json_object *hour_obj = json_object_array_get_idx(top_apps_obj, i);
            if (!hour_obj || json_object_get_type(hour_obj) != json_type_array)
                continue;
            for (j = 0; j < TOP_APP_PER_HOUR && j < json_object_array_length(hour_obj); j++) {
                stat->hourly_top_apps[i][j] = json_object_get_int(json_object_array_get_idx(hour_obj, j));
            }
        }
    }

    if (json_object_object_get_ex(stat_obj, "hourly_traffic", &traffic_obj) &&
        json_object_get_type(traffic_obj) == json_type_array) {
        int hour_count = json_object_array_length(traffic_obj);
        if (hour_count > HOURS_PER_DAY)
            hour_count = HOURS_PER_DAY;
        for (i = 0; i < hour_count; i++) {
            struct json_object *hour_obj = json_object_array_get_idx(traffic_obj, i);
            struct json_object *up_obj = NULL;
            struct json_object *down_obj = NULL;
            if (!hour_obj)
                continue;
            if (json_object_object_get_ex(hour_obj, "up_bytes", &up_obj))
                stat->hourly_traffic[i].up_bytes = json_object_get_int64(up_obj);
            if (json_object_object_get_ex(hour_obj, "down_bytes", &down_obj))
                stat->hourly_traffic[i].down_bytes = json_object_get_int64(down_obj);
        }
    }

    if (json_object_object_get_ex(stat_obj, "hourly_online_time", &online_time_obj) &&
        json_object_get_type(online_time_obj) == json_type_array) {
        int hour_count = json_object_array_length(online_time_obj);
        if (hour_count > HOURS_PER_DAY)
            hour_count = HOURS_PER_DAY;
        for (i = 0; i < hour_count; i++) {
            stat->hourly_online_time[i] = json_object_get_int64(json_object_array_get_idx(online_time_obj, i));
        }
    }

    if (json_object_object_get_ex(stat_obj, "hourly_active_time", &active_time_obj) &&
        json_object_get_type(active_time_obj) == json_type_array) {
        int hour_count = json_object_array_length(active_time_obj);
        if (hour_count > HOURS_PER_DAY)
            hour_count = HOURS_PER_DAY;
        for (i = 0; i < hour_count; i++) {
            stat->hourly_active_time[i] = json_object_get_int64(json_object_array_get_idx(active_time_obj, i));
        }
    }
}

static void load_daily_top_apps_from_json(daily_top_apps_stat_t *stat, struct json_object *stat_obj) {
    int i;
    struct json_object *value_obj = NULL;
    struct json_object *apps_obj = NULL;

    if (!stat)
        return;

    memset(stat, 0, sizeof(*stat));
    init_daily_top_apps_default(stat);
    if (!stat_obj)
        return;

    if (json_object_object_get_ex(stat_obj, "date", &value_obj))
        stat->date = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(stat_obj, "is_today", &value_obj))
        stat->is_today = json_object_get_int(value_obj);
    if (json_object_object_get_ex(stat_obj, "count", &value_obj))
        stat->count = json_object_get_int(value_obj);

    if (stat->count < 0)
        stat->count = 0;
    if (stat->count > MAX_TOP_APPS_PER_DAY)
        stat->count = MAX_TOP_APPS_PER_DAY;

    if (json_object_object_get_ex(stat_obj, "apps", &apps_obj) &&
        json_object_get_type(apps_obj) == json_type_array) {
        int app_count = json_object_array_length(apps_obj);
        if (app_count > MAX_TOP_APPS_PER_DAY)
            app_count = MAX_TOP_APPS_PER_DAY;
        for (i = 0; i < app_count; i++) {
            struct json_object *app_obj = json_object_array_get_idx(apps_obj, i);
            struct json_object *appid_obj = NULL;
            struct json_object *time_obj = NULL;
            if (!app_obj)
                continue;
            if (json_object_object_get_ex(app_obj, "appid", &appid_obj))
                stat->apps[i].appid = json_object_get_int(appid_obj);
            if (json_object_object_get_ex(app_obj, "total_time", &time_obj))
                stat->apps[i].total_time = json_object_get_int64(time_obj);
        }
    }
}

static int load_client_backup_from_file(const char *file_path) {
    struct json_object *json_obj = NULL;
    struct json_object *mac_obj = NULL;
    struct json_object *value_obj = NULL;
    struct json_object *online_session_obj = NULL;
    struct json_object *daily_stats_obj = NULL;
    struct json_object *daily_top_apps_obj = NULL;
    const char *mac = NULL;
    client_node_t *client = NULL;

    if (!file_path)
        return -1;

    json_obj = json_object_from_file(file_path);
    if (!json_obj) {
        LOG_ERROR("Failed to load client backup file: %s\n", file_path);
        return -1;
    }

    if (!json_object_object_get_ex(json_obj, "mac", &mac_obj)) {
        json_object_put(json_obj);
        return -1;
    }

    mac = json_object_get_string(mac_obj);
    if (!mac || strlen(mac) == 0) {
        json_object_put(json_obj);
        return -1;
    }

    client = find_client_node(mac);
    if (!client) {
        client = add_client_node((char *)mac);
        if (!client) {
            json_object_put(json_obj);
            return -1;
        }
    }

    reset_client_runtime_fields(client);

    if (json_object_object_get_ex(json_obj, "ip", &value_obj))
        strncpy(client->ip, json_object_get_string(value_obj), sizeof(client->ip) - 1);
    client->ip[sizeof(client->ip) - 1] = '\0';
    if (json_object_object_get_ex(json_obj, "ipv6", &value_obj))
        strncpy(client->ipv6, json_object_get_string(value_obj), sizeof(client->ipv6) - 1);
    client->ipv6[sizeof(client->ipv6) - 1] = '\0';
    if (json_object_object_get_ex(json_obj, "hostname", &value_obj))
        strncpy(client->hostname, json_object_get_string(value_obj), sizeof(client->hostname) - 1);
    client->hostname[sizeof(client->hostname) - 1] = '\0';
    if (json_object_object_get_ex(json_obj, "nickname", &value_obj))
        strncpy(client->nickname, json_object_get_string(value_obj), sizeof(client->nickname) - 1);
    client->nickname[sizeof(client->nickname) - 1] = '\0';
    if (json_object_object_get_ex(json_obj, "expire", &value_obj))
        client->expire = json_object_get_int(value_obj);
    if (json_object_object_get_ex(json_obj, "offline_time", &value_obj))
        client->offline_time = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(json_obj, "online_time", &value_obj))
        client->online_time = json_object_get_int64(value_obj);
    if (json_object_object_get_ex(json_obj, "mf_user_loaded", &value_obj))
        client->mf_user_loaded = json_object_get_int(value_obj);
    if (json_object_object_get_ex(json_obj, "is_wireless", &value_obj))
        client->is_wireless = json_object_get_int(value_obj);

    if (json_object_object_get_ex(json_obj, "online_session", &online_session_obj))
        load_online_session_stat_from_json(&client->online_session, online_session_obj);
    if (json_object_object_get_ex(json_obj, "daily_stats", &daily_stats_obj))
        load_daily_stats_from_json(&client->daily_stats, daily_stats_obj);
    if (json_object_object_get_ex(json_obj, "daily_top_apps_stats", &daily_top_apps_obj))
        load_daily_top_apps_from_json(&client->daily_top_apps_stats, daily_top_apps_obj);

    json_object_put(json_obj);
    return 0;
}

void load_client_backup_from_files(void) {
    DIR *backup_dir = NULL;
    struct dirent *entry = NULL;
    char dir_path[512] = {0};

    get_client_backup_dir(dir_path, sizeof(dir_path));
    if (ensure_dir_exists(dir_path) != 0) {
        LOG_ERROR("Failed to create client backup directory: %s\n", dir_path);
        return;
    }

    backup_dir = opendir(dir_path);
    if (!backup_dir) {
        LOG_ERROR("Failed to open client backup directory: %s\n", dir_path);
        return;
    }

    while ((entry = readdir(backup_dir)) != NULL) {
        char file_path[512] = {0};
        char mac_dir[512] = {0};
        char base_info_file[512] = {0};
        size_t name_len = 0;
        struct stat st;

        if (entry->d_name[0] == '.')
            continue;

        snprintf(mac_dir, sizeof(mac_dir), "%s/%s", dir_path, entry->d_name);
        if (stat(mac_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(base_info_file, sizeof(base_info_file), "%s/base_info/client.json", mac_dir);
            if (stat(base_info_file, &st) == 0 && S_ISREG(st.st_mode)) {
                load_client_backup_from_file(base_info_file);
            }
            continue;
        }

        name_len = strlen(entry->d_name);
        if (name_len < 6 || strcmp(entry->d_name + name_len - 5, ".json") != 0)
            continue;

        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
        load_client_backup_from_file(file_path);
    }

    closedir(backup_dir);
}


void load_app_valid_time_config(void) {
    struct uci_context *uci_ctx = uci_alloc_context();
    if (uci_ctx) {
        int app_valid_time = fwx_uci_get_int_value(uci_ctx, "fwx.record.app_valid_time");
        if (app_valid_time > 0) {
            g_app_valid_time = app_valid_time;
        } else {
            g_app_valid_time = 300;
        }
        uci_free_context(uci_ctx);
        LOG_DEBUG("Loaded app_valid_time config: %d seconds\n", g_app_valid_time);
    }
}


int get_app_valid_time(void) {
    return g_app_valid_time;
}

static void build_client_visit_db_path(char *db_path, size_t len) {
    if (!db_path || len == 0)
        return;

    snprintf(db_path, len, "%s/client.db", get_history_data_root_dir());
}

static int open_client_visit_db(sqlite3 **db) {
    char db_path[512] = {0};
    int rc = SQLITE_OK;

    if (!db)
        return -1;

    if (ensure_dir_exists(get_history_data_root_dir()) != 0) {
        LOG_ERROR("Failed to create root directory: %s\n", get_history_data_root_dir());
        return -1;
    }

    build_client_visit_db_path(db_path, sizeof(db_path));
    rc = sqlite3_open(db_path, db);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to open sqlite db: %s (rc: %d)\n", db_path, rc);
        if (*db) {
            sqlite3_close(*db);
            *db = NULL;
        }
        return -1;
    }

    rc = sqlite3_exec(*db,
                      "CREATE TABLE IF NOT EXISTS app_visit_record ("
                      "mac TEXT NOT NULL,"
                      "record_date INTEGER NOT NULL,"
                      "appid INTEGER NOT NULL,"
                      "start_time INTEGER NOT NULL,"
                      "end_time INTEGER NOT NULL,"
                      "duration INTEGER NOT NULL,"
                      "action INTEGER NOT NULL"
                      ");"
                      "CREATE INDEX IF NOT EXISTS idx_app_visit_record_date ON app_visit_record (record_date);"
                      "CREATE INDEX IF NOT EXISTS idx_app_visit_record_mac_date ON app_visit_record (mac, record_date);",
                      NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to init sqlite db: %s (rc: %d)\n", db_path, rc);
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }

    return 0;
}

static int save_visit_record_to_db(const char *mac, visit_info_t *visit) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int duration = 0;
    u_int32_t record_date = 0;

    if (!mac || !visit)
        return -1;

    if (open_client_visit_db(&db) != 0)
        return -1;

    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO app_visit_record (mac, record_date, appid, start_time, end_time, duration, action) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    duration = visit->latest_time - visit->first_time;
    if (duration == 0)
        duration = 1;
    record_date = get_today_start_timestamp_from_ts(visit->first_time);

    sqlite3_bind_text(stmt, 1, mac, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, record_date);
    sqlite3_bind_int(stmt, 3, visit->appid);
    sqlite3_bind_int64(stmt, 4, visit->first_time);
    sqlite3_bind_int64(stmt, 5, visit->latest_time);
    sqlite3_bind_int(stmt, 6, duration);
    sqlite3_bind_int(stmt, 7, visit->action);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
        goto CLEANUP;

    rc = SQLITE_OK;

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to save visit record to sqlite db: mac=%s, appid=%d, start=%u, end=%u, rc=%d\n",
                  mac, visit->appid, visit->first_time, visit->latest_time, rc);
        return -1;
    }

    return 0;
}

void init_client_visit_db(void) {
    sqlite3 *db = NULL;
    char db_path[512] = {0};

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (open_client_visit_db(&db) != 0) {
        LOG_ERROR("Failed to init client visit db on startup: %s\n", db_path);
        return;
    }

    sqlite3_close(db);
    LOG_INFO("Client visit db ready: %s\n", db_path);
}

int add_mock_visit_records_to_db(int record_count, int mac_count, unsigned long long *old_size_bytes, unsigned long long *new_size_bytes) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int i = 0;
    int inserted = 0;
    int transaction_started = 0;
    int safe_record_count = record_count;
    int safe_mac_count = mac_count;
    u_int32_t now = 0;
    u_int32_t base_time = 0;
    char db_path[512] = {0};
    struct stat st = {0};

    if (old_size_bytes)
        *old_size_bytes = 0;
    if (new_size_bytes)
        *new_size_bytes = 0;

    if (safe_record_count <= 0)
        return -1;
    if (safe_record_count > 500000)
        safe_record_count = 500000;

    if (safe_mac_count <= 0)
        safe_mac_count = 16;
    if (safe_mac_count > 512)
        safe_mac_count = 512;

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (stat(db_path, &st) == 0 && old_size_bytes) {
        *old_size_bytes = (unsigned long long)st.st_size;
    }

    if (open_client_visit_db(&db) != 0)
        return -1;

    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;
    transaction_started = 1;

    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO app_visit_record (mac, record_date, appid, start_time, end_time, duration, action) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    now = (u_int32_t)time(NULL);
    base_time = now - (u_int32_t)(7 * SECONDS_PER_DAY);
    for (i = 0; i < safe_record_count; i++) {
        char mac[32] = {0};
        int mac_idx = i % safe_mac_count;
        int appid = 1000 + (i % 4096);
        u_int32_t start_time = base_time + (u_int32_t)((i * 37) % (7 * SECONDS_PER_DAY));
        int duration = 10 + (i % 1800);
        u_int32_t end_time = start_time + (u_int32_t)duration;
        u_int32_t record_date = get_today_start_timestamp_from_ts(start_time);
        int action = i % 2;

        snprintf(mac, sizeof(mac), "02:%02X:%02X:%02X:%02X:%02X",
                 (mac_idx >> 16) & 0xFF, (mac_idx >> 12) & 0xFF, (mac_idx >> 8) & 0xFF,
                 (mac_idx >> 4) & 0xFF, mac_idx & 0xFF);

        sqlite3_bind_text(stmt, 1, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, record_date);
        sqlite3_bind_int(stmt, 3, appid);
        sqlite3_bind_int64(stmt, 4, start_time);
        sqlite3_bind_int64(stmt, 5, end_time);
        sqlite3_bind_int(stmt, 6, duration);
        sqlite3_bind_int(stmt, 7, action);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE)
            goto CLEANUP;

        inserted++;
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;
    transaction_started = 0;
    rc = SQLITE_OK;

CLEANUP:
    if (rc != SQLITE_OK && transaction_started) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
    }

    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    if (stat(db_path, &st) == 0 && new_size_bytes) {
        *new_size_bytes = (unsigned long long)st.st_size;
    }

    if (rc != SQLITE_OK) {
        LOG_ERROR("add_mock_visit_records_to_db failed: rc=%d, record_count=%d, mac_count=%d\n",
                  rc, record_count, mac_count);
        return -1;
    }

    LOG_WARN("add_mock_visit_records_to_db done: inserted=%d, record_count=%d, mac_count=%d\n",
             inserted, record_count, safe_mac_count);
    return inserted;
}

static int find_oldest_date_in_visit_db(char *oldest_date, size_t len) {
    char db_path[512] = {0};
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    sqlite3_int64 record_date = 0;
    int rc = SQLITE_OK;

    if (!oldest_date || len == 0)
        return -1;

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return -1;

    if (open_client_visit_db(&db) != 0)
        return -1;

    rc = sqlite3_prepare_v2(db, "SELECT MIN(record_date) FROM app_visit_record;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW || sqlite3_column_type(stmt, 0) == SQLITE_NULL)
        goto CLEANUP;

    record_date = sqlite3_column_int64(stmt, 0);
    if (record_date > 0) {
        get_date_string((u_int32_t)record_date, oldest_date, len);
        rc = SQLITE_OK;
    } else {
        rc = SQLITE_ERROR;
    }

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    return rc == SQLITE_OK ? 0 : -1;
}

static int delete_visit_records_by_date(const char *date_str) {
    u_int32_t record_date = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int deleted_count = 0;
    char db_path[512] = {0};

    if (!date_str || strlen(date_str) == 0)
        return 0;

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return 0;

    record_date = parse_date_string(date_str);
    if (record_date == 0)
        return 0;

    if (open_client_visit_db(&db) != 0)
        return 0;

    rc = sqlite3_prepare_v2(db, "DELETE FROM app_visit_record WHERE record_date = ?;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    sqlite3_bind_int64(stmt, 1, record_date);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
        deleted_count = sqlite3_changes(db);

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    return deleted_count;
}

static int delete_expired_visit_records(u_int32_t expire_timestamp) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int deleted_count = 0;
    char db_path[512] = {0};

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return 0;

    if (open_client_visit_db(&db) != 0)
        return 0;

    rc = sqlite3_prepare_v2(db, "DELETE FROM app_visit_record WHERE record_date < ?;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    sqlite3_bind_int64(stmt, 1, expire_timestamp);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
        deleted_count = sqlite3_changes(db);

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    return deleted_count;
}

static int delete_oldest_visit_records_batch(int batch_count) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int deleted_count = 0;
    char db_path[512] = {0};

    if (batch_count <= 0)
        return 0;

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return 0;

    if (open_client_visit_db(&db) != 0)
        return 0;

    rc = sqlite3_prepare_v2(
        db,
        "DELETE FROM app_visit_record "
        "WHERE rowid IN ("
        "SELECT rowid FROM app_visit_record "
        "ORDER BY record_date ASC, rowid ASC "
        "LIMIT ?"
        ");",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    sqlite3_bind_int(stmt, 1, batch_count);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
        deleted_count = sqlite3_changes(db);

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    return deleted_count;
}

static int get_visit_record_count(void) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int record_count = -1;
    char db_path[512] = {0};

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return -1;

    if (open_client_visit_db(&db) != 0)
        return -1;

    rc = sqlite3_prepare_v2(db, "SELECT COUNT(1) FROM app_visit_record;", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        goto CLEANUP;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        record_count = sqlite3_column_int(stmt, 0);
        rc = SQLITE_OK;
    }

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    if (rc != SQLITE_OK)
        return -1;

    return record_count;
}

static int vacuum_visit_db_file(void) {
    sqlite3 *db = NULL;
    int rc = SQLITE_OK;

    if (open_client_visit_db(&db) != 0)
        return -1;

    rc = sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);
    sqlite3_close(db);

    if (rc != SQLITE_OK)
        return -1;

    return 0;
}

static int delete_visit_records_in_range(const char *mac, u_int32_t start_timestamp, u_int32_t end_timestamp) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int deleted_count = 0;
    char db_path[512] = {0};

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0)
        return 0;

    if (open_client_visit_db(&db) != 0)
        return 0;

    if (mac && strlen(mac) > 0) {
        rc = sqlite3_prepare_v2(db,
                                "DELETE FROM app_visit_record WHERE mac = ? AND record_date >= ? AND record_date <= ?;",
                                -1, &stmt, NULL);
        if (rc != SQLITE_OK)
            goto CLEANUP;

        sqlite3_bind_text(stmt, 1, mac, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, start_timestamp);
        sqlite3_bind_int64(stmt, 3, end_timestamp);
    } else {
        rc = sqlite3_prepare_v2(db,
                                "DELETE FROM app_visit_record WHERE record_date >= ? AND record_date <= ?;",
                                -1, &stmt, NULL);
        if (rc != SQLITE_OK)
            goto CLEANUP;

        sqlite3_bind_int64(stmt, 1, start_timestamp);
        sqlite3_bind_int64(stmt, 2, end_timestamp);
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
        deleted_count = sqlite3_changes(db);

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    return deleted_count;
}

static int find_oldest_date_in_dir(const char *dir_path, char *oldest_date, size_t date_len) {
    DIR *base_dir = opendir(dir_path);
    char oldest[32] = {0};
    int found = 0;
    struct dirent *client_entry;

    if (base_dir) {
        while ((client_entry = readdir(base_dir)) != NULL) {
            if (client_entry->d_name[0] == '.')
                continue;
            
            char client_dir[512] = {0};
            snprintf(client_dir, sizeof(client_dir), "%s/%s", dir_path, client_entry->d_name);
            
            struct stat st;
            if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
                continue;
            
            char stats_dir[512] = {0};
            snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
            
            DIR *stats_d = opendir(stats_dir);
            if (stats_d) {
                struct dirent *file_entry;
                while ((file_entry = readdir(stats_d)) != NULL) {
                    if (file_entry->d_name[0] == '.')
                        continue;
                    
                    char date_str[32] = {0};
                    if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                        if (!found || strcmp(date_str, oldest) < 0) {
                            strncpy(oldest, date_str, sizeof(oldest) - 1);
                            found = 1;
                        }
                    }
                }
                closedir(stats_d);
            }
            
            char visits_dir[512] = {0};
            snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
            
            DIR *visits_d = opendir(visits_dir);
            if (visits_d) {
                struct dirent *file_entry;
                while ((file_entry = readdir(visits_d)) != NULL) {
                    if (file_entry->d_name[0] == '.')
                        continue;
                    
                    char date_str[32] = {0};
                    if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) != 0)
                        continue;
                    
                    if (strlen(date_str) > 0) {
                        if (!found || strcmp(date_str, oldest) < 0) {
                            strncpy(oldest, date_str, sizeof(oldest) - 1);
                            found = 1;
                        }
                    }
                }
                closedir(visits_d);
            }
        }
        
        closedir(base_dir);
    }
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_history_data_root_dir());
    
    DIR *global_stats_d = opendir(global_stats_dir);
    if (global_stats_d) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                if (!found || strcmp(date_str, oldest) < 0) {
                    strncpy(oldest, date_str, sizeof(oldest) - 1);
                    found = 1;
                }
            }
        }
        closedir(global_stats_d);
    }

    {
        char visit_oldest[32] = {0};
        if (find_oldest_date_in_visit_db(visit_oldest, sizeof(visit_oldest)) == 0) {
            if (!found || strcmp(visit_oldest, oldest) < 0) {
                strncpy(oldest, visit_oldest, sizeof(oldest) - 1);
                found = 1;
            }
        }
    }
    
    if (found) {
        strncpy(oldest_date, oldest, date_len - 1);
        oldest_date[date_len - 1] = '\0';
        return 0;
    }
    
    return -1;
}

static void delete_date_files(const char *date_str) {
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        delete_visit_records_by_date(date_str);
        return;
    }
    
    struct dirent *client_entry;
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_d = opendir(stats_dir);
        if (!stats_d)
            continue;
        
        struct dirent *file_entry;
        while ((file_entry = readdir(stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char file_date[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, file_date, sizeof(file_date)) == 0) {
                if (strcmp(file_date, date_str) == 0) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                    unlink(file_path);
                }
            }
        }
        closedir(stats_d);
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_d = opendir(visits_dir);
        if (!visits_d)
            continue;
        
        while ((file_entry = readdir(visits_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char file_date[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, file_date, sizeof(file_date)) != 0)
                continue;
            
            if (strcmp(file_date, date_str) == 0) {
                char file_path[512] = {0};
                snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                unlink(file_path);
            }
        }
        closedir(visits_d);
    }
    
    closedir(base_dir);
    delete_visit_records_by_date(date_str);
}

static void cleanup_expired_files_by_days(void) {
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx)
        return;
    
    int record_time = fwx_uci_get_int_value(uci_ctx, "fwx.record.record_time");
    uci_free_context(uci_ctx);
    LOG_INFO("cleanup_expired_files_by_days: record_time: %d\n", record_time);
    if (record_time <= 0) {
        return;
    }
    
    time_t now = time(NULL);
    u_int32_t expire_timestamp = (u_int32_t)now - (record_time * SECONDS_PER_DAY);
    int deleted_count = 0;
    deleted_count += delete_expired_visit_records(expire_timestamp);
    
    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        return;
    }
    
    struct dirent *client_entry;
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_d = opendir(stats_dir);
        if (stats_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(stats_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                        }
                    }
                }
            }
            closedir(stats_d);
        }
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_d = opendir(visits_dir);
        if (visits_d) {
            struct dirent *file_entry;
            while ((file_entry = readdir(visits_d)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char file_date[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, file_date, sizeof(file_date)) != 0)
                    continue;
                
                u_int32_t file_date_ts = parse_date_string(file_date);
                if (file_date_ts > 0 && file_date_ts < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                    }
                }
            }
            closedir(visits_d);
        }
    }
    
    closedir(base_dir);
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_history_data_root_dir());
    
    DIR *global_stats_d = opendir(global_stats_dir);
    if (global_stats_d) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_d)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                u_int32_t file_date = parse_date_string(date_str);
                if (file_date > 0 && file_date < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", global_stats_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                    }
                }
            }
        }
        closedir(global_stats_d);
    }
    
    if (deleted_count > 0) {
        LOG_INFO("Cleaned up %d expired files (record_time: %d days)\n", deleted_count, record_time);
    }
}

void check_and_cleanup_history_data_by_size(void) {
    LOG_INFO("check_and_cleanup_history_data_by_size: start\n");

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx)
        return;
    
    char history_data_size[64] = {0};
    fwx_uci_get_value(uci_ctx, "fwx.record.history_data_size", history_data_size, sizeof(history_data_size));
    uci_free_context(uci_ctx);
    
    if (strlen(history_data_size) == 0) {
        return;
    }
    
    char *endptr = NULL;
    long max_size_mb = strtol(history_data_size, &endptr, 10);
    if (*endptr != '\0' || max_size_mb <= 0) {
        return;
    }

    char db_path[512] = {0};
    struct stat st = {0};
    unsigned long long old_size_bytes = 0;
    unsigned long long new_size_bytes = 0;
    unsigned long long max_size_bytes = ((unsigned long long)max_size_mb) * 1024ULL * 1024ULL;

    build_client_visit_db_path(db_path, sizeof(db_path));
    if (access(db_path, F_OK) != 0) {
        return;
    }

    if (stat(db_path, &st) != 0) {
        return;
    }

    old_size_bytes = (unsigned long long)st.st_size;
    if (old_size_bytes <= max_size_bytes) {
        return;
    }

    LOG_WARN("client.db cleanup begin: size=%llu bytes, limit=%llu bytes, over=%llu bytes\n",
             old_size_bytes, max_size_bytes, old_size_bytes - max_size_bytes);

    int current_record_count = get_visit_record_count();
    int cleanup_batch_count = 0;
    if (current_record_count > 0) {
        cleanup_batch_count = current_record_count / 4;
        if (cleanup_batch_count <= 0)
            cleanup_batch_count = 1;
    }

    if (cleanup_batch_count <= 0) {
        LOG_WARN("client.db cleanup skipped: invalid batch, record_count=%d\n", current_record_count);
        return;
    }

    int deleted_count = delete_oldest_visit_records_batch(cleanup_batch_count);
    if (deleted_count <= 0) {
        LOG_WARN("client.db exceeds limit but no records deleted: size=%llu bytes, limit=%llu bytes\n",
                 old_size_bytes, max_size_bytes);
        return;
    }

    if (stat(db_path, &st) == 0) {
        new_size_bytes = (unsigned long long)st.st_size;
    } else {
        new_size_bytes = old_size_bytes;
    }

    if (new_size_bytes > max_size_bytes) {
        unsigned long long before_vacuum_size = new_size_bytes;
        if (vacuum_visit_db_file() == 0) {
            if (stat(db_path, &st) == 0) {
                new_size_bytes = (unsigned long long)st.st_size;
            }
            LOG_WARN("client.db vacuum done: size=%llu->%llu bytes\n",
                     before_vacuum_size, new_size_bytes);
        } else {
            LOG_WARN("client.db vacuum failed\n");
        }
    }

    LOG_WARN("client.db cleanup end: deleted=%d, batch=%d, size=%llu->%llu bytes, reduced=%lld bytes, limit=%llu bytes\n",
             deleted_count, cleanup_batch_count, old_size_bytes, new_size_bytes,
             (long long)old_size_bytes - (long long)new_size_bytes, max_size_bytes);

    current_record_count = get_visit_record_count();
    LOG_WARN("client.db current record count: %d\n", current_record_count);
}

int get_timestamp(void)
{
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    return cur_time.tv_sec;
}




void add_visit_info_node(struct list_head *visit_list, visit_info_t *node)
{
    if (!visit_list || !node)
        return;


    list_add(&node->visit, visit_list);
}

static void normalize_mac_lower(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0;

    if (!dst || dst_len == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src) {
        return;
    }

    for (i = 0; i + 1 < dst_len && src[i] != '\0'; i++) {
        char c = src[i];
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
        dst[i] = c;
    }
    dst[i] = '\0';
}

void init_client_list(void)
{
    INIT_LIST_HEAD(&client_list);
    printf("init client list ok...\n");
}

client_node_t *add_client_node(char *mac)
{
	int j;
    client_node_t *node = NULL;
    client_node_t *exist = NULL;
    char mac_norm[MAX_MAC_LEN] = {0};
    u_int32_t now = get_timestamp();

    if (!mac || mac[0] == '\0') {
        return NULL;
    }
    normalize_mac_lower(mac, mac_norm, sizeof(mac_norm));
    exist = find_client_node(mac_norm);
    if (exist) {
        return exist;
    }

    node = (client_node_t *)calloc(1, sizeof(client_node_t));
    if (!node)
        return NULL;
    strncpy(node->mac, mac_norm, sizeof(node->mac) - 1);
    node->mac[sizeof(node->mac) - 1] = '\0';
    node->online = 0;
    node->online_time = now;
    node->offline_time = now;

    node->ipv6[0] = '\0';
    node->up_rate = 0;
    node->down_rate = 0;
    node->rssi = 0;
    node->rx_rate = 0;
    node->tx_rate = 0;
    node->band[0] = '\0';
    node->wifi_ifname[0] = '\0';
    node->is_wireless = 0;
    node->wireless_online = 0;
    node->active = 0;  
    node->last_online_state = 0;
    node->session_online_recorded = 0;
    reset_online_session_stat(node, now);

    INIT_LIST_HEAD(&node->online_visit);
    INIT_LIST_HEAD(&node->visit);

    INIT_LIST_HEAD(&node->stat_list);

    INIT_LIST_HEAD(&node->online_offline_records);

    INIT_LIST_HEAD(&node->client);

    u_int32_t today = get_today_start_timestamp();
    node->daily_stats.date = today;
    node->daily_stats.is_today = 1;
    for (j = 0; j < HOURS_PER_DAY; j++) {
        for (int k = 0; k < TOP_APP_PER_HOUR; k++) {
            node->daily_stats.hourly_top_apps[j][k] = -1;
        }
    }
    

    node->daily_top_apps_stats.date = today;
    node->daily_top_apps_stats.is_today = 1;
    node->daily_top_apps_stats.count = 0;
    for (j = 0; j < MAX_TOP_APPS_PER_DAY; j++) {
        node->daily_top_apps_stats.apps[j].appid = -1;
        node->daily_top_apps_stats.apps[j].total_time = 0;
    }

    list_add(&node->client, &client_list);
    g_cur_user_num++;
    printf("add mac:%s to client list....success\n", node->mac);
    return node;
}

client_node_t *find_client_node(const char *mac)
{
    client_node_t *p = NULL;
    char mac_norm[MAX_MAC_LEN] = {0};

    if (!mac || mac[0] == '\0') {
        return NULL;
    }
    normalize_mac_lower(mac, mac_norm, sizeof(mac_norm));
    
    list_for_each_entry(p, &client_list, client) {
        if (0 == strcasecmp(p->mac, mac_norm))
        {
            if (strncmp(p->mac, mac_norm, sizeof(p->mac)) != 0) {
                strncpy(p->mac, mac_norm, sizeof(p->mac) - 1);
                p->mac[sizeof(p->mac) - 1] = '\0';
            }
            return p;
        }
    }
    return NULL;
}

void client_foreach(void *arg, iter_func iter)
{
    client_node_t *node = NULL;
    int count = 0;

    LOG_DEBUG("client_foreach: Starting iteration over client_list...\n");
    list_for_each_entry(node, &client_list, client) {
        count++;
        LOG_DEBUG("client_foreach: Processing client[%d] - mac=%s, online=%d\n", 
               count, node->mac, node->online);
        iter(arg, node);
    }
    LOG_DEBUG("client_foreach: Finished iteration, processed %d clients\n", count);
}

char *format_time(int timetamp)
{
    char time_buf[64] = {0};
    time_t seconds = timetamp;
    struct tm *auth_tm = localtime(&seconds);
    strftime(time_buf, sizeof(time_buf), "%Y %m %d %H:%M:%S", auth_tm);
    return strdup(time_buf);
}

void update_client_hostname(void)
{
    char line_buf[256] = {0};
    char hostname_buf[128] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};

    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
    {
        printf("open dhcp lease file....failed\n");
        return;
    }
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        if (strlen(line_buf) <= 16)
            continue;
        sscanf(line_buf, "%*s %s %s %s", mac_buf, ip_buf, hostname_buf);
        client_node_t *node = find_client_node(mac_buf);
        if (!node)
        {
            node = add_client_node(mac_buf);
            strncpy(node->ip, ip_buf, sizeof(node->ip));
            node->online = 0;
            node->offline_time = get_timestamp();
        }

        if (strlen(hostname_buf) > 0 && hostname_buf[0] != '*')
        {
            strncpy(node->hostname, hostname_buf, sizeof(node->hostname));
        }
    }
    fclose(fp);
}

void clean_client_nickname_iter(void *arg, client_node_t *client)
{
    client->nickname[0] = '\0';
}

void clean_client_nickname(void)
{
    client_foreach(NULL, clean_client_nickname_iter);
}

void update_client_nickname(void)
{
	int i;
    char nickname_buf[128] = {0};
    char mac_str[128] = {0};
    struct uci_context *uci_ctx = uci_alloc_context();
    clean_client_nickname();
    int num = fwx_uci_get_list_num(uci_ctx, "user_info", "user_info");

    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str, sizeof(mac_str));
        client_node_t *node = find_client_node(mac_str);
        if (!node)
            continue;

        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].nickname", i, nickname_buf, sizeof(nickname_buf));
        strncpy(node->nickname, nickname_buf, sizeof(node->nickname));
    }   
    uci_free_context(uci_ctx);
}

static char *get_command_output(const char *cmd)
{
    FILE *fp = NULL;
    char *buf = NULL;
    size_t buf_size = 4096;
    size_t total_read = 0;
    size_t n_read = 0;

    if (!cmd || cmd[0] == '\0') {
        return NULL;
    }

    fp = popen(cmd, "r");
    if (!fp) {
        return NULL;
    }

    buf = (char *)calloc(1, buf_size);
    if (!buf) {
        pclose(fp);
        return NULL;
    }

    while (!feof(fp)) {
        size_t remain = buf_size - total_read - 1;
        if (remain < 512) {
            char *new_buf = NULL;
            buf_size *= 2;
            new_buf = (char *)realloc(buf, buf_size);
            if (!new_buf) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = new_buf;
            remain = buf_size - total_read - 1;
        }

        n_read = fread(buf + total_read, 1, remain, fp);
        total_read += n_read;

        if (ferror(fp)) {
            free(buf);
            pclose(fp);
            return NULL;
        }
    }

    pclose(fp);

    if (total_read == 0) {
        free(buf);
        return NULL;
    }

    buf[total_read] = '\0';
    return buf;
}

static struct json_object *get_command_json(const char *cmd)
{
    char *output = NULL;
    struct json_object *obj = NULL;

    output = get_command_output(cmd);
    if (!output) {
        return NULL;
    }

    obj = json_tokener_parse(output);
    free(output);
    return obj;
}

static void clear_client_wireless_status(void)
{
    client_node_t *node = NULL;

    list_for_each_entry(node, &client_list, client) {
        node->rssi = 0;
        node->rx_rate = 0;
        node->tx_rate = 0;
        node->band[0] = '\0';
        node->wifi_ifname[0] = '\0';
        node->wireless_online = 0;
    }
}

static client_node_t *find_client_node_nocase(const char *mac)
{
    client_node_t *node = NULL;

    if (!mac || mac[0] == '\0') {
        return NULL;
    }

    list_for_each_entry(node, &client_list, client) {
        if (strcasecmp(node->mac, mac) == 0) {
            return node;
        }
    }

    return NULL;
}

static unsigned int get_wireless_rate_value(struct json_object *rate_obj)
{
    struct json_object *rate_value_obj = NULL;
    long long rate = 0;

    if (!rate_obj || json_object_get_type(rate_obj) != json_type_object) {
        return 0;
    }

    if (!json_object_object_get_ex(rate_obj, "rate", &rate_value_obj) || !rate_value_obj) {
        return 0;
    }

    rate = json_object_get_int64(rate_value_obj);
    if (rate <= 0) {
        return 0;
    }

    if ((unsigned long long)rate > UINT_MAX) {
        return UINT_MAX;
    }

    return (unsigned int)rate;
}

static void append_wireless_ifname(char ifnames[][MAX_WIRELESS_IFNAME_LEN], char bands[][MAX_WIRELESS_BAND_LEN], int *if_num, int max_if_num, const char *ifname, const char *band)
{
    int i;

    if (!ifnames || !bands || !if_num || !ifname || ifname[0] == '\0') {
        return;
    }

    for (i = 0; i < *if_num; i++) {
        if (strcmp(ifnames[i], ifname) == 0) {
            if (bands[i][0] == '\0' && band && band[0] != '\0') {
                snprintf(bands[i], MAX_WIRELESS_BAND_LEN, "%s", band);
            }
            return;
        }
    }

    if (*if_num >= max_if_num) {
        return;
    }

    snprintf(ifnames[*if_num], MAX_WIRELESS_IFNAME_LEN, "%s", ifname);
    if (band && band[0] != '\0') {
        snprintf(bands[*if_num], MAX_WIRELESS_BAND_LEN, "%s", band);
    } else {
        bands[*if_num][0] = '\0';
    }
    (*if_num)++;
}

static int collect_wireless_ifnames(char ifnames[][MAX_WIRELESS_IFNAME_LEN], char bands[][MAX_WIRELESS_BAND_LEN], int max_if_num)
{
    int if_num = 0;
    struct json_object *status_obj = NULL;

    status_obj = get_command_json("ubus call network.wireless status 2>/dev/null");
    if (!status_obj) {
        return 0;
    }

    json_object_object_foreach(status_obj, radio_name, radio_obj) {
        char radio_band[MAX_WIRELESS_BAND_LEN] = {0};
        struct json_object *config_obj = NULL;
        struct json_object *band_obj = NULL;
        struct json_object *interfaces_obj = NULL;
        int i;

        (void)radio_name;

        if (!radio_obj || json_object_get_type(radio_obj) != json_type_object) {
            continue;
        }

        if (json_object_object_get_ex(radio_obj, "config", &config_obj) &&
            config_obj && json_object_get_type(config_obj) == json_type_object &&
            json_object_object_get_ex(config_obj, "band", &band_obj) && band_obj) {
            snprintf(radio_band, sizeof(radio_band), "%s", json_object_get_string(band_obj));
        } else if (json_object_object_get_ex(radio_obj, "band", &band_obj) && band_obj) {
            snprintf(radio_band, sizeof(radio_band), "%s", json_object_get_string(band_obj));
        }

        if (!json_object_object_get_ex(radio_obj, "interfaces", &interfaces_obj) ||
            !interfaces_obj || json_object_get_type(interfaces_obj) != json_type_array) {
            continue;
        }

        for (i = 0; i < json_object_array_length(interfaces_obj); i++) {
            struct json_object *iface_obj = json_object_array_get_idx(interfaces_obj, i);
            struct json_object *ifname_obj = NULL;
            struct json_object *vlans_obj = NULL;
            int j;

            if (!iface_obj || json_object_get_type(iface_obj) != json_type_object) {
                continue;
            }

            if (json_object_object_get_ex(iface_obj, "ifname", &ifname_obj) && ifname_obj) {
                append_wireless_ifname(ifnames, bands, &if_num, max_if_num, json_object_get_string(ifname_obj), radio_band);
            }

            if (!json_object_object_get_ex(iface_obj, "vlans", &vlans_obj) ||
                !vlans_obj || json_object_get_type(vlans_obj) != json_type_array) {
                continue;
            }

            for (j = 0; j < json_object_array_length(vlans_obj); j++) {
                struct json_object *vlan_obj = json_object_array_get_idx(vlans_obj, j);
                struct json_object *vlan_ifname_obj = NULL;

                if (!vlan_obj || json_object_get_type(vlan_obj) != json_type_object) {
                    continue;
                }

                if (json_object_object_get_ex(vlan_obj, "ifname", &vlan_ifname_obj) && vlan_ifname_obj) {
                    append_wireless_ifname(ifnames, bands, &if_num, max_if_num, json_object_get_string(vlan_ifname_obj), radio_band);
                }
            }
        }
    }

    json_object_put(status_obj);
    return if_num;
}

static void update_client_wireless_status_by_ifname(const char *ifname, const char *band)
{
    char cmd[256] = {0};
    struct json_object *assoc_obj = NULL;
    struct json_object *results_obj = NULL;
    int i;

    if (!ifname || ifname[0] == '\0') {
        return;
    }

    snprintf(cmd, sizeof(cmd), "ubus call iwinfo assoclist '{\"device\":\"%s\"}' 2>/dev/null", ifname);
    assoc_obj = get_command_json(cmd);
    if (!assoc_obj) {
        return;
    }

    if (!json_object_object_get_ex(assoc_obj, "results", &results_obj) || !results_obj) {
        if (json_object_get_type(assoc_obj) == json_type_array) {
            results_obj = assoc_obj;
        }
    }

    if (!results_obj || json_object_get_type(results_obj) != json_type_array) {
        json_object_put(assoc_obj);
        return;
    }

    for (i = 0; i < json_object_array_length(results_obj); i++) {
        struct json_object *station_obj = json_object_array_get_idx(results_obj, i);
        struct json_object *mac_obj = NULL;
        struct json_object *signal_obj = NULL;
        struct json_object *rx_obj = NULL;
        struct json_object *tx_obj = NULL;
        client_node_t *node = NULL;
        const char *mac = NULL;

        if (!station_obj || json_object_get_type(station_obj) != json_type_object) {
            continue;
        }

        if (!json_object_object_get_ex(station_obj, "mac", &mac_obj) || !mac_obj) {
            continue;
        }

        mac = json_object_get_string(mac_obj);
        if (!mac || mac[0] == '\0') {
            continue;
        }

        node = find_client_node_nocase(mac);
        if (!node) {
            char mac_buf[MAX_MAC_LEN] = {0};
            snprintf(mac_buf, sizeof(mac_buf), "%s", mac);
            node = add_client_node(mac_buf);
            if (!node) {
                continue;
            }
        }

        if (json_object_object_get_ex(station_obj, "signal", &signal_obj) && signal_obj) {
            node->rssi = json_object_get_int(signal_obj);
        } else if (json_object_object_get_ex(station_obj, "signal_avg", &signal_obj) && signal_obj) {
            node->rssi = json_object_get_int(signal_obj);
        } else {
            node->rssi = 0;
        }

        if (json_object_object_get_ex(station_obj, "rx", &rx_obj) && rx_obj) {
            node->rx_rate = get_wireless_rate_value(rx_obj);
        }

        if (json_object_object_get_ex(station_obj, "tx", &tx_obj) && tx_obj) {
            node->tx_rate = get_wireless_rate_value(tx_obj);
        }

        if (band && band[0] != '\0') {
            snprintf(node->band, sizeof(node->band), "%s", band);
        }
        snprintf(node->wifi_ifname, sizeof(node->wifi_ifname), "%s", ifname);
        node->is_wireless = 1;
        node->wireless_online = 1;
    }

    json_object_put(assoc_obj);
}

void refresh_client_wireless_status(void)
{
    char ifnames[MAX_WIRELESS_IFACE_NUM][MAX_WIRELESS_IFNAME_LEN] = {{0}};
    char bands[MAX_WIRELESS_IFACE_NUM][MAX_WIRELESS_BAND_LEN] = {{0}};
    int if_num = 0;
    int i;

    clear_client_wireless_status();

    if (!g_fwx_capability.wireless_support) {
        return;
    }

    if_num = collect_wireless_ifnames(ifnames, bands, MAX_WIRELESS_IFACE_NUM);
    LOG_DEBUG("refresh_client_wireless_status: if_num=%d\n", if_num);
    for (i = 0; i < if_num; i++) {
        update_client_wireless_status_by_ifname(ifnames[i], bands[i]);
    }
}



void clean_client_online_status(void)
{
    client_node_t *node = NULL;

    list_for_each_entry(node, &client_list, client) {
        node->last_online_state = node->online;
        node->active = 0;
        if (node->online)
        {
            node->offline_time = get_timestamp();
            node->online = 0;
        }
    }
}


void update_client_from_kernel(void)
{
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};
    char ipv6_buf[128] = {0};
    unsigned int status = 1;
    unsigned int up_rate = 0;
    unsigned int down_rate = 0;

    FILE *fp = fopen("/proc/net/af_client", "r");
    if (!fp)
    {
        printf("open client file....failed\n");
        return;
    }
    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        int id;
        int parsed = 0;
        int has_status = 0;

        status = 1;
        up_rate = 0;
        down_rate = 0;

        parsed = sscanf(line_buf, "%d %31s %31s %127s %*u %u %u %u",
                        &id, mac_buf, ip_buf, ipv6_buf, &status, &up_rate, &down_rate);
        if (parsed == 7) {
            has_status = 1;
        } else {
            parsed = sscanf(line_buf, "%d %31s %31s %127s %*u %u %u",
                            &id, mac_buf, ip_buf, ipv6_buf, &up_rate, &down_rate);
            if (parsed == 6) {
                has_status = 0;
                status = 1;
            } else {
                parsed = sscanf(line_buf, "%d %31s %31s %127s %u %u",
                                &id, mac_buf, ip_buf, ipv6_buf, &up_rate, &down_rate);
                if (parsed == 6) {
                    has_status = 0;
                    status = 1;
                }
            }
        }
        LOG_DEBUG("update_client_from_kernel: parsed = %d, line_buf = %s\n", parsed, line_buf);
        if (parsed < 3) 
        {
            printf("invalid line format:%s\n", line_buf);
            continue;
        }
        if (strlen(mac_buf) < 17)
        {
            printf("invalid mac:%s\n", mac_buf);
            continue;
        }
        client_node_t *node = find_client_node(mac_buf);
        if (!node)
        {
            node = add_client_node(mac_buf);
            if (!node)
                continue;
            strncpy(node->ip, ip_buf, sizeof(node->ip));
        }

        strncpy(node->ip, ip_buf, sizeof(node->ip));

        if (parsed >= 4 && strlen(ipv6_buf) > 0)
        {
            strncpy(node->ipv6, ipv6_buf, sizeof(node->ipv6));
            LOG_DEBUG("update_client_from_kernel: ipv6 = %s\n", ipv6_buf);
        }
        else
        {
            node->ipv6[0] = '\0'; 
        }

        if (parsed >= 5)
        {
            node->up_rate = up_rate;
            LOG_DEBUG("update_client_from_kernel: up_rate = %d\n", up_rate);
        }
        else
        {
            node->up_rate = 0;
            LOG_DEBUG("update_client_from_kernel: up_rate = 0\n");
        }
        if (parsed >= 6)
        {
            node->down_rate = down_rate;
            LOG_DEBUG("update_client_from_kernel: down_rate = %d\n", down_rate);
        }
        else
        {
            node->down_rate = 0;
        }
        node->online = 1;
        if (has_status) {
            node->active = (status >= 2) ? 1 : 0;
        }
    }
    fclose(fp);
}

void update_client_online_status(void)
{
    int now = get_timestamp();
    int work_mode = 0;
    int is_bypass_mode = 0;
    client_node_t *node = NULL;
    struct uci_context *uci_ctx = uci_alloc_context();

    if (uci_ctx) {
        work_mode = fwx_uci_get_int_value(uci_ctx, "fwx.network.work_mode");
        if (work_mode != 0 && work_mode != 1) {
            work_mode = 0;
        }
        uci_free_context(uci_ctx);
    }
    is_bypass_mode = (work_mode == 1);

    update_client_from_kernel();
    refresh_client_wireless_status();
    list_for_each_entry(node, &client_list, client) {
        if (!node->is_wireless) {
            continue;
        }
        if (node->wireless_online) {
            node->online = 1;
        } else {
            node->online = 0;
            node->active = 0;
        }
    }
    list_for_each_entry(node, &client_list, client) {
        int was_online = node->last_online_state;
        int is_online = node->online;
        if (!was_online && is_online) {
            node->online_time = now;
            reset_online_session_stat(node, now);
            node->session_online_recorded = 0;
        } else if (was_online && !is_online) {
            node->offline_time = now;
            if (node->session_online_recorded) {
                add_user_record(node, 1, now);
            }
            node->session_online_recorded = 0;
            save_client_backup_to_file(node);
        } else if (is_online && !node->session_online_recorded &&
                   (is_bypass_mode || node->active)) {
            add_user_record(node, 0, now);
            node->session_online_recorded = 1;
        }
        node->last_online_state = is_online;
    }
}

#define CLIENT_OFFLINE_TIME (SECONDS_PER_DAY * 3)

int check_client_expire(void)
{
    int count = 0;
    int cur_time = get_timestamp();
    int offline_time = 0;
    int expire_count = 0;
    int visit_count = 0;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;

    list_for_each_entry(node, &client_list, client) {
        if (node->online)
            continue;
        visit_count = 0;
        offline_time = cur_time - node->offline_time;
        if (offline_time > CLIENT_OFFLINE_TIME)
        {
            node->expire = 1;
            list_for_each_entry(p_info, &node->visit, visit) {
                p_info->expire = 1;
                visit_count++;
            }
            expire_count++;
            LOG_WARN("client:%s expired, offline time = %ds, count=%d, visit_count=%d\n",
                   node->mac, offline_time, expire_count, visit_count);
        }
    }
    return expire_count;
}

void flush_expire_client_node(void)
{
    int count = 0;
    client_node_t *node = NULL, *tmp = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;
    visit_stat_t *stat_node = NULL, *tmp_stat_node = NULL;

    list_for_each_entry_safe(node, tmp, &client_list, client) {
        if (node->expire)
        {
            list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {
                list_del(&p_info->visit);
                free(p_info);
            }

            list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
                list_del(&p_info->visit);
                free(p_info);
            }

            list_for_each_entry_safe(stat_node, tmp_stat_node, &node->stat_list, list) {
                list_del(&stat_node->list);
                free(stat_node);
            }
            list_del(&node->client);
            free(node);
            count++;
            g_cur_user_num--;
        }
    }
}

#define ONLINE_VISIT_TIMEOUT_SEC 300

void move_expired_online_visit_to_offline(void)
{
    int cur_time = get_timestamp();
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {
        list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {
            int diff = cur_time - (int)p_info->latest_time;
            LOG_INFO("move_expired_online_visit_to_offline: mac = %s, diff = %d\n", node->mac, diff);
            if (diff > ONLINE_VISIT_TIMEOUT_SEC) {
                list_del(&p_info->visit);
                LOG_INFO("move_expired_online_visit_to_offline: mac = %s, appid = %d, action = %d, first_time = %d, latest_time = %d\n", node->mac, p_info->appid, p_info->action, p_info->first_time, p_info->latest_time);
                

                int total_time = p_info->latest_time - p_info->first_time;
                if (total_time < g_app_valid_time) {
                    LOG_DEBUG("Discard visit record (too short): mac=%s, appid=%d, duration=%ds < %ds\n", 
                              node->mac, p_info->appid, total_time, g_app_valid_time);
                    free(p_info); 
                } else {
                    p_info->expire = 0;
                    add_visit_info_node(&node->visit, p_info);
                    save_visit_record_to_db(node->mac, p_info);
                }
            }
        }
    }
}

static int is_invalid_visit_url(const char *url)
{
    if (!url || url[0] == '\0') {
        return 1;
    }
    if (strcasecmp(url, "none") == 0 ||
        strcasecmp(url, "undefined") == 0 ||
        strcasecmp(url, "null") == 0) {
        return 1;
    }
    return 0;
}

void update_client_visiting_info(void){
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char url_buf[MAX_REPORT_URL_LEN] = {0};
    char app_buf[32] = {0};

    FILE *fp = fopen("/proc/net/af_visit", "r");    
    if (!fp)
    {
        printf("open af_visit file....failed\n");
        return;
    }
    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))   
    {
        memset(mac_buf, 0, sizeof(mac_buf));
        memset(app_buf, 0, sizeof(app_buf));
        memset(url_buf, 0, sizeof(url_buf));
        if (sscanf(line_buf, "%31s %31s %63s", mac_buf, app_buf, url_buf) != 3) {
            continue;
        }
        client_node_t *node = find_client_node(mac_buf);
        if (!node)
            continue;
        if (is_invalid_visit_url(url_buf)) {
            node->visiting_url[0] = '\0';
        }
        else {
            strncpy(node->visiting_url, url_buf, sizeof(node->visiting_url) - 1);
            node->visiting_url[sizeof(node->visiting_url) - 1] = '\0';
        }
        node->visiting_app = atoi(app_buf);
    }
    fclose(fp);
}

void update_client_list(void)
{
    clean_client_online_status();
    update_client_hostname();
    update_client_nickname();
    update_client_online_status();
    update_client_visiting_info();
}


void dump_client_list(void)
{
    int count = 0;
    char hostname_buf[MAX_HOSTNAME_SIZE] = {0};
    char ip_buf[MAX_IP_LEN] = {0};

    FILE *fp = fopen(OAF_DEV_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }
  
    fprintf(fp, "%-4s %-20s %-20s %-32s %-8s %-12s %-12s\n", 
            "Id", "Mac Addr", "Ip Addr", "Hostname", "Online", "OnlineTime", "OfflineTime");
    

    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (node->online != 0)
        {
            if (strlen(node->hostname) == 0)
                strcpy(hostname_buf, "*");
            else
                strcpy(hostname_buf, node->hostname);
            if (strlen(node->ip) == 0)
                strcpy(ip_buf, "*");
            else
                strcpy(ip_buf, node->ip);
            fprintf(fp, "%-4d %-20s %-20s %-32s %-8d %-12u %-12u\n",
                    count + 1, node->mac, ip_buf, hostname_buf, node->online, 
                    node->online_time, node->offline_time);
            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto EXIT;
        }
    }
    

    list_for_each_entry(node, &client_list, client) {
        if (node->online == 0)
        {
            if (strlen(node->hostname) == 0)
                strcpy(hostname_buf, "*");
            else
                strcpy(hostname_buf, node->hostname);

            if (strlen(node->ip) == 0)
                strcpy(ip_buf, "*");
            else
                strcpy(ip_buf, node->ip);

            fprintf(fp, "%-4d %-20s %-20s %-32s %-8d %-12u %-12u\n",
                    count + 1, node->mac, ip_buf, hostname_buf, node->online,
                    node->online_time, node->offline_time);
            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto EXIT;
        }
    }
EXIT:
    fclose(fp);
}


#define MAX_RECORD_TIME (3 * 24 * 60 * 60) // 7day

#define RECORD_REMAIN_TIME (24 * 60 * 60) // 1day
#define INVALID_RECORD_TIME (5 * 60)      // 5min

void check_client_visit_info_expire(void)
{
    int count = 0;
    int cur_time = get_timestamp();
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            int total_time = p_info->latest_time - p_info->first_time;
            int interval_time = cur_time - p_info->first_time;
            if (interval_time > MAX_RECORD_TIME || interval_time < 0)
            {
                p_info->expire = 1;
            }
            else if (interval_time > RECORD_REMAIN_TIME)
            {
                if (total_time < INVALID_RECORD_TIME)
                    p_info->expire = 1;
            }
        }
    }
}

void flush_expire_visit_info(void)
{
    int count = 0;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL, *tmp_info = NULL;

    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            if (p_info->expire)
            {
                list_del(&p_info->visit);
                free(p_info);
                count++;
            }
        }
    }
}

void dump_client_visit_list(void)
{
    int count = 0;
    FILE *fp = fopen(OAF_VISIT_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }

    fprintf(fp, "%-4s %-20s %-20s %-8s %-32s %-32s %-32s %-8s\n", "Id", "Mac Addr",
            "Ip Addr", "Appid", "First Time", "Latest Time", "Total Time(s)", "Expire");
    
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;
    list_for_each_entry(node, &client_list, client) {

        list_for_each_entry(p_info, &node->visit, visit) {
            char *first_time_str = format_time(p_info->first_time);
            char *latest_time_str = format_time(p_info->latest_time);
            int total_time = p_info->latest_time - p_info->first_time;
            fprintf(fp, "%-4d %-20s %-20s %-8d %-32s %-32s %-32d %-4d\n",
                    count, node->mac, node->ip, p_info->appid, first_time_str,
                    latest_time_str, total_time, p_info->expire);
            if (first_time_str)
                free(first_time_str);
            if (latest_time_str)
                free(latest_time_str);
            count++;
            if (count > 50)
                goto EXIT;
        }
    }
EXIT:
    fclose(fp);
}


typedef struct app_hour_stat {
    int appid;
    unsigned long long total_time;
} app_hour_stat_t;


static int compare_app_stat(const void *a, const void *b) {
    app_hour_stat_t *pa = (app_hour_stat_t *)a;
    app_hour_stat_t *pb = (app_hour_stat_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


int get_hour_from_timestamp(u_int32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info)
        return -1;
    return tm_info->tm_hour;
}

static u_int32_t get_next_hour_timestamp(u_int32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        return timestamp + 3600;
    }

    struct tm next_hour = *tm_info;
    next_hour.tm_min = 0;
    next_hour.tm_sec = 0;
    next_hour.tm_hour += 1;

    time_t next_ts = mktime(&next_hour);
    if (next_ts <= (time_t)timestamp) {
        return timestamp + 3600;
    }
    return (u_int32_t)next_ts;
}

unsigned long long get_visit_duration_in_hour(visit_info_t *visit, int target_hour) {
    u_int32_t start;
    u_int32_t end;
    u_int32_t cursor;
    unsigned long long total = 0;

    if (!visit || target_hour < 0 || target_hour >= HOURS_PER_DAY) {
        return 0;
    }

    start = visit->first_time;
    end = visit->latest_time;
    if (end <= start) {
        int hour = get_hour_from_timestamp(start);
        return (hour == target_hour) ? 1 : 0;
    }

    cursor = start;
    while (cursor < end) {
        int hour = get_hour_from_timestamp(cursor);
        u_int32_t next_hour = get_next_hour_timestamp(cursor);
        u_int32_t segment_end = end < next_hour ? end : next_hour;
        unsigned long long segment_duration = (unsigned long long)(segment_end - cursor);

        if (segment_duration == 0) {
            segment_duration = 1;
        }

        if (hour == target_hour) {
            total += segment_duration;
        }
        cursor = segment_end;
    }

    return total;
}

static void add_app_duration_to_hour_stats(
    app_hour_stat_t hour_stats[HOURS_PER_DAY][MAX_APP_STAT_NUM],
    int hour_count[HOURS_PER_DAY],
    int hour,
    int appid,
    unsigned long long duration) {
    int i;
    int found = 0;

    if (hour < 0 || hour >= HOURS_PER_DAY || appid <= 0 || duration == 0) {
        return;
    }

    for (i = 0; i < hour_count[hour]; i++) {
        if (hour_stats[hour][i].appid == appid) {
            hour_stats[hour][i].total_time += duration;
            if (hour_stats[hour][i].total_time > 3600ULL) {
                hour_stats[hour][i].total_time = 3600ULL;
            }
            found = 1;
            break;
        }
    }

    if (!found && hour_count[hour] < MAX_APP_STAT_NUM) {
        hour_stats[hour][hour_count[hour]].appid = appid;
        hour_stats[hour][hour_count[hour]].total_time = duration;
        if (hour_stats[hour][hour_count[hour]].total_time > 3600ULL) {
            hour_stats[hour][hour_count[hour]].total_time = 3600ULL;
        }
        hour_count[hour]++;
    } else if (!found && hour_count[hour] >= MAX_APP_STAT_NUM) {
        int min_idx = 0;
        unsigned long long min_time = hour_stats[hour][0].total_time;

        for (i = 1; i < MAX_APP_STAT_NUM; i++) {
            if (hour_stats[hour][i].total_time < min_time) {
                min_time = hour_stats[hour][i].total_time;
                min_idx = i;
            }
        }

        if (duration > min_time) {
            hour_stats[hour][min_idx].appid = appid;
            hour_stats[hour][min_idx].total_time = duration;
            if (hour_stats[hour][min_idx].total_time > 3600ULL) {
                hour_stats[hour][min_idx].total_time = 3600ULL;
            }
        }
    }
}

static void accumulate_visit_to_hour_stats(
    app_hour_stat_t hour_stats[HOURS_PER_DAY][MAX_APP_STAT_NUM],
    int hour_count[HOURS_PER_DAY],
    visit_info_t *visit) {
    u_int32_t start;
    u_int32_t end;
    u_int32_t cursor;

    if (!visit || visit->appid <= 0) {
        return;
    }

    start = visit->first_time;
    end = visit->latest_time;

    if (end <= start) {
        int hour = get_hour_from_timestamp(start);
        add_app_duration_to_hour_stats(hour_stats, hour_count, hour, visit->appid, 1);
        return;
    }

    cursor = start;
    while (cursor < end) {
        int hour = get_hour_from_timestamp(cursor);
        u_int32_t next_hour = get_next_hour_timestamp(cursor);
        u_int32_t segment_end = end < next_hour ? end : next_hour;
        unsigned long long segment_duration = (unsigned long long)(segment_end - cursor);

        if (segment_duration == 0) {
            segment_duration = 1;
        }

        add_app_duration_to_hour_stats(hour_stats, hour_count, hour, visit->appid, segment_duration);
        cursor = segment_end;
    }
}


static int is_same_day(u_int32_t timestamp1, u_int32_t timestamp2) {
    time_t t1 = (time_t)timestamp1;
    time_t t2 = (time_t)timestamp2;
    struct tm *tm1 = localtime(&t1);
    struct tm *tm2 = localtime(&t2);
    if (!tm1 || !tm2)
        return 0;
    return (tm1->tm_year == tm2->tm_year &&
            tm1->tm_mon == tm2->tm_mon &&
            tm1->tm_mday == tm2->tm_mday);
}


u_int32_t get_today_start_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info)
        return 0;
    tm_info->tm_hour = 0;
    tm_info->tm_min = 0;
    tm_info->tm_sec = 0;
    return (u_int32_t)mktime(tm_info);
}


daily_hourly_stat_t *get_today_stat(client_node_t *client) {
	int i, j;
    if (!client)
        return NULL;
    
    u_int32_t today = get_today_start_timestamp();
    
    
    if (client->daily_stats.date == today && client->daily_stats.is_today == 1) {
        return &client->daily_stats;
    }
    
    
    if (client->daily_stats.date != 0 && client->daily_stats.date != today) {
        save_daily_stats_to_file(client, client->daily_stats.date);
    }
    
    
    client->daily_stats.date = today;
    client->daily_stats.is_today = 1;
    for (i = 0; i < HOURS_PER_DAY; i++) {
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            client->daily_stats.hourly_top_apps[i][j] = -1;
        }
        
        client->daily_stats.hourly_traffic[i].up_bytes = 0;
        client->daily_stats.hourly_traffic[i].down_bytes = 0;
        client->daily_stats.hourly_online_time[i] = 0;
        client->daily_stats.hourly_active_time[i] = 0;
    }
    
    return &client->daily_stats;
}


daily_hourly_stat_t *load_history_stat_from_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return NULL;
    
    
    
    return NULL;
}


void update_hourly_top_apps(client_node_t *client) {
    if (!client)
        return;

    
    daily_hourly_stat_t *today_stat = get_today_stat(client);
    if (!today_stat)
        return;

    int cur_time = get_timestamp();
    app_hour_stat_t hour_stats[HOURS_PER_DAY][MAX_APP_STAT_NUM];
    int hour_count[HOURS_PER_DAY] = {0};
    int i, j;

    
    for (i = 0; i < HOURS_PER_DAY; i++) {
        hour_count[i] = 0;
        for (j = 0; j < MAX_APP_STAT_NUM; j++) {
            hour_stats[i][j].appid = -1;
            hour_stats[i][j].total_time = 0;
        }
    }

    
    visit_info_t *p_info = NULL;
    list_for_each_entry(p_info, &client->online_visit, visit) {
        if (!is_same_day(p_info->first_time, cur_time))
            continue;
        accumulate_visit_to_hour_stats(hour_stats, hour_count, p_info);
    }

    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (!is_same_day(p_info->first_time, cur_time))
            continue;
        accumulate_visit_to_hour_stats(hour_stats, hour_count, p_info);
    }

    
    for (i = 0; i < HOURS_PER_DAY; i++) {
        
        for (j = 0; j < TOP_APP_PER_HOUR; j++) {
            today_stat->hourly_top_apps[i][j] = -1;
        }

        if (hour_count[i] == 0)
            continue;

        
        qsort(hour_stats[i], hour_count[i], sizeof(app_hour_stat_t), compare_app_stat);

        
        int top_count = (hour_count[i] < TOP_APP_PER_HOUR) ? hour_count[i] : TOP_APP_PER_HOUR;
        for (j = 0; j < top_count; j++) {
            if (hour_stats[i][j].appid > 0 && hour_stats[i][j].total_time > 0) {
                today_stat->hourly_top_apps[i][j] = hour_stats[i][j].appid;
            }
        }
    }
}


void get_hourly_top_apps(client_node_t *client, int hour, int *appids, int max_count) {

	int i;
    if (!client || !appids || hour < 0 || hour >= HOURS_PER_DAY || max_count <= 0)
        return;

    daily_hourly_stat_t *today_stat = get_today_stat(client);
    if (!today_stat)
        return;

    int count = (max_count < TOP_APP_PER_HOUR) ? max_count : TOP_APP_PER_HOUR;
    for (i = 0; i < count; i++) {
        appids[i] = today_stat->hourly_top_apps[hour][i];
    }
    
    for (i = count; i < max_count; i++) {
        appids[i] = -1;
    }
}


void save_daily_stats_to_file(client_node_t *client, u_int32_t date) {
	int i;
	int hour;
    if (!client)
        return;
    
    daily_hourly_stat_t *stat = &client->daily_stats;
    if (stat->date != date) {
        char date_str[32] = {0};
        char stat_date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        get_date_string(stat->date, stat_date_str, sizeof(stat_date_str));
        LOG_DEBUG("Date mismatch for client %s hourly stats: requested %s, but stat date is %s, skip saving\n", 
                 client->mac, date_str, stat_date_str);
        return;  
    }
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s hourly stats (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/hourly_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    
    
    struct json_object *hourly_array = json_object_new_array();
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        struct json_object *apps_array = json_object_new_array();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
        
        for (i = 0; i < TOP_APP_PER_HOUR; i++) {
            if (stat->hourly_top_apps[hour][i] > 0) {
                struct json_object *app_obj = json_object_new_object();
                json_object_object_add(app_obj, "appid", json_object_new_int(stat->hourly_top_apps[hour][i]));
                if (!app_icon_exists_by_id(stat->hourly_top_apps[hour][i]))
                    json_object_object_add(app_obj, "icon", json_object_new_int(0));
                const char *app_name = get_app_name_by_id(stat->hourly_top_apps[hour][i]);
                if (app_name) {
                    json_object_object_add(app_obj, "name", json_object_new_string(app_name));
                }
                json_object_array_add(apps_array, app_obj);
            }
        }
        
        json_object_object_add(hour_obj, "apps", apps_array);
        
        
        struct json_object *traffic_obj = json_object_new_object();
        json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(stat->hourly_traffic[hour].up_bytes));
        json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(stat->hourly_traffic[hour].down_bytes));
        json_object_object_add(hour_obj, "traffic", traffic_obj);
        
        
        json_object_object_add(hour_obj, "online_time", json_object_new_int64(stat->hourly_online_time[hour]));
        json_object_object_add(hour_obj, "active_time", json_object_new_int64(stat->hourly_active_time[hour]));
        
        json_object_array_add(hourly_array, hour_obj);
    }
    
    json_object_object_add(json_obj, "hourly_stats", hourly_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved daily hourly stats for client %s (date: %s) to %s\n", 
                 client->mac, date_str, file_path);
    } else {
        LOG_ERROR("Failed to save daily stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


static u_int32_t get_today_start_timestamp_from_ts(u_int32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info)
        return 0;
    
    struct tm tm_day_start = *tm_info;
    tm_day_start.tm_hour = 0;
    tm_day_start.tm_min = 0;
    tm_day_start.tm_sec = 0;
    
    return (u_int32_t)mktime(&tm_day_start);
}


void add_online_offline_record(client_node_t *client, int type, u_int32_t timestamp, unsigned long long duration) {
    if (!client)
        return;
    
    online_offline_record_t *record = (online_offline_record_t *)calloc(1, sizeof(online_offline_record_t));
    if (!record) {
        LOG_ERROR("Failed to allocate memory for online_offline_record\n");
        return;
    }
    
    record->type = type;
    record->timestamp = timestamp;
    record->duration = duration;
    

    list_add(&record->record, &client->online_offline_records);
    
    LOG_DEBUG("Added %s record for client %s at timestamp %u, duration: %llu seconds\n",
             type == 0 ? "online" : "offline", client->mac, timestamp, duration);
}


void save_online_offline_records_to_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return;
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s online_offline records (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/online_offline_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    
    
    struct json_object *records_array = json_object_new_array();
    online_offline_record_t *record = NULL;
    u_int32_t date_end = date + SECONDS_PER_DAY - 1;
    
    
    list_for_each_entry(record, &client->online_offline_records, record) {
        
        if (record->timestamp >= date && record->timestamp <= date_end) {
            struct json_object *record_obj = json_object_new_object();
            json_object_object_add(record_obj, "type", json_object_new_int(record->type));
            json_object_object_add(record_obj, "timestamp", json_object_new_int64(record->timestamp));
            json_object_object_add(record_obj, "duration", json_object_new_int64(record->duration));
            json_object_array_add(records_array, record_obj);
        }
    }
    
    json_object_object_add(json_obj, "records", records_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved online_offline records for client %s (date: %s) to %s\n", 
                 client->mac, date_str, file_path);
    } else {
        LOG_ERROR("Failed to save online_offline records to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


void archive_and_save_online_offline_records(void) {
    client_node_t *client = NULL;
    u_int32_t today = get_today_start_timestamp();
    
    list_for_each_entry(client, &client_list, client) {
        
        online_offline_record_t *record = NULL;
        u_int32_t oldest_date = 0;
        
        
        list_for_each_entry(record, &client->online_offline_records, record) {
            u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
            if (oldest_date == 0 || record_date < oldest_date) {
                oldest_date = record_date;
            }
        }
        
        
        if (oldest_date != 0 && oldest_date < today) {
            
            for (u_int32_t date = oldest_date; date < today; date += SECONDS_PER_DAY) {
                
                int has_records = 0;
                list_for_each_entry(record, &client->online_offline_records, record) {
                    u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
                    if (record_date == date) {
                        has_records = 1;
                        break;
                    }
                }
                
                if (has_records) {
                    save_online_offline_records_to_file(client, date);
                }
            }
            
            
            struct list_head *pos, *n;
            list_for_each_safe(pos, n, &client->online_offline_records) {
                record = list_entry(pos, online_offline_record_t, record);
                u_int32_t record_date = get_today_start_timestamp_from_ts(record->timestamp);
                if (record_date < today) {
                    list_del(pos);
                    free(record);
                }
            }
        }
    }
}


void save_global_traffic_stats_to_file(u_int32_t date) {
    char date_str[32] = {0};
	int hour;
    get_date_string(date, date_str, sizeof(date_str));
    
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_history_data_root_dir());
    
    if (ensure_dir_exists(global_stats_dir) != 0) {
        LOG_ERROR("Failed to create global stats directory %s for traffic stats (date: %s)\n", 
                  global_stats_dir, date_str);
        return;
    }
    
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/traffic_%s.json", global_stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    
    
    struct json_object *hourly_array = json_object_new_array();
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
        
        
        struct json_object *traffic_obj = json_object_new_object();
        json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(g_global_hourly_traffic[hour].up_bytes));
        json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(g_global_hourly_traffic[hour].down_bytes));
        json_object_object_add(hour_obj, "traffic", traffic_obj);
        
        json_object_array_add(hourly_array, hour_obj);
    }
    
    json_object_object_add(json_obj, "hourly_traffic", hourly_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        LOG_DEBUG("Saved global traffic stats (date: %s) to %s\n", date_str, file_path);
    } else {
        LOG_ERROR("Failed to save global traffic stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}



void check_and_archive_all_clients(void) {
	int i, j;
    client_node_t *node = NULL;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info){
        LOG_ERROR("Failed to get local time\n");
        return;
    }
    
    u_int32_t today = get_today_start_timestamp();
    
    u_int32_t yesterday = today - SECONDS_PER_DAY;
    
    char yesterday_str[32] = {0};
    char today_str[32] = {0};
    get_date_string(yesterday, yesterday_str, sizeof(yesterday_str));
    get_date_string(today, today_str, sizeof(today_str));
    
    LOG_WARN("Date changed: %s -> %s, starting archive process...\n", yesterday_str, today_str);
    
    int client_count = 0;
    list_for_each_entry(node, &client_list, client) {
        client_count++;
        LOG_DEBUG("archiving client %s\n", node->mac);

        visit_info_t *p_info = NULL, *tmp_info = NULL;
        list_for_each_entry_safe(p_info, tmp_info, &node->online_visit, visit) {

            int total_time = p_info->latest_time - p_info->first_time;
            if (total_time < g_app_valid_time) {
                LOG_DEBUG("Discard visit record on date change (too short): mac=%s, appid=%d, duration=%ds < %ds\n", 
                          node->mac, p_info->appid, total_time, g_app_valid_time);
                list_del(&p_info->visit);
                free(p_info);  // 直接删除，不加入visit列表
            } else {
                p_info->expire = 0;


                list_move(&p_info->visit, &node->visit);
                save_visit_record_to_db(node->mac, p_info);
            }
        }
        
        save_client_visit_data_to_file(node, yesterday);
        
        
        if (node->daily_stats.date == yesterday) {
            save_daily_stats_to_file(node, yesterday);
        }
        if (node->daily_top_apps_stats.date == yesterday) {
            save_daily_top_apps_stats_to_file(node, yesterday);
        }
        
        
        u_int32_t date_end = yesterday + SECONDS_PER_DAY - 1;
        
        list_for_each_entry_safe(p_info, tmp_info, &node->visit, visit) {
            if (p_info->first_time >= yesterday && p_info->first_time <= date_end) {
                list_del(&p_info->visit);
                free(p_info);
            }
        }
        
        
        visit_stat_t *stat_node = NULL, *tmp_stat_node = NULL;
        list_for_each_entry_safe(stat_node, tmp_stat_node, &node->stat_list, list) {
            list_del(&stat_node->list);
            free(stat_node);
        }
        
        
        node->daily_stats.date = today;
        node->daily_stats.is_today = 1;
        for (i = 0; i < HOURS_PER_DAY; i++) {
            for (j = 0; j < TOP_APP_PER_HOUR; j++) {
                node->daily_stats.hourly_top_apps[i][j] = -1;
            }
            
            node->daily_stats.hourly_traffic[i].up_bytes = 0;
            node->daily_stats.hourly_traffic[i].down_bytes = 0;
            node->daily_stats.hourly_online_time[i] = 0;
            node->daily_stats.hourly_active_time[i] = 0;
        }
        
        node->daily_top_apps_stats.date = today;
        node->daily_top_apps_stats.is_today = 1;
        node->daily_top_apps_stats.count = 0;
        for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
            node->daily_top_apps_stats.apps[i].appid = -1;
            node->daily_top_apps_stats.apps[i].total_time = 0;
        }
    }
    
    
    today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
        LOG_DEBUG("Reset global daily type stats for new day\n");
    }
    
    
    if (g_global_traffic_date != 0 && g_global_traffic_date != today) {
        save_global_traffic_stats_to_file(g_global_traffic_date);
    }
    
    
    if (g_global_traffic_date != today) {
        memset(g_global_hourly_traffic, 0, sizeof(g_global_hourly_traffic));
        g_global_traffic_date = today;
        LOG_DEBUG("Reset global traffic stats for new day\n");
    }
    
    
    global_app_type_record_t *record = NULL, *tmp_record = NULL;
    list_for_each_entry_safe(record, tmp_record, &global_hourly_records, list) {
        list_del(&record->list);
        free(record);
    }
    LOG_DEBUG("Reset global hourly type stats for new day\n");
    
    LOG_DEBUG("Archive completed: processed %d clients for date %s\n", client_count, yesterday_str);
    
    save_all_client_backup_to_files();
    
    
    cleanup_old_record_files();
}


typedef struct app_time_stat {
    int appid;
    unsigned long long total_time;
} app_time_stat_t;


static int compare_app_time_stat(const void *a, const void *b) {
    app_time_stat_t *pa = (app_time_stat_t *)a;
    app_time_stat_t *pb = (app_time_stat_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


daily_top_apps_stat_t *get_today_top_apps_stat(client_node_t *client) {
	int i;
    if (!client)
        return NULL;
    
    u_int32_t today = get_today_start_timestamp();
    
    
    if (client->daily_top_apps_stats.date == today && client->daily_top_apps_stats.is_today == 1) {
        return &client->daily_top_apps_stats;
    }
    
    
    if (client->daily_top_apps_stats.date != 0 && client->daily_top_apps_stats.date != today) {
        save_daily_top_apps_stats_to_file(client, client->daily_top_apps_stats.date);
    }
    
    
    client->daily_top_apps_stats.date = today;
    client->daily_top_apps_stats.is_today = 1;
    client->daily_top_apps_stats.count = 0;
    for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
        client->daily_top_apps_stats.apps[i].appid = -1;
        client->daily_top_apps_stats.apps[i].total_time = 0;
    }
    
    return &client->daily_top_apps_stats;
}


daily_top_apps_stat_t *load_history_top_apps_stat_from_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return NULL;
    
    
    
    return NULL;
}


void update_daily_top_apps(client_node_t *client) {
    if (!client)
        return;

    
    daily_top_apps_stat_t *today_stat = get_today_top_apps_stat(client);
    if (!today_stat)
        return;

    int cur_time = get_timestamp();
    app_time_stat_t app_stats[MAX_APP_STAT_NUM];
    int app_count = 0;
    int i;

    
    for (i = 0; i < MAX_APP_STAT_NUM; i++) {
        app_stats[i].appid = -1;
        app_stats[i].total_time = 0;
    }

    
    visit_info_t *p_info = NULL;
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (!is_same_day(p_info->first_time, cur_time))
            continue;

        
        unsigned long long visit_time = p_info->latest_time - p_info->first_time;
        if (visit_time == 0)
            visit_time = 1; 

        
        int found = 0;
        for (i = 0; i < app_count; i++) {
            if (app_stats[i].appid == p_info->appid) {
                app_stats[i].total_time += visit_time;
                found = 1;
                break;
            }
        }

        
        if (!found && app_count < MAX_APP_STAT_NUM) {
            app_stats[app_count].appid = p_info->appid;
            app_stats[app_count].total_time = visit_time;
            app_count++;
        } else if (!found && app_count >= MAX_APP_STAT_NUM) {
            
            int min_idx = 0;
            unsigned long long min_time = app_stats[0].total_time;
            for (i = 1; i < MAX_APP_STAT_NUM; i++) {
                if (app_stats[i].total_time < min_time) {
                    min_time = app_stats[i].total_time;
                    min_idx = i;
                }
            }
            if (visit_time > min_time) {
                app_stats[min_idx].appid = p_info->appid;
                app_stats[min_idx].total_time = visit_time;
            }
        }
    }

    if (app_count == 0) {
        
        today_stat->count = 0;
        for (i = 0; i < MAX_TOP_APPS_PER_DAY; i++) {
            today_stat->apps[i].appid = -1;
            today_stat->apps[i].total_time = 0;
        }
        return;
    }

    
    qsort(app_stats, app_count, sizeof(app_time_stat_t), compare_app_time_stat);

    
    int top_count = (app_count < MAX_TOP_APPS_PER_DAY) ? app_count : MAX_TOP_APPS_PER_DAY;
    today_stat->count = 0;
    
    for (i = 0; i < top_count; i++) {
        if (app_stats[i].appid > 0 && app_stats[i].total_time > 0) {
            today_stat->apps[today_stat->count].appid = app_stats[i].appid;
            today_stat->apps[today_stat->count].total_time = app_stats[i].total_time;
            today_stat->count++;
        }
    }
    
    
    for (i = today_stat->count; i < MAX_TOP_APPS_PER_DAY; i++) {
        today_stat->apps[i].appid = -1;
        today_stat->apps[i].total_time = 0;
    }
}


void save_daily_top_apps_stats_to_file(client_node_t *client, u_int32_t date) {
	int i;
    if (!client)
        return;
    
    daily_top_apps_stat_t *stat = &client->daily_top_apps_stats;
    if (stat->date != date) {
        char date_str[32] = {0};
        char stat_date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        get_date_string(stat->date, stat_date_str, sizeof(stat_date_str));
        LOG_DEBUG("Date mismatch for client %s: requested %s, but stat date is %s, skip saving\n", 
                 client->mac, date_str, stat_date_str);
        return;  
    }
    
    
    char stats_dir[512] = {0};
    char mac_dirname[64] = {0};
    mac_to_dirname(client->mac, mac_dirname, sizeof(mac_dirname));
    snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats", get_client_data_base_dir(), mac_dirname);
    
    if (ensure_dir_exists(stats_dir) != 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_ERROR("Failed to create stats directory %s for client %s top apps (date: %s)\n", 
                  stats_dir, client->mac, date_str);
        return;
    }
    
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    snprintf(file_path, sizeof(file_path), "%s/top_apps_%s.json", stats_dir, date_str);
    
    
    struct json_object *json_obj = json_object_new_object();
    json_object_object_add(json_obj, "date", json_object_new_int64(date));
    json_object_object_add(json_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(json_obj, "count", json_object_new_int(stat->count));
    
    
    struct json_object *apps_array = json_object_new_array();
    for (i = 0; i < stat->count; i++) {
        struct json_object *app_obj = json_object_new_object();
        json_object_object_add(app_obj, "appid", json_object_new_int(stat->apps[i].appid));
        if (!app_icon_exists_by_id(stat->apps[i].appid))
            json_object_object_add(app_obj, "icon", json_object_new_int(0));
        json_object_object_add(app_obj, "total_time", json_object_new_int64(stat->apps[i].total_time));
        const char *app_name = get_app_name_by_id(stat->apps[i].appid);
        if (app_name) {
            json_object_object_add(app_obj, "name", json_object_new_string(app_name));
        }
        json_object_array_add(apps_array, app_obj);
    }
    
    json_object_object_add(json_obj, "apps", apps_array);
    
    
    const char *json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%s\n", json_string);
        fclose(fp);
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("Saved daily top apps stats for client %s (date: %s, count: %d) to %s\n", 
                 client->mac, date_str, stat->count, file_path);
    } else {
        LOG_ERROR("Failed to save daily top apps stats to file: %s (errno: %d)\n", file_path, errno);
    }
    
    json_object_put(json_obj);
}


static void mac_to_dirname(const char *mac, char *dirname, size_t len) {
	int i;
    if (!mac || !dirname || len == 0)
        return;
    
    strncpy(dirname, mac, len - 1);
    dirname[len - 1] = '\0';
    
    
    for (i = 0; dirname[i] != '\0'; i++) {
        if (dirname[i] == ':') {
            dirname[i] = '_';
        }
    }
}


static int ensure_dir_exists(const char *path) {
    char cmd[512] = {0};
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", path);
    system(cmd);
    
    return 0;
}


static void get_date_string(u_int32_t timestamp, char *date_str, size_t len) {
    if (!date_str || len == 0)
        return;
    
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        date_str[0] = '\0';
        return;
    }
    
    strftime(date_str, len, "%Y-%m-%d", tm_info);
}


static void format_time_string(u_int32_t timestamp, char *time_str, size_t len) {
    if (!time_str || len == 0)
        return;
    
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        time_str[0] = '\0';
        return;
    }
    
    strftime(time_str, len, "%Y-%m-%d %H:%M:%S", tm_info);
}


void save_client_visit_data_to_file(client_node_t *client, u_int32_t date) {
    if (!client)
        return;
    LOG_DEBUG("begin save_client_visit_data_to_file: %s, date: %u\n", client->mac, date);
    
    int visit_count = 0;
    visit_info_t *p_info = NULL;
    u_int32_t date_end = date + SECONDS_PER_DAY - 1;  
    
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (p_info->first_time >= date && p_info->first_time <= date_end) {
            visit_count++;
        }
    }
    
    
    if (visit_count == 0) {
        char date_str[32] = {0};
        get_date_string(date, date_str, sizeof(date_str));
        LOG_DEBUG("No visit records for client %s on date %s, skip saving\n", client->mac, date_str);
        return;
    }
    
    
    if (ensure_dir_exists(get_history_data_root_dir()) != 0) {
        LOG_ERROR("Failed to create root directory: %s\n", get_history_data_root_dir());
        return;
    }
    
    char date_str[32] = {0};
    get_date_string(date, date_str, sizeof(date_str));
    
    char file_path[512] = {0};
    sqlite3 *db = NULL;
    sqlite3_stmt *delete_stmt = NULL;
    sqlite3_stmt *insert_stmt = NULL;
    int rc = SQLITE_OK;
    int transaction_started = 0;
    build_client_visit_db_path(file_path, sizeof(file_path));

    if (open_client_visit_db(&db) != 0) {
        LOG_ERROR("Failed to open client visit db: %s (client: %s, date: %s)\n",
                  file_path, client->mac, date_str);
        return;
    }

    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to begin transaction: %s (rc: %d)\n", file_path, rc);
        sqlite3_close(db);
        return;
    }
    transaction_started = 1;

    rc = sqlite3_prepare_v2(db,
                            "DELETE FROM app_visit_record WHERE mac = ? AND record_date = ?;",
                            -1, &delete_stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to prepare delete statement: %s (rc: %d)\n", file_path, rc);
        goto CLEANUP;
    }

    sqlite3_bind_text(delete_stmt, 1, client->mac, -1, SQLITE_STATIC);
    sqlite3_bind_int64(delete_stmt, 2, date);
    rc = sqlite3_step(delete_stmt);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to clear app visit records: %s (rc: %d)\n", file_path, rc);
        goto CLEANUP;
    }

    rc = sqlite3_prepare_v2(db,
                            "INSERT INTO app_visit_record (mac, record_date, appid, start_time, end_time, duration, action) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?);",
                            -1, &insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to prepare insert statement: %s (rc: %d)\n", file_path, rc);
        goto CLEANUP;
    }

    
    list_for_each_entry(p_info, &client->visit, visit) {
        
        if (p_info->first_time < date || p_info->first_time > date_end) {
            LOG_DEBUG("skip visit record: %u, %u\n", p_info->first_time, date_end);
            continue;
        }
        
        int duration = p_info->latest_time - p_info->first_time;
        if (duration == 0)
            duration = 1;

        sqlite3_bind_text(insert_stmt, 1, client->mac, -1, SQLITE_STATIC);
        sqlite3_bind_int64(insert_stmt, 2, date);
        sqlite3_bind_int(insert_stmt, 3, p_info->appid);
        sqlite3_bind_int64(insert_stmt, 4, p_info->first_time);
        sqlite3_bind_int64(insert_stmt, 5, p_info->latest_time);
        sqlite3_bind_int(insert_stmt, 6, duration);
        sqlite3_bind_int(insert_stmt, 7, p_info->action);

        rc = sqlite3_step(insert_stmt);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("Failed to insert app visit record: %s (rc: %d)\n", file_path, rc);
            goto CLEANUP;
        }
        sqlite3_reset(insert_stmt);
        sqlite3_clear_bindings(insert_stmt);
    }

    rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to commit transaction: %s (rc: %d)\n", file_path, rc);
        goto CLEANUP;
    }
    transaction_started = 0;
    
    LOG_DEBUG("Saved visit data for client %s (date: %s, records: %d) to sqlite db %s\n", 
             client->mac, date_str, visit_count, file_path);

CLEANUP:
    if (delete_stmt)
        sqlite3_finalize(delete_stmt);
    if (insert_stmt)
        sqlite3_finalize(insert_stmt);
    if (transaction_started)
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
    if (db)
        sqlite3_close(db);
}


static u_int32_t parse_date_string(const char *date_str) {
    if (!date_str)
        return 0;
    
    struct tm tm_info = {0};
    if (sscanf(date_str, "%d-%d-%d", &tm_info.tm_year, &tm_info.tm_mon, &tm_info.tm_mday) != 3)
        return 0;
    
    tm_info.tm_year -= 1900;  
    tm_info.tm_mon -= 1;       
    tm_info.tm_hour = 0;
    tm_info.tm_min = 0;
    tm_info.tm_sec = 0;
    
    return (u_int32_t)mktime(&tm_info);
}


static int extract_date_from_filename(const char *filename, char *date_str, size_t len) {
	int i;
    if (!filename || !date_str || len == 0)
        return -1;
    
    
    const char *prefixes[] = {"hourly_", "top_apps_", "traffic_", NULL};
    const char *start = filename;
    
    
    for (i = 0; prefixes[i] != NULL; i++) {
        size_t prefix_len = strlen(prefixes[i]);
        if (strncmp(filename, prefixes[i], prefix_len) == 0) {
            start = filename + prefix_len;
            break;
        }
    }
    
    
    int year, mon, mday;
    if (sscanf(start, "%d-%d-%d", &year, &mon, &mday) != 3)
        return -1;
    
    snprintf(date_str, len, "%04d-%02d-%02d", year, mon, mday);
    return 0;
}


static void cleanup_old_record_files(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (!tm_info) {
        LOG_ERROR("Failed to get local time for cleanup\n");
        return;
    }
    
    u_int32_t expire_timestamp = (u_int32_t)now - (MAX_RECORD_DAY * SECONDS_PER_DAY);
    int deleted_count = 0;
    deleted_count += delete_expired_visit_records(expire_timestamp);

    DIR *base_dir = opendir(get_client_data_base_dir());
    if (!base_dir) {
        LOG_DEBUG("Base directory %s does not exist, skip cleanup\n", get_client_data_base_dir());
        return;
    }
    
    struct dirent *client_entry;
    
    
    while ((client_entry = readdir(base_dir)) != NULL) {
        if (client_entry->d_name[0] == '.')
            continue;  
        
        char client_dir[512] = {0};
        snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
        
        struct stat st;
        if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;  
        
        
        char visits_dir[512] = {0};
        snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
        
        DIR *visits_dp = opendir(visits_dir);
        if (visits_dp) {
            struct dirent *file_entry;
            while ((file_entry = readdir(visits_dp)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                            LOG_WARN("Deleted expired visit file: %s (date: %s)\n", file_path, date_str);
                        } else {
                            LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                        }
                    }
                }
            }
            closedir(visits_dp);
        }
        
        
        char stats_dir[512] = {0};
        snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
        
        DIR *stats_dp = opendir(stats_dir);
        if (stats_dp) {
            struct dirent *file_entry;
            while ((file_entry = readdir(stats_dp)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date < expire_timestamp) {
                        char file_path[512] = {0};
                        snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                        if (unlink(file_path) == 0) {
                            deleted_count++;
                            LOG_WARN("Deleted expired stats file: %s (date: %s)\n", file_path, date_str);
                        } else {
                            LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                        }
                    }
                }
            }
            closedir(stats_dp);
        }
    }
    
    closedir(base_dir);
    
    
    char global_stats_dir[512] = {0};
    snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_history_data_root_dir());
    
    DIR *global_stats_dp = opendir(global_stats_dir);
    if (global_stats_dp) {
        struct dirent *file_entry;
        while ((file_entry = readdir(global_stats_dp)) != NULL) {
            if (file_entry->d_name[0] == '.')
                continue;
            
            char date_str[32] = {0};
            if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                u_int32_t file_date = parse_date_string(date_str);
                if (file_date > 0 && file_date < expire_timestamp) {
                    char file_path[512] = {0};
                    snprintf(file_path, sizeof(file_path), "%s/%s", global_stats_dir, file_entry->d_name);
                    if (unlink(file_path) == 0) {
                        deleted_count++;
                        LOG_WARN("Deleted expired global traffic stats file: %s (date: %s)\n", file_path, date_str);
                    } else {
                        LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                    }
                }
            }
        }
        closedir(global_stats_dp);
    }
    
    if (deleted_count > 0) {
        LOG_WARN("Cleanup completed: deleted %d expired record files (older than %d days)\n", 
                 deleted_count, MAX_RECORD_DAY);
    }
}


void get_global_traffic_stats(traffic_stat_t *traffic_array) {
    if (!traffic_array)
        return;
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_global_traffic_date != today) {
        memset(g_global_hourly_traffic, 0, sizeof(g_global_hourly_traffic));
        g_global_traffic_date = today;
    }
    
    
    memcpy(traffic_array, g_global_hourly_traffic, sizeof(g_global_hourly_traffic));
}






void delete_client_record_files(const char *mac, const char *start_date, const char *end_date, const char *delete_type) {
    u_int32_t start_timestamp = 0;
    u_int32_t end_timestamp = UINT32_MAX;
    
    
    if (start_date && strlen(start_date) > 0) {
        
        if (strchr(start_date, '-')) {
            start_timestamp = parse_date_string(start_date);
        } else {
            start_timestamp = (u_int32_t)atoi(start_date);
        }
    }
    
    
    if (end_date && strlen(end_date) > 0) {
        if (strchr(end_date, '-')) {
            u_int32_t end_date_ts = parse_date_string(end_date);
            
            end_timestamp = end_date_ts + SECONDS_PER_DAY - 1;
        } else {
            end_timestamp = (u_int32_t)atoi(end_date);
        }
    }
    
    
    int delete_visits = 1;
    int delete_stats = 1;
    if (delete_type && strlen(delete_type) > 0) {
        if (strcmp(delete_type, "visits") == 0) {
            delete_visits = 1;
            delete_stats = 0;
        } else if (strcmp(delete_type, "stats") == 0) {
            delete_visits = 0;
            delete_stats = 1;
        } else if (strcmp(delete_type, "all") == 0) {
            delete_visits = 1;
            delete_stats = 1;
        }
    }
    
    char mac_dirname[64] = {0};
    int specific_mac = 0;
    if (mac && strlen(mac) > 0) {
        mac_to_dirname(mac, mac_dirname, sizeof(mac_dirname));
        specific_mac = 1;
    }
    
    DIR *base_dir = opendir(get_client_data_base_dir());
    int deleted_count = 0;

    if (delete_visits) {
        deleted_count += delete_visit_records_in_range(specific_mac ? mac : NULL, start_timestamp, end_timestamp);
    }

    if (!base_dir) {
        LOG_DEBUG("Base directory %s does not exist, skip client directory cleanup\n", get_client_data_base_dir());
    } else {
        struct dirent *client_entry;
        
        while ((client_entry = readdir(base_dir)) != NULL) {
            if (client_entry->d_name[0] == '.')
                continue;  
            
            
            if (specific_mac && strcmp(client_entry->d_name, mac_dirname) != 0)
                continue;
            
            char client_dir[512] = {0};
            snprintf(client_dir, sizeof(client_dir), "%s/%s", get_client_data_base_dir(), client_entry->d_name);
            
            struct stat st;
            if (stat(client_dir, &st) != 0 || !S_ISDIR(st.st_mode))
                continue;  
            
            
            if (delete_visits) {
                char visits_dir[512] = {0};
                snprintf(visits_dir, sizeof(visits_dir), "%s/visits", client_dir);
                
                DIR *visits_dp = opendir(visits_dir);
                if (visits_dp) {
                    struct dirent *file_entry;
                    while ((file_entry = readdir(visits_dp)) != NULL) {
                        if (file_entry->d_name[0] == '.')
                            continue;
                        
                        char date_str[32] = {0};
                        if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                            u_int32_t file_date = parse_date_string(date_str);
                            if (file_date > 0 && file_date >= start_timestamp && file_date <= end_timestamp) {
                                char file_path[512] = {0};
                                snprintf(file_path, sizeof(file_path), "%s/%s", visits_dir, file_entry->d_name);
                                if (unlink(file_path) == 0) {
                                    deleted_count++;
                                    LOG_DEBUG("Deleted visit file: %s (date: %s)\n", file_path, date_str);
                                } else {
                                    LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                                }
                            }
                        }
                    }
                    closedir(visits_dp);
                }
            }
            
            
            if (delete_stats) {
                char stats_dir[512] = {0};
                snprintf(stats_dir, sizeof(stats_dir), "%s/stats", client_dir);
                
                DIR *stats_dp = opendir(stats_dir);
                if (stats_dp) {
                    struct dirent *file_entry;
                    while ((file_entry = readdir(stats_dp)) != NULL) {
                        if (file_entry->d_name[0] == '.')
                            continue;
                        
                        char date_str[32] = {0};
                        if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                            u_int32_t file_date = parse_date_string(date_str);
                            if (file_date > 0 && file_date >= start_timestamp && file_date <= end_timestamp) {
                                char file_path[768] = {0};  
                                int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", stats_dir, file_entry->d_name);
                                if (path_len >= 0 && path_len < sizeof(file_path)) {
                                    if (unlink(file_path) == 0) {
                                        deleted_count++;
                                        LOG_DEBUG("Deleted stats file: %s (date: %s)\n", file_path, date_str);
                                    } else {
                                        LOG_ERROR("Failed to delete file: %s (errno: %d)\n", file_path, errno);
                                    }
                                } else {
                                    LOG_ERROR("File path too long: %s/%s\n", stats_dir, file_entry->d_name);
                                }
                            }
                        }
                    }
                    closedir(stats_dp);
                }
            }
        }
        
        closedir(base_dir);
    }

    if (delete_stats && !specific_mac) {
        char global_stats_dir[512] = {0};
        snprintf(global_stats_dir, sizeof(global_stats_dir), "%s/global/stats", get_history_data_root_dir());
        DIR *global_dp = opendir(global_stats_dir);
        if (global_dp) {
            struct dirent *file_entry;
            while ((file_entry = readdir(global_dp)) != NULL) {
                if (file_entry->d_name[0] == '.')
                    continue;
                char date_str[32] = {0};
                if (extract_date_from_filename(file_entry->d_name, date_str, sizeof(date_str)) == 0) {
                    u_int32_t file_date = parse_date_string(date_str);
                    if (file_date > 0 && file_date >= start_timestamp && file_date <= end_timestamp) {
                        char file_path[768] = {0};
                        int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", global_stats_dir, file_entry->d_name);
                        if (path_len >= 0 && path_len < sizeof(file_path)) {
                            if (unlink(file_path) == 0) {
                                deleted_count++;
                                LOG_DEBUG("Deleted global stats file: %s (date: %s)\n", file_path, date_str);
                            } else {
                                LOG_ERROR("Failed to delete global stats file: %s (errno: %d)\n", file_path, errno);
                            }
                        }
                    }
                }
            }
            closedir(global_dp);
        }
    }
    
    LOG_DEBUG("Delete completed: deleted %d record files\n", deleted_count);
}


void update_global_app_type_stats(int appid, unsigned long long time_delta) {
    if (appid <= 0 || time_delta == 0)
        return;
    
    int app_type = appid / 1000;
    if (app_type <= 0 || app_type > MAX_APP_TYPE)
        return;
    
    int type_index = app_type - 1;  
    u_int32_t cur_time = get_timestamp();
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
    }
    
    
    g_daily_type_stats[type_index] += time_delta;
    
    
    global_app_type_record_t *record = (global_app_type_record_t *)calloc(1, sizeof(global_app_type_record_t));
    if (record) {
        record->app_type = app_type;
        record->time_delta = time_delta;
        record->timestamp = cur_time;
        INIT_LIST_HEAD(&record->list);
        list_add_tail(&record->list, &global_hourly_records);
    }
}


void cleanup_expired_hourly_stats(void) {
    u_int32_t cur_time = get_timestamp();
    u_int32_t expire_time = cur_time - 3600;  
    
    global_app_type_record_t *record = NULL, *tmp_record = NULL;
    int cleared_count = 0;
    
    
    list_for_each_entry_safe(record, tmp_record, &global_hourly_records, list) {
        if (record->timestamp < expire_time) {
            
            list_del(&record->list);
            free(record);
            cleared_count++;
        } else {
            
            break;
        }
    }
    
    if (cleared_count > 0) {
        LOG_DEBUG("Cleared %d expired hourly records\n", cleared_count);
    }
}


void get_global_daily_app_type_stats(unsigned long long *type_time_array) {
    if (!type_time_array)
        return;
    
    
    u_int32_t today = get_today_start_timestamp();
    if (g_daily_stat_date != today) {
        memset(g_daily_type_stats, 0, sizeof(g_daily_type_stats));
        g_daily_stat_date = today;
    }
    
    
    memcpy(type_time_array, g_daily_type_stats, sizeof(g_daily_type_stats));
}


void get_global_hourly_app_type_stats(unsigned long long *type_time_array) {
    if (!type_time_array)
        return;
    
    
    cleanup_expired_hourly_stats();
    
    
    memset(type_time_array, 0, sizeof(unsigned long long) * MAX_APP_TYPE);
    
    
    u_int32_t cur_time = get_timestamp();
    u_int32_t expire_time = cur_time - 3600;  
    
    global_app_type_record_t *record = NULL;
    list_for_each_entry(record, &global_hourly_records, list) {
        if (record->timestamp >= expire_time) {
            int type_index = record->app_type - 1;
            if (type_index >= 0 && type_index < MAX_APP_TYPE) {
                type_time_array[type_index] += record->time_delta;
            }
        }
    }
}
