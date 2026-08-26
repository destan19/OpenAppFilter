// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dirent.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <sqlite3.h>
#include <time.h>
#include "fwx_user.h"
#include "fwx_config.h"
#include "fwx_feature.h"
#include "fwx_feature_online.h"
#include "fwx_custom_feature.h"
#include <uci.h>
#include "fwx.h"
#include "fwx_utils.h"

#define CLIENT_DATA_BASE_DIR_DEFAULT "/tmp/fwx/client_data"
#include "fwx_app_filter.h"
#include "fwx_mac_filter.h"
#include "fwx_record.h"
#include "fwx_network.h"
#include "fwx_wireless.h"
#include "fwx_firewall.h"
#include "fwx_system.h"
#include "fwx_stat.h"
#include <fcntl.h>
#include <unistd.h>
#include <libubox/list.h>

extern fwx_status_t g_fwx_status;
extern void reload_oaf_rule(void);

static int ensure_feature_data_loaded(void)
{
    char *feature_data = NULL;
    size_t feature_len = 0;

    if (fwx_feature_get_data(&feature_len) && feature_len > 0)
        return 0;

    if (fwx_feature_decrypt_file(FWX_FEATURE_BIN_PATH, &feature_data, &feature_len) < 0) {
        LOG_ERROR("class_list failed: decrypt feature file failed\n");
        return -1;
    }

    fwx_feature_replace_data(feature_data, feature_len);
    init_app_name_table();
    init_app_class_name_table();
    if (fwx_custom_feature_reload() < 0)
        LOG_WARN("class_list warning: custom feature reload failed\n");
    else if (fwx_custom_feature_add_app_names() < 0)
        LOG_WARN("class_list warning: custom app names init failed\n");

    LOG_WARN("class_list loaded feature data without netlink\n");
    return 0;
}

static void add_app_icon_missing_flag(struct json_object *obj, int appid)
{
    if (!obj || appid <= 0)
        return;
    if (!app_icon_exists_by_id(appid))
        json_object_object_add(obj, "icon", json_object_new_int(0));
}


#define MAX_INTERFACE_TRAFFIC_POINTS 60
#define INTERFACE_TRAFFIC_INTERVAL 2  
#define FWX_USER_SESSION_PROC_PATH "/proc/net/fwx_user"

typedef struct interface_traffic_node {
    struct list_head list;
    unsigned long long up_bytes;      
    unsigned long long down_bytes;    
    unsigned int up_rate;             
    unsigned int down_rate;           
    u_int32_t timestamp;              
} interface_traffic_node_t;


static LIST_HEAD(interface_traffic_list);
static int interface_traffic_count = 0;
static char g_interface_name[16] = {0};  
static unsigned long long last_up_bytes = 0;
static unsigned long long last_down_bytes = 0;
static u_int32_t last_traffic_time = 0;

struct ubus_context *ubus_ctx = NULL;
static struct blob_buf b;

extern char *format_time(int timetamp);




void ubus_response_json(struct ubus_context *ctx, struct ubus_request_data *req, struct json_object *response){
    struct blob_buf b_buf = {};
    blob_buf_init(&b_buf, 0);
    blobmsg_add_object(&b_buf, response);
    ubus_send_reply(ctx, req, b_buf.head);
    blob_buf_free(&b_buf);
}

void reload_oaf_rule(){
    system("/usr/bin/oaf_rule reload");
}

void get_hostname_by_mac(char *mac, char *hostname)
{
    if (!mac || !hostname)
        return;
    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
    {
        printf("open dhcp lease file....failed\n");
        return;
    }
    char line_buf[256] = {0};
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        char hostname_buf[128] = {0};
        char mac_buf[32] = {0};
        sscanf(line_buf, "%*s %s %*s %s", mac_buf, hostname_buf);
        if (0 == strcmp(mac, mac_buf))
        {
            strcpy(hostname, hostname_buf);
        }
    }
    fclose(fp);
}


int compare_lt(const void *a, const void *b) {
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;

    struct json_object *lt_a, *lt_b;
    json_object_object_get_ex(obj_a, "lt", &lt_a);
    json_object_object_get_ex(obj_b, "lt", &lt_b);

    int lt_val_a = json_object_get_int(lt_a);
    int lt_val_b = json_object_get_int(lt_b);

    return lt_val_b - lt_val_a;
}

typedef struct active_app_visit_record {
    char mac[MAX_MAC_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    int appid;
    int action;
    u_int32_t first_time;
    u_int32_t latest_time;
    int total_time;
} active_app_visit_record_t;

static int compare_active_app_visit_record(const void *a, const void *b) {
    active_app_visit_record_t *pa = (active_app_visit_record_t *)a;
    active_app_visit_record_t *pb = (active_app_visit_record_t *)b;

    if (pa->latest_time > pb->latest_time)
        return -1;
    if (pa->latest_time < pb->latest_time)
        return 1;

    if (pa->total_time < pb->total_time)
        return -1;
    if (pa->total_time > pb->total_time)
        return 1;

    return 0;
}

static int collect_active_app_visit_records(active_app_visit_record_t *records, int max_records) {
    int count = 0;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;

    list_for_each_entry(node, &client_list, client) {
        list_for_each_entry(p_info, &node->online_visit, visit) {
            if (records && count < max_records) {
                int total_time = p_info->latest_time - p_info->first_time;
                if (total_time == 0)
                    total_time = 1;

                strncpy(records[count].mac, node->mac, sizeof(records[count].mac) - 1);
                records[count].mac[sizeof(records[count].mac) - 1] = '\0';
                strncpy(records[count].hostname, node->hostname, sizeof(records[count].hostname) - 1);
                records[count].hostname[sizeof(records[count].hostname) - 1] = '\0';
                strncpy(records[count].nickname, node->nickname, sizeof(records[count].nickname) - 1);
                records[count].nickname[sizeof(records[count].nickname) - 1] = '\0';
                records[count].appid = p_info->appid;
                records[count].action = p_info->action;
                records[count].first_time = p_info->first_time;
                records[count].latest_time = p_info->latest_time;
                records[count].total_time = total_time;
            }
            count++;
        }
    }

    return count;
}

static int bind_app_history_filters(sqlite3_stmt *stmt, const char *mac, int appid, u_int32_t start_time, u_int32_t end_time) {
    int idx = 1;

    if (mac && strlen(mac) > 0) {
        sqlite3_bind_text(stmt, idx++, mac, -1, SQLITE_STATIC);
    }

    if (appid > 0) {
        sqlite3_bind_int(stmt, idx++, appid);
    }

    if (start_time > 0 && end_time > 0) {
        sqlite3_bind_int64(stmt, idx++, start_time);
        sqlite3_bind_int64(stmt, idx++, end_time);
    } else if (start_time > 0) {
        sqlite3_bind_int64(stmt, idx++, start_time);
    } else if (end_time > 0) {
        sqlite3_bind_int64(stmt, idx++, end_time);
    }

    return idx;
}


static int
appfilter_handle_dev_visit_list(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    int i;
    struct json_object *root_obj = json_object_new_object();
    struct json_object *visit_array = json_object_new_array();
    int page = 1;
    int page_size = 15;

    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str)
    {
        printf("format json failed\n");
        return 0;
    }

    printf("msg_obj_str:%s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj)
    {
        printf("mac is null\n");
        json_object_put(req_obj);
        return 0;
    }


    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    if (page_obj) {
        page = json_object_get_int(page_obj);
        if (page < 1) page = 1;
    }
    if (page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size < 1) page_size = 15;
    }

    char *mac = json_object_get_string(mac_obj);
    client_node_t *node = find_client_node(mac);

    if (!node)
    {
        printf("not found mac:%s\n", mac);
        json_object_put(req_obj);
        return 0;
    }

    json_object_object_add(root_obj, "hostname", json_object_new_string(node->hostname));
    json_object_object_add(root_obj, "mac", json_object_new_string(node->mac));
    json_object_object_add(root_obj, "ip", json_object_new_string(node->ip));
    json_object_object_add(root_obj, "ipv6", json_object_new_string(node->ipv6));


    struct json_object *online_array = json_object_new_array();
    struct json_object *offline_array = json_object_new_array();
    visit_info_t *p_info = NULL;

    int online_num = 0;
    int offline_num = 0;

    list_for_each_entry(p_info, &node->online_visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(get_app_name_by_id(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        add_app_icon_missing_flag(visit_obj, p_info->appid);
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(1));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(online_array, visit_obj);
        online_num++;
    }

    list_for_each_entry(p_info, &node->visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(get_app_name_by_id(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        add_app_icon_missing_flag(visit_obj, p_info->appid);
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(0));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(offline_array, visit_obj);
        offline_num++;
    }

    json_object_array_sort(online_array, compare_lt);
    json_object_array_sort(offline_array, compare_lt);

    int total_num = online_num + offline_num;
    int total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) total_page = 1;
    if (page > total_page) page = total_page;
    

    struct json_object *paged_array = json_object_new_array();
    int start_idx = (page - 1) * page_size;
    int end_idx = start_idx + page_size;
    if (end_idx > total_num) end_idx = total_num;

    for (i = start_idx; i < end_idx; i++) {
        struct json_object *item = NULL;
        if (i < online_num) {
            item = json_object_array_get_idx(online_array, i);
        } else {
            item = json_object_array_get_idx(offline_array, i - online_num);
        }
        if (item) {
            json_object_get(item);
            json_object_array_add(paged_array, item);
        }
    }

    json_object_put(online_array);
    json_object_put(offline_array);
    

    json_object_object_add(root_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(root_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(root_obj, "page", json_object_new_int(page));
    json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(root_obj, "list", paged_array);
    
    json_object_put(req_obj);
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, root_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(root_obj);
    return 0;
}



typedef struct {
    int app_id;
    unsigned long long total_time;
} app_stat_sort_t;


static int compare_app_stat_sort(const void *a, const void *b) {
    app_stat_sort_t *pa = (app_stat_sort_t *)a;
    app_stat_sort_t *pb = (app_stat_sort_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}

void update_app_visit_time_list(char *mac, struct app_visit_stat_info *visit_info)
{
	int i;
    client_node_t *node = find_client_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    
    
    app_stat_sort_t app_stats[MAX_APP_STAT_NUM * 2];  
    int app_count = 0;
    
    visit_stat_t *stat_node = NULL;
    list_for_each_entry(stat_node, &node->stat_list, list) {
        if (stat_node->total_time == 0)
            continue;
        
        
        int found = 0;
        for (i = 0; i < app_count; i++) {
            if (app_stats[i].app_id == stat_node->appid) {
                app_stats[i].total_time += stat_node->total_time;
                found = 1;
                break;
            }
        }
        
        
        if (!found) {
            if (app_count < MAX_APP_STAT_NUM * 2) {
                app_stats[app_count].app_id = stat_node->appid;
                app_stats[app_count].total_time = stat_node->total_time;
                app_count++;
            }
        }
    }
    
    
    if (app_count > 0) {
        qsort(app_stats, app_count, sizeof(app_stat_sort_t), compare_app_stat_sort);
        
        int top_count = (app_count < MAX_APP_STAT_NUM) ? app_count : MAX_APP_STAT_NUM;
        for (i = 0; i < top_count; i++) {
            visit_info->visit_list[i].app_id = app_stats[i].app_id;
            visit_info->visit_list[i].total_time = app_stats[i].total_time;
        }
        visit_info->num = top_count;
    } else {
        visit_info->num = 0;
    }
}

void update_app_class_visit_time_list(char *mac, int *visit_time)
{
    client_node_t *node = find_client_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    
    
    visit_stat_t *stat_node = NULL;
    list_for_each_entry(stat_node, &node->stat_list, list) {
        if (stat_node->total_time == 0)
            continue;
        
        int type = stat_node->appid / 1000;
        if (type > 0 && type <= MAX_APP_TYPE) {
            visit_time[type - 1] += stat_node->total_time;
        }
    }
}

void ubus_get_dev_visit_time_info(char *mac, struct blob_buf *b)
{
    int i, j;
    void *c, *array;
    void *t;
    void *s;
    struct app_visit_stat_info info;
    memset((char *)&info, 0x0, sizeof(info));
    update_app_visit_time_list(mac, &info);
}

static int handle_debug(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    int ret;
    blob_buf_init(&b, 0);
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str)
    {
        printf("format json failed\n");
        return 0;
    }

    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *debug_obj = json_object_object_get(req_obj, "debug");

    if (debug_obj)
    {
        current_log_level = json_object_get_int(debug_obj);
        LOG_WARN("debug level set to %d\n", current_log_level);
    }

    ubus_send_reply(ctx, req, b.head);
    return 0;
}



typedef struct app_visit_time_info
{
    int app_id;
    unsigned long long total_time;
} app_visit_time_info_t;

int visit_time_compare(const void *a, const void *b)
{
    app_visit_time_info_t *p1 = (app_visit_time_info_t *)a;
    app_visit_time_info_t *p2 = (app_visit_time_info_t *)b;
    return p1->total_time < p2->total_time ? 1 : -1;
}

#define MAX_STAT_APP_NUM 128
void update_top5_app(client_node_t *node, app_visit_time_info_t top5_app_list[])
{
	int i;
    app_visit_time_info_t app_visit_array[MAX_STAT_APP_NUM];
    memset(app_visit_array, 0x0, sizeof(app_visit_array));
    int app_visit_num = 0;

    
    visit_stat_t *stat_node = NULL;
    list_for_each_entry(stat_node, &node->stat_list, list) {
        if (stat_node->total_time == 0)
            continue;
        
        
        int found = 0;
        for (i = 0; i < app_visit_num; i++) {
            if (app_visit_array[i].app_id == stat_node->appid) {
                app_visit_array[i].total_time += stat_node->total_time;
                found = 1;
                break;
            }
        }
        
        
        if (!found && app_visit_num < MAX_STAT_APP_NUM) {
            app_visit_array[app_visit_num].app_id = stat_node->appid;
            app_visit_array[app_visit_num].total_time = stat_node->total_time;
            app_visit_num++;
        }
    }

    qsort((void *)app_visit_array, app_visit_num, sizeof(app_visit_time_info_t), visit_time_compare);

    int top_count = (app_visit_num < 5) ? app_visit_num : 5;
    for (i = 0; i < top_count; i++)
    {
        top5_app_list[i] = app_visit_array[i];


    }
}

static int
appfilter_handle_dev_list(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    int i, j;
    struct json_object *root_obj = json_object_new_object();

    struct json_object *dev_array = json_object_new_array();
    int count = 0;
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        struct json_object *dev_obj = json_object_new_object();
        struct json_object *app_array = json_object_new_array();
        app_visit_time_info_t top5_app_list[5];
        memset(top5_app_list, 0x0, sizeof(top5_app_list));
        update_top5_app(node, top5_app_list);

            for (j = 0; j < 5; j++)
            {
                if (top5_app_list[j].app_id == 0)
                    break;
                struct json_object *app_obj = json_object_new_object();
                json_object_object_add(app_obj, "id", json_object_new_int(top5_app_list[j].app_id));
                json_object_object_add(app_obj, "name", json_object_new_string(get_app_name_by_id(top5_app_list[j].app_id)));
                add_app_icon_missing_flag(app_obj, top5_app_list[j].app_id);
                json_object_array_add(app_array, app_obj);
            }

            json_object_object_add(dev_obj, "applist", app_array);
            json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
            char hostname[128] = {0};
            get_hostname_by_mac(node->mac, hostname);
            json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));
            json_object_object_add(dev_obj, "ipv6", json_object_new_string(node->ipv6));

            json_object_object_add(dev_obj, "online", json_object_new_int(1));
            json_object_object_add(dev_obj, "hostname", json_object_new_string(hostname));
            json_object_object_add(dev_obj, "nickname", json_object_new_string(""));


            json_object_array_add(dev_array, dev_obj);

            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto END;
    }

END:

    json_object_object_add(root_obj, "devlist", dev_array);
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, root_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(root_obj);
    return 0;
}


static int appfilter_handle_visit_time(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    int ret;
    struct app_visit_stat_info info;
    blob_buf_init(&b, 0);
    memset((char *)&info, 0x0, sizeof(info));
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str)
    {
        printf("format json failed\n");
        return 0;
    }

    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj)
    {
        printf("mac is NULL\n");
        return 0;
    }
    update_app_visit_time_list(json_object_get_string(mac_obj), &info);

    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_info_array = json_object_new_array();
    json_object_object_add(resp_obj, "list", app_info_array);
    json_object_object_add(resp_obj, "total_num", json_object_new_int(info.num));
    int i;
    for (i = 0; i < info.num; i++)
    {
        struct json_object *app_info_obj = json_object_new_object();
        json_object_object_add(app_info_obj, "id", json_object_new_int(info.visit_list[i].app_id));
        add_app_icon_missing_flag(app_info_obj, info.visit_list[i].app_id);
        json_object_object_add(app_info_obj, "name", json_object_new_string(get_app_name_by_id(info.visit_list[i].app_id)));
        json_object_object_add(app_info_obj, "t", json_object_new_int(info.visit_list[i].total_time));
        json_object_array_add(app_info_array, app_info_obj);
    }

    blobmsg_add_object(&b, resp_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp_obj);
    json_object_put(req_obj);
    return 0;
}

static int
handle_app_class_visit_time(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
    int ret;
    int i;
    blob_buf_init(&b, 0);
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str)
    {
        printf("format json failed\n");
        return 0;
    }

    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj)
    {
        printf("mac is NULL\n");
        return 0;
    }
    int app_class_visit_time[MAX_APP_TYPE];
    memset(app_class_visit_time, 0x0, sizeof(app_class_visit_time));
    update_app_class_visit_time_list(json_object_get_string(mac_obj), app_class_visit_time);

    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_class_array = json_object_new_array();
    json_object_object_add(resp_obj, "class_list", app_class_array);
    for (i = 0; i < MAX_APP_TYPE; i++)
    {
        if (i >= g_cur_class_num)
            break;
        struct json_object *app_class_obj = json_object_new_object();
        json_object_object_add(app_class_obj, "type", json_object_new_int(i));
        json_object_object_add(app_class_obj, "name", json_object_new_string(CLASS_NAME_TABLE[i]));
        json_object_object_add(app_class_obj, "visit_time", json_object_new_int(app_class_visit_time[i]));
        json_object_array_add(app_class_array, app_class_obj);
    }

    blobmsg_add_object(&b, resp_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp_obj);
    json_object_put(req_obj);
    return 0;
}


static char *trim_feature_space(char *text)
{
    char *end;

    if (!text)
        return NULL;
    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int parse_feature_app_header_text(const char *line, int *app_id,
                                         char *app_name, size_t app_name_len)
{
    char header[128];
    char *slash;
    char *id_text;
    char *name_text;
    char *endptr;
    long id;
    const char *colon;
    size_t header_len;

    if (!line || !app_id || !app_name || app_name_len == 0)
        return -1;

    colon = strchr(line, ':');
    if (!colon)
        return -1;
    header_len = (size_t)(colon - line);
    if (header_len == 0 || header_len >= sizeof(header))
        return -1;

    memcpy(header, line, header_len);
    header[header_len] = '\0';
    slash = strchr(header, '~');
    if (!slash)
        return -1;
    *slash = '\0';

    id_text = trim_feature_space(header);
    name_text = trim_feature_space(slash + 1);
    if (!id_text || !id_text[0] || !name_text || !name_text[0])
        return -1;

    id = strtol(id_text, &endptr, 10);
    endptr = trim_feature_space(endptr);
    if (id <= 0 || (endptr && endptr[0] != '\0'))
        return -1;

    *app_id = (int)id;
    strncpy(app_name, name_text, app_name_len - 1);
    app_name[app_name_len - 1] = '\0';
    return 0;
}

static int parse_feature_cfg(struct json_object *class_list) {
    const char *feature_data;
    size_t feature_len = 0;
    size_t offset = 0;
    char line[1024];
    struct json_object *current_class = NULL;
    struct json_object *app_list = NULL;
    struct json_object *class_map[MAX_APP_TYPE + 1] = {0};
    int current_class_id = 0;

    if (ensure_feature_data_loaded() < 0)
        return -1;

    feature_data = fwx_feature_get_data(&feature_len);
    if (!feature_data || feature_len == 0)
        return -1;

    while (fwx_feature_next_line(feature_data, feature_len, &offset,
                                 line, sizeof(line)) != 0) {

        if (strncmp(line, "#class", 6) == 0) {

            if (current_class) {

                json_object_object_add(current_class, "app_list", app_list);
                json_object_array_add(class_list, current_class);
                if (current_class_id > 0 && current_class_id <= MAX_APP_TYPE)
                    class_map[current_class_id] = current_class;
                current_class = NULL;
                app_list = NULL;
            }


            char class_key[32] = {0};
            char class_name[64] = {0};
            if (sscanf(line + 7, "%31s %d %63s", class_key,
                       &current_class_id, class_name) != 3)
                continue;
            current_class = json_object_new_object();
            json_object_object_add(current_class, "name", json_object_new_string(class_name));
            app_list = json_object_new_array();
        } else if (current_class) {

            int appid = 0;
            char app_name[64] = {0};
            if (parse_feature_app_header_text(line, &appid, app_name, sizeof(app_name)) == 0) {
                char combined[256];
                if (app_icon_exists_by_id(appid))
                    snprintf(combined, sizeof(combined), "%d,%s", appid, app_name);
                else
                    snprintf(combined, sizeof(combined), "%d,%s,0", appid, app_name);
                json_object_array_add(app_list, json_object_new_string(combined));
            }
        }
    }


    if (current_class) {
        json_object_object_add(current_class, "app_list", app_list);
        json_object_array_add(class_list, current_class);
        if (current_class_id > 0 && current_class_id <= MAX_APP_TYPE)
            class_map[current_class_id] = current_class;
    }

    fwx_custom_feature_append_class_apps(class_map, MAX_APP_TYPE + 1);

    return 0;
}

static int handle_get_class_list(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *class_list = json_object_new_array();

    if (parse_feature_cfg(class_list) != 0) {
        json_object_put(response);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }

    json_object_object_add(response, "class_list", class_list);

    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);

    return 0;
}

typedef struct all_users_info {
    int flag;
    struct json_object *users_array;
    int pc_status_num;
    int blacklist_num;
    int session_num;
    struct {
        char mac[32];
        char status[32];
    } pc_status_items[MAX_SUPPORT_DEV_NUM];
    char blacklist_macs[MAX_SUPPORT_DEV_NUM][32];
    struct {
        char mac[32];
        int conn_count;
    } session_items[MAX_SUPPORT_DEV_NUM];
} all_users_info_t;

#define USER_PARENTAL_CONTROL_STATUS_FILE "/tmp/fwx_cache/user_parental_control_status"
#define USER_PARENTAL_CONTROL_DETAIL_FILE "/tmp/fwx_cache/user_parental_control_detail.json"
#define BLACKLIST_MAC_FILTER_RULE_ID 102
#define BLACKLIST_RULE_NAME "Internet Blacklist"
#define MAC_BLACKLIST_UCI_LIST "mac_blacklist.base.mac_list"
#define MAC_BLACKLIST_CONFIG "mac_blacklist"
#define MACFILTER_RULES_STATE_FILE "/tmp/macfilter_rules_state"

static void normalize_mac_value(const char *mac, char *out, size_t out_len)
{
    const char *start = mac;
    const char *end = NULL;
    size_t len = 0;
    size_t i;

    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (!mac) {
        return;
    }

    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) {
        end--;
    }

    len = end > start ? (size_t)(end - start) : 0;
    if (len >= out_len) {
        len = out_len - 1;
    }

    for (i = 0; i < len; i++) {
        out[i] = (char)toupper((unsigned char)start[i]);
    }
    out[len] = '\0';
}

static int compare_mac_value(const void *a, const void *b)
{
    return strcasecmp((const char *)a, (const char *)b);
}

static int mac_blacklist_has_item(char macs[][32], int count, const char *mac)
{
    int i;

    if (!mac || mac[0] == '\0') {
        return 0;
    }

    for (i = 0; i < count; i++) {
        if (strcasecmp(macs[i], mac) == 0) {
            return 1;
        }
    }

    return 0;
}

static int load_mac_blacklist_items(char macs[][32], int max_count)
{
    struct uci_context *uci_ctx = NULL;
    char list_buf[4096] = {0};
    char *token = NULL;
    char *saveptr = NULL;
    int count = 0;

    if (!macs || max_count <= 0) {
        return 0;
    }

    memset(macs, 0, max_count * sizeof(macs[0]));

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return 0;
    }

    if (fwx_uci_get_list_value(uci_ctx, MAC_BLACKLIST_UCI_LIST, list_buf, sizeof(list_buf), " ") == 0 &&
        list_buf[0] != '\0') {
        token = strtok_r(list_buf, " ", &saveptr);
        while (token && count < max_count) {
            char normalized_mac[32] = {0};
            normalize_mac_value(token, normalized_mac, sizeof(normalized_mac));
            if (normalized_mac[0] != '\0' && !mac_blacklist_has_item(macs, count, normalized_mac)) {
                strncpy(macs[count], normalized_mac, sizeof(macs[count]) - 1);
                count++;
            }
            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    if (count > 1) {
        qsort(macs, count, sizeof(macs[0]), compare_mac_value);
    }

    uci_free_context(uci_ctx);
    return count;
}

static int save_mac_blacklist_items(char macs[][32], int count)
{
    struct uci_context *uci_ctx = NULL;
    int i;
    int ret = 0;

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return -1;
    }

    fwx_uci_set_value(uci_ctx, "mac_blacklist.base", "settings");
    fwx_uci_delete(uci_ctx, MAC_BLACKLIST_UCI_LIST);

    for (i = 0; i < count; i++) {
        if (macs[i][0] != '\0' && fwx_uci_add_list(uci_ctx, MAC_BLACKLIST_UCI_LIST, macs[i]) != UCI_OK) {
            ret = -1;
            break;
        }
    }

    if (ret == 0 && fwx_uci_commit(uci_ctx, MAC_BLACKLIST_CONFIG) != UCI_OK) {
        ret = -1;
    }

    uci_free_context(uci_ctx);
    return ret;
}

static void touch_macfilter_rules_state_file(void)
{
    FILE *fp = fopen(MACFILTER_RULES_STATE_FILE, "w");
    if (!fp) {
        return;
    }
    fprintf(fp, "1\n");
    fclose(fp);
}
#define PC_PERMISSION_UNLIMITED "unlimited"
#define PC_PERMISSION_APP_LIMITED "app_limited"
#define PC_PERMISSION_MAC_BLOCKED "mac_blocked"

static const char *map_pc_status_key(const char *status_token)
{
    if (!status_token || status_token[0] == '\0') {
        return PC_PERMISSION_UNLIMITED;
    }
    if (strcmp(status_token, PC_PERMISSION_MAC_BLOCKED) == 0) {
        return PC_PERMISSION_MAC_BLOCKED;
    }
    if (strcmp(status_token, PC_PERMISSION_APP_LIMITED) == 0) {
        return PC_PERMISSION_APP_LIMITED;
    }
    return PC_PERMISSION_UNLIMITED;
}

static void load_parental_control_status(all_users_info_t *au_info)
{
    FILE *fp = NULL;
    char line[128] = {0};

    if (!au_info) {
        return;
    }

    au_info->pc_status_num = 0;
    fp = fopen(USER_PARENTAL_CONTROL_STATUS_FILE, "r");
    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char mac[32] = {0};
        char status[32] = {0};
        if (sscanf(line, "%31s %31s", mac, status) != 2) {
            continue;
        }
        if (au_info->pc_status_num >= MAX_SUPPORT_DEV_NUM) {
            break;
        }
        strncpy(au_info->pc_status_items[au_info->pc_status_num].mac, mac,
                sizeof(au_info->pc_status_items[au_info->pc_status_num].mac) - 1);
        strncpy(au_info->pc_status_items[au_info->pc_status_num].status, status,
                sizeof(au_info->pc_status_items[au_info->pc_status_num].status) - 1);
        au_info->pc_status_num++;
    }

    fclose(fp);
}

static void load_mac_blacklist(all_users_info_t *au_info)
{
    if (!au_info) {
        return;
    }

    au_info->blacklist_num = 0;
    memset(au_info->blacklist_macs, 0, sizeof(au_info->blacklist_macs));
    au_info->blacklist_num = load_mac_blacklist_items(au_info->blacklist_macs, MAX_SUPPORT_DEV_NUM);
}

static void load_user_session_count(all_users_info_t *au_info)
{
    FILE *fp = NULL;
    char line[256] = {0};

    if (!au_info) {
        return;
    }

    au_info->session_num = 0;
    memset(au_info->session_items, 0, sizeof(au_info->session_items));

    fp = fopen(FWX_USER_SESSION_PROC_PATH, "r");
    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        int id = 0;
        int conn_count = 0;
        int session_count = 0;
        char mac[32] = {0};

        if (sscanf(line, "%d %31s %d %d", &id, mac, &conn_count, &session_count) != 4) {
            continue;
        }

        if (au_info->session_num >= MAX_SUPPORT_DEV_NUM) {
            break;
        }

        strncpy(au_info->session_items[au_info->session_num].mac, mac,
                sizeof(au_info->session_items[au_info->session_num].mac) - 1);
        au_info->session_items[au_info->session_num].conn_count = conn_count;
        au_info->session_num++;
    }

    fclose(fp);
}

static int get_session_count_for_mac(all_users_info_t *au_info, const char *mac)
{
    int i;

    if (!au_info || !mac || mac[0] == '\0') {
        return 0;
    }

    for (i = 0; i < au_info->session_num; i++) {
        if (strcasecmp(au_info->session_items[i].mac, mac) == 0) {
            return au_info->session_items[i].conn_count;
        }
    }

    return 0;
}

static int is_blacklist_mac(all_users_info_t *au_info, const char *mac)
{
    int i;

    if (!au_info || !mac || mac[0] == '\0') {
        return 0;
    }

    for (i = 0; i < au_info->blacklist_num; i++) {
        if (strcasecmp(au_info->blacklist_macs[i], mac) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_mac_in_blacklist_uci(const char *mac)
{
    struct uci_context *uci_ctx = NULL;
    char list_buf[4096] = {0};
    char *token = NULL;
    char *saveptr = NULL;
    int matched = 0;

    if (!mac || mac[0] == '\0') {
        return 0;
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return 0;
    }

    if (fwx_uci_get_list_value(uci_ctx, "mac_blacklist.base.mac_list", list_buf, sizeof(list_buf), " ") == 0 &&
        list_buf[0] != '\0') {
        token = strtok_r(list_buf, " ", &saveptr);
        while (token) {
            if (strcasecmp(token, mac) == 0) {
                matched = 1;
                break;
            }
            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    uci_free_context(uci_ctx);
    return matched;
}

static int is_mac_in_whitelist_config(const char *config, const char *mac)
{
    struct uci_context *uci_ctx = NULL;
    char mac_path[128] = {0};
    char mac_str[32] = {0};
    int num = 0;
    int i;
    int matched = 0;

    if (!config || !mac || config[0] == '\0' || mac[0] == '\0') {
        return 0;
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return 0;
    }

    snprintf(mac_path, sizeof(mac_path), "%s.@whitelist_mac[%%d].mac", config);
    num = fwx_uci_get_list_num(uci_ctx, config, "whitelist_mac");
    for (i = 0; i < num; i++) {
        memset(mac_str, 0, sizeof(mac_str));
        fwx_uci_get_array_value(uci_ctx, mac_path, i, mac_str, sizeof(mac_str));
        if (mac_str[0] != '\0' && strcasecmp(mac_str, mac) == 0) {
            matched = 1;
            break;
        }
    }

    uci_free_context(uci_ctx);
    return matched;
}

static int is_appfilter_whitelist_mac(const char *mac)
{
    return is_mac_in_whitelist_config("appfilter_whitelist", mac);
}

static int is_macfilter_whitelist_mac(const char *mac)
{
    return is_mac_in_whitelist_config("macfilter_whitelist", mac);
}

static const char *apply_whitelist_pc_status(const char *status_key, int af_whitelist, int mf_whitelist)
{
    if (!status_key || status_key[0] == '\0') {
        return PC_PERMISSION_UNLIMITED;
    }
    if (af_whitelist && strcmp(status_key, PC_PERMISSION_APP_LIMITED) == 0) {
        return PC_PERMISSION_UNLIMITED;
    }
    if (mf_whitelist && strcmp(status_key, PC_PERMISSION_MAC_BLOCKED) == 0) {
        return PC_PERMISSION_UNLIMITED;
    }
    return status_key;
}

static struct json_object *build_blacklist_rule_detail(const char *mac)
{
    struct json_object *rule_obj = json_object_new_object();
    if (!rule_obj) {
        return NULL;
    }

    json_object_object_add(rule_obj, "rule_id", json_object_new_int(BLACKLIST_MAC_FILTER_RULE_ID));
    json_object_object_add(rule_obj, "rule_name", json_object_new_string(BLACKLIST_RULE_NAME));
    json_object_object_add(rule_obj, "mode", json_object_new_int(2));
    json_object_object_add(rule_obj, "time_mode", json_object_new_int(1));
    json_object_object_add(rule_obj, "user_mac", json_object_new_string(mac ? mac : ""));
    json_object_object_add(rule_obj, "match_type", json_object_new_string("blacklist"));
    return rule_obj;
}

static const char *get_pc_status_for_mac(all_users_info_t *au_info, const char *mac)
{
    int i;

    if (!au_info || !mac || mac[0] == '\0') {
        return PC_PERMISSION_UNLIMITED;
    }

    if (is_blacklist_mac(au_info, mac)) {
        return PC_PERMISSION_MAC_BLOCKED;
    }

    for (i = 0; i < au_info->pc_status_num; i++) {
        if (strcasecmp(au_info->pc_status_items[i].mac, mac) == 0) {
            return map_pc_status_key(au_info->pc_status_items[i].status);
        }
    }
    return PC_PERMISSION_UNLIMITED;
}

static const char *get_pc_status_key_for_mac(all_users_info_t *au_info, const char *mac)
{
    int i;

    if (!au_info || !mac || mac[0] == '\0') {
        return PC_PERMISSION_UNLIMITED;
    }

    if (is_blacklist_mac(au_info, mac)) {
        return PC_PERMISSION_MAC_BLOCKED;
    }

    for (i = 0; i < au_info->pc_status_num; i++) {
        if (strcasecmp(au_info->pc_status_items[i].mac, mac) == 0) {
            if (strcmp(au_info->pc_status_items[i].status, PC_PERMISSION_MAC_BLOCKED) == 0) {
                return PC_PERMISSION_MAC_BLOCKED;
            }
            if (strcmp(au_info->pc_status_items[i].status, PC_PERMISSION_APP_LIMITED) == 0) {
                return PC_PERMISSION_APP_LIMITED;
            }
            break;
        }
    }

    return PC_PERMISSION_UNLIMITED;
}

static struct json_object *find_user_detail_by_mac(struct json_object *users_obj, const char *mac)
{
    struct json_object *user_obj = NULL;
    if (!users_obj || !mac || mac[0] == '\0') {
        return NULL;
    }

    if (json_object_object_get_ex(users_obj, mac, &user_obj)) {
        return user_obj;
    }

    json_object_object_foreach(users_obj, key, val) {
        if (key && val && strcasecmp(key, mac) == 0) {
            return val;
        }
    }

    return NULL;
}

static void pc_get_current_time_context(int *current_weekday, int *current_minutes)
{
    time_t now = time(NULL);
    struct tm now_tm;

    if (!current_weekday || !current_minutes) {
        return;
    }

    *current_weekday = 0;
    *current_minutes = 0;
    if (localtime_r(&now, &now_tm) == NULL) {
        return;
    }
    *current_weekday = now_tm.tm_wday;
    *current_minutes = now_tm.tm_hour * 60 + now_tm.tm_min;
}

static int pc_parse_time_minutes(const char *time_str, int *minutes)
{
    int hour = 0;
    int minute = 0;

    if (!time_str || !minutes) {
        return -1;
    }

    if (sscanf(time_str, "%d:%d", &hour, &minute) != 2) {
        return -1;
    }
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
        return -1;
    }

    *minutes = hour * 60 + minute;
    return 0;
}

static int pc_weekday_in_list(struct json_object *weekdays_obj, int target_weekday)
{
    int i;
    int len;

    if (!weekdays_obj || !json_object_is_type(weekdays_obj, json_type_array)) {
        return 0;
    }

    len = json_object_array_length(weekdays_obj);
    for (i = 0; i < len; i++) {
        struct json_object *day_obj = json_object_array_get_idx(weekdays_obj, i);
        if (day_obj && json_object_get_int(day_obj) == target_weekday) {
            return 1;
        }
    }
    return 0;
}

static int pc_is_time_rule_matched(struct json_object *time_rules_obj, int current_weekday, int current_minutes)
{
    int i;
    int len;
    int prev_weekday = (current_weekday + 6) % 7;

    if (!time_rules_obj || !json_object_is_type(time_rules_obj, json_type_array)) {
        return 0;
    }

    len = json_object_array_length(time_rules_obj);
    for (i = 0; i < len; i++) {
        struct json_object *rule_obj = json_object_array_get_idx(time_rules_obj, i);
        struct json_object *weekdays_obj = NULL;
        struct json_object *start_time_obj = NULL;
        struct json_object *end_time_obj = NULL;
        const char *start_time_str = NULL;
        const char *end_time_str = NULL;
        int start_minutes = 0;
        int end_minutes = 0;

        if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
            continue;
        }

        if (!json_object_object_get_ex(rule_obj, "weekdays", &weekdays_obj)) {
            continue;
        }
        if (!json_object_object_get_ex(rule_obj, "start_time", &start_time_obj) ||
            !json_object_object_get_ex(rule_obj, "end_time", &end_time_obj)) {
            continue;
        }

        start_time_str = json_object_get_string(start_time_obj);
        end_time_str = json_object_get_string(end_time_obj);
        if (pc_parse_time_minutes(start_time_str, &start_minutes) != 0 ||
            pc_parse_time_minutes(end_time_str, &end_minutes) != 0) {
            continue;
        }

        if (start_minutes <= end_minutes) {
            if (pc_weekday_in_list(weekdays_obj, current_weekday) &&
                current_minutes >= start_minutes &&
                current_minutes <= end_minutes) {
                return 1;
            }
        } else {
            if (pc_weekday_in_list(weekdays_obj, current_weekday) &&
                current_minutes >= start_minutes) {
                return 1;
            }
            if (pc_weekday_in_list(weekdays_obj, prev_weekday) &&
                current_minutes <= end_minutes) {
                return 1;
            }
        }
    }

    return 0;
}

static void pc_get_today_limit(struct json_object *time_rules_obj, const char *field_key, int current_weekday,
                               int *has_today_rule, double *limit_value, int *has_unlimited)
{
    int i;
    int len;
    int found_limit = 0;
    double min_limit = 0.0;

    if (has_today_rule) {
        *has_today_rule = 0;
    }
    if (limit_value) {
        *limit_value = 0.0;
    }
    if (has_unlimited) {
        *has_unlimited = 0;
    }

    if (!time_rules_obj || !json_object_is_type(time_rules_obj, json_type_array) ||
        !field_key || field_key[0] == '\0' || !has_today_rule || !limit_value || !has_unlimited) {
        return;
    }

    len = json_object_array_length(time_rules_obj);
    for (i = 0; i < len; i++) {
        struct json_object *rule_obj = json_object_array_get_idx(time_rules_obj, i);
        struct json_object *weekdays_obj = NULL;
        struct json_object *value_obj = NULL;
        double value = 0.0;

        if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
            continue;
        }

        if (!json_object_object_get_ex(rule_obj, "weekdays", &weekdays_obj)) {
            continue;
        }
        if (!pc_weekday_in_list(weekdays_obj, current_weekday)) {
            continue;
        }

        *has_today_rule = 1;
        if (json_object_object_get_ex(rule_obj, field_key, &value_obj)) {
            value = json_object_get_double(value_obj);
        }

        if (value <= 0.0) {
            *has_unlimited = 1;
            *limit_value = 0.0;
            return;
        }

        if (!found_limit || value < min_limit) {
            min_limit = value;
            found_limit = 1;
        }
    }

    if (found_limit) {
        *limit_value = min_limit;
    }
}

static int pc_is_rule_enabled(struct json_object *rule_obj)
{
    struct json_object *enabled_obj = NULL;
    int enabled = 1;

    if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
        return 0;
    }
    if (json_object_object_get_ex(rule_obj, "enabled", &enabled_obj)) {
        enabled = json_object_get_int(enabled_obj);
    }
    return enabled == 1 ? 1 : 0;
}

static int count_enabled_uci_rules(const char *package_name)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *e = NULL;
    int count = 0;

    if (!package_name || package_name[0] == '\0') {
        return 0;
    }

    ctx = uci_alloc_context();
    if (!ctx) {
        return 0;
    }

    if (uci_load(ctx, package_name, &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return 0;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *section = uci_to_section(e);
        struct uci_option *enabled_opt = NULL;
        int enabled = 1;

        if (!section || strcmp(section->type, "rule") != 0) {
            continue;
        }

        enabled_opt = uci_lookup_option(ctx, section, "enabled");
        if (enabled_opt && enabled_opt->type == UCI_TYPE_STRING && enabled_opt->v.string) {
            enabled = atoi(enabled_opt->v.string);
        }

        if (enabled == 1) {
            count++;
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return count;
}

static int count_app_visit_record_rows(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char db_path[512] = {0};
    int count = 0;
    int rc = SQLITE_OK;

    snprintf(db_path, sizeof(db_path), "%s/client.db", get_history_data_root_dir());
    if (access(db_path, F_OK) != 0) {
        return 0;
    }

    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK || !db) {
        if (db) {
            sqlite3_close(db);
        }
        return 0;
    }

    rc = sqlite3_prepare_v2(db, "SELECT COUNT(1) FROM app_visit_record;", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    if (stmt) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return count;
}

static const char *json_get_string_value(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value) {
        return "";
    }

    return json_object_get_string(value);
}

static int json_get_int_value(struct json_object *obj, const char *key, int default_value)
{
    struct json_object *value = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value) {
        return default_value;
    }

    return json_object_get_int(value);
}

static void build_dashboard_version(struct json_object *system_status, char *version, size_t len)
{
    const char *openwrt_version = json_get_string_value(system_status, "openwrt_version");
    const char *fwx_version = json_get_string_value(system_status, "fwx_version");
    const char *release_date = json_get_string_value(system_status, "release_date");
    int release_type = json_get_int_value(system_status, "release_type", 0);
    char openwrt_display[96] = {0};

    if (!version || len == 0) {
        return;
    }

    version[0] = '\0';
    if (openwrt_version && strcmp(openwrt_version, "SNAPSHOT") == 0 && release_date && release_date[0]) {
        snprintf(openwrt_display, sizeof(openwrt_display), "s%s", release_date);
    } else if (openwrt_version && openwrt_version[0]) {
        snprintf(openwrt_display, sizeof(openwrt_display), "%s", openwrt_version);
    }

    if (openwrt_display[0] && fwx_version && fwx_version[0]) {
        snprintf(version, len, "%s-%s", openwrt_display, fwx_version);
    } else if (openwrt_display[0]) {
        snprintf(version, len, "%s", openwrt_display);
    } else if (fwx_version && fwx_version[0]) {
        snprintf(version, len, "%s", fwx_version);
    } else {
        snprintf(version, len, "--");
    }

    if (strcmp(version, "--") != 0) {
        size_t used = strlen(version);
        if (release_type == 1 && used + strlen("(alpha)") + 1 < len) {
            strncat(version, "(alpha)", len - used - 1);
        } else if (release_type == 2 && used + strlen("(beta)") + 1 < len) {
            strncat(version, "(beta)", len - used - 1);
        }
    }
}

static int pc_is_rule_applicable(struct json_object *rule_obj, const char *target_mac)
{
    struct json_object *mode_obj = NULL;
    struct json_object *user_mac_obj = NULL;
    const char *user_mac = NULL;
    int mode = 1;

    if (!rule_obj || !json_object_is_type(rule_obj, json_type_object) || !target_mac || target_mac[0] == '\0') {
        return 0;
    }

    if (json_object_object_get_ex(rule_obj, "mode", &mode_obj)) {
        mode = json_object_get_int(mode_obj);
    }
    if (json_object_object_get_ex(rule_obj, "user_mac", &user_mac_obj)) {
        user_mac = json_object_get_string(user_mac_obj);
    }

    if (mode == 1) {
        return 1;
    }
    if (mode == 2) {
        return (user_mac && user_mac[0] != '\0' && strcasecmp(user_mac, target_mac) == 0) ? 1 : 0;
    }

    if (!user_mac || user_mac[0] == '\0') {
        return 1;
    }
    return strcasecmp(user_mac, target_mac) == 0 ? 1 : 0;
}

static struct json_object *pc_build_appfilter_rule(struct json_object *rule_obj, int current_weekday, int current_minutes)
{
    struct json_object *out_obj = NULL;
    struct json_object *condition_obj = NULL;
    struct json_object *status_obj = NULL;
    struct json_object *time_rules_obj = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *name_obj = NULL;
    const char *rule_name = "";
    int rule_id = 0;
    int matched = 0;
    const char *permission_key = PC_PERMISSION_UNLIMITED;

    if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
        return NULL;
    }

    json_object_object_get_ex(rule_obj, "id", &id_obj);
    json_object_object_get_ex(rule_obj, "name", &name_obj);
    json_object_object_get_ex(rule_obj, "time_rules", &time_rules_obj);
    rule_id = id_obj ? json_object_get_int(id_obj) : 0;
    rule_name = name_obj ? json_object_get_string(name_obj) : "";
    if (!rule_name) {
        rule_name = "";
    }

    matched = pc_is_time_rule_matched(time_rules_obj, current_weekday, current_minutes);
    if (matched) {
        permission_key = PC_PERMISSION_APP_LIMITED;
    }

    out_obj = json_object_new_object();
    condition_obj = json_object_new_object();
    status_obj = json_object_new_object();
    if (!out_obj || !condition_obj || !status_obj) {
        if (out_obj) json_object_put(out_obj);
        if (condition_obj) json_object_put(condition_obj);
        if (status_obj) json_object_put(status_obj);
        return NULL;
    }

    json_object_object_add(out_obj, "module", json_object_new_string("appfilter"));
    json_object_object_add(out_obj, "rule_id", json_object_new_int(rule_id));
    json_object_object_add(out_obj, "rule_name", json_object_new_string(rule_name));
    json_object_object_add(out_obj, "condition_type", json_object_new_string("time_range"));
    json_object_object_add(condition_obj, "time_rules",
        (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) ?
            json_object_get(time_rules_obj) : json_object_new_array());
    json_object_object_add(out_obj, "condition", condition_obj);

    json_object_object_add(status_obj, "matched", json_object_new_int(matched));
    json_object_object_add(out_obj, "today_status", status_obj);
    json_object_object_add(out_obj, "permission_key", json_object_new_string(permission_key));
    json_object_object_add(out_obj, "permission_text", json_object_new_string(permission_key));
    return out_obj;
}

static struct json_object *pc_build_macfilter_rule(struct json_object *rule_obj,
                                                   unsigned long long today_active_time,
                                                   unsigned long long today_up_bytes,
                                                   unsigned long long today_down_bytes,
                                                   int current_weekday,
                                                   int current_minutes)
{
    struct json_object *out_obj = NULL;
    struct json_object *condition_obj = NULL;
    struct json_object *status_obj = NULL;
    struct json_object *time_rules_obj = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *name_obj = NULL;
    struct json_object *time_mode_obj = NULL;
    const char *rule_name = "";
    const char *permission_key = PC_PERMISSION_UNLIMITED;
    int rule_id = 0;
    int time_mode = 1;
    int used_minutes = (int)(today_active_time / 60);
    double used_flow_mb = ((double)(today_up_bytes + today_down_bytes)) / (1024.0 * 1024.0);

    if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
        return NULL;
    }

    json_object_object_get_ex(rule_obj, "id", &id_obj);
    json_object_object_get_ex(rule_obj, "name", &name_obj);
    json_object_object_get_ex(rule_obj, "time_mode", &time_mode_obj);
    json_object_object_get_ex(rule_obj, "time_rules", &time_rules_obj);

    rule_id = id_obj ? json_object_get_int(id_obj) : 0;
    rule_name = name_obj ? json_object_get_string(name_obj) : "";
    if (!rule_name) {
        rule_name = "";
    }
    if (time_mode_obj) {
        time_mode = json_object_get_int(time_mode_obj);
    }

    used_flow_mb = ((double)((long long)(used_flow_mb * 100.0 + 0.5))) / 100.0;

    out_obj = json_object_new_object();
    condition_obj = json_object_new_object();
    status_obj = json_object_new_object();
    if (!out_obj || !condition_obj || !status_obj) {
        if (out_obj) json_object_put(out_obj);
        if (condition_obj) json_object_put(condition_obj);
        if (status_obj) json_object_put(status_obj);
        return NULL;
    }

    json_object_object_add(out_obj, "module", json_object_new_string("macfilter"));
    json_object_object_add(out_obj, "rule_id", json_object_new_int(rule_id));
    json_object_object_add(out_obj, "rule_name", json_object_new_string(rule_name));

    if (time_mode == 2) {
        int has_today_rule = 0;
        int has_unlimited = 0;
        int exceeded = 0;
        int progress_percent = 0;
        double limit_value = 0.0;
        int limit_minutes = 0;

        pc_get_today_limit(time_rules_obj, "duration_minutes", current_weekday,
                           &has_today_rule, &limit_value, &has_unlimited);
        limit_minutes = (int)(limit_value + 0.5);
        if (has_today_rule && !has_unlimited && limit_minutes > 0) {
            exceeded = (used_minutes > limit_minutes) ? 1 : 0;
            progress_percent = (int)(((double)used_minutes / (double)limit_minutes) * 100.0 + 0.5);
            if (progress_percent < 0) {
                progress_percent = 0;
            } else if (progress_percent > 100) {
                progress_percent = 100;
            }
        }
        if (has_today_rule && !has_unlimited && limit_minutes > 0 && exceeded) {
            permission_key = PC_PERMISSION_MAC_BLOCKED;
        }

        json_object_object_add(out_obj, "condition_type", json_object_new_string("duration"));
        json_object_object_add(condition_obj, "duration_rules",
            (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) ?
                json_object_get(time_rules_obj) : json_object_new_array());
        json_object_object_add(status_obj, "used", json_object_new_int(used_minutes));
        json_object_object_add(status_obj, "limit", json_object_new_int(limit_minutes));
        json_object_object_add(status_obj, "progress_percent", json_object_new_int(progress_percent));
        json_object_object_add(status_obj, "effective_today", json_object_new_int(has_today_rule));
        json_object_object_add(status_obj, "exceeded", json_object_new_int(exceeded));
        json_object_object_add(status_obj, "unlimited", json_object_new_int(has_unlimited));
    } else if (time_mode == 3) {
        int has_today_rule = 0;
        int has_unlimited = 0;
        int exceeded = 0;
        int progress_percent = 0;
        double limit_value = 0.0;

        pc_get_today_limit(time_rules_obj, "flow_mb", current_weekday,
                           &has_today_rule, &limit_value, &has_unlimited);
        if (has_today_rule && !has_unlimited && limit_value > 0.0) {
            exceeded = (used_flow_mb > limit_value) ? 1 : 0;
            progress_percent = (int)((used_flow_mb / limit_value) * 100.0 + 0.5);
            if (progress_percent < 0) {
                progress_percent = 0;
            } else if (progress_percent > 100) {
                progress_percent = 100;
            }
        }
        if (has_today_rule && !has_unlimited && limit_value > 0.0 && exceeded) {
            permission_key = PC_PERMISSION_MAC_BLOCKED;
        }

        json_object_object_add(out_obj, "condition_type", json_object_new_string("flow"));
        json_object_object_add(condition_obj, "flow_rules",
            (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) ?
                json_object_get(time_rules_obj) : json_object_new_array());
        json_object_object_add(status_obj, "used", json_object_new_double(used_flow_mb));
        json_object_object_add(status_obj, "limit", json_object_new_double(limit_value));
        json_object_object_add(status_obj, "progress_percent", json_object_new_int(progress_percent));
        json_object_object_add(status_obj, "effective_today", json_object_new_int(has_today_rule));
        json_object_object_add(status_obj, "exceeded", json_object_new_int(exceeded));
        json_object_object_add(status_obj, "unlimited", json_object_new_int(has_unlimited));
    } else {
        int matched = pc_is_time_rule_matched(time_rules_obj, current_weekday, current_minutes);
        if (matched) {
            permission_key = PC_PERMISSION_MAC_BLOCKED;
        }

        json_object_object_add(out_obj, "condition_type", json_object_new_string("time_range"));
        json_object_object_add(condition_obj, "time_rules",
            (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) ?
                json_object_get(time_rules_obj) : json_object_new_array());
        json_object_object_add(status_obj, "matched", json_object_new_int(matched));
    }

    json_object_object_add(out_obj, "condition", condition_obj);
    json_object_object_add(out_obj, "today_status", status_obj);
    json_object_object_add(out_obj, "permission_key", json_object_new_string(permission_key));
    json_object_object_add(out_obj, "permission_text", json_object_new_string(permission_key));
    return out_obj;
}

static struct json_object *pc_build_blacklist_rule(const char *target_mac)
{
    struct json_object *out_obj = NULL;
    struct json_object *condition_obj = NULL;
    struct json_object *status_obj = NULL;

    (void)target_mac;

    out_obj = json_object_new_object();
    condition_obj = json_object_new_object();
    status_obj = json_object_new_object();
    if (!out_obj || !condition_obj || !status_obj) {
        if (out_obj) json_object_put(out_obj);
        if (condition_obj) json_object_put(condition_obj);
        if (status_obj) json_object_put(status_obj);
        return NULL;
    }

    json_object_object_add(out_obj, "module", json_object_new_string("blacklist"));
    json_object_object_add(out_obj, "rule_id", json_object_new_int(BLACKLIST_MAC_FILTER_RULE_ID));
    json_object_object_add(out_obj, "rule_name", json_object_new_string(BLACKLIST_RULE_NAME));
    json_object_object_add(out_obj, "condition_type", json_object_new_string("blacklist"));
    json_object_object_add(out_obj, "condition", condition_obj);
    json_object_object_add(status_obj, "matched", json_object_new_int(1));
    json_object_object_add(out_obj, "today_status", status_obj);
    json_object_object_add(out_obj, "permission_key", json_object_new_string(PC_PERMISSION_MAC_BLOCKED));
    json_object_object_add(out_obj, "permission_text", json_object_new_string(PC_PERMISSION_MAC_BLOCKED));
    return out_obj;
}

static struct json_object *pc_get_array_field(struct json_object *src_obj, const char *key)
{
    struct json_object *arr_obj = NULL;

    if (!src_obj || !key || key[0] == '\0') {
        return json_object_new_array();
    }
    if (json_object_object_get_ex(src_obj, key, &arr_obj) &&
        json_object_is_type(arr_obj, json_type_array)) {
        return json_object_get(arr_obj);
    }
    return json_object_new_array();
}

static struct json_object *pc_build_cached_appfilter_rule(struct json_object *detail_obj)
{
    struct json_object *out_obj = NULL;
    struct json_object *condition_obj = NULL;
    struct json_object *status_obj = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *name_obj = NULL;
    const char *rule_name = "";
    int rule_id = 0;

    if (!detail_obj || !json_object_is_type(detail_obj, json_type_object)) {
        return NULL;
    }

    json_object_object_get_ex(detail_obj, "rule_id", &id_obj);
    json_object_object_get_ex(detail_obj, "rule_name", &name_obj);
    rule_id = id_obj ? json_object_get_int(id_obj) : 0;
    rule_name = name_obj ? json_object_get_string(name_obj) : "";
    if (!rule_name) {
        rule_name = "";
    }

    out_obj = json_object_new_object();
    condition_obj = json_object_new_object();
    status_obj = json_object_new_object();
    if (!out_obj || !condition_obj || !status_obj) {
        if (out_obj) json_object_put(out_obj);
        if (condition_obj) json_object_put(condition_obj);
        if (status_obj) json_object_put(status_obj);
        return NULL;
    }

    json_object_object_add(out_obj, "module", json_object_new_string("appfilter"));
    json_object_object_add(out_obj, "rule_id", json_object_new_int(rule_id));
    json_object_object_add(out_obj, "rule_name", json_object_new_string(rule_name));
    json_object_object_add(out_obj, "condition_type", json_object_new_string("time_range"));
    json_object_object_add(condition_obj, "time_rules", pc_get_array_field(detail_obj, "time_rules"));
    json_object_object_add(out_obj, "condition", condition_obj);
    json_object_object_add(status_obj, "matched", json_object_new_int(1));
    json_object_object_add(out_obj, "today_status", status_obj);
    json_object_object_add(out_obj, "permission_key", json_object_new_string(PC_PERMISSION_APP_LIMITED));
    json_object_object_add(out_obj, "permission_text", json_object_new_string(PC_PERMISSION_APP_LIMITED));
    return out_obj;
}

static struct json_object *pc_build_cached_macfilter_rule(struct json_object *detail_obj)
{
    struct json_object *out_obj = NULL;
    struct json_object *condition_obj = NULL;
    struct json_object *status_obj = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *name_obj = NULL;
    struct json_object *match_type_obj = NULL;
    struct json_object *used_obj = NULL;
    struct json_object *limit_obj = NULL;
    const char *rule_name = "";
    const char *match_type = "time_range";
    const char *module = "macfilter";
    int rule_id = 0;

    if (!detail_obj || !json_object_is_type(detail_obj, json_type_object)) {
        return NULL;
    }

    json_object_object_get_ex(detail_obj, "rule_id", &id_obj);
    json_object_object_get_ex(detail_obj, "rule_name", &name_obj);
    json_object_object_get_ex(detail_obj, "match_type", &match_type_obj);
    rule_id = id_obj ? json_object_get_int(id_obj) : 0;
    rule_name = name_obj ? json_object_get_string(name_obj) : "";
    match_type = match_type_obj ? json_object_get_string(match_type_obj) : "time_range";
    if (!rule_name) rule_name = "";
    if (!match_type || match_type[0] == '\0') match_type = "time_range";
    if (strcmp(match_type, "blacklist") == 0) module = "blacklist";

    out_obj = json_object_new_object();
    condition_obj = json_object_new_object();
    status_obj = json_object_new_object();
    if (!out_obj || !condition_obj || !status_obj) {
        if (out_obj) json_object_put(out_obj);
        if (condition_obj) json_object_put(condition_obj);
        if (status_obj) json_object_put(status_obj);
        return NULL;
    }

    json_object_object_add(out_obj, "module", json_object_new_string(module));
    json_object_object_add(out_obj, "rule_id", json_object_new_int(rule_id));
    json_object_object_add(out_obj, "rule_name", json_object_new_string(rule_name));

    if (strcmp(match_type, "duration") == 0) {
        int used_minutes = 0;
        int limit_minutes = 0;
        int progress_percent = 0;

        json_object_object_get_ex(detail_obj, "used_minutes", &used_obj);
        json_object_object_get_ex(detail_obj, "limit_minutes", &limit_obj);
        used_minutes = used_obj ? json_object_get_int(used_obj) : 0;
        limit_minutes = limit_obj ? json_object_get_int(limit_obj) : 0;
        if (limit_minutes > 0) {
            progress_percent = (int)(((double)used_minutes / (double)limit_minutes) * 100.0 + 0.5);
            if (progress_percent < 0) progress_percent = 0;
            if (progress_percent > 100) progress_percent = 100;
        }

        json_object_object_add(out_obj, "condition_type", json_object_new_string("duration"));
        json_object_object_add(condition_obj, "duration_rules", pc_get_array_field(detail_obj, "duration_rules"));
        json_object_object_add(status_obj, "used", json_object_new_int(used_minutes));
        json_object_object_add(status_obj, "limit", json_object_new_int(limit_minutes));
        json_object_object_add(status_obj, "progress_percent", json_object_new_int(progress_percent));
        json_object_object_add(status_obj, "effective_today", json_object_new_int(1));
        json_object_object_add(status_obj, "exceeded", json_object_new_int(1));
        json_object_object_add(status_obj, "unlimited", json_object_new_int(0));
    } else if (strcmp(match_type, "flow") == 0) {
        double used_mb = 0.0;
        double limit_mb = 0.0;
        int progress_percent = 0;

        json_object_object_get_ex(detail_obj, "used_mb", &used_obj);
        json_object_object_get_ex(detail_obj, "limit_mb", &limit_obj);
        used_mb = used_obj ? json_object_get_double(used_obj) : 0.0;
        limit_mb = limit_obj ? json_object_get_double(limit_obj) : 0.0;
        if (limit_mb > 0.0) {
            progress_percent = (int)((used_mb / limit_mb) * 100.0 + 0.5);
            if (progress_percent < 0) progress_percent = 0;
            if (progress_percent > 100) progress_percent = 100;
        }

        json_object_object_add(out_obj, "condition_type", json_object_new_string("flow"));
        json_object_object_add(condition_obj, "flow_rules", pc_get_array_field(detail_obj, "flow_rules"));
        json_object_object_add(status_obj, "used", json_object_new_double(used_mb));
        json_object_object_add(status_obj, "limit", json_object_new_double(limit_mb));
        json_object_object_add(status_obj, "progress_percent", json_object_new_int(progress_percent));
        json_object_object_add(status_obj, "effective_today", json_object_new_int(1));
        json_object_object_add(status_obj, "exceeded", json_object_new_int(1));
        json_object_object_add(status_obj, "unlimited", json_object_new_int(0));
    } else if (strcmp(match_type, "blacklist") == 0) {
        json_object_object_add(out_obj, "condition_type", json_object_new_string("blacklist"));
        json_object_object_add(status_obj, "matched", json_object_new_int(1));
    } else {
        json_object_object_add(out_obj, "condition_type", json_object_new_string("time_range"));
        json_object_object_add(condition_obj, "time_rules", pc_get_array_field(detail_obj, "time_rules"));
        json_object_object_add(status_obj, "matched", json_object_new_int(1));
    }

    json_object_object_add(out_obj, "condition", condition_obj);
    json_object_object_add(out_obj, "today_status", status_obj);
    json_object_object_add(out_obj, "permission_key", json_object_new_string(PC_PERMISSION_MAC_BLOCKED));
    json_object_object_add(out_obj, "permission_text", json_object_new_string(PC_PERMISSION_MAC_BLOCKED));
    return out_obj;
}

static int pc_add_cached_rules(struct json_object *list_obj, struct json_object *rules_obj, int appfilter)
{
    int i;
    int len;
    int count = 0;

    if (!list_obj || !rules_obj || !json_object_is_type(rules_obj, json_type_array)) {
        return 0;
    }

    len = json_object_array_length(rules_obj);
    for (i = 0; i < len; i++) {
        struct json_object *detail_obj = json_object_array_get_idx(rules_obj, i);
        struct json_object *item_obj = appfilter ?
            pc_build_cached_appfilter_rule(detail_obj) : pc_build_cached_macfilter_rule(detail_obj);
        if (item_obj) {
            json_object_array_add(list_obj, item_obj);
            count++;
        }
    }

    return count;
}

static int pc_append_array_items(struct json_object *dst_obj, struct json_object *src_obj)
{
    int i;
    int len;
    int count = 0;

    if (!dst_obj || !src_obj || !json_object_is_type(dst_obj, json_type_array) ||
        !json_object_is_type(src_obj, json_type_array)) {
        return 0;
    }

    len = json_object_array_length(src_obj);
    for (i = 0; i < len; i++) {
        struct json_object *item_obj = json_object_array_get_idx(src_obj, i);
        if (item_obj && json_object_is_type(item_obj, json_type_object)) {
            json_object_array_add(dst_obj, json_object_get(item_obj));
            count++;
        }
    }

    return count;
}

static struct json_object *pc_build_appfilter_rule_detail_summary(struct json_object *rule_obj)
{
    struct json_object *detail_obj = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *name_obj = NULL;
    struct json_object *mode_obj = NULL;
    struct json_object *user_mac_obj = NULL;
    struct json_object *time_rules_obj = NULL;
    struct json_object *app_ids_obj = NULL;
    const char *rule_name = "";
    const char *user_mac = "";
    int app_count = 0;

    if (!rule_obj || !json_object_is_type(rule_obj, json_type_object)) {
        return NULL;
    }

    detail_obj = json_object_new_object();
    if (!detail_obj) {
        return NULL;
    }

    json_object_object_get_ex(rule_obj, "id", &id_obj);
    json_object_object_get_ex(rule_obj, "name", &name_obj);
    json_object_object_get_ex(rule_obj, "mode", &mode_obj);
    json_object_object_get_ex(rule_obj, "user_mac", &user_mac_obj);
    json_object_object_get_ex(rule_obj, "time_rules", &time_rules_obj);
    json_object_object_get_ex(rule_obj, "app_ids", &app_ids_obj);

    rule_name = name_obj ? json_object_get_string(name_obj) : "";
    user_mac = user_mac_obj ? json_object_get_string(user_mac_obj) : "";
    if (!rule_name) rule_name = "";
    if (!user_mac) user_mac = "";
    if (app_ids_obj && json_object_is_type(app_ids_obj, json_type_array)) {
        app_count = json_object_array_length(app_ids_obj);
    }

    json_object_object_add(detail_obj, "rule_id", json_object_new_int(id_obj ? json_object_get_int(id_obj) : 0));
    json_object_object_add(detail_obj, "rule_name", json_object_new_string(rule_name));
    json_object_object_add(detail_obj, "mode", json_object_new_int(mode_obj ? json_object_get_int(mode_obj) : 1));
    json_object_object_add(detail_obj, "user_mac", json_object_new_string(user_mac));
    json_object_object_add(detail_obj, "time_rules",
        (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) ?
            json_object_get(time_rules_obj) : json_object_new_array());
    json_object_object_add(detail_obj, "category_ids", json_object_new_array());
    json_object_object_add(detail_obj, "category_stats", json_object_new_array());
    json_object_object_add(detail_obj, "category_count", json_object_new_int(0));
    json_object_object_add(detail_obj, "app_count", json_object_new_int(app_count));
    return detail_obj;
}

static int pc_get_module_order(const char *module)
{
    if (!module || module[0] == '\0') {
        return 99;
    }
    if (strcmp(module, "appfilter") == 0) {
        return 1;
    }
    if (strcmp(module, "macfilter") == 0) {
        return 2;
    }
    if (strcmp(module, "blacklist") == 0) {
        return 3;
    }
    return 99;
}

static int pc_compare_rule_item(const void *a, const void *b)
{
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;
    struct json_object *module_a_obj = NULL;
    struct json_object *module_b_obj = NULL;
    struct json_object *id_a_obj = NULL;
    struct json_object *id_b_obj = NULL;
    struct json_object *name_a_obj = NULL;
    struct json_object *name_b_obj = NULL;
    const char *module_a = "";
    const char *module_b = "";
    const char *name_a = "";
    const char *name_b = "";
    int order_a;
    int order_b;
    int id_a = 0;
    int id_b = 0;
    int cmp;

    if (!obj_a && !obj_b) {
        return 0;
    }
    if (!obj_a) {
        return 1;
    }
    if (!obj_b) {
        return -1;
    }

    json_object_object_get_ex(obj_a, "module", &module_a_obj);
    json_object_object_get_ex(obj_b, "module", &module_b_obj);
    module_a = module_a_obj ? json_object_get_string(module_a_obj) : "";
    module_b = module_b_obj ? json_object_get_string(module_b_obj) : "";
    if (!module_a) module_a = "";
    if (!module_b) module_b = "";
    order_a = pc_get_module_order(module_a);
    order_b = pc_get_module_order(module_b);
    if (order_a != order_b) {
        return order_a - order_b;
    }

    json_object_object_get_ex(obj_a, "rule_id", &id_a_obj);
    json_object_object_get_ex(obj_b, "rule_id", &id_b_obj);
    id_a = id_a_obj ? json_object_get_int(id_a_obj) : 0;
    id_b = id_b_obj ? json_object_get_int(id_b_obj) : 0;
    if (id_a != id_b) {
        return id_a - id_b;
    }

    json_object_object_get_ex(obj_a, "rule_name", &name_a_obj);
    json_object_object_get_ex(obj_b, "rule_name", &name_b_obj);
    name_a = name_a_obj ? json_object_get_string(name_a_obj) : "";
    name_b = name_b_obj ? json_object_get_string(name_b_obj) : "";
    if (!name_a) name_a = "";
    if (!name_b) name_b = "";

    cmp = strcmp(name_a, name_b);
    if (cmp != 0) {
        return cmp;
    }
    return 0;
}

static struct json_object *pc_sort_rule_list(struct json_object *list_obj)
{
    int i;
    int len;
    struct json_object **items = NULL;
    struct json_object *sorted_obj = NULL;

    if (!list_obj || !json_object_is_type(list_obj, json_type_array)) {
        return NULL;
    }

    len = json_object_array_length(list_obj);
    sorted_obj = json_object_new_array();
    if (!sorted_obj) {
        return NULL;
    }
    if (len <= 0) {
        return sorted_obj;
    }

    items = (struct json_object **)calloc((size_t)len, sizeof(struct json_object *));
    if (!items) {
        json_object_put(sorted_obj);
        return NULL;
    }

    for (i = 0; i < len; i++) {
        items[i] = json_object_array_get_idx(list_obj, i);
    }

    qsort(items, (size_t)len, sizeof(struct json_object *), pc_compare_rule_item);
    for (i = 0; i < len; i++) {
        if (items[i]) {
            json_object_array_add(sorted_obj, json_object_get(items[i]));
        }
    }

    free(items);
    return sorted_obj;
}

static struct json_object *pc_get_response_data(struct json_object *resp_obj)
{
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;

    if (!resp_obj || !json_object_is_type(resp_obj, json_type_object)) {
        return NULL;
    }

    if (!json_object_object_get_ex(resp_obj, "code", &code_obj) ||
        json_object_get_int(code_obj) != API_CODE_SUCCESS) {
        return NULL;
    }

    if (!json_object_object_get_ex(resp_obj, "data", &data_obj) ||
        !json_object_is_type(data_obj, json_type_object)) {
        return NULL;
    }

    return data_obj;
}

static struct json_object *pc_get_response_list(struct json_object *resp_obj, const char *key)
{
    struct json_object *data_obj = NULL;
    struct json_object *list_obj = NULL;

    if (!key || key[0] == '\0') {
        return NULL;
    }

    data_obj = pc_get_response_data(resp_obj);
    if (!data_obj) {
        return NULL;
    }
    if (!json_object_object_get_ex(data_obj, key, &list_obj) ||
        !json_object_is_type(list_obj, json_type_array)) {
        return NULL;
    }
    return list_obj;
}

static int pc_get_today_usage_by_mac(const char *target_mac,
                                     unsigned long long *today_online_time,
                                     unsigned long long *today_active_time,
                                     unsigned long long *today_up_bytes,
                                     unsigned long long *today_down_bytes)
{
    client_node_t *client = NULL;
    int hour;

    if (!target_mac || target_mac[0] == '\0' ||
        !today_online_time || !today_active_time || !today_up_bytes || !today_down_bytes) {
        return -1;
    }

    *today_online_time = 0;
    *today_active_time = 0;
    *today_up_bytes = 0;
    *today_down_bytes = 0;

    list_for_each_entry(client, &client_list, client) {
        if (strcasecmp(client->mac, target_mac) == 0) {
            daily_hourly_stat_t *today_stat = get_today_stat(client);
            if (!today_stat) {
                return 0;
            }
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                *today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                *today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
                *today_online_time += today_stat->hourly_online_time[hour];
                *today_active_time += today_stat->hourly_active_time[hour];
            }
            return 0;
        }
    }

    return -1;
}

void all_users_callback(void *arg, client_node_t *client)
{
    int flag = 0;
    int i;
	int hour;
    all_users_info_t *au_info = (all_users_info_t *)arg;
    if (!au_info || !client) {
        LOG_ERROR("all_users_callback: arg or client is NULL\n");
        return;
    }
    
    flag = au_info->flag;
    struct json_object *users_array = au_info->users_array;
    if (!users_array) {
        LOG_ERROR("all_users_callback: users_array is NULL\n");
        return;
    }

    int current_count = json_object_array_length(users_array);
    if (current_count >= MAX_SUPPORT_DEV_NUM)
    {
        LOG_ERROR("all_users_callback: users_array length (%d) >= MAX_SUPPORT_DEV_NUM (%d), skipping\n", 
               current_count, MAX_SUPPORT_DEV_NUM);
        return;
    }

    LOG_DEBUG("all_users_callback: Processing client - mac=%s, online=%d, flag=%d, current_count=%d\n", 
           client->mac, client->online, flag, current_count);

    struct json_object *user_obj = json_object_new_object();
    if (!user_obj) {
        LOG_ERROR("all_users_callback: Failed to create user_obj for mac=%s\n", client->mac);
        return;
    }
    int af_whitelist = is_appfilter_whitelist_mac(client->mac);
    int mf_whitelist = is_macfilter_whitelist_mac(client->mac);
    const char *pc_status = apply_whitelist_pc_status(get_pc_status_for_mac(au_info, client->mac), af_whitelist, mf_whitelist);
    const char *pc_status_key = apply_whitelist_pc_status(get_pc_status_key_for_mac(au_info, client->mac), af_whitelist, mf_whitelist);
    
    json_object_object_add(user_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(user_obj, "pc_status", json_object_new_string(pc_status));
    json_object_object_add(user_obj, "pc_status_key", json_object_new_string(pc_status_key));
    json_object_object_add(user_obj, "in_blacklist", json_object_new_int(is_blacklist_mac(au_info, client->mac) ? 1 : 0));
    json_object_object_add(user_obj, "af_whitelist", json_object_new_int(af_whitelist ? 1 : 0));
    json_object_object_add(user_obj, "mf_whitelist", json_object_new_int(mf_whitelist ? 1 : 0));
    json_object_object_add(user_obj, "online", json_object_new_int(client->online));
    json_object_object_add(user_obj, "active", json_object_new_int(client->active));
    json_object_object_add(user_obj, "is_wireless", json_object_new_int(client->is_wireless));
    json_object_object_add(user_obj, "terminal_type", json_object_new_string(client->is_wireless ? "wireless" : "wired"));
    json_object_object_add(user_obj, "session", json_object_new_int(get_session_count_for_mac(au_info, client->mac)));
    json_object_object_add(user_obj, "online_time", json_object_new_int(client->online_time));
    json_object_object_add(user_obj, "offline_time", json_object_new_int(client->offline_time));

    if (flag > 0) {
        json_object_object_add(user_obj, "ip", json_object_new_string(client->ip));
        json_object_object_add(user_obj, "ipv6", json_object_new_string(client->ipv6));
        LOG_DEBUG("all_users_callback: Added IP: %s for mac=%s\n", client->ip, client->mac);
    }

    if (flag > 1){
        json_object_object_add(user_obj, "hostname", json_object_new_string(client->hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(client->nickname));
        LOG_DEBUG("all_users_callback: Added hostname=%s, nickname=%s for mac=%s\n", 
               client->hostname, client->nickname, client->mac);
    }

    if (flag > 2){
        struct json_object *app_array = json_object_new_array();
        app_visit_time_info_t top5_app_list[5];
        memset(top5_app_list, 0x0, sizeof(top5_app_list));
        update_top5_app(client, top5_app_list);
        int app_count = 0;
        for (i = 0; i < 5; i++)
        {
            if (top5_app_list[i].app_id == 0)
                break;

            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "id", json_object_new_int(top5_app_list[i].app_id));
            const char *app_name = get_app_name_by_id(top5_app_list[i].app_id);
            json_object_object_add(app_obj, "name", json_object_new_string(app_name));
            add_app_icon_missing_flag(app_obj, top5_app_list[i].app_id);

            json_object_array_add(app_array, app_obj);
            app_count++;
        }
        json_object_object_add(user_obj, "applist", app_array);
        LOG_DEBUG("all_users_callback: Added %d apps to applist for mac=%s\n", app_count, client->mac);

        if (strlen(client->visiting_url) > 0)
            json_object_object_add(user_obj, "url", json_object_new_string(client->visiting_url));
        else
            json_object_object_add(user_obj, "url", json_object_new_string(""));
        if (client->visiting_app > 0) {
            const char *app_name = get_app_name_by_id(client->visiting_app);
            json_object_object_add(user_obj, "app_id", json_object_new_int(client->visiting_app));
            json_object_object_add(user_obj, "app", json_object_new_string(app_name));
            if (!app_icon_exists_by_id(client->visiting_app))
                json_object_object_add(user_obj, "app_icon", json_object_new_int(0));
            LOG_DEBUG("all_users_callback: Added visiting app=%s (id=%d), url=%s for mac=%s\n", 
                   app_name, client->visiting_app, client->visiting_url, client->mac);
        } else {
            json_object_object_add(user_obj, "app_id", json_object_new_int(0));
            json_object_object_add(user_obj, "app", json_object_new_string(""));
        }
        

        json_object_object_add(user_obj, "up_rate", json_object_new_int(client->up_rate));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(client->down_rate));
        json_object_object_add(user_obj, "rssi", json_object_new_int(client->rssi));
        json_object_object_add(user_obj, "rx_rate", json_object_new_int(client->rx_rate));
        json_object_object_add(user_obj, "tx_rate", json_object_new_int(client->tx_rate));
        json_object_object_add(user_obj, "band", json_object_new_string(client->band));
        json_object_object_add(user_obj, "wifi_ifname", json_object_new_string(client->wifi_ifname));
        

        daily_hourly_stat_t *today_stat = get_today_stat(client);
        unsigned long long today_up_bytes = 0;
        unsigned long long today_down_bytes = 0;
        unsigned long long today_active_time = 0;
        int today_active_minutes = 0;
        
        if (today_stat) {
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
                today_active_time += today_stat->hourly_active_time[hour];
            }
        }
        today_active_minutes = (int)(today_active_time / 60);
        

        json_object_object_add(user_obj, "today_up_bytes", json_object_new_int64(today_up_bytes));
        json_object_object_add(user_obj, "today_down_bytes", json_object_new_int64(today_down_bytes));
        json_object_object_add(user_obj, "today_active_time", json_object_new_int64(today_active_time));
        json_object_object_add(user_obj, "today_active_minutes", json_object_new_int(today_active_minutes));
    }
    
    json_object_array_add(users_array, user_obj);
    int new_count = json_object_array_length(users_array);
    LOG_DEBUG("all_users_callback: Successfully added user mac=%s, array length now: %d\n", 
           client->mac, new_count);
}

int compare_users(const void *a, const void *b)
{
    struct json_object *user_a = *(struct json_object **)a;
    struct json_object *user_b = *(struct json_object **)b;

    struct json_object *active_a, *active_b;
    struct json_object *online_a, *online_b;
    json_object_object_get_ex(user_a, "online", &online_a);
    json_object_object_get_ex(user_b, "online", &online_b);
    json_object_object_get_ex(user_a, "active", &active_a);
    json_object_object_get_ex(user_b, "active", &active_b);

    int online_val_a = online_a ? json_object_get_int(online_a) : 0;
    int online_val_b = online_b ? json_object_get_int(online_b) : 0;
    int active_val_a = active_a ? json_object_get_int(active_a) : 0;
    int active_val_b = active_b ? json_object_get_int(active_b) : 0;
    int rank_a = (online_val_a == 1 && active_val_a == 1) ? 0 : (online_val_a == 1 ? 1 : 2);
    int rank_b = (online_val_b == 1 && active_val_b == 1) ? 0 : (online_val_b == 1 ? 1 : 2);

    if (rank_a != rank_b)
        return rank_a - rank_b;

    struct json_object *online_time_a, *online_time_b;
    json_object_object_get_ex(user_a, "online_time", &online_time_a);
    json_object_object_get_ex(user_b, "online_time", &online_time_b);

    int online_time_val_a = online_time_a ? json_object_get_int(online_time_a) : 0;
    int online_time_val_b = online_time_b ? json_object_get_int(online_time_b) : 0;

    if (rank_a == 0 || rank_a == 1) {
        return online_time_val_b - online_time_val_a;
    } else {

        struct json_object *offline_time_a, *offline_time_b;
        json_object_object_get_ex(user_a, "offline_time", &offline_time_a);
        json_object_object_get_ex(user_b, "offline_time", &offline_time_b);

        int offline_time_val_a = offline_time_a ? json_object_get_int(offline_time_a) : 0;
        int offline_time_val_b = offline_time_b ? json_object_get_int(offline_time_b) : 0;

        return offline_time_val_b - offline_time_val_a;
    }
}

static int handle_get_all_users(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    int flag = 0;
    int page = 0;
    int page_size = 15;
    int use_paging = 0;
	int i;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return 0;
    }

    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (msg_obj_str)
    {
        struct json_object *req_obj = json_tokener_parse(msg_obj_str);
        if (!req_obj) {
            LOG_ERROR("handle_get_all_users: Failed to parse request JSON\n");
        } else {
            struct json_object *flag_obj = json_object_object_get(req_obj, "flag");
            struct json_object *page_obj = json_object_object_get(req_obj, "page");
            struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
            if (flag_obj) {
                flag = json_object_get_int(flag_obj);
            }
            if (page_obj) {
                page = json_object_get_int(page_obj);
                if (page > 0) {
                    use_paging = 1;
                } else {
                    page = 0;
                }
            }
            if (use_paging && page_size_obj) {
                page_size = json_object_get_int(page_size_obj);
                if (page_size < 1) page_size = 15;
            }
            json_object_put(req_obj);
        }
        free(msg_obj_str);
    }

    extern struct list_head client_list;
    extern int g_cur_user_num;
    
    all_users_info_t au_info;
    memset(&au_info, 0, sizeof(au_info));
    au_info.flag = flag;
    au_info.users_array = json_object_new_array();
    if (!au_info.users_array) {
        uci_free_context(uci_ctx);
        return 0;
    }
    load_parental_control_status(&au_info);
    load_mac_blacklist(&au_info);
    load_user_session_count(&au_info);

    update_client_nickname();
    update_client_visiting_info();
    
    client_foreach(&au_info, all_users_callback);

    int user_count = json_object_array_length(au_info.users_array);
    
    json_object_array_sort(au_info.users_array, compare_users);


    int total_num = json_object_array_length(au_info.users_array);
    int total_page = 1;
    int resp_page = 0;
    int resp_page_size = total_num;
    struct json_object *list_obj = au_info.users_array;

    if (use_paging) {
        total_page = (total_num + page_size - 1) / page_size;
        if (total_page < 1) total_page = 1;
        if (page > total_page) page = total_page;

        struct json_object *paged_array = json_object_new_array();
        int start_idx = (page - 1) * page_size;
        int end_idx = start_idx + page_size;
        if (end_idx > total_num) end_idx = total_num;

        for (i = start_idx; i < end_idx; i++) {
            struct json_object *item = json_object_array_get_idx(au_info.users_array, i);
            if (item) {
                json_object_get(item);
                json_object_array_add(paged_array, item);
            }
        }

        json_object_put(au_info.users_array);
        list_obj = paged_array;
        resp_page = page;
        resp_page_size = page_size;
    }

    json_object_object_add(data_obj, "list", list_obj);
    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(resp_page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(resp_page_size));
    json_object_object_add(response, "data", data_obj);

    uci_free_context(uci_ctx);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}




struct json_object *fwx_api_set_nickname(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    struct json_object *nickname_obj = json_object_object_get(req_obj, "nickname");
    
    if (!nickname_obj || !mac_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    const char *nickname = json_object_get_string(nickname_obj);
    
    if (!mac) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int num = fwx_uci_get_list_num(uci_ctx, "user_info", "user_info");
    char mac_str[128] = {0};
    int index = -1;
    int i;
    
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, mac) == 0) {
            index = i;
            LOG_DEBUG("found nickname index: %d\n", index);
            break;
        }
    }

    if (nickname && strlen(nickname) > 0) {
        if (index == -1) {
            fwx_uci_add_section(uci_ctx, "user_info", "user_info");
            index = num;  
        }
        fwx_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].mac", index, (char *)mac);
        fwx_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].nickname", index, (char *)nickname);
    } else {
        if (index >= 0) {
            char uci_option[128] = {0};
            snprintf(uci_option, sizeof(uci_option), "user_info.@user_info[%d]", index);
            fwx_uci_delete(uci_ctx, uci_option);
            LOG_DEBUG("delete nickname mac = %s\n", mac);
        }
    }

    fwx_uci_commit(uci_ctx, "user_info");
    reload_oaf_rule();
    uci_free_context(uci_ctx);

    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_get_nickname_list(struct json_object *req_obj)
{
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    struct uci_context *uci_ctx = NULL;
    int num = 0;
    int i = 0;

    (void)req_obj;

    if (!data_obj || !list_obj) {
        if (data_obj) {
            json_object_put(data_obj);
        }
        if (list_obj) {
            json_object_put(list_obj);
        }
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        json_object_put(data_obj);
        json_object_put(list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    num = fwx_uci_get_list_num(uci_ctx, "user_info", "user_info");
    for (i = 0; i < num; i++) {
        char mac[128] = {0};
        char nickname[128] = {0};
        struct json_object *item_obj = NULL;

        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac, sizeof(mac));
        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].nickname", i, nickname, sizeof(nickname));
        if (mac[0] == '\0' || nickname[0] == '\0') {
            continue;
        }

        item_obj = json_object_new_object();
        if (!item_obj) {
            continue;
        }
        json_object_object_add(item_obj, "mac", json_object_new_string(mac));
        json_object_object_add(item_obj, "nickname", json_object_new_string(nickname));
        json_object_array_add(list_obj, item_obj);
    }

    uci_free_context(uci_ctx);
    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_mac_blacklist(struct json_object *req_obj)
{
    char macs[MAX_SUPPORT_DEV_NUM][32] = {{0}};
    int count = load_mac_blacklist_items(macs, MAX_SUPPORT_DEV_NUM);
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    int i;

    (void)req_obj;

    if (!data_obj || !list_obj) {
        if (data_obj) {
            json_object_put(data_obj);
        }
        if (list_obj) {
            json_object_put(list_obj);
        }
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    update_client_nickname();

    for (i = 0; i < count; i++) {
        client_node_t *dev = find_client_node(macs[i]);
        struct json_object *item_obj = json_object_new_object();
        if (!item_obj) {
            continue;
        }

        json_object_object_add(item_obj, "mac", json_object_new_string(macs[i]));
        if (dev) {
            json_object_object_add(item_obj, "hostname", json_object_new_string(dev->hostname));
            json_object_object_add(item_obj, "nickname", json_object_new_string(dev->nickname));
        } else {
            json_object_object_add(item_obj, "hostname", json_object_new_string("--"));
            json_object_object_add(item_obj, "nickname", json_object_new_string("--"));
        }
        json_object_array_add(list_obj, item_obj);
    }

    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_add_mac_blacklist(struct json_object *req_obj)
{
    char macs[MAX_SUPPORT_DEV_NUM][32] = {{0}};
    int count = load_mac_blacklist_items(macs, MAX_SUPPORT_DEV_NUM);
    struct json_object *mac_obj = NULL;
    struct json_object *mac_list_obj = NULL;
    int valid_count = 0;
    int overflow = 0;
    int i;

    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    mac_obj = json_object_object_get(req_obj, "mac");
    if (mac_obj) {
        char normalized_mac[32] = {0};
        normalize_mac_value(json_object_get_string(mac_obj), normalized_mac, sizeof(normalized_mac));
        if (normalized_mac[0] != '\0') {
            valid_count++;
            if (!mac_blacklist_has_item(macs, count, normalized_mac)) {
                if (count >= MAX_SUPPORT_DEV_NUM) {
                    overflow = 1;
                } else {
                    strncpy(macs[count], normalized_mac, sizeof(macs[count]) - 1);
                    count++;
                }
            }
        }
    }

    mac_list_obj = json_object_object_get(req_obj, "mac_list");
    if (mac_list_obj && json_object_is_type(mac_list_obj, json_type_array)) {
        int array_len = json_object_array_length(mac_list_obj);
        for (i = 0; i < array_len; i++) {
            char normalized_mac[32] = {0};
            struct json_object *item_obj = json_object_array_get_idx(mac_list_obj, i);
            normalize_mac_value(json_object_get_string(item_obj), normalized_mac, sizeof(normalized_mac));
            if (normalized_mac[0] == '\0') {
                continue;
            }

            valid_count++;
            if (mac_blacklist_has_item(macs, count, normalized_mac)) {
                continue;
            }
            if (count >= MAX_SUPPORT_DEV_NUM) {
                overflow = 1;
                break;
            }

            strncpy(macs[count], normalized_mac, sizeof(macs[count]) - 1);
            count++;
        }
    }

    if (valid_count == 0 || overflow) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (count > 1) {
        qsort(macs, count, sizeof(macs[0]), compare_mac_value);
    }

    if (save_mac_blacklist_items(macs, count) != 0) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    touch_macfilter_rules_state_file();
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_del_mac_blacklist(struct json_object *req_obj)
{
    char macs[MAX_SUPPORT_DEV_NUM][32] = {{0}};
    char normalized_mac[32] = {0};
    int count;
    int write_idx = 0;
    int i;
    struct json_object *mac_obj = NULL;

    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    mac_obj = json_object_object_get(req_obj, "mac");
    normalize_mac_value(mac_obj ? json_object_get_string(mac_obj) : NULL, normalized_mac, sizeof(normalized_mac));
    if (normalized_mac[0] == '\0') {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    count = load_mac_blacklist_items(macs, MAX_SUPPORT_DEV_NUM);
    for (i = 0; i < count; i++) {
        if (strcasecmp(macs[i], normalized_mac) == 0) {
            continue;
        }
        if (write_idx != i) {
            strncpy(macs[write_idx], macs[i], sizeof(macs[write_idx]) - 1);
            macs[write_idx][sizeof(macs[write_idx]) - 1] = '\0';
            macs[i][0] = '\0';
        }
        write_idx++;
    }

    if (save_mac_blacklist_items(macs, write_idx) != 0) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    touch_macfilter_rules_state_file();
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_dev_visit_list(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int page = 1;
    int page_size = 15;
    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    if (page_obj) {
        page = json_object_get_int(page_obj);
        if (page < 1) page = 1;
    }
    if (page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size < 1) page_size = 15;
    }
    
    struct json_object *root_obj = json_object_new_object();
    struct json_object *visit_array = json_object_new_array();
    
    client_node_t *node = find_client_node(mac);
    if (!node) {
        json_object_object_add(root_obj, "hostname", json_object_new_string(""));
        json_object_object_add(root_obj, "mac", json_object_new_string(mac));
        json_object_object_add(root_obj, "ip", json_object_new_string(""));
        json_object_object_add(root_obj, "ipv6", json_object_new_string(""));
        json_object_object_add(root_obj, "total_num", json_object_new_int(0));
        json_object_object_add(root_obj, "total_page", json_object_new_int(1));
        json_object_object_add(root_obj, "page", json_object_new_int(page));
        json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
        json_object_object_add(root_obj, "list", visit_array);
        return fwx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
    }
    
    json_object_object_add(root_obj, "hostname", json_object_new_string(node->hostname));
    json_object_object_add(root_obj, "mac", json_object_new_string(node->mac));
    json_object_object_add(root_obj, "ip", json_object_new_string(node->ip));
    

    struct json_object *online_array = json_object_new_array();
    struct json_object *offline_array = json_object_new_array();
    visit_info_t *p_info = NULL;

    int online_num = 0;
    int offline_num = 0;

    list_for_each_entry(p_info, &node->online_visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(get_app_name_by_id(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        add_app_icon_missing_flag(visit_obj, p_info->appid);
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(1));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(online_array, visit_obj);
        online_num++;
    }

    list_for_each_entry(p_info, &node->visit, visit) {
        int total_time = p_info->latest_time - p_info->first_time;
        struct json_object *visit_obj = json_object_new_object();
        json_object_object_add(visit_obj, "name", json_object_new_string(get_app_name_by_id(p_info->appid)));
        json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
        add_app_icon_missing_flag(visit_obj, p_info->appid);
        json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
        json_object_object_add(visit_obj, "online", json_object_new_int(0));
        json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
        json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
        json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
        json_object_array_add(offline_array, visit_obj);
        offline_num++;
    }

    json_object_array_sort(online_array, compare_lt);
    json_object_array_sort(offline_array, compare_lt);

    int total_num = online_num + offline_num;
    int total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) total_page = 1;
    if (page > total_page) page = total_page;
    

    struct json_object *paged_array = json_object_new_array();
    int start_idx = (page - 1) * page_size;
    int end_idx = start_idx + page_size;
    if (end_idx > total_num) end_idx = total_num;
    
    int i;
    for (i = start_idx; i < end_idx; i++) {
        struct json_object *item = NULL;
        if (i < online_num) {
            item = json_object_array_get_idx(online_array, i);
        } else {
            item = json_object_array_get_idx(offline_array, i - online_num);
        }
        if (item) {
            json_object_get(item);
            json_object_array_add(paged_array, item);
        }
    }
    
    json_object_put(online_array);
    json_object_put(offline_array);
    
    json_object_object_add(root_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(root_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(root_obj, "page", json_object_new_int(page));
    json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(root_obj, "list", paged_array);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}

struct json_object *fwx_api_get_active_app_records(struct json_object *req_obj) {
    int page = 1;
    int page_size = 15;
    int total_num = 0;
    int total_page = 1;
    int start_idx = 0;
    int end_idx = 0;
    int i = 0;
    active_app_visit_record_t *records = NULL;
    struct json_object *page_obj = NULL;
    struct json_object *page_size_obj = NULL;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();

    if (req_obj) {
        page_obj = json_object_object_get(req_obj, "page");
        page_size_obj = json_object_object_get(req_obj, "page_size");
        if (page_obj) {
            page = json_object_get_int(page_obj);
            if (page < 1)
                page = 1;
        }
        if (page_size_obj) {
            page_size = json_object_get_int(page_size_obj);
            if (page_size < 1)
                page_size = 15;
            if (page_size > 200)
                page_size = 200;
        }
    }

    update_client_nickname();

    total_num = collect_active_app_visit_records(NULL, 0);
    total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1)
        total_page = 1;
    if (page > total_page)
        page = total_page;

    if (total_num > 0) {
        records = (active_app_visit_record_t *)calloc(total_num, sizeof(active_app_visit_record_t));
        if (!records) {
            json_object_put(data_obj);
            json_object_put(list_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }

        total_num = collect_active_app_visit_records(records, total_num);
        if (total_num > 1) {
            qsort(records, total_num, sizeof(active_app_visit_record_t), compare_active_app_visit_record);
        }

        total_page = (total_num + page_size - 1) / page_size;
        if (total_page < 1)
            total_page = 1;
        if (page > total_page)
            page = total_page;

        start_idx = (page - 1) * page_size;
        end_idx = start_idx + page_size;
        if (end_idx > total_num)
            end_idx = total_num;

        for (i = start_idx; i < end_idx; i++) {
            struct json_object *item_obj = json_object_new_object();
            json_object_object_add(item_obj, "mac", json_object_new_string(records[i].mac));
            json_object_object_add(item_obj, "hostname", json_object_new_string(records[i].hostname));
            json_object_object_add(item_obj, "nickname", json_object_new_string(records[i].nickname));
            json_object_object_add(item_obj, "name", json_object_new_string(get_app_name_by_id(records[i].appid)));
            json_object_object_add(item_obj, "id", json_object_new_int(records[i].appid));
            add_app_icon_missing_flag(item_obj, records[i].appid);
            json_object_object_add(item_obj, "act", json_object_new_int(records[i].action));
            json_object_object_add(item_obj, "online", json_object_new_int(1));
            json_object_object_add(item_obj, "ft", json_object_new_int(records[i].first_time));
            json_object_object_add(item_obj, "lt", json_object_new_int(records[i].latest_time));
            json_object_object_add(item_obj, "tt", json_object_new_int(records[i].total_time));
            json_object_object_add(item_obj, "appname", json_object_new_string(get_app_name_by_id(records[i].appid)));
            json_object_object_add(item_obj, "appid", json_object_new_int(records[i].appid));
            json_object_object_add(item_obj, "latest_action", json_object_new_int(records[i].action));
            json_object_object_add(item_obj, "first_time", json_object_new_int(records[i].first_time));
            json_object_object_add(item_obj, "latest_time", json_object_new_int(records[i].latest_time));
            json_object_object_add(item_obj, "total_time", json_object_new_int(records[i].total_time));
            json_object_array_add(list_obj, item_obj);
        }
    }

    if (records) {
        free(records);
    }

    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_app_history_records(struct json_object *req_obj) {
    int page = 1;
    int page_size = 15;
    int total_num = 0;
    int total_page = 1;
    int start_idx = 0;
    int end_idx = 0;
    int appid = 0;
    u_int32_t start_time = 0;
    u_int32_t end_time = 0;
    const char *mac = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;
    int bind_idx = 1;
    char db_path[512] = {0};
    char where_sql[512] = " WHERE 1=1";
    char count_sql[1024] = {0};
    char query_sql[1200] = {0};
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();

    if (req_obj) {
        struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
        struct json_object *appid_obj = json_object_object_get(req_obj, "appid");
        struct json_object *start_time_obj = json_object_object_get(req_obj, "start_time");
        struct json_object *end_time_obj = json_object_object_get(req_obj, "end_time");
        struct json_object *page_obj = json_object_object_get(req_obj, "page");
        struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");

        if (mac_obj) {
            mac = json_object_get_string(mac_obj);
            if (mac && strlen(mac) == 0)
                mac = NULL;
        }
        if (appid_obj) {
            appid = json_object_get_int(appid_obj);
            if (appid < 0)
                appid = 0;
        }
        if (start_time_obj) {
            start_time = (u_int32_t)json_object_get_int64(start_time_obj);
        }
        if (end_time_obj) {
            end_time = (u_int32_t)json_object_get_int64(end_time_obj);
        }
        if (page_obj) {
            page = json_object_get_int(page_obj);
            if (page < 1)
                page = 1;
        }
        if (page_size_obj) {
            page_size = json_object_get_int(page_size_obj);
            if (page_size < 1)
                page_size = 15;
            if (page_size > 200)
                page_size = 200;
        }
    }

    if (start_time > 0 && end_time > 0 && start_time > end_time) {
        u_int32_t temp = start_time;
        start_time = end_time;
        end_time = temp;
    }

    update_client_nickname();

    snprintf(db_path, sizeof(db_path), "%s/client.db", get_history_data_root_dir());
    if (access(db_path, F_OK) != 0) {
        json_object_object_add(data_obj, "total_num", json_object_new_int(0));
        json_object_object_add(data_obj, "total_page", json_object_new_int(1));
        json_object_object_add(data_obj, "page", json_object_new_int(page));
        json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
        json_object_object_add(data_obj, "list", list_obj);
        return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
    }

    rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        json_object_put(data_obj);
        json_object_put(list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    sqlite3_exec(db,
                 "CREATE TABLE IF NOT EXISTS app_visit_record ("
                 "mac TEXT NOT NULL,"
                 "record_date INTEGER NOT NULL,"
                 "appid INTEGER NOT NULL,"
                 "start_time INTEGER NOT NULL,"
                 "end_time INTEGER NOT NULL,"
                 "duration INTEGER NOT NULL,"
                 "action INTEGER NOT NULL"
                 ");",
                 NULL, NULL, NULL);

    if (mac) {
        strncat(where_sql, " AND mac = ?", sizeof(where_sql) - strlen(where_sql) - 1);
    }
    if (appid > 0) {
        strncat(where_sql, " AND appid = ?", sizeof(where_sql) - strlen(where_sql) - 1);
    }
    if (start_time > 0 && end_time > 0) {
        strncat(where_sql, " AND end_time >= ? AND start_time <= ?", sizeof(where_sql) - strlen(where_sql) - 1);
    } else if (start_time > 0) {
        strncat(where_sql, " AND end_time >= ?", sizeof(where_sql) - strlen(where_sql) - 1);
    } else if (end_time > 0) {
        strncat(where_sql, " AND start_time <= ?", sizeof(where_sql) - strlen(where_sql) - 1);
    }

    snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(1) FROM app_visit_record%s;", where_sql);
    rc = sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        goto CLEANUP;
    }
    bind_app_history_filters(stmt, mac, appid, start_time, end_time);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        total_num = sqlite3_column_int(stmt, 0);
    } else {
        rc = SQLITE_ERROR;
        goto CLEANUP;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1)
        total_page = 1;
    if (page > total_page)
        page = total_page;

    start_idx = (page - 1) * page_size;
    end_idx = start_idx + page_size;
    if (end_idx > total_num)
        end_idx = total_num;

    if (total_num > 0 && start_idx < end_idx) {
        snprintf(query_sql, sizeof(query_sql),
                 "SELECT mac, appid, action, start_time, end_time, duration "
                 "FROM app_visit_record%s "
                 "ORDER BY end_time DESC, duration ASC "
                 "LIMIT ? OFFSET ?;",
                 where_sql);
        rc = sqlite3_prepare_v2(db, query_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            goto CLEANUP;
        }

        bind_idx = bind_app_history_filters(stmt, mac, appid, start_time, end_time);
        sqlite3_bind_int(stmt, bind_idx++, page_size);
        sqlite3_bind_int(stmt, bind_idx++, start_idx);

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *row_mac = (const char *)sqlite3_column_text(stmt, 0);
            int row_appid = sqlite3_column_int(stmt, 1);
            int row_action = sqlite3_column_int(stmt, 2);
            u_int32_t row_start = (u_int32_t)sqlite3_column_int64(stmt, 3);
            u_int32_t row_end = (u_int32_t)sqlite3_column_int64(stmt, 4);
            int row_duration = sqlite3_column_int(stmt, 5);
            struct json_object *item_obj = json_object_new_object();
            client_node_t *node = find_client_node(row_mac ? row_mac : "");
            const char *hostname = "";
            const char *nickname = "";

            if (node) {
                hostname = node->hostname;
                nickname = node->nickname;
            }

            json_object_object_add(item_obj, "mac", json_object_new_string(row_mac ? row_mac : ""));
            json_object_object_add(item_obj, "hostname", json_object_new_string(hostname ? hostname : ""));
            json_object_object_add(item_obj, "nickname", json_object_new_string(nickname ? nickname : ""));
            json_object_object_add(item_obj, "name", json_object_new_string(get_app_name_by_id(row_appid)));
            json_object_object_add(item_obj, "id", json_object_new_int(row_appid));
            add_app_icon_missing_flag(item_obj, row_appid);
            json_object_object_add(item_obj, "act", json_object_new_int(row_action));
            json_object_object_add(item_obj, "online", json_object_new_int(0));
            json_object_object_add(item_obj, "ft", json_object_new_int(row_start));
            json_object_object_add(item_obj, "lt", json_object_new_int(row_end));
            json_object_object_add(item_obj, "tt", json_object_new_int(row_duration));
            json_object_object_add(item_obj, "appname", json_object_new_string(get_app_name_by_id(row_appid)));
            json_object_object_add(item_obj, "appid", json_object_new_int(row_appid));
            json_object_object_add(item_obj, "latest_action", json_object_new_int(row_action));
            json_object_object_add(item_obj, "first_time", json_object_new_int(row_start));
            json_object_object_add(item_obj, "latest_time", json_object_new_int(row_end));
            json_object_object_add(item_obj, "total_time", json_object_new_int(row_duration));
            json_object_array_add(list_obj, item_obj);
        }
        if (rc != SQLITE_DONE) {
            goto CLEANUP;
        }
    }

    rc = SQLITE_OK;

CLEANUP:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);

    if (rc != SQLITE_OK) {
        json_object_put(data_obj);
        json_object_put(list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_dev_visit_time(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct app_visit_stat_info info;
    memset((char *)&info, 0x0, sizeof(info));
    update_app_visit_time_list((char *)mac, &info);
    
    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_info_array = json_object_new_array();
    json_object_object_add(resp_obj, "list", app_info_array);
    json_object_object_add(resp_obj, "total_num", json_object_new_int(info.num));
    
    int i;
    for (i = 0; i < info.num; i++) {
        struct json_object *app_info_obj = json_object_new_object();
        json_object_object_add(app_info_obj, "id", json_object_new_int(info.visit_list[i].app_id));
        add_app_icon_missing_flag(app_info_obj, info.visit_list[i].app_id);
        json_object_object_add(app_info_obj, "name", json_object_new_string(get_app_name_by_id(info.visit_list[i].app_id)));
        json_object_object_add(app_info_obj, "t", json_object_new_int(info.visit_list[i].total_time));
        json_object_array_add(app_info_array, app_info_obj);
    }
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, resp_obj);
}


struct json_object *fwx_api_app_class_visit_time(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int app_class_visit_time[MAX_APP_TYPE];
    memset(app_class_visit_time, 0x0, sizeof(app_class_visit_time));
    update_app_class_visit_time_list((char *)mac, app_class_visit_time);
    
    struct json_object *resp_obj = json_object_new_object();
    struct json_object *app_class_array = json_object_new_array();
    json_object_object_add(resp_obj, "class_list", app_class_array);
    
    extern int g_cur_class_num;
    int i;
    for (i = 0; i < MAX_APP_TYPE; i++) {
        if (i >= g_cur_class_num)
            break;
        struct json_object *app_class_obj = json_object_new_object();
        json_object_object_add(app_class_obj, "type", json_object_new_int(i));
        json_object_object_add(app_class_obj, "name", json_object_new_string(CLASS_NAME_TABLE[i]));
        json_object_object_add(app_class_obj, "visit_time", json_object_new_int(app_class_visit_time[i]));
        json_object_array_add(app_class_array, app_class_obj);
    }
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, resp_obj);
}


struct json_object *fwx_api_dev_list(struct json_object *req_obj) {
    int i, j;
    struct json_object *root_obj = json_object_new_object();
    struct json_object *dev_array = json_object_new_array();
    
    extern struct list_head client_list;
    extern int g_cur_user_num;
    
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        struct json_object *dev_obj = json_object_new_object();
        json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
        json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));
        json_object_object_add(dev_obj, "ipv6", json_object_new_string(node->ipv6));
        json_object_object_add(dev_obj, "hostname", json_object_new_string(node->hostname));
        json_object_object_add(dev_obj, "nickname", json_object_new_string(node->nickname));
        json_object_object_add(dev_obj, "online", json_object_new_int(node->online));
        
        app_visit_time_info_t top5_app_list[5] = {0};
        update_top5_app(node, top5_app_list);
        
        struct json_object *visit_info_array = json_object_new_array();
        for (i = 0; i < 5; i++) {
            if (top5_app_list[i].app_id == 0)
                break;
            struct json_object *visit_info_obj = json_object_new_object();
            json_object_object_add(visit_info_obj, "appid", json_object_new_int(top5_app_list[i].app_id));
            add_app_icon_missing_flag(visit_info_obj, top5_app_list[i].app_id);
            json_object_object_add(visit_info_obj, "appname", json_object_new_string(get_app_name_by_id(top5_app_list[i].app_id)));
            json_object_object_add(visit_info_obj, "latest_time", json_object_new_int64(top5_app_list[i].total_time));
            json_object_array_add(visit_info_array, visit_info_obj);
        }
        json_object_object_add(dev_obj, "visit_info", visit_info_array);
        json_object_array_add(dev_array, dev_obj);
    }
    
    json_object_object_add(root_obj, "dev_list", dev_array);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}


struct json_object *fwx_api_class_list(struct json_object *req_obj) {
    struct json_object *class_list = json_object_new_array();
    
    if (parse_feature_cfg(class_list) != 0) {
        json_object_put(class_list);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "class_list", class_list);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, response);
}

static struct json_object *build_feature_info_object(void)
{
    struct json_object *data_obj = json_object_new_object();
    const char *feature_data;
    size_t feature_len = 0;
    size_t offset = 0;
    char line[1024];
    char version[64] = {0};
    int feature_type = 0;
    int feature_free = 0;
    int loaded = 0;
    int line_ret;

    feature_data = fwx_feature_get_data(&feature_len);
    if (feature_data && feature_len > 0) {
        loaded = 1;
        while ((line_ret = fwx_feature_next_line(feature_data, feature_len, &offset,
                                                 line, sizeof(line))) != 0) {
            if (line_ret < 0)
                continue;
            if (!line[0])
                continue;
            if (!strncmp(line, "#version ", 9)) {
                sscanf(line, "#version %63s", version);
            } else if (!strncmp(line, "#type ", 6)) {
                sscanf(line, "#type %d", &feature_type);
                if (feature_type != 0 && feature_type != 1)
                    feature_type = 0;
            } else if (!strncmp(line, "#free ", 6)) {
                sscanf(line, "#free %d", &feature_free);
                feature_free = feature_free ? 1 : 0;
            }
        }
    }

    json_object_object_add(data_obj, "loaded", json_object_new_int(loaded));
    json_object_object_add(data_obj, "version", json_object_new_string(version));
    json_object_object_add(data_obj, "type", json_object_new_int(feature_type));
    json_object_object_add(data_obj, "free", json_object_new_int(feature_free));
    json_object_object_add(data_obj, "format", json_object_new_string("v4.0"));
    json_object_object_add(data_obj, "app_count", json_object_new_int(g_app_count));
    return data_obj;
}

struct json_object *fwx_api_get_feature_info(struct json_object *req_obj) {
    struct json_object *data_obj = NULL;

    (void)req_obj;
    data_obj = build_feature_info_object();
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_all_users(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int flag = 0;
    int page = 0;
    int page_size = 15;
    int use_paging = 0;
    
    struct json_object *flag_obj = json_object_object_get(req_obj, "flag");
    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    
    if (flag_obj) {
        flag = json_object_get_int(flag_obj);
    }
    if (page_obj) {
        page = json_object_get_int(page_obj);
        if (page > 0) {
            use_paging = 1;
        } else {
            page = 0;
        }
    }
    if (use_paging && page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size < 1) page_size = 15;
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    extern struct list_head client_list;
    extern int g_cur_user_num;
    
    all_users_info_t au_info;
    memset(&au_info, 0, sizeof(au_info));
    au_info.flag = flag;
    au_info.users_array = json_object_new_array();
    if (!au_info.users_array) {
        LOG_ERROR("Failed to create users_array\n");
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    load_parental_control_status(&au_info);
    load_mac_blacklist(&au_info);
    load_user_session_count(&au_info);
    
    update_client_nickname();
    update_client_visiting_info();
    client_foreach(&au_info, all_users_callback);
    
    int user_count = json_object_array_length(au_info.users_array);
    json_object_array_sort(au_info.users_array, compare_users);
    

    int total_num = json_object_array_length(au_info.users_array);
    int total_page = 1;
    int resp_page = 0;
    int resp_page_size = total_num;
    struct json_object *list_obj = au_info.users_array;

    if (use_paging) {
        total_page = (total_num + page_size - 1) / page_size;
        if (total_page < 1) total_page = 1;
        if (page > total_page) page = total_page;

        struct json_object *paged_array = json_object_new_array();
        int start_idx = (page - 1) * page_size;
        int end_idx = start_idx + page_size;
        if (end_idx > total_num) end_idx = total_num;

        int i;
        for (i = start_idx; i < end_idx; i++) {
            struct json_object *item = json_object_array_get_idx(au_info.users_array, i);
            if (item) {
                json_object_get(item);
                json_object_array_add(paged_array, item);
            }
        }

        json_object_put(au_info.users_array);
        list_obj = paged_array;
        resp_page = page;
        resp_page_size = page_size;
    }

    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "list", list_obj);
    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(resp_page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(resp_page_size));
    
    uci_free_context(uci_ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_parental_control_detail(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *appfilter_rules_out = json_object_new_array();
    struct json_object *macfilter_rules_out = json_object_new_array();
    struct json_object *mac_obj = NULL;
    const char *mac = NULL;
    const char *status_key = PC_PERMISSION_UNLIMITED;
    FILE *fp = NULL;
    long file_len = 0;
    char *json_buf = NULL;
    struct json_object *root_obj = NULL;
    struct json_object *users_obj = NULL;
    struct json_object *user_obj = NULL;
    struct json_object *global_app_rules_obj = NULL;
    struct json_object *global_mac_rules_obj = NULL;
    struct json_object *app_rules_resp = NULL;
    struct json_object *app_rules = NULL;
    int current_weekday = 0;
    int current_minutes = 0;
    int blacklist_hit = 0;
    int af_whitelist = 0;
    int mf_whitelist = 0;
    int i;
    int len;
    if (!data_obj || !appfilter_rules_out || !macfilter_rules_out) {
        if (data_obj) json_object_put(data_obj);
        if (appfilter_rules_out) json_object_put(appfilter_rules_out);
        if (macfilter_rules_out) json_object_put(macfilter_rules_out);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (req_obj) {
        mac_obj = json_object_object_get(req_obj, "mac");
    }
    if (mac_obj) {
        mac = json_object_get_string(mac_obj);
    }
    if (mac && mac[0] != '\0') {
        af_whitelist = is_appfilter_whitelist_mac(mac);
        mf_whitelist = is_macfilter_whitelist_mac(mac);
        blacklist_hit = is_mac_in_blacklist_uci(mac);

        fp = fopen(USER_PARENTAL_CONTROL_DETAIL_FILE, "r");
        if (fp) {
            if (fseek(fp, 0, SEEK_END) == 0) {
                file_len = ftell(fp);
                if (file_len > 0) {
                    rewind(fp);
                    json_buf = (char *)calloc(1, (size_t)file_len + 1);
                    if (json_buf && fread(json_buf, 1, (size_t)file_len, fp) == (size_t)file_len) {
                        root_obj = json_tokener_parse(json_buf);
                    }
                }
            }
            fclose(fp);
        }

        if (root_obj) {
            json_object_object_get_ex(root_obj, "appfilter_all_user_rules", &global_app_rules_obj);
            json_object_object_get_ex(root_obj, "macfilter_all_user_rules", &global_mac_rules_obj);
        }

        if (root_obj && json_object_object_get_ex(root_obj, "users", &users_obj)) {
            user_obj = find_user_detail_by_mac(users_obj, mac);
            if (user_obj) {
                struct json_object *status_obj = NULL;
                struct json_object *app_rules_obj = NULL;
                struct json_object *mac_rules_obj = NULL;
                const char *status_raw = NULL;

                if (json_object_object_get_ex(user_obj, "pc_status", &status_obj)) {
                    status_raw = json_object_get_string(status_obj);
                    if (status_raw && status_raw[0] != '\0') {
                        status_key = status_raw;
                    }
                    status_key = map_pc_status_key(status_key);
                }

                if (!af_whitelist &&
                    json_object_object_get_ex(user_obj, "appfilter_rules", &app_rules_obj) &&
                    json_object_is_type(app_rules_obj, json_type_array)) {
                    struct json_object *tmp_rules_out = json_object_new_array();
                    if (tmp_rules_out) {
                        pc_append_array_items(tmp_rules_out, app_rules_obj);
                        json_object_put(appfilter_rules_out);
                        appfilter_rules_out = tmp_rules_out;
                    }
                }

                if (!mf_whitelist &&
                    json_object_object_get_ex(user_obj, "macfilter_rules", &mac_rules_obj) &&
                    json_object_is_type(mac_rules_obj, json_type_array)) {
                    struct json_object *tmp_rules_out = json_object_new_array();
                    if (tmp_rules_out) {
                        pc_append_array_items(tmp_rules_out, mac_rules_obj);
                        json_object_put(macfilter_rules_out);
                        macfilter_rules_out = tmp_rules_out;
                    }
                }
            }
        }

        if (!af_whitelist) {
            pc_append_array_items(appfilter_rules_out, global_app_rules_obj);
        }
        if (!mf_whitelist) {
            pc_append_array_items(macfilter_rules_out, global_mac_rules_obj);
        }

        if (blacklist_hit && !mf_whitelist) {
            struct json_object *blacklist_rule = NULL;
            struct json_object *blacklist_rules_out = NULL;

            status_key = PC_PERMISSION_MAC_BLOCKED;

            blacklist_rules_out = json_object_new_array();
            if (blacklist_rules_out) {
                blacklist_rule = build_blacklist_rule_detail(mac);
                if (blacklist_rule) {
                    json_object_array_add(blacklist_rules_out, blacklist_rule);
                }
                json_object_put(macfilter_rules_out);
                macfilter_rules_out = blacklist_rules_out;
            }
        }

        if (!af_whitelist && json_object_array_length(appfilter_rules_out) == 0) {
            pc_get_current_time_context(&current_weekday, &current_minutes);
            app_rules_resp = fwx_api_get_filter_rules(NULL);
            app_rules = pc_get_response_list(app_rules_resp, "list");
            if (app_rules) {
                len = json_object_array_length(app_rules);
                for (i = 0; i < len; i++) {
                    struct json_object *rule_obj = json_object_array_get_idx(app_rules, i);
                    struct json_object *time_rules_obj = NULL;
                    struct json_object *detail_obj = NULL;

                    if (!pc_is_rule_enabled(rule_obj) || !pc_is_rule_applicable(rule_obj, mac)) {
                        continue;
                    }
                    json_object_object_get_ex(rule_obj, "time_rules", &time_rules_obj);
                    if (!pc_is_time_rule_matched(time_rules_obj, current_weekday, current_minutes)) {
                        continue;
                    }

                    detail_obj = pc_build_appfilter_rule_detail_summary(rule_obj);
                    if (detail_obj) {
                        json_object_array_add(appfilter_rules_out, detail_obj);
                        status_key = PC_PERMISSION_APP_LIMITED;
                    }
                }
            }
        }

        status_key = apply_whitelist_pc_status(status_key, af_whitelist, mf_whitelist);
    }

    if (app_rules_resp) {
        json_object_put(app_rules_resp);
    }
    if (json_buf) {
        free(json_buf);
    }
    json_object_object_add(data_obj, "pc_status", json_object_new_string(status_key));
    json_object_object_add(data_obj, "pc_status_key", json_object_new_string(status_key));
    json_object_object_add(data_obj, "af_whitelist", json_object_new_int(af_whitelist ? 1 : 0));
    json_object_object_add(data_obj, "mf_whitelist", json_object_new_int(mf_whitelist ? 1 : 0));
    json_object_object_add(data_obj, "appfilter_rules", appfilter_rules_out);
    json_object_object_add(data_obj, "macfilter_rules", macfilter_rules_out);
    if (root_obj) {
        json_object_put(root_obj);
    }
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_user_parental_control_rules(struct json_object *req_obj)
{
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    struct json_object *sorted_list_obj = NULL;
    struct json_object *mac_obj = NULL;
    const char *target_mac = NULL;
    int current_weekday = 0;
    int current_minutes = 0;
    struct json_object *app_rules_resp = NULL;
    struct json_object *mac_rules_resp = NULL;
    struct json_object *detail_req = NULL;
    struct json_object *detail_resp = NULL;
    struct json_object *detail_data = NULL;
    struct json_object *app_rules = NULL;
    struct json_object *mac_rules = NULL;
    struct json_object *cached_rules = NULL;
    unsigned long long today_online_time = 0;
    unsigned long long today_active_time = 0;
    unsigned long long today_up_bytes = 0;
    unsigned long long today_down_bytes = 0;
    int i;
    int len;
    int af_whitelist = 0;
    int mf_whitelist = 0;
    int cache_rule_count = 0;

    if (!data_obj || !list_obj) {
        if (data_obj) json_object_put(data_obj);
        if (list_obj) json_object_put(list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (req_obj) {
        json_object_object_get_ex(req_obj, "mac", &mac_obj);
    }
    target_mac = mac_obj ? json_object_get_string(mac_obj) : NULL;
    if (!target_mac) {
        target_mac = "";
    }

    if (target_mac[0] != '\0') {
        af_whitelist = is_appfilter_whitelist_mac(target_mac);
        mf_whitelist = is_macfilter_whitelist_mac(target_mac);
        pc_get_current_time_context(&current_weekday, &current_minutes);
        update_client_nickname();
        update_client_visiting_info();
        pc_get_today_usage_by_mac(target_mac, &today_online_time, &today_active_time,
                                  &today_up_bytes, &today_down_bytes);

        detail_req = json_object_new_object();
        if (detail_req) {
            json_object_object_add(detail_req, "mac", json_object_new_string(target_mac));
            detail_resp = fwx_api_get_parental_control_detail(detail_req);
            detail_data = pc_get_response_data(detail_resp);
            if (detail_data) {
                if (!af_whitelist && json_object_object_get_ex(detail_data, "appfilter_rules", &cached_rules)) {
                    cache_rule_count += pc_add_cached_rules(list_obj, cached_rules, 1);
                }
                cached_rules = NULL;
                if (!mf_whitelist && json_object_object_get_ex(detail_data, "macfilter_rules", &cached_rules)) {
                    cache_rule_count += pc_add_cached_rules(list_obj, cached_rules, 0);
                }
            }
        }

        if (cache_rule_count <= 0 && !af_whitelist) {
            app_rules_resp = fwx_api_get_filter_rules(NULL);
            app_rules = pc_get_response_list(app_rules_resp, "list");
            if (app_rules) {
                len = json_object_array_length(app_rules);
                for (i = 0; i < len; i++) {
                    struct json_object *rule_obj = json_object_array_get_idx(app_rules, i);
                    struct json_object *item_obj = NULL;

                    if (!pc_is_rule_enabled(rule_obj) || !pc_is_rule_applicable(rule_obj, target_mac)) {
                        continue;
                    }

                    item_obj = pc_build_appfilter_rule(rule_obj, current_weekday, current_minutes);
                    if (item_obj) {
                        json_object_array_add(list_obj, item_obj);
                    }
                }
            }
        }

        if (cache_rule_count <= 0 && !mf_whitelist) {
            mac_rules_resp = fwx_api_get_mac_filter_rules(NULL);
            mac_rules = pc_get_response_list(mac_rules_resp, "list");
            if (mac_rules) {
                len = json_object_array_length(mac_rules);
                for (i = 0; i < len; i++) {
                    struct json_object *rule_obj = json_object_array_get_idx(mac_rules, i);
                    struct json_object *item_obj = NULL;

                    if (!pc_is_rule_enabled(rule_obj) || !pc_is_rule_applicable(rule_obj, target_mac)) {
                        continue;
                    }

                    item_obj = pc_build_macfilter_rule(rule_obj, today_active_time, today_up_bytes, today_down_bytes,
                                                       current_weekday, current_minutes);
                    if (item_obj) {
                        json_object_array_add(list_obj, item_obj);
                    }
                }
            }

            if (is_mac_in_blacklist_uci(target_mac)) {
                struct json_object *blacklist_obj = pc_build_blacklist_rule(target_mac);
                if (blacklist_obj) {
                    json_object_array_add(list_obj, blacklist_obj);
                }
            }
        }
    }

    sorted_list_obj = pc_sort_rule_list(list_obj);
    json_object_object_add(data_obj, "mac", json_object_new_string(target_mac));
    json_object_object_add(data_obj, "af_whitelist", json_object_new_int(af_whitelist ? 1 : 0));
    json_object_object_add(data_obj, "mf_whitelist", json_object_new_int(mf_whitelist ? 1 : 0));
    if (sorted_list_obj) {
        json_object_object_add(data_obj, "list", sorted_list_obj);
        json_object_put(list_obj);
    } else {
        json_object_object_add(data_obj, "list", list_obj);
    }

    if (app_rules_resp) {
        json_object_put(app_rules_resp);
    }
    if (mac_rules_resp) {
        json_object_put(mac_rules_resp);
    }
    if (detail_resp) {
        json_object_put(detail_resp);
    }
    if (detail_req) {
        json_object_put(detail_req);
    }

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_user_stat(struct json_object *req_obj) {
    int hour;
    int total_num = 0;
    (void)req_obj;

    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    if (!data_obj || !list_obj) {
        if (data_obj) {
            json_object_put(data_obj);
        }
        if (list_obj) {
            json_object_put(list_obj);
        }
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    extern struct list_head client_list;
    client_node_t *node = NULL;

    list_for_each_entry(node, &client_list, client) {
        unsigned long long today_up_flow = 0;
        unsigned long long today_down_flow = 0;
        unsigned long long today_active_time = 0;
        daily_hourly_stat_t *today_stat = get_today_stat(node);
        struct json_object *item_obj = NULL;

        if (today_stat) {
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                today_up_flow += today_stat->hourly_traffic[hour].up_bytes;
                today_down_flow += today_stat->hourly_traffic[hour].down_bytes;
                today_active_time += today_stat->hourly_active_time[hour];
            }
        }

        item_obj = json_object_new_object();
        if (!item_obj) {
            continue;
        }

        json_object_object_add(item_obj, "m", json_object_new_string(node->mac));
        json_object_object_add(item_obj, "at", json_object_new_int64(today_active_time));
        json_object_object_add(item_obj, "uf", json_object_new_int64(today_up_flow));
        json_object_object_add(item_obj, "df", json_object_new_int64(today_down_flow));
        json_object_array_add(list_obj, item_obj);
        total_num++;
    }

    json_object_object_add(data_obj, "l", list_obj);
    json_object_object_add(data_obj, "n", json_object_new_int(total_num));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}



struct json_object *fwx_api_get_system_base_info(struct json_object *req_obj) {
    int user_session_enable = 0;
    struct json_object *data_obj = NULL;

    (void)req_obj;

    data_obj = json_object_new_object();
    if (!data_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (access(FWX_USER_SESSION_PROC_PATH, F_OK) == 0) {
        user_session_enable = 1;
    }

    json_object_object_add(data_obj, "user_session_enable", json_object_new_int(user_session_enable));
    if (g_fwx_capability.wireless_support) {
        json_object_object_add(data_obj, "wireless_support", json_object_new_int(1));
    }

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_visit_list(struct json_object *req_obj) {
    const char *mac = NULL;
    
    if (req_obj) {
        struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
        if (mac_obj) {
            mac = json_object_get_string(mac_obj);
        }
    }
    
    struct json_object *root_obj = json_object_new_object();
    struct json_object *dev_array = json_object_new_array();
    
    extern struct list_head client_list;
    client_node_t *node = NULL;
    visit_info_t *p_info = NULL;
    
    list_for_each_entry(node, &client_list, client) {
        if (mac && strcmp(mac, node->mac)) {
            continue;
        }
        
        struct json_object *dev_obj = json_object_new_object();
        json_object_object_add(dev_obj, "hostname", json_object_new_string(node->hostname ? node->hostname : "unknown"));
        json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
        json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));
        json_object_object_add(dev_obj, "ipv6", json_object_new_string(node->ipv6));
        
        struct json_object *online_array = json_object_new_array();
        struct json_object *offline_array = json_object_new_array();

        list_for_each_entry(p_info, &node->online_visit, visit) {
            int total_time = p_info->latest_time - p_info->first_time;
            
            struct json_object *visit_obj = json_object_new_object();
            json_object_object_add(visit_obj, "appname", json_object_new_string(get_app_name_by_id(p_info->appid)));
            json_object_object_add(visit_obj, "appid", json_object_new_int(p_info->appid));
            add_app_icon_missing_flag(visit_obj, p_info->appid);
            json_object_object_add(visit_obj, "latest_action", json_object_new_int(p_info->action));
            json_object_object_add(visit_obj, "online", json_object_new_int(1));
            json_object_object_add(visit_obj, "first_time", json_object_new_int(p_info->first_time));
            json_object_object_add(visit_obj, "latest_time", json_object_new_int(p_info->latest_time));
            json_object_object_add(visit_obj, "total_time", json_object_new_int(total_time));
            json_object_array_add(online_array, visit_obj);
        }

        list_for_each_entry(p_info, &node->visit, visit) {
            char *first_time_str = format_time(p_info->first_time);
            char *latest_time_str = format_time(p_info->latest_time);
            int total_time = p_info->latest_time - p_info->first_time;
            
            struct json_object *visit_obj = json_object_new_object();
            json_object_object_add(visit_obj, "appname", json_object_new_string(get_app_name_by_id(p_info->appid)));
            json_object_object_add(visit_obj, "appid", json_object_new_int(p_info->appid));
            add_app_icon_missing_flag(visit_obj, p_info->appid);
            json_object_object_add(visit_obj, "latest_action", json_object_new_int(p_info->action));
            json_object_object_add(visit_obj, "online", json_object_new_int(0));
            json_object_object_add(visit_obj, "first_time", json_object_new_int(p_info->first_time));
            json_object_object_add(visit_obj, "latest_time", json_object_new_int(p_info->latest_time));
            json_object_object_add(visit_obj, "total_time", json_object_new_int(total_time));
            json_object_array_add(offline_array, visit_obj);
            
            if (first_time_str)
                free(first_time_str);
            if (latest_time_str)
                free(latest_time_str);
        }

        json_object_array_sort(online_array, compare_lt);
        json_object_array_sort(offline_array, compare_lt);

        struct json_object *visit_array = json_object_new_array();
        int online_num = json_object_array_length(online_array);
        int offline_num = json_object_array_length(offline_array);
        int idx;
        for (idx = 0; idx < online_num; idx++) {
            struct json_object *item = json_object_array_get_idx(online_array, idx);
            if (item) {
                json_object_get(item);
                json_object_array_add(visit_array, item);
            }
        }
        for (idx = 0; idx < offline_num; idx++) {
            struct json_object *item = json_object_array_get_idx(offline_array, idx);
            if (item) {
                json_object_get(item);
                json_object_array_add(visit_array, item);
            }
        }

        json_object_put(online_array);
        json_object_put(offline_array);

        json_object_object_add(dev_obj, "visit_info", visit_array);
        json_object_array_add(dev_array, dev_obj);
    }
    
    json_object_object_add(root_obj, "dev_list", dev_array);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, root_obj);
}


static int handle_set_nickname(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {

    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return -1;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
   
    struct json_object *nickname_obj = json_object_object_get(req_obj, "nickname");
    if (!nickname_obj || !mac_obj)
        return -1;
    
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return -1;
    }
    int num = fwx_uci_get_list_num(uci_ctx, "user_info", "user_info");
    char mac_str[128] = {0};
    int index = -1;
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            index = i;
            printf("found nickname index: %d\n", index);
            break;
        }
    }

    if (strlen(json_object_get_string(nickname_obj)) > 0) {
        if (index == -1) {
            fwx_uci_add_section(uci_ctx, "user_info", "user_info");
        }
        fwx_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].mac", index, (char *)json_object_get_string(mac_obj));
        fwx_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].nickname", index, (char *)json_object_get_string(nickname_obj));
    }
    else{
        char uci_option[128] = {0};
        sprintf(uci_option, "user_info.@user_info[%d]", index);
        fwx_uci_delete(uci_ctx, uci_option);
        printf("delete nickname mac = %s\n", json_object_get_string(mac_obj));
    }

  
    fwx_uci_commit(uci_ctx, "user_info");
    reload_oaf_rule();

    uci_free_context(uci_ctx);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}

extern fwx_run_time_status_t g_af_status;



static int handle_get_whitelist_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    int i;
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    struct json_object *user_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "appfilter", "whitelist");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str, sizeof(mac_str));
        struct json_object *user_obj = json_object_new_object();
        json_object_object_add(user_obj, "mac", json_object_new_string(mac_str));
        client_node_t *dev = find_client_node(mac_str);
        if (dev){
            json_object_object_add(user_obj, "nickname", json_object_new_string(dev->nickname));
            json_object_object_add(user_obj, "hostname", json_object_new_string(dev->hostname));
        }else{
            json_object_object_add(user_obj, "nickname", json_object_new_string(""));
            json_object_object_add(user_obj, "hostname", json_object_new_string(""));
        }       
        json_object_array_add(user_array, user_obj);
    }
    json_object_object_add(data_obj, "list", user_array);
    json_object_object_add(response, "data", data_obj);
    
    uci_free_context(uci_ctx);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}
static int handle_add_whitelist_user(struct ubus_context *ctx, struct ubus_object *obj,
                    struct ubus_request_data *req, const char *method,
                    struct blob_attr *msg) 
{
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return -1;
    }
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_array = json_object_object_get(req_obj, "mac_list");
    if (!mac_array)
        return -1;


    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return -1;
    }

    int len = json_object_array_length(mac_array);
    for (i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
        fwx_uci_add_section(uci_ctx, "appfilter", "whitelist");
        fwx_uci_set_value(uci_ctx, "appfilter.@whitelist[-1].mac", (char *)json_object_get_string(mac_obj));
    }
    fwx_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();

    uci_free_context(uci_ctx);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


static int handle_del_whitelist_user(struct ubus_context *ctx, struct ubus_object *obj,
                    struct ubus_request_data *req, const char *method,
                    struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return 0;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        printf("mac_obj is NULL\n");
        return 0;
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "appfilter", "whitelist");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            char buf[128] = {0};
            sprintf(buf, "appfilter.@whitelist[%d]", i);
            fwx_uci_delete(uci_ctx, buf);
            break;
        }
    }

    fwx_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();

    uci_free_context(uci_ctx);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


static char *get_model(void) {
    char model[32] = {0};
    struct json_object *board_json = json_object_from_file("/etc/board.json");
    if (!board_json) {
        strcpy(model, "Unknown");
    } else {
        struct json_object *model_obj = json_object_object_get(board_json, "model");
        if (model_obj) {
            struct json_object *name_obj = json_object_object_get(model_obj, "name");
            if (name_obj)
                strncpy(model, json_object_get_string(name_obj), sizeof(model) - 1);
            else
                strcpy(model, "Unknown");
        } else {
            strcpy(model, "Unknown");
        }
    }
    if (board_json)
        json_object_put(board_json);
    

    if (strcmp(model, "Unknown") == 0) {
        char buf[256] = {0};
        if (exec_with_result_line("cat /proc/device-tree/model 2>/dev/null || cat /tmp/sysinfo/board_name 2>/dev/null || echo Unknown", buf, sizeof(buf)) == 0 && strlen(buf) > 0) {
            strncpy(model, buf, sizeof(model) - 1);
        }
    }
    
    return strdup(model);
}


static int get_uptime(void) {
    FILE *uptime_fp = fopen("/proc/uptime", "r");
    if (uptime_fp) {
        double uptime_sec = 0;
        if (fscanf(uptime_fp, "%lf", &uptime_sec) == 1) {
            fclose(uptime_fp);
            return (int)uptime_sec;
        }
        fclose(uptime_fp);
    }
    return 0;
}


static int read_file_buf(const char *file, char *buf, int len) {
    if (!file || !buf || len <= 0)
        return -1;
    
    int fd = open(file, O_RDONLY | O_NONBLOCK, 0644);
    if (fd < 0) {
        return -1;
    }
    
    int size = read(fd, buf, len - 1);
    close(fd);
    
    if (size > 0) {
        buf[size] = '\0';
        str_trim(buf);
        return size;
    }
    
    return -1;
}

static int temperature_value_valid(int temp)
{
    return temp >= -50 && temp <= 150;
}

static int parse_temperature_value(const char *buf, int *temp)
{
    const char *p;

    if (!buf || !temp) {
        return -1;
    }

    p = buf;
    while (*p) {
        if (isdigit((unsigned char)*p) || *p == '-' || *p == '+') {
            char *end = NULL;
            float value = strtof(p, &end);
            if (end && end > p) {
                int value_int;

                if (value > 1000.0f || value < -1000.0f) {
                    value = value / 1000.0f;
                }

                value_int = (int)(value >= 0.0f ? value + 0.5f : value - 0.5f);
                if (temperature_value_valid(value_int)) {
                    *temp = value_int;
                    return 0;
                }
                p = end;
                continue;
            }
        }
        p++;
    }

    return -1;
}

static int get_temperature_from_file(const char *path)
{
    char temp_buf[64] = {0};
    int temp = -1;

    if (read_file_buf(path, temp_buf, sizeof(temp_buf)) <= 0) {
        return -1;
    }

    if (parse_temperature_value(temp_buf, &temp) == 0) {
        return temp;
    }

    return -1;
}

static int is_x86_board(void)
{
    char buf[512] = {0};
    char arch[64] = {0};

    if (read_file_buf("/etc/openwrt_release", buf, sizeof(buf)) > 0) {
        if (strstr(buf, "DISTRIB_TARGET='x86/") ||
            strstr(buf, "DISTRIB_TARGET=\"x86/") ||
            strstr(buf, "DISTRIB_TARGET=x86/")) {
            return 1;
        }
    }

    if (exec_with_result_line("uname -m", arch, sizeof(arch)) == 0) {
        if (strcmp(arch, "x86_64") == 0 ||
            strcmp(arch, "i386") == 0 ||
            strcmp(arch, "i486") == 0 ||
            strcmp(arch, "i586") == 0 ||
            strcmp(arch, "i686") == 0) {
            return 1;
        }
    }

    return 0;
}

static int hwmon_name_score(const char *name)
{
    if (!name || name[0] == '\0') {
        return 0;
    }

    if (strstr(name, "coretemp") ||
        strstr(name, "k10temp") ||
        strstr(name, "zenpower")) {
        return 100;
    }

    if (strstr(name, "x86_pkg_temp") ||
        strstr(name, "cpu_thermal")) {
        return 90;
    }

    if (strstr(name, "acpitz")) {
        return 70;
    }

    if (strstr(name, "cpu")) {
        return 60;
    }

    return 0;
}

static int hwmon_label_score(const char *label)
{
    if (!label || label[0] == '\0') {
        return 0;
    }

    if (strstr(label, "Package id") ||
        strstr(label, "Tctl") ||
        strstr(label, "Tdie")) {
        return 40;
    }

    if (strstr(label, "CPU") ||
        strstr(label, "Core")) {
        return 30;
    }

    return 0;
}

static int get_x86_hwmon_temperature(void)
{
    DIR *hwmon_root = opendir("/sys/class/hwmon");
    struct dirent *hwmon_entry;
    int best_temp = -1;
    int best_score = 0;

    if (!hwmon_root) {
        return -1;
    }

    while ((hwmon_entry = readdir(hwmon_root)) != NULL) {
        char hwmon_dir[256] = {0};
        char name_path[320] = {0};
        char hwmon_name[64] = {0};
        DIR *temp_dir = NULL;
        struct dirent *temp_entry;
        int name_score = 0;

        if (strncmp(hwmon_entry->d_name, "hwmon", 5) != 0) {
            continue;
        }

        snprintf(hwmon_dir, sizeof(hwmon_dir), "/sys/class/hwmon/%s", hwmon_entry->d_name);
        snprintf(name_path, sizeof(name_path), "%s/name", hwmon_dir);
        if (read_file_buf(name_path, hwmon_name, sizeof(hwmon_name)) > 0) {
            name_score = hwmon_name_score(hwmon_name);
        }

        temp_dir = opendir(hwmon_dir);
        if (!temp_dir) {
            continue;
        }

        while ((temp_entry = readdir(temp_dir)) != NULL) {
            char input_path[320] = {0};
            char label_path[320] = {0};
            char label[64] = {0};
            char temp_id[32] = {0};
            char *suffix;
            int label_score = 0;
            int temp = -1;
            int score = name_score;
            size_t id_len;

            if (strncmp(temp_entry->d_name, "temp", 4) != 0) {
                continue;
            }

            suffix = strstr(temp_entry->d_name, "_input");
            if (!suffix) {
                continue;
            }

            id_len = suffix - temp_entry->d_name;
            if (id_len <= 0 || id_len >= sizeof(temp_id)) {
                continue;
            }

            strncpy(temp_id, temp_entry->d_name, id_len);
            temp_id[id_len] = '\0';
            snprintf(input_path, sizeof(input_path), "%s/%s", hwmon_dir, temp_entry->d_name);
            temp = get_temperature_from_file(input_path);
            if (temp < 0) {
                continue;
            }

            snprintf(label_path, sizeof(label_path), "%s/%s_label", hwmon_dir, temp_id);
            if (read_file_buf(label_path, label, sizeof(label)) > 0) {
                label_score = hwmon_label_score(label);
                score += label_score;
            }

            if (score <= 0) {
                continue;
            }

            if (best_temp < 0 || score > best_score) {
                best_temp = temp;
                best_score = score;
            }
        }

        closedir(temp_dir);
    }

    closedir(hwmon_root);
    return best_temp;
}

static int get_x86_sensors_temperature(void)
{
    char temp_buf[64] = {0};
    int temp = -1;
    const char *cmds[] = {
        "sensors \"coretemp-*\" 2>/dev/null | awk '/Package id|Core / {print $2; exit}'",
        "sensors \"k10temp-*\" 2>/dev/null | awk '/Tctl|Tdie|temp1/ {print $2; exit}'",
        "sensors \"zenpower-*\" 2>/dev/null | awk '/Tctl|Tdie|temp1/ {print $2; exit}'",
        "sensors \"acpitz-*\" 2>/dev/null | awk '/temp[0-9]+/ {print $2; exit}'",
        "sensors 2>/dev/null | awk '/Package id|Tctl|Tdie|CPU|Core / {print $2; exit}'",
        NULL
    };
    int i;

    if (access("/usr/bin/sensors", X_OK) != 0 && access("/usr/sbin/sensors", X_OK) != 0) {
        return -1;
    }

    for (i = 0; cmds[i] != NULL; i++) {
        memset(temp_buf, 0, sizeof(temp_buf));
        if (exec_with_result_line((char *)cmds[i], temp_buf, sizeof(temp_buf)) == 0 &&
            parse_temperature_value(temp_buf, &temp) == 0) {
            return temp;
        }
    }

    return -1;
}

static int get_x86_cpu_temperature(void)
{
    int temp = get_x86_hwmon_temperature();

    if (temp > 0) {
        return temp;
    }

    return get_x86_sensors_temperature();
}


static int is_safe_dashboard_port_name(const char *name) {
    if (!name || name[0] == '\0') {
        return 0;
    }
    if (strchr(name, '/') || strstr(name, "..")) {
        return 0;
    }
    return 1;
}

static int dashboard_port_exists(struct json_object *port_array, const char *name) {
    int i;
    int len;

    if (!port_array || !name) {
        return 0;
    }

    len = json_object_array_length(port_array);
    for (i = 0; i < len; i++) {
        struct json_object *item = json_object_array_get_idx(port_array, i);
        struct json_object *name_obj = NULL;
        const char *item_name = NULL;

        if (!item || !json_object_object_get_ex(item, "name", &name_obj)) {
            continue;
        }
        item_name = json_object_get_string(name_obj);
        if (item_name && strcmp(item_name, name) == 0) {
            return 1;
        }
    }

    return 0;
}

static void add_dashboard_port_status(struct json_object *port_array, const char *name, const char *role) {
    char path[128] = {0};
    char state[32] = {0};
    char carrier[32] = {0};
    char speed_buf[32] = {0};
    char mac[64] = {0};
    char duplex[32] = {0};
    char stat_buf[32] = {0};
    int up = 0;
    int speed = 0;
    unsigned long long rx_bytes = 0;
    unsigned long long tx_bytes = 0;
    unsigned long long rx_packets = 0;
    unsigned long long tx_packets = 0;
    unsigned long long rx_error_packets = 0;
    unsigned long long tx_error_packets = 0;
    struct json_object *port_obj = NULL;

    if (!port_array || !is_safe_dashboard_port_name(name) || dashboard_port_exists(port_array, name)) {
        return;
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", name);
    if (read_file_buf(path, carrier, sizeof(carrier)) > 0) {
        up = atoi(carrier) == 1 ? 1 : 0;
    } else {
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", name);
        if (read_file_buf(path, state, sizeof(state)) > 0 && strcmp(state, "up") == 0) {
            up = 1;
        }
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", name);
    if (read_file_buf(path, speed_buf, sizeof(speed_buf)) > 0) {
        speed = atoi(speed_buf);
        if (speed < 0) {
            speed = 0;
        }
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
    read_file_buf(path, mac, sizeof(mac));

    snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", name);
    read_file_buf(path, duplex, sizeof(duplex));

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) rx_bytes = strtoull(stat_buf, NULL, 10);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) tx_bytes = strtoull(stat_buf, NULL, 10);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) rx_packets = strtoull(stat_buf, NULL, 10);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) tx_packets = strtoull(stat_buf, NULL, 10);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_errors", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) rx_error_packets = strtoull(stat_buf, NULL, 10);
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_errors", name);
    if (read_file_buf(path, stat_buf, sizeof(stat_buf)) > 0) tx_error_packets = strtoull(stat_buf, NULL, 10);

    port_obj = json_object_new_object();
    if (!port_obj) {
        return;
    }

    json_object_object_add(port_obj, "name", json_object_new_string(name));
    json_object_object_add(port_obj, "role", json_object_new_string(role ? role : ""));
    json_object_object_add(port_obj, "up", json_object_new_int(up));
    json_object_object_add(port_obj, "speed", json_object_new_int(speed));
    json_object_object_add(port_obj, "mac", json_object_new_string(mac));
    json_object_object_add(port_obj, "duplex", json_object_new_string(duplex));
    json_object_object_add(port_obj, "rx_bytes", json_object_new_int64(rx_bytes));
    json_object_object_add(port_obj, "tx_bytes", json_object_new_int64(tx_bytes));
    json_object_object_add(port_obj, "rx_packets", json_object_new_int64(rx_packets));
    json_object_object_add(port_obj, "tx_packets", json_object_new_int64(tx_packets));
    json_object_object_add(port_obj, "rx_error_packets", json_object_new_int64(rx_error_packets));
    json_object_object_add(port_obj, "tx_error_packets", json_object_new_int64(tx_error_packets));
    json_object_array_add(port_array, port_obj);
}

static void add_dashboard_board_ports(struct json_object *port_array, struct json_object *network_obj, const char *role) {
    struct json_object *role_obj = NULL;
    struct json_object *ports_obj = NULL;
    struct json_object *device_obj = NULL;
    int i;
    int len;

    if (!port_array || !network_obj || !role) {
        return;
    }
    if (!json_object_object_get_ex(network_obj, role, &role_obj) || !role_obj) {
        return;
    }

    if (json_object_object_get_ex(role_obj, "ports", &ports_obj) &&
        json_object_get_type(ports_obj) == json_type_array) {
        len = json_object_array_length(ports_obj);
        for (i = 0; i < len; i++) {
            struct json_object *port_obj = json_object_array_get_idx(ports_obj, i);
            const char *name = port_obj ? json_object_get_string(port_obj) : NULL;
            add_dashboard_port_status(port_array, name, role);
        }
    }

    if (json_object_object_get_ex(role_obj, "device", &device_obj)) {
        add_dashboard_port_status(port_array, json_object_get_string(device_obj), role);
    }
}

static void load_dashboard_ports_from_board_json(struct json_object *port_array) {
    FILE *fp = NULL;
    long file_len = 0;
    char *json_buf = NULL;
    struct json_object *root_obj = NULL;
    struct json_object *network_obj = NULL;

    if (!port_array) {
        return;
    }

    fp = fopen("/etc/board.json", "r");
    if (!fp) {
        return;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return;
    }
    file_len = ftell(fp);
    if (file_len <= 0) {
        fclose(fp);
        return;
    }
    rewind(fp);

    json_buf = (char *)calloc(1, (size_t)file_len + 1);
    if (!json_buf) {
        fclose(fp);
        return;
    }
    if (fread(json_buf, 1, (size_t)file_len, fp) != (size_t)file_len) {
        free(json_buf);
        fclose(fp);
        return;
    }
    fclose(fp);

    root_obj = json_tokener_parse(json_buf);
    free(json_buf);
    if (!root_obj) {
        return;
    }

    if (json_object_object_get_ex(root_obj, "network", &network_obj)) {
        add_dashboard_board_ports(port_array, network_obj, "lan");
        add_dashboard_board_ports(port_array, network_obj, "wan");
    }

    json_object_put(root_obj);
}

static void load_dashboard_eth_ports_from_sysfs(struct json_object *port_array) {
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (!port_array) {
        return;
    }

    dir = opendir("/sys/class/net");
    if (!dir) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "eth", 3) != 0) {
            continue;
        }
        add_dashboard_port_status(port_array, entry->d_name, "unknown");
    }

    closedir(dir);
}

static struct json_object *get_dashboard_port_status(void) {
    struct json_object *port_array = json_object_new_array();

    if (!port_array) {
        return NULL;
    }

    load_dashboard_ports_from_board_json(port_array);
    if (json_object_array_length(port_array) == 0) {
        load_dashboard_eth_ports_from_sysfs(port_array);
    }

    return port_array;
}







static int parse_tempinfo_output(char *output, int *cpu_temp, int *wifi_temp) {
    if (!output || !cpu_temp || !wifi_temp) {
        return -1;
    }
    

    *cpu_temp = -1;
    *wifi_temp = -1;
    

    char *cpu_label = strstr(output, "CPU:");
    if (cpu_label) {
        cpu_label += 4; 

        while (*cpu_label == ' ' || *cpu_label == '\t') {
            cpu_label++;
        }

        char *celsius_pos = strstr(cpu_label, "");
        if (celsius_pos && celsius_pos > cpu_label) {

            char temp_str[64] = {0};
            size_t len = celsius_pos - cpu_label;
            if (len < sizeof(temp_str)) {
                strncpy(temp_str, cpu_label, len);
                temp_str[len] = '\0';

                float cpu_temp_float = 0.0;
                if (sscanf(temp_str, "%f", &cpu_temp_float) == 1) {
                    *cpu_temp = (int)(cpu_temp_float + 0.5); 

                    if (*cpu_temp < -50 || *cpu_temp > 150) {
                        *cpu_temp = -1;
                    }
                }
            }
        }
    }
    

    char *wifi_label = strstr(output, "WiFi:");
    if (wifi_label) {
        wifi_label += 5; 

        while (*wifi_label == ' ' || *wifi_label == '\t') {
            wifi_label++;
        }

        char *celsius_pos = strstr(wifi_label, "");
        if (celsius_pos && celsius_pos > wifi_label) {

            char temp_str[64] = {0};
            size_t len = celsius_pos - wifi_label;
            if (len < sizeof(temp_str)) {
                strncpy(temp_str, wifi_label, len);
                temp_str[len] = '\0';

                float wifi_temp_float = 0.0;
                if (sscanf(temp_str, "%f", &wifi_temp_float) == 1) {
                    *wifi_temp = (int)(wifi_temp_float + 0.5); 

                    if (*wifi_temp < -50 || *wifi_temp > 150) {
                        *wifi_temp = -1;
                    }
                }
            }
        }
    }
    

    if (*cpu_temp > 0 || *wifi_temp > 0) {
        return 0;
    }
    
    return -1;
}


static int get_cpu_temperature(void) {
    int cpu_temp = -1;
    int wifi_temp = -1; 
    int i;

    if (is_x86_board()) {
        int x86_temp = get_x86_cpu_temperature();
        if (x86_temp > 0) {
            return x86_temp;
        }
    }

    if (access("/sbin/tempinfo", F_OK) == 0) {
        FILE *fp = popen("/sbin/tempinfo", "r");
        if (fp) {
            char output[256] = {0};
            char line[256] = {0};
            size_t total_read = 0;
            

            while (fgets(line, sizeof(line), fp) != NULL && total_read < sizeof(output) - 1) {
                size_t line_len = strlen(line);
                if (total_read + line_len < sizeof(output) - 1) {
                    strncpy(output + total_read, line, line_len);
                    total_read += line_len;
                    output[total_read] = '\0';
                } else {
                    break;
                }
            }
            pclose(fp);
            

            if (parse_tempinfo_output(output, &cpu_temp, &wifi_temp) == 0 && cpu_temp > 0) {
                return cpu_temp;
            }
        }
    }
    

    char temp_buf[64] = {0};
    int temp_millidegrees = 0;
    int temp_degrees = 0;
    


    if (read_file_buf("/sys/class/thermal/thermal_zone0/temp", temp_buf, sizeof(temp_buf)) > 0) {
        temp_millidegrees = atoi(temp_buf);
        if (temp_millidegrees > 0) {

            temp_degrees = temp_millidegrees / 1000;

            if (temp_degrees >= -50 && temp_degrees <= 150) {
                return temp_degrees;
            }
        }
    }
    


    for (i = 0; i < 10; i++) {
        char path[256] = {0};
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", i);
        if (read_file_buf(path, temp_buf, sizeof(temp_buf)) > 0) {
            temp_millidegrees = atoi(temp_buf);
            if (temp_millidegrees > 0) {
                temp_degrees = temp_millidegrees / 1000;
                if (temp_degrees >= -50 && temp_degrees <= 150) {
                    return temp_degrees;
                }
            }
        }
    }
    

    return -1;
}


static int get_wifi_temperature(void) {
    int cpu_temp = -1; 
    int wifi_temp = -1;
    int i;

    if (access("/sbin/tempinfo", F_OK) == 0) {
        FILE *fp = popen("/sbin/tempinfo", "r");
        if (fp) {
            char output[256] = {0};
            char line[256] = {0};
            size_t total_read = 0;
            

            while (fgets(line, sizeof(line), fp) != NULL && total_read < sizeof(output) - 1) {
                size_t line_len = strlen(line);
                if (total_read + line_len < sizeof(output) - 1) {
                    strncpy(output + total_read, line, line_len);
                    total_read += line_len;
                    output[total_read] = '\0';
                } else {
                    break;
                }
            }
            pclose(fp);
            

            if (parse_tempinfo_output(output, &cpu_temp, &wifi_temp) == 0 && wifi_temp > 0) {
                return wifi_temp;
            }
        }
    }
    

    char temp_buf[64] = {0};
    int temp_degrees = 0;
    


    if (read_file_buf("/sys/class/ieee80211/phy0/temperature", temp_buf, sizeof(temp_buf)) > 0) {
        temp_degrees = atoi(temp_buf);

        if (temp_degrees >= -50 && temp_degrees <= 150) {
            return temp_degrees;
        }
    }
    

    for (i = 0; i < 10; i++) {
        char path[256] = {0};
        snprintf(path, sizeof(path), "/sys/class/ieee80211/phy%d/temperature", i);
        if (read_file_buf(path, temp_buf, sizeof(temp_buf)) > 0) {
            temp_degrees = atoi(temp_buf);
            if (temp_degrees >= -50 && temp_degrees <= 150) {
                return temp_degrees;
            }
        }
    }
    

    return -1;
}


static int get_cpu_model_name_from_proc(char *model_name, size_t len);
static int get_cpu_model_name_from_ubus(char *model_name, size_t len);


static int get_cpu_model_name_from_proc(char *model_name, size_t len) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        return -1;
    }
    
    char line[256] = {0};
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {

        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {

                char *name_start = colon + 1;

                while (*name_start == ' ' || *name_start == '\t') {
                    name_start++;
                }

                char *newline = strchr(name_start, '\n');
                if (newline) {
                    *newline = '\0';
                }

                char *carriage = strchr(name_start, '\r');
                if (carriage) {
                    *carriage = '\0';
                }

                strncpy(model_name, name_start, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
                break;
            }
        }

        else if (strncmp(line, "cpu model", 9) == 0 || strncmp(line, "Processor", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                char *name_start = colon + 1;
                while (*name_start == ' ' || *name_start == '\t') {
                    name_start++;
                }
                char *newline = strchr(name_start, '\n');
                if (newline) {
                    *newline = '\0';
                }
                char *carriage = strchr(name_start, '\r');
                if (carriage) {
                    *carriage = '\0';
                }
                strncpy(model_name, name_start, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
                break;
            }
        }
    }
    
    fclose(fp);
    
    if (!found) {
        return -1;
    }
    
    LOG_DEBUG("get_cpu_model_name_from_proc: found CPU model: %s\n", model_name);
    return 0;
}


static int get_cpu_model_name(char *model_name, size_t len) {

    if (get_cpu_model_name_from_proc(model_name, len) == 0) {
        return 0;
    }
    

    LOG_DEBUG("get_cpu_model_name: CPU model name not found in /proc/cpuinfo, trying ubus call system board\n");
    if (get_cpu_model_name_from_ubus(model_name, len) == 0) {
        return 0;
    }
    
    return -1;
}


static int get_cpu_model_name_from_ubus(char *model_name, size_t len) {

    FILE *ubus_fp = popen("ubus call system board 2>/dev/null", "r");
    if (!ubus_fp) {
        LOG_ERROR("get_cpu_model_name_from_ubus: failed to call ubus system board\n");
        return -1;
    }
    

    char ubus_output[2048] = {0};
    size_t total_read = 0;
    char line_buf[256] = {0};
    
    while (fgets(line_buf, sizeof(line_buf), ubus_fp) && total_read < sizeof(ubus_output) - 1) {
        size_t line_len = strlen(line_buf);
        if (total_read + line_len < sizeof(ubus_output) - 1) {
            strcat(ubus_output, line_buf);
            total_read += line_len;
        } else {
            break;
        }
    }
    pclose(ubus_fp);
    
    if (strlen(ubus_output) == 0) {
        LOG_ERROR("get_cpu_model_name_from_ubus: ubus output is empty\n");
        return -1;
    }
    

    struct json_object *board_obj = json_tokener_parse(ubus_output);
    if (!board_obj) {
        LOG_ERROR("get_cpu_model_name_from_ubus: failed to parse ubus JSON output\n");
        return -1;
    }
    
    int found = 0;
    

    struct json_object *release_obj = json_object_object_get(board_obj, "release");
    if (release_obj) {
        struct json_object *target_obj = json_object_object_get(release_obj, "target");
        if (target_obj) {
            const char *target_str = json_object_get_string(target_obj);
            if (target_str && strlen(target_str) > 0) {
                strncpy(model_name, target_str, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
            }
        }
    }
    

    if (!found) {
        struct json_object *system_obj = json_object_object_get(board_obj, "system");
        if (system_obj) {
            const char *system_str = json_object_get_string(system_obj);
            if (system_str && strlen(system_str) > 0) {
                strncpy(model_name, system_str, len - 1);
                model_name[len - 1] = '\0';
                str_trim(model_name);
                found = 1;
            }
        }
    }
    
    json_object_put(board_obj);
    
    if (!found) {
        LOG_ERROR("get_cpu_model_name_from_ubus: CPU model name not found in ubus system board\n");
        return -1;
    }
    
    LOG_DEBUG("get_cpu_model_name_from_ubus: found CPU model: %s\n", model_name);
    return 0;
}


static int get_os_release_field(const char *field_name, char *value, size_t len) {
    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) {
        LOG_ERROR("get_os_release_field: failed to open /etc/os-release\n");
        return -1;
    }
    
    char line[256] = {0};
    size_t field_len = strlen(field_name);
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {

        if (strncmp(line, field_name, field_len) == 0 && line[field_len] == '=') {
            char *value_start = line + field_len + 1;

            if (*value_start == '"' || *value_start == '\'') {
                value_start++;
            }
            

            char *value_end = value_start;
            while (*value_end != '\0' && *value_end != '\n' && *value_end != '\r') {
                if ((*value_end == '"' || *value_end == '\'') && value_end > value_start) {
                    break;
                }
                value_end++;
            }
            

            size_t value_size = value_end - value_start;
            if (value_size > 0 && value_size < len) {
                strncpy(value, value_start, value_size);
                value[value_size] = '\0';
                str_trim(value);
                found = 1;
                break;
            }
        }
    }
    
    fclose(fp);
    
    if (!found) {
        LOG_ERROR("get_os_release_field: field %s not found in /etc/os-release\n", field_name);
        return -1;
    }
    
    LOG_DEBUG("get_os_release_field: found %s = %s\n", field_name, value);
    return 0;
}

static int get_fwx_release_field(const char *field_name, char *value, size_t len) {
    FILE *fp = fopen("/etc/fwx_release", "r");
    if (!fp) {
        return -1;
    }

    char line[256] = {0};
    size_t field_len = strlen(field_name);
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *line_ptr = line;
        while (*line_ptr == ' ' || *line_ptr == '\t') {
            line_ptr++;
        }
        if (*line_ptr == '#' || *line_ptr == '\0' || *line_ptr == '\n' || *line_ptr == '\r') {
            continue;
        }

        if (strncmp(line_ptr, field_name, field_len) == 0 && line_ptr[field_len] == '=') {
            char *value_start = line_ptr + field_len + 1;
            while (*value_start == ' ' || *value_start == '\t') {
                value_start++;
            }

            char *value_end = value_start;
            while (*value_end != '\0' && *value_end != '\n' && *value_end != '\r') {
                value_end++;
            }

            size_t value_size = value_end - value_start;
            if (value_size > 0 && value_size < len) {
                strncpy(value, value_start, value_size);
                value[value_size] = '\0';
                str_trim(value);
                value_size = strlen(value);
                if (value_size >= 2) {
                    if ((value[0] == '\'' && value[value_size - 1] == '\'') ||
                        (value[0] == '"' && value[value_size - 1] == '"')) {
                        memmove(value, value + 1, value_size - 2);
                        value[value_size - 2] = '\0';
                    }
                }
                found = 1;
                break;
            }
        }
    }

    fclose(fp);

    if (!found) {
        return -1;
    }
    return 0;
}

static int get_product_feature_field(const char *field_name, char *value, size_t len) {
    FILE *fp = fopen("/etc/product_feature", "r");
    if (!fp) {
        return -1;
    }

    char line[256] = {0};
    size_t field_len = strlen(field_name);
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *line_ptr = line;
        while (*line_ptr == ' ' || *line_ptr == '\t') {
            line_ptr++;
        }
        if (*line_ptr == '#' || *line_ptr == '\0' || *line_ptr == '\n' || *line_ptr == '\r') {
            continue;
        }

        if (strncmp(line_ptr, field_name, field_len) == 0 && line_ptr[field_len] == '=') {
            char *value_start = line_ptr + field_len + 1;
            while (*value_start == ' ' || *value_start == '\t') {
                value_start++;
            }

            char *value_end = value_start;
            while (*value_end != '\0' && *value_end != '\n' && *value_end != '\r') {
                value_end++;
            }

            size_t value_size = value_end - value_start;
            if (value_size > 0 && value_size < len) {
                strncpy(value, value_start, value_size);
                value[value_size] = '\0';
                str_trim(value);
                value_size = strlen(value);
                if (value_size >= 2) {
                    if ((value[0] == '\'' && value[value_size - 1] == '\'') ||
                        (value[0] == '"' && value[value_size - 1] == '"')) {
                        memmove(value, value + 1, value_size - 2);
                        value[value_size - 2] = '\0';
                    }
                }
                found = 1;
                break;
            }
        }
    }

    fclose(fp);

    if (!found) {
        return -1;
    }
    return 0;
}

static int get_dashboard_init_status(void) {
    char init_status_buf[16] = {0};
    int init_status = 1;

    if (read_file_buf("/etc/fwx_init_status", init_status_buf, sizeof(init_status_buf)) > 0) {
        str_trim(init_status_buf);
        if (atoi(init_status_buf) == 0) {
            init_status = 0;
        }
    }

    return init_status;
}

static int set_dashboard_init_status(int init_status) {
    int fd = -1;
    char status_buf[8] = {0};
    int len = 0;

    if (init_status != 0 && init_status != 1) {
        return -1;
    }

    fd = open("/etc/fwx_init_status", O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0) {
        return -1;
    }

    len = snprintf(status_buf, sizeof(status_buf), "%d\n", init_status);
    if (len <= 0 || write(fd, status_buf, len) != len) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}


static struct json_object *get_dashboard_system_status(void) {
    struct json_object *system_status = json_object_new_object();
    char buf[256] = {0};
    char result[128] = {0};
	int hour;
    

    char *model = get_model();
    json_object_object_add(system_status, "model", json_object_new_string(model));
    free(model);
    

    char cpu_model_name[256] = {0};
    if (get_cpu_model_name(cpu_model_name, sizeof(cpu_model_name)) == 0) {
        json_object_object_add(system_status, "cpu_model_name", json_object_new_string(cpu_model_name));
    } else {
        json_object_object_add(system_status, "cpu_model_name", json_object_new_string("Unknown"));
    }
    

    char hostname[128] = {0};
    if (read_file_buf("/proc/sys/kernel/hostname", hostname, sizeof(hostname)) > 0) {
        json_object_object_add(system_status, "hostname", json_object_new_string(hostname));
    } else {
        json_object_object_add(system_status, "hostname", json_object_new_string("Unknown"));
    }
    

    char openwrt_version[64] = {0};
    if (get_os_release_field("VERSION", openwrt_version, sizeof(openwrt_version)) == 0) {
        json_object_object_add(system_status, "openwrt_version", json_object_new_string(openwrt_version));
    } else {
        json_object_object_add(system_status, "openwrt_version", json_object_new_string("Unknown"));
    }
    

    char arch[64] = {0};
    if (get_os_release_field("OPENWRT_ARCH", arch, sizeof(arch)) == 0) {
        json_object_object_add(system_status, "arch", json_object_new_string(arch));
    } else {
        json_object_object_add(system_status, "arch", json_object_new_string("Unknown"));
    }
    

    char oaf_version_buf[32] = {0};
    if (read_file_buf("/etc/oaf_version", oaf_version_buf, sizeof(oaf_version_buf)) > 0) {
        str_trim(oaf_version_buf);
        json_object_object_add(system_status, "fwx_version", json_object_new_string(oaf_version_buf));
    } else {

        if (read_file_buf("/etc/version", oaf_version_buf, sizeof(oaf_version_buf)) > 0) {
            str_trim(oaf_version_buf);
            json_object_object_add(system_status, "fwx_version", json_object_new_string(oaf_version_buf));
        } else {
            json_object_object_add(system_status, "fwx_version", json_object_new_string("Unknown"));
        }
    }

    char release_type_buf[16] = {0};
    if (get_fwx_release_field("RELEASE_TYPE", release_type_buf, sizeof(release_type_buf)) == 0) {
        json_object_object_add(system_status, "release_type", json_object_new_int(atoi(release_type_buf)));
    } else {
        json_object_object_add(system_status, "release_type", json_object_new_int(0));
    }

    char snapshot_buf[16] = {0};
    if (get_fwx_release_field("SNAPSHOT", snapshot_buf, sizeof(snapshot_buf)) == 0) {
        json_object_object_add(system_status, "snapshot", json_object_new_int(atoi(snapshot_buf)));
    } else {
        json_object_object_add(system_status, "snapshot", json_object_new_int(0));
    }

    char release_date[32] = {0};
    if (get_fwx_release_field("RELEASE_DATE", release_date, sizeof(release_date)) == 0) {
        str_trim(release_date);
        json_object_object_add(system_status, "release_date", json_object_new_string(release_date));
    } else {
        json_object_object_add(system_status, "release_date", json_object_new_string(""));
    }

    char expand_root_buf[16] = {0};
    if (get_product_feature_field("EXPAND_ROOT", expand_root_buf, sizeof(expand_root_buf)) == 0) {
        json_object_object_add(system_status, "expand_root", json_object_new_int(atoi(expand_root_buf)));
    } else {
        json_object_object_add(system_status, "expand_root", json_object_new_int(0));
    }

    memset(buf, 0, sizeof(buf));
    if (exec_with_result_line("uname -r", buf, sizeof(buf)) == 0 && strlen(buf) > 0) {
        str_trim(buf);
        json_object_object_add(system_status, "kernel_version", json_object_new_string(buf));
    } else {
        json_object_object_add(system_status, "kernel_version", json_object_new_string("Unknown"));
    }
    

    int uptime = get_uptime();
    json_object_object_add(system_status, "uptime", json_object_new_int(uptime));
    json_object_object_add(system_status, "oaf", json_object_new_int(1));

    memset(result, 0, sizeof(result));
    int total_mem_kb = 0;
    int used_mem_kb = 0;
    if (exec_with_result_line("free | grep Mem | awk '{print $2}'", result, sizeof(result)) == 0) {
        total_mem_kb = atoi(result);
    }
    memset(result, 0, sizeof(result));
    if (exec_with_result_line("free | grep Mem | awk '{print $3}'", result, sizeof(result)) == 0) {
        used_mem_kb = atoi(result);
    }
    

    json_object_object_add(system_status, "total_mem", json_object_new_int(total_mem_kb));
    json_object_object_add(system_status, "used_mem", json_object_new_int(used_mem_kb));
    

    memset(result, 0, sizeof(result));
    int cpu_usage = 0;

    if (exec_with_result_line("top -n 1 | grep 'CPU:' | awk -F '%' '{print$4}' | awk -F ' ' '{print$2}'", result, sizeof(result)) < 0) {

        cpu_usage = 0;
    } else {
        cpu_usage = 100 - atoi(result);
    } 


    snprintf(buf, sizeof(buf), "%d", cpu_usage);
    json_object_object_add(system_status, "cpu", json_object_new_string(buf));
    

    int connections = fwx_stat_read_conntrack_count();
    json_object_object_add(system_status, "connections", json_object_new_int(connections));
    
    

    extern struct list_head client_list;
    int online_client_num = 0;
    int offline_client_num = 0;
    client_node_t *client = NULL;
    list_for_each_entry(client, &client_list, client) {
        if (client->online == 1) {
            online_client_num++;
        } else {
            offline_client_num++;
        }
    }
    json_object_object_add(system_status, "client_num", json_object_new_int(online_client_num));
    json_object_object_add(system_status, "online_user_count", json_object_new_int(online_client_num));
    json_object_object_add(system_status, "offline_user_count", json_object_new_int(offline_client_num));

    int af_rule_count = count_enabled_uci_rules("appfilter");
    int mf_rule_count = count_enabled_uci_rules("macfilter");
    json_object_object_add(system_status, "af_rule_count", json_object_new_int(af_rule_count));
    json_object_object_add(system_status, "mf_rule_count", json_object_new_int(mf_rule_count));
    json_object_object_add(system_status, "filter_rule_count", json_object_new_int(af_rule_count + mf_rule_count));
    

    struct json_object *storage_obj = json_object_new_object();
    FILE *df_fp = popen("df -k", "r");
    if (df_fp) {
        char line[512];
        int found_tmp = 0, found_root = 0, found_boot = 0;
        

        if (fgets(line, sizeof(line), df_fp)) {

            while (fgets(line, sizeof(line), df_fp)) {
                char filesystem[256] = {0};
                unsigned long long total_kb = 0, used_kb = 0;
                unsigned long long available_kb = 0;  
                int use_percent = 0; 
                char mount_point[256] = {0};
                


                if (sscanf(line, "%255s %llu %llu %llu %d%% %255s", 
                          filesystem, &total_kb, &used_kb, &available_kb, &use_percent, mount_point) >= 6) {

                    if (strcmp(mount_point, "/tmp") == 0 && !found_tmp) {
                        struct json_object *tmp_obj = json_object_new_object();
                        json_object_object_add(tmp_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(tmp_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "tmp", tmp_obj);
                        found_tmp = 1;
                    } else if (strcmp(mount_point, "/") == 0 && !found_root) {
                        struct json_object *root_obj = json_object_new_object();
                        json_object_object_add(root_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(root_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "root", root_obj);
                        found_root = 1;
                    } else if (strcmp(mount_point, "/boot") == 0 && !found_boot) {
                        struct json_object *boot_obj = json_object_new_object();
                        json_object_object_add(boot_obj, "total_kb", json_object_new_int64(total_kb));
                        json_object_object_add(boot_obj, "used_kb", json_object_new_int64(used_kb));
                        json_object_object_add(storage_obj, "boot", boot_obj);
                        found_boot = 1;
                    }
                }
                

                if (found_tmp && found_root && found_boot) {
                    break;
                }
            }
        }
        pclose(df_fp);
    }
    

    if (!json_object_object_get(storage_obj, "tmp")) {
        struct json_object *tmp_obj = json_object_new_object();
        json_object_object_add(tmp_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(tmp_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "tmp", tmp_obj);
    }
    if (!json_object_object_get(storage_obj, "root")) {
        struct json_object *root_obj = json_object_new_object();
        json_object_object_add(root_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(root_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "root", root_obj);
    }
    if (!json_object_object_get(storage_obj, "boot")) {
        struct json_object *boot_obj = json_object_new_object();
        json_object_object_add(boot_obj, "total_kb", json_object_new_int64(0));
        json_object_object_add(boot_obj, "used_kb", json_object_new_int64(0));
        json_object_object_add(storage_obj, "boot", boot_obj);
    }
    
    json_object_object_add(system_status, "storage", storage_obj);
    

    struct json_object *flow_obj = json_object_new_object();
    unsigned long long today_up = 0;
    unsigned long long today_down = 0;
    

    extern traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY];
    extern u_int32_t g_global_traffic_date;
    

    u_int32_t today = get_today_start_timestamp();
    if (g_global_traffic_date == today) {
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            today_down += g_global_hourly_traffic[hour].down_bytes;
            today_up += g_global_hourly_traffic[hour].up_bytes;
        }
    } else {


        today_down = 0;
        today_up = 0;
    }
    

    today_down = today_down / 1024;
    today_up = today_up / 1024;
    
    json_object_object_add(flow_obj, "today_up", json_object_new_int64(today_up));
    json_object_object_add(flow_obj, "today_down", json_object_new_int64(today_down));
    json_object_object_add(system_status, "flow", flow_obj);


    int cpu_temp = get_cpu_temperature();
    if (cpu_temp > 0) {
        json_object_object_add(system_status, "cpu_temp", json_object_new_int(cpu_temp));
    }
    

    int wifi_temp = get_wifi_temperature();
    if (wifi_temp > 0) {
        json_object_object_add(system_status, "wifi_temp", json_object_new_int(wifi_temp));
    }
    
    return system_status;
}


static struct json_object *get_dashboard_network_status(void) {
    struct json_object *network_status = json_object_new_object();
    struct uci_context *uci_ctx = uci_alloc_context();
    

    int work_mode = 1; 
    if (uci_ctx) {
        work_mode = fwx_uci_get_int_value(uci_ctx, "appfilter.global.work_mode");
        if (work_mode < 0) work_mode = 1;
    }
    json_object_object_add(network_status, "work_mode", json_object_new_int(work_mode));
    


    struct json_object *lan_obj = json_object_new_object();
    iface_status_t lan_status;
    memset(&lan_status, 0, sizeof(lan_status));
    
    if (get_iface_status("lan", &lan_status) == 0) {
        
	    json_object_object_add(lan_obj, "ip", json_object_new_string(strlen(lan_status.ip) > 0 ? lan_status.ip : ""));
	    json_object_object_add(lan_obj, "mask", json_object_new_string(strlen(lan_status.mask) > 0 ? lan_status.mask : ""));
	
	    json_object_object_add(lan_obj, "gateway", json_object_new_string(strlen(lan_status.gateway) > 0 ? lan_status.gateway : ""));

	    struct json_object *lan_dns = json_object_new_array();
	    if (strlen(lan_status.dns1) > 0) {
	        json_object_array_add(lan_dns, json_object_new_string(lan_status.dns1));
	    }
	    if (strlen(lan_status.dns2) > 0) {
	        json_object_array_add(lan_dns, json_object_new_string(lan_status.dns2));
	    }
	    json_object_object_add(lan_obj, "dns", lan_dns);
    }
    
    json_object_object_add(network_status, "lan", lan_obj);
    
    struct json_object *wan_obj = json_object_new_object();
    iface_status_t wan_status;
    memset(&wan_status, 0, sizeof(wan_status));
	
    if (get_iface_status("wan", &wan_status) == 0){
	    json_object_object_add(wan_obj, "ip", json_object_new_string(wan_status.ip));
	    json_object_object_add(wan_obj, "mask", json_object_new_string(wan_status.mask));
	    json_object_object_add(wan_obj, "gateway", json_object_new_string(wan_status.gateway));
	    struct json_object *wan_dns = json_object_new_array();
	    if (strlen(wan_status.dns1) > 0) {
	        json_object_array_add(wan_dns, json_object_new_string(wan_status.dns1));
	    }
	    if (strlen(wan_status.dns2) > 0) {
	        json_object_array_add(wan_dns, json_object_new_string(wan_status.dns2));
	    }
		
		json_object_object_add(wan_obj, "dns", wan_dns);
    }
    json_object_object_add(network_status, "wan", wan_obj);
    json_object_object_add(network_status, "port_status", get_dashboard_port_status());
    
    if (uci_ctx) {
        uci_free_context(uci_ctx);
    }
    
    return network_status;
}


static struct json_object *get_dashboard_active_app(void) {
    struct json_object *active_app = json_object_new_object();
    struct json_object *app_list = json_object_new_array();
    
    int online_record_count = collect_active_app_visit_records(NULL, 0);
    int offline_record_count = count_app_visit_record_rows();
    FILE *fp = fopen("/proc/net/af_active_app", "r");
    if (!fp) {

        json_object_object_add(active_app, "total", json_object_new_int(online_record_count));
        json_object_object_add(active_app, "online_total", json_object_new_int(online_record_count));
        json_object_object_add(active_app, "offline_total", json_object_new_int(offline_record_count));
        json_object_object_add(active_app, "list", app_list);
        return active_app;
    }
    
    char line[1024] = {0};
    int line_count = 0;
    int total_count = 0;
    

    while (fgets(line, sizeof(line), fp)) {

        if (line_count == 0) {
            line_count++;
            continue;
        }
        

        str_trim(line);
        if (strlen(line) == 0) {
            continue;
        }
        



        unsigned int app_id;
        char mac[32] = {0};
        char src_ip[64] = {0};
        unsigned int src_port;
        char dst_ip[64] = {0};
        unsigned int dst_port;
        char proto[8] = {0};
        unsigned int app_proto;
        unsigned int drop;
        char host[64] = {0};
        unsigned int last_update;
        char uri[64] = {0};
        u_int32_t current_time = get_timestamp();



        int parsed = sscanf(line, "%u %s %s %u %s %u %s %u %u %63s %u %63s",
                           &app_id, mac, src_ip, &src_port, dst_ip, &dst_port,
                           proto, &app_proto, &drop, host, &last_update, uri);
        

        if (parsed < 10) {
            continue; 
        }
        if (current_time > last_update && (current_time - last_update) > 180) {
            continue; 
        }

        if (parsed < 12) {
            uri[0] = '\0';
        }
        

        str_trim(host);
        str_trim(uri);
        

        struct json_object *app = json_object_new_object();
        json_object_object_add(app, "id", json_object_new_int(app_id));
        add_app_icon_missing_flag(app, app_id);
        

        const char *app_name = get_app_name_by_id(app_id);
        if (app_name && strlen(app_name) > 0) {
            json_object_object_add(app, "name", json_object_new_string(app_name));
        } else {
            json_object_object_add(app, "name", json_object_new_string(""));
        }
        

        json_object_object_add(app, "mac", json_object_new_string(mac));

        client_node_t *client = find_client_node(mac);
        if (client) {
            json_object_object_add(app, "hostname", json_object_new_string(client->hostname[0] ? client->hostname : ""));
            json_object_object_add(app, "nickname", json_object_new_string(client->nickname[0] ? client->nickname : ""));
        } else {
            json_object_object_add(app, "hostname", json_object_new_string(""));
            json_object_object_add(app, "nickname", json_object_new_string(""));
        }
        

        json_object_object_add(app, "src_ip", json_object_new_string(src_ip));
        json_object_object_add(app, "dst_ip", json_object_new_string(dst_ip));
        

        json_object_object_add(app, "src_port", json_object_new_int(src_port));
        json_object_object_add(app, "dst_port", json_object_new_int(dst_port));
        

        json_object_object_add(app, "protocol", json_object_new_string(proto));
        

        json_object_object_add(app, "app_proto", json_object_new_int(app_proto));
        

        json_object_object_add(app, "drop", json_object_new_int(drop));
        

        if (host[0] != '\0' && strcmp(host, "-") != 0) {
            json_object_object_add(app, "domain", json_object_new_string(host));
        } else {
            json_object_object_add(app, "domain", json_object_new_string(""));
        }
        

        if (app_proto == 1 && uri[0] != '\0' && strcmp(uri, "-") != 0) {
            json_object_object_add(app, "uri", json_object_new_string(uri));
        } else {
            json_object_object_add(app, "uri", json_object_new_string(""));
        }
        

        json_object_object_add(app, "timestamp", json_object_new_int(last_update));
        
        json_object_array_add(app_list, app);
        total_count++;
    }
    
    fclose(fp);
    
    json_object_object_add(active_app, "total", json_object_new_int(online_record_count));
    json_object_object_add(active_app, "online_total", json_object_new_int(online_record_count));
    json_object_object_add(active_app, "offline_total", json_object_new_int(offline_record_count));
    json_object_object_add(active_app, "list", app_list);
    
    return active_app;
}


static int compare_host_timestamp(const void *a, const void *b) {
    struct json_object *obj_a = *(struct json_object **)a;
    struct json_object *obj_b = *(struct json_object **)b;
    
    struct json_object *ts_a, *ts_b;
    json_object_object_get_ex(obj_a, "timestamp", &ts_a);
    json_object_object_get_ex(obj_b, "timestamp", &ts_b);
    
    int ts_val_a = ts_a ? json_object_get_int(ts_a) : 0;
    int ts_val_b = ts_b ? json_object_get_int(ts_b) : 0;
    
    return ts_val_b - ts_val_a; 
}

static int is_invalid_active_host_value(const char *host) {
    if (!host || host[0] == '\0') {
        return 1;
    }
    if (strcmp(host, "-") == 0) {
        return 1;
    }
    if (strcasecmp(host, "undefined") == 0 ||
        strncasecmp(host, "undefined.", 10) == 0 ||
        strncasecmp(host, "undefined:", 10) == 0) {
        return 1;
    }
    if (strcasecmp(host, "null") == 0 ||
        strcasecmp(host, "(null)") == 0) {
        return 1;
    }
    return 0;
}


static struct json_object *get_dashboard_active_host(void) {
    struct json_object *active_host = json_object_new_object();
    struct json_object *host_list = json_object_new_array();
    int i;
    FILE *fp = fopen("/proc/net/af_active_host", "r");
    if (!fp) {

        json_object_object_add(active_host, "total", json_object_new_int(0));
        json_object_object_add(active_host, "list", host_list);
        return active_host;
    }
    
    char line[1024] = {0};
    int line_count = 0;
    int total_count = 0;
    

    while (fgets(line, sizeof(line), fp)) {

        if (line_count == 0) {
            line_count++;
            continue;
        }
        

        str_trim(line);
        if (strlen(line) == 0) {
            continue;
        }
        


        char host_buf[64] = {0};
        char mac[32] = {0};
        char src_ip[64] = {0};
        unsigned int src_port;
        char dst_ip[64] = {0};
        unsigned int dst_port;
        char proto[8] = {0};
        unsigned int app_proto;
        unsigned int drop;
        unsigned int last_update;
        

        int parsed = sscanf(line, "%63s %s %s %u %s %u %s %u %u %u",
                           host_buf, mac, src_ip, &src_port, dst_ip, &dst_port,
                           proto, &app_proto, &drop, &last_update);
        

        if (parsed < 10) {
            continue; 
        }
        

        time_t current_time = time(NULL);
        if (current_time > last_update && (current_time - last_update) > 180) {
            continue;
        }
        

        str_trim(host_buf);
        

        if (is_invalid_active_host_value(host_buf)) {
            continue;
        }
        

        struct json_object *host_obj = json_object_new_object();
        

        json_object_object_add(host_obj, "mac", json_object_new_string(mac));
        

        extern struct list_head client_list;
        client_node_t *client = find_client_node(mac);
        

        char display_name[128] = {0};
        if (client && client->nickname[0] != '\0') {
            strncpy(display_name, client->nickname, sizeof(display_name) - 1);
        } else if (client && client->hostname[0] != '\0') {
            strncpy(display_name, client->hostname, sizeof(display_name) - 1);
        } else {
            strncpy(display_name, mac, sizeof(display_name) - 1);
        }
        json_object_object_add(host_obj, "name", json_object_new_string(display_name));
        

        if (client) {
            json_object_object_add(host_obj, "hostname", json_object_new_string(client->hostname[0] ? client->hostname : ""));
            json_object_object_add(host_obj, "nickname", json_object_new_string(client->nickname[0] ? client->nickname : ""));
        } else {
            json_object_object_add(host_obj, "hostname", json_object_new_string(""));
            json_object_object_add(host_obj, "nickname", json_object_new_string(""));
        }
        

        char url[128] = {0};
        if (app_proto == 1) {  
            snprintf(url, sizeof(url), "http://%s", host_buf);
        } else if (app_proto == 2) {  
            snprintf(url, sizeof(url), "https://%s", host_buf);
        } else {

            strncpy(url, host_buf, sizeof(url) - 1);
        }
        json_object_object_add(host_obj, "url", json_object_new_string(url));
        json_object_object_add(host_obj, "host", json_object_new_string(host_buf));
        

        json_object_object_add(host_obj, "app_proto", json_object_new_int(app_proto));
        


        json_object_object_add(host_obj, "timestamp", json_object_new_int(last_update));
        
        json_object_array_add(host_list, host_obj);
        total_count++;
    }
    
    fclose(fp);
    

    if (total_count > 0) {
        json_object_array_sort(host_list, compare_host_timestamp);
    }
    

    #define MAX_HOST_LIST_SIZE 10
    int array_len = json_object_array_length(host_list);
    if (array_len > MAX_HOST_LIST_SIZE) {

        for (i = array_len - 1; i >= MAX_HOST_LIST_SIZE; i--) {
            struct json_object *old_obj = json_object_array_get_idx(host_list, i);
            json_object_array_del_idx(host_list, i, 1);
        }
    }
    
    json_object_object_add(active_host, "total", json_object_new_int(total_count));
    json_object_object_add(active_host, "list", host_list);
    
    return active_host;
}



static int get_interface_device(const char *interface_name, char *device_name, size_t device_name_len) {
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("get_interface_device: failed to allocate UCI context\n");
        return -1;
    }
    
    char uci_key[128] = {0};
    snprintf(uci_key, sizeof(uci_key), "network.%s.device", interface_name);
    
    int ret = fwx_uci_get_value(uci_ctx, uci_key, device_name, device_name_len);
    uci_free_context(uci_ctx);
    
    if (ret != 0) {
        LOG_ERROR("get_interface_device: failed to get device for interface %s\n", interface_name);
        return -1;
    }
    
    return 0;
}


static int read_interface_traffic(const char *ifname, unsigned long long *up_bytes, unsigned long long *down_bytes) {
    FILE *netdev_fp = fopen("/proc/net/dev", "r");
    if (!netdev_fp) {
        LOG_ERROR("read_interface_traffic: failed to open /proc/net/dev\n");
        return -1;
    }
    
    char line[512];
    int found = 0;
    

    fgets(line, sizeof(line), netdev_fp);
    fgets(line, sizeof(line), netdev_fp);
    
    while (fgets(line, sizeof(line), netdev_fp)) {
        char interface[32] = {0};
        unsigned long long rx_pkts, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast;
        unsigned long long tx_pkts, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed;
        unsigned long long rx_bytes = 0, tx_bytes = 0;
        

        char *colon = strchr(line, ':');
        if (colon) {
            int ifname_len = colon - line;
            if (ifname_len > 0 && ifname_len < sizeof(interface)) {
                strncpy(interface, line, ifname_len);
                interface[ifname_len] = '\0';
                str_trim(interface);
                

                if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", 
                           &rx_bytes, &rx_pkts, &rx_errs, &rx_drop, &rx_fifo, &rx_frame, &rx_compressed, &rx_multicast, &tx_bytes) >= 9) {
                    if (strcmp(interface, ifname) == 0) {
                        *down_bytes = rx_bytes;  
                        *up_bytes = tx_bytes;    
                        found = 1;
                        break;
                    }
                }
            }
        }
    }
    
    fclose(netdev_fp);
    return found ? 0 : -1;
}


static void add_interface_traffic_point(unsigned long long up_bytes, unsigned long long down_bytes) {
    u_int32_t current_time = time(NULL);
    unsigned int up_rate = 0;
    unsigned int down_rate = 0;
    

    if (last_traffic_time > 0 && current_time > last_traffic_time) {
        unsigned long long up_diff = (up_bytes > last_up_bytes) ? (up_bytes - last_up_bytes) : 0;
        unsigned long long down_diff = (down_bytes > last_down_bytes) ? (down_bytes - last_down_bytes) : 0;
        unsigned int time_diff = current_time - last_traffic_time;
        
        if (time_diff > 0) {
            up_rate = (unsigned int)(up_diff / time_diff);
            down_rate = (unsigned int)(down_diff / time_diff);
        }
    }
    

    interface_traffic_node_t *node = (interface_traffic_node_t *)calloc(1, sizeof(interface_traffic_node_t));
    if (!node) {
        return;
    }
    
    node->up_bytes = up_bytes;
    node->down_bytes = down_bytes;
    node->up_rate = up_rate;
    node->down_rate = down_rate;
    node->timestamp = current_time;
    

    list_add(&node->list, &interface_traffic_list);
    interface_traffic_count++;
    

    if (interface_traffic_count > MAX_INTERFACE_TRAFFIC_POINTS) {
        interface_traffic_node_t *old_node = list_last_entry(&interface_traffic_list, interface_traffic_node_t, list);
        list_del(&old_node->list);
        free(old_node);
        interface_traffic_count--;
    }
    

    last_up_bytes = up_bytes;
    last_down_bytes = down_bytes;
    last_traffic_time = current_time;
    
    LOG_DEBUG("add_interface_traffic_point: up_rate=%u B/s, down_rate=%u B/s\n", up_rate, down_rate);
}

void check_and_update_monitor_device(void) {    
    char monitor_device[64] = {0};
    char wan_device_name[16] = {0};

    monitor_device[0] = '\0';
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx)
        return;
    
    int ret = fwx_uci_get_value(uci_ctx, "fwx.dashboard.monitor_device", monitor_device, sizeof(monitor_device));
    if (ret == 0 && strlen(monitor_device) > 0) {
        strncpy(g_interface_name, monitor_device, sizeof(g_interface_name) - 1);
    }
    else{
        if (get_interface_device("wan", wan_device_name, sizeof(wan_device_name)) == 0 && strlen(wan_device_name) > 0) {
            strncpy(g_interface_name, wan_device_name, sizeof(g_interface_name) - 1);
        } else {
            strcpy(g_interface_name, "br-lan");
        }
        fwx_uci_set_value(uci_ctx, "fwx.dashboard.monitor_device", g_interface_name);
        fwx_uci_commit(uci_ctx, "fwx");
    }
    uci_free_context(uci_ctx);
}


void collect_interface_traffic_rate(void) {
    unsigned long long up_bytes = 0, down_bytes = 0;
    if (strlen(g_interface_name) == 0){
        check_and_update_monitor_device();
        if (strlen(g_interface_name) == 0) {
            return;
        }
    }

    if (read_interface_traffic(g_interface_name, &up_bytes, &down_bytes) == 0)
        add_interface_traffic_point(up_bytes, down_bytes);
}

static struct json_object *get_dashboard_interface_traffic(void) {
    struct json_object *interface_traffic = json_object_new_object();
    json_object_object_add(interface_traffic, "interface", json_object_new_string(g_interface_name));
    struct json_object *traffic_array = json_object_new_array();
    interface_traffic_node_t *node = NULL;
    list_for_each_entry_reverse(node, &interface_traffic_list, list) {
        struct json_object *traffic = json_object_new_object();
        json_object_object_add(traffic, "up", json_object_new_int64(node->up_rate));
        json_object_object_add(traffic, "down", json_object_new_int64(node->down_rate));
        json_object_array_add(traffic_array, traffic);
    }
    
    int current_count = interface_traffic_count;
    while (current_count < MAX_INTERFACE_TRAFFIC_POINTS) {
        struct json_object *traffic = json_object_new_object();
        json_object_object_add(traffic, "up", json_object_new_int64(0));
        json_object_object_add(traffic, "down", json_object_new_int64(0));
        json_object_array_add(traffic_array, traffic);
        current_count++;
    }
    
    json_object_object_add(interface_traffic, "traffic", traffic_array);
    
    return interface_traffic;
}

static struct json_object *get_dashboard_oaf_status(struct json_object *system_status)
{
    struct json_object *oaf_status = json_object_new_object();
    char version[160] = {0};
    char buf[128] = {0};
    int work_mode = -1;
    int record_enable = 0;

    (void)system_status;
    if (read_file_buf("/etc/oaf_version", version, sizeof(version)) > 0) {
        str_trim(version);
    } else {
        version[0] = '\0';
    }
    json_object_object_add(oaf_status, "version", json_object_new_string(version));

    if (read_file_buf("/proc/sys/fwx/version", buf, sizeof(buf)) > 0) {
        str_trim(buf);
        json_object_object_add(oaf_status, "engine_version", json_object_new_string(buf));
    } else {
        json_object_object_add(oaf_status, "engine_version", json_object_new_string(""));
    }

    memset(buf, 0, sizeof(buf));
    if (read_file_buf("/proc/sys/fwx/work_mode", buf, sizeof(buf)) > 0) {
        str_trim(buf);
        work_mode = atoi(buf);
    }
    json_object_object_add(oaf_status, "work_mode", json_object_new_int(work_mode));

    memset(buf, 0, sizeof(buf));
    if (read_file_buf("/proc/sys/fwx/record_enable", buf, sizeof(buf)) > 0) {
        str_trim(buf);
        record_enable = atoi(buf);
    }
    json_object_object_add(oaf_status, "record_enable", json_object_new_int(record_enable));

    json_object_object_add(oaf_status, "app_record_count", json_object_new_int(count_app_visit_record_rows()));
    json_object_object_add(oaf_status, "feature", build_feature_info_object());

    return oaf_status;
}


struct json_object *fwx_api_get_dashboard_common(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    update_client_nickname();

    struct json_object *system_status = get_dashboard_system_status();
    struct json_object *network_status = get_dashboard_network_status();
    struct json_object *active_app = get_dashboard_active_app();
    struct json_object *active_host = get_dashboard_active_host();
    struct json_object *interface_traffic = get_dashboard_interface_traffic();
    struct json_object *oaf_status = get_dashboard_oaf_status(system_status);
    struct json_object *advanced = json_object_new_object();
    json_object_object_add(advanced, "disable_hnat", json_object_new_int(fwx_get_disable_hnat()));
    json_object_object_add(advanced, "notice_status", json_object_new_int(fwx_get_notice_status()));
    
    json_object_object_add(data_obj, "system_status", system_status);
    json_object_object_add(data_obj, "network_status", network_status);
    json_object_object_add(data_obj, "active_app", active_app);
    json_object_object_add(data_obj, "active_host", active_host);
    json_object_object_add(data_obj, "interface_traffic", interface_traffic);
    json_object_object_add(data_obj, "oaf_status", oaf_status);
    json_object_object_add(data_obj, "advanced", advanced);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_hourly_top_apps(struct json_object *req_obj) {
	int i;
    struct json_object *data_obj = json_object_new_object();
    
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }
    
    
    client_node_t *client = find_client_node(mac);
    if (!client) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    daily_hourly_stat_t *stat = NULL;
    
    if (is_today) {
        
        update_hourly_top_apps(client);
        stat = get_today_stat(client);
        if (!stat) {
            json_object_put(data_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else {
        
        char stats_dir[512] = {0};
        char mac_dirname[64] = {0};
        char mac_buf[MAX_MAC_LEN] = {0};
        strncpy(mac_buf, client->mac, sizeof(mac_buf) - 1);
        
        
        for (i = 0; mac_buf[i] != '\0'; i++) {
            if (mac_buf[i] == ':') {
                mac_buf[i] = '_';
            }
        }
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        } 
        snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats/hourly_%s.json", 
                 get_client_data_base_dir(), mac_buf, date_str);
 
        struct json_object *file_json = json_object_from_file(stats_dir);
        if (!file_json) {
            json_object_put(data_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }

        json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        struct json_object *hourly_stats = json_object_object_get(file_json, "hourly_stats");
        if (hourly_stats) {
            
            json_object_object_add(data_obj, "hourly_stats", hourly_stats);
        } else {
            json_object_object_add(data_obj, "hourly_stats", json_object_new_array());
        }
          
        json_object_put(file_json);
        return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
    }
    
    
    struct json_object *hourly_array = json_object_new_array();
    int hour;
    for (hour = 0; hour < HOURS_PER_DAY; hour++) {
        struct json_object *hour_obj = json_object_new_object();
        struct json_object *apps_array = json_object_new_array();
        
        json_object_object_add(hour_obj, "hour", json_object_new_int(hour));  
        for (i = 0; i < TOP_APP_PER_HOUR; i++) {
            if (stat->hourly_top_apps[hour][i] > 0) {
                struct json_object *app_obj = json_object_new_object();
                int appid = stat->hourly_top_apps[hour][i];
                json_object_object_add(app_obj, "appid", json_object_new_int(appid));
                add_app_icon_missing_flag(app_obj, appid);
                const char *app_name = get_app_name_by_id(appid);
                if (app_name) {
                    json_object_object_add(app_obj, "name", json_object_new_string(app_name));
                } else {
                    json_object_object_add(app_obj, "name", json_object_new_string("unknown"));
                }
                
                
                unsigned long long app_time = 0;
                if (is_today && client) {
                    u_int32_t today_start = get_today_start_timestamp();
                    visit_info_t *p_info = NULL;
                    list_for_each_entry(p_info, &client->online_visit, visit) {
                        if (p_info->first_time < today_start || p_info->appid != appid)
                            continue;

                        app_time += get_visit_duration_in_hour(p_info, hour);
                    }
                    list_for_each_entry(p_info, &client->visit, visit) {
                        if (p_info->first_time < today_start || p_info->appid != appid)
                            continue;

                        app_time += get_visit_duration_in_hour(p_info, hour);
                    }
                    if (app_time > 3600ULL) {
                        app_time = 3600ULL;
                    }
                }
                json_object_object_add(app_obj, "time", json_object_new_int64(app_time));
                
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
    
    json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
    json_object_object_add(data_obj, "date", json_object_new_int64(stat->date));
    json_object_object_add(data_obj, "is_today", json_object_new_int(stat->is_today));
    json_object_object_add(data_obj, "hourly_stats", hourly_array);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_daily_top_apps(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    int i;
    int count;
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    const char *mac = json_object_get_string(mac_obj);
    if (!mac) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }

    client_node_t *client = find_client_node(mac);
    if (!client) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    daily_top_apps_stat_t *stat = NULL;
    
    if (is_today) {
        
        update_daily_top_apps(client);
        stat = get_today_top_apps_stat(client);
        if (!stat) {
            json_object_put(data_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        struct json_object *apps_array = json_object_new_array();
        
        for (i = 0; i < stat->count; i++) {
            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "appid", json_object_new_int(stat->apps[i].appid));
            json_object_object_add(app_obj, "total_time", json_object_new_int64(stat->apps[i].total_time));
            add_app_icon_missing_flag(app_obj, stat->apps[i].appid);
            const char *app_name = get_app_name_by_id(stat->apps[i].appid);
            if (app_name) {
                json_object_object_add(app_obj, "name", json_object_new_string(app_name));
            } else {
                json_object_object_add(app_obj, "name", json_object_new_string("unknown"));
            }
            json_object_array_add(apps_array, app_obj);
        }
        
        json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        json_object_object_add(data_obj, "date", json_object_new_int64(stat->date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(stat->is_today));
        json_object_object_add(data_obj, "count", json_object_new_int(stat->count));
        json_object_object_add(data_obj, "apps", apps_array);
    } else {
        
        char stats_dir[512] = {0};
        char mac_buf[64] = {0};
        strncpy(mac_buf, client->mac, sizeof(mac_buf) - 1);
        mac_buf[sizeof(mac_buf) - 1] = '\0';

        
        for (i = 0; mac_buf[i] != '\0'; i++) {
            if (mac_buf[i] == ':') {
                mac_buf[i] = '_';       
            }
        }
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        }
        
        snprintf(stats_dir, sizeof(stats_dir), "%s/%s/stats/top_apps_%s.json", 
                 get_client_data_base_dir(), mac_buf, date_str);
        
        
        struct json_object *file_json = json_object_from_file(stats_dir);
        if (!file_json) {
            json_object_put(data_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        struct json_object *mac_obj = json_object_object_get(file_json, "mac");
        struct json_object *date_obj = json_object_object_get(file_json, "date");
        struct json_object *count_obj = json_object_object_get(file_json, "count");
        struct json_object *apps_obj = json_object_object_get(file_json, "apps");
        
        if (mac_obj) {
            json_object_object_add(data_obj, "mac", mac_obj);
        } else {
            json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
        }
        
        if (date_obj) {
            json_object_object_add(data_obj, "date", date_obj);
        } else {
            json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        }
        
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        if (count_obj) {
            json_object_object_add(data_obj, "count", count_obj);
        } else {
            json_object_object_add(data_obj, "count", json_object_new_int(0));
        }
        
        if (apps_obj) {
            json_object_object_add(data_obj, "apps", apps_obj);
        } else {
            json_object_object_add(data_obj, "apps", json_object_new_array());
        }
        
        
        json_object_put(file_json);
    }
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_delete_record_files(struct json_object *req_obj) {
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    struct json_object *start_date_obj = json_object_object_get(req_obj, "start_date");
    struct json_object *end_date_obj = json_object_object_get(req_obj, "end_date");
    struct json_object *type_obj = json_object_object_get(req_obj, "type");
    
    const char *mac = NULL;
    const char *start_date = NULL;
    const char *end_date = NULL;
    const char *delete_type = NULL;
    
    if (mac_obj) {
        mac = json_object_get_string(mac_obj);
    }
    if (start_date_obj) {
        start_date = json_object_get_string(start_date_obj);
    }
    if (end_date_obj) {
        end_date = json_object_get_string(end_date_obj);
    }
    if (type_obj) {
        delete_type = json_object_get_string(type_obj);
    }
    
    LOG_DEBUG("Delete record files: mac=%s, start_date=%s, end_date=%s, type=%s\n",
             mac ? mac : "all", 
             start_date ? start_date : "none",
             end_date ? end_date : "none",
             delete_type ? delete_type : "all");
    
    
    delete_client_record_files(mac, start_date, end_date, delete_type);
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "message", json_object_new_string("Delete request processed"));
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct {
    int app_type;  
    unsigned long long total_time;  
} app_type_stat_sort_t;


static int compare_app_type_stat_sort(const void *a, const void *b) {
    app_type_stat_sort_t *pa = (app_type_stat_sort_t *)a;
    app_type_stat_sort_t *pb = (app_type_stat_sort_t *)b;
    if (pa->total_time > pb->total_time)
        return -1;
    if (pa->total_time < pb->total_time)
        return 1;
    return 0;
}


struct json_object *fwx_api_get_global_app_type_stats(struct json_object *req_obj) {
    struct json_object *type_obj = json_object_object_get(req_obj, "type");
    struct json_object *limit_obj = json_object_object_get(req_obj, "limit");
    int i;
    const char *stat_type = "daily";  
    int limit = 10;  
    
    if (type_obj) {
        stat_type = json_object_get_string(type_obj);
    }
    if (limit_obj) {
        limit = json_object_get_int(limit_obj);
        if (limit <= 0 || limit > MAX_APP_TYPE)
            limit = MAX_APP_TYPE;
    }
    
    unsigned long long type_time_array[MAX_APP_TYPE] = {0};
    
    
    if (stat_type && strcmp(stat_type, "hourly") == 0) {
        get_global_hourly_app_type_stats(type_time_array);
    } else {
        get_global_daily_app_type_stats(type_time_array);
    }
    
    
    app_type_stat_sort_t stats[MAX_APP_TYPE];
    int valid_count = 0;
    
    for (i = 0; i < MAX_APP_TYPE; i++) {
        if (type_time_array[i] > 0) {
            stats[valid_count].app_type = i + 1;  
            stats[valid_count].total_time = type_time_array[i];
            valid_count++;
        }
    }
    
    
    if (valid_count == 0) {
        for (i = 0; i < 5; i++) {
            stats[valid_count].app_type = i + 1;  
            stats[valid_count].total_time = 0;     
            valid_count++;
        }
    }
    
    
    if (valid_count > 0) {
        qsort(stats, valid_count, sizeof(app_type_stat_sort_t), compare_app_type_stat_sort);
    }
    
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "type", json_object_new_string(stat_type));
    json_object_object_add(data_obj, "limit", json_object_new_int(limit));
    json_object_object_add(data_obj, "total_count", json_object_new_int(valid_count));
    
    struct json_object *types_array = json_object_new_array();
    int return_count = (valid_count < limit) ? valid_count : limit;
    
    for (i = 0; i < return_count; i++) {
        struct json_object *type_obj = json_object_new_object();
        json_object_object_add(type_obj, "app_type", json_object_new_int(stats[i].app_type));
        json_object_object_add(type_obj, "total_time", json_object_new_int64(stats[i].total_time));
        
        
        int type_index = stats[i].app_type - 1;
        const char *type_name = NULL;
        if (type_index >= 0 && type_index < MAX_APP_TYPE && strlen(CLASS_NAME_TABLE[type_index]) > 0) {
            type_name = CLASS_NAME_TABLE[type_index];
        }
        if (!type_name) {
            
            static char default_name[32] = {0};
            snprintf(default_name, sizeof(default_name), "Category %d", stats[i].app_type);
            type_name = default_name;
        }
        json_object_object_add(type_obj, "name", json_object_new_string(type_name));
        
        json_object_array_add(types_array, type_obj);
    }
    
    json_object_object_add(data_obj, "types", types_array);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_global_traffic_stats(struct json_object *req_obj) {
    struct json_object *date_obj = json_object_object_get(req_obj, "date");
    int hour;
    u_int32_t target_date = 0;
    int is_today = 1;
    u_int32_t today = get_today_start_timestamp();
    
    if (date_obj) {
        target_date = (u_int32_t)json_object_get_int64(date_obj);
        is_today = (target_date == today);
    } else {
        target_date = today;
    }
    
    struct json_object *data_obj = json_object_new_object();
    
    if (is_today) {
        
        traffic_stat_t traffic_array[HOURS_PER_DAY];
        get_global_traffic_stats(traffic_array);
        
        json_object_object_add(data_obj, "date", json_object_new_int64(today));
        json_object_object_add(data_obj, "is_today", json_object_new_int(1));
        
        struct json_object *hourly_array = json_object_new_array();
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            struct json_object *hour_obj = json_object_new_object();
            json_object_object_add(hour_obj, "hour", json_object_new_int(hour));
            
            struct json_object *traffic_obj = json_object_new_object();
            json_object_object_add(traffic_obj, "up_bytes", json_object_new_int64(traffic_array[hour].up_bytes));
            json_object_object_add(traffic_obj, "down_bytes", json_object_new_int64(traffic_array[hour].down_bytes));
            json_object_object_add(hour_obj, "traffic", traffic_obj);
            
            json_object_array_add(hourly_array, hour_obj);
        }
        
        json_object_object_add(data_obj, "hourly_traffic", hourly_array);
    } else {
        
        char date_str[32] = {0};
        time_t t = (time_t)target_date;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(date_str, sizeof(date_str), "%Y-%m-%d", tm_info);
        }
        
        char file_path[512] = {0};
        snprintf(file_path, sizeof(file_path), "%s/global/stats/traffic_%s.json", get_history_data_root_dir(), date_str);
        
        
        struct json_object *file_json = json_object_from_file(file_path);
        if (!file_json) {
            json_object_put(data_obj);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        
        json_object_object_add(data_obj, "date", json_object_new_int64(target_date));
        json_object_object_add(data_obj, "is_today", json_object_new_int(0));
        
        struct json_object *hourly_traffic = json_object_object_get(file_json, "hourly_traffic");
        if (hourly_traffic) {
            json_object_object_add(data_obj, "hourly_traffic", hourly_traffic);
        } else {
            json_object_object_add(data_obj, "hourly_traffic", json_object_new_array());
        }
        
        json_object_put(file_json);
    }
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

static void get_dashboard_date_string(u_int32_t timestamp, char *date_str, size_t len)
{
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);

    if (!date_str || len == 0) {
        return;
    }

    date_str[0] = '\0';
    if (tm_info) {
        strftime(date_str, len, "%Y-%m-%d", tm_info);
    }
}

static void sum_hourly_traffic_array(struct json_object *hourly_traffic,
                                     unsigned long long *up_bytes,
                                     unsigned long long *down_bytes)
{
    int i;
    int len;

    if (!up_bytes || !down_bytes) {
        return;
    }

    if (!hourly_traffic || !json_object_is_type(hourly_traffic, json_type_array)) {
        return;
    }

    len = json_object_array_length(hourly_traffic);
    for (i = 0; i < len; i++) {
        struct json_object *hour_obj = json_object_array_get_idx(hourly_traffic, i);
        struct json_object *traffic_obj = NULL;
        struct json_object *up_obj = NULL;
        struct json_object *down_obj = NULL;

        if (!hour_obj || !json_object_is_type(hour_obj, json_type_object)) {
            continue;
        }
        if (!json_object_object_get_ex(hour_obj, "traffic", &traffic_obj) || !traffic_obj) {
            continue;
        }
        if (json_object_object_get_ex(traffic_obj, "up_bytes", &up_obj) && up_obj) {
            *up_bytes += (unsigned long long)json_object_get_int64(up_obj);
        }
        if (json_object_object_get_ex(traffic_obj, "down_bytes", &down_obj) && down_obj) {
            *down_bytes += (unsigned long long)json_object_get_int64(down_obj);
        }
    }
}

struct json_object *fwx_api_get_history_traffic_stats(struct json_object *req_obj)
{
    struct json_object *days_obj = NULL;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_array = json_object_new_array();
    unsigned long long total_up = 0;
    unsigned long long total_down = 0;
    u_int32_t today = get_today_start_timestamp();
    int days = 30;
    int i;

    if (req_obj && json_object_object_get_ex(req_obj, "days", &days_obj) && days_obj) {
        days = json_object_get_int(days_obj);
    }
    if (days <= 0) {
        days = 1;
    }
    if (days > 365) {
        days = 365;
    }

    for (i = days - 1; i >= 0; i--) {
        u_int32_t date = today - (u_int32_t)(i * SECONDS_PER_DAY);
        unsigned long long day_up = 0;
        unsigned long long day_down = 0;
        char date_str[32] = {0};
        struct json_object *day_obj = json_object_new_object();

        get_dashboard_date_string(date, date_str, sizeof(date_str));

        if (date == today) {
            int hour;
            traffic_stat_t traffic_array[HOURS_PER_DAY];

            get_global_traffic_stats(traffic_array);
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                day_up += traffic_array[hour].up_bytes;
                day_down += traffic_array[hour].down_bytes;
            }
            json_object_object_add(day_obj, "is_today", json_object_new_int(1));
        } else if (date_str[0]) {
            char file_path[512] = {0};
            struct json_object *file_json = NULL;
            struct json_object *hourly_traffic = NULL;

            snprintf(file_path, sizeof(file_path), "%s/global/stats/traffic_%s.json",
                     get_history_data_root_dir(), date_str);
            file_json = json_object_from_file(file_path);
            if (file_json) {
                if (json_object_object_get_ex(file_json, "hourly_traffic", &hourly_traffic)) {
                    sum_hourly_traffic_array(hourly_traffic, &day_up, &day_down);
                }
                json_object_put(file_json);
            }
            json_object_object_add(day_obj, "is_today", json_object_new_int(0));
        } else {
            json_object_object_add(day_obj, "is_today", json_object_new_int(0));
        }

        total_up += day_up;
        total_down += day_down;

        json_object_object_add(day_obj, "date", json_object_new_int64(date));
        json_object_object_add(day_obj, "date_str", json_object_new_string(date_str));
        json_object_object_add(day_obj, "up_bytes", json_object_new_int64(day_up));
        json_object_object_add(day_obj, "down_bytes", json_object_new_int64(day_down));
        json_object_object_add(day_obj, "total_bytes", json_object_new_int64(day_up + day_down));
        json_object_array_add(list_array, day_obj);
    }

    json_object_object_add(data_obj, "days", json_object_new_int(days));
    json_object_object_add(data_obj, "start_date", json_object_new_int64(today - (u_int32_t)((days - 1) * SECONDS_PER_DAY)));
    json_object_object_add(data_obj, "end_date", json_object_new_int64(today));
    json_object_object_add(data_obj, "total_up_bytes", json_object_new_int64(total_up));
    json_object_object_add(data_obj, "total_down_bytes", json_object_new_int64(total_down));
    json_object_object_add(data_obj, "total_bytes", json_object_new_int64(total_up + total_down));
    json_object_object_add(data_obj, "list", list_array);

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct user_traffic_sort {
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    unsigned long long up_bytes;
    unsigned long long down_bytes;
    unsigned long long total_bytes;  
} user_traffic_sort_t;


static int compare_user_traffic(const void *a, const void *b) {
    const user_traffic_sort_t *ua = (const user_traffic_sort_t *)a;
    const user_traffic_sort_t *ub = (const user_traffic_sort_t *)b;
    
    if (ua->total_bytes > ub->total_bytes) {
        return -1;
    } else if (ua->total_bytes < ub->total_bytes) {
        return 1;
    }
    return 0;
}


struct json_object *fwx_api_get_daily_top_users(struct json_object *req_obj) {
	int i;
	int hour;
    LOG_DEBUG("fwx_api_get_daily_top_users: called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        LOG_ERROR("fwx_api_get_daily_top_users: failed to create data_obj\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    u_int32_t today = get_today_start_timestamp();
    LOG_DEBUG("fwx_api_get_daily_top_users: today timestamp = %u\n", today);
    
    
    user_traffic_sort_t user_traffic_list[1024];  
    int user_count = 0;
    
    LOG_DEBUG("fwx_api_get_daily_top_users: start iterating client_list\n");
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (user_count >= 1024) {
            LOG_ERROR("fwx_api_get_daily_top_users: user_count reached max limit 1024\n");
            break;  
        }
        
        
        daily_hourly_stat_t *today_stat = get_today_stat(node);
        if (!today_stat) {
            LOG_DEBUG("fwx_api_get_daily_top_users: client %s has no today_stat, skip\n", node->mac);
            continue;
        }
        
        
        unsigned long long up_bytes = 0;
        unsigned long long down_bytes = 0;
        
        for (hour = 0; hour < HOURS_PER_DAY; hour++) {
            up_bytes += today_stat->hourly_traffic[hour].up_bytes;
            down_bytes += today_stat->hourly_traffic[hour].down_bytes;
        }
        
        LOG_DEBUG("fwx_api_get_daily_top_users: client %s, up_bytes=%llu, down_bytes=%llu\n", 
                 node->mac, up_bytes, down_bytes);
        
        
        if (up_bytes > 0 || down_bytes > 0) {
            user_traffic_sort_t *user = &user_traffic_list[user_count];
            
            strncpy(user->mac, node->mac, sizeof(user->mac) - 1);
            user->mac[sizeof(user->mac) - 1] = '\0';
            
            strncpy(user->ip, node->ip, sizeof(user->ip) - 1);
            user->ip[sizeof(user->ip) - 1] = '\0';
            
            strncpy(user->hostname, node->hostname, sizeof(user->hostname) - 1);
            user->hostname[sizeof(user->hostname) - 1] = '\0';
            
            strncpy(user->nickname, node->nickname, sizeof(user->nickname) - 1);
            user->nickname[sizeof(user->nickname) - 1] = '\0';
            
            user->up_bytes = up_bytes;
            user->down_bytes = down_bytes;
            user->total_bytes = up_bytes + down_bytes;
            
            LOG_DEBUG("fwx_api_get_daily_top_users: added user %s (mac=%s, total_bytes=%llu)\n", 
                     user->nickname[0] ? user->nickname : (user->hostname[0] ? user->hostname : user->mac),
                     user->mac, user->total_bytes);
            
            user_count++;
        }
    }
    
    LOG_DEBUG("fwx_api_get_daily_top_users: total user_count = %d\n", user_count);
    
    
    if (user_count > 0) {
        LOG_DEBUG("fwx_api_get_daily_top_users: sorting %d users\n", user_count);
        qsort(user_traffic_list, user_count, sizeof(user_traffic_sort_t), compare_user_traffic);
    }
    
    
    int return_count = (user_count < 8) ? user_count : 8;
    LOG_DEBUG("fwx_api_get_daily_top_users: return_count = %d\n", return_count);
    
    
    json_object_object_add(data_obj, "date", json_object_new_int64(today));
    json_object_object_add(data_obj, "total_count", json_object_new_int(user_count));
    
    struct json_object *users_array = json_object_new_array();
    if (!users_array) {
        LOG_ERROR("fwx_api_get_daily_top_users: failed to create users_array\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    for (i = 0; i < return_count; i++) {
        struct json_object *user_obj = json_object_new_object();
        if (!user_obj) {
            LOG_ERROR("fwx_api_get_daily_top_users: failed to create user_obj[%d]\n", i);
            continue;
        }
        
        json_object_object_add(user_obj, "mac", json_object_new_string(user_traffic_list[i].mac));
        json_object_object_add(user_obj, "ip", json_object_new_string(user_traffic_list[i].ip));
        json_object_object_add(user_obj, "hostname", json_object_new_string(user_traffic_list[i].hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(user_traffic_list[i].nickname));
        json_object_object_add(user_obj, "up_bytes", json_object_new_int64(user_traffic_list[i].up_bytes));
        json_object_object_add(user_obj, "down_bytes", json_object_new_int64(user_traffic_list[i].down_bytes));
        json_object_object_add(user_obj, "total_bytes", json_object_new_int64(user_traffic_list[i].total_bytes));
        
        json_object_array_add(users_array, user_obj);
        
        LOG_DEBUG("fwx_api_get_daily_top_users: added user[%d]: mac=%s, total_bytes=%llu\n", 
                 i, user_traffic_list[i].mac, user_traffic_list[i].total_bytes);
    }
    
    json_object_object_add(data_obj, "users", users_array);
    
    LOG_DEBUG("fwx_api_get_daily_top_users: success, returning %d users\n", return_count);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


typedef struct active_user_sort {
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    unsigned int up_rate;  
    unsigned int down_rate;  
    int rssi;
    unsigned int rx_rate;
    unsigned int tx_rate;
    char band[16];
    char wifi_ifname[64];
    int is_wireless;
    unsigned long long today_up_bytes;  
    unsigned long long today_down_bytes;  
    int visiting_app;  
    char visiting_url[MAX_REPORT_URL_LEN];  
    unsigned int total_rate;  
    int active;  
    u_int32_t online_duration;  
    u_int32_t last_update_time;  
} active_user_sort_t;


static int compare_active_users(const void *a, const void *b) {
    const active_user_sort_t *user_a = (const active_user_sort_t *)a;
    const active_user_sort_t *user_b = (const active_user_sort_t *)b;
    
    
    if (user_b->total_rate > user_a->total_rate)
        return 1;
    else if (user_b->total_rate < user_a->total_rate)
        return -1;
    
    
    if (user_b->active > user_a->active)
        return 1;
    else if (user_b->active < user_a->active)
        return -1;
    
    
    int user_a_visiting = (user_a->visiting_app > 0 || (user_a->visiting_url && strlen(user_a->visiting_url) > 0)) ? 1 : 0;
    int user_b_visiting = (user_b->visiting_app > 0 || (user_b->visiting_url && strlen(user_b->visiting_url) > 0)) ? 1 : 0;
    if (user_b_visiting > user_a_visiting)
        return 1;
    else if (user_b_visiting < user_a_visiting)
        return -1;
    
    
    if (user_b->online_duration > user_a->online_duration)
        return 1;
    else if (user_b->online_duration < user_a->online_duration)
        return -1;
    
    
    if (user_b->last_update_time > user_a->last_update_time)
        return 1;
    else if (user_b->last_update_time < user_a->last_update_time)
        return -1;
    
    return 0;
}


struct json_object *fwx_api_get_active_users(struct json_object *req_obj) {
	int i;
	int hour;
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        LOG_ERROR("fwx_api_get_active_users: failed to create data_obj\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    int count = 10;
    if (req_obj) {
        struct json_object *count_obj = json_object_object_get(req_obj, "count");
        if (count_obj) {
            count = json_object_get_int(count_obj);
            if (count <= 0 || count > 100) {
                count = 10;  
            }
        }
    }
    
    LOG_DEBUG("fwx_api_get_active_users: start, count=%d\n", count);
    
    
    update_client_nickname();
    update_client_visiting_info();
    
    active_user_sort_t active_user_list[1024];  
    int user_count = 0;
    
    client_node_t *node = NULL;
    list_for_each_entry(node, &client_list, client) {
        if (user_count >= 1024) {
            LOG_ERROR("fwx_api_get_active_users: user_count reached max limit 1024\n");
            break;
        }
        
        
        if (!node->online) {
            continue;
        }
        LOG_DEBUG("mac = %s, online = %d\n", node->mac, node->online);
        
        
        unsigned int total_rate = node->up_rate + node->down_rate;

        active_user_sort_t *user = &active_user_list[user_count];
        
        strncpy(user->mac, node->mac, sizeof(user->mac) - 1);
        user->mac[sizeof(user->mac) - 1] = '\0';
        
        strncpy(user->ip, node->ip, sizeof(user->ip) - 1);
        user->ip[sizeof(user->ip) - 1] = '\0';
        
        strncpy(user->hostname, node->hostname, sizeof(user->hostname) - 1);
        user->hostname[sizeof(user->hostname) - 1] = '\0';
        
        strncpy(user->nickname, node->nickname, sizeof(user->nickname) - 1);
        user->nickname[sizeof(user->nickname) - 1] = '\0';
        
        user->up_rate = node->up_rate;
        user->down_rate = node->down_rate;
        user->rssi = node->rssi;
        user->rx_rate = node->rx_rate;
        user->tx_rate = node->tx_rate;
        snprintf(user->band, sizeof(user->band), "%s", node->band);
        snprintf(user->wifi_ifname, sizeof(user->wifi_ifname), "%s", node->wifi_ifname);
        user->is_wireless = node->is_wireless;
        user->total_rate = total_rate;
        user->active = node->active;  
        user->visiting_app = node->visiting_app;
        
        strncpy(user->visiting_url, node->visiting_url, sizeof(user->visiting_url) - 1);
        user->visiting_url[sizeof(user->visiting_url) - 1] = '\0';
        
        
        u_int32_t current_time = get_timestamp();
        if (node->online_time > 0) {
            user->online_duration = current_time - node->online_time;  
            user->last_update_time = node->online_time;  
        } else {
            user->online_duration = 0;
            user->last_update_time = 0;
        }
        
        
        daily_hourly_stat_t *today_stat = get_today_stat(node);
        unsigned long long today_up_bytes = 0;
        unsigned long long today_down_bytes = 0;
        
        if (today_stat) {
            for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
            }
        }
        
        user->today_up_bytes = today_up_bytes;
        user->today_down_bytes = today_down_bytes;
        
        user_count++;
        
        LOG_DEBUG("fwx_api_get_active_users: added user: mac=%s, total_rate=%u\n", 
                    user->mac, user->total_rate);
        
    }
    
    
    if (user_count > 0) {
        LOG_DEBUG("fwx_api_get_active_users: sorting %d users\n", user_count);
        qsort(active_user_list, user_count, sizeof(active_user_sort_t), compare_active_users);
    }
    
    
    int return_count = (user_count < count) ? user_count : count;
    LOG_DEBUG("fwx_api_get_active_users: return_count = %d\n", return_count);
    
    
    json_object_object_add(data_obj, "total_count", json_object_new_int(user_count));
    
    struct json_object *users_array = json_object_new_array();
    if (!users_array) {
        LOG_ERROR("fwx_api_get_active_users: failed to create users_array\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    for (i = 0; i < return_count; i++) {
        struct json_object *user_obj = json_object_new_object();
        if (!user_obj) {
            LOG_ERROR("fwx_api_get_active_users: failed to create user_obj[%d]\n", i);
            continue;
        }
        
        json_object_object_add(user_obj, "mac", json_object_new_string(active_user_list[i].mac));
        json_object_object_add(user_obj, "ip", json_object_new_string(active_user_list[i].ip));
        json_object_object_add(user_obj, "hostname", json_object_new_string(active_user_list[i].hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(active_user_list[i].nickname));
        json_object_object_add(user_obj, "up_rate", json_object_new_int(active_user_list[i].up_rate));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(active_user_list[i].down_rate));
        json_object_object_add(user_obj, "rssi", json_object_new_int(active_user_list[i].rssi));
        json_object_object_add(user_obj, "rx_rate", json_object_new_int(active_user_list[i].rx_rate));
        json_object_object_add(user_obj, "tx_rate", json_object_new_int(active_user_list[i].tx_rate));
        json_object_object_add(user_obj, "band", json_object_new_string(active_user_list[i].band));
        json_object_object_add(user_obj, "wifi_ifname", json_object_new_string(active_user_list[i].wifi_ifname));
        json_object_object_add(user_obj, "is_wireless", json_object_new_int(active_user_list[i].is_wireless));
        json_object_object_add(user_obj, "terminal_type", json_object_new_string(active_user_list[i].is_wireless ? "wireless" : "wired"));
        json_object_object_add(user_obj, "today_up_bytes", json_object_new_int64(active_user_list[i].today_up_bytes));
        json_object_object_add(user_obj, "today_down_bytes", json_object_new_int64(active_user_list[i].today_down_bytes));
        
        
        if (active_user_list[i].visiting_app > 0) {
            json_object_object_add(user_obj, "app", json_object_new_string(get_app_name_by_id(active_user_list[i].visiting_app)));
        } else {
            json_object_object_add(user_obj, "app", json_object_new_string(""));
        }
        
        if (strlen(active_user_list[i].visiting_url) > 0) {
            json_object_object_add(user_obj, "url", json_object_new_string(active_user_list[i].visiting_url));
        } else {
            json_object_object_add(user_obj, "url", json_object_new_string(""));
        }
        
        json_object_array_add(users_array, user_obj);
        
        LOG_DEBUG("fwx_api_get_active_users: added user[%d]: mac=%s, total_rate=%u\n", 
                 i, active_user_list[i].mac, active_user_list[i].total_rate);
    }
    
    json_object_object_add(data_obj, "users", users_array);
    LOG_DEBUG("data_obj: %s\n", json_object_to_json_string(data_obj));
    
    LOG_DEBUG("fwx_api_get_active_users: success, returning %d users\n", return_count);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_user_basic_info(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    int hour;
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *target_mac = json_object_get_string(mac_obj);
    if (!target_mac) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    update_client_nickname();
    update_client_visiting_info();
    
    extern struct list_head client_list;
    client_node_t *client = NULL;
    u_int32_t cur_time = get_timestamp();
    u_int32_t today_start = get_today_start_timestamp();
    

    list_for_each_entry(client, &client_list, client) {
        if (strcmp(client->mac, target_mac) == 0) {

            json_object_object_add(data_obj, "mac", json_object_new_string(client->mac));
            json_object_object_add(data_obj, "ip", json_object_new_string(client->ip));
            json_object_object_add(data_obj, "ipv6", json_object_new_string(client->ipv6));
            json_object_object_add(data_obj, "nickname", json_object_new_string(client->nickname));
            json_object_object_add(data_obj, "hostname", json_object_new_string(client->hostname));
            json_object_object_add(data_obj, "online", json_object_new_int(client->online));
            json_object_object_add(data_obj, "active", json_object_new_int(client->active));
            json_object_object_add(data_obj, "af_whitelist", json_object_new_int(is_appfilter_whitelist_mac(client->mac) ? 1 : 0));
            json_object_object_add(data_obj, "mf_whitelist", json_object_new_int(is_macfilter_whitelist_mac(client->mac) ? 1 : 0));
            json_object_object_add(data_obj, "up_rate", json_object_new_int(client->up_rate));
            json_object_object_add(data_obj, "down_rate", json_object_new_int(client->down_rate));
            json_object_object_add(data_obj, "rssi", json_object_new_int(client->rssi));
            json_object_object_add(data_obj, "rx_rate", json_object_new_int(client->rx_rate));
            json_object_object_add(data_obj, "tx_rate", json_object_new_int(client->tx_rate));
            json_object_object_add(data_obj, "band", json_object_new_string(client->band));
            json_object_object_add(data_obj, "wifi_ifname", json_object_new_string(client->wifi_ifname));
            json_object_object_add(data_obj, "is_wireless", json_object_new_int(client->is_wireless));
            json_object_object_add(data_obj, "terminal_type", json_object_new_string(client->is_wireless ? "wireless" : "wired"));
            

            daily_hourly_stat_t *today_stat = get_today_stat(client);
            unsigned long long today_up_bytes = 0;
            unsigned long long today_down_bytes = 0;
            unsigned long long today_online_time = 0;
            unsigned long long today_active_time = 0;
            
            if (today_stat) {
                for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                    today_up_bytes += today_stat->hourly_traffic[hour].up_bytes;
                    today_down_bytes += today_stat->hourly_traffic[hour].down_bytes;
                    today_online_time += today_stat->hourly_online_time[hour];
                    today_active_time += today_stat->hourly_active_time[hour];
                }
            }
            
            json_object_object_add(data_obj, "today_up_bytes", json_object_new_int64(today_up_bytes));
            json_object_object_add(data_obj, "today_down_bytes", json_object_new_int64(today_down_bytes));
            json_object_object_add(data_obj, "today_online_time", json_object_new_int64(today_online_time));
            json_object_object_add(data_obj, "today_active_time", json_object_new_int64(today_active_time));
            

            return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
        }
    }
    

    json_object_put(data_obj);
    return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
}


struct json_object *fwx_api_get_online_offline_records(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *mac_obj = NULL;
    if (!json_object_object_get_ex(req_obj, "mac", &mac_obj) || !mac_obj) {
        LOG_ERROR("fwx_api_get_online_offline_records: missing mac parameter\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *mac = json_object_get_string(mac_obj);
    if (!mac || strlen(mac) == 0) {
        LOG_ERROR("fwx_api_get_online_offline_records: invalid mac parameter\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    extern struct list_head client_list;
    client_node_t *client = find_client_node(mac);
    if (!client) {
        LOG_ERROR("fwx_api_get_online_offline_records: client not found for mac=%s\n", mac);
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct json_object *records_array = json_object_new_array();
    if (!records_array) {
        LOG_ERROR("fwx_api_get_online_offline_records: failed to create records_array\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    online_offline_record_t *record = NULL;
    int record_count = 0;
    list_for_each_entry(record, &client->online_offline_records, record) {
        struct json_object *record_obj = json_object_new_object();
        if (!record_obj) {
            LOG_ERROR("fwx_api_get_online_offline_records: failed to create record_obj\n");
            continue;
        }
        
        json_object_object_add(record_obj, "type", json_object_new_int(record->type));
        json_object_object_add(record_obj, "timestamp", json_object_new_int64(record->timestamp));
        json_object_object_add(record_obj, "duration", json_object_new_int64(record->duration));
        
        
        char time_str[64] = {0};
        time_t t = (time_t)record->timestamp;
        struct tm *tm_info = localtime(&t);
        if (tm_info) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        }
        json_object_object_add(record_obj, "time_str", json_object_new_string(time_str));
        
        
        char duration_str[64] = {0};
        unsigned long long hours = record->duration / 3600;
        unsigned long long minutes = (record->duration % 3600) / 60;
        unsigned long long seconds = record->duration % 60;
        if (hours > 0) {
            snprintf(duration_str, sizeof(duration_str), "%lluh%llum%llus", hours, minutes, seconds);
        } else if (minutes > 0) {
            snprintf(duration_str, sizeof(duration_str), "%llum%llus", minutes, seconds);
        } else {
            snprintf(duration_str, sizeof(duration_str), "%llus", seconds);
        }
        json_object_object_add(record_obj, "duration_str", json_object_new_string(duration_str));
        
        json_object_array_add(records_array, record_obj);
        record_count++;
    }
    
    json_object_object_add(data_obj, "mac", json_object_new_string(mac));
    json_object_object_add(data_obj, "records", records_array);
    json_object_object_add(data_obj, "count", json_object_new_int(record_count));
    
    LOG_DEBUG("fwx_api_get_online_offline_records: success, returning %d records for mac=%s\n", record_count, mac);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_user_records(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    struct json_object *mac_obj = NULL;
    struct json_object *start_obj = NULL;
    struct json_object *end_obj = NULL;
    struct json_object *page_obj = NULL;
    struct json_object *page_size_obj = NULL;
    const char *mac_filter = NULL;
    u_int32_t start_time = 0;
    u_int32_t end_time = 0;
    int page = 1;
    int page_size = 15;
    int total_num = 0;
    int total_page = 1;
    int start_idx = 0;
    int end_idx = 0;
    int idx = 0;
    user_record_t *record = NULL;

    if (req_obj) {
        if (json_object_object_get_ex(req_obj, "mac", &mac_obj) && mac_obj) {
            mac_filter = json_object_get_string(mac_obj);
        }
        if (json_object_object_get_ex(req_obj, "start_time", &start_obj) && start_obj) {
            start_time = (u_int32_t)json_object_get_int64(start_obj);
        }
        if (json_object_object_get_ex(req_obj, "end_time", &end_obj) && end_obj) {
            end_time = (u_int32_t)json_object_get_int64(end_obj);
        }
        if (json_object_object_get_ex(req_obj, "page", &page_obj) && page_obj) {
            page = json_object_get_int(page_obj);
            if (page < 1) page = 1;
        }
        if (json_object_object_get_ex(req_obj, "page_size", &page_size_obj) && page_size_obj) {
            page_size = json_object_get_int(page_size_obj);
            if (page_size < 1) page_size = 15;
            if (page_size > 200) page_size = 200;
        }
    }

    list_for_each_entry(record, &user_record_list, list) {
        if (mac_filter && strlen(mac_filter) > 0) {
            if (!strstr(record->mac, mac_filter)) {
                continue;
            }
        }
        if (start_time > 0 && record->timestamp < start_time) {
            continue;
        }
        if (end_time > 0 && record->timestamp > end_time) {
            continue;
        }
        total_num++;
    }

    total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) total_page = 1;
    if (page > total_page) page = total_page;
    start_idx = (page - 1) * page_size;
    end_idx = start_idx + page_size;

    idx = 0;
    list_for_each_entry(record, &user_record_list, list) {
        int i = 0;
        char time_str[64] = {0};
        struct json_object *item = NULL;
        struct json_object *apps_obj = NULL;
        time_t t;
        struct tm *tm_info = NULL;

        if (mac_filter && strlen(mac_filter) > 0) {
            if (!strstr(record->mac, mac_filter)) {
                continue;
            }
        }
        if (start_time > 0 && record->timestamp < start_time) {
            continue;
        }
        if (end_time > 0 && record->timestamp > end_time) {
            continue;
        }
        if (idx < start_idx) {
            idx++;
            continue;
        }
        if (idx >= end_idx) {
            break;
        }

        item = json_object_new_object();
        t = (time_t)record->timestamp;
        tm_info = localtime(&t);
        if (tm_info) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        }
        json_object_object_add(item, "timestamp", json_object_new_int64(record->timestamp));
        json_object_object_add(item, "time_str", json_object_new_string(time_str));
        json_object_object_add(item, "action", json_object_new_int(record->action));
        json_object_object_add(item, "action_str", json_object_new_string(record->action == 0 ? "online" : "offline"));
        json_object_object_add(item, "mac", json_object_new_string(record->mac));
        json_object_object_add(item, "nickname", json_object_new_string(record->nickname));
        json_object_object_add(item, "hostname", json_object_new_string(record->hostname));
        json_object_object_add(item, "up_bytes", json_object_new_int64(record->up_bytes));
        json_object_object_add(item, "down_bytes", json_object_new_int64(record->down_bytes));
        json_object_object_add(item, "online_duration", json_object_new_int64(record->online_duration));
        json_object_object_add(item, "active_duration", json_object_new_int64(record->active_duration));

        apps_obj = json_object_new_array();
        for (i = 0; i < record->recent_app_count; i++) {
            int appid = record->recent_apps[i];
            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "id", json_object_new_int(appid));
            json_object_object_add(app_obj, "name", json_object_new_string(get_app_name_by_id(appid)));
            add_app_icon_missing_flag(app_obj, appid);
            json_object_array_add(apps_obj, app_obj);
        }
        json_object_object_add(item, "recent_apps", apps_obj);
        json_object_array_add(list_obj, item);
        idx++;
    }

    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_record_base(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int enable = fwx_uci_get_int_value(ctx, "fwx.record.enable");
    int record_time = fwx_uci_get_int_value(ctx, "fwx.record.record_time");
    int app_valid_time = fwx_uci_get_int_value(ctx, "fwx.record.app_valid_time");
    
    char history_data_size[64] = {0};
    char history_data_path[256] = {0};
    char base_data_path[256] = {0};
    char terminal_data_path[256] = {0};
    fwx_uci_get_value(ctx, "fwx.record.history_data_size", history_data_size, sizeof(history_data_size));
    fwx_uci_get_value(ctx, "fwx.record.history_data_path", history_data_path, sizeof(history_data_path));
    fwx_uci_get_value(ctx, "fwx.record.base_data_path", base_data_path, sizeof(base_data_path));
    if (strlen(base_data_path) == 0) {
        fwx_uci_get_value(ctx, "fwx.record.terminal_data_path", terminal_data_path, sizeof(terminal_data_path));
        if (strlen(terminal_data_path) > 0) {
            strncpy(base_data_path, terminal_data_path, sizeof(base_data_path) - 1);
        } else if (strlen(history_data_path) > 0) {
            strncpy(base_data_path, history_data_path, sizeof(base_data_path) - 1);
        }
    }

    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "record_time", json_object_new_int(record_time));
    json_object_object_add(data_obj, "app_valid_time", json_object_new_int(app_valid_time));
    json_object_object_add(data_obj, "history_data_size", json_object_new_string(history_data_size));
    json_object_object_add(data_obj, "history_data_path", json_object_new_string(history_data_path));
    json_object_object_add(data_obj, "base_data_path", json_object_new_string(base_data_path));

    struct json_object *status_obj = json_object_new_object();
    char terminal_root_dir[512] = {0};
    char history_root_dir[512] = {0};
    char data_dir[512] = {0};
    char backup_dir[512] = {0};
    char global_dir[512] = {0};
    char visit_db_path[512] = {0};
    char cmd[1024] = {0};
    char result[256] = {0};
    unsigned long long data_size_kb = 0;
    unsigned long long client_data_kb = 0;
    unsigned long long client_backup_kb = 0;
    unsigned long long global_kb = 0;
    unsigned long long visit_db_kb = 0;
    unsigned long long history_root_kb = 0;

    strncpy(terminal_root_dir, get_client_data_root_dir(), sizeof(terminal_root_dir) - 1);
    strncpy(history_root_dir, get_history_data_root_dir(), sizeof(history_root_dir) - 1);
    snprintf(data_dir, sizeof(data_dir), "%s/client_data", terminal_root_dir);
    snprintf(backup_dir, sizeof(backup_dir), "%s/client_backup", terminal_root_dir);
    snprintf(global_dir, sizeof(global_dir), "%s/global", history_root_dir);
    snprintf(visit_db_path, sizeof(visit_db_path), "%s/client.db", history_root_dir);

    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", history_root_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        history_root_kb = strtoull(result, NULL, 10);
    }
    data_size_kb = history_root_kb;

    memset(result, 0, sizeof(result));
    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", data_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        client_data_kb = strtoull(result, NULL, 10);
    }

    memset(result, 0, sizeof(result));
    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", backup_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        client_backup_kb = strtoull(result, NULL, 10);
    }

    memset(result, 0, sizeof(result));
    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", global_dir);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        global_kb = strtoull(result, NULL, 10);
    }

    memset(result, 0, sizeof(result));
    snprintf(cmd, sizeof(cmd), "du -sk %s 2>/dev/null | awk '{print $1}'", visit_db_path);
    if (exec_with_result_line(cmd, result, sizeof(result)) == 0 && strlen(result) > 0) {
        visit_db_kb = strtoull(result, NULL, 10);
    }

    json_object_object_add(status_obj, "data_size", json_object_new_int64(data_size_kb));
    json_object_object_add(status_obj, "data_size_unit", json_object_new_string("KB"));
    json_object_object_add(status_obj, "client_data_size", json_object_new_int64(client_data_kb));
    json_object_object_add(status_obj, "client_backup_size", json_object_new_int64(client_backup_kb));
    json_object_object_add(status_obj, "global_size", json_object_new_int64(global_kb));
    json_object_object_add(status_obj, "visit_db_size", json_object_new_int64(visit_db_kb));
    json_object_object_add(data_obj, "status", status_obj);

    uci_free_context(ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_set_record_base(struct json_object *req_obj) {
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int enable = 0, record_time = 0, app_valid_time = 0;
    const char *history_data_size = NULL;
    const char *history_data_path = NULL;
    const char *base_data_path = NULL;
    const char *terminal_data_path = NULL;
    struct json_object *v;
    if (req_obj && json_object_object_get_ex(req_obj, "enable", &v) && v)
        enable = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "record_time", &v) && v)
        record_time = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "app_valid_time", &v) && v)
        app_valid_time = json_object_get_int(v);
    if (req_obj && json_object_object_get_ex(req_obj, "history_data_size", &v) && v)
        history_data_size = json_object_get_string(v);
    if (req_obj && json_object_object_get_ex(req_obj, "history_data_path", &v) && v)
        history_data_path = json_object_get_string(v);
    if (req_obj && json_object_object_get_ex(req_obj, "base_data_path", &v) && v)
        base_data_path = json_object_get_string(v);
    if (req_obj && json_object_object_get_ex(req_obj, "terminal_data_path", &v) && v)
        terminal_data_path = json_object_get_string(v);
    if ((!base_data_path || strlen(base_data_path) == 0) && terminal_data_path && strlen(terminal_data_path) > 0) {
        base_data_path = terminal_data_path;
    }

    if (enable < 0) enable = 0;
    if (record_time < 0) record_time = 0;
    if (app_valid_time < 0) app_valid_time = 0;

    if (history_data_size && strlen(history_data_size) > 0) {
        char *endptr = NULL;
        long size_val = strtol(history_data_size, &endptr, 10);
        if (*endptr != '\0' || size_val < 1 || size_val > 1024) {
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }

    if (!history_data_path || strlen(history_data_path) == 0) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (!base_data_path || strlen(base_data_path) == 0) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strcmp(history_data_path, "/") == 0) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strcmp(base_data_path, "/") == 0) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strlen(history_data_path) > 64) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (strlen(base_data_path) > 64) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int num = fwx_uci_get_list_num(ctx, "fwx", "record");
    if (num <= 0) {
        fwx_uci_add_section(ctx, "fwx", "record");
    }

    char buf[16];
    snprintf(buf, sizeof(buf), "%d", enable);
    fwx_uci_set_value(ctx, "fwx.record.enable", buf);
    snprintf(buf, sizeof(buf), "%d", record_time);
    fwx_uci_set_value(ctx, "fwx.record.record_time", buf);
    snprintf(buf, sizeof(buf), "%d", app_valid_time);
    fwx_uci_set_value(ctx, "fwx.record.app_valid_time", buf);
    
    if (history_data_size && strlen(history_data_size) > 0) {
        fwx_uci_set_value(ctx, "fwx.record.history_data_size", (char *)history_data_size);
    } else {
        fwx_uci_delete(ctx, "fwx.record.history_data_size");
    }
    
    char old_history_path[256] = {0};
    char old_base_path[256] = {0};
    char old_terminal_path[256] = {0};
    fwx_uci_get_value(ctx, "fwx.record.history_data_path", old_history_path, sizeof(old_history_path));
    fwx_uci_get_value(ctx, "fwx.record.base_data_path", old_base_path, sizeof(old_base_path));
    if (strlen(old_base_path) == 0) {
        fwx_uci_get_value(ctx, "fwx.record.terminal_data_path", old_terminal_path, sizeof(old_terminal_path));
        if (strlen(old_terminal_path) > 0) {
            strncpy(old_base_path, old_terminal_path, sizeof(old_base_path) - 1);
        } else if (strlen(old_history_path) > 0) {
            strncpy(old_base_path, old_history_path, sizeof(old_base_path) - 1);
        }
    }
    
    fwx_uci_set_value(ctx, "fwx.record.history_data_path", (char *)history_data_path);
    fwx_uci_set_value(ctx, "fwx.record.base_data_path", (char *)base_data_path);
    fwx_uci_delete(ctx, "fwx.record.terminal_data_path");

    fwx_uci_commit(ctx, "fwx");
    
    if ((history_data_path && strlen(history_data_path) > 0) ||
        (base_data_path && strlen(base_data_path) > 0)) {
        if (strlen(old_base_path) > 0 && strcmp(old_base_path, base_data_path) != 0) {
            char old_data_dir[512] = {0};
            char new_data_dir[512] = {0};
            char old_backup_dir[512] = {0};
            char new_backup_dir[512] = {0};
            char cmd[4096] = {0};

            snprintf(old_data_dir, sizeof(old_data_dir), "%s/client_data", old_base_path);
            snprintf(new_data_dir, sizeof(new_data_dir), "%s/client_data", base_data_path);
            snprintf(old_backup_dir, sizeof(old_backup_dir), "%s/client_backup", old_base_path);
            snprintf(new_backup_dir, sizeof(new_backup_dir), "%s/client_backup", base_data_path);

            snprintf(cmd, sizeof(cmd),
                     "mkdir -p %s %s %s 2>/dev/null; "
                     "mv %s/* %s/ 2>/dev/null; "
                     "mv %s/* %s/ 2>/dev/null; true",
                     base_data_path, new_data_dir, new_backup_dir,
                     old_data_dir, new_data_dir,
                     old_backup_dir, new_backup_dir);
            system(cmd);
            LOG_WARN("move base data path: %s -> %s\n", old_base_path, base_data_path);
        }

        if (strlen(old_history_path) > 0 && strcmp(old_history_path, history_data_path) != 0) {
            char old_global_dir[512] = {0};
            char new_global_dir[512] = {0};
            char old_db_path[512] = {0};
            char new_db_path[512] = {0};
            char cmd[4096] = {0};

            snprintf(old_global_dir, sizeof(old_global_dir), "%s/global", old_history_path);
            snprintf(new_global_dir, sizeof(new_global_dir), "%s/global", history_data_path);
            snprintf(old_db_path, sizeof(old_db_path), "%s/client.db", old_history_path);
            snprintf(new_db_path, sizeof(new_db_path), "%s/client.db", history_data_path);

            snprintf(cmd, sizeof(cmd),
                     "mkdir -p %s %s 2>/dev/null; "
                     "mv %s/* %s/ 2>/dev/null; "
                     "mv %s %s 2>/dev/null; true",
                     history_data_path, new_global_dir,
                     old_global_dir, new_global_dir,
                     old_db_path, new_db_path);
            system(cmd);
            LOG_WARN("move history data path: %s -> %s\n", old_history_path, history_data_path);
        }

        reset_client_data_base_dir_cache();
    }
    
    uci_free_context(ctx);

    update_fwx_proc_u32_value("record_enable", enable);
    

    load_app_valid_time_config();

    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

static int clear_visit_db_tables(const char *db_path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = SQLITE_OK;

    if (!db_path || strlen(db_path) == 0) {
        return -1;
    }

    rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK || !db) {
        if (db) {
            sqlite3_close(db);
        }
        return -1;
    }

    sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);

    rc = sqlite3_prepare_v2(db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *table_name = (const char *)sqlite3_column_text(stmt, 0);
            if (!table_name || table_name[0] == '\0') {
                continue;
            }

            char sql[256] = {0};
            snprintf(sql, sizeof(sql), "DELETE FROM \"%s\";", table_name);
            if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
                LOG_WARN("clear_visit_db_tables delete table failed: %s\n", table_name);
            }
        }
    }

    if (stmt) {
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;
}

struct json_object *fwx_api_record_action(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *action_obj = json_object_object_get(req_obj, "action");
    if (!action_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *action = json_object_get_string(action_obj);
    if (!action) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    if (strcmp(action, "clean_all_data") == 0) {
        struct uci_context *ctx = uci_alloc_context();
        if (!ctx) {
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        char history_data_path[256] = {0};
        char base_data_path[256] = {0};
        char terminal_data_path[256] = {0};
        fwx_uci_get_value(ctx, "fwx.record.history_data_path", history_data_path, sizeof(history_data_path));
        fwx_uci_get_value(ctx, "fwx.record.base_data_path", base_data_path, sizeof(base_data_path));
        if (strlen(base_data_path) == 0) {
            fwx_uci_get_value(ctx, "fwx.record.terminal_data_path", terminal_data_path, sizeof(terminal_data_path));
            if (strlen(terminal_data_path) > 0) {
                strncpy(base_data_path, terminal_data_path, sizeof(base_data_path) - 1);
            } else if (strlen(history_data_path) > 0) {
                strncpy(base_data_path, history_data_path, sizeof(base_data_path) - 1);
            }
        }
        uci_free_context(ctx);
        
        char terminal_root_dir[512] = {0};
        char history_root_dir[512] = {0};
        char base_data_dir[512] = {0};
        char base_backup_dir[512] = {0};
        char base_global_dir[512] = {0};
        char history_data_dir[512] = {0};
        char history_backup_dir[512] = {0};
        char history_global_dir[512] = {0};
        char history_visit_db_path[512] = {0};
        char cmd[8192] = {0};
        if (strlen(base_data_path) > 0) {
            strncpy(terminal_root_dir, base_data_path, sizeof(terminal_root_dir) - 1);
        } else {
            strncpy(terminal_root_dir, get_client_data_root_dir(), sizeof(terminal_root_dir) - 1);
        }
        if (strlen(history_data_path) > 0) {
            strncpy(history_root_dir, history_data_path, sizeof(history_root_dir) - 1);
        } else {
            strncpy(history_root_dir, get_history_data_root_dir(), sizeof(history_root_dir) - 1);
        }

        snprintf(base_data_dir, sizeof(base_data_dir), "%s/client_data", terminal_root_dir);
        snprintf(base_backup_dir, sizeof(base_backup_dir), "%s/client_backup", terminal_root_dir);
        snprintf(base_global_dir, sizeof(base_global_dir), "%s/global", terminal_root_dir);

        snprintf(history_data_dir, sizeof(history_data_dir), "%s/client_data", history_root_dir);
        snprintf(history_backup_dir, sizeof(history_backup_dir), "%s/client_backup", history_root_dir);
        snprintf(history_global_dir, sizeof(history_global_dir), "%s/global", history_root_dir);
        snprintf(history_visit_db_path, sizeof(history_visit_db_path), "%s/client.db", history_root_dir);
        snprintf(cmd, sizeof(cmd),
                 "rm -rf %s %s %s %s %s %s 2>/dev/null; "
                 "mkdir -p %s %s %s %s %s %s 2>/dev/null; true",
                 base_data_dir, base_backup_dir, base_global_dir,
                 history_data_dir, history_backup_dir, history_global_dir,
                 base_data_dir, base_backup_dir, base_global_dir,
                 history_data_dir, history_backup_dir, history_global_dir);
        system(cmd);

        if (access(history_visit_db_path, F_OK) == 0) {
            clear_visit_db_tables(history_visit_db_path);
        }
        
        reset_client_data_base_dir_cache();
        
        return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
    }
    
    return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
}

struct json_object *fwx_api_add_mock_visit_records(struct json_object *req_obj) {
    int record_count = 1000;
    int mac_count = 32;
    int inserted = 0;
    unsigned long long old_size_bytes = 0;
    unsigned long long new_size_bytes = 0;
    struct json_object *count_obj = NULL;
    struct json_object *mac_count_obj = NULL;
    struct json_object *data_obj = NULL;

    if (!g_fwxd_debug_mode) {
        data_obj = json_object_new_object();
        json_object_object_add(data_obj, "msg", json_object_new_string("debug mode is disabled"));
        json_object_object_add(data_obj, "debug_mode", json_object_new_int(0));
        return fwx_gen_api_response_data(API_CODE_ERROR, data_obj);
    }

    if (req_obj) {
        count_obj = json_object_object_get(req_obj, "count");
        if (count_obj) {
            record_count = json_object_get_int(count_obj);
        }

        mac_count_obj = json_object_object_get(req_obj, "mac_count");
        if (mac_count_obj) {
            mac_count = json_object_get_int(mac_count_obj);
        }
    }

    if (record_count <= 0) {
        data_obj = json_object_new_object();
        json_object_object_add(data_obj, "msg", json_object_new_string("invalid count"));
        json_object_object_add(data_obj, "count", json_object_new_int(record_count));
        return fwx_gen_api_response_data(API_CODE_ERROR, data_obj);
    }

    inserted = add_mock_visit_records_to_db(record_count, mac_count, &old_size_bytes, &new_size_bytes);
    if (inserted < 0) {
        data_obj = json_object_new_object();
        json_object_object_add(data_obj, "msg", json_object_new_string("insert mock records failed"));
        return fwx_gen_api_response_data(API_CODE_ERROR, data_obj);
    }

    data_obj = json_object_new_object();
    json_object_object_add(data_obj, "inserted", json_object_new_int(inserted));
    json_object_object_add(data_obj, "db_size_before", json_object_new_int64((long long)old_size_bytes));
    json_object_object_add(data_obj, "db_size_after", json_object_new_int64((long long)new_size_bytes));
    json_object_object_add(data_obj, "debug_mode", json_object_new_int(1));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_device_list(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_device_list: called\n");
    
    struct json_object *data_obj = json_object_new_object();
    struct json_object *device_array = json_object_new_array();
    
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        LOG_ERROR("Failed to open /proc/net/dev\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char line[256];
    int line_num = 0;
    

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        

        if (line_num <= 2) {
            continue;
        }
        

        char *colon = strchr(line, ':');
        if (!colon) {
            continue;
        }
        
 
        int ifname_len = colon - line;
        if (ifname_len <= 0 || ifname_len >= 64) {
            continue;
        }
        
        char ifname[64] = {0};
        strncpy(ifname, line, ifname_len);
        

        char *ifname_start = ifname;
        while (*ifname_start == ' ' || *ifname_start == '\t') {
            ifname_start++;
        }
    
        if (strcmp(ifname_start, "lo") == 0) {
            continue;
        }

        if (strlen(ifname_start) == 0) {
            continue;
        }

        json_object_array_add(device_array, json_object_new_string(ifname_start));
        LOG_DEBUG("Added interface: %s\n", ifname_start);
    }
    
    fclose(fp);
    
    json_object_object_add(data_obj, "device_list", device_array);
    LOG_DEBUG("fwx_api_get_device_list: returning %d devices\n", json_object_array_length(device_array));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_dashboard_param(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_dashboard_param: called\n");
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char monitor_device[64] = {0};
    int ret = fwx_uci_get_value(uci_ctx, "fwx.dashboard.monitor_device", monitor_device, sizeof(monitor_device));
    if (ret != 0) {
        monitor_device[0] = '\0';
    }
    
    uci_free_context(uci_ctx);
    
    struct json_object *data_obj = json_object_new_object();
    json_object_object_add(data_obj, "monitor_device", json_object_new_string(monitor_device));
    
    LOG_DEBUG("fwx_api_get_dashboard_param: monitor_device=%s\n", monitor_device);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_get_init_status(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    (void)req_obj;
    json_object_object_add(data_obj, "init_status", json_object_new_int(get_dashboard_init_status()));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_set_init_status(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    int init_status = 1;

    if (req_obj) {
        struct json_object *init_status_obj = json_object_object_get(req_obj, "init_status");
        if (init_status_obj) {
            init_status = json_object_get_int(init_status_obj);
        }
    }

    if (init_status != 0 && init_status != 1) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (set_dashboard_init_status(init_status) != 0) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    json_object_object_add(data_obj, "init_status", json_object_new_int(init_status));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_set_dashboard_param(struct json_object *req_obj) {
    
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *monitor_device_obj = json_object_object_get(req_obj, "monitor_device");
    if (!monitor_device_obj) {
        LOG_ERROR("monitor_device parameter missing\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *monitor_device = json_object_get_string(monitor_device_obj);
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    if (monitor_device && strlen(monitor_device) > 0) {
        fwx_uci_set_value(uci_ctx, "fwx.dashboard.monitor_device", (char *)monitor_device);
        fwx_uci_commit(uci_ctx, "fwx");
        g_interface_name[0] = '\0';
    }
    
    uci_free_context(uci_ctx);
    
    LOG_DEBUG("fwx_api_set_dashboard_param: set monitor_device=%s\n", monitor_device ? monitor_device : "(empty)");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

typedef struct json_object * (*fwx_api_handler)(struct json_object *data_obj);

typedef enum {
    FWX_API_METHOD_GET,
    FWX_API_METHOD_POST
} fwx_api_method_t;

typedef struct fwx_api_node{
    char *api_name;
    fwx_api_handler handler;
    int forward;      
    fwx_api_method_t method;
}fwx_api_node_t;

static int fwx_validate_api_request(struct json_object *req_obj) {
    struct json_object *copyright_obj = NULL;

    if (!req_obj || !json_object_is_type(req_obj, json_type_object) ||
        !json_object_object_get_ex(req_obj, "CopyRight", &copyright_obj) ||
        !json_object_is_type(copyright_obj, json_type_string)) {
        return 0;
    }

    return strcmp(json_object_get_string(copyright_obj),
                  "www.fanchmwrt.com") == 0;
}

static void fwx_add_api_response_copyright(struct json_object *response_obj) {
    struct json_object *code_obj = NULL;

    if (!response_obj || !json_object_is_type(response_obj, json_type_object) ||
        !json_object_object_get_ex(response_obj, "code", &code_obj) ||
        json_object_get_int(code_obj) != API_CODE_SUCCESS) {
        return;
    }

    json_object_object_add(response_obj, "CopyRight",
                           json_object_new_string("www.fanchmwrt.com"));
}

static int fwx_api_need_copyright(const char *api_name) {
    return api_name && strcmp(api_name, "class_list") == 0;
}

static void fwx_forward_to_agent(struct json_object *req_obj) {
	char *cmd_buf = NULL;
	if (!req_obj)
		return;
    const char *req_str = json_object_to_json_string(req_obj);
	int buf_len = strlen(req_str) + 128;
	cmd_buf = (char *)malloc(buf_len);
	if (!cmd_buf)
		return;
    snprintf(cmd_buf, buf_len, "ubus -t 2 call fwx_agent forward '%s'", req_str);
	
  	system(cmd_buf);
	free(cmd_buf);
}

struct json_object *fwx_api_get_dashboard_common(struct json_object *req_obj);
struct json_object *fwx_api_get_history_session(struct json_object *req_obj);
struct json_object *fwx_api_get_hourly_top_apps(struct json_object *req_obj);
struct json_object *fwx_api_get_daily_top_apps(struct json_object *req_obj);
struct json_object *fwx_api_delete_record_files(struct json_object *req_obj);
struct json_object *fwx_api_get_global_app_type_stats(struct json_object *req_obj);
struct json_object *fwx_api_get_global_traffic_stats(struct json_object *req_obj);
struct json_object *fwx_api_get_history_traffic_stats(struct json_object *req_obj);
struct json_object *fwx_api_get_daily_top_users(struct json_object *req_obj);
struct json_object *fwx_api_get_active_users(struct json_object *req_obj);
struct json_object *fwx_api_get_active_app_records(struct json_object *req_obj);
struct json_object *fwx_api_get_app_history_records(struct json_object *req_obj);
struct json_object *fwx_api_get_filter_rules(struct json_object *req_obj);
struct json_object *fwx_api_add_filter_rule(struct json_object *req_obj);
struct json_object *fwx_api_update_filter_rule(struct json_object *req_obj);
struct json_object *fwx_api_delete_filter_rule(struct json_object *req_obj);
struct json_object *fwx_api_get_online_offline_records(struct json_object *req_obj);
struct json_object *fwx_api_get_user_records(struct json_object *req_obj);
struct json_object *fwx_api_get_record_base(struct json_object *req_obj);
struct json_object *fwx_api_set_record_base(struct json_object *req_obj);
struct json_object *fwx_api_record_action(struct json_object *req_obj);
struct json_object *fwx_api_set_nickname(struct json_object *req_obj);
struct json_object *fwx_api_get_nickname_list(struct json_object *req_obj);
struct json_object *fwx_api_get_mac_blacklist(struct json_object *req_obj);
struct json_object *fwx_api_add_mac_blacklist(struct json_object *req_obj);
struct json_object *fwx_api_del_mac_blacklist(struct json_object *req_obj);
struct json_object *fwx_api_dev_visit_list(struct json_object *req_obj);
struct json_object *fwx_api_dev_visit_time(struct json_object *req_obj);
struct json_object *fwx_api_app_class_visit_time(struct json_object *req_obj);
struct json_object *fwx_api_dev_list(struct json_object *req_obj);
struct json_object *fwx_api_class_list(struct json_object *req_obj);
struct json_object *fwx_api_get_all_users(struct json_object *req_obj);
struct json_object *fwx_api_get_parental_control_detail(struct json_object *req_obj);
struct json_object *fwx_api_get_user_parental_control_rules(struct json_object *req_obj);
struct json_object *fwx_api_get_user_stat(struct json_object *req_obj);
struct json_object *fwx_api_visit_list(struct json_object *req_obj);
struct json_object *fwx_api_add_mock_visit_records(struct json_object *req_obj);
struct json_object *fwx_api_get_device_list(struct json_object *req_obj);
struct json_object *fwx_api_get_dashboard_param(struct json_object *req_obj);
struct json_object *fwx_api_get_init_status(struct json_object *req_obj);
struct json_object *fwx_api_set_init_status(struct json_object *req_obj);
struct json_object *fwx_api_set_dashboard_param(struct json_object *req_obj);
struct json_object *fwx_api_get_system_base_info(struct json_object *req_obj);



static fwx_api_node_t fwx_api_node_list[] = {
    {"get_custom_feature", fwx_api_get_custom_feature, 0, FWX_API_METHOD_GET},
    {"get_custom_feature_class_list", fwx_api_get_custom_feature_class_list, 0, FWX_API_METHOD_GET},
    {"set_custom_feature", fwx_api_set_custom_feature, 0, FWX_API_METHOD_POST},
    {"get_feature_info", fwx_api_get_feature_info, 0, FWX_API_METHOD_GET},
    {"get_feature_online_config", fwx_api_get_feature_online_config, 0, FWX_API_METHOD_GET},
    {"set_feature_online_config", fwx_api_set_feature_online_config, 0, FWX_API_METHOD_POST},
    {"get_feature_online_list", fwx_api_get_feature_online_list, 0, FWX_API_METHOD_GET},
    {"start_feature_online_update", fwx_api_start_feature_online_update, 0, FWX_API_METHOD_POST},
    {"get_feature_online_update_status", fwx_api_get_feature_online_update_status, 0, FWX_API_METHOD_GET},
    {"get_dashboard_common", fwx_api_get_dashboard_common, 0, FWX_API_METHOD_GET},
    {"get_history_session", fwx_api_get_history_session, 0, FWX_API_METHOD_GET},
    {"get_hourly_top_apps", fwx_api_get_hourly_top_apps, 0, FWX_API_METHOD_GET},
    {"get_daily_top_apps", fwx_api_get_daily_top_apps, 0, FWX_API_METHOD_GET},
    {"delete_record_files", fwx_api_delete_record_files, 0, FWX_API_METHOD_POST},
    {"get_global_app_type_stats", fwx_api_get_global_app_type_stats, 0, FWX_API_METHOD_GET},
    {"get_global_traffic_stats", fwx_api_get_global_traffic_stats, 0, FWX_API_METHOD_GET},
    {"get_history_traffic_stats", fwx_api_get_history_traffic_stats, 0, FWX_API_METHOD_GET},
    {"get_daily_top_users", fwx_api_get_daily_top_users, 0, FWX_API_METHOD_GET},
    {"get_active_users", fwx_api_get_active_users, 0, FWX_API_METHOD_GET},
    {"get_active_app_records", fwx_api_get_active_app_records, 0, FWX_API_METHOD_GET},
    {"get_app_history_records", fwx_api_get_app_history_records, 0, FWX_API_METHOD_GET},
    {"get_filter_rules", fwx_api_get_filter_rules, 0, FWX_API_METHOD_GET},
    {"add_filter_rule", fwx_api_add_filter_rule, 1, FWX_API_METHOD_POST},
    {"update_filter_rule", fwx_api_update_filter_rule, 1, FWX_API_METHOD_POST},
    {"delete_filter_rule", fwx_api_delete_filter_rule, 1, FWX_API_METHOD_POST},
    {"get_user_basic_info", fwx_api_get_user_basic_info, 0, FWX_API_METHOD_GET},
    {"get_online_offline_records", fwx_api_get_online_offline_records, 0, FWX_API_METHOD_GET},
    {"get_user_records", fwx_api_get_user_records, 0, FWX_API_METHOD_GET},
    {"get_appfilter_whitelist", fwx_api_get_appfilter_whitelist, 0, FWX_API_METHOD_GET},
    {"add_appfilter_whitelist", fwx_api_add_appfilter_whitelist, 1, FWX_API_METHOD_POST},
    {"del_appfilter_whitelist", fwx_api_del_appfilter_whitelist, 1, FWX_API_METHOD_POST},
    {"get_app_filter_adv", fwx_api_get_app_filter_adv, 0, FWX_API_METHOD_GET},
    {"set_app_filter_adv", fwx_api_set_app_filter_adv, 1, FWX_API_METHOD_POST},
    {"get_system_info", fwx_api_get_system_info, 0, FWX_API_METHOD_GET},
    {"get_system_base_info", fwx_api_get_system_base_info, 0, FWX_API_METHOD_GET},
    {"set_system_info", fwx_api_set_system_info, 1, FWX_API_METHOD_POST},
    {"get_tcp_rst", fwx_api_get_tcp_rst, 0, FWX_API_METHOD_GET},
    {"set_tcp_rst", fwx_api_set_tcp_rst, 1, FWX_API_METHOD_POST},
    {"get_advanced_settings", fwx_api_get_advanced_settings, 0, FWX_API_METHOD_GET},
    {"set_advanced_settings", fwx_api_set_advanced_settings, 1, FWX_API_METHOD_POST},
    {"set_dashboard_notice_status", fwx_api_set_dashboard_notice_status, 1, FWX_API_METHOD_POST},
    {"get_mac_filter_rules", fwx_api_get_mac_filter_rules, 0, FWX_API_METHOD_GET},
    {"add_mac_filter_rule", fwx_api_add_mac_filter_rule, 1, FWX_API_METHOD_POST},
    {"update_mac_filter_rule", fwx_api_update_mac_filter_rule, 1, FWX_API_METHOD_POST},
    {"delete_mac_filter_rule", fwx_api_delete_mac_filter_rule, 1, FWX_API_METHOD_POST},
    {"get_mac_filter_whitelist", fwx_api_get_mac_filter_whitelist, 0, FWX_API_METHOD_GET},
    {"add_mac_filter_whitelist", fwx_api_add_mac_filter_whitelist, 1, FWX_API_METHOD_POST},
    {"del_mac_filter_whitelist", fwx_api_del_mac_filter_whitelist, 1, FWX_API_METHOD_POST},
    {"get_mac_filter_adv", fwx_api_get_mac_filter_adv, 0, FWX_API_METHOD_GET},
    {"set_mac_filter_adv", fwx_api_set_mac_filter_adv, 1, FWX_API_METHOD_POST},
    {"get_record_base", fwx_api_get_record_base, 0, FWX_API_METHOD_GET},
    {"set_record_base", fwx_api_set_record_base, 1, FWX_API_METHOD_POST},
    {"get_record_whitelist", fwx_api_get_record_whitelist, 0, FWX_API_METHOD_GET},
    {"add_record_whitelist", fwx_api_add_record_whitelist, 1, FWX_API_METHOD_POST},
    {"del_record_whitelist", fwx_api_del_record_whitelist, 1, FWX_API_METHOD_POST},
    {"set_record_whitelist", fwx_api_set_record_whitelist, 1, FWX_API_METHOD_POST},
    {"update_record_whitelist", fwx_api_set_record_whitelist, 1, FWX_API_METHOD_POST},
    {"record_action", fwx_api_record_action, 0, FWX_API_METHOD_POST},
    {"add_mock_visit_records", fwx_api_add_mock_visit_records, 0, FWX_API_METHOD_POST},
    {"get_lan_list", fwx_api_get_lan_list, 0, FWX_API_METHOD_GET},
    {"add_lan", fwx_api_add_lan, 1, FWX_API_METHOD_POST},
    {"mod_lan", fwx_api_mod_lan, 1, FWX_API_METHOD_POST},
    {"del_lan", fwx_api_del_lan, 1, FWX_API_METHOD_POST},
    {"get_wan_list", fwx_api_get_wan_list, 0, FWX_API_METHOD_GET},
    {"add_wan", fwx_api_add_wan, 1, FWX_API_METHOD_POST},
    {"mod_wan", fwx_api_mod_wan, 1, FWX_API_METHOD_POST},
    {"del_wan", fwx_api_del_wan, 1, FWX_API_METHOD_POST},
    {"get_lan_info", fwx_api_get_lan_info, 0, FWX_API_METHOD_GET},
    {"set_lan_info", fwx_api_set_lan_info, 1, FWX_API_METHOD_POST},
    {"get_wan_info", fwx_api_get_wan_info, 0, FWX_API_METHOD_GET},
    {"set_wan_info", fwx_api_set_wan_info, 1, FWX_API_METHOD_POST},
	{"get_firewall", fwx_api_get_firewall, 0, FWX_API_METHOD_GET},
    {"set_firewall", fwx_api_set_firewall, 1, FWX_API_METHOD_POST},
    {"get_wireless_base_setting", fwx_api_get_wireless_base_setting, 0, FWX_API_METHOD_GET},
    {"set_wireless_base_setting", fwx_api_set_wireless_base_setting, 1, FWX_API_METHOD_POST},
    {"get_work_mode", fwx_api_get_work_mode, 0, FWX_API_METHOD_GET},
    {"set_work_mode", fwx_api_set_work_mode, 1, FWX_API_METHOD_POST},
    {"set_nickname", fwx_api_set_nickname, 1, FWX_API_METHOD_POST},
    {"get_nickname_list", fwx_api_get_nickname_list, 0, FWX_API_METHOD_GET},
    {"get_mac_blacklist", fwx_api_get_mac_blacklist, 0, FWX_API_METHOD_GET},
    {"add_mac_blacklist", fwx_api_add_mac_blacklist, 1, FWX_API_METHOD_POST},
    {"del_mac_blacklist", fwx_api_del_mac_blacklist, 1, FWX_API_METHOD_POST},
    {"dev_visit_list", fwx_api_dev_visit_list, 0, FWX_API_METHOD_GET},
    {"dev_visit_time", fwx_api_dev_visit_time, 0, FWX_API_METHOD_GET},
    {"app_class_visit_time", fwx_api_app_class_visit_time, 0, FWX_API_METHOD_GET},
    {"dev_list", fwx_api_dev_list, 0, FWX_API_METHOD_GET},
    {"class_list", fwx_api_class_list, 0, FWX_API_METHOD_GET},
    {"get_all_users", fwx_api_get_all_users, 0, FWX_API_METHOD_GET},
    {"get_parental_control_detail", fwx_api_get_parental_control_detail, 0, FWX_API_METHOD_GET},
    {"get_user_parental_control_rules", fwx_api_get_user_parental_control_rules, 0, FWX_API_METHOD_GET},
    {"get_user_stat", fwx_api_get_user_stat, 0, FWX_API_METHOD_GET},
    {"visit_list", fwx_api_visit_list, 0, FWX_API_METHOD_GET},
    {"get_device_list", fwx_api_get_device_list, 0, FWX_API_METHOD_GET},
    {"get_dashboard_param", fwx_api_get_dashboard_param, 0, FWX_API_METHOD_GET},
    {"get_init_status", fwx_api_get_init_status, 0, FWX_API_METHOD_GET},
    {"set_init_status", fwx_api_set_init_status, 0, FWX_API_METHOD_POST},
    {"set_dashboard_param", fwx_api_set_dashboard_param, 1, FWX_API_METHOD_POST},

    {NULL, NULL, 0, FWX_API_METHOD_GET}
};

int ubus_handle_common(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, 
                        const char *method, struct blob_attr *msg) {
    int i = 0;
    fwx_api_node_t *api_node = NULL;
    LOG_DEBUG("method: %s\n", method);
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) 
        return 0;
    LOG_DEBUG("received common ubus request\n");
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    if (!req_obj) {
        LOG_ERROR("Failed to parse JSON request\n");
        ubus_response_json(ctx, req, fwx_gen_api_response_data(API_CODE_ERROR, NULL));
        free(msg_obj_str);
        return 0;
    }
    const char *api_name = NULL;
    struct json_object *api_obj = json_object_object_get(req_obj, "api");
    if (api_obj) {
        api_name = json_object_get_string(api_obj);
    } else {
        LOG_ERROR("api_obj is NULL\n");
        struct json_object *error_response = fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        ubus_response_json(ctx, req, error_response);
        json_object_put(error_response);
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }
    LOG_DEBUG("req data = %s\n", json_object_get_string(req_obj));
    if (fwx_api_need_copyright(api_name) && !fwx_validate_api_request(req_obj)) {
        struct json_object *error_response;

        LOG_INFO("Invalid or missing CopyRight in API request: %s\n", api_name);
        error_response = fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        ubus_response_json(ctx, req, error_response);
        json_object_put(error_response);
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }

    struct json_object *data_obj = json_object_object_get(req_obj, "data");
    if (!data_obj) {
        data_obj = req_obj;
    }


    for (i = 0; i < sizeof(fwx_api_node_list) / sizeof(fwx_api_node_t); i++) {

        if (fwx_api_node_list[i].api_name == NULL) {
            break;
        }
        if (strcmp(fwx_api_node_list[i].api_name, api_name) == 0) {
            api_node = &fwx_api_node_list[i];
            LOG_DEBUG("found api_node: %s\n", api_node->api_name);
            break;
        }
    }
    struct json_object *response_obj = NULL;
    if (api_node && api_node->handler) {
        response_obj = api_node->handler(data_obj);
        if (response_obj) {
            fwx_add_api_response_copyright(response_obj);
            ubus_response_json(ctx, req, response_obj);
            if (api_node->forward) {
                struct json_object *code_obj = json_object_object_get(response_obj, "code");
                struct json_object *no_forward_obj = json_object_object_get(data_obj, "no_forward");
                int no_forward = no_forward_obj ? json_object_get_int(no_forward_obj) : 0;
                if (code_obj && json_object_get_int(code_obj) == API_CODE_SUCCESS && !no_forward) {
                    fwx_forward_to_agent(req_obj);
                }
            }
        } else {
            LOG_ERROR("Handler returned NULL for API: %s\n", api_name);
            response_obj = fwx_gen_api_response_data(API_CODE_ERROR, NULL);
            ubus_response_json(ctx, req, response_obj);
        }
    }
    else {
        LOG_WARN("API not found: %s\n", api_name);
        response_obj = fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        ubus_response_json(ctx, req, response_obj);
    }
    
    if (response_obj) {
        json_object_put(response_obj);
    }
    json_object_put(req_obj);
    free(msg_obj_str);
    return 0;
}

static const struct blobmsg_policy def_policy[1] = {

};


int ubus_handle_common(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, 
                        const char *method, struct blob_attr *msg);

static struct ubus_method fwx_object_methods[] = {
    UBUS_METHOD("common", ubus_handle_common, def_policy),
    UBUS_METHOD("debug", handle_debug, def_policy),
};


static struct ubus_object_type fwx_object_type =
    UBUS_OBJECT_TYPE("fwx", fwx_object_methods);


static struct ubus_object fwx_object = {
    .name = "fwx",
    .type = &fwx_object_type,
    .methods = fwx_object_methods,
    .n_methods = ARRAY_SIZE(fwx_object_methods),
};

static void fwx_add_object(struct ubus_object *obj)
{
    int ret = ubus_add_object(ubus_ctx, obj);
    if (ret != 0)
        LOG_ERROR("Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
}

int fwx_ubus_init(void)
{
    LOG_INFO("fwx ubus init...\n");
	ubus_ctx = ubus_connect("/var/run/ubus/ubus.sock");
    if (!ubus_ctx){
		ubus_ctx = ubus_connect("/var/run/ubus.sock");
	}
	if (!ubus_ctx){
        LOG_ERROR("Failed to connect to ubus\n");
		return -EIO;
	}

    fwx_add_object(&fwx_object);
    ubus_add_uloop(ubus_ctx);
    return 0;
}
