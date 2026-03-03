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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include "appfilter_user.h"
#include "appfilter_config.h"
#include <uci.h>
#include "appfilter.h"
#include "utils.h"

extern int g_oaf_config_change;
int g_enable_agent = 0;

struct ubus_context *ubus_ctx = NULL;
static struct blob_buf b;

extern char *format_time(int timetamp);

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

int check_app_icon_exist(int app_id)
{
    char icon_path[512];
    snprintf(icon_path, sizeof(icon_path), "/www/luci-static/resources/app_icons/%d.png", app_id);
    int with_icon = access(icon_path, F_OK) == 0 ? 1 : 0; 
    return with_icon;
}

void ubus_dump_visit_list(struct blob_buf *b, char *mac)
{
    int i, j;
    void *c, *array;
    void *t;
    void *s;

    array = blobmsg_open_array(b, "dev_list");

    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            if (mac && strcmp(mac, node->mac))
            {
                node = node->next;
                continue;
            }
            t = blobmsg_open_table(b, NULL);
            blobmsg_add_string(b, "hostname", "unknown");
            blobmsg_add_string(b, "mac", node->mac);
            blobmsg_add_string(b, "ip", node->ip);
            void *visit_array;

            visit_array = blobmsg_open_array(b, "visit_info");
            for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
            {
                visit_info_t *p_info = node->visit_htable[j];
                while (p_info)
                {
                    char *first_time_str = format_time(p_info->first_time);
                    char *latest_time_str = format_time(p_info->latest_time);
                    int total_time = p_info->latest_time - p_info->first_time;
                    s = blobmsg_open_table(b, NULL);
                    blobmsg_add_string(b, "appname", "unknown");
                    blobmsg_add_u32(b, "appid", p_info->appid);
                    blobmsg_add_u32(b, "latest_action", p_info->action);
                    blobmsg_add_u32(b, "first_time", p_info->first_time);
                    blobmsg_add_u32(b, "latest_time", p_info->latest_time);
                    blobmsg_close_table(b, s);
                    if (first_time_str)
                        free(first_time_str);
                    if (latest_time_str)
                        free(latest_time_str);
                    p_info = p_info->next;
                }
            }

            blobmsg_close_array(b, visit_array);
            blobmsg_close_table(b, t);
            node = node->next;
        }
    }
    blobmsg_close_array(b, array);
}

// Function to compare JSON objects based on the "lt" field
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


static int
appfilter_handle_dev_visit_list(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    int i, j;
    struct json_object *root_obj = json_object_new_object();
    struct json_object *visit_array = json_object_new_array();
    int page = 0;
    int page_size = 20; // Default page size

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
        free(msg_obj_str);
        return 0;
    }

    // Parse pagination parameters
    struct json_object *page_obj = json_object_object_get(req_obj, "page");
    struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
    if (page_obj) {
        page = json_object_get_int(page_obj);
    }
    if (page_size_obj) {
        page_size = json_object_get_int(page_size_obj);
        if (page_size <= 0) {
            page_size = 20; // Default to 20 if invalid
        }
    }

    char *mac = json_object_get_string(mac_obj);
    dev_node_t *node = find_dev_node(mac);

    if (!node)
    {
        printf("not found mac:%s\n", mac);
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }

    json_object_object_add(root_obj, "hostname", json_object_new_string(node->hostname));
    json_object_object_add(root_obj, "mac", json_object_new_string(node->mac));
    json_object_object_add(root_obj, "ip", json_object_new_string(node->ip));

    for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
    { 
        visit_info_t *p_info = node->visit_htable[j];
        while (p_info)
        {
            char *first_time_str = format_time(p_info->first_time);
            char *latest_time_str = format_time(p_info->latest_time);
            int total_time = p_info->latest_time - p_info->first_time;
            if (strlen(get_app_name_by_id(p_info->appid)) == 0){
                p_info = p_info->next;
                if (first_time_str)
                    free(first_time_str);
                if (latest_time_str)
                    free(latest_time_str);
                continue;
            }
            struct json_object *visit_obj = json_object_new_object();
            json_object_object_add(visit_obj, "name", json_object_new_string(get_app_name_by_id(p_info->appid)));
            json_object_object_add(visit_obj, "id", json_object_new_int(p_info->appid));
            if (check_app_icon_exist(p_info->appid)) {
                json_object_object_add(visit_obj, "icon", json_object_new_int(1));
            }
            else
                json_object_object_add(visit_obj, "icon", json_object_new_int(0));
            json_object_object_add(visit_obj, "act", json_object_new_int(p_info->action));
            json_object_object_add(visit_obj, "ft", json_object_new_int(p_info->first_time));
            json_object_object_add(visit_obj, "lt", json_object_new_int(p_info->latest_time));
            json_object_object_add(visit_obj, "tt", json_object_new_int(total_time));
            json_object_array_add(visit_array, visit_obj);

            if (first_time_str)
                free(first_time_str);
            if (latest_time_str)
                free(latest_time_str);
            p_info = p_info->next;
        }
    }

    json_object_array_sort(visit_array, compare_lt);

    int total_count = json_object_array_length(visit_array);

    struct json_object *paged_array = NULL;
    if (page == 0) {
        paged_array = visit_array;
        json_object_get(visit_array); 
    } else {
        paged_array = json_object_new_array();
        int start_idx = (page - 1) * page_size;
        int end_idx = start_idx + page_size;
        int i;
        for (i = start_idx; i < end_idx && i < total_count; i++) {
            struct json_object *visit_obj = json_object_array_get_idx(visit_array, i);
            if (visit_obj) {
                json_object_get(visit_obj);
                json_object_array_add(paged_array, visit_obj);
            }
        }
    }

    json_object_object_add(root_obj, "total", json_object_new_int(total_count));
    json_object_object_add(root_obj, "list", paged_array);
    json_object_object_add(root_obj, "page", json_object_new_int(page));
    json_object_object_add(root_obj, "page_size", json_object_new_int(page_size));
    
    int total_pages = 0;
    if (page_size > 0) {
        total_pages = (total_count + page_size - 1) / page_size; // Ceiling division
    }
    json_object_object_add(root_obj, "total_pages", json_object_new_int(total_pages));

    if (req_obj) {
        json_object_put(req_obj);
    }
    if (msg_obj_str) {
        free(msg_obj_str);
    }
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, root_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(root_obj);
    return 0;
}


void update_app_visit_time_list(char *mac, struct app_visit_stat_info *visit_info)
{
    int i, j, s;
    int num = 0;

    dev_node_t *node = find_dev_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    for (i = 0; i < MAX_APP_TYPE; i++)
    {
        for (j = 0; j < MAX_APP_ID_NUM; j++)
        {
            unsigned long long min = visit_info->visit_list[0].total_time;
            int min_index = 0;
            if (node->stat[i][j].total_time == 0)
                continue;
            if (num < MAX_APP_STAT_NUM)
            {
                min_index = num;
            }
            else
            {
                for (s = 0; s < MAX_APP_STAT_NUM; s++)
                {
                    if (visit_info->visit_list[s].total_time < min)
                    {
                        min_index = s;
                        break;
                    }
                }
            }
            num++;
            if (node->stat[i][j].total_time > visit_info->visit_list[min_index].total_time)
            {
                visit_info->visit_list[min_index].total_time = node->stat[i][j].total_time;
                visit_info->visit_list[min_index].app_id = (i + 1) * 1000 + j + 1;
            }
        }
    }
    if (num < MAX_APP_STAT_NUM)
        visit_info->num = num;
    else
        visit_info->num = MAX_APP_STAT_NUM;
}

void update_app_class_visit_time_list(char *mac, int *visit_time)
{
    int i, j, s;
    int num = 0;

    dev_node_t *node = find_dev_node(mac);
    if (!node)
    {
        printf("not found mac:%s\n", mac);
        return;
    }
    for (i = 0; i < MAX_APP_TYPE; i++)
    {
        for (j = 0; j < MAX_APP_ID_NUM; j++)
        {
            if (node->stat[i][j].total_time == 0)
                continue;
            visit_time[i] += node->stat[i][j].total_time;
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

static int
appfilter_handle_visit_list(struct ubus_context *ctx, struct ubus_object *obj,
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
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");

    if (!mac_obj)
    {
        ubus_dump_visit_list(&b, NULL);
    }
    else
        ubus_dump_visit_list(&b, json_object_get_string(mac_obj));
    ubus_send_reply(ctx, req, b.head);
    json_object_put(req_obj);
    free(msg_obj_str);
    return 0;
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
    json_object_put(req_obj);
    free(msg_obj_str);
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
void update_top5_app(dev_node_t *node, app_visit_time_info_t top5_app_list[])
{
    int i, j;
    app_visit_time_info_t app_visit_array[MAX_STAT_APP_NUM];
    memset(app_visit_array, 0x0, sizeof(app_visit_array));
    int app_visit_num = 0;

    for (i = 0; i < MAX_APP_TYPE; i++)
    {
        for (j = 0; j < MAX_APP_ID_NUM; j++)
        {
            if (node->stat[i][j].total_time == 0)
                continue;
            app_visit_array[app_visit_num].app_id = (i + 1) * 1000 + j + 1;
            app_visit_array[app_visit_num].total_time = node->stat[i][j].total_time;
            app_visit_num++;
        }
    }

    qsort((void *)app_visit_array, app_visit_num, sizeof(app_visit_time_info_t), visit_time_compare);
#if 0
for (i = 0; i < app_visit_num; i++){
printf("appid %d-----------total time %llu\n", app_visit_array[i].app_id,
app_visit_array[i].total_time);
}
#endif
    for (i = 0; i < 5; i++)
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
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {

        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            struct json_object *dev_obj = json_object_new_object();
            struct json_object *app_array = json_object_new_array();
            app_visit_time_info_t top5_app_list[5];
            memset(top5_app_list, 0x0, sizeof(top5_app_list));
            update_top5_app(node, top5_app_list);

            for (j = 0; j < 5; j++)
            {
                if (top5_app_list[j].app_id == 0 || strlen(get_app_name_by_id(top5_app_list[j].app_id)) == 0)
                    break;
                struct json_object *app_obj = json_object_new_object();
                json_object_object_add(app_obj, "id", json_object_new_int(top5_app_list[j].app_id));
                json_object_object_add(app_obj, "name", json_object_new_string(get_app_name_by_id(top5_app_list[j].app_id)));
                json_object_array_add(app_array, app_obj);
            }

            json_object_object_add(dev_obj, "applist", app_array);
            json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
            char hostname[128] = {0};
            get_hostname_by_mac(node->mac, hostname);
            json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));

            json_object_object_add(dev_obj, "online", json_object_new_int(1));
            json_object_object_add(dev_obj, "hostname", json_object_new_string(hostname));
            json_object_object_add(dev_obj, "nickname", json_object_new_string(""));


            json_object_array_add(dev_array, dev_obj);

            node = node->next;
            count++;
        }
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
        if (strlen(get_app_name_by_id(info.visit_list[i].app_id)) == 0){
            continue;
        }
        struct json_object *app_info_obj = json_object_new_object();
        json_object_object_add(app_info_obj, "id", json_object_new_int(info.visit_list[i].app_id));
        json_object_object_add(app_info_obj, "name", json_object_new_string(get_app_name_by_id(info.visit_list[i].app_id)));
        json_object_object_add(app_info_obj, "t", json_object_new_int(info.visit_list[i].total_time));
        json_object_array_add(app_info_array, app_info_obj);
    }

    blobmsg_add_object(&b, resp_obj);
    ubus_send_reply(ctx, req, b.head);
    json_object_put(resp_obj);
    json_object_put(req_obj);
    free(msg_obj_str);
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
        json_object_put(req_obj);
        free(msg_obj_str);
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
    free(msg_obj_str);
    return 0;
}


static int parse_feature_cfg(struct json_object *class_list) {
    FILE *file = fopen("/tmp/feature.cfg", "r");
    if (!file) {
        perror("Failed to open /tmp/feature.cfg");
        return -1;
    }

	char line[1024];
    char app_buf[128];
    struct json_object *current_class = NULL;
    struct json_object *app_list = NULL;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        if (strncmp(line, "#class", 6) == 0) {
            if (current_class) {
                json_object_object_add(current_class, "app_list", app_list);
                json_object_array_add(class_list, current_class);
            }

            char *name = strtok(line + 7, " ");
            char *class_name = NULL;
            while (name != NULL) {
                class_name = name; 
                name = strtok(NULL, " ");
            }
            current_class = json_object_new_object();
            json_object_object_add(current_class, "name", json_object_new_string(class_name));
            app_list = json_object_new_array();
        } else if (current_class) {
            char *p_end = strstr(line, ":");
            if (!p_end) {
                continue;
            }
            strncpy(app_buf, line, p_end - line);
            app_buf[p_end - line] = '\0';
            char *appid_str = strtok(app_buf, " ");
            char *name = strtok(NULL, " ");
            if (appid_str && name) {
                char combined[256];
                char icon_path[512];
                snprintf(icon_path, sizeof(icon_path), "/www/luci-static/resources/app_icons/%s.png", appid_str);
                int with_icon = access(icon_path, F_OK) == 0 ? 1 : 0; 
                snprintf(combined, sizeof(combined), "%s,%s,%d", appid_str, name, with_icon);
                json_object_array_add(app_list, json_object_new_string(combined));
            }
        }
    }

    // Add the last class to the class list
    if (current_class) {
        json_object_object_add(current_class, "app_list", app_list);
        json_object_array_add(class_list, current_class);
    }

    fclose(file);
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
#define MAX_APPFILTER_STR_LEN 8192
static int handle_get_app_filter(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {

    int i;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    char *appfilter_buf = (char *)malloc(MAX_APPFILTER_STR_LEN);
    if (!appfilter_buf){
        return 0;
    }
    appfilter_buf[0] = '\0';
    struct json_object *response = json_object_new_object();
    struct json_object *app_list = json_object_new_array();
    af_uci_get_list_value(uci_ctx, "appfilter.rule.app_list", appfilter_buf, MAX_APPFILTER_STR_LEN - 1, " ");
    char *app_id_str = strtok(appfilter_buf, " ");
    while (app_id_str) {
        json_object_array_add(app_list, json_object_new_int(atoi(app_id_str)));
        app_id_str = strtok(NULL, " ");
    }
    json_object_object_add(response, "app_list", app_list);
    uci_free_context(uci_ctx);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    free(appfilter_buf);
    json_object_put(response);
    return 0;
}



void af_forward_msg_to_agent(char *api, char *msg_str, int msg_len)
{
	if (!api || !msg_str || !msg_len)
		return;
	char *cmd_buf = (char *)malloc(msg_len + 128);
	if (!cmd_buf)
		return;
	sprintf(cmd_buf, "ubus -t 2 call oaf_agent %s '%s'", api, msg_str);
	printf("exec %s\n", cmd_buf);
	system(cmd_buf);
	free(cmd_buf);
}


static int handle_set_app_filter(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    printf("handle_set_app_filter\n");
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return 0;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *app_list = json_object_object_get(req_obj, "app_list");
    if (!app_list) {
        printf("app_list is NULL\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }

   af_uci_delete(uci_ctx, "appfilter.rule.app_list");

   int len = json_object_array_length(app_list);
    for (i = 0; i < json_object_array_length(app_list); i++) {
        struct json_object *app_id_obj = json_object_array_get_idx(app_list, i);
        af_uci_add_int_list(uci_ctx, "appfilter.rule.app_list", json_object_get_int(app_id_obj));
    }
    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    g_oaf_config_change = 1;

    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}




static int handle_get_app_filter_base(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    int i;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    int enable = 0;
    int work_mode = 0;
    int record_enable = 0;
    int disable_quic = 0;
    int app_filter_mode = 0;
    enable = af_uci_get_int_value(uci_ctx, "appfilter.global.enable");
    work_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.work_mode");
    record_enable = af_uci_get_int_value(uci_ctx, "appfilter.global.record_enable");
    disable_quic = af_uci_get_int_value(uci_ctx, "appfilter.global.disable_quic");
    app_filter_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.app_filter_mode");
    if (app_filter_mode < 0) {
        app_filter_mode = 0; // Default to specified apps mode
    }


    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));
    json_object_object_add(data_obj, "record_enable", json_object_new_int(record_enable));
    json_object_object_add(data_obj, "disable_quic", json_object_new_int(disable_quic));
    json_object_object_add(data_obj, "app_filter_mode", json_object_new_int(app_filter_mode));


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

static int handle_set_app_filter_base(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    printf("handle_set_app_filter_base\n");
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return 0;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *enable_obj = json_object_object_get(req_obj, "enable");
    struct json_object *record_enable_obj = json_object_object_get(req_obj, "record_enable");
    struct json_object *work_mode_obj = json_object_object_get(req_obj, "work_mode");
    struct json_object *disable_quic_obj = json_object_object_get(req_obj, "disable_quic");
    struct json_object *app_filter_mode_obj = json_object_object_get(req_obj, "app_filter_mode");
    if (!enable_obj || !work_mode_obj) {
        printf("enable_obj or work_mode_obj is NULL\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    printf("enable_obj: %d\n", json_object_get_int(enable_obj));
    printf("work_mode_obj: %d\n", json_object_get_int(work_mode_obj));


    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }

    af_uci_set_int_value(uci_ctx, "appfilter.global.enable", json_object_get_int(enable_obj));
    af_uci_set_int_value(uci_ctx, "appfilter.global.work_mode", json_object_get_int(work_mode_obj));
    
    if (record_enable_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.record_enable", json_object_get_int(record_enable_obj));
    else
        af_uci_set_int_value(uci_ctx, "appfilter.global.record_enable", 0);
    
    if (disable_quic_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.disable_quic", json_object_get_int(disable_quic_obj));
    else
        af_uci_set_int_value(uci_ctx, "appfilter.global.disable_quic", 0);
    
    if (app_filter_mode_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.app_filter_mode", json_object_get_int(app_filter_mode_obj));
    else
        af_uci_set_int_value(uci_ctx, "appfilter.global.app_filter_mode", 0);


    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    g_oaf_config_change = 1;
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


static int handle_get_app_filter_adv(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();

    int i;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    char lan_ifname[16];

    int tcp_rst = af_uci_get_int_value(uci_ctx, "appfilter.global.tcp_rst");
    af_uci_get_value(uci_ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname));
    int disable_hnat = af_uci_get_int_value(uci_ctx, "appfilter.global.disable_hnat");
    int auto_load_engine = af_uci_get_int_value(uci_ctx, "appfilter.global.auto_load_engine");

    json_object_object_add(data_obj, "tcp_rst", json_object_new_int(tcp_rst));
    json_object_object_add(data_obj, "lan_ifname", json_object_new_string(lan_ifname));
    json_object_object_add(data_obj, "disable_hnat", json_object_new_int(disable_hnat));
    json_object_object_add(data_obj, "auto_load_engine", json_object_new_int(auto_load_engine));

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
static int handle_set_app_filter_adv(struct ubus_context *ctx, struct ubus_object *obj,
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
    struct json_object *tcp_rst_obj = json_object_object_get(req_obj, "tcp_rst");
    struct json_object *lan_ifname_obj = json_object_object_get(req_obj, "lan_ifname");
    struct json_object *disable_hnat_obj = json_object_object_get(req_obj, "disable_hnat");
    struct json_object *auto_load_engine_obj = json_object_object_get(req_obj, "auto_load_engine");

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    if (tcp_rst_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.tcp_rst", json_object_get_int(tcp_rst_obj));
    if (lan_ifname_obj)
        af_uci_set_value(uci_ctx, "appfilter.global.lan_ifname", json_object_get_string(lan_ifname_obj));
    if (disable_hnat_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.disable_hnat", json_object_get_int(disable_hnat_obj));
    if (auto_load_engine_obj){
        af_uci_set_int_value(uci_ctx, "appfilter.global.auto_load_engine", json_object_get_int(auto_load_engine_obj));
        if (json_object_get_int(auto_load_engine_obj) == 0){
            system("rm /etc/modules.d/oaf");
        }
    }


    af_uci_commit(uci_ctx, "appfilter");
    g_oaf_config_change = 1;
    reload_oaf_rule();
    system("/usr/bin/hnat.sh &");
    if (g_enable_agent) {
        af_forward_msg_to_agent("set_app_filter_adv", msg_obj_str, strlen(msg_obj_str));
    }
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


static int handle_get_app_filter_time(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    // Get current system time (format: 2025/2/27 10:00)
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);
    char current_time_str[64] = {0};
    snprintf(current_time_str, sizeof(current_time_str), "%d/%d/%d %d:%02d",
             current_time->tm_year + 1900,
             current_time->tm_mon + 1,
             current_time->tm_mday,
             current_time->tm_hour,
             current_time->tm_min);
    json_object_object_add(data_obj, "current_time", json_object_new_string(current_time_str));

    // Get time_mode
    int time_mode = af_uci_get_int_value(uci_ctx, "appfilter.time.time_mode");
    json_object_object_add(data_obj, "mode", json_object_new_int(time_mode));

    // Get days (global weekday_list)
    char days_str[128] = {0};
    af_uci_get_value(uci_ctx, "appfilter.time.days", days_str, sizeof(days_str));
    printf("days_str: %s\n", days_str);
    struct json_object *days_array = json_object_new_array();
    char *day = strtok(days_str, " ");
    while (day) {
        json_object_array_add(days_array, json_object_new_int(atoi(day)));
        day = strtok(NULL, " ");
    }
    json_object_object_add(data_obj, "weekday_list", days_array);

    // Get start_time and end_time
    char start_time[32] = {0};
    char end_time[32] = {0};
    af_uci_get_value(uci_ctx, "appfilter.time.start_time", start_time, sizeof(start_time));
    af_uci_get_value(uci_ctx, "appfilter.time.end_time", end_time, sizeof(end_time));
    json_object_object_add(data_obj, "start_time", json_object_new_string(start_time));
    json_object_object_add(data_obj, "end_time", json_object_new_string(end_time));

    // Get deny_time and allow_time
    int deny_time = af_uci_get_int_value(uci_ctx, "appfilter.time.deny_time");
    int allow_time = af_uci_get_int_value(uci_ctx, "appfilter.time.allow_time");
    json_object_object_add(data_obj, "deny_time", json_object_new_int(deny_time));
    json_object_object_add(data_obj, "allow_time", json_object_new_int(allow_time));

    // Get time list and parse into objects with start_time and end_time
    char time_str[MAX_TIME_LIST_LEN] = {0};
    af_uci_get_list_value(uci_ctx, "appfilter.time.time", time_str, sizeof(time_str), " ");
    printf("time_str from uci: %s\n", time_str);
    struct json_object *time_array = json_object_new_array();
    
    // Parse global weekday_list (used as fallback if time period doesn't have weekdays)
    int global_weekdays[7] = {0};
    char days_str_copy[128] = {0};
    strncpy(days_str_copy, days_str, sizeof(days_str_copy) - 1);
    char *day_token = strtok(days_str_copy, " ");
    while (day_token) {
        int day_val = atoi(day_token);
        if (day_val >= 0 && day_val < 7) {
            global_weekdays[day_val] = 1;
        }
        day_token = strtok(NULL, " ");
    }
    
    char time_str_copy[MAX_TIME_LIST_LEN] = {0};
    strncpy(time_str_copy, time_str, sizeof(time_str_copy) - 1);
    printf("ubus parsing time_str_copy: %s\n", time_str_copy);
    
    // Use strtok_r (reentrant version) to avoid issues with nested strtok calls
    char *saveptr1 = NULL;
    char *time_period = strtok_r(time_str_copy, " ", &saveptr1);
    int period_count = 0;
    
    while (time_period) {
        period_count++;
        printf("ubus parsing period[%d]: %s\n", period_count, time_period);
        
        char start[16] = {0};
        char end[16] = {0};
        char weekdays_str[64] = {0};
        int has_weekdays = 0;
        
        char *semicolon = strchr(time_period, ';');
        if (semicolon) {
            has_weekdays = 1;
            strncpy(weekdays_str, time_period, semicolon - time_period);
            weekdays_str[semicolon - time_period] = '\0';
            time_period = semicolon + 1;
            printf("ubus period[%d] has weekdays: %s, time_part: %s\n", period_count, weekdays_str, time_period);
        }
        
        char *delimiter = strchr(time_period, '-');
        if (delimiter) {
            strncpy(start, time_period, delimiter - time_period);
            start[delimiter - time_period] = '\0';
            
            strcpy(end, delimiter + 1);
            
            printf("ubus period[%d] parsed: start=%s, end=%s\n", period_count, start, end);

            struct json_object *period_obj = json_object_new_object();
            json_object_object_add(period_obj, "start", json_object_new_string(start));
            json_object_object_add(period_obj, "end", json_object_new_string(end));
            
            struct json_object *period_weekdays = json_object_new_array();
            if (has_weekdays) {
                char weekdays_copy[64] = {0};
                strncpy(weekdays_copy, weekdays_str, sizeof(weekdays_copy) - 1);
                char *saveptr2 = NULL;
                char *wd = strtok_r(weekdays_copy, ",", &saveptr2);
                while (wd) {
                    json_object_array_add(period_weekdays, json_object_new_int(atoi(wd)));
                    wd = strtok_r(NULL, ",", &saveptr2);
                }
                printf("ubus period[%d] weekday_list size: %d\n", period_count, json_object_array_length(period_weekdays));
            } else {
                // Use global weekdays as fallback
                int i;
                for (i = 0; i < 7; i++) {
                    if (global_weekdays[i]) {
                        json_object_array_add(period_weekdays, json_object_new_int(i));
                    }
                }
            }
            json_object_object_add(period_obj, "weekday_list", period_weekdays);
            
            json_object_array_add(time_array, period_obj);
            printf("ubus period[%d] added to array, current array length: %d\n", period_count, json_object_array_length(time_array));
        } else {
            printf("ubus period[%d] ERROR: no delimiter found\n", period_count);
        }
        
        // Get next period using strtok_r
        time_period = strtok_r(NULL, " ", &saveptr1);
        if (time_period) {
            printf("ubus next period will be: %s\n", time_period);
        } else {
            printf("ubus no more periods\n");
        }
    }
    json_object_object_add(data_obj, "time_list", time_array);


    if (time_mode == 2) {
        struct json_object *daily_time_list_array = json_object_new_array();
        
        // Initialize array with 7 elements (Sunday to Saturday)
        int weekday;
        for (weekday = 0; weekday < 7; weekday++) {
            char uci_key[64] = {0};
            snprintf(uci_key, sizeof(uci_key), "appfilter.time.daily_limit_%d", weekday);
            
            char daily_limit_str[128] = {0};
            af_uci_get_value(uci_ctx, uci_key, daily_limit_str, sizeof(daily_limit_str));
            

            int enable = 0;
            int am_time = 0;
            int pm_time = 0;
            if (strlen(daily_limit_str) > 0) {
                char *first_colon = strchr(daily_limit_str, ':');
                if (first_colon) {
                    char *second_colon = strchr(first_colon + 1, ':');
                    if (second_colon) {
                        // New format: "enable:am_time:pm_time"
                        enable = atoi(daily_limit_str);
                        am_time = atoi(first_colon + 1);
                        pm_time = atoi(second_colon + 1);
                    } else {
                        enable = 1; // Default to enabled for old format
                        am_time = atoi(daily_limit_str);
                        pm_time = atoi(first_colon + 1);
                    }
                } else {
                    enable = 1; // Default to enabled
                    am_time = atoi(daily_limit_str);
                }
            }
            
            struct json_object *day_obj = json_object_new_object();
            json_object_object_add(day_obj, "enable", json_object_new_int(enable));
            json_object_object_add(day_obj, "am_time", json_object_new_int(am_time));
            json_object_object_add(day_obj, "pm_time", json_object_new_int(pm_time));
            json_object_array_add(daily_time_list_array, day_obj);
        }
        
        json_object_object_add(data_obj, "daily_time_list", daily_time_list_array);
        
        time_t now = time(NULL);
        struct tm *current_time = localtime(&now);
        int current_weekday = current_time->tm_wday; // 0=Sunday, 1=Monday, ..., 6=Saturday
        int current_hour = current_time->tm_hour;
        
        json_object_object_add(data_obj, "current_weekday", json_object_new_int(current_weekday));
    
        int total_am_time = 0;
        int total_pm_time = 0;
        int i;
        for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
            dev_node_t *node = dev_hash_table[i];
            while (node) {
                if (node->is_selected) {
                    total_am_time += node->today_am_active_time;
                    total_pm_time += node->today_pm_active_time;
                }
                node = node->next;
            }
        }
        
        json_object_object_add(data_obj, "current_am_used_time", json_object_new_int(total_am_time));
        json_object_object_add(data_obj, "current_pm_used_time", json_object_new_int(total_pm_time));
        
        daily_limit_config_t *daily_limit = &g_af_config.time.daily_limit[current_weekday];
        json_object_object_add(data_obj, "current_am_limit", json_object_new_int(daily_limit->am_time));
        json_object_object_add(data_obj, "current_pm_limit", json_object_new_int(daily_limit->pm_time));
        json_object_object_add(data_obj, "current_day_enabled", json_object_new_int(daily_limit->enable));
    }

    json_object_object_add(response, "data", data_obj);
    
    printf("response_json: %s\n", json_object_to_json_string(response));
    uci_free_context(uci_ctx);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


//  {"end_time":"12:00","weekday_list":[1,2,3,4,5,6,0],"deny_time":5,"start_time":"22:22","allow_time":30,"mode":1}
// {"mode":0,"weekday_list":[1,2],"time_list":[{"start":"00:11","end":"00:12"},{"start":"12:00","end":"14:00"}]}
static int handle_set_app_filter_time(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    printf("set appfilter time\n");
    int mode = 0;
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        return 0;
    }
     printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    if (!mode_obj) {
        printf("mode_obj is NULL\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }
    printf("mode_obj: %d\n", json_object_get_int(mode_obj));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        return 0;
    }
    mode = json_object_get_int(mode_obj);
    af_uci_set_int_value(uci_ctx, "appfilter.time.time_mode", mode);

    struct json_object *weekday_list_obj = json_object_object_get(req_obj, "weekday_list");
    if (weekday_list_obj && (mode == 0 || mode == 1)) {
        char days_str[128] = {0};
        for (i = 0; i < json_object_array_length(weekday_list_obj); i++) {
            struct json_object *weekday_obj = json_object_array_get_idx(weekday_list_obj, i);
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "%d", json_object_get_int(weekday_obj));
            if (i > 0) strcat(days_str, " ");
            strcat(days_str, tmp);
        }
        af_uci_set_value(uci_ctx, "appfilter.time.days", days_str);
    }

    if (mode == 0) {
        struct json_object *time_list_obj = json_object_object_get(req_obj, "time_list");
        if (!time_list_obj) {
            printf("time_list_obj is NULL\n");
            goto EXIT;
        }
        af_uci_delete(uci_ctx, "appfilter.time.time");
        int time_list_len = json_object_array_length(time_list_obj);
        for (i = 0; i < time_list_len; i++) {
            struct json_object *time_obj = json_object_array_get_idx(time_list_obj, i);
            struct json_object *start_time_obj = json_object_object_get(time_obj, "start");
            struct json_object *end_time_obj = json_object_object_get(time_obj, "end");
            if (!start_time_obj || !end_time_obj) {
                printf("start_time_obj or end_time_obj is NULL\n");
                goto EXIT;
            }
            
            char time_str[256] = {0};
            
            struct json_object *period_weekday_list_obj = json_object_object_get(time_obj, "weekday_list");
            if (period_weekday_list_obj && json_object_array_length(period_weekday_list_obj) > 0) {
                // Build weekday string: "1,2,4,5"
                char weekday_str[64] = {0};
                int j;
                for (j = 0; j < json_object_array_length(period_weekday_list_obj); j++) {
                    struct json_object *wd_obj = json_object_array_get_idx(period_weekday_list_obj, j);
                    if (j > 0) strcat(weekday_str, ",");
                    char tmp[8];
                    snprintf(tmp, sizeof(tmp), "%d", json_object_get_int(wd_obj));
                    strcat(weekday_str, tmp);
                }
                sprintf(time_str, "%s;%s-%s", weekday_str, 
                        json_object_get_string(start_time_obj), 
                        json_object_get_string(end_time_obj));
            } else {
                // No weekday_list in time_obj: use global weekday_list (fallback to old format)
                sprintf(time_str, "%s-%s", 
                        json_object_get_string(start_time_obj), 
                        json_object_get_string(end_time_obj));
            }
            
            printf("time_str: %s\n", time_str);
            af_uci_add_list(uci_ctx, "appfilter.time.time", time_str);
        }
    }
    else if (mode == 1) {
        struct json_object *deny_time_obj = json_object_object_get(req_obj, "deny_time");
        struct json_object *allow_time_obj = json_object_object_get(req_obj, "allow_time");
        struct json_object *start_time_obj = json_object_object_get(req_obj, "start_time");
        struct json_object *end_time_obj = json_object_object_get(req_obj, "end_time");
        if (!deny_time_obj || !allow_time_obj || !start_time_obj || !end_time_obj) {
            printf("deny_time_obj or allow_time_obj or start_time_obj or end_time_obj is NULL\n");
            goto EXIT;
        }
        af_uci_set_int_value(uci_ctx, "appfilter.time.deny_time", json_object_get_int(deny_time_obj));
        af_uci_set_int_value(uci_ctx, "appfilter.time.allow_time", json_object_get_int(allow_time_obj));
        af_uci_set_value(uci_ctx, "appfilter.time.start_time", json_object_get_string(start_time_obj));
        af_uci_set_value(uci_ctx, "appfilter.time.end_time", json_object_get_string(end_time_obj));
    }
    else if (mode == 2) {

        struct json_object *daily_time_list_obj = json_object_object_get(req_obj, "daily_time_list");
        if (!daily_time_list_obj) {
            printf("daily_time_list_obj is NULL\n");
            goto EXIT;
        }
        
        int daily_time_list_len = json_object_array_length(daily_time_list_obj);
        if (daily_time_list_len != 7) {
            printf("daily_time_list length should be 7, got %d\n", daily_time_list_len);
            goto EXIT;
        }
        
        for (i = 0; i < 7; i++) {
            char uci_key[64] = {0};
            snprintf(uci_key, sizeof(uci_key), "appfilter.time.daily_limit_%d", i);
            af_uci_delete(uci_ctx, uci_key);
        }
        
        for (i = 0; i < 7; i++) {
            struct json_object *day_obj = json_object_array_get_idx(daily_time_list_obj, i);
            struct json_object *enable_obj = json_object_object_get(day_obj, "enable");
            struct json_object *am_time_obj = json_object_object_get(day_obj, "am_time");
            struct json_object *pm_time_obj = json_object_object_get(day_obj, "pm_time");
            
            if (enable_obj && am_time_obj && pm_time_obj) {
                int enable = json_object_get_int(enable_obj);
                int am_time = json_object_get_int(am_time_obj);
                int pm_time = json_object_get_int(pm_time_obj);
                
                // Format: "enable:am_time:pm_time" (e.g., "1:100:200")
                char limit_str[32] = {0};
                snprintf(limit_str, sizeof(limit_str), "%d:%d:%d", enable, am_time, pm_time);
                
                char uci_key[64] = {0};
                snprintf(uci_key, sizeof(uci_key), "appfilter.time.daily_limit_%d", i);
                printf("daily_limit_%d: %s\n", i, limit_str);
                af_uci_set_value(uci_ctx, uci_key, limit_str);
            }
        }
    }
    af_uci_commit(uci_ctx, "appfilter");
    g_oaf_config_change = 1;
    if (g_enable_agent) {
        af_forward_msg_to_agent("set_app_filter_time", msg_obj_str, strlen(msg_obj_str));
    }
EXIT:
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
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
} all_users_info_t;



void all_users_callback(void *arg, dev_node_t *dev)
{
    int flag = 0;
    int i;
    all_users_info_t *au_info = (all_users_info_t *)arg;
    flag = au_info->flag;
    struct json_object *users_array = au_info->users_array;

    struct json_object *user_obj = json_object_new_object();
    json_object_object_add(user_obj, "mac", json_object_new_string(dev->mac));
    
    int online_status = dev->online;
    if (dev->active == 1 && dev->online == 1) {
        online_status = 2; 
    }
    json_object_object_add(user_obj, "online", json_object_new_int(online_status));
    json_object_object_add(user_obj, "online_time", json_object_new_int(dev->online_time));
    json_object_object_add(user_obj, "offline_time", json_object_new_int(dev->offline_time));
    json_object_object_add(user_obj, "today_am_active_time", json_object_new_int(dev->today_am_active_time));
    json_object_object_add(user_obj, "today_pm_active_time", json_object_new_int(dev->today_pm_active_time));

    if (flag > 0) {
        json_object_object_add(user_obj, "ip", json_object_new_string(dev->ip));
      
    }

    if (flag > 1){
        json_object_object_add(user_obj, "hostname", json_object_new_string(dev->hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(dev->nickname));
        json_object_object_add(user_obj, "is_whitelist", json_object_new_int(dev->is_whitelist));
        json_object_object_add(user_obj, "is_selected", json_object_new_int(dev->is_selected));
    }

    if (flag > 2){
        struct json_object *app_array = json_object_new_array();
        app_visit_time_info_t top5_app_list[5];
        memset(top5_app_list, 0x0, sizeof(top5_app_list));
        update_top5_app(dev, top5_app_list);
        for (i = 0; i < 5; i++)
        {
            if (top5_app_list[i].app_id == 0 || strlen(get_app_name_by_id(top5_app_list[i].app_id)) == 0)
                break;

            struct json_object *app_obj = json_object_new_object();
            json_object_object_add(app_obj, "id", json_object_new_int(top5_app_list[i].app_id));

            if (check_app_icon_exist(top5_app_list[i].app_id)) {
                json_object_object_add(app_obj, "icon", json_object_new_int(1));
            }
            else
                json_object_object_add(app_obj, "icon", json_object_new_int(0));

            
            json_object_object_add(app_obj, "name", json_object_new_string(get_app_name_by_id(top5_app_list[i].app_id)));

            json_object_array_add(app_array, app_obj);
        }
        json_object_object_add(user_obj, "applist", app_array);

        if (strlen(dev->visiting_url) > 0)
            json_object_object_add(user_obj, "url", json_object_new_string(dev->visiting_url));
        else
            json_object_object_add(user_obj, "url", json_object_new_string(""));
        if (dev->visiting_app > 0 && strlen(get_app_name_by_id(dev->visiting_app)) > 0)
            json_object_object_add(user_obj, "app", json_object_new_string(get_app_name_by_id(dev->visiting_app)));
        else
            json_object_object_add(user_obj, "app", json_object_new_string(""));
        
        json_object_object_add(user_obj, "up_rate", json_object_new_int(dev->up_rate / 1024));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(dev->down_rate / 1024));
		u_int32_t up_flow = (u_int32_t)(dev->today_up_bytes / 1024);
		u_int32_t down_flow = (u_int32_t)(dev->today_down_bytes / 1024);
        json_object_object_add(user_obj, "up_rate", json_object_new_int(dev->up_rate / 1024));
        json_object_object_add(user_obj, "down_rate", json_object_new_int(dev->down_rate / 1024));
        json_object_object_add(user_obj, "today_up_flow", json_object_new_int(up_flow));
        json_object_object_add(user_obj, "today_down_flow", json_object_new_int(down_flow));
    }
    json_object_array_add(users_array, user_obj);
}

int compare_users(const void *a, const void *b)
{
    struct json_object *user_a = *(struct json_object **)a;
    struct json_object *user_b = *(struct json_object **)b;

    struct json_object *online_a, *online_b;
    json_object_object_get_ex(user_a, "online", &online_a);
    json_object_object_get_ex(user_b, "online", &online_b);

    int online_val_a = json_object_get_int(online_a);
    int online_val_b = json_object_get_int(online_b);

    if (online_val_a != online_val_b)
        return online_val_b - online_val_a;

    struct json_object *online_time_a, *online_time_b;
    json_object_object_get_ex(user_a, "online_time", &online_time_a);
    json_object_object_get_ex(user_b, "online_time", &online_time_b);

    int online_time_val_a = json_object_get_int(online_time_a);
    int online_time_val_b = json_object_get_int(online_time_b);

    if (online_val_a == 1 && online_val_b == 1) {
        // Both are online, sort by online_time
        return online_time_val_a - online_time_val_b;
    } else {
        // Both are offline, sort by offline_time
        struct json_object *offline_time_a, *offline_time_b;
        json_object_object_get_ex(user_a, "offline_time", &offline_time_a);
        json_object_object_get_ex(user_b, "offline_time", &offline_time_b);

        int offline_time_val_a = json_object_get_int(offline_time_a);
        int offline_time_val_b = json_object_get_int(offline_time_b);

        return offline_time_val_a - offline_time_val_b;
    }
}

static int handle_get_all_users(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    int flag = 0;
    int page = 0;
    int page_size = 20; // Default page size
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(response);
        json_object_put(data_obj);
        return 0;
    }

    char *msg_obj_str = blobmsg_format_json(msg, true);
    struct json_object *req_obj = NULL;
    if (msg_obj_str)
    {
        req_obj = json_tokener_parse(msg_obj_str);
        struct json_object *flag_obj = json_object_object_get(req_obj, "flag");
        struct json_object *page_obj = json_object_object_get(req_obj, "page");
        struct json_object *page_size_obj = json_object_object_get(req_obj, "page_size");
        if (flag_obj) {
            flag = json_object_get_int(flag_obj);
        }
        if (page_obj) {
            page = json_object_get_int(page_obj);
        }
        if (page_size_obj) {
            page_size = json_object_get_int(page_size_obj);
            if (page_size <= 0) {
                page_size = 20; // Default to 20 if invalid
            }
        }
    }

    printf("flag: %d, page: %d, page_size: %d\n", flag, page, page_size);
    all_users_info_t au_info;
    au_info.flag = flag;
    au_info.users_array = json_object_new_array();

    update_dev_nickname();
    update_dev_visiting_info();
    update_dev_whitelist_flag();
    dev_foreach(&au_info, all_users_callback);
    
    json_object_array_sort(au_info.users_array, compare_users);

    int total_count = json_object_array_length(au_info.users_array);
    
    struct json_object *paged_array = NULL;
    if (page == 0) {
        paged_array = au_info.users_array;
        json_object_get(au_info.users_array); // Increment reference count to prevent double free
    } else {
        paged_array = json_object_new_array();
        int start_idx = (page - 1) * page_size;
        int end_idx = start_idx + page_size;
        int i;
        for (i = start_idx; i < end_idx && i < total_count; i++) {
            struct json_object *user_obj = json_object_array_get_idx(au_info.users_array, i);
            if (user_obj) {
                json_object_get(user_obj); // Increment reference count
                json_object_array_add(paged_array, user_obj);
            }
        }
    }

    json_object_object_add(data_obj, "list", paged_array);
    json_object_object_add(data_obj, "total", json_object_new_int(total_count));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    
    // Calculate total pages
    int total_pages = 0;
    if (page_size > 0) {
        total_pages = (total_count + page_size - 1) / page_size; // Ceiling division
    }
    json_object_object_add(data_obj, "total_pages", json_object_new_int(total_pages));

    json_object_object_add(response, "data", data_obj);
    
    if (req_obj) {
        json_object_put(req_obj);
    }
    if (msg_obj_str) {
        free(msg_obj_str);
    }
    uci_free_context(uci_ctx);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}


static int handle_get_app_filter_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(response);
        json_object_put(data_obj);
        return 0;
    }

    int mode = af_uci_get_int_value(uci_ctx, "appfilter.global.user_mode");
    if (mode < 0)
        mode = 0;
    json_object_object_add(data_obj, "mode", json_object_new_int(mode));

    struct json_object *user_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = af_get_uci_list_num(uci_ctx, "appfilter", "af_user");
    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "appfilter.@af_user[%d].mac", i, mac_str, sizeof(mac_str));
        
        struct json_object *user_obj = json_object_new_object();
        json_object_object_add(user_obj, "mac", json_object_new_string(mac_str));
        dev_node_t *dev = find_dev_node(mac_str);
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


static int handle_set_app_filter_user(struct ubus_context *ctx, struct ubus_object *obj,
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
    struct json_object *mode_object = json_object_object_get(req_obj, "mode");
    if (!mode_object) {
        printf("mode_object is NULL\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    printf("mode_object: %d\n", json_object_get_int(mode_object));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }

    af_uci_set_int_value(uci_ctx, "appfilter.global.user_mode", json_object_get_int(mode_object));
    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    if (g_enable_agent) {
        af_forward_msg_to_agent("set_app_filter_user", msg_obj_str, strlen(msg_obj_str));
    }

    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}




static int handle_del_app_filter_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    printf("handle_del_app_filter_user\n");
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
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    printf("mac: %s\n", json_object_get_string(mac_obj));

 

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    char mac_str[128] = {0};
       int num = af_get_uci_list_num(uci_ctx, "appfilter", "af_user");
    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "appfilter.@af_user[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            printf("delete af_user[%d]\n", i);

            char buf[128] = {0};
            sprintf(buf, "appfilter.@af_user[%d]", i);
            af_uci_delete(uci_ctx, buf);
            break;
        }
    }

    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    if (g_enable_agent) {
        af_forward_msg_to_agent("del_app_filter_user", msg_obj_str, strlen(msg_obj_str));
    }

    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}




static int handle_add_app_filter_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    printf("handle_add_app_filter_user\n");
    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        json_object_put(response);
        return -1;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    if (!req_obj) {
        printf("parse json failed\n");
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    struct json_object *mac_array = json_object_object_get(req_obj, "mac_list");
    if (!mac_array) {
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }

    int len = json_object_array_length(mac_array);
    printf("len: %d\n", len);
    for (int i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
        af_uci_add_section(uci_ctx, "appfilter", "af_user");
        af_uci_set_value(uci_ctx, "appfilter.@af_user[-1].mac", json_object_get_string(mac_obj));
    }
    printf("add af_user ok\n");
    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    if (g_enable_agent) {
        af_forward_msg_to_agent("add_app_filter_user", msg_obj_str, strlen(msg_obj_str));
    }
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}

static int handle_set_nickname(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {

    struct json_object *response = json_object_new_object();
    int i;
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        json_object_put(response);
        return -1;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    if (!req_obj) {
        printf("parse json failed\n");
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
   
    struct json_object *nickname_obj = json_object_object_get(req_obj, "nickname");
    if (!nickname_obj || !mac_obj) {
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    int num = af_get_uci_list_num(uci_ctx, "user_info", "user_info");
    char mac_str[128] = {0};
    int index = -1;
    for (i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            index = i;
            printf("found nickname index: %d\n", index);
            break;
        }
    }

    if (strlen(json_object_get_string(nickname_obj)) > 0) {
        if (index == -1) {
            af_uci_add_section(uci_ctx, "user_info", "user_info");
        }
        af_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].mac", index, json_object_get_string(mac_obj));
        af_uci_set_array_value(uci_ctx, "user_info.@user_info[%d].nickname", index, json_object_get_string(nickname_obj));
    }
    else{
        char uci_option[128] = {0};
        sprintf(uci_option, "user_info.@user_info[%d]", index);
        af_uci_delete(uci_ctx, uci_option);
        printf("delete nickname mac = %s\n", json_object_get_string(mac_obj));
    }

  
    af_uci_commit(uci_ctx, "user_info");
    reload_oaf_rule();
    if (g_enable_agent) {
        af_forward_msg_to_agent("set_nickname", msg_obj_str, strlen(msg_obj_str));
    }
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}

extern af_run_time_status_t g_af_status;


static int handle_get_oaf_status(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    char result[128] = {0};
    char kernel_version[128] = {0};
    int enable = 0;
    int ret = 0;
    int engine_status = 0;
    struct uci_context *uci_ctx = uci_alloc_context();

    ret = af_read_file_value("/proc/sys/oaf/enable", result, sizeof(result));
    if (ret !=0 || strlen(result) == 0){
        engine_status = 0;
        enable = 0;
    }
    else{
        enable = atoi(result);
        engine_status = 1;
    }
 
    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "version", json_object_new_string(OAF_VERSION));

    json_object_object_add(data_obj, "engine_status", json_object_new_int(engine_status));

    // Read disable_hnat configuration
    if (uci_ctx) {
        int disable_hnat = af_uci_get_int_value(uci_ctx, "appfilter.global.disable_hnat");
        json_object_object_add(data_obj, "disable_hnat", json_object_new_int(disable_hnat));
        uci_free_context(uci_ctx);
    } else {
        json_object_object_add(data_obj, "disable_hnat", json_object_new_int(0));
    }

    ret = exec_with_result_line("cat /proc/sys/oaf/version", kernel_version, sizeof(kernel_version));
    if (ret >= 0){
        json_object_object_add(data_obj, "engine_version", json_object_new_string(kernel_version));
    }
    else{
        json_object_object_add(data_obj, "engine_version", json_object_new_string(""));
    }

    ret = exec_with_result_line("uname -r", kernel_version, sizeof(kernel_version));
    if (ret >= 0){
        json_object_object_add(data_obj, "kernel_version", json_object_new_string(kernel_version));
    }   
    else{
        json_object_object_add(data_obj, "kernel_version", json_object_new_string(""));
    }


    json_object_object_add(data_obj, "config_enable", json_object_new_int(g_af_config.global.enable));
    json_object_object_add(data_obj, "time_mode", json_object_new_int(g_af_config.time.time_mode));
    json_object_object_add(data_obj, "match_time", json_object_new_int(g_af_status.match_time));

    if (g_af_config.time.time_mode == 1) {
        json_object_object_add(data_obj, "filter", json_object_new_int(g_af_status.filter));
        if (g_af_status.filter == 1) {
            json_object_object_add(data_obj, "remain_time", json_object_new_int(g_af_config.time.deny_time - g_af_status.deny_time));
        }
        else {
            json_object_object_add(data_obj, "remain_time", json_object_new_int(g_af_config.time.allow_time - g_af_status.allow_time));
        }
    } else if (g_af_config.time.time_mode == 2) {
        json_object_object_add(data_obj, "remain_time", json_object_new_int(g_af_status.remain_time));
        json_object_object_add(data_obj, "used_time", json_object_new_int(g_af_status.used_time));
        json_object_object_add(data_obj, "period_blocked", json_object_new_int(g_af_status.period_blocked));
        
        time_t now = time(NULL);
        struct tm *current_time = localtime(&now);
        int current_weekday = current_time->tm_wday;
        int current_hour = current_time->tm_hour;
        
        json_object_object_add(data_obj, "current_weekday", json_object_new_int(current_weekday));
        
        daily_limit_config_t *daily_limit = &g_af_config.time.daily_limit[current_weekday];
        if (daily_limit->enable) {
            if (current_hour < 12) {
                json_object_object_add(data_obj, "am_time_limit", json_object_new_int(daily_limit->am_time));
                json_object_object_add(data_obj, "pm_time_limit", json_object_new_int(daily_limit->pm_time));
            } else {
                json_object_object_add(data_obj, "am_time_limit", json_object_new_int(daily_limit->am_time));
                json_object_object_add(data_obj, "pm_time_limit", json_object_new_int(daily_limit->pm_time));
            }
        } else {
            json_object_object_add(data_obj, "am_time_limit", json_object_new_int(0));
            json_object_object_add(data_obj, "pm_time_limit", json_object_new_int(0));
        }
        

        int total_am_time = 0;
        int total_pm_time = 0;
        int selected_user_count = 0;
        int i;
        for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++) {
            dev_node_t *node = dev_hash_table[i];
            while (node) {
                if (node->is_selected) {
                    total_am_time += node->today_am_active_time;
                    total_pm_time += node->today_pm_active_time;
                    if (node->online) {
                        selected_user_count++;
                    }
                }
                node = node->next;
            }
        }
        
        json_object_object_add(data_obj, "current_am_used_time", json_object_new_int(total_am_time));
        json_object_object_add(data_obj, "current_pm_used_time", json_object_new_int(total_pm_time));
        json_object_object_add(data_obj, "selected_user_count", json_object_new_int(selected_user_count));
        json_object_object_add(data_obj, "current_am_limit", json_object_new_int(daily_limit->am_time));
        json_object_object_add(data_obj, "current_pm_limit", json_object_new_int(daily_limit->pm_time));
        json_object_object_add(data_obj, "current_day_enabled", json_object_new_int(daily_limit->enable));
    }


    json_object_object_add(response, "data", data_obj);
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;

}

static int handle_get_whitelist_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(response);
        json_object_put(data_obj);
        return 0;
    }

    struct json_object *user_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str, sizeof(mac_str));
        struct json_object *user_obj = json_object_new_object();
        json_object_object_add(user_obj, "mac", json_object_new_string(mac_str));
        dev_node_t *dev = find_dev_node(mac_str);
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
        json_object_put(response);
        return -1;
    }
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    if (!req_obj) {
        printf("parse json failed\n");
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }
    struct json_object *mac_array = json_object_object_get(req_obj, "mac_list");
    if (!mac_array) {
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }


    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return -1;
    }

    int len = json_object_array_length(mac_array);
    for (int i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
        af_uci_add_section(uci_ctx, "appfilter", "whitelist");
        af_uci_set_value(uci_ctx, "appfilter.@whitelist[-1].mac", json_object_get_string(mac_obj));
    }
    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();

    if (g_enable_agent) {
        af_forward_msg_to_agent("add_whitelist_user", msg_obj_str, strlen(msg_obj_str));
    }
    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}

					
static int handle_service_config(struct ubus_context *ctx, struct ubus_object *obj,
					struct ubus_request_data *req, const char *method,
					struct blob_attr *msg) 
{
	struct json_object *response = json_object_new_object();
	int i;
	char *msg_obj_str = blobmsg_format_json(msg, true);
	if (!msg_obj_str) {
		printf("format json failed\n");
		json_object_put(response);
		return -1;
	}
	struct json_object *req_obj = json_tokener_parse(msg_obj_str);
	if (!req_obj) {
		printf("parse json failed\n");
		free(msg_obj_str);
		json_object_put(response);
		return -1;
	}
	struct json_object *agent_enable_obj = json_object_object_get(req_obj, "agent_enable");
	if (!agent_enable_obj) {
		json_object_put(req_obj);
		free(msg_obj_str);
		json_object_put(response);
		return -1;
	}

	g_enable_agent = json_object_get_int(agent_enable_obj);

    printf("g_enable_agent: %d\n", g_enable_agent);

	json_object_put(req_obj);
	free(msg_obj_str);
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
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    char mac_str[128] = {0};
    int num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            char buf[128] = {0};
            sprintf(buf, "appfilter.@whitelist[%d]", i);
            af_uci_delete(uci_ctx, buf);
            break;
        }
    }

    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();

    if (g_enable_agent) {
        af_forward_msg_to_agent("del_whitelist_user", msg_obj_str, strlen(msg_obj_str));
    }

    uci_free_context(uci_ctx);
    json_object_put(req_obj);
    free(msg_obj_str);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    json_object_put(response);
    return 0;
}



static int handle_cmd(struct ubus_context *ctx, struct ubus_object *obj,
                      struct ubus_request_data *req, const char *method,
                      struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (!msg_obj_str) {
        printf("format json failed\n");
        json_object_put(response);
        return 0;
    }
    printf("handle_cmd: msg_obj_str: %s\n", msg_obj_str);
    
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    if (!req_obj) {
        printf("parse json failed\n");
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    
    struct json_object *action_obj = json_object_object_get(req_obj, "action");
    if (!action_obj) {
        printf("action is NULL\n");
        json_object_put(req_obj);
        free(msg_obj_str);
        json_object_put(response);
        return 0;
    }
    
    const char *action = json_object_get_string(action_obj);
    printf("handle_cmd: action = %s\n", action);
    
    int ret = 0;
    const char *result_msg = NULL;
    
    if (strcmp(action, "clear_active_time") == 0) {
        // Clear all users' today active time (AM and PM)
        reset_all_users_today_active_time();
        result_msg = "Successfully cleared all users' active time";
        ret = 0;
        printf("handle_cmd: cleared all users' active time\n");
    } else if (strcmp(action, "clear_offline_users") == 0) {
        // Clear all offline users
        flush_offline_users();
        result_msg = "Successfully cleared all offline users";
        ret = 0;
        printf("handle_cmd: cleared all offline users\n");
    } else {
        result_msg = "Unknown action";
        ret = -1;
        printf("handle_cmd: unknown action: %s\n", action);
    }
    
    json_object_object_add(response, "code", json_object_new_int(ret));
    json_object_object_add(response, "message", json_object_new_string(result_msg));
    
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    json_object_put(req_obj);
    free(msg_obj_str);
    json_object_put(response);
    return 0;
}

static const struct blobmsg_policy empty_policy[1] = {
    //[DEV_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

static struct ubus_method appfilter_object_methods[] = {
    UBUS_METHOD("dev_visit_list", appfilter_handle_dev_visit_list, empty_policy),
    UBUS_METHOD("dev_visit_time", appfilter_handle_visit_time, empty_policy),
    UBUS_METHOD("app_class_visit_time", handle_app_class_visit_time, empty_policy),
    UBUS_METHOD("dev_list", appfilter_handle_dev_list, empty_policy),
    UBUS_METHOD("class_list", handle_get_class_list, empty_policy),
    UBUS_METHOD("set_app_filter", handle_set_app_filter, empty_policy),
    UBUS_METHOD("get_app_filter", handle_get_app_filter, empty_policy),
    UBUS_METHOD("set_app_filter_base", handle_set_app_filter_base, empty_policy),
    UBUS_METHOD("get_app_filter_base", handle_get_app_filter_base, empty_policy),
    UBUS_METHOD("set_app_filter_adv", handle_set_app_filter_adv, empty_policy),
    UBUS_METHOD("get_app_filter_adv", handle_get_app_filter_adv, empty_policy),
    UBUS_METHOD("set_app_filter_time", handle_set_app_filter_time, empty_policy),
    UBUS_METHOD("get_app_filter_time", handle_get_app_filter_time, empty_policy),
    UBUS_METHOD("get_all_users", handle_get_all_users, empty_policy),
    UBUS_METHOD("get_app_filter_user", handle_get_app_filter_user, empty_policy),
    UBUS_METHOD("set_app_filter_user", handle_set_app_filter_user, empty_policy),
    UBUS_METHOD("del_app_filter_user", handle_del_app_filter_user, empty_policy),
    UBUS_METHOD("add_app_filter_user", handle_add_app_filter_user, empty_policy),
    UBUS_METHOD("set_nickname", handle_set_nickname, empty_policy),
    UBUS_METHOD("get_oaf_status", handle_get_oaf_status, empty_policy),
    UBUS_METHOD("debug", handle_debug, empty_policy),
    UBUS_METHOD("get_whitelist_user", handle_get_whitelist_user, empty_policy),
    UBUS_METHOD("add_whitelist_user", handle_add_whitelist_user, empty_policy),
    UBUS_METHOD("del_whitelist_user", handle_del_whitelist_user, empty_policy),
    UBUS_METHOD("service_config", handle_service_config, empty_policy),
    UBUS_METHOD("cmd", handle_cmd, empty_policy),
};




static struct ubus_object_type main_object_type =
    UBUS_OBJECT_TYPE("appfilter", appfilter_object_methods);

static struct ubus_object main_object = {
    .name = "appfilter",
    .type = &main_object_type,
    .methods = appfilter_object_methods,
    .n_methods = ARRAY_SIZE(appfilter_object_methods),
};

static void appfilter_add_object(struct ubus_object *obj)
{
    ubus_add_object(ubus_ctx, obj);
}

int appfilter_ubus_init(void)
{
	ubus_ctx = ubus_connect("/var/run/ubus/ubus.sock");
    if (!ubus_ctx){
		ubus_ctx = ubus_connect("/var/run/ubus.sock");
	}
	if (!ubus_ctx){
		return -EIO;
	}

    appfilter_add_object(&main_object);
    ubus_add_uloop(ubus_ctx);
    return 0;
}
