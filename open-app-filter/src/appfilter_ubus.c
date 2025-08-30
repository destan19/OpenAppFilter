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
        return 0;
    }

    char *mac = json_object_get_string(mac_obj);
    dev_node_t *node = find_dev_node(mac);

    if (!node)
    {
        printf("not found mac:%s\n", mac);
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

    // Sort the visit_array based on the "lt" field
    json_object_array_sort(visit_array, compare_lt);

    json_object_object_add(root_obj, "total_num", json_object_new_int(json_object_array_length(visit_array)));
    json_object_object_add(root_obj, "list", visit_array);
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
    //memset(app_array, 0x0, sizeof(int) *size);
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
        //printf("appid %d-----------total time %llu\n", app_visit_array[i].app_id,
        //	app_visit_array[i].total_time);
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
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto END;
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
        // Remove newline character
        line[strcspn(line, "\n")] = 0;

        if (strncmp(line, "#class", 6) == 0) {
            // New class definition
            if (current_class) {
                // Add the previous class to the class list
                json_object_object_add(current_class, "app_list", app_list);
                json_object_array_add(class_list, current_class);
            }

            // Parse class name
            char *name = strtok(line + 7, " ");
            char *class_name = NULL;
            while (name != NULL) {
                class_name = name;  // Keep updating class_name until the last token
                name = strtok(NULL, " ");
            }
            current_class = json_object_new_object();
            json_object_object_add(current_class, "name", json_object_new_string(class_name));
            app_list = json_object_new_array();
        } else if (current_class) {
            // Parse app definition
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
                int with_icon = access(icon_path, F_OK) == 0 ? 1 : 0; // 检查文件是否存在
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
        return 0;
    }
    printf("app_list: %s\n", json_object_get_string(app_list));

    // 新增代码：将 app_list_str 存储到 UCI 配置中
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
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
    enable = af_uci_get_int_value(uci_ctx, "appfilter.global.enable");
    work_mode = af_uci_get_int_value(uci_ctx, "appfilter.global.work_mode");
    record_enable = af_uci_get_int_value(uci_ctx, "appfilter.global.record_enable");


    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));
    json_object_object_add(data_obj, "record_enable", json_object_new_int(record_enable));


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
    if (!enable_obj || !work_mode_obj) {
        printf("enable_obj or work_mode_obj is NULL\n");
        return 0;
    }
    printf("enable_obj: %d\n", json_object_get_int(enable_obj));
    printf("work_mode_obj: %d\n", json_object_get_int(work_mode_obj));


    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    af_uci_set_int_value(uci_ctx, "appfilter.global.enable", json_object_get_int(enable_obj));
    af_uci_set_int_value(uci_ctx, "appfilter.global.work_mode", json_object_get_int(work_mode_obj));
    
    if (record_enable_obj)
        af_uci_set_int_value(uci_ctx, "appfilter.global.record_enable", json_object_get_int(record_enable_obj));
    else
        af_uci_set_int_value(uci_ctx, "appfilter.global.record_enable", 0);


    af_uci_commit(uci_ctx, "appfilter");
    reload_oaf_rule();
    g_oaf_config_change = 1;
    uci_free_context(uci_ctx);
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
    uci_free_context(uci_ctx);
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

    // Get time_mode
    int time_mode = af_uci_get_int_value(uci_ctx, "appfilter.time.time_mode");
    json_object_object_add(data_obj, "mode", json_object_new_int(time_mode));

    // Get days
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
    char time_str[512] = {0};
    af_uci_get_list_value(uci_ctx, "appfilter.time.time", time_str, sizeof(time_str), " ");
    struct json_object *time_array = json_object_new_array();
    char *time_period = strtok(time_str, " ");
    while (time_period) {
        char start[16] = {0};
        char end[16] = {0};
        char *delimiter = strchr(time_period, '-');
        if (delimiter) {
            // Copy start_time (characters before '-')
            strncpy(start, time_period, delimiter - time_period);
            start[delimiter - time_period] = '\0';
            
            // Copy end_time (characters after '-')
            strcpy(end, delimiter + 1);

            // Create time period object
            struct json_object *period_obj = json_object_new_object();
            json_object_object_add(period_obj, "start", json_object_new_string(start));
            json_object_object_add(period_obj, "end", json_object_new_string(end));
            json_object_array_add(time_array, period_obj);
        }
        time_period = strtok(NULL, " ");
    }
    json_object_object_add(data_obj, "time_list", time_array);

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
    struct json_object *weekday_list_obj = json_object_object_get(req_obj, "weekday_list");
    if (!mode_obj || !weekday_list_obj) {
        printf("mode_obj or weekday_list_obj is NULL\n");
        return 0;
    }
    printf("mode_obj: %d\n", json_object_get_int(mode_obj));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    mode = json_object_get_int(mode_obj);
    af_uci_set_int_value(uci_ctx, "appfilter.time.time_mode", mode);

    // Build days string from weekday array
    char days_str[128] = {0};
    for (i = 0; i < json_object_array_length(weekday_list_obj); i++) {
        struct json_object *weekday_obj = json_object_array_get_idx(weekday_list_obj, i);
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%d", json_object_get_int(weekday_obj));
        if (i > 0) strcat(days_str, " ");
        strcat(days_str, tmp);
    }
    af_uci_set_value(uci_ctx, "appfilter.time.days", days_str);

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
            char time_str[128] = {0};
            sprintf(time_str, "%s-%s", json_object_get_string(start_time_obj), json_object_get_string(end_time_obj));
            printf("time_str: %s\n", time_str);
            af_uci_add_list(uci_ctx, "appfilter.time.time", time_str);
        }
    }
    else  {
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
    af_uci_commit(uci_ctx, "appfilter");
    g_oaf_config_change = 1;
    printf("uci commit ok\n");
  //  reload_oaf_rule();
EXIT:
    uci_free_context(uci_ctx);
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

    if (json_object_array_length(users_array) >= MAX_SUPPORT_DEV_NUM)
    {
        printf("users_array length >= MAX_SUPPORT_DEV_NUM\n");
        return;
    }

    struct json_object *user_obj = json_object_new_object();
    json_object_object_add(user_obj, "mac", json_object_new_string(dev->mac));
    json_object_object_add(user_obj, "online", json_object_new_int(dev->online));
    json_object_object_add(user_obj, "online_time", json_object_new_int(dev->online_time));
    json_object_object_add(user_obj, "offline_time", json_object_new_int(dev->offline_time));

    if (flag > 0) {
        json_object_object_add(user_obj, "ip", json_object_new_string(dev->ip));
      
    }

    if (flag > 1){
        json_object_object_add(user_obj, "hostname", json_object_new_string(dev->hostname));
        json_object_object_add(user_obj, "nickname", json_object_new_string(dev->nickname));
        json_object_object_add(user_obj, "is_whitelist", json_object_new_int(dev->is_whitelist));
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
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    char *msg_obj_str = blobmsg_format_json(msg, true);
    if (msg_obj_str)
    {
        struct json_object *req_obj = json_tokener_parse(msg_obj_str);
        struct json_object *flag_obj = json_object_object_get(req_obj, "flag");
        struct json_object *page_obj = json_object_object_get(req_obj, "page");
        if (flag_obj) {
            flag = json_object_get_int(flag_obj);
        }
        if (page_obj) {
            page = json_object_get_int(page_obj);
        }
    }

    printf("flag: %d, page: %d\n", flag, page);
    all_users_info_t au_info;
    au_info.flag = flag;
    au_info.users_array = json_object_new_array();

    struct json_object *users_array = json_object_new_array();

    update_dev_nickname();
    update_dev_visiting_info();
    update_dev_whitelist_flag();
    dev_foreach(&au_info, all_users_callback);
    
    // 对 users_array 进行排序
    json_object_array_sort(au_info.users_array, compare_users);

    json_object_object_add(data_obj, "list", au_info.users_array);

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


static int handle_get_app_filter_user(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
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
        return 0;
    }
    printf("mode_object: %d\n", json_object_get_int(mode_object));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }

    af_uci_set_int_value(uci_ctx, "appfilter.global.user_mode", json_object_get_int(mode_object));
    af_uci_commit(uci_ctx, "appfilter");
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
        return 0;
    }
    printf("mac: %s\n", json_object_get_string(mac_obj));

 

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
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

    uci_free_context(uci_ctx);
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
        return -1;
    }
    printf("msg_obj_str: %s\n", msg_obj_str);
    struct json_object *req_obj = json_tokener_parse(msg_obj_str);
    struct json_object *mac_array = json_object_object_get(req_obj, "mac_list");
    if (!mac_array)
        return -1;
    
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
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

    uci_free_context(uci_ctx);
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

    uci_free_context(uci_ctx);
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
        if (g_af_status.filter == 1) { // 过滤中
            json_object_object_add(data_obj, "remain_time", json_object_new_int(g_af_config.time.deny_time - g_af_status.deny_time));
        }
        else {
            json_object_object_add(data_obj, "remain_time", json_object_new_int(g_af_config.time.allow_time - g_af_status.allow_time));
        }
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
    for (int i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
        af_uci_add_section(uci_ctx, "appfilter", "whitelist");
        af_uci_set_value(uci_ctx, "appfilter.@whitelist[-1].mac", json_object_get_string(mac_obj));
    }
    af_uci_commit(uci_ctx, "appfilter");
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

    uci_free_context(uci_ctx);
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    blobmsg_add_object(&b, response);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
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
    int ret = ubus_add_object(ubus_ctx, obj);

    if (ret != 0)
        fprintf(stderr, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
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
