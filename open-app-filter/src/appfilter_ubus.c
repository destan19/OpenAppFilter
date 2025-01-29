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
            if (node->online == 0)
            {

                node = node->next;
                continue;
            }
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
                json_object_array_add(app_array, app_obj);
            }

            json_object_object_add(dev_obj, "applist", app_array);
            json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
            char hostname[128] = {0};
            get_hostname_by_mac(node->mac, hostname);
            json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));

            json_object_object_add(dev_obj, "online", json_object_new_int(1));
            json_object_object_add(dev_obj, "hostname", json_object_new_string(hostname));
            json_object_object_add(dev_obj, "latest_app", json_object_new_string("test"));
            json_object_array_add(dev_array, dev_obj);

            node = node->next;
            count++;
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto END;
        }
    }
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            if (node->online != 0)
            {

                node = node->next;
                continue;
            }
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
                json_object_array_add(app_array, app_obj);
            }

            json_object_object_add(dev_obj, "applist", app_array);
            json_object_object_add(dev_obj, "mac", json_object_new_string(node->mac));
            char hostname[32] = {0};
            get_hostname_by_mac(node->mac, hostname);
            json_object_object_add(dev_obj, "ip", json_object_new_string(node->ip));

            json_object_object_add(dev_obj, "online", json_object_new_int(0));
            json_object_object_add(dev_obj, "hostname", json_object_new_string(hostname));
            json_object_object_add(dev_obj, "latest_app", json_object_new_string("test"));
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

static int
appfilter_handle_visit_time(struct ubus_context *ctx, struct ubus_object *obj,
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
    json_object_object_add(resp_obj, "app_list", app_info_array);
    int i;
    for (i = 0; i < info.num; i++)
    {
        struct json_object *app_info_obj = json_object_new_object();
        json_object_object_add(app_info_obj, "app_id",
                               json_object_new_string(get_app_name_by_id(info.visit_list[i].app_id)));
        json_object_object_add(app_info_obj, "visit_time",
                               json_object_new_int(info.visit_list[i].total_time));
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

    char line[256];
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

static int handle_get_app_filter(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg) {
    struct json_object *response = json_object_new_object();
    struct json_object *app_list = json_object_new_array();
    int i;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        printf("Failed to allocate UCI context\n");
        return 0;
    }
    char app_filter_str[1024] = {0};
    app_filter_str[0] = '\0';
    af_uci_get_list_value(uci_ctx, "appfilter.rule.app_list", app_filter_str, sizeof(app_filter_str), " ");
    printf("app_filter_str: %s\n", app_filter_str);
    char *app_id_str = strtok(app_filter_str, " ");
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
    enable = uci_get_int_value(uci_ctx, "appfilter.global.enable");
    work_mode = uci_get_int_value(uci_ctx, "appfilter.global.work_mode");

    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));


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
    UBUS_METHOD("visit_list", appfilter_handle_visit_list, empty_policy),
    UBUS_METHOD("dev_visit_time", appfilter_handle_visit_time, empty_policy),
    UBUS_METHOD("app_class_visit_time", handle_app_class_visit_time, empty_policy),
    UBUS_METHOD("dev_list", appfilter_handle_dev_list, empty_policy),
    UBUS_METHOD("class_list", handle_get_class_list, empty_policy),
    UBUS_METHOD("set_app_filter", handle_set_app_filter, empty_policy),
    UBUS_METHOD("get_app_filter", handle_get_app_filter, empty_policy),

    UBUS_METHOD("set_app_filter_base", handle_set_app_filter_base, empty_policy),
    UBUS_METHOD("get_app_filter_base", handle_get_app_filter_base, empty_policy),
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
