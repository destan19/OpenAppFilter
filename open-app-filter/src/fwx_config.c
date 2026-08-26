
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "fwx_config.h"
#include "fwx.h"
#include "fwx_feature.h"
#include <uci.h>

app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
int g_app_count = 0;
static int g_base_app_count = 0;
int g_cur_class_num = 0;
char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

static char *trim_space(char *text)
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

static int parse_feature_app_header(const char *line, int *app_id, char *app_name, size_t app_name_len)
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

    id_text = trim_space(header);
    name_text = trim_space(slash + 1);
    if (!id_text || !id_text[0] || !name_text || !name_text[0])
        return -1;

    id = strtol(id_text, &endptr, 10);
    endptr = trim_space(endptr);
    if (id <= 0 || (endptr && endptr[0] != '\0'))
        return -1;

    *app_id = (int)id;
    strncpy(app_name, name_text, app_name_len - 1);
    app_name[app_name_len - 1] = '\0';
    return 0;
}

int app_icon_exists_by_id(int id)
{
    char icon_path[256];

    if (id <= 0)
        return 0;

    snprintf(icon_path, sizeof(icon_path),
             "/www/luci-static/resources/oaf/app_icons/%d.png", id);
    return access(icon_path, F_OK) == 0;
}

char *get_app_name_by_id(int id)
{
    int i;
    static char fallback_name[32];

    for (i = 0; i < g_app_count; i++)
    {
        if (id == app_name_table[i].id)
            return app_name_table[i].name;
    }
    if (id > 0) {
        snprintf(fallback_name, sizeof(fallback_name), "App%d", id);
        return fallback_name;
    }
    return "";
}

int add_app_name_to_table(int id, const char *name)
{
    if (!name || !name[0] || g_app_count >= MAX_SUPPORT_APP_NUM)
        return -1;
    app_name_table[g_app_count].id = id;
    strncpy(app_name_table[g_app_count].name, name,
            sizeof(app_name_table[g_app_count].name) - 1);
    app_name_table[g_app_count].name[sizeof(app_name_table[g_app_count].name) - 1] = '\0';
    g_app_count++;
    return 0;
}

int get_base_app_count(void)
{
    return g_base_app_count;
}

void init_app_name_table(void)
{
    char line_buf[2048] = {0};
    const char *feature_data;
    size_t feature_len = 0;
    size_t offset = 0;

    feature_data = fwx_feature_get_data(&feature_len);
    if (!feature_data)
        return;
    memset(app_name_table, 0, sizeof(app_name_table));
    g_app_count = 0;
    while (fwx_feature_next_line(feature_data, feature_len, &offset,
                                 line_buf, sizeof(line_buf)) != 0) {
        int app_id = 0;
        char app_name[64] = {0};

        if (strstr(line_buf, "#"))
            continue;
        if (strlen(line_buf) < 10)
            continue;
        if (parse_feature_app_header(line_buf, &app_id, app_name, sizeof(app_name)) < 0)
            continue;
        if (g_app_count >= MAX_SUPPORT_APP_NUM)
            break;
        app_name_table[g_app_count].id = app_id;
        strncpy(app_name_table[g_app_count].name, app_name,
                sizeof(app_name_table[g_app_count].name) - 1);
        g_app_count++;
    }
    g_base_app_count = g_app_count;
}

void init_app_class_name_table(void)
{
    char line_buf[2048] = {0};
    const char *feature_data;
    size_t feature_len = 0;
    size_t offset = 0;

    feature_data = fwx_feature_get_data(&feature_len);
    if (!feature_data)
        return;
    memset(CLASS_NAME_TABLE, 0, sizeof(CLASS_NAME_TABLE));
    g_cur_class_num = 0;
    while (fwx_feature_next_line(feature_data, feature_len, &offset,
                                 line_buf, sizeof(line_buf)) != 0) {
        int class_id = 0;
        char class_name[MAX_CLASS_NAME_LEN] = {0};

        if (strncmp(line_buf, "#class ", 7) != 0)
            continue;
        if (sscanf(line_buf, "#class %*s %d %31s", &class_id, class_name) != 2 ||
            class_id < 1 || class_id > MAX_APP_TYPE)
            continue;
        strncpy(CLASS_NAME_TABLE[class_id - 1], class_name, MAX_CLASS_NAME_LEN - 1);
        if (class_id > g_cur_class_num)
            g_cur_class_num = class_id;
    }
}

int check_time_valid(char *t)
{
    if (!t)
        return 0;
    if (strlen(t) < 3 || strlen(t) > 5 || (!strstr(t, ":")))
        return 0;
    else
        return 1;
}


int config_get_appfilter_enable(void)
{
    int enable = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
	enable = fwx_uci_get_int_value(ctx, "appfilter.global.enable");
    if (enable < 0)
        enable = 0;
    
	uci_free_context(ctx);
    return enable;
}

int config_get_lan_ip(char *lan_ip, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = fwx_uci_get_value(ctx, "network.lan.ipaddr", lan_ip, len);
    uci_free_context(ctx);
    return ret;
}

int config_get_lan_mask(char *lan_mask, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = fwx_uci_get_value(ctx, "network.lan.netmask", lan_mask, len);
    uci_free_context(ctx);
    return ret;
}
