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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "appfilter_config.h"
#include <uci.h>

app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
int g_app_count = 0;
int g_cur_class_num = 0;
char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

const char *config_path = "./config";
static struct uci_context *uci_ctx = NULL;
static struct uci_package *uci_appfilter;


int uci_get_int_value(struct uci_context *ctx, char *key)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = -1;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
            ret = atoi(ptr.o->v.string);
			goto done;
        default:
            break;
    }
done:
	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int uci_get_value(struct uci_context *ctx, char *key, char *output, int out_len)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        ret = 1;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            snprintf(output, out_len, "%s", ptr.s->type);
            break;
        case UCI_TYPE_OPTION:
            snprintf(output, out_len, "%s", ptr.o->v.string);
			break;
        default:
			ret = 1;
            break;
    }
done:    
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

//
static struct uci_package *
config_init_package(const char *config)
{
    struct uci_context *ctx = uci_ctx;
    struct uci_package *p = NULL;

    if (!ctx)
    {
        ctx = uci_alloc_context();
        uci_ctx = ctx;
        ctx->flags &= ~UCI_FLAG_STRICT;
        //if (config_path)
        //	uci_set_confdir(ctx, config_path);
    }
    else
    {
        p = uci_lookup_package(ctx, config);
        if (p)
            uci_unload(ctx, p);
    }

    if (uci_load(ctx, config, &p))
        return NULL;

    return p;
}
char *get_app_name_by_id(int id)
{
    int i;
    for (i = 0; i < g_app_count; i++)
    {
        if (id == app_name_table[i].id)
            return app_name_table[i].name;
    }
    return "";
}

void init_app_name_table(void)
{
    int count = 0;
    char line_buf[2048] = {0};

    FILE *fp = fopen("/tmp/feature.cfg", "r");
    if (!fp)
    {
        printf("open file failed\n");
        return;
    }

    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        if (strstr(line_buf, "#"))
            continue;
        if (strlen(line_buf) < 10)
            continue;
        if (!strstr(line_buf, ":"))
            continue;
        char *pos1 = strstr(line_buf, ":");
        char app_info_buf[128] = {0};
        int app_id;
        char app_name[64] = {0};
        memset(app_name, 0x0, sizeof(app_name));
        strncpy(app_info_buf, line_buf, pos1 - line_buf);
        sscanf(app_info_buf, "%d %s", &app_id, app_name);
        app_name_table[g_app_count].id = app_id;
        strcpy(app_name_table[g_app_count].name, app_name);
        g_app_count++;
    }
    fclose(fp);
}

void init_app_class_name_table(void)
{
    char line_buf[2048] = {0};
    int class_id;
    char class_name[64] = {0};
    FILE *fp = fopen("/tmp/app_class.txt", "r");
    if (!fp)
    {
        printf("open file failed\n");
        return;
    }
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        sscanf(line_buf, "%d %*s %s", &class_id, class_name);
        strcpy(CLASS_NAME_TABLE[class_id - 1], class_name);
        g_cur_class_num++;
    }
    fclose(fp);
}
//00:00 9:1
int check_time_valid(char *t)
{
    if (!t)
        return 0;
    if (strlen(t) < 3 || strlen(t) > 5 || (!strstr(t, ":")))
        return 0;
    else
        return 1;
}

void dump_af_time(af_ctl_time_t *t)
{
    int i;
    printf("---------dump af time-------------\n");
    printf("%d:%d ---->%d:%d\n", t->start.hour, t->start.min,
           t->end.hour, t->end.min);
    for (i = 0; i < 7; i++)
    {
        printf("%d ", t->days[i]);
    }
    printf("\n");
}

af_ctl_time_t *load_appfilter_ctl_time_config(void)
{
    char start_time_str[64] = {0};
    char end_time_str[64] = {0};
    char start_time_str2[64] = {0};
    char end_time_str2[64] = {0};
    char days_str[64] = {0};
    int value = 0;
    int ret = 0;
    af_ctl_time_t *t = NULL;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return NULL;

    memset(start_time_str, 0x0, sizeof(start_time_str));
    memset(end_time_str, 0x0, sizeof(end_time_str));
    memset(start_time_str2, 0x0, sizeof(start_time_str2));
    memset(end_time_str2, 0x0, sizeof(end_time_str2));

    uci_get_value(ctx, "appfilter.time.start_time", start_time_str, sizeof(start_time_str));
    uci_get_value(ctx, "appfilter.time.end_time", end_time_str, sizeof(end_time_str));
    uci_get_value(ctx, "appfilter.time.start_time2", start_time_str2, sizeof(start_time_str2));
    uci_get_value(ctx, "appfilter.time.end_time2", end_time_str2, sizeof(end_time_str2));
    uci_get_value(ctx, "appfilter.time.days", days_str, sizeof(days_str));


    t = malloc(sizeof(af_ctl_time_t));

    value = uci_get_int_value(ctx, "appfilter.time.time_mode");
    if (value < 0)
        t->time_mode = 0;
    else
        t->time_mode = value;
    if (check_time_valid(start_time_str) && check_time_valid(end_time_str)){
        sscanf(start_time_str, "%d:%d", &t->start.hour, &t->start.min);
        sscanf(end_time_str, "%d:%d", &t->end.hour, &t->end.min);
    }
    if (check_time_valid(start_time_str2) && check_time_valid(end_time_str2)){
        sscanf(start_time_str2, "%d:%d", &t->start2.hour, &t->start2.min);
        sscanf(end_time_str2, "%d:%d", &t->end2.hour, &t->end2.min);
    }

    char *p = strtok(days_str, " ");
    if (!p)
        goto EXIT;
    do
    {
        int day = atoi(p);
        if (day >= 0 && day <= 6)
            t->days[day] = 1;
        else
            ret = 0;
    } while (p = strtok(NULL, " "));
EXIT:
	uci_free_context(ctx);
    return t;
}



int config_get_appfilter_enable(void)
{
    int enable = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return NULL;
	enable = uci_get_int_value(ctx, "appfilter.global.enable");
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
    ret = uci_get_value(ctx, "network.lan.ipaddr", lan_ip, len);
    uci_free_context(ctx);
    return ret;
}

int config_get_lan_mask(char *lan_mask, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = uci_get_value(ctx, "network.lan.netmask", lan_mask, len);
    uci_free_context(ctx);
    return ret;
}


int appfilter_config_alloc(void)
{
    char *err;
    uci_appfilter = config_init_package("appfilter");
    if (!uci_appfilter)
    {
        uci_get_errorstr(uci_ctx, &err, NULL);
        printf("Failed to load appfilter config (%s)\n", err);
        free(err);
        return -1;
    }

    return 0;
}

int appfilter_config_free(void)
{
    if (uci_appfilter)
    {
        uci_unload(uci_ctx, uci_appfilter);
        uci_appfilter = NULL;
    }
    if (uci_ctx)
    {
        uci_free_context(uci_ctx);
        uci_ctx = NULL;
    }
}
