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
#include "appfilter.h"
#include <uci.h>

app_name_info_t app_name_table[MAX_SUPPORT_APP_NUM];
int g_app_count = 0;
int g_cur_class_num = 0;
char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

const char *config_path = "./config";
static struct uci_context *uci_ctx = NULL;
static struct uci_package *uci_appfilter;


int af_uci_get_int_value(struct uci_context *ctx, char *key)
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


int af_uci_get_value(struct uci_context *ctx, char *key, char *output, int out_len)
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


int af_uci_delete(struct uci_context *ctx, char *key)
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
    ret = uci_delete(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}



int af_uci_add_list(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters;
    if (strlen(value) + strlen(key) >= MAX_PARAM_LIST_LEN  - 1) {
        printf("value too long\n");
        return -1;
    }
    char param_tmp[MAX_PARAM_LIST_LEN] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int af_uci_get_list_value(struct uci_context *ctx, char *key, char *output, int out_len, char *delimt)
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
    int sep = 0;
    e = ptr.last;
	int len = 0;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
			if (UCI_TYPE_LIST == ptr.o->type){
				memset(output, 0x0, out_len);
				uci_foreach_element(&ptr.o->v.list, e) {
					len = strlen(output);
					if (sep){
						strncat(output + len, delimt, out_len);
					}
					len = strlen(output);
					sprintf(output + len, "%s", e->name);
					sep = 1;
				}
				ret = 0;
			}
			goto done;
        default:
            break;
    }
done:	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int af_uci_add_int_list(struct uci_context *ctx, char *key, int value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%d", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int af_uci_del_list(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_del_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int af_uci_set_value(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[2048] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    e = ptr.last;
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int af_uci_set_int_value(struct uci_context *ctx, char *key, int value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%d", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    e = ptr.last;
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

    if (ptr.p)
        uci_unload(ctx, ptr.p);
    return ret;
}

int af_uci_del_array_value(struct uci_context *ctx, char *key_fmt, int index){
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return af_uci_delete(ctx, key);
}

int af_uci_set_array_value(struct uci_context *ctx, char *key_fmt, int index, char *value){
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return af_uci_set_value(ctx, key, value);
}

int af_uci_commit(struct uci_context *ctx, const char * package) {
    struct uci_ptr ptr;
    int ret = UCI_OK;
    if (!package){
        return -1;
    }
    if (uci_lookup_ptr(ctx, &ptr, package, true) != UCI_OK) {
        return -1;
    }   

    if (uci_commit(ctx, &ptr.p, false) != UCI_OK) {
    	ret = -1;
        goto done;
    }
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);

    return UCI_OK;
}

int af_get_uci_list_num(struct uci_context * ctx, char *package, char *section){
    int count = 0;
    struct uci_ptr p;
    struct uci_element *e; 
    struct uci_package *pkg = NULL;

    if (UCI_OK != uci_load(ctx, package, &pkg)){
        return -1; 
    }   
    uci_foreach_element(&pkg->sections, e){ 
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, section)){
            continue;
        }
        count++;
    }   
    uci_unload(ctx, pkg);
    return count;
}
int af_uci_get_array_value(struct uci_context *ctx, char *key_fmt, int index, char *output, int out_len)
{
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return af_uci_get_value(ctx, key, output, out_len);
}

int af_uci_add_section(struct uci_context * ctx, char *package_name, char *section)
{
    struct uci_section *s = NULL;
    struct uci_package *p = NULL;
    int ret;
    ret = uci_load(ctx, package_name , &p);
    if (ret != UCI_OK)
        goto done;

    ret = uci_add_section(ctx, p, section, &s);
    if (ret != UCI_OK)
        goto done;
    ret = uci_save(ctx, p); 
done:
    if (s) 
        fprintf(stdout, "%s\n", s->e.name);
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
    g_app_count = 0;
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
    g_cur_class_num = 0;
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


int config_get_appfilter_enable(void)
{
    int enable = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
	enable = af_uci_get_int_value(ctx, "appfilter.global.enable");
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
    ret = af_uci_get_value(ctx, "network.lan.ipaddr", lan_ip, len);
    uci_free_context(ctx);
    return ret;
}

int config_get_lan_mask(char *lan_mask, int len)
{
    int ret = 0;
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = af_uci_get_value(ctx, "network.lan.netmask", lan_mask, len);
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
