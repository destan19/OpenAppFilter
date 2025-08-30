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
#ifndef __APPFILTER_CONFIG_H__
#define __APPFILTER_CONFIG_H__
#include <uci.h>

#define MAX_SUPPORT_APP_NUM 1024
#define MAX_CLASS_NAME_LEN 32
#define MAX_PARAM_LIST_LEN 1024

#include "appfilter_user.h"
extern int g_cur_class_num;
extern int g_app_count;
extern char CLASS_NAME_TABLE[MAX_APP_TYPE][MAX_CLASS_NAME_LEN];

typedef struct app_name_info
{
    int id;
    char name[64];
} app_name_info_t;
void init_app_name_table(void);
void init_app_class_name_table(void);
char *get_app_name_by_id(int id);

int appfilter_config_alloc(void);

int appfilter_config_free(void);
int config_get_appfilter_enable(void);
int config_get_lan_ip(char *lan_ip, int len);
int config_get_lan_mask(char *lan_mask, int len);
int af_uci_delete(struct uci_context *ctx, char *key);
int af_uci_add_list(struct uci_context *ctx, char *key, char *value);
int af_uci_add_int_list(struct uci_context *ctx, char *key, int value);
int af_uci_del_list(struct uci_context *ctx, char *key, char *value);
int af_uci_get_list_value(struct uci_context *ctx, char *key, char *output, int out_len, char *delimt);
int af_uci_set_value(struct uci_context *ctx, char *key, char *value);
int af_uci_set_int_value(struct uci_context *ctx, char *key, int value);
int af_uci_del_array_value(struct uci_context *ctx, char *key_fmt, int index);
int af_uci_set_array_value(struct uci_context *ctx, char *key_fmt, int index, char *value);
int af_get_uci_list_num(struct uci_context * ctx, char *package, char *section);
int af_uci_get_array_value(struct uci_context *ctx, char *key_fmt, int index, char *output, int out_len);
int af_uci_get_int_value(struct uci_context *ctx, char *key);
int af_uci_get_value(struct uci_context *ctx, char *key, char *output, int out_len);
int af_uci_add_section(struct uci_context * ctx, char *package_name, char *section);
int af_uci_commit(struct uci_context *ctx, const char * package);
char *get_app_name_by_id(int id);

#endif

