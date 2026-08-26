// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_UCI_H__
#define __FWX_UCI_H__
#include <uci.h>

#define MAX_PARAM_LIST_LEN 1024

int fwx_uci_get_int_value(struct uci_context *ctx, char *key);
int fwx_uci_get_value(struct uci_context *ctx, char *key, char *output, int out_len);
int fwx_uci_add_list(struct uci_context *ctx, char *key, char *value);
int fwx_uci_get_list_value(struct uci_context *ctx, char *key, char *output, int out_len, char *delimt);
int fwx_uci_add_int_list(struct uci_context *ctx, char *key, int value);
int fwx_uci_del_list(struct uci_context *ctx, char *key, char *value);
int fwx_uci_set_value(struct uci_context *ctx, char *key, char *value);
int fwx_uci_set_int_value(struct uci_context *ctx, char *key, int value);
int fwx_uci_del_array_value(struct uci_context *ctx, char *key_fmt, int index);
int fwx_uci_set_array_value(struct uci_context *ctx, char *key_fmt, int index, char *value);
int fwx_uci_get_list_num(struct uci_context * ctx, char *package, char *section);
int fwx_uci_get_array_value(struct uci_context *ctx, char *key_fmt, int index, char *output, int out_len);
int fwx_uci_add_section(struct uci_context * ctx, char *package_name, char *section);
int fwx_uci_commit(struct uci_context *ctx, const char * package);
int fwx_uci_delete(struct uci_context *ctx, char *key);
#endif

