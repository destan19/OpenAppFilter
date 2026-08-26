// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_MAC_FILTER_H__
#define __FWX_MAC_FILTER_H__
#include "k_json.h"
#include "fwx_mac.h"
#include <linux/list.h>

#define MAX_MAC_FILTER_RULE_NUM 64
#define MAC_FILTER_MODE_ALL_USERS 1
#define MAC_FILTER_MODE_SINGLE_USER 2

typedef struct mac_filter_rule {
    int rule_id;
    int mode;
    mac_config_t mac_list;
    struct list_head list;
} mac_filter_rule_t;

extern int g_mac_filter_enable;

int fwx_api_add_mac_filter_whitelist(cJSON *data_obj);
int fwx_api_del_mac_filter_whitelist(cJSON *data_obj);
int fwx_api_flush_mac_filter_whitelist(cJSON *data_obj);

int fwx_match_mac_filter_whitelist(const unsigned char *mac);

int fwx_mac_filter_init(void);

void fwx_mac_filter_exit(void);

int fwx_add_mac_filter_rule(int rule_id, int mode);

int fwx_del_mac_filter_rule(int rule_id);

mac_filter_rule_t *fwx_find_mac_filter_rule(int rule_id);

int fwx_add_mac_to_rule(int rule_id, const unsigned char *mac);

int fwx_del_mac_from_rule(int rule_id, const unsigned char *mac);

mac_filter_rule_t *fwx_match_mac_filter_rule(const unsigned char *mac);

int fwx_api_add_mac_filter_rule(cJSON *data_obj);

int fwx_api_del_mac_filter_rule(cJSON *data_obj);

int fwx_api_dump_mac_filter_rule(cJSON *data_obj);

int fwx_api_flush_mac_filter_rule(cJSON *data_obj);

int fwx_api_mod_mac_filter_rule(cJSON *data_obj);

#endif 