
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_APP_FILTER_H__
#define __FWX_APP_FILTER_H__
#include "k_json.h"
#include "fwx_mac.h"
#include <linux/list.h>
#include <linux/types.h>

#define MAX_APP_FILTER_RULE_NUM 64
#define MAX_APP_ID_PER_RULE 1024
#define APPID_HASH_SIZE 256

extern u_int32_t g_appfilter_update_jiffies;

typedef struct app_id_node {
    int app_id;
    struct hlist_node hlist;
} app_id_node_t;


typedef struct app_id_config {
    struct hlist_head hash_table[APPID_HASH_SIZE]; 
    int count;
} app_id_config_t;


typedef struct app_filter_rule {
    int rule_id;                
    int enable;                 
    int filter_quic;
    mac_config_t mac_list;      
    app_id_config_t app_id_list; 
    struct list_head list;  
} app_filter_rule_t;

extern int g_appfilter_enable;


int fwx_app_filter_init(void);


void fwx_app_filter_exit(void);


int fwx_add_app_filter_rule(int rule_id);


int fwx_del_app_filter_rule(int rule_id);


app_filter_rule_t *fwx_find_app_filter_rule(int rule_id);


int fwx_add_app_id_to_rule(int rule_id, int app_id);


int fwx_del_app_id_from_rule(int rule_id, int app_id);


app_filter_rule_t *fwx_match_app_filter_rule(int app_id, const unsigned char *mac);


int fwx_api_add_app_filter_rule(cJSON *data_obj);


int fwx_api_del_app_filter_rule(cJSON *data_obj);


int fwx_api_dump_app_filter_rule(cJSON *data_obj);


int fwx_api_flush_app_filter_rule(cJSON *data_obj);


int fwx_api_mod_app_filter_rule(cJSON *data_obj);


int fwx_api_add_app_filter_whitelist(cJSON *data_obj);
int fwx_api_flush_app_filter_whitelist(cJSON *data_obj);


int fwx_match_app_filter_whitelist(const unsigned char *mac);

#endif

