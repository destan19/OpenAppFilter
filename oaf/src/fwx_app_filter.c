
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include "k_json.h"
#include "fwx.h"
#include "fwx_app_filter.h"
#include "fwx_mac.h"
#include "fwx_log.h"

DEFINE_RWLOCK(app_filter_lock);

#define app_filter_read_lock() read_lock_bh(&app_filter_lock);
#define app_filter_read_unlock() read_unlock_bh(&app_filter_lock);
#define app_filter_write_lock() write_lock_bh(&app_filter_lock);
#define app_filter_write_unlock() write_unlock_bh(&app_filter_lock);
int g_appfilter_enable = 0;
u_int32_t g_appfilter_update_jiffies = 0;

static int g_app_rule_count = 0;
static LIST_HEAD(app_filter_rule_list);


static mac_config_t g_app_filter_whitelist;


static void app_id_config_init(app_id_config_t *config) {
    int i;
    for (i = 0; i < APPID_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&config->hash_table[i]);
    }
    config->count = 0;
}


static void flush_app_id_list(app_id_config_t *config) {
    int i;
    app_id_node_t *node;
    struct hlist_node *n;
    
    for (i = 0; i < APPID_HASH_SIZE; i++) {
        hlist_for_each_entry_safe(node, n, &config->hash_table[i], hlist) {
            hlist_del(&node->hlist);
            kfree(node);
        }
    }
    config->count = 0;
}


static app_id_node_t *find_app_id_node(app_id_config_t *config, int app_id) {
    int hash = app_id % APPID_HASH_SIZE;
    app_id_node_t *node;
    
    hlist_for_each_entry(node, &config->hash_table[hash], hlist) {
        if (node->app_id == app_id) {
            return node;
        }
    }
    return NULL;
}


static int add_app_id_node(app_id_config_t *config, int app_id) {
    app_id_node_t *node;
    int hash;
    

    if (find_app_id_node(config, app_id)) {
        return 0;  // 已存在，返回成功
    }
    
    if (config->count >= MAX_APP_ID_PER_RULE) {
        AF_ERROR("app id count exceeds limit\n");
        return -1;
    }
    
    node = kmalloc(sizeof(app_id_node_t), GFP_ATOMIC);
    if (!node) {
        AF_ERROR("kmalloc app_id_node failed\n");
        return -1;
    }
    
    node->app_id = app_id;
    hash = app_id % APPID_HASH_SIZE;
    hlist_add_head(&node->hlist, &config->hash_table[hash]);
    config->count++;
    
    return 0;
}

static int add_app_id_token_to_rule(app_filter_rule_t *rule, cJSON *app_id_obj)
{
    int start_id = 0, end_id = 0;
    int single_id = 0;
    int i = 0;
    const char *token = NULL;

	
    if (!rule || !app_id_obj) {
        return -1;
    }

    if (app_id_obj->type == cJSON_Number) {
        if (app_id_obj->valueint > 0) {
            return add_app_id_node(&rule->app_id_list, app_id_obj->valueint);
        }
        return -1;
    }

    if (app_id_obj->type != cJSON_String || !app_id_obj->valuestring) {
        return -1;
    }

    token = app_id_obj->valuestring;
    if (sscanf(token, "%d-%d", &start_id, &end_id) == 2) {
        if (start_id <= 0 || end_id < start_id) {
            AF_ERROR("invalid app_id range: %s\n", token);
            return -1;
        }
        for (i = start_id; i <= end_id; i++) {
			AF_INFO("token parse %s, id = %d\n", token, i);
            if (add_app_id_node(&rule->app_id_list, i) < 0) {
                return -1;
            }
        }
        return 0;
    }

    if (kstrtoint(token, 10, &single_id) == 0 && single_id > 0) {
        return add_app_id_node(&rule->app_id_list, single_id);
    }

    AF_ERROR("invalid app_id token: %s\n", token);
    return -1;
}

static int del_app_id_token_from_rule(int rule_id, cJSON *app_id_obj)
{
    int start_id = 0, end_id = 0;
    int single_id = 0;
    int i = 0;
    const char *token = NULL;

    if (!app_id_obj) {
        return -1;
    }

    if (app_id_obj->type == cJSON_Number) {
        return fwx_del_app_id_from_rule(rule_id, app_id_obj->valueint);
    }

    if (app_id_obj->type != cJSON_String || !app_id_obj->valuestring) {
        return -1;
    }

    token = app_id_obj->valuestring;
    if (sscanf(token, "%d-%d", &start_id, &end_id) == 2) {
        if (start_id <= 0 || end_id < start_id) {
            AF_ERROR("invalid app_id range for delete: %s\n", token);
            return -1;
        }
        for (i = start_id; i <= end_id; i++) {
            fwx_del_app_id_from_rule(rule_id, i);
        }
        return 0;
    }

    if (kstrtoint(token, 10, &single_id) == 0 && single_id > 0) {
        return fwx_del_app_id_from_rule(rule_id, single_id);
    }

    AF_ERROR("invalid app_id token for delete: %s\n", token);
    return -1;
}

int fwx_app_filter_init(void) {
    app_filter_write_lock();
    INIT_LIST_HEAD(&app_filter_rule_list);
    g_app_rule_count = 0;
    fwx_mac_config_init(&g_app_filter_whitelist);
    app_filter_write_unlock();
    
    AF_INFO("app filter init...ok\n");
    return 0;
}

void fwx_app_filter_exit(void) {
    app_filter_rule_t *rule, *next;
    app_filter_write_lock();
    list_for_each_entry_safe(rule, next, &app_filter_rule_list, list) {
        flush_app_id_list(&rule->app_id_list);
        fwx_flush_mac_list(&rule->mac_list);
        list_del(&rule->list);
        kfree(rule);
    }
    g_app_rule_count = 0;
    fwx_flush_mac_list(&g_app_filter_whitelist);
    app_filter_write_unlock();
    AF_INFO("app filter exit...ok\n");
}

app_filter_rule_t *fwx_find_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    list_for_each_entry(rule, &app_filter_rule_list, list) {
        if (rule->rule_id == rule_id) {
            return rule;
        }
    }
    return NULL;
}

void fwx_update_appfilter_jiffies(void){
    g_appfilter_update_jiffies = jiffies;
}



int fwx_add_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    
    if (g_app_rule_count >= MAX_APP_FILTER_RULE_NUM) {
        AF_ERROR("app filter rule count exceeds limit\n");
        return -1;
    }
    
    if (fwx_find_app_filter_rule(rule_id)) {
        AF_ERROR("app filter rule %d already exists\n", rule_id);
        return -1;
    }
    
    rule = kmalloc(sizeof(app_filter_rule_t), GFP_ATOMIC);
    if (!rule) {
        AF_ERROR("kmalloc app filter rule failed\n");
        return -1;
    }
    
    rule->rule_id = rule_id;
    rule->enable = 1;
    rule->filter_quic = 0;
    fwx_mac_config_init(&rule->mac_list);
    app_id_config_init(&rule->app_id_list);
    INIT_LIST_HEAD(&rule->list);
    
    app_filter_write_lock();
    list_add(&rule->list, &app_filter_rule_list);
    g_app_rule_count++;
    app_filter_write_unlock();
	
    AF_INFO("add app filter rule %d ok\n", rule_id);
    return 0;
}

int fwx_del_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    
    app_filter_write_lock();
    rule = fwx_find_app_filter_rule(rule_id);
    if (rule) {
        flush_app_id_list(&rule->app_id_list);
        fwx_flush_mac_list(&rule->mac_list);
        list_del(&rule->list);
        kfree(rule);
        g_app_rule_count--;
        app_filter_write_unlock();
        AF_INFO("del app filter rule %d ok\n", rule_id);
        return 0;
    }
    app_filter_write_unlock();
    
    AF_ERROR("app filter rule %d not found\n", rule_id);
    return -1;
}

int fwx_add_app_id_to_rule(int rule_id, int app_id) {
    app_filter_rule_t *rule;
    
    app_filter_write_lock();
    rule = fwx_find_app_filter_rule(rule_id);
    if (rule) {
        add_app_id_node(&rule->app_id_list, app_id);
        app_filter_write_unlock();
        return 0;
    }
    app_filter_write_unlock();
    
    AF_ERROR("app filter rule %d not found\n", rule_id);
    return -1;
}

int fwx_del_app_id_from_rule(int rule_id, int app_id) {
    app_filter_rule_t *rule;
    app_id_node_t *node;
    int hash;
    
    app_filter_write_lock();
    rule = fwx_find_app_filter_rule(rule_id);
    if (rule) {
        hash = app_id % APPID_HASH_SIZE;
        hlist_for_each_entry(node, &rule->app_id_list.hash_table[hash], hlist) {
            if (node->app_id == app_id) {
                hlist_del(&node->hlist);
                kfree(node);
                rule->app_id_list.count--;
                app_filter_write_unlock();
                return 0;
            }
        }
    }
    app_filter_write_unlock();
    
    AF_ERROR("app_id %d or rule %d not found\n", app_id, rule_id);
    return -1;
}


app_filter_rule_t *fwx_match_app_filter_rule(int app_id, const unsigned char *mac) {
    app_filter_rule_t *rule;
    app_id_node_t *node;
    struct mac_node *mac_node;
    int i;
    int mac_list_empty;
    
    app_filter_read_lock();
    list_for_each_entry(rule, &app_filter_rule_list, list) {
        if (!rule->enable) {
            continue;
        }
        



        mac_node = fwx_find_mac_node(&rule->mac_list, mac);
        if (!mac_node) {

            mac_list_empty = 1;
            for (i = 0; i < MAC_HASH_SIZE; i++) {
                if (!hlist_empty(&rule->mac_list.hash_table[i])) {
                    mac_list_empty = 0;
                    break;
                }
            }
            if (!mac_list_empty) {

                continue;
            }
        }
        

        if (app_id == FWX_QUIC_PROTO) {
            if (rule->filter_quic == 1) {
                app_filter_read_unlock();
                return rule;
            }
            continue;
        }

        node = find_app_id_node(&rule->app_id_list, app_id);
        if (node) {
            app_filter_read_unlock();
            return rule;
        }
    }
    app_filter_read_unlock();
    return NULL;
}

int fwx_api_add_app_filter_rule(cJSON *data_obj) {
    cJSON *rule_id_obj;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    
    if (!rule_id_obj) {
        AF_ERROR("invalid rule format\n");
        return -1;
    }
    
	fwx_update_appfilter_jiffies();

    if (fwx_add_app_filter_rule(rule_id_obj->valueint) < 0) {
        return -1;
    }
    AF_INFO("add app filter rule %d ok\n", rule_id_obj->valueint);
    
    return 0;
}

int fwx_api_mod_app_filter_rule(cJSON *data_obj) {
    int i;
    cJSON *rule_id_obj;
    cJSON *app_id_array;
    cJSON *app_id_obj;
    cJSON *action_obj;
    cJSON *enable_obj;
    cJSON *filter_quic_obj;
    app_filter_rule_t *rule = NULL;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    action_obj = cJSON_GetObjectItem(data_obj, "app_action");
    cJSON *mac_action_obj = cJSON_GetObjectItem(data_obj, "mac_action");
    
    if (!rule_id_obj) {
        AF_ERROR("rule_id not found\n");
        return -1;
    }
    

    rule = fwx_find_app_filter_rule(rule_id_obj->valueint);
    if (!rule) {
        AF_ERROR("rule %d not found\n", rule_id_obj->valueint);
        return -1;
    }
    

    if (mac_action_obj) {
        if (mac_action_obj->valueint == 1 || mac_action_obj->valueint == 2) {
            cJSON *mac_array = cJSON_GetObjectItem(data_obj, "mac_list");
            if (mac_array) {
                app_filter_write_lock();
                if (mac_action_obj->valueint == 1) {  // flush old
                    fwx_flush_mac_list(&rule->mac_list);
                }
                for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
                    cJSON *mac_obj = cJSON_GetArrayItem(mac_array, i);
                    u8 mac_bin[ETH_ALEN] = {0};
                    if (mac_obj && mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
                        fwx_add_mac_node(&rule->mac_list, mac_bin);
                    }
                }
                app_filter_write_unlock();
            }
        } else if (mac_action_obj->valueint == 3) {
            cJSON *mac_obj = cJSON_GetObjectItem(data_obj, "mac");
            if (mac_obj) {
                app_filter_write_lock();
                u8 mac_bin[ETH_ALEN] = {0};
                if (mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
                    fwx_add_mac_node(&rule->mac_list, mac_bin);
                }
                app_filter_write_unlock();
            }
        } else {

            app_filter_write_lock();
            fwx_flush_mac_list(&rule->mac_list);
            app_filter_write_unlock();
        }
    }
    

    if (action_obj) {
        if (action_obj->valueint == 1 || action_obj->valueint == 2) {

            app_id_array = cJSON_GetObjectItem(data_obj, "app_id_list");
            if (app_id_array) {
                app_filter_write_lock();
                if (action_obj->valueint == 1) {  // flush old
                    flush_app_id_list(&rule->app_id_list);
                }
                for (i = 0; i < cJSON_GetArraySize(app_id_array); i++) {
                    app_id_obj = cJSON_GetArrayItem(app_id_array, i);
                    if (app_id_obj) {
                        add_app_id_token_to_rule(rule, app_id_obj);
                    }
                }
                app_filter_write_unlock();
            }
        } else if (action_obj->valueint == 3) {

            app_id_obj = cJSON_GetObjectItem(data_obj, "app_id");
            if (app_id_obj) {
                app_filter_write_lock();
                add_app_id_token_to_rule(rule, app_id_obj);
                app_filter_write_unlock();
            }
        } else {

            app_filter_write_lock();
            flush_app_id_list(&rule->app_id_list);
            app_filter_write_unlock();
        }
    }
    
    enable_obj = cJSON_GetObjectItem(data_obj, "enable");
    if (enable_obj) {
        rule->enable = enable_obj->valueint;
    }

    filter_quic_obj = cJSON_GetObjectItem(data_obj, "filter_quic");
    if (filter_quic_obj) {
        rule->filter_quic = (filter_quic_obj->valueint == 1) ? 1 : 0;
    }
    
	fwx_update_appfilter_jiffies();
    return 0;
}

int fwx_api_del_app_filter_rule(cJSON *data_obj) {
    cJSON *rule_id_obj;
    cJSON *app_id_obj;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    if (!rule_id_obj) {
        AF_ERROR("rule_id not found\n");
        return -1;
    }
    
	fwx_update_appfilter_jiffies();
    app_id_obj = cJSON_GetObjectItem(data_obj, "app_id");
    if (app_id_obj) {

        return del_app_id_token_from_rule(rule_id_obj->valueint, app_id_obj);
    } else {

        return fwx_del_app_filter_rule(rule_id_obj->valueint);
    }
}

int fwx_api_dump_app_filter_rule(cJSON *data_obj) {
    app_filter_rule_t *rule;
    app_id_node_t *node;
    struct mac_node *mac_node;
    int app_count = 0;
    int mac_count = 0;
    int i;
    
    if (!data_obj) {
        return -1;
    }
    
    cJSON *rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    
    app_filter_read_lock();
    

    printk("\n");
    printk("+--------+-------+-----------+------------------+------------------+\n");
    printk("| RuleID | Enable| FilterQUIC| MAC List         | App ID List      |\n");
    printk("+--------+-------+-----------+------------------+------------------+\n");
    
    if (rule_id_obj) {
        rule = fwx_find_app_filter_rule(rule_id_obj->valueint);
        if (rule) {

            for (i = 0; i < MAC_HASH_SIZE; i++) {
                hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                    mac_count++;
                }
            }
            for (i = 0; i < APPID_HASH_SIZE; i++) {
                hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                    app_count++;
                }
            }
            

            printk(KERN_CONT "| %-6d | %-5d | %-9d | ", rule->rule_id, rule->enable, rule->filter_quic);
            

            if (mac_count == 0) {
                printk(KERN_CONT "%-16s | ", "(all MACs)");
            } else {
                int total_mac_count = mac_count;
                mac_count = 0;
                for (i = 0; i < MAC_HASH_SIZE; i++) {
                    hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                        if (mac_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%pM", mac_node->mac);
                        mac_count++;
                        if (mac_count >= 32) { 
                            if (mac_count < total_mac_count) {
                                printk(KERN_CONT "...");
                            }
                            break;
                        }
                    }
                }
                printk(KERN_CONT " | ");
            }
            

            if (app_count == 0) {
                printk(KERN_CONT "%-16s |\n", "(empty)");
            } else {
                int total_app_count = app_count;
                int printed_count = 0;
                int should_break = 0;
                app_count = 0;
                for (i = 0; i < APPID_HASH_SIZE && !should_break; i++) {
                    hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                        if (printed_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%d", node->app_id);
                        printed_count++;
                        app_count++;
                        if (printed_count >= 128) { 
                            if (app_count < total_app_count) {
                                printk(KERN_CONT "...");
                            }
                            should_break = 1;
                            break;
                        }
                    }
                }
                printk(KERN_CONT " |\n");
            }
        }
    } else {
        list_for_each_entry(rule, &app_filter_rule_list, list) {
            app_count = 0;
            mac_count = 0;
            

            for (i = 0; i < MAC_HASH_SIZE; i++) {
                hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                    mac_count++;
                }
            }
            for (i = 0; i < 256; i++) {
                hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                    app_count++;
                }
            }
            

            printk(KERN_CONT "| %-6d | %-5d | %-9d | ", rule->rule_id, rule->enable, rule->filter_quic);
            

            if (mac_count == 0) {
                printk(KERN_CONT "%-16s | ", "(all MACs)");
            } else {
                int total_mac_count = mac_count;
                mac_count = 0;
                for (i = 0; i < MAC_HASH_SIZE; i++) {
                    hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                        if (mac_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%pM", mac_node->mac);
                        mac_count++;
                        if (mac_count >= 32) {  
                            if (mac_count < total_mac_count) {
                                printk(KERN_CONT "...");
                            }
                            break;
                        }
                    }
                }
                printk(KERN_CONT " | ");
            }
            

            if (app_count == 0) {
                printk(KERN_CONT "%-16s |\n", "(empty)");
            } else {
                int total_app_count = app_count;
                int printed_count = 0;
                int should_break = 0;
                app_count = 0;
                for (i = 0; i < APPID_HASH_SIZE && !should_break; i++) {
                    hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                        if (printed_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%d", node->app_id);
                        printed_count++;
                        app_count++;
                        if (printed_count >= 128) {  
                            if (app_count < total_app_count) {
                                printk(KERN_CONT "...");
                            }
                            should_break = 1;
                            break;
                        }
                    }
                }
                printk(KERN_CONT " |\n");
            }
        }
    }
    
    printk("+--------+-------+-----------+------------------+------------------+\n");
    

    printk("\n");
    printk("App Filter Whitelist:\n");
    printk("+----------------------------------------+\n");
    printk("| MAC Address                           |\n");
    printk("+----------------------------------------+\n");
    
    int total_whitelist_count = 0;
    struct mac_node *whitelist_node;
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        hlist_for_each_entry(whitelist_node, &g_app_filter_whitelist.hash_table[i], hlist) {
            total_whitelist_count++;
        }
    }
    
    if (total_whitelist_count == 0) {
        printk(KERN_CONT "| %-38s |\n", "(empty)");
    } else {
        int printed_count = 0;
        int should_break = 0;
        
        for (i = 0; i < MAC_HASH_SIZE && !should_break; i++) {
            hlist_for_each_entry(whitelist_node, &g_app_filter_whitelist.hash_table[i], hlist) {
                printk(KERN_CONT "| %-38pM |\n", whitelist_node->mac);
                printed_count++;
                if (printed_count >= 10) {  
                    if (printed_count < total_whitelist_count) {
                        printk(KERN_CONT "| %-38s |\n", "...");
                    }
                    should_break = 1;
                    break;
                }
            }
        }
    }
    
    printk("+----------------------------------------+\n");
    printk("Total whitelist entries: %d\n", total_whitelist_count);
    
    app_filter_read_unlock();
    
    return 0;
}

int fwx_api_flush_app_filter_rule(cJSON *data_obj) {
    app_filter_rule_t *rule, *next;
    
    app_filter_write_lock();
    list_for_each_entry_safe(rule, next, &app_filter_rule_list, list) {
        flush_app_id_list(&rule->app_id_list);
        list_del(&rule->list);
        kfree(rule);
    }
    g_app_rule_count = 0;
    app_filter_write_unlock();
    
	fwx_update_appfilter_jiffies();
    return 0;
}


int fwx_match_app_filter_whitelist(const unsigned char *mac) {
    struct mac_node *node;
    int ret = 0;

    app_filter_read_lock();
    node = fwx_find_mac_node(&g_app_filter_whitelist, mac);
    ret = (node != NULL);
    app_filter_read_unlock();

    return ret;
}


int fwx_api_add_app_filter_whitelist(cJSON *data_obj) {
    cJSON *mac_array;
    int i;
    u8 mac_bin[ETH_ALEN];

    if (!data_obj) {
        return -1;
    }

    mac_array = cJSON_GetObjectItem(data_obj, "mac_list");
    if (!mac_array) {
        printk("mac_list not found\n");
        return -1;
    }

    app_filter_write_lock();
    for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
        cJSON *mac_obj = cJSON_GetArrayItem(mac_array, i);
        if (mac_obj && mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
            fwx_add_mac_node(&g_app_filter_whitelist, mac_bin);
        }
    }
    app_filter_write_unlock();
	
	fwx_update_appfilter_jiffies();
    return 0;
}


int fwx_api_flush_app_filter_whitelist(cJSON *data_obj) {
    app_filter_write_lock();
    fwx_flush_mac_list(&g_app_filter_whitelist);
    app_filter_write_unlock();
	
	fwx_update_appfilter_jiffies();
    return 0;
}

