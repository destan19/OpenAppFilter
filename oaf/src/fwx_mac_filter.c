
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
#include "k_json.h"
#include "fwx.h"
#include "fwx_mac.h"
#include "fwx_mac_filter.h"

DEFINE_RWLOCK(mac_filter_lock);

#define mac_filter_read_lock() read_lock_bh(&mac_filter_lock);
#define mac_filter_read_unlock() read_unlock_bh(&mac_filter_lock);
#define mac_filter_write_lock() write_lock_bh(&mac_filter_lock);
#define mac_filter_write_unlock() write_unlock_bh(&mac_filter_lock);
static int g_mac_rule_count = 0;
static LIST_HEAD(mac_filter_rule_list);
int g_mac_filter_enable = 0;

static mac_config_t g_mac_filter_whitelist;

int fwx_mac_filter_init(void) {
	mac_filter_write_lock();
	INIT_LIST_HEAD(&mac_filter_rule_list);
	g_mac_rule_count = 0;
	fwx_mac_config_init(&g_mac_filter_whitelist);
	mac_filter_write_unlock();
	return 0;
}

void fwx_mac_filter_exit(void) {
	mac_filter_rule_t *rule, *next;
	mac_filter_write_lock();
	list_for_each_entry_safe(rule, next, &mac_filter_rule_list, list) {
		fwx_flush_mac_list(&rule->mac_list);
		list_del(&rule->list);
		kfree(rule);
	}
	g_mac_rule_count = 0;
	fwx_flush_mac_list(&g_mac_filter_whitelist);
	mac_filter_write_unlock();
}

mac_filter_rule_t *fwx_find_mac_filter_rule(int rule_id) {
	mac_filter_rule_t *rule;
	list_for_each_entry(rule, &mac_filter_rule_list, list) {
		if (rule->rule_id == rule_id) {
			return rule;
		}
	}
	return NULL;
}

int fwx_add_mac_filter_rule(int rule_id, int mode) {
	mac_filter_rule_t *rule;

	if (g_mac_rule_count >= MAX_MAC_FILTER_RULE_NUM) {
		return -1;
	}

	if (fwx_find_mac_filter_rule(rule_id)) {
		return -1;
	}

	rule = kmalloc(sizeof(mac_filter_rule_t), GFP_ATOMIC);
	if (!rule) {
		printk("kmalloc mac filter rule failed\n");
		return -1;
	}

	rule->rule_id = rule_id;
	rule->mode = (mode == MAC_FILTER_MODE_SINGLE_USER) ? MAC_FILTER_MODE_SINGLE_USER : MAC_FILTER_MODE_ALL_USERS;
	fwx_mac_config_init(&rule->mac_list);
	INIT_LIST_HEAD(&rule->list);

	mac_filter_write_lock();
	list_add(&rule->list, &mac_filter_rule_list);
	g_mac_rule_count++;
	mac_filter_write_unlock();

	return 0;
}

int fwx_del_mac_filter_rule(int rule_id) {
	mac_filter_rule_t *rule;
	
	mac_filter_write_lock();
	rule = fwx_find_mac_filter_rule(rule_id);
	if (rule) {
		fwx_flush_mac_list(&rule->mac_list);
		list_del(&rule->list);
		kfree(rule);
		g_mac_rule_count--;
		mac_filter_write_unlock();
		return 0;
	}
	mac_filter_write_unlock();
	
	return -1;
}

int fwx_add_mac_to_rule(int rule_id, const unsigned char *mac) {
	mac_filter_rule_t *rule;
	
	mac_filter_write_lock();
	rule = fwx_find_mac_filter_rule(rule_id);
	if (rule) {
		fwx_add_mac_node(&rule->mac_list, mac);
		mac_filter_write_unlock();
		return 0;
	}
	mac_filter_write_unlock();
	
	return -1;
}

int fwx_del_mac_from_rule(int rule_id, const unsigned char *mac) {
	mac_filter_rule_t *rule;
	struct mac_node *node;
	
	mac_filter_write_lock();
	rule = fwx_find_mac_filter_rule(rule_id);
	if (rule) {
		node = fwx_find_mac_node(&rule->mac_list, mac);
		if (node) {
			hlist_del(&node->hlist);
			kfree(node);
			mac_filter_write_unlock();
			return 0;
		}
	}
	mac_filter_write_unlock();
	
	return -1;
}

mac_filter_rule_t *fwx_match_mac_filter_rule(const unsigned char *mac) {
	mac_filter_rule_t *rule;
	struct mac_node *node;

	mac_filter_read_lock();
	list_for_each_entry(rule, &mac_filter_rule_list, list) {
		if (rule->mode == MAC_FILTER_MODE_ALL_USERS) {
			mac_filter_read_unlock();
			return rule;
		}

		node = fwx_find_mac_node(&rule->mac_list, mac);
		if (node) {
			mac_filter_read_unlock();
			return rule;
		}
	}
	mac_filter_read_unlock();
	return NULL;
}

int fwx_api_add_mac_filter_rule(cJSON *data_obj) {
	cJSON *rule_id_obj;
	cJSON *mode_obj;
	int mode = MAC_FILTER_MODE_ALL_USERS;
	
	if (!data_obj) {
		return -1;
	}
	
	rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
	mode_obj = cJSON_GetObjectItem(data_obj, "mode");
	if (mode_obj) {
		mode = mode_obj->valueint;
	}
	if (mode != MAC_FILTER_MODE_SINGLE_USER) {
		mode = MAC_FILTER_MODE_ALL_USERS;
	}
	if (!rule_id_obj) {
		printk("invalid rule format\n");
		return -1;
	}
	
	if (fwx_add_mac_filter_rule(rule_id_obj->valueint, mode) < 0) {
		return -1;
	}

	return 0;
}

int fwx_api_mod_mac_filter_rule(cJSON *data_obj) {
	int i;
	cJSON *rule_id_obj;
	cJSON *mac_array;
	cJSON *mac_obj;
	cJSON *action_obj;
	cJSON *mode_obj;
	mac_filter_rule_t *rule = NULL;

	if (!data_obj) {
		return -1;
	}
	rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");

	action_obj = cJSON_GetObjectItem(data_obj, "mac_action"); 


	if (!rule_id_obj) {
		printk("rule_id not found\n");
		return -1;
	}


	rule = fwx_find_mac_filter_rule(rule_id_obj->valueint);
	if (!rule) {
		printk("rule %d not found\n", rule_id_obj->valueint);
		return -1;
	}

	mode_obj = cJSON_GetObjectItem(data_obj, "mode");
	if (mode_obj) {
		int mode = mode_obj->valueint;
		if (mode != MAC_FILTER_MODE_SINGLE_USER) {
			mode = MAC_FILTER_MODE_ALL_USERS;
		}
		mac_filter_write_lock();
		rule->mode = mode;
		mac_filter_write_unlock();
	}
	

    if (action_obj){
		if (action_obj->valueint == 1 || action_obj->valueint == 2) {
			mac_array = cJSON_GetObjectItem(data_obj, "mac_list");
			if (mac_array) {
				mac_filter_write_lock();
				if (action_obj->valueint == 1){ // flush old
					fwx_flush_mac_list(&rule->mac_list);
				}
				for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
					mac_obj = cJSON_GetArrayItem(mac_array, i);
					u8 mac_bin[ETH_ALEN] = {0};
					if (mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
						fwx_add_mac_node(&rule->mac_list, mac_bin);
					}
				}
				mac_filter_write_unlock();
			}
		}

		else if (action_obj->valueint == 3) {
			mac_obj = cJSON_GetObjectItem(data_obj, "mac");
			if (mac_obj) {
				mac_filter_write_lock();
				u8 mac_bin[ETH_ALEN] = {0};
				if (mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
					fwx_add_mac_node(&rule->mac_list, mac_bin);
				}	
				mac_filter_write_unlock();
			}
		}
		else{
			mac_filter_write_lock();
			fwx_flush_mac_list(&rule->mac_list);
			mac_filter_write_unlock();
		}
	}

	return 0;
}

int fwx_api_del_mac_filter_rule(cJSON *data_obj) {
	cJSON *rule_id_obj;
	cJSON *mac_obj;
	
	if (!data_obj) {
		return -1;
	}
	
	rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
	if (!rule_id_obj) {
		printk("rule_id not found\n");
		return -1;
	}
	
	mac_obj = cJSON_GetObjectItem(data_obj, "mac");
	if (mac_obj) {

		u8 mac_bin[ETH_ALEN] = {0};
		if (mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
			return fwx_del_mac_from_rule(rule_id_obj->valueint, mac_bin);
		}
	} else {

		return fwx_del_mac_filter_rule(rule_id_obj->valueint);
	}
	
	return -1;
}

int fwx_api_dump_mac_filter_rule(cJSON *data_obj) {
	mac_filter_rule_t *rule;
	struct mac_node *node;
	int mac_count = 0;
	int i;
	
	if (!data_obj) {
		return -1;
	}

	cJSON *rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
	
	mac_filter_read_lock();

	printk("\n");
	printk("+--------+------+----------------------------------------+\n");
	printk("| RuleID | Mode | MAC List                               |\n");
	printk("+--------+------+----------------------------------------+\n");
	
	if (rule_id_obj) {
		rule = fwx_find_mac_filter_rule(rule_id_obj->valueint);
		if (rule) {

			for (i = 0; i < MAC_HASH_SIZE; i++) {
				hlist_for_each_entry(node, &rule->mac_list.hash_table[i], hlist) {
					mac_count++;
				}
			}
			

			printk(KERN_CONT "| %-6d | %-4d | ", rule->rule_id, rule->mode);
			

			if (rule->mode == MAC_FILTER_MODE_ALL_USERS) {
				printk(KERN_CONT "%-38s |\n", "(all users)");
			} else if (mac_count == 0) {
				printk(KERN_CONT "%-38s |\n", "(empty)");
			} else {
				int total_mac_count = mac_count;
				mac_count = 0;
				for (i = 0; i < MAC_HASH_SIZE; i++) {
					hlist_for_each_entry(node, &rule->mac_list.hash_table[i], hlist) {
						if (mac_count > 0) {
							printk(KERN_CONT ", ");
						}
						printk(KERN_CONT "%pM", node->mac);
						mac_count++;
						if (mac_count >= 5) {  // 最多显示5个MAC
							if (mac_count < total_mac_count) {
								printk(KERN_CONT "...");
							}
							break;
						}
					}
				}
				printk(KERN_CONT " |\n");
			}
		}
	} else {
		list_for_each_entry(rule, &mac_filter_rule_list, list) {
			mac_count = 0;
			

			for (i = 0; i < MAC_HASH_SIZE; i++) {
				hlist_for_each_entry(node, &rule->mac_list.hash_table[i], hlist) {
					mac_count++;
				}
			}
			

			printk(KERN_CONT "| %-6d | %-4d | ", rule->rule_id, rule->mode);
			

			if (rule->mode == MAC_FILTER_MODE_ALL_USERS) {
				printk(KERN_CONT "%-38s |\n", "(all users)");
			} else if (mac_count == 0) {
				printk(KERN_CONT "%-38s |\n", "(empty)");
			} else {
				int total_mac_count = mac_count;
				mac_count = 0;
				for (i = 0; i < MAC_HASH_SIZE; i++) {
					hlist_for_each_entry(node, &rule->mac_list.hash_table[i], hlist) {
						if (mac_count > 0) {
							printk(KERN_CONT ", ");
						}
						printk(KERN_CONT "%pM", node->mac);
						mac_count++;
						if (mac_count >= 5) {  // 最多显示5个MAC
							if (mac_count < total_mac_count) {
								printk(KERN_CONT "...");
							}
							break;
						}
					}
				}
				printk(KERN_CONT " |\n");
			}
		}
	}
	
	printk("+--------+------+----------------------------------------+\n");
	

	printk("\n");
	printk("MAC Filter Whitelist:\n");
	printk("+----------------------------------------+\n");
	printk("| MAC Address                           |\n");
	printk("+----------------------------------------+\n");
	
	int total_whitelist_count = 0;
	for (i = 0; i < MAC_HASH_SIZE; i++) {
		hlist_for_each_entry(node, &g_mac_filter_whitelist.hash_table[i], hlist) {
			total_whitelist_count++;
		}
	}
	
	if (total_whitelist_count == 0) {
		printk(KERN_CONT "| %-38s |\n", "(empty)");
	} else {
		int printed_count = 0;
		int should_break = 0;
		
		for (i = 0; i < MAC_HASH_SIZE && !should_break; i++) {
			hlist_for_each_entry(node, &g_mac_filter_whitelist.hash_table[i], hlist) {
				printk(KERN_CONT "| %-38pM |\n", node->mac);
				printed_count++;
				if (printed_count >= 10) {  // 最多显示10个MAC
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
	
	mac_filter_read_unlock();
	
	return 0;
}

int fwx_api_flush_mac_filter_rule(cJSON *data_obj) {
	mac_filter_rule_t *rule, *next;
	
	mac_filter_write_lock();
	list_for_each_entry_safe(rule, next, &mac_filter_rule_list, list) {
		fwx_flush_mac_list(&rule->mac_list);
		list_del(&rule->list);
		kfree(rule);
	}
	g_mac_rule_count = 0;
	mac_filter_write_unlock();
	
	return 0;
}


int fwx_match_mac_filter_whitelist(const unsigned char *mac) {
	struct mac_node *node;
	int ret = 0;

	mac_filter_read_lock();
	node = fwx_find_mac_node(&g_mac_filter_whitelist, mac);
	ret = (node != NULL);
	mac_filter_read_unlock();

	return ret;
}


int fwx_api_add_mac_filter_whitelist(cJSON *data_obj) {
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

	mac_filter_write_lock();
	for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
		cJSON *mac_obj = cJSON_GetArrayItem(mac_array, i);
		if (mac_obj && mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
			fwx_add_mac_node(&g_mac_filter_whitelist, mac_bin);
		}
	}
	mac_filter_write_unlock();

	return 0;
}


int fwx_api_del_mac_filter_whitelist(cJSON *data_obj) {
	cJSON *mac_obj;
	u8 mac_bin[ETH_ALEN];
	struct mac_node *node;

	if (!data_obj) {
		return -1;
	}

	mac_obj = cJSON_GetObjectItem(data_obj, "mac");
	if (!mac_obj) {
		printk("mac not found\n");
		return -1;
	}

	if (!mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
		printk("invalid mac format\n");
		return -1;
	}

	mac_filter_write_lock();
	node = fwx_find_mac_node(&g_mac_filter_whitelist, mac_bin);
	if (node) {
		hlist_del(&node->hlist);
		kfree(node);
		mac_filter_write_unlock();
		return 0;
	}
	mac_filter_write_unlock();

	return -1;
}


int fwx_api_flush_mac_filter_whitelist(cJSON *data_obj) {
	mac_filter_write_lock();
	fwx_flush_mac_list(&g_mac_filter_whitelist);
	mac_filter_write_unlock();
	return 0;
}
