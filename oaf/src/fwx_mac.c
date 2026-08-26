
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "fwx.h"
#include "fwx_mac.h"

static int mac_hash(const unsigned char *mac) {
    int hash = 0;
    int i;
    for (i = 0; i < ETH_ALEN; i++) {
        hash += mac[i];
    }
    return hash % MAC_HASH_SIZE;
}

void fwx_mac_config_init(mac_config_t *config){
	int i;
	for (i = 0; i < MAC_HASH_SIZE; i++){
 		INIT_HLIST_HEAD(&config->hash_table[i]);
	}
}

void fwx_add_mac_node(mac_config_t *config, const unsigned char *mac) {
    struct mac_node *new_node;
    int hash = mac_hash(mac);

    new_node = kmalloc(sizeof(struct mac_node), GFP_KERNEL);
    if (!new_node) {
        pr_err("Memory allocation failed\n");
        return;
    }
    memcpy(new_node->mac, mac, ETH_ALEN);
    INIT_HLIST_NODE(&new_node->hlist);

    hlist_add_head(&new_node->hlist, &config->hash_table[hash]);
}

void fwx_dump_mac_node(mac_config_t *config) {
	int i;
    struct mac_node *node;
	for(i = 0; i < MAC_HASH_SIZE; i++){
		hlist_for_each_entry(node, &config->hash_table[i], hlist) {
			printk("dump node: %pM\n", node->mac);
		}
	}
}

struct mac_node *fwx_find_mac_node(mac_config_t *config, const unsigned char *mac){
	struct mac_node *node;
	if (!config || !mac)
		return NULL;
	int hash = mac_hash(mac);
	hlist_for_each_entry(node, &config->hash_table[hash], hlist) {
		if (memcmp(node->mac, mac, ETH_ALEN) == 0) {
			return node;
		}
	}
	return NULL;
}

struct mac_node *fwx_flush_mac_list(mac_config_t *config){
    int i;
	struct mac_node *node;
    struct hlist_node *n;
	if (!config)
		return NULL;
	for (i = 0; i < MAC_HASH_SIZE; i++){
        hlist_for_each_entry_safe(node, n, &config->hash_table[i], hlist) {
            hlist_del(&node->hlist);
            kfree(node);
        }
    }
	return NULL;
}
