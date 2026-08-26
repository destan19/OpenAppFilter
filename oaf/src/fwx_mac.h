// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_MAC_H__
#define __FWX_MAC_H__
#define MAC_HASH_SIZE 128
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
struct mac_node {
    unsigned char mac[ETH_ALEN];  
    struct hlist_node hlist;  
};

typedef struct mac_config{
	struct hlist_head hash_table[MAC_HASH_SIZE];
}mac_config_t;

void fwx_mac_config_init(mac_config_t *config);
void fwx_add_mac_node(mac_config_t *config, const unsigned char *mac);
void fwx_dump_mac_node(mac_config_t *config);
struct mac_node *fwx_find_mac_node(mac_config_t *config, const unsigned char *mac);
int mac_str_to_bin(const char *mac_str, u8 *mac_bin);
struct mac_node *fwx_flush_mac_list(mac_config_t *config);

#endif
