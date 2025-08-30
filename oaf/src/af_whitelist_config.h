#ifndef __AF_WHITELIST_CONFIG_H__
#define __AF_WHITELIST_CONFIG_H__
#include "app_filter.h"
#include "af_utils.h"

#define MAX_AF_WHITELIST_MAC_HASH_SIZE 64

typedef struct af_whitelist_mac_node{
    struct list_head list;
    unsigned char mac[MAC_ADDR_LEN];
}af_whitelist_mac_node_t;

void af_whitelist_mac_init(void);
void af_whitelist_mac_flush(void);
af_whitelist_mac_node_t *af_whitelist_mac_find(unsigned char *mac);
af_whitelist_mac_node_t *af_whitelist_mac_add(unsigned char *mac);
int af_config_set_whitelist_mac_list(cJSON *data_obj);

#endif