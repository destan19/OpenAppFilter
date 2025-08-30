#ifndef __AF_USER_CONFIG_H__
#define __AF_USER_CONFIG_H__
#include "app_filter.h"
#include "af_utils.h"

typedef struct af_mac_node {
    struct list_head list;
    unsigned char mac[MAC_ADDR_LEN];
}af_mac_node_t;

void af_mac_list_init(void);
void af_mac_list_flush(void);
af_mac_node_t *af_mac_find(unsigned char *mac);
af_mac_node_t *af_mac_add(unsigned char *mac);

#endif