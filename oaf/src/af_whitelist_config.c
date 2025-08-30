#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include "app_filter.h"
#include "af_utils.h"
#include "af_log.h"
#include "cJSON.h"
#include "af_whitelist_config.h"


DEFINE_RWLOCK(af_whitelist_mac_lock);

struct list_head af_whitelist_mac_htable[MAX_AF_MAC_HASH_SIZE];

void af_whitelist_mac_init(void)
{
	int i;
	write_lock_bh(&af_whitelist_mac_lock);
	for (i = 0; i < MAX_AF_MAC_HASH_SIZE; i++)
	{
		INIT_LIST_HEAD(&af_whitelist_mac_htable[i]);
	}
	write_unlock_bh(&af_whitelist_mac_lock);
}

void af_whitelist_mac_flush(void)
{
	int i;
	af_whitelist_mac_node_t *p = NULL;
	char mac_str[32] = {0};
	write_lock_bh(&af_whitelist_mac_lock);
	for (i = 0; i < MAX_AF_MAC_HASH_SIZE; i++)
	{
		while (!list_empty(&af_whitelist_mac_htable[i]))
		{
			p = list_first_entry(&af_whitelist_mac_htable[i], af_whitelist_mac_node_t, list);
			memset(mac_str, 0x0, sizeof(mac_str));
			sprintf(mac_str, MAC_FMT, MAC_ARRAY(p->mac));
			list_del(&(p->list));
			kfree(p);
		}
	}
	write_unlock_bh(&af_whitelist_mac_lock);
}

af_whitelist_mac_node_t *af_whitelist_mac_find(unsigned char *mac)
{
	af_whitelist_mac_node_t *node = NULL;
	unsigned int index = 0;

	index = hash_mac(mac);
	read_lock_bh(&af_whitelist_mac_lock);
	list_for_each_entry(node, &af_whitelist_mac_htable[index], list)
	{
		if (0 == memcmp(node->mac, mac, 6))
		{
			read_unlock_bh(&af_whitelist_mac_lock);
			return node;
		}
	}
	read_unlock_bh(&af_whitelist_mac_lock);
	return NULL;
}

af_whitelist_mac_node_t *af_whitelist_mac_add(unsigned char *mac)
{
	af_whitelist_mac_node_t *node = NULL;
	int index = 0;

	node = (af_whitelist_mac_node_t *)kmalloc(sizeof(af_whitelist_mac_node_t), GFP_ATOMIC);
	if (node == NULL)
	{
		return NULL;
	}

	memset(node, 0, sizeof(af_whitelist_mac_node_t));
	memcpy(node->mac, mac, MAC_ADDR_LEN);
	index = hash_mac(mac);

	AF_DEBUG("add whitelist mac=" MAC_FMT "\n", MAC_ARRAY(node->mac));
	write_lock_bh(&af_whitelist_mac_lock);
	list_add(&(node->list), &af_whitelist_mac_htable[index]);
	write_unlock_bh(&af_whitelist_mac_lock);
	return node;
}


int af_config_set_whitelist_mac_list(cJSON *data_obj)
{
	int i;
	cJSON *mac_arr = NULL;
	u8 mac_hex[MAC_ADDR_LEN] = {0};
	if (!data_obj)
	{
		AF_ERROR("data obj is null\n");
		return -1;
	}
	mac_arr = cJSON_GetObjectItem(data_obj, "mac_list");
	if (!mac_arr)
	{
		AF_ERROR("mac_list obj is null\n");
		return -1;
	}	
	af_whitelist_mac_flush();
	for (i = 0; i < cJSON_GetArraySize(mac_arr); i++)
	{
		cJSON *mac_obj = cJSON_GetArrayItem(mac_arr, i);
		if (!mac_obj)
		{
			AF_ERROR("mac obj is null\n");
			return -1;
		}
		if (-1 == mac_to_hex(mac_obj->valuestring, mac_hex))
		{
			continue;
		}
		af_whitelist_mac_add(mac_hex);
	}
	return 0;
}
