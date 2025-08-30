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
#include "af_user_config.h"

DEFINE_RWLOCK(af_mac_lock);

u32 total_mac = 0;
struct list_head af_mac_htable[MAX_AF_MAC_HASH_SIZE];
void af_mac_list_init(void)
{
	int i;
	write_lock_bh(&af_mac_lock);
	for (i = 0; i < MAX_AF_MAC_HASH_SIZE; i++)
	{
		INIT_LIST_HEAD(&af_mac_htable[i]);
	}
	write_unlock_bh(&af_mac_lock);
}

void af_mac_list_flush(void)
{
	int i;
	af_mac_node_t *p = NULL;
	char mac_str[32] = {0};
	write_lock_bh(&af_mac_lock);
	for (i = 0; i < MAX_AF_MAC_HASH_SIZE; i++)
	{
		while (!list_empty(&af_mac_htable[i]))
		{
			p = list_first_entry(&af_mac_htable[i], af_mac_node_t, list);
			memset(mac_str, 0x0, sizeof(mac_str));
			sprintf(mac_str, MAC_FMT, MAC_ARRAY(p->mac));
			list_del(&(p->list));
			kfree(p);
		}
	}
	total_mac = 0;
	write_unlock_bh(&af_mac_lock);
}

af_mac_node_t *af_mac_find(unsigned char *mac)
{
	af_mac_node_t *node;
	unsigned int index;

	index = hash_mac(mac);
	read_lock_bh(&af_mac_lock);
	list_for_each_entry(node, &af_mac_htable[index], list)
	{
		if (0 == memcmp(node->mac, mac, 6))
		{
			read_unlock_bh(&af_mac_lock);
			return node;
		}
	}
	read_unlock_bh(&af_mac_lock);
	return NULL;
}

af_mac_node_t *af_mac_add(unsigned char *mac)
{
	af_mac_node_t *node;
	int index = 0;

	node = (af_mac_node_t *)kmalloc(sizeof(af_mac_node_t), GFP_ATOMIC);
	if (node == NULL)
	{
		return NULL;
	}

	memset(node, 0, sizeof(af_mac_node_t));
	memcpy(node->mac, mac, MAC_ADDR_LEN);

	index = hash_mac(mac);

	printk("add user mac=" MAC_FMT "\n", MAC_ARRAY(node->mac));
	total_mac++;
	write_lock_bh(&af_mac_lock);
	list_add(&(node->list), &af_mac_htable[index]);
	write_unlock_bh(&af_mac_lock);
	return node;
}

int is_user_match_enable(void)
{
	return total_mac > 0;
}



int af_config_set_mac_list(cJSON *data_obj)
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
	af_mac_list_flush();
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
		af_mac_add(mac_hex);
	}
	AF_DEBUG("## mac num = %d\n", total_mac);
	return 0;
}
