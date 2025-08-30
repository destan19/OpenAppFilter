#ifndef __AF_CONFIG_H__
#define __AF_CONFIG_H__
#include "app_filter.h"

enum AF_CONFIG_CMD
{
	AF_CMD_ADD_APPID = 1,
	AF_CMD_DEL_APPID,
	AF_CMD_CLEAN_APPID,
	AF_CMD_SET_MAC_LIST,
	AF_CMD_SET_WHITELIST_MAC_LIST,
};

typedef int (*af_config_handler_t)(cJSON *data);

struct af_config_interface
{
	enum AF_CONFIG_CMD cmd;
	af_config_handler_t handler;
	const char *description;
};

int af_register_dev(void);
void af_unregister_dev(void);

int af_config_add_appid(cJSON *data);
int af_config_del_appid(cJSON *data);
int af_config_clean_appid(cJSON *data);
int af_config_set_mac_list(cJSON *data);
int af_config_set_whitelist_mac_list(cJSON *data);


#endif