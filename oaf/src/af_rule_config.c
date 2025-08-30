#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#include "cJSON.h"
#include "app_filter.h"
#include "af_utils.h"
#include "af_log.h"

#define AF_MAX_APP_TYPE_NUM 32
#define AF_MAX_APP_NUM 512

DEFINE_RWLOCK(af_rule_lock);

#define af_rule_read_lock() read_lock_bh(&af_rule_lock);
#define af_rule_read_unlock() read_unlock_bh(&af_rule_lock);
#define af_rule_write_lock() write_lock_bh(&af_rule_lock);
#define af_rule_write_unlock() write_unlock_bh(&af_rule_lock);

extern u_int32_t g_update_jiffies;

char g_app_id_array[AF_MAX_APP_TYPE_NUM][AF_MAX_APP_NUM] = {0};

void af_show_app_status(void)
{
	int i, j;
	for (i = 0; i < AF_MAX_APP_TYPE_NUM; i++)
	{
		for (j = 0; j < AF_MAX_APP_NUM; j++)
		{
			af_rule_read_lock();
			if (g_app_id_array[i][j] == AF_TRUE)
			{
				AF_DEBUG("%d, %d\n", i, j);
			}
			af_rule_read_unlock();
		}
	}

	AF_DEBUG("\n\n\n");
}

int af_change_app_status(cJSON *data_obj, int status)
{
	int i;
	int id;
	int type;
	cJSON *appid_arr = NULL;
	if (!data_obj)
	{
		AF_ERROR("data obj is null\n");
		return -1;
	}
	appid_arr = cJSON_GetObjectItem(data_obj, "apps");
	if (!appid_arr)
	{
		AF_ERROR("apps obj is null\n");
		return -1;
	}
	for (i = 0; i < cJSON_GetArraySize(appid_arr); i++)
	{
		cJSON *appid_obj = cJSON_GetArrayItem(appid_arr, i);
		if (!appid_obj)
			return -1;
		id = AF_APP_ID(appid_obj->valueint);
		type = AF_APP_TYPE(appid_obj->valueint);
		af_rule_write_lock();
		g_app_id_array[type][id] = status;
		af_rule_write_unlock();
	}

	return 0;
}



void af_init_app_status(void)
{
	int i, j;

	for (i = 0; i < AF_MAX_APP_TYPE_NUM; i++)
	{
		for (j = 0; j < AF_MAX_APP_NUM; j++)
		{
			af_rule_write_lock();
			g_app_id_array[i][j] = AF_FALSE;
			af_rule_write_unlock();
		}
	}
}
int af_get_app_status(int appid)
{
	int status = 0;
	int id = AF_APP_ID(appid);
	int type = AF_APP_TYPE(appid);
	af_rule_read_lock();
	status = g_app_id_array[type][id];
	af_rule_read_unlock();
	return status;
}

int af_config_add_appid(cJSON *data)
{
	return af_change_app_status(data, 1);
}

int af_config_del_appid(cJSON *data)
{
	return af_change_app_status(data, 0);
}

int af_config_clean_appid(cJSON *data)
{
	af_init_app_status();
	return 0;
}