#include <linux/init.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/version.h>
#include "cJSON.h"
#include "app_filter.h"
#include "af_config.h"
#include "af_utils.h"
#include "af_log.h"
#include "af_rule_config.h"
#include "af_user_config.h"
#include "af_whitelist_config.h"

#define AF_DEV_NAME "appfilter"

extern u_int32_t g_update_jiffies;

static struct mutex af_cdev_mutex;
struct af_config_dev
{
	dev_t id;
	struct cdev char_dev;
	struct class *c;
};
struct af_config_dev g_af_dev;

struct af_cdev_file
{
	size_t size;
	char buf[256 << 10];
};

static struct af_config_interface af_config_interfaces[] = {
	{AF_CMD_ADD_APPID, af_config_add_appid, "Add App ID"},
	{AF_CMD_DEL_APPID, af_config_del_appid, "Delete App ID"},
	{AF_CMD_CLEAN_APPID, af_config_clean_appid, "Clean App ID"},
	{AF_CMD_SET_MAC_LIST, af_config_set_mac_list, "Set MAC List"},
	{AF_CMD_SET_WHITELIST_MAC_LIST, af_config_set_whitelist_mac_list, "Set Whitelist MAC List"},
	{0, NULL, NULL} 
};

static af_config_handler_t af_find_handler(enum AF_CONFIG_CMD cmd)
{
	struct af_config_interface *interface = af_config_interfaces;
	
	while (interface->handler != NULL) {
		if (interface->cmd == cmd) {
			return interface->handler;
		}
		interface++;
	}
	return NULL;
}

/*
add:
{
	"op":1,
	"data":{
		"apps":[]
	}
}
clean
{
	"op":3,
}
*/
int af_config_handle(char *config, unsigned int len)
{
	cJSON *config_obj = NULL;
	cJSON *cmd_obj = NULL;
	cJSON *data_obj = NULL;
	int ret = 0;
	af_config_handler_t handler = NULL;
	
	if (!config || len == 0)
	{
		AF_ERROR("config or len is invalid\n");
		return -1;
	}
	
	AF_DEBUG("config = %s\n", config);
	config_obj = cJSON_Parse(config);
	if (!config_obj)
	{
		AF_ERROR("config_obj is NULL\n");
		cJSON_Delete(config_obj);
		return -1;
	}
	
	cmd_obj = cJSON_GetObjectItem(config_obj, "op");
	if (!cmd_obj)
	{
		AF_ERROR("not find op object\n");
		cJSON_Delete(config_obj);
		return -1;
	}
	
	data_obj = cJSON_GetObjectItem(config_obj, "data");

	handler = af_find_handler(cmd_obj->valueint);
	if (handler) {
		ret = handler(data_obj);
		g_update_jiffies = jiffies;
		cJSON_Delete(config_obj);
		return ret;
	} else {
		AF_ERROR("invalid cmd %d\n", cmd_obj->valueint);
		cJSON_Delete(config_obj);
		return -1;
	}
}


static int af_cdev_open(struct inode *inode, struct file *filp)
{
	struct af_cdev_file *file;
	file = vzalloc(sizeof(*file));
	if (!file)
		return -EINVAL;

	mutex_lock(&af_cdev_mutex);
	filp->private_data = file;
	return 0;
}

static ssize_t af_cdev_read(struct file *filp, char *buf, size_t count, loff_t *off)
{
	return 0;
}

static int af_cdev_release(struct inode *inode, struct file *filp)
{
	struct af_cdev_file *file = filp->private_data;
	AF_DEBUG("config size: %d,data = %s\n", (int)file->size, file->buf);
	af_config_handle(file->buf, file->size);
	filp->private_data = NULL;
	mutex_unlock(&af_cdev_mutex);
	vfree(file);
	return 0;
}

static ssize_t af_cdev_write(struct file *filp, const char *buffer, size_t count, loff_t *off)
{
	struct af_cdev_file *file = filp->private_data;
	int ret;
	if (file->size + count > sizeof(file->buf))
	{
		AF_ERROR("config overflow, cur_size: %d, block_size: %d, max_size: %d",
				 (int)file->size, (int)count, (int)sizeof(file->buf));
		return -EINVAL;
	}

	ret = copy_from_user(file->buf + file->size, buffer, count);
	if (ret != 0)
		return -EINVAL;

	file->size += count;
	return count;
}

static struct file_operations af_cdev_ops = {
	owner : THIS_MODULE,
	release : af_cdev_release,
	open : af_cdev_open,
	write : af_cdev_write,
	read : af_cdev_read,
};

int af_register_dev(void)
{
	struct device *dev;
	int res;
	mutex_init(&af_cdev_mutex);

	res = alloc_chrdev_region(&g_af_dev.id, 0, 1, AF_DEV_NAME);
	if (res != 0)
	{
		return -EINVAL;
	}

	cdev_init(&g_af_dev.char_dev, &af_cdev_ops);
	res = cdev_add(&g_af_dev.char_dev, g_af_dev.id, 1);
	if (res < 0)
	{
		goto REGION_OUT;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	g_af_dev.c = class_create(THIS_MODULE, AF_DEV_NAME);
#else
    g_af_dev.c = class_create(AF_DEV_NAME);
#endif
	if (IS_ERR_OR_NULL(g_af_dev.c))
	{
		goto CDEV_OUT;
	}

	dev = device_create(g_af_dev.c, NULL, g_af_dev.id, NULL, AF_DEV_NAME);
	if (IS_ERR_OR_NULL(dev))
	{
		goto CLASS_OUT;
	}
	AF_INFO("register char dev....ok\n");
	return 0;

CLASS_OUT:
	class_destroy(g_af_dev.c);
CDEV_OUT:
	cdev_del(&g_af_dev.char_dev);
REGION_OUT:
	unregister_chrdev_region(g_af_dev.id, 1);

	AF_ERROR("register char dev....fail\n");
	return -EINVAL;
}

void af_unregister_dev(void)
{
	device_destroy(g_af_dev.c, g_af_dev.id);
	class_destroy(g_af_dev.c);
	cdev_del(&g_af_dev.char_dev);
	unregister_chrdev_region(g_af_dev.id, 1);
	AF_INFO("unregister char dev....ok\n");
}
