#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include "app_filter.h"
#include "af_log.h"
int af_log_lvl = 1;
int af_test_mode = 0;
// todo: rename af_log.c
int g_oaf_enable __read_mostly = 0;
int af_work_mode = AF_MODE_GATEWAY;
unsigned int af_lan_ip = 0;
unsigned int af_lan_mask = 0;
/* 
	cat /proc/sys/oaf/debug
*/
static struct ctl_table oaf_table[] = {
	{
		.procname	= "debug",
		.data		= &af_log_lvl,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "test_mode",
		.data		= &af_test_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable",
		.data		= &g_oaf_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "work_mode",
		.data		= &af_work_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ip",
		.data		= &af_lan_ip,
		.maxlen = 	sizeof(unsigned int),
		.mode		= 0666,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname = "lan_mask",
		.data = &af_lan_mask,
		.maxlen = sizeof(unsigned int),
		.mode = 0666,
		.proc_handler = proc_douintvec,
	},
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
	{}
#endif
};

static struct ctl_table oaf_root_table[] = {
	{
		.procname	= "oaf",
		.mode		= 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child		= oaf_table,
#endif
	},
	{}
};
static struct ctl_table_header *oaf_table_header;


static int af_init_log_sysctl(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
	oaf_table_header = register_sysctl_table(oaf_root_table);
#else
	oaf_table_header = register_sysctl(oaf_root_table->procname, oaf_table);
#endif
	if (oaf_table_header == NULL){
		printk("init log sysctl...failed\n");
		return -ENOMEM;
	}
	printk("init oaf sysctl...ok\n");
	return 0;
}

static int af_fini_log_sysctl(void)
{
	if (oaf_table_header)
		unregister_sysctl_table(oaf_table_header);
	return 0;
}

int af_log_init(void){
	af_init_log_sysctl();
	return 0;
}

int af_log_exit(void){
	af_fini_log_sysctl();
	return 0;
}
