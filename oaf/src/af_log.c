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
int g_oaf_filter_enable __read_mostly = 0;
int g_oaf_record_enable __read_mostly = 0;
int g_by_pass_accl = 1;
int g_user_mode = 0;
int af_work_mode = AF_MODE_GATEWAY;
unsigned int af_lan_ip = 0;
unsigned int af_lan_mask = 0;
char g_lan_ifname[64] = "br-lan";
int g_tcp_rst = 1;
int g_feature_init = 0;
char g_oaf_version[64] = AF_VERSION;
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
		.procname	= "feature_init",
		.data		= &g_feature_init,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "version",
		.data		= g_oaf_version,
		.maxlen 	= 64,
		.mode		= 0444,
		.proc_handler = proc_dostring,
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
		.data		= &g_oaf_filter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "by_pass_accl",
		.data		= &g_by_pass_accl,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_rst",
		.data		= &g_tcp_rst,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ifname",
		.data		= g_lan_ifname,
		.maxlen 	= 64,
		.mode		= 0666,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "record_enable",
		.data		= &g_oaf_record_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "user_mode",
		.data		= &g_user_mode,
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
	{
	}
#endif
};
#define OAF_SYS_PROC_DIR "oaf"

static struct ctl_table oaf_root_table[] = {
	{
		.procname	= OAF_SYS_PROC_DIR,
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
	oaf_table_header = register_sysctl(OAF_SYS_PROC_DIR, oaf_table);
#endif
	if (oaf_table_header == NULL){
		printk("init log sysctl...failed\n");
		return -ENOMEM;
	}
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
