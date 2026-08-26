// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include "fwx.h"
#include "fwx_log.h"
#include "fwx_mac_filter.h"
#include "fwx_app_filter.h"
#include "fwx_client.h"
int af_log_lvl = 0;
int fwx_test_mode = 0;

int g_record_enable = 0;
int g_by_pass_accl = 1;
int g_user_mode = 0;
int af_work_mode = AF_MODE_GATEWAY;
unsigned int fwx_lan_ip = 0;
unsigned int fwx_lan_mask = 0;
char g_lan_ifname[64] = "br-lan";
int g_tcp_rst = 1;
int g_feature_init = 0;
char g_fwx_version[64] = FWX_VERSION;
int g_feature_count = 0;
char g_record_whitelist[1024] = {0};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
static int fwx_proc_record_whitelist_handler(struct ctl_table *table, int write,
					      void *buffer, size_t *lenp, loff_t *ppos)
#else
static int fwx_proc_record_whitelist_handler(const struct ctl_table *table, int write,
					      void *buffer, size_t *lenp, loff_t *ppos)
#endif
{
	int ret = 0;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret || !write) {
		return ret;
	}

	fwx_set_record_whitelist(g_record_whitelist);
	return ret;
}

static struct ctl_table fwx_table[] = {
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
		.data		= g_fwx_version,
		.maxlen 	= 64,
		.mode		= 0444,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "feature_count",
		.data		= &g_feature_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "test_mode",
		.data		= &fwx_test_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "appfilter_enable",
		.data		= &g_appfilter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "macfilter_enable",
		.data		= &g_mac_filter_enable,
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
		.data		= &g_record_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "record_whitelist",
		.data		= g_record_whitelist,
		.maxlen 	= sizeof(g_record_whitelist),
		.mode		= 0666,
		.proc_handler	= fwx_proc_record_whitelist_handler,
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
		.data		= &fwx_lan_ip,
		.maxlen = 	sizeof(unsigned int),
		.mode		= 0666,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname = "lan_mask",
		.data = &fwx_lan_mask,
		.maxlen = sizeof(unsigned int),
		.mode = 0666,
		.proc_handler = proc_douintvec,
	},
	{
		.procname	= "max_app_report_count",
		.data		= &g_max_app_report_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "min_http_match_count",
		.data		= &g_min_http_match_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
		
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
	{
	}
#endif
};
#define FWX_SYS_PROC_DIR "fwx"

static struct ctl_table fwx_root_table[] = {
	{
		.procname	= FWX_SYS_PROC_DIR,
		.mode		= 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child		= fwx_table,
#endif
	},
	{}
};
static struct ctl_table_header *fwx_table_header;


static int af_init_log_sysctl(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		fwx_table_header = register_sysctl_table(fwx_root_table);
#else
	fwx_table_header = register_sysctl(FWX_SYS_PROC_DIR, fwx_table);
#endif
	if (fwx_table_header == NULL){
		printk("init log sysctl...failed\n");
		return -ENOMEM;
	}
	return 0;
}

static int af_fini_log_sysctl(void)
{
	if (fwx_table_header)
		unregister_sysctl_table(fwx_table_header);
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
