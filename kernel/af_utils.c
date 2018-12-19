#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "af_utils.h"

int check_local_network_ip(unsigned int ip)
{
	if ((ip & 0xffff0000) == 0xc0a80000)
		return 1;
	else if ((ip & 0xfff00000) == 0xac100000)
		return 1;
	else if ((ip & 0xff000000) == 0x0a000000)
		return 1;
	else
		return 0;
}

void dump_str(char *name, unsigned char *p, int len)
{
	#define MAX_DUMP_STR_LEN 64
	int i;
	if (len > MAX_DUMP_STR_LEN) {
		len = MAX_DUMP_STR_LEN - 1;
	}
	printk("%s: ",name);
	for (i = 0; i < len; i++) {
		printk("%c",*(p + i));
	}
	printk("\n");
}

void dump_hex(char *name, unsigned char *p, int len)
{
	#define MAX_DUMP_STR_LEN 64
	int i;
	if (len > MAX_DUMP_STR_LEN) {
		len = MAX_DUMP_STR_LEN - 1;
	}
	printk("%s: ",name);
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printk("\n");
		printk("%02X ",*(p + i));
	}
	printk("\n");
}

