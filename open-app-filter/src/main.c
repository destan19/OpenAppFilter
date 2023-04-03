/*
Copyright (C) 2020 Derry <destan19@126.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "appfilter_user.h"
#include "appfilter_netlink.h"
#include "appfilter_ubus.h"
#include "appfilter_config.h"
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "appfilter.h"


void check_appfilter_enable(void)
{
    int enable = 1;
    struct tm *t;
	af_ctl_time_t *af_t = NULL;
    time_t tt;
    time(&tt);
    enable = config_get_appfilter_enable();

    if (0 == enable)
        goto EXIT;
    af_t = load_appfilter_ctl_time_config();
    if (!af_t)
    {
        enable = 0;
        goto EXIT;
    }

    t = localtime(&tt);
    if (af_t->days[t->tm_wday] != 1)
    {
        if (af_t->time_mode == 0){
            enable = 0;
            goto EXIT;
        }
    }

    int cur_mins = t->tm_hour * 60 + t->tm_min;
    if (((af_t->start.hour * 60 + af_t->start.min < cur_mins) && (cur_mins < af_t->end.hour * 60 + af_t->end.min))
        || ((af_t->start2.hour * 60 + af_t->start2.min < cur_mins) && (cur_mins < af_t->end2.hour * 60 + af_t->end2.min))
    )
    {
        if (af_t->time_mode == 0){
            enable = 1;
        }
        else{
            enable = 0;
        }
    }
    else{
        if (af_t->time_mode == 0){
            enable = 0;
        }
        else{
            enable = 1;
        }
    }
EXIT:
    if (enable)
    {
        system("echo 1 >/proc/sys/oaf/enable ");
    }
    else
        system("echo 0 >/proc/sys/oaf/enable ");
	if (af_t)
   		free(af_t);
}

void update_lan_ip(void){
    char ip_str[32] = {0};
	char mask_str[32] = {0};
    struct in_addr addr;
	struct in_addr mask_addr;
    char cmd_buf[128] = {0};
    u_int32_t lan_ip = 0;
	u_int32_t lan_mask = 0;
	
    exec_with_result_line(CMD_GET_LAN_IP, ip_str, sizeof(ip_str));
    if (strlen(ip_str) < MIN_INET_ADDR_LEN){
        sprintf(cmd_buf, "echo 0 >/proc/sys/oaf/lan_ip");
    }
    else{
        inet_aton(ip_str, &addr);
        lan_ip = addr.s_addr;
        sprintf(cmd_buf, "echo %u >/proc/sys/oaf/lan_ip", lan_ip);
    }
	system(cmd_buf);
    exec_with_result_line(CMD_GET_LAN_MASK, mask_str, sizeof(mask_str));

    if (strlen(mask_str) < MIN_INET_ADDR_LEN){
        sprintf(cmd_buf, "echo 0 >/proc/sys/oaf/lan_mask");
    }
    else{
        inet_aton(mask_str, &mask_addr);
        lan_mask = mask_addr.s_addr;
        sprintf(cmd_buf, "echo %u >/proc/sys/oaf/lan_mask", lan_mask);
    }
    system(cmd_buf);
}

void dev_list_timeout_handler(struct uloop_timeout *t)
{
    dump_dev_list();
    check_dev_visit_info_expire();
    flush_expire_visit_info();
    //dump_dev_visit_list();
    update_lan_ip();
    check_appfilter_enable();
    if (check_dev_expire()){
        flush_expire_visit_info();
        flush_dev_expire_node();
    }
    uloop_timeout_set(t, 10000);
}

struct uloop_timeout dev_tm = {
    .cb = dev_list_timeout_handler};

static struct uloop_fd appfilter_nl_fd = {
    .cb = appfilter_nl_handler,
};

int main(int argc, char **argv)
{
    int ret = 0;
    uloop_init();
    printf("init appfilter\n");
    init_dev_node_htable();
    init_app_name_table();
    init_app_class_name_table();
    if (appfilter_ubus_init() < 0)
    {
        fprintf(stderr, "Failed to connect to ubus\n");
        return 1;
    }   


    appfilter_nl_fd.fd = appfilter_nl_init();
    uloop_fd_add(&appfilter_nl_fd, ULOOP_READ);
    af_msg_t msg;
    msg.action = AF_MSG_INIT;
    send_msg_to_kernel(appfilter_nl_fd.fd, (void *)&msg, sizeof(msg));
    uloop_timeout_set(&dev_tm, 5000);
    uloop_timeout_add(&dev_tm);
    uloop_run();
    uloop_done();
    return 0;
}
