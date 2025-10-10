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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <json-c/json.h>
#include "appfilter_user.h"
#include "appfilter_netlink.h"
#include "appfilter.h"
#include "appfilter_config.h"

#define MAX_NL_RCV_BUF_SIZE 4096

#define REPORT_INTERVAL_SECS 60
extern int hash_appid(int appid);
extern unsigned int g_feature_update_time;
void appfilter_nl_handler(struct uloop_fd *u, unsigned int ev)
{
    int ret;
    int i;
    char buf[MAX_NL_RCV_BUF_SIZE];
    struct sockaddr_nl nladdr;
    struct iovec iov = {buf, sizeof(buf)};
    struct nlmsghdr *h;
    int type;
    int id;
    char *mac = NULL;
    u_int32_t cur_time = get_timestamp();

    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    do
    {
        ret = recvmsg(u->fd, &msg, 0);
    } while ((-1 == ret) && (EINTR == errno));

    if (ret < 0)
    {
        printf("recv msg error\n");
        return;
    }
    else if (0 == ret)
    {
        return;
    }

    h = (struct nlmsghdr *)buf;
    char *kmsg = (char *)NLMSG_DATA(h);
    struct af_msg_hdr *af_hdr = (struct af_msg_hdr *)kmsg;
    if (af_hdr->magic != 0xa0b0c0d0)
    {
        printf("magic error %x\n", af_hdr->magic);
        return;
    }

    if (af_hdr->len <= 0 || af_hdr->len >= MAX_OAF_NETLINK_MSG_LEN)
    {
        printf("data len error\n");
        return;
    }

    char *kdata = kmsg + sizeof(struct af_msg_hdr);
    struct json_object *root = json_tokener_parse(kdata);
    if (!root)
    {
        printf("parse json failed:%s", kdata);
        return;
    }

    LOG_DEBUG("report %s\n", kdata);
    struct json_object *mac_obj = json_object_object_get(root, "mac");

    if (!mac_obj)
    {
        printf("parse mac obj failed\n");
        json_object_put(root);
        return;
    }

    mac = json_object_get_string(mac_obj);

    dev_node_t *node = find_dev_node(mac);

    if (!node)
    {
        node = add_dev_node(mac);
        if (!node)
        {
            goto EXIT;
        }
    }

    struct json_object *ip_obj = json_object_object_get(root, "ip");
    if (ip_obj)
        strncpy(node->ip, json_object_get_string(ip_obj), sizeof(node->ip));


    struct json_object *visit_array = json_object_object_get(root, "visit_info");
    if (!visit_array)
    {
       goto EXIT;
    }


    for (i = 0; i < json_object_array_length(visit_array); i++)
    {
        struct json_object *visit_obj = json_object_array_get_idx(visit_array, i);
        struct json_object *appid_obj = json_object_object_get(visit_obj, "appid");
        struct json_object *action_obj = json_object_object_get(visit_obj, "latest_action");

        // old appid may be not in the feature list
        if (cur_time - g_feature_update_time < 300){
            if (strlen(get_app_name_by_id(json_object_get_int(appid_obj))) == 0){
                LOG_INFO("ignore appid %d because it is not in the feature list\n", json_object_get_int(appid_obj)); 
                continue;
            }
        }

        int appid = json_object_get_int(appid_obj);
        int action = json_object_get_int(action_obj);

        type = appid / 1000;
        id = appid % 1000;
        if (id <= 0 || type <= 0)
            continue;
        node->stat[type - 1][id - 1].total_time += REPORT_INTERVAL_SECS;
        int hash = hash_appid(appid);
        visit_info_t *head = node->visit_htable[hash];
        visit_info_t *p = head;
        while(p){
            if((p->appid == appid) && (cur_time - p->latest_time < 300)){
                LOG_DEBUG("match appid = %d\n", appid, cur_time - p->latest_time);
                break;
            }
            p = p->next;
        }
        if (!p){
            p = (visit_info_t *)calloc(1, sizeof(visit_info_t));
            p->appid = appid;
            p->next = NULL;
            p->first_time = cur_time;
            add_visit_info_node(&node->visit_htable[hash], p);
        }
        p->action = action;
        p->latest_time = cur_time;
    }
EXIT:
    json_object_put(root);
}

#define MAX_NL_MSG_LEN 1024
int send_msg_to_kernel(int fd, void *msg, int len)
{
    struct sockaddr_nl saddr, daddr;
    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;
    int ret = 0;
    struct nlmsghdr *nlh = NULL;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_NL_MSG_LEN));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_NL_MSG_LEN);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = DEFAULT_USR_NL_PID;

    char msg_buf[MAX_NL_MSG_LEN] = {0};
    struct af_msg_hdr *hdr = (struct af_msg_hdr *)msg_buf;
    hdr->magic = 0xa0b0c0d0;
    hdr->len = len;
    char *p_data = msg_buf + sizeof(struct af_msg_hdr);
    memcpy(p_data, msg, len);

    memcpy(NLMSG_DATA(nlh), msg_buf, len + sizeof(struct af_msg_hdr));

    ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
	free(nlh);
    if (!ret)
    {
        perror("sendto error\n");
        return -1;
    }

    return 0;
}

int appfilter_nl_init(void)
{
    int fd;
    struct sockaddr_nl nls;
    fd = socket(AF_NETLINK, SOCK_RAW, OAF_NETLINK_ID);
    if (fd < 0)
    {
        LOG_DEBUG("Connect netlink %d failed %s\n", OAF_NETLINK_ID, strerror(errno));
        return -1;
    }
    memset(&nls, 0, sizeof(struct sockaddr_nl));
    nls.nl_pid = DEFAULT_USR_NL_PID;
    nls.nl_groups = 0;
    nls.nl_family = AF_NETLINK;

    if (bind(fd, (void *)&nls, sizeof(struct sockaddr_nl)))
    {
        LOG_DEBUG("Bind failed %s\n", strerror(errno));
        return -1;
    }

    return fd;
}
