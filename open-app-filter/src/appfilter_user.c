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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <json-c/json.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include "appfilter_config.h"
#include "appfilter.h"
#include "appfilter_user.h"

dev_node_t *dev_hash_table[MAX_DEV_NODE_HASH_SIZE];
int g_cur_user_num = 0;
unsigned int hash_mac(unsigned char *mac)
{
    if (!mac)
        return 0;
    else
        return mac[0] & (MAX_DEV_NODE_HASH_SIZE - 1);
}

int hash_appid(int appid)
{
    return appid % (MAX_VISIT_HASH_SIZE - 1);
}

void add_visit_info_node(visit_info_t **head, visit_info_t *node)
{
    if (*head == NULL)
    {
        *head = node;
    }
    else
    {
        node->next = *head;
        *head = node;
    }
}

void init_dev_node_htable()
{
    int i;
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_hash_table[i] = NULL;
    }
    printf("init dev node htable ok...\n");
}

dev_node_t *add_dev_node(char *mac)
{
    unsigned int hash = 0;
    hash = hash_mac(mac);
    if (hash >= MAX_DEV_NODE_HASH_SIZE)
    {
        printf("hash code error %d\n", hash);
        return NULL;
    }
    dev_node_t *node = (dev_node_t *)calloc(1, sizeof(dev_node_t));
    if (!node)
        return NULL;
    strncpy(node->mac, mac, sizeof(node->mac));
    node->online = 1;
    node->online_time = get_timestamp();
    if (dev_hash_table[hash] == NULL)
        dev_hash_table[hash] = node;
    else
    {
        node->next = dev_hash_table[hash];
        dev_hash_table[hash] = node;
    }
    g_cur_user_num++;
    printf("add mac:%s to htable[%d]....success\n", mac, hash);
    return node;
}

dev_node_t *find_dev_node(char *mac)
{
    unsigned int hash = 0;
    dev_node_t *p = NULL;
    hash = hash_mac(mac);
    if (hash >= MAX_DEV_NODE_HASH_SIZE)
    {
        printf("hash code error %d\n", hash);
        return NULL;
    }
    p = dev_hash_table[hash];
    while (p)
    {
        if (0 == strncmp(p->mac, mac, sizeof(p->mac)))
        {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

void dev_foreach(void *arg, iter_func iter)
{
    int i, j;
    dev_node_t *node = NULL;

    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            iter(arg, node);
            node = node->next;
        }
    }
}

char *format_time(int timetamp)
{
    char time_buf[64] = {0};
    time_t seconds = timetamp;
    struct tm *auth_tm = localtime(&seconds);
    strftime(time_buf, sizeof(time_buf), "%Y %m %d %H:%M:%S", auth_tm);
    return strdup(time_buf);
}

void update_dev_hostname(void)
{
    char line_buf[256] = {0};
    char hostname_buf[128] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};

    FILE *fp = fopen("/tmp/dhcp.leases", "r");
    if (!fp)
    {
        printf("open dhcp lease file....failed\n");
        return;
    }
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        if (strlen(line_buf) <= 16)
            continue;
        sscanf(line_buf, "%*s %s %s %s", mac_buf, ip_buf, hostname_buf);
        dev_node_t *node = find_dev_node(mac_buf);
        if (!node)
        {
            node = add_dev_node(mac_buf);
			if (!node)
				continue;
            strncpy(node->ip, ip_buf, sizeof(node->ip));
            node->online = 0;
            node->offline_time = get_timestamp();
        }

        if (strlen(hostname_buf) > 0 && hostname_buf[0] != '*')
        {
            strncpy(node->hostname, hostname_buf, sizeof(node->hostname));
        }
    }
    fclose(fp);
}

void clean_dev_nickname_iter(void *arg, dev_node_t *node)
{
    node->nickname[0] = '\0';
}

void clean_dev_nickname(void)
{
    dev_foreach(NULL, clean_dev_nickname_iter);
}

void update_dev_nickname(void)
{
    char nickname_buf[128] = {0};
    char mac_str[128] = {0};
    struct uci_context *uci_ctx = uci_alloc_context();
    clean_dev_nickname();
    int num = af_get_uci_list_num(uci_ctx, "user_info", "user_info");

    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].mac", i, mac_str, sizeof(mac_str));
        dev_node_t *node = find_dev_node(mac_str);
        if (!node)
            continue;

        af_uci_get_array_value(uci_ctx, "user_info.@user_info[%d].nickname", i, nickname_buf, sizeof(nickname_buf));
        printf("update dev nickname: %s\n", nickname_buf);
        strncpy(node->nickname, nickname_buf, sizeof(node->nickname));
    }   
    printf("update dev nickname ok\n");
    uci_free_context(uci_ctx);
}


void clean_dev_whitelist_flag_iter(void *arg, dev_node_t *node)
{
    node->is_whitelist = 0;
}

void clean_dev_whitelist_flag(void)
{
    dev_foreach(NULL, clean_dev_whitelist_flag_iter);
}


void update_dev_whitelist_flag(void)
{
    clean_dev_whitelist_flag();
    dev_node_t *node = NULL;
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        return;
    }
    char mac_str[128] = {0};
    int num = af_get_uci_list_num(uci_ctx, "appfilter", "whitelist");
    for (int i = 0; i < num; i++) {
        af_uci_get_array_value(uci_ctx, "appfilter.@whitelist[%d].mac", i, mac_str, sizeof(mac_str));
        node = find_dev_node(mac_str);
        if (node) {
            node->is_whitelist = 1;
        }
    }
    uci_free_context(uci_ctx);
}



void clean_dev_online_status(void)
{
    int i;
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {

            if (node->online)
            {
                node->offline_time = get_timestamp();
                node->online = 0;
            }
            node = node->next;
        }
    }

}

/*
Id   Mac                  Ip
1    10:bf:48:37:0c:94    192.168.66.244
*/
void update_dev_from_oaf(void)
{
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char ip_buf[32] = {0};

    FILE *fp = fopen("/proc/net/af_client", "r");
    if (!fp)
    {
        printf("open dev file....failed\n");
        return;
    }
    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))
    {
        sscanf(line_buf, "%*s %s %s", mac_buf, ip_buf);
        if (strlen(mac_buf) < 17)
        {
            printf("invalid mac:%s\n", mac_buf);
            continue;
        }
        dev_node_t *node = find_dev_node(mac_buf);
        if (!node)
        {
            node = add_dev_node(mac_buf);
            if (!node)
                continue;
            strncpy(node->ip, ip_buf, sizeof(node->ip));
        }
        node->online = 1;
    }
    fclose(fp);
}

void update_dev_online_status(void)
{
    update_dev_from_oaf();
}

#define DEV_OFFLINE_TIME (SECONDS_PER_DAY * 7)

int check_dev_expire(void)
{
    int i, j;
    int count = 0;
    int cur_time = get_timestamp();
    int offline_time = 0;
    int expire_count = 0;
    int visit_count = 0;
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            if (node->online)
                goto NEXT;
            visit_count = 0;
            offline_time = cur_time - node->offline_time;
            if (offline_time > DEV_OFFLINE_TIME)
            {
                node->expire = 1;
                for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
                {
                    visit_info_t *p_info = node->visit_htable[j];
                    while (p_info)
                    {
                        p_info->expire = 1;
                        visit_count++;
                        p_info = p_info->next;
                    }
                }
                expire_count++;
                LOG_WARN("dev:%s expired, offline time = %ds, count=%d, visit_count=%d\n",
                       node->mac, offline_time, expire_count, visit_count);
            }
        NEXT:
            node = node->next;
        }
    }
    return expire_count;
}

void flush_dev_expire_node(void)
{
    int i, j;
    int count = 0;
    dev_node_t *node = NULL;
    dev_node_t *prev = NULL;
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        prev = NULL;
        while (node)
        {
            if (node->expire)
            {
                if (NULL == prev)
                {
                    dev_hash_table[i] = node->next;
                    free(node);
                    node = dev_hash_table[i];
                    prev = NULL;
                }
                else
                {
                    prev->next = node->next;
                    free(node);
                    node = prev->next;
                }
            }
            else
            {
                prev = node;
                node = node->next;
            }
        }
    }
}

void update_dev_visiting_info(void){
    char line_buf[256] = {0};
    char mac_buf[32] = {0};
    char url_buf[32] = {0};
    char app_buf[32] = {0};
    char time_buf[32] = {0};

    FILE *fp = fopen("/proc/net/af_visit", "r");    
    if (!fp)
    {
        printf("open af_visit file....failed\n");
        return;
    }
    fgets(line_buf, sizeof(line_buf), fp); // title
    while (fgets(line_buf, sizeof(line_buf), fp))   
    {
        sscanf(line_buf, "%s %s %s", mac_buf, app_buf, url_buf);
        dev_node_t *node = find_dev_node(mac_buf);
        if (!node)
            continue;
        if (strcmp(url_buf, "none") == 0) {
            node->visiting_url[0] = '\0';
        }
        else {
            strncpy(node->visiting_url, url_buf, sizeof(node->visiting_url));
        }
        node->visiting_app = atoi(app_buf);
    }
    fclose(fp);
}

void update_dev_list(void)
{
    clean_dev_online_status();
    update_dev_hostname();
    update_dev_nickname();
    update_dev_online_status();
    update_dev_visiting_info();
}


void dump_dev_list(void)

{
    int i, j;
    int count = 0;
    char hostname_buf[MAX_HOSTNAME_SIZE] = {0};
    char ip_buf[MAX_IP_LEN] = {0};

    FILE *fp = fopen(OAF_DEV_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }
    fprintf(fp, "%-4s %-20s %-20s %-32s %-8s\n", "Id", "Mac Addr", "Ip Addr", "Hostname", "Online");
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            if (node->online != 0)
            {
                if (strlen(node->hostname) == 0)
                    strcpy(hostname_buf, "*");
                else
                    strcpy(hostname_buf, node->hostname);
                if (strlen(node->ip) == 0)
                    strcpy(ip_buf, "*");
                else
                    strcpy(ip_buf, node->ip);
                fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
                        i + 1, node->mac, ip_buf, hostname_buf, node->online);
                count++;
            }
            if (count >= MAX_SUPPORT_DEV_NUM)
            {
                goto EXIT;
            }
            node = node->next;
        }
    }
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            if (node->online == 0)
            {
                if (strlen(node->hostname) == 0)
                    strcpy(hostname_buf, "*");
                else
                    strcpy(hostname_buf, node->hostname);

                if (strlen(node->ip) == 0)
                    strcpy(ip_buf, "*");
                else
                    strcpy(ip_buf, node->ip);

                fprintf(fp, "%-4d %-20s %-20s %-32s %-8d\n",
                        i + 1, node->mac, ip_buf, hostname_buf, node->online);
            }
            if (count >= MAX_SUPPORT_DEV_NUM)
                goto EXIT;
            node = node->next;
        }
    }
EXIT:
    fclose(fp);
}

#define MAX_RECORD_TIME (3 * 24 * 60 * 60) // 3day
// 超过1天后清除短时间的记录
#define RECORD_REMAIN_TIME (60 * 60) // 1hour
#define INVALID_RECORD_TIME (5 * 60)      // 5min
void check_dev_visit_info_expire(void)
{
    int i, j;
    int count = 0;
    int cur_time = get_timestamp();
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
            {
                visit_info_t *p_info = node->visit_htable[j];
                while (p_info)
                {
					
                    int total_time = p_info->latest_time - p_info->first_time;
                    int interval_time = cur_time - p_info->first_time;
                    if (interval_time > MAX_RECORD_TIME || interval_time < 0)
                    {
                        p_info->expire = 1;
                    }
                    else if (interval_time > RECORD_REMAIN_TIME)
                    {
                        if (total_time < INVALID_RECORD_TIME)
                            p_info->expire = 1;
                    }
					LOG_DEBUG("[%s] appid:%d total_time:%ds interval:%ds, expire = %d\n", node->mac, p_info->appid, total_time, interval_time, p_info->expire);
                    p_info = p_info->next;
                }
            }
            node = node->next;
        }
    }
}

void flush_expire_visit_info(void)
{
    int i, j;
    int count = 0;
    visit_info_t *prev = NULL;
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
            {
                visit_info_t *p_info = node->visit_htable[j];
                prev = NULL;
                while (p_info)
                {
                    if (p_info->expire)
                    {
                        LOG_DEBUG("check expire,flush expire visit info: %s, appid=%d\n", node->mac, p_info->appid);
                        if (NULL == prev)
                        {
                            node->visit_htable[j] = p_info->next;
                            free(p_info);
                            p_info = node->visit_htable[j];
                            prev = NULL;
                        }
                        else
                        {
                            prev->next = p_info->next;
                            free(p_info);
                            p_info = prev->next;
                        }
                    }
                    else
                    {
                        prev = p_info;
                        p_info = p_info->next;
                    }
                }
            }
            node = node->next;
        }
    }
}

void dump_dev_visit_list(void)
{
    int i, j;
    int count = 0;
    FILE *fp = fopen(OAF_VISIT_LIST_FILE, "w");
    if (!fp)
    {
        return;
    }

    fprintf(fp, "%-4s %-20s %-20s %-8s %-32s %-32s %-32s %-8s\n", "Id", "Mac Addr",
            "Ip Addr", "Appid", "First Time", "Latest Time", "Total Time(s)", "Expire");
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
            {
                visit_info_t *p_info = node->visit_htable[j];
                while (p_info)
                {
                    char *first_time_str = format_time(p_info->first_time);
                    char *latest_time_str = format_time(p_info->latest_time);
                    int total_time = p_info->latest_time - p_info->first_time;
                    fprintf(fp, "%-4d %-20s %-20s %-8d %-32s %-32s %-32d %-4d\n",
                            count, node->mac, node->ip, p_info->appid, first_time_str,
                            latest_time_str, total_time, p_info->expire);
                    if (first_time_str)
                        free(first_time_str);
                    if (latest_time_str)
                        free(latest_time_str);
                    p_info = p_info->next;
                    count++;
                    if (count > 50)
                        goto EXIT;
                }
            }
            node = node->next;
        }
    }
EXIT:
    fclose(fp);
}

void clean_invalid_app_records(void)
{
    int i, j;
    int invalid_count = 0;
    int total_count = 0;
    
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            for (j = 0; j < MAX_VISIT_HASH_SIZE; j++)
            {
                visit_info_t *p_info = node->visit_htable[j];
                while (p_info)
                {
                    total_count++;
                    char *app_name = get_app_name_by_id(p_info->appid);
                    if (app_name && strlen(app_name) == 0)
                    {
                        p_info->expire = 1;
                        invalid_count++;
                        LOG_DEBUG("clean: MAC=%s, AppID=%d\n", node->mac, p_info->appid);
                    }
                    p_info = p_info->next;
                }
            }
            node = node->next;
        }
    }
    if (invalid_count > 0)
    {
        flush_expire_visit_info();
    }
}

void clear_device_app_statistics(void)
{
    int i;
    
    for (i = 0; i < MAX_DEV_NODE_HASH_SIZE; i++)
    {
        dev_node_t *node = dev_hash_table[i];
        while (node)
        {
            memset(node->stat, 0, sizeof(node->stat));
            node = node->next;
        }
    }
    
}
