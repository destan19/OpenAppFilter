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

#ifndef __FILTER_USER_H__
#define __FILTER_USER_H__
#include <sys/types.h>
#define MAX_IP_LEN 32
#define MAX_MAC_LEN 32
#define MAX_VISIT_HASH_SIZE 64
#define MAX_DEV_NODE_HASH_SIZE 64
#define MAX_HOSTNAME_SIZE 64
#define OAF_VISIT_LIST_FILE "/tmp/visit_list"
#define OAF_DEV_LIST_FILE "/tmp/dev_list"
#define MIN_VISIT_TIME 5 // default 5s
#define MAX_APP_STAT_NUM 8
#define MAX_VISITLIST_DUMP_NUM 16
#define MAX_APP_TYPE 32
#define MAX_APP_ID_NUM 512
#define MAX_SUPPORT_DEV_NUM 256
#define SECONDS_PER_DAY (24 * 3600)
#define MAX_NICKNAME_SIZE 64
#define MAX_REPORT_URL_LEN 64


typedef struct visit_info
{
    int appid;
    u_int32_t first_time;
    u_int32_t latest_time;
    int action;
    int expire; 
    struct visit_info *next;
} visit_info_t;

typedef struct visit_stat
{
    u_int32_t total_time;
} visit_stat_t;

typedef struct dev_node
{
    char mac[MAX_MAC_LEN];
    char ip[MAX_IP_LEN];
    char hostname[MAX_HOSTNAME_SIZE];
    char nickname[MAX_NICKNAME_SIZE];
    int online;
    int expire;
    u_int32_t offline_time;
    u_int32_t online_time;
    visit_info_t *visit_htable[MAX_VISIT_HASH_SIZE];
    visit_stat_t stat[MAX_APP_TYPE][MAX_APP_ID_NUM]; // todo: list
    char visiting_url[MAX_REPORT_URL_LEN];
    int visiting_app;
    int is_whitelist;
    struct dev_node *next;
} dev_node_t;

struct app_visit_info
{
    int app_id;
    char app_name[32];
    int total_time;
};

struct app_visit_stat_info
{
    int num;
    struct app_visit_info visit_list[MAX_APP_STAT_NUM];
};
typedef void (*iter_func)(void *arg, dev_node_t *dev);
//todo:dev for each
extern dev_node_t *dev_hash_table[MAX_DEV_NODE_HASH_SIZE];

dev_node_t *add_dev_node(char *mac);
void init_dev_node_htable();
void dump_dev_list(void);
void dump_dev_visit_list(void);
dev_node_t *find_dev_node(char *mac);
void dev_foreach(void *arg, iter_func iter);
void add_visit_info_node(visit_info_t **head, visit_info_t *node);
void check_dev_visit_info_expire(void);
void flush_expire_visit_info();
int check_dev_expire(void);
void flush_dev_expire_node(void);
void flush_expire_visit_info(void);
void update_dev_list(void);
void update_dev_nickname(void);
void update_dev_visiting_info(void);
void update_dev_whitelist_flag(void);
void clean_invalid_app_records(void);

void clear_device_app_statistics(void);

#endif
