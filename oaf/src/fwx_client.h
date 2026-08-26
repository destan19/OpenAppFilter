// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __AF_CLIENT_H__
#define __AF_CLIENT_H__
#include "fwx.h"
struct cJSON;

extern rwlock_t af_client_lock;

extern u32 nfc_debug_level;



extern int g_max_app_report_count;
extern int g_min_http_match_count;

#define VISIT_INFO_TIMEOUT_SEC 300

#define MAX_AF_CLIENT_HASH_SIZE 64
#define NF_CLIENT_TIMER_EXPIRE 1
#define MAX_CLIENT_ACTIVE_TIME 180

#define AF_CLIENT_LOCK_R() read_lock_bh(&af_client_lock);
#define AF_CLIENT_UNLOCK_R() read_unlock_bh(&af_client_lock);
#define AF_CLIENT_LOCK_W() write_lock_bh(&af_client_lock);
#define AF_CLIENT_UNLOCK_W() write_unlock_bh(&af_client_lock);

#define NIPQUAD(addr)                \
	((unsigned char *)&addr)[0],     \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"



#define MAX_VISIT_HISTORY_TIME 24
#define MAX_RECORD_APP_NUM 64
#define MAX_VISIT_INFO_HASH_SIZE 32
#define MIN_REPORT_URL_LEN 4
#define MAX_REPORT_URL_LEN 64

typedef struct flow_stat
{
	long long up_bytes;
	long long down_bytes;
	long long up_pkts;
	long long down_pkts;
} flow_stat_t;

typedef struct flow_rate
{
	unsigned int up_rate;
	unsigned int down_rate;
	unsigned int pkt_up_rate;
	unsigned int pkt_down_rate;
}flow_rate_t;
typedef struct app_visit_info
{
	struct hlist_node hlist;
	unsigned int app_id;
	unsigned int total_num;
	unsigned int drop_num;
	unsigned long latest_time;
	unsigned int latest_action;
	unsigned int conn_count;
	unsigned int is_http;
} app_visit_info_t;

typedef struct visiting_info{
    int visiting_app;
    int app_time;
    char visiting_url[MAX_REPORT_URL_LEN];
    int url_time;
}visiting_info_t;

typedef struct af_client_info
{
	struct list_head hlist;
	unsigned char mac[MAC_ADDR_LEN];
	unsigned int ip;
	struct in6_addr ipv6;
	unsigned long create_jiffies;
	unsigned long update_jiffies;
	flow_stat_t flow;
	flow_stat_t last_flow;
	flow_stat_t period_flow; 
	flow_rate_t rate;
	struct timer_list client_timer;
	unsigned int visit_app_num;
	int active_time;
	int inactive_time;
	int active;
	int record_whitelist;
	visiting_info_t visiting;
	int report_count;
	unsigned int timer_count;  
	spinlock_t visit_info_lock;
	struct hlist_head visit_info_hash[MAX_VISIT_INFO_HASH_SIZE];
	struct proc_dir_entry *proc_dir;
} af_client_info_t;

int af_client_init(void);

void af_client_exit(void);
af_client_info_t *find_af_client_by_ip(unsigned int ip);
af_client_info_t *find_af_client_by_ipv6(struct in6_addr *addr);

af_client_info_t *find_af_client(unsigned char *mac);

void check_client_expire(void);

void af_visit_info_report(void);

void af_client_list_reset_report_num(void);
af_client_info_t *nf_client_add(unsigned char *mac);
af_client_info_t *find_and_add_af_client(unsigned char *mac);
app_visit_info_t *get_or_create_visit_info(af_client_info_t *node, unsigned int app_id);
int af_update_client_app_info(af_client_info_t *node, int app_id, int drop, int from_conntrack, int is_http, int update_visiting);
void check_expired_visit_info(af_client_info_t *node);

int fwx_match_record_whitelist(const unsigned char *mac);
int fwx_set_record_whitelist(const char *mac_list_str);
int fwx_api_add_record_whitelist(struct cJSON *data_obj);
int fwx_api_del_record_whitelist(struct cJSON *data_obj);
int fwx_api_flush_record_whitelist(struct cJSON *data_obj);

#endif
