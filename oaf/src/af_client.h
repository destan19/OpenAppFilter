#ifndef __AF_CLIENT_H__
#define __AF_CLIENT_H__
#include "app_filter.h"

extern rwlock_t af_client_lock;

extern u32 nfc_debug_level;

#define MAX_AF_CLIENT_HASH_SIZE 64
#define NF_CLIENT_TIMER_EXPIRE 1
#define MAX_CLIENT_ACTIVE_TIME 90

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

enum NFC_PKT_DIR
{
	PKT_DIR_DOWN,
	PKT_DIR_UP
};

#define MAX_VISIT_HISTORY_TIME 24
#define MAX_RECORD_APP_NUM 64
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
	unsigned int app_id;
	unsigned int total_num;
	unsigned int drop_num;
	unsigned long latest_time;
	unsigned int latest_action;
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
	visiting_info_t visiting;
	int report_count;
	app_visit_info_t visit_info[MAX_RECORD_APP_NUM];
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

#endif
