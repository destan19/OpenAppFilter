
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_H__
#define __FWX_H__
#define FWX_VERSION "6.0.1"
#define MAX_FWX_NL_MSG_LEN 1024
#define FWX_TIMER_INTERVAL 1
#define MAX_HOST_LEN 40
#define MIN_HOST_LEN 4
#define MAX_FWX_NETLINK_MSG_LEN 1024
#define MAX_MATCH_PKT_NUM 20
#define FWX_NETLINK_ID 29

#define MAX_NETLINK_MSG_LEN 1024


#include <linux/types.h>
#include <linux/list.h>
#include <linux/in6.h>

#define AF_FEATURE_CONFIG_FILE "/tmp/feature.cfg"

#define MAX_DPI_PKT_NUM 256
#define MIN_HTTP_DATA_LEN 16
#define MAX_APP_NAME_LEN 64
#define MAX_FEATURE_NUM_PER_APP 16 
#define MIN_FEATURE_STR_LEN 8
#define MAX_FEATURE_STR_LEN 128
#define MAX_HOST_URL_LEN 128
#define MAX_REQUEST_URL_LEN 128
#define MAX_FEATURE_BITS 16
#define MAX_POS_INFO_PER_FEATURE 16
#define MAX_FEATURE_LINE_LEN 800
#define MIN_FEATURE_LINE_LEN 16
#define MAX_URL_MATCH_LEN 64
#define MAX_BYPASS_DPI_PKT_LEN 600

#define FWX_QUIC_PROTO 10
#define DNS_PORT 53
#define DNS_TYPE_HTTPS 65
#define DNS_HEADER_LEN 12
#define DNS_TCP_PREFIX_LEN 2
#define MAX_DNS_DOMAIN_LEN MAX_HOST_URL_LEN
#define MAX_DNS_QUERY_NUM 16

extern u_int32_t fwx_log_level;



#define HTTP_GET_METHOD_STR "GET"
#define HTTP_POST_METHOD_STR "POST"
#define HTTP_HEADER "HTTP"
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define MAC_ARRAY(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define AF_TRUE 1
#define AF_FALSE 0

#define AF_APP_TYPE(a) (a) / 1000
#define AF_APP_ID(a) (a) % 1000
#define MAC_ADDR_LEN      		6

#define HTTPS_URL_OFFSET		9
#define HTTPS_LEN_OFFSET		7

#define MAX_SEARCH_STR_LEN 32

enum AF_FEATURE_PARAM_INDEX{
	AF_PROTO_PARAM_INDEX,
	AF_SRC_PORT_PARAM_INDEX,
	AF_DST_PORT_PARAM_INDEX,
	AF_HOST_URL_PARAM_INDEX,
	AF_REQUEST_URL_PARAM_INDEX,
	AF_DICT_PARAM_INDEX,
	AF_STR_PARAM_INDEX,
	AF_IGNORE_PARAM_INDEX,
};


#define OAF_NETLINK_ID 29
#define MAX_OAF_NL_MSG_LEN 1024


enum E_FWX_NL_MSG_TYPE
{
    FWX_NL_MSG_INIT,
    FWX_NL_MSG_ADD_FEATURE,
    FWX_NL_MSG_CLEAN_FEATURE,
    FWX_NL_MSG_FEATURE_LOAD_DONE,
    FWX_NL_MSG_MAX
};

enum AF_WORK_MODE {
	AF_MODE_GATEWAY,
	AF_MODE_BYPASS,
	AF_MODE_BRIDGE,
};
#define MAX_AF_MSG_DATA_LEN 800
typedef struct af_msg{
	int action;
}af_msg_t;

struct af_msg_hdr{
    int magic;
    int len;
};

enum e_http_method{
	HTTP_METHOD_GET = 1,
	HTTP_METHOD_POST,
};
typedef struct http_proto{
	int match;
	int method;
	char *url_pos;
	int url_len;
	char *host_pos;
	int host_len;
	char *data_pos;
	int data_len;
}http_proto_t;

typedef struct https_proto{
	int match;
	char *url_pos;
	int url_len;
}https_proto_t;




typedef struct af_pos_info{
	int pos;
	unsigned char value;
}af_pos_info_t;

#define MAX_PORT_RANGE_NUM 5

typedef struct range_value
{
	int not ;
	int start;
	int end;
} range_value_t;

typedef struct port_info
{
	u_int8_t mode; // 0: match, 1: not match
	int num;
	range_value_t range_list[MAX_PORT_RANGE_NUM];
} port_info_t;

typedef struct dns_proto{
	int match;
	int query_num;
	int qdcount;
	u_int16_t qtype[MAX_DNS_QUERY_NUM];
	char domain[MAX_DNS_QUERY_NUM][MAX_DNS_DOMAIN_LEN];
}dns_proto_t;



typedef struct af_feature_node{
	struct list_head  		head;
	u_int32_t app_id;
	char app_name[MAX_APP_NAME_LEN];
	char feature[MAX_FEATURE_STR_LEN];
	u_int32_t proto;
	u_int32_t sport;
	u_int32_t dport;
	port_info_t dport_info;
	char host_url[MAX_HOST_URL_LEN];
	char request_url[MAX_REQUEST_URL_LEN];
	int pos_num;
	char search_str[MAX_SEARCH_STR_LEN];
	int ignore;
	af_pos_info_t pos_info[MAX_POS_INFO_PER_FEATURE];
}af_feature_node_t;

typedef struct af_mac_info {
    struct list_head   hlist;
    unsigned char      mac[MAC_ADDR_LEN];
}af_mac_info_t;

typedef struct flow_info{
	struct nf_conn *ct;
	u_int32_t src; 
	u_int32_t dst;
	struct in6_addr *src6;
	struct in6_addr *dst6;
	int l4_protocol;
	u_int16_t sport;
	u_int16_t dport;
	unsigned char *l4_data;
	int l4_len;
	http_proto_t http;
	https_proto_t https;
	dns_proto_t dns;
	u_int32_t app_id;
	u_int8_t app_name[MAX_APP_NAME_LEN];
	u_int8_t drop;
	u_int8_t ignore;
	u_int8_t match_by_dns;
	u_int8_t dir;
	u_int16_t total_len;
	u_int8_t client_hello;
	af_feature_node_t *feature;
}flow_info_t;


#define MAX_ACTIVE_APP_LIST_SIZE 10
#define MAX_ACTIVE_HOST_LIST_SIZE 10


typedef struct active_app_node {
	struct list_head list;        
	u_int32_t app_id;             
	unsigned char mac[MAC_ADDR_LEN];  
	u_int32_t src_ip;             
	u_int32_t dst_ip;             
	struct in6_addr src_ip6;       
	struct in6_addr dst_ip6;       
	u_int16_t src_port;           
	u_int16_t dst_port;           
	u_int8_t l4_protocol;          
	u_int8_t drop;                 
	u_int8_t proto_type;           
	char host[32];                 
	char uri[32];                  
	u_int32_t update_time;         
} active_app_node_t;


typedef struct active_host_node {
	struct list_head list;        
	char host[64];                 
	unsigned char mac[MAC_ADDR_LEN];  
	u_int32_t src_ip;             
	u_int32_t dst_ip;             
	struct in6_addr src_ip6;       
	struct in6_addr dst_ip6;       
	u_int16_t src_port;           
	u_int16_t dst_port;           
	u_int8_t l4_protocol;          
	u_int8_t drop;                 
	u_int8_t proto_type;           
	u_int32_t update_time;         
} active_host_node_t;

int regexp_match(char *reg, char *text);
int is_user_match_enable(void);


struct af_client_info;
typedef struct af_client_info af_client_info_t;

void af_update_active_app_list(af_client_info_t *client, flow_info_t *flow);
active_app_node_t *af_find_active_app(u_int32_t app_id);
void af_clear_active_app_list(void);

void af_update_active_host_list(af_client_info_t *client, flow_info_t *flow);
active_host_node_t *af_find_active_host(const char *host);
void af_clear_active_host_list(void);


enum FWX_PKT_DIR
{
	PKT_DIR_DOWN,
	PKT_DIR_UP
};

typedef struct fwx_msg
{
    int action;
    void *data;
} fwx_msg_t;

struct fwx_msg_hdr
{
    int len;
    int msg_type;
};


extern int af_log_lvl;

#define LOG(level, fmt, ...) do { \
    if ((level) <= af_log_lvl) { \
        printk(KERN_CONT"%s %d " fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

#define LLOG(level, fmt, ...) do { \
	if ((level) <= af_log_lvl) { \
        pr_info_ratelimited(KERN_CONT "%s %d " fmt, __func__, __LINE__, ##__VA_ARGS__); \
	} \
} while (0)


#define AF_ERROR(...)			LOG(0, ##__VA_ARGS__)
#define AF_WARN(...)         	LOG(1, ##__VA_ARGS__)
#define AF_INFO(...)         	LOG(2, ##__VA_ARGS__)
#define AF_DEBUG(...)       	LOG(3, ##__VA_ARGS__)

#define AF_LMT_ERROR(...)      	LLOG(0, ##__VA_ARGS__)
#define AF_LMT_WARN(...)       	LLOG(1, ##__VA_ARGS__)
#define AF_LMT_INFO(...)       	LLOG(2, ##__VA_ARGS__)
#define AF_LMT_DEBUG(...)     	LLOG(3, ##__VA_ARGS__)


#endif
