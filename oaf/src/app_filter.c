
/*
	author: derry
	date:2019/1/10
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include "app_filter.h"
#include "af_utils.h"
#include "af_log.h"
#include "af_client.h"
#include "af_client_fs.h"
#include "cJSON.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("destan19@126.com");
MODULE_DESCRIPTION("app filter module");
MODULE_VERSION("5.0");
struct list_head af_feature_head = LIST_HEAD_INIT(af_feature_head);

DEFINE_RWLOCK(af_feature_lock);

#define feature_list_read_lock() read_lock_bh(&af_feature_lock);
#define feature_list_read_unlock() read_unlock_bh(&af_feature_lock);
#define feature_list_write_lock() write_lock_bh(&af_feature_lock);
#define feature_list_write_unlock() write_unlock_bh(&af_feature_lock);

#define SET_APPID(mark, appid) (mark = appid)
#define GET_APPID(mark) (mark)
#define MAX_OAF_NETLINK_MSG_LEN 1024

int __add_app_feature(int appid, char *name, int proto, int src_port,
				port_info_t dport_info, char *host_url, char *request_url, char *dict)
{
	af_feature_node_t *node = NULL;
	char *p = dict;
	char *begin = dict;
	char pos[32] = {0};
	int index = 0;
	int value = 0;
	node = kzalloc(sizeof(af_feature_node_t), GFP_KERNEL);
	if (node == NULL)
	{
		printk("malloc feature memory error\n");
		return -1;
	}
	else
	{
		node->app_id = appid;
		strcpy(node->app_name, name);
		node->proto = proto;
		node->dport_info = dport_info;
		node->sport = src_port;
		strcpy(node->host_url, host_url);
		strcpy(node->request_url, request_url);
		// 00:0a-01:11
		p = dict;
		begin = dict;
		index = 0;
		value = 0;
		while (*p++)
		{
			if (*p == '|')
			{
				memset(pos, 0x0, sizeof(pos));
				strncpy(pos, begin, p - begin);
				k_sscanf(pos, "%d:%x", &index, &value);
				begin = p + 1;
				node->pos_info[node->pos_num].pos = index;
				node->pos_info[node->pos_num].value = value;
				node->pos_num++;
			}
		}

		if (begin != dict)
			strncpy(pos, begin, p - begin);
		else
			strcpy(pos, dict);
		
		k_sscanf(pos, "%d:%x", &index, &value);
		node->pos_info[node->pos_num].pos = index;
		node->pos_info[node->pos_num].value = value;
		node->pos_num++;
		feature_list_write_lock();
		list_add(&(node->head), &af_feature_head);
		feature_list_write_unlock();
	}
	return 0;
}
int validate_range_value(char *range_str){
	if (!range_str)
		return 0;
	char *p = range_str;
	while(*p){
		if (*p == ' ' || *p == '!' || *p == '-' ||
		((*p >= '0') && (*p <= '9'))){
			p++;
			continue;
		}
		else{
			printk("error, invalid char %x\n", *p);
			return 0;
		}
	}
	return 1;
}

int parse_range_value(char *range_str, range_value_t *range){
	char pure_range[128] = {0};
	if (!validate_range_value(range_str)){
		printk("validate range str failed, value = %s\n", range_str);
		return -1;
	}
	k_trim(range_str);
	if (range_str[0] == '!'){
		range->not = 1;
		strcpy(pure_range, range_str + 1);
	}
	else{
		range->not = 0;
		strcpy(pure_range, range_str);
	}
	k_trim(pure_range);
	int start, end;
	if (strstr(pure_range, "-")){
		if (2 != sscanf(pure_range, "%d-%d",&start, &end))
			return -1;
	}
	else{
		if (1 != sscanf(pure_range, "%d", &start))
			return -1;
		end = start;
	}
	range->start = start;
	range->end = end;
	return 0;
}

int parse_port_info(char *port_str, port_info_t *info){
	char *p = port_str;
	char *begin = port_str;
	int param_num = 0;
	char one_port_buf[128] = {0};
	k_trim(port_str);
	if (strlen(port_str) == 0)
		return -1;

	while(*p++) {
		if (*p != '|')
			continue;
		memset(one_port_buf, 0x0, sizeof(one_port_buf));
		strncpy(one_port_buf, begin, p - begin);
		if (0 == parse_range_value(one_port_buf, &info->range_list[info->num])){
			info->num++;
		}		
		param_num++;
		begin = p + 1;
	}
	memset(one_port_buf, 0x0, sizeof(one_port_buf));
	strncpy(one_port_buf, begin, p - begin);
	if (0 == parse_range_value(one_port_buf, &info->range_list[info->num])){
		info->num++;
	}
	return 0;
}

int af_match_port(port_info_t *info, int port){
	int i;
	int with_not = 0;
	if (info->num == 0)
		return 1;
	for (i = 0; i < info->num; i++){
		if (info->range_list[i].not){
			with_not = 1;
			break;
		}
	}
	for (i = 0; i < info->num; i++){
		if (with_not){
			if (info->range_list[i].not && port >= info->range_list[i].start 
				&& port <= info->range_list[i].end){
				return 0;
			}
		}
		else{
			if (port >= info->range_list[i].start 
				&& port <= info->range_list[i].end){
				return 1;
			}
		}
	}
	if (with_not)
		return 1;
	else
		return 0;
}
//[tcp;;443;baidu.com;;]
int add_app_feature(int appid, char *name, char *feature)
{
	char proto_str[16] = {0};
	char src_port_str[16] = {0};
	port_info_t dport_info;
	char dst_port_str[16] = {0};
	char host_url[32] = {0};
	char request_url[128] = {0};
	char dict[128] = {0};
	int proto = IPPROTO_TCP;
	char *p = feature;
	char *begin = feature;
	int param_num = 0;
	int dst_port = 0;
	int src_port = 0;

	if (!name || !feature)
	{
		AF_ERROR("error, name or feature is null\n");
		return -1;
	}
	// tcp;8000;www.sina.com;0:get_name;00:0a-01:11
	memset(&dport_info, 0x0, sizeof(dport_info));
	while (*p++)
	{
		if (*p != ';')
			continue;

		switch (param_num)
		{

		case AF_PROTO_PARAM_INDEX:
			strncpy(proto_str, begin, p - begin);
			break;
		case AF_SRC_PORT_PARAM_INDEX:
			strncpy(src_port_str, begin, p - begin);
			break;
		case AF_DST_PORT_PARAM_INDEX:
			strncpy(dst_port_str, begin, p - begin);
			break;

		case AF_HOST_URL_PARAM_INDEX:
			strncpy(host_url, begin, p - begin);
			break;

		case AF_REQUEST_URL_PARAM_INDEX:
			strncpy(request_url, begin, p - begin);
			break;
		}
		param_num++;
		begin = p + 1;
	}
	if (AF_DICT_PARAM_INDEX != param_num && strlen(feature) > MIN_FEATURE_STR_LEN)
	{
		return -1;
	}
	strncpy(dict, begin, p - begin);

	if (0 == strcmp(proto_str, "tcp"))
		proto = IPPROTO_TCP;
	else if (0 == strcmp(proto_str, "udp"))
		proto = IPPROTO_UDP;
	else
	{
		AF_DEBUG("proto %s is not support\n", proto_str);
		return -1;
	}
	sscanf(src_port_str, "%d", &src_port);
//	sscanf(dst_port_str, "%d", &dst_port);
	parse_port_info(dst_port_str, &dport_info);

	__add_app_feature(appid, name, proto, src_port, dport_info, host_url, request_url, dict);
	return 0;
}

void af_init_feature(char *feature_str)
{
	int app_id;
	char app_name[128] = {0};
	char feature_buf[MAX_FEATURE_LINE_LEN] = {0};
	char *p = feature_str;
	char *pos = NULL;
	int len = 0;
	char *begin = NULL;
	char feature[MAX_FEATURE_STR_LEN];

	if (strstr(feature_str, "#"))
		return;

	k_sscanf(feature_str, "%d%[^:]", &app_id, app_name);
	while (*p++)
	{
		if (*p == '[')
		{
			pos = p + 1;
			continue;
		}
		if (*p == ']' && pos != NULL)
		{
			len = p - pos;
		}
	}

	if (pos && len)
		strncpy(feature_buf, pos, len);
	memset(feature, 0x0, sizeof(feature));
	p = feature_buf;
	begin = feature_buf;

	while (*p++)
	{
		if (*p == ',')
		{
			memset(feature, 0x0, sizeof(feature));
			strncpy((char *)feature, begin, p - begin);

			add_app_feature(app_id, app_name, feature);
			begin = p + 1;
		}
	}
	if (p != begin)
	{
		memset(feature, 0x0, sizeof(feature));
		strncpy((char *)feature, begin, p - begin);
		add_app_feature(app_id, app_name, feature);
	}
}

void load_feature_buf_from_file(char **config_buf)
{
	struct inode *inode = NULL;
	struct file *fp = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	 mm_segment_t fs;
#endif
	off_t size;
	fp = filp_open(AF_FEATURE_CONFIG_FILE, O_RDONLY, 0);

	if (IS_ERR(fp))
	{
		return;
	}

	inode = fp->f_inode;
	size = inode->i_size;
	if (size == 0)
	{
		return;
	}
	*config_buf = (char *)kzalloc(sizeof(char) * size, GFP_KERNEL);
	if (NULL == *config_buf)
	{
		AF_ERROR("alloc buf fail\n");
		filp_close(fp, NULL);
		return;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif
// 4.14rc3 vfs_read-->kernel_read
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	kernel_read(fp, *config_buf, size, &(fp->f_pos));
#else
	vfs_read(fp, *config_buf, size, &(fp->f_pos));
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	set_fs(fs);
#endif
	filp_close(fp, NULL);
}

int load_feature_config(void)
{
	char *feature_buf = NULL;
	char *p;
	char *begin;
	char line[MAX_FEATURE_LINE_LEN] = {0};

	load_feature_buf_from_file(&feature_buf);
	if (!feature_buf)
	{
		return -1;
	}
	p = begin = feature_buf;
	while (*p++)
	{
		if (*p == '\n')
		{
			if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			{
				begin = p + 1;
				continue;
			}
			memset(line, 0x0, sizeof(line));
			strncpy(line, begin, p - begin);
			af_init_feature(line);
			begin = p + 1;
		}
	}
	if (p != begin)
	{
		if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			return 0;
		memset(line, 0x0, sizeof(line));
		strncpy(line, begin, p - begin);
		af_init_feature(line);
		begin = p + 1;
	}
	if (feature_buf)
		kfree(feature_buf);
	return 0;
}

static void af_clean_feature_list(void)
{
	af_feature_node_t *node;
	feature_list_write_lock();
	while (!list_empty(&af_feature_head))
	{
		node = list_first_entry(&af_feature_head, af_feature_node_t, head);
		list_del(&(node->head));
		kfree(node);
	}
	feature_list_write_unlock();
}

int parse_flow_proto(struct sk_buff *skb, flow_info_t *flow)
{
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct nf_conn *ct = NULL;
	struct iphdr *iph = NULL;
	if (!skb)
		return -1;
	iph = ip_hdr(skb);
	if (!iph)
		return -1;
	flow->src = iph->saddr;
	flow->dst = iph->daddr;
	flow->l4_protocol = iph->protocol;
	switch (iph->protocol)
	{
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)(iph + 1);
		flow->l4_data = skb->data + iph->ihl * 4 + tcph->doff * 4;
		flow->l4_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;
		flow->dport = htons(tcph->dest);
		flow->sport = htons(tcph->source);
		return 0;
	case IPPROTO_UDP:
		udph = (struct udphdr *)(iph + 1);
		flow->l4_data = skb->data + iph->ihl * 4 + 8;
		flow->l4_len = ntohs(udph->len) - 8;
		flow->dport = htons(udph->dest);
		flow->sport = htons(udph->source);
		return 0;
	case IPPROTO_ICMP:
		break;
	default:
		return -1;
	}
	return -1;
}
#define MAX_HOST_LEN 32
#define MIN_HOST_LEN 4

int dpi_https_proto(flow_info_t *flow)
{
	int i;
	short url_len = 0;
	char *p = flow->l4_data;
	int data_len = flow->l4_len;

	if (NULL == flow)
	{
		AF_ERROR("flow is NULL\n");
		return -1;
	}
	if (NULL == p || data_len == 0)
	{
		return -1;
	}
	if (!(p[0] == 0x16 && p[1] == 0x03 && p[2] == 0x01))
		return -1;


	for (i = 0; i < data_len; i++)
	{
		if (i + HTTPS_URL_OFFSET >= data_len)
		{
			return -1;
		}
		

		if (p[i] == 0x0 && p[i + 1] == 0x0 && p[i + 2] == 0x0 && p[i + 3] != 0x0)
		{
			// 2 bytes
			memcpy(&url_len, p + i + HTTPS_LEN_OFFSET, 2);

			if (ntohs(url_len) <= MIN_HOST_LEN || ntohs(url_len) > data_len || ntohs(url_len) > MAX_HOST_LEN)
			{
				continue;
			}
			if (i + HTTPS_URL_OFFSET + ntohs(url_len) < data_len)
			{
				flow->https.match = AF_TRUE;
				flow->https.url_pos = p + i + HTTPS_URL_OFFSET;
				flow->https.url_len = ntohs(url_len);
				return 0;
			}
		}
	}
	return -1;
}

void dpi_http_proto(flow_info_t *flow)
{
	int i = 0;
	int start = 0;
	char *data = NULL;
	int data_len = 0;
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_protocol != IPPROTO_TCP)
	{
		return;
	}

	data = flow->l4_data;
	data_len = flow->l4_len;
	if (data_len < MIN_HTTP_DATA_LEN)
	{
		return;
	}
	if (flow->sport != 80 && flow->dport != 80)
		return;
	for (i = 0; i < data_len; i++)
	{
		if (data[i] == 0x0d && data[i + 1] == 0x0a)
		{
			if (0 == memcmp(&data[start], "POST ", 5))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_POST;
				flow->http.url_pos = data + start + 5;
				flow->http.url_len = i - start - 5;
			}
			else if (0 == memcmp(&data[start], "GET ", 4))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_GET;
				flow->http.url_pos = data + start + 4;
				flow->http.url_len = i - start - 4;
			}
			else if (0 == memcmp(&data[start], "Host:", 5))
			{
				flow->http.host_pos = data + start + 6;
				flow->http.host_len = i - start - 6;
			}
			if (data[i + 2] == 0x0d && data[i + 3] == 0x0a)
			{
				flow->http.data_pos = data + i + 4;
				flow->http.data_len = data_len - i - 4;
				break;
			}
			// 0x0d 0x0a
			start = i + 2;
		}
	}
}

static void dump_http_flow_info(http_proto_t *http)
{
	if (!http)
	{
		AF_ERROR("http ptr is NULL\n");
		return;
	}
	if (!http->match)
		return;
	if (http->method == HTTP_METHOD_GET)
	{
		printk("Http method: " HTTP_GET_METHOD_STR "\n");
	}
	else if (http->method == HTTP_METHOD_POST)
	{
		printk("Http method: " HTTP_POST_METHOD_STR "\n");
	}
	if (http->url_len > 0 && http->url_pos)
	{
		dump_str("Request url", http->url_pos, http->url_len);
	}

	if (http->host_len > 0 && http->host_pos)
	{
		dump_str("Host", http->host_pos, http->host_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}

static void dump_https_flow_info(https_proto_t *https)
{
	if (!https)
	{
		AF_ERROR("https ptr is NULL\n");
		return;
	}
	if (!https->match)
		return;

	if (https->url_len > 0 && https->url_pos)
	{
		dump_str("https server name", https->url_pos, https->url_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}
static void dump_flow_info(flow_info_t *flow)
{
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_len > 0)
	{
		AF_LMT_INFO("src=" NIPQUAD_FMT ",dst=" NIPQUAD_FMT ",sport: %d, dport: %d, data_len: %d\n",
					NIPQUAD(flow->src), NIPQUAD(flow->dst), flow->sport, flow->dport, flow->l4_len);
	}

	if (flow->l4_protocol == IPPROTO_TCP)
	{
		if (AF_TRUE == flow->http.match)
		{
			printk("-------------------http protocol-------------------------\n");
			printk("protocol:TCP , sport: %-8d, dport: %-8d, data_len: %-8d\n",
				   flow->sport, flow->dport, flow->l4_len);
			dump_http_flow_info(&flow->http);
		}
		if (AF_TRUE == flow->https.match)
		{
			printk("-------------------https protocol-------------------------\n");
			dump_https_flow_info(&flow->https);
		}
	}
}
int af_match_by_pos(flow_info_t *flow, af_feature_node_t *node)
{
	int i;
	unsigned int pos = 0;

	if (!flow || !node)
		return AF_FALSE;
	if (node->pos_num > 0)
	{
		for (i = 0; i < node->pos_num; i++)
		{
			// -1
			if (node->pos_info[i].pos < 0)
			{
				pos = flow->l4_len + node->pos_info[i].pos;
			}
			else
			{
				pos = node->pos_info[i].pos;
			}
			if (pos >= flow->l4_len)
			{
				return AF_FALSE;
			}
			if (flow->l4_data[pos] != node->pos_info[i].value)
			{
				return AF_FALSE;
			}
		}
		AF_DEBUG("match by pos, appid=%d\n", node->app_id);
		return AF_TRUE;
	}
	return AF_FALSE;
}

int af_match_by_url(flow_info_t *flow, af_feature_node_t *node)
{
	char reg_url_buf[MAX_URL_MATCH_LEN] = {0};

	if (!flow || !node)
		return AF_FALSE;
	// match host or https url
	if (flow->https.match == AF_TRUE && flow->https.url_pos)
	{
		if (flow->https.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->https.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->https.url_pos, flow->https.url_len);
	}
	else if (flow->http.match == AF_TRUE && flow->http.host_pos)
	{
		if (flow->http.host_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.host_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.host_pos, flow->http.host_len);
	}
	if (strlen(reg_url_buf) > 0 && strlen(node->host_url) > 0 && regexp_match(node->host_url, reg_url_buf))
	{
		AF_DEBUG("match url:%s	 reg = %s, appid=%d\n",
				 reg_url_buf, node->host_url, node->app_id);
		return AF_TRUE;
	}

	// match request url
	if (flow->http.match == AF_TRUE && flow->http.url_pos)
	{
		memset(reg_url_buf, 0x0, sizeof(reg_url_buf));
		if (flow->http.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.url_pos, flow->http.url_len);
		if (strlen(reg_url_buf) > 0 && strlen(node->request_url) && regexp_match(node->request_url, reg_url_buf))
		{
			AF_DEBUG("match request:%s   reg:%s appid=%d\n",
					 reg_url_buf, node->request_url, node->app_id);
			return AF_TRUE;
		}
	}
	return AF_FALSE;
}

int af_match_one(flow_info_t *flow, af_feature_node_t *node)
{
	int ret = AF_FALSE;
	if (!flow || !node)
	{
		AF_ERROR("node or flow is NULL\n");
		return AF_FALSE;
	}
	if (node->proto > 0 && flow->l4_protocol != node->proto)
		return AF_FALSE;
	if (flow->l4_len == 0)
		return AF_FALSE;

	if (node->sport != 0 && flow->sport != node->sport)
	{
		return AF_FALSE;
	}
	
	if (!af_match_port(&node->dport_info, flow->dport)){
		return AF_FALSE;
	}

	if (strlen(node->request_url) > 0 ||
		strlen(node->host_url) > 0)
	{
		ret = af_match_by_url(flow, node);
	}
	else if (node->pos_num > 0)
	{
		ret = af_match_by_pos(flow, node);
	}
	else
	{
		AF_DEBUG("node is empty, match sport:%d,dport:%d, appid = %d\n",
				 node->sport, node->dport, node->app_id);
		return AF_TRUE;
	}
	return ret;
}

int app_filter_match(flow_info_t *flow)
{
	af_feature_node_t *n, *node;
	af_client_info_t *client = NULL;
	feature_list_read_lock();
	if (!list_empty(&af_feature_head))
	{
		list_for_each_entry_safe(node, n, &af_feature_head, head)
		{
			if (af_match_one(flow, node))
			{
				flow->app_id = node->app_id;
				strncpy(flow->app_name, node->app_name, sizeof(flow->app_name) - 1);
				client = find_af_client_by_ip(flow->src);
				if (!client)
				{
					goto EXIT;
				}
				if (is_user_match_enable() && !find_af_mac(client->mac))
				{
					goto EXIT;
				}
				if (af_get_app_status(node->app_id))
				{
					flow->drop = AF_TRUE;
					feature_list_read_unlock();
					return AF_TRUE;
				}
				else
				{
					goto EXIT;
				}
			}
		}
	}
EXIT:
	flow->drop = AF_FALSE;
	feature_list_read_unlock();
	return AF_FALSE;
}

#define NF_DROP_BIT 0x80000000

static int af_get_visit_index(af_client_info_t *node, int app_id)
{
	int i;
	for (i = 0; i < MAX_RECORD_APP_NUM; i++)
	{
		if (node->visit_info[i].app_id == app_id || node->visit_info[i].app_id == 0)
		{
			return i;
		}
	}
	// default 0
	return 0;
}

int af_update_client_app_info(af_client_info_t *node, int app_id, int drop)
{
	int index = -1;
	if (!node)
		return -1;

	index = af_get_visit_index(node, app_id);
	if (index < 0 || index >= MAX_RECORD_APP_NUM)
		return 0;
	node->visit_info[index].total_num++;
	if (drop)
		node->visit_info[index].drop_num++;
	node->visit_info[index].app_id = app_id;
	node->visit_info[index].latest_time = af_get_timestamp_sec();
	node->visit_info[index].latest_action = drop;
	return 0;
}

int af_send_msg_to_user(char *pbuf, uint16_t len);
int af_match_bcast_packet(flow_info_t *f){
	if (!f)
		return 0;
	if (0 == f->src || 0 == f->dst 
	|| 0xffffffff == f->dst || 0 == f->dst)
		return 1;
	return 0;
}

int af_match_local_packet(flow_info_t *f){
	if (!f)
		return 0;
	if (0x0100007f == f->src || 0x0100007f == f->dst){
		return 1;
	}
	return 0;
}

int dpi_main(struct sk_buff *skb, flow_info_t *flow){
	dpi_http_proto(flow);
	dpi_https_proto(flow);
	if (TEST_MODE())
		dump_flow_info(flow);
	return 0;
}

void af_get_smac(struct sk_buff *skb, u_int8_t *smac){
	struct ethhdr *ethhdr = NULL;
	ethhdr = eth_hdr(skb);
	if (ethhdr)
		memcpy(smac, ethhdr->h_source, ETH_ALEN);
	else
		memcpy(smac, &skb->cb[40], ETH_ALEN);
}
int is_ipv4_broadcast(uint32_t ip) {

    return (ip & 0x00FFFFFF) == 0x00FFFFFF;
}

int is_ipv4_multicast(uint32_t ip) {
    return (ip & 0xF0000000) == 0xE0000000;
}
int af_check_bcast_ip(flow_info_t *f)
{
		
	if (0 == f->src || 0 == f->dst)
		return 1;
	if (is_ipv4_broadcast(ntohl(f->src)) || is_ipv4_broadcast(ntohl(f->dst))){
		return 1;
	}
	if (is_ipv4_multicast(ntohl(f->src)) || is_ipv4_multicast(ntohl(f->dst))){
		return 1;
	}

	return 0;
}
u_int32_t app_filter_hook_bypass_handle(struct sk_buff *skb, struct net_device *dev){
	flow_info_t flow;
	u_int8_t smac[ETH_ALEN];
	af_client_info_t *client = NULL;

	if (!skb || !dev)
		return NF_ACCEPT;

	if (0 == af_lan_ip || 0 == af_lan_mask)
		return NF_ACCEPT;
	if (strstr(dev->name, "docker"))
		return NF_ACCEPT;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;
	
	if (af_lan_ip == flow.src || af_lan_ip == flow.dst){
		return NF_ACCEPT;
	}
	if (af_check_bcast_ip(&flow) || af_match_local_packet(&flow))
		return NF_ACCEPT;

	if ((flow.src & af_lan_mask) != (af_lan_ip & af_lan_mask)){
		return NF_ACCEPT;
	}
	af_get_smac(skb, smac);

	AF_CLIENT_LOCK_W();
	client = find_and_add_af_client(smac);
	if (!client){
		AF_CLIENT_UNLOCK_W();
		return NF_ACCEPT;
	}
	client->update_jiffies = jiffies;
	AF_CLIENT_UNLOCK_W();

	if (0 != dpi_main(skb, &flow))
		return NF_ACCEPT;

	client->ip = flow.src;
	app_filter_match(&flow);
	if (flow.app_id != 0){
		af_update_client_app_info(client, flow.app_id, flow.drop);
	}
	if (flow.drop)
	{
		return NF_DROP;
	}
	return NF_ACCEPT;
}

u_int32_t app_filter_hook_gateway_handle(struct sk_buff *skb, struct net_device *dev){
	unsigned long long total_packets = 0;
	flow_info_t flow;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct nf_conn_acct *acct;
	af_client_info_t *client = NULL;
	int app_id = 0;
	int drop = 0;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL || !nf_ct_is_confirmed(ct))
		return NF_ACCEPT;

	AF_CLIENT_LOCK_R();
	client = find_af_client_by_ip(flow.src);
	if (!client){
		AF_CLIENT_UNLOCK_R();
		return NF_ACCEPT;
	}
	client->update_jiffies = jiffies;
	AF_CLIENT_UNLOCK_R();

	if (ct->mark != 0)
	{
		app_id = ct->mark & (~NF_DROP_BIT);
		if (app_id > 1000 && app_id < 9999){
			if (NF_DROP_BIT == (ct->mark & NF_DROP_BIT))
				drop = 1;
			AF_CLIENT_LOCK_W();
			af_update_client_app_info(client, app_id, drop);
			AF_CLIENT_UNLOCK_W();

			if (drop){
				return NF_DROP;
			}
		}
	}
	acct = nf_conn_acct_find(ct);
	if(!acct)
		return NF_ACCEPT;
	total_packets = (unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_ORIGINAL].packets) 
		+ (unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_REPLY].packets);

	if(total_packets > MAX_DPI_PKT_NUM)
		return NF_ACCEPT;

	if (0 != dpi_main(skb, &flow))
		return NF_ACCEPT;

	app_filter_match(&flow);

	if (flow.app_id != 0)
	{
		ct->mark = flow.app_id;
		AF_CLIENT_LOCK_W();
		af_update_client_app_info(client, flow.app_id, flow.drop);
		AF_CLIENT_UNLOCK_W();
		AF_LMT_INFO("match %s %pI4(%d)--> %pI4(%d) len = %d, %d\n ", IPPROTO_TCP == flow.l4_protocol ? "tcp" : "udp",
					&flow.src, flow.sport, &flow.dst, flow.dport, skb->len, flow.app_id);
	}
	if (flow.drop)
	{
		ct->mark |= NF_DROP_BIT;
		AF_LMT_INFO("##Drop app %s flow, appid is %d\n", flow.app_name, flow.app_id);
		return NF_DROP;
	}
	return NF_ACCEPT;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t app_filter_hook(void *priv,
								 struct sk_buff *skb,
								 const struct nf_hook_state *state)
{
#else
static u_int32_t app_filter_hook(unsigned int hook,
								 struct sk_buff *skb,
								 const struct net_device *in,
								 const struct net_device *out,
								 int (*okfn)(struct sk_buff *))
{
#endif
	if (!g_oaf_enable)
		return NF_ACCEPT;
	if (AF_MODE_BYPASS == af_work_mode)
		return NF_ACCEPT;
	return app_filter_hook_gateway_handle(skb, skb->dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t app_filter_by_pass_hook(void *priv,
								 struct sk_buff *skb,
								 const struct nf_hook_state *state)
{
#else
static u_int32_t app_filter_by_pass_hook(unsigned int hook,
								 struct sk_buff *skb,
								 const struct net_device *in,
								 const struct net_device *out,
								 int (*okfn)(struct sk_buff *))
{
#endif
	if (!g_oaf_enable)
		return NF_ACCEPT;
	if (AF_MODE_GATEWAY == af_work_mode)
		return NF_ACCEPT;
	return app_filter_hook_bypass_handle(skb, skb->dev);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static struct nf_hook_ops app_filter_ops[] __read_mostly = {
	{
		.hook = app_filter_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,

	},
	{
		.hook = app_filter_by_pass_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#else
static struct nf_hook_ops app_filter_ops[] __read_mostly = {
	{
		.hook = app_filter_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#endif


struct timer_list oaf_timer;
int report_flag = 0;
#define OAF_TIMER_INTERVAL 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void oaf_timer_func(struct timer_list *t)
#else
static void oaf_timer_func(unsigned long ptr)
#endif
{
	static int count = 0;
	if (count % 60 == 0)
		check_client_expire();
	if (count % 60 == 0 || report_flag)
	{
		report_flag = 0;
		af_visit_info_report();
	}
	count++;
	mod_timer(&oaf_timer, jiffies + OAF_TIMER_INTERVAL * HZ);
}

void init_oaf_timer(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&oaf_timer, oaf_timer_func, 0);
#else
	setup_timer(&oaf_timer, oaf_timer_func, OAF_TIMER_INTERVAL * HZ);
#endif
	mod_timer(&oaf_timer, jiffies + OAF_TIMER_INTERVAL * HZ);
	AF_INFO("init oaf timer...ok");
}

void fini_oaf_timer(void)
{
	del_timer_sync(&oaf_timer);
	AF_INFO("del oaf timer...ok");
}

static struct sock *oaf_sock = NULL;

#define OAF_EXTRA_MSG_BUF_LEN 128
int af_send_msg_to_user(char *pbuf, uint16_t len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	int buf_len = OAF_EXTRA_MSG_BUF_LEN + len;
	char *msg_buf = NULL;
	struct af_msg_hdr *hdr = NULL;
	char *p_data = NULL;
	int ret;
	if (len >= MAX_OAF_NL_MSG_LEN)
		return -1;

	msg_buf = kmalloc(buf_len, GFP_KERNEL);
	if (!msg_buf)
		return -1;

	memset(msg_buf, 0x0, buf_len);
	nl_skb = nlmsg_new(len + sizeof(struct af_msg_hdr), GFP_ATOMIC);
	if (!nl_skb)
	{
		ret = -1;
		goto fail;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, OAF_NETLINK_ID, len + sizeof(struct af_msg_hdr), 0);
	if (nlh == NULL)
	{
		nlmsg_free(nl_skb);
		ret = -1;
		goto fail;
	}

	hdr = (struct af_msg_hdr *)msg_buf;
	hdr->magic = 0xa0b0c0d0;
	hdr->len = len;
	p_data = msg_buf + sizeof(struct af_msg_hdr);
	memcpy(p_data, pbuf, len);
	memcpy(nlmsg_data(nlh), msg_buf, len + sizeof(struct af_msg_hdr));
	ret = netlink_unicast(oaf_sock, nl_skb, 999, MSG_DONTWAIT);

fail:
	kfree(msg_buf);
	return ret;
}

static void oaf_user_msg_handle(af_msg_t *msg)
{
	switch (msg->action)
	{
	case AF_MSG_INIT:
		af_client_list_reset_report_num();
		report_flag = 1;
		break;
	default:
		break;
	}
}
static void oaf_msg_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	char *umsg = NULL;
	void *udata = NULL;
	struct af_msg_hdr *af_hdr = NULL;
	if (skb->len >= nlmsg_total_size(0))
	{
		nlh = nlmsg_hdr(skb);
		umsg = NLMSG_DATA(nlh);
		af_hdr = (struct af_msg_hdr *)umsg;
		if (af_hdr->magic != 0xa0b0c0d0)
			return;
		if (af_hdr->len <= 0 || af_hdr->len >= MAX_OAF_NETLINK_MSG_LEN)
			return;
		udata = umsg + sizeof(struct af_msg_hdr);

		if (udata)
			oaf_user_msg_handle((af_msg_t *)udata);
	}
}

int netlink_oaf_init(void)
{
	struct netlink_kernel_cfg nl_cfg = {0};
	nl_cfg.input = oaf_msg_rcv;
	oaf_sock = netlink_kernel_create(&init_net, OAF_NETLINK_ID, &nl_cfg);

	if (NULL == oaf_sock)
	{
		AF_ERROR("init oaf netlink failed, id=%d\n", OAF_NETLINK_ID);
		return -1;
	}
	AF_INFO("init oaf netlink ok, id = %d\n", OAF_NETLINK_ID);
	return 0;
}

static int __init app_filter_init(void)
{
	if (0 != load_feature_config())
	{
		return -1;
	}

	netlink_oaf_init();
	af_log_init();
	af_register_dev();
	af_mac_list_init();
	af_init_app_status();
	init_af_client_procfs();
	af_client_init();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_register_net_hooks(&init_net, app_filter_ops, ARRAY_SIZE(app_filter_ops));
#else
	nf_register_hooks(app_filter_ops, ARRAY_SIZE(app_filter_ops));
#endif
	init_oaf_timer();
	AF_INFO("init app filter ........ok\n");
	return 0;
}

static void app_filter_fini(void)
{
	AF_INFO("app filter module exit\n");
	fini_oaf_timer();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_unregister_net_hooks(&init_net, app_filter_ops, ARRAY_SIZE(app_filter_ops));
#else
	nf_unregister_hooks(app_filter_ops, ARRAY_SIZE(app_filter_ops));
#endif

	af_clean_feature_list();
	af_mac_list_clear();
	af_unregister_dev();
	af_log_exit();
	af_client_exit();
	finit_af_client_procfs();
	if (oaf_sock)
		netlink_kernel_release(oaf_sock);
	return;
}

module_init(app_filter_init);
module_exit(app_filter_fini);
