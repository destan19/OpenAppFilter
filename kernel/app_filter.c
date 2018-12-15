
#include <linux/init.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>

#include "app_filter.h"
#include "af_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("destan19@126.com");
MODULE_DESCRIPTION("app filter module");

#define MIN_HTTP_DATA_LEN 16


int parse_flow_base(struct sk_buff *skb, flow_info_t *flow) 
{
	struct tcphdr * tcph = NULL;
	struct udphdr * udph = NULL;
	struct nf_conn *ct = NULL;
	struct iphdr *iph = NULL;
	if (!skb) {
		return -1;
	}
	ct = (struct nf_conn *)skb->nfct;
	if (!ct) {
		return -1;
	}
	iph = ip_hdr(skb);
	if ( !iph ) {
		return -1;
	}
	flow->ct = ct;
	flow->src = iph->saddr;
	flow->dst = iph->daddr;
	flow->l4_protocol = iph->protocol;
	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(iph + 1);
			flow->l4_data = skb->data + iph->ihl * 4 + tcph->doff * 4;
			flow->l4_len =  ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;
			flow->dport = htons(tcph->dest);
			flow->sport = htons(tcph->source);
			break;
		case IPPROTO_UDP:
			udph = (struct udphdr *)(iph + 1);
			flow->l4_data = skb->data + iph->ihl * 4 + 8;
			flow->l4_len = ntohs(udph->len) - 8;
			flow->dport = htons(udph->dest);
			flow->sport = htons(udph->source);
			break;
		case IPPROTO_ICMP:
			break;
		default:
			return -1;
	}
	return -1;
}


void parse_http_proto(flow_info_t *flow) 
{
	if (!flow) {
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_protocol != IPPROTO_TCP) {
		return;
	}

	int i = 0;
	int start = 0;
	char *data = flow->l4_data;
	int data_len = flow->l4_len;
	if (data_len < MIN_HTTP_DATA_LEN) {
		return;
	}
	if (flow->sport != 80 && flow->dport != 80)
		return;
	for (i = 0; i < data_len - 4; i++) {
		if (data[i] == 0x0d && data[i + 1] == 0x0a){
			if (0 == memcmp(&data[start], "POST ", 5)) {
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_POST;
				flow->http.url_pos = data + start + 5;
				flow->http.url_len = i - start - 5;
				//dump_str("get request", flow->http.url_pos, flow->http.url_len);
			}
			else if(0 == memcmp(&data[start], "GET ", 4)) {
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_GET;
				flow->http.url_pos = data + start + 4;
				flow->http.url_len = i - start - 4;
				//dump_str("post request", flow->http.url_pos, flow->http.url_len);
			}
			else if (0 == memcmp(&data[start], "Host: ", 6) ){
				flow->http.host_pos = data + start + 6;
				flow->http.host_len = i - start - 6;
				//dump_str("host ", flow->http.host_pos, flow->http.host_len);
			}
			// 判断http头部结束
			if (data[i + 2] == 0x0d && data[i + 3] == 0x0a){
				flow->http.data_pos = data + i + 4;
				flow->http.data_len = data_len - i - 4;
				break;
			}
			// 0x0d 0x0a
			start = i + 2; 
		}
	}
}

static void dump_http_flow_info(http_proto_t *http) {
	if (!http) {
		AF_ERROR("http ptr is NULL\n");
		return ;
	}
	if (!http->match)
		return;	
	if (http->method == HTTP_METHOD_GET){
		printk("Http method: "HTTP_GET_METHOD_STR"\n");
	}
	else if (http->method == HTTP_METHOD_POST) {
		printk("Http method: "HTTP_POST_METHOD_STR"\n");
	}
	if (http->url_len > 0 && http->url_pos){
		dump_str("Request url", http->url_pos, http->url_len);
	}

	if (http->host_len > 0 && http->host_pos){
		dump_str("Host", http->host_pos, http->host_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}

static void dump_flow_info(flow_info_t *flow)
{
	if (!flow) {
		AF_ERROR("flow is null\n");
		return;
	}
	#if 0
	if (check_local_network_ip(ntohl(flow->src))) {
		printk("src ip(inner net):"NIPQUAD_FMT", dst ip = "NIPQUAD_FMT"\n", NIPQUAD(flow->src), NIPQUAD(flow->dst));
	}
	else {
		printk("src ip(outer net):"NIPQUAD_FMT", dst ip = "NIPQUAD_FMT"\n", NIPQUAD(flow->src), NIPQUAD(flow->dst));
	}
	#endif
	if (flow->l4_protocol == IPPROTO_TCP) {
		if (AF_TRUE == flow->http.match) {
			printk("-------------------http protocol-------------------------\n");
			printk("protocol:TCP , sport: %-8d, dport: %-8d, data_len: %-8d\n",
					flow->sport, flow->dport, flow->l4_len);
			dump_http_flow_info(&flow->http);
		}
	}
	else if (flow->l4_protocol == IPPROTO_UDP) {
		//	printk("protocol:UDP ,sport: %-8d, dport: %-8d, data_len: %-8d\n",
		//					flow->sport, flow->dport, flow->l4_len);
	}
	else {
		return;
	}
}

/* 在netfilter框架注册的钩子 */
static u_int32_t app_filter_hook(unsigned int hook,
						    struct sk_buff *pskb,
					           const struct net_device *in,
					           const struct net_device *out,
					           int (*okfn)(struct sk_buff *))
{
	struct nf_conn *ct = (struct nf_conn *)pskb->nfct;
	
	if (ct == NULL) {
        return NF_ACCEPT;
    }
	flow_info_t flow;
	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	parse_flow_base(pskb, &flow);
	parse_http_proto(&flow);
	dump_flow_info(&flow);
	// todo: match url rules
	// this is example
	if (flow.http.match == AF_TRUE) {
		if (flow.http.host_pos && 
			strnstr(flow.http.host_pos, "sohu", flow.http.host_len)){
			
			dump_str("Drop url ",flow.http.host_pos, flow.http.host_len);
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}


static struct nf_hook_ops app_filter_ops[] __read_mostly = {
	{
		.hook		= app_filter_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_MANGLE + 10,
	},
};
/*
	模块退出
*/
static void app_filter_fini(void)
{
	AF_DEBUG("app filter module exit\n");
	nf_unregister_hooks(app_filter_ops, ARRAY_SIZE(app_filter_ops));
	return ;
}

/*
	模块初始化
*/
static int __init app_filter_init(void)
{
	AF_DEBUG("app filter module init\n");
	nf_register_hooks(app_filter_ops, ARRAY_SIZE(app_filter_ops));
	printk("init app filter ........ok\n");
	return 0;
}

module_init(app_filter_init);
module_exit(app_filter_fini);
