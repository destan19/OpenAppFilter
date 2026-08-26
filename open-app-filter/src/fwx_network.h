// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_NETWORK_H__
#define __FWX_NETWORK_H__

#include <json-c/json.h>

#define MAX_INET_ADDR_LEN 32

typedef struct iface_status{
    int proto;
    char ip[MAX_INET_ADDR_LEN];
    char mask[MAX_INET_ADDR_LEN];
    char gateway[MAX_INET_ADDR_LEN];
    char dns1[MAX_INET_ADDR_LEN];
    char dns2[MAX_INET_ADDR_LEN];
}iface_status_t;

int get_iface_status(char *ifname, iface_status_t *status);
char *get_interface_status_buf(char *ifname);
char *cidr2str(int cidr);


struct json_object *fwx_api_get_lan_list(struct json_object *req_obj);
struct json_object *fwx_api_add_lan(struct json_object *req_obj);
struct json_object *fwx_api_mod_lan(struct json_object *req_obj);
struct json_object *fwx_api_del_lan(struct json_object *req_obj);
struct json_object *fwx_api_get_wan_list(struct json_object *req_obj);
struct json_object *fwx_api_add_wan(struct json_object *req_obj);
struct json_object *fwx_api_mod_wan(struct json_object *req_obj);
struct json_object *fwx_api_del_wan(struct json_object *req_obj);


struct json_object *fwx_api_get_lan_info(struct json_object *req_obj);
struct json_object *fwx_api_set_lan_info(struct json_object *req_obj);
struct json_object *fwx_api_get_wan_info(struct json_object *req_obj);
struct json_object *fwx_api_set_wan_info(struct json_object *req_obj);


struct json_object *fwx_api_get_work_mode(struct json_object *req_obj);
struct json_object *fwx_api_set_work_mode(struct json_object *req_obj);

#endif

