// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <uci.h>
#include "fwx.h"
#include "fwx_user.h"
#include "fwx_netlink.h"
#include "fwx_ubus.h"
#include "fwx_config.h"
#include "fwx_utils.h"
#include "fwx_network.h"
#include "fwx_uci.h"
#define MAX_INET_ADDR_LEN 32
#define MAX_MAC_ADDR_LEN 18

int get_iface_status(char *ifname, iface_status_t *status){
    int ret = -1; 
    char *buf = NULL;

    buf = get_interface_status_buf(ifname);
    if (!buf){
		
    LOG_ERROR("get interface status buf error\n");
        return -1; 
    }   
    struct json_object *resp_obj = json_tokener_parse(buf);
    if (!resp_obj) {
        LOG_ERROR("get_iface_status: failed to parse JSON\n");
        free(buf);
        return -1;
    }
    
    struct json_object *ipv4_addr_array = json_object_object_get(resp_obj, "ipv4-address");
    struct json_object *route_array = json_object_object_get(resp_obj, "route");
    struct json_object *dns_server_array = json_object_object_get(resp_obj, "dns-server");
    
    if (ipv4_addr_array && json_object_array_length(ipv4_addr_array) > 0){ 
       struct json_object *ipv4_addr_obj = json_object_array_get_idx(ipv4_addr_array, 0); 
       struct json_object *addr_obj = json_object_object_get(ipv4_addr_obj, "address");
       struct json_object *mask_obj = json_object_object_get(ipv4_addr_obj, "mask");
       if (addr_obj && mask_obj){
           strcpy(status->ip, json_object_get_string(addr_obj));
           char *mask_str = cidr2str(json_object_get_int(mask_obj));
            if (mask_str) 
           strcpy(status->mask, mask_str);

       }
    }  
	else{
		LOG_ERROR("parse json error\n");
	}
    
    if (route_array && json_object_array_length(route_array) > 0){ 
       struct json_object *route_obj = json_object_array_get_idx(route_array, 0); 
       struct json_object *nexhop_obj = json_object_object_get(route_obj, "nexthop");
       if (nexhop_obj){
           strcpy(status->gateway, json_object_get_string(nexhop_obj));
       }
    }   

    if (dns_server_array && json_object_array_length(dns_server_array) > 0){ 
       struct json_object *dns1_obj = json_object_array_get_idx(dns_server_array, 0); 
       if (dns1_obj){
           strcpy(status->dns1, json_object_get_string(dns1_obj));
       }
    }   
    if (dns_server_array && json_object_array_length(dns_server_array)  > 1){ 
       struct json_object *dns2_obj = json_object_array_get_idx(dns_server_array, 1); 
       if (dns2_obj){
           strcpy(status->dns2, json_object_get_string(dns2_obj));
       }
    }

    ret = 0;
DONE:
    if (buf) {
        free(buf);
    }
    if (resp_obj) {
        json_object_put(resp_obj);
    }
    return ret;
}


char *get_interface_status_buf(char *ifname) {
    if (!ifname) {
        return NULL;
    }
    

    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "ifstatus %s", ifname);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return NULL;
    }
    

    size_t buf_size = 4096;
    char *buf = malloc(buf_size);
    if (!buf) {
        pclose(fp);
        return NULL;
    }
    
    size_t total_read = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t line_len = strlen(line);
        if (total_read + line_len >= buf_size) {
            buf_size *= 2;
            char *new_buf = realloc(buf, buf_size);
            if (!new_buf) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = new_buf;
        }
        strncpy(buf + total_read, line, line_len);
        total_read += line_len;
        buf[total_read] = '\0';
    }
    
    pclose(fp);
    return buf;
}


char *cidr2str(int cidr) {
    if (cidr < 0 || cidr > 32) {
        return NULL;
    }
    
    static char mask_str[16];
    unsigned int mask = 0xFFFFFFFF << (32 - cidr);
    

    snprintf(mask_str, sizeof(mask_str), "%d.%d.%d.%d",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF);
    
    return mask_str;
}

static int netmask_to_prefix(const char *mask_str)
{
    struct in_addr addr;
    uint32_t mask;
    int prefix = 0;
    int i;

    if (!mask_str || inet_aton(mask_str, &addr) == 0) {
        return -1;
    }

    mask = ntohl(addr.s_addr);
    for (i = 31; i >= 0; i--) {
        if (mask & (1u << i)) {
            prefix++;
        } else {
            break;
        }
    }

    if (prefix < 0 || prefix > 32) {
        return -1;
    }

    if (prefix < 32) {
        uint32_t expected = (prefix == 0) ? 0u : (~0u << (32 - prefix));
        if (mask != expected) {
            return -1;
        }
    } else if (mask != 0xFFFFFFFFu) {
        return -1;
    }

    return prefix;
}

static int parse_ipaddr_list_token(const char *token, char *ip_out, size_t ip_out_len, char *mask_out, size_t mask_out_len)
{
    char local[64] = {0};
    char *slash = NULL;
    int prefix = -1;
    char *mask_str = NULL;

    if (!token || !ip_out || !mask_out || ip_out_len == 0 || mask_out_len == 0) {
        return -1;
    }

    snprintf(local, sizeof(local), "%s", token);
    slash = strchr(local, '/');
    if (!slash) {
        return -1;
    }

    *slash = '\0';
    slash++;
    if (local[0] == '\0' || slash[0] == '\0') {
        return -1;
    }

    prefix = atoi(slash);
    if (prefix < 0 || prefix > 32) {
        return -1;
    }

    mask_str = cidr2str(prefix);
    if (!mask_str) {
        return -1;
    }

    snprintf(ip_out, ip_out_len, "%s", local);
    snprintf(mask_out, mask_out_len, "%s", mask_str);
    return 0;
}

static const char *get_section_option_value(struct uci_section *s, const char *option_name);

static int replace_first_list_item(struct uci_context *ctx, const char *uci_key, const char *first_item)
{
    char list_buf[256] = {0};
    char *items[32] = {0};
    int item_count = 0;
    int i = 0;
    char *saveptr = NULL;
    char *token = NULL;

    if (!ctx || !uci_key || !first_item || first_item[0] == '\0') {
        return -1;
    }

    if (fwx_uci_get_list_value(ctx, (char *)uci_key, list_buf, sizeof(list_buf), " ") == 0 && list_buf[0] != '\0') {
        token = strtok_r(list_buf, " ", &saveptr);
        while (token && item_count < (int)(sizeof(items) / sizeof(items[0]))) {
            items[item_count++] = token;
            token = strtok_r(NULL, " ", &saveptr);
        }
    }

    fwx_uci_delete(ctx, (char *)uci_key);
    fwx_uci_add_list(ctx, (char *)uci_key, (char *)first_item);

    for (i = 1; i < item_count; i++) {
        if (items[i] && items[i][0] != '\0') {
            fwx_uci_add_list(ctx, (char *)uci_key, items[i]);
        }
    }

    return 0;
}

static void get_interface_ipaddr_and_mask(struct uci_context *ctx, struct uci_section *s, char *ip_out, size_t ip_out_len, char *mask_out, size_t mask_out_len)
{
    const char *ipaddr_str = NULL;
    const char *netmask_str = NULL;
    struct uci_option *ipaddr_opt = NULL;
    struct uci_element *e = NULL;

    if (!ctx || !s || !ip_out || !mask_out || ip_out_len == 0 || mask_out_len == 0) {
        return;
    }

    ipaddr_str = get_section_option_value(s, "ipaddr");
    netmask_str = get_section_option_value(s, "netmask");
    if (ipaddr_str && ipaddr_str[0] != '\0') {
        snprintf(ip_out, ip_out_len, "%s", ipaddr_str);
        if (netmask_str && netmask_str[0] != '\0') {
            snprintf(mask_out, mask_out_len, "%s", netmask_str);
        }
        return;
    }

    ipaddr_opt = uci_lookup_option(ctx, s, "ipaddr");
    if (ipaddr_opt && ipaddr_opt->type == UCI_TYPE_LIST) {
        uci_foreach_element(&ipaddr_opt->v.list, e) {
            if (e->name && parse_ipaddr_list_token(e->name, ip_out, ip_out_len, mask_out, mask_out_len) == 0) {
                return;
            }
        }
    }
}


static int interface_name_matches(const char *ifname, const char *prefix) {
    if (!ifname || !prefix) return 0;
    int len = strlen(prefix);
    if (strlen(ifname) < len) return 0;
    return strncasecmp(ifname, prefix, len) == 0;
}


static void append_lan_dhcp_to_response(struct json_object *data_obj);
static int update_lan_dhcp_from_req(struct json_object *dhcp_obj);


static int ensure_fwx_network_section(struct uci_context *ctx)
{
    struct uci_ptr ptr;
    if (uci_lookup_ptr(ctx, &ptr, "fwx.network", true) == UCI_OK) {
        return 0;
    }
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "fwx", &pkg) != UCI_OK) {
        LOG_ERROR("ensure_fwx_network_section: load fwx failed\n");
        return -1;
    }
    char path[64];
    snprintf(path, sizeof(path), "fwx.network=network");
    if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) {
        LOG_ERROR("ensure_fwx_network_section: lookup ptr failed\n");
        uci_unload(ctx, pkg);
        return -1;
    }
    if (uci_set(ctx, &ptr) != UCI_OK) {
        LOG_ERROR("ensure_fwx_network_section: set failed\n");
        if (ptr.p) uci_unload(ctx, ptr.p);
        return -1;
    }
    if (uci_save(ctx, ptr.p) != UCI_OK) {
        LOG_ERROR("ensure_fwx_network_section: save failed\n");
        if (ptr.p) uci_unload(ctx, ptr.p);
        return -1;
    }
    if (ptr.p) uci_unload(ctx, ptr.p);
    return 0;
}


static const char *get_section_option_value(struct uci_section *s, const char *option_name) {
    if (!s || !option_name) return NULL;
    
    struct uci_option *o = uci_lookup_option(s->package->ctx, s, option_name);
    if (!o || o->type != UCI_TYPE_STRING) {
        return NULL;
    }
    return o->v.string;
}


static void get_section_list_values(struct uci_section *s, const char *option_name, 
                                     struct json_object *array) {
    if (!s || !option_name || !array) return;
    
    struct uci_option *o = uci_lookup_option(s->package->ctx, s, option_name);
    if (!o || o->type != UCI_TYPE_LIST) {
        return;
    }
    
    struct uci_element *e;
    uci_foreach_element(&o->v.list, e) {
        json_object_array_add(array, json_object_new_string(e->name));
    }
}


static struct json_object *get_interface_list_by_type(const char *iftype) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *interfaces_array = json_object_new_array();
    LOG_DEBUG("get_interface_list_by_type called\n");
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "network", &pkg) != UCI_OK) {
        LOG_ERROR("Failed to load network package\n");
        uci_free_context(ctx);
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
		
        struct uci_section *s = uci_to_section(e);
		
		LOG_DEBUG("s = %p\n", s);
        LOG_DEBUG("s->type: %s\n", s->type);

        if (strcmp(s->type, "interface") != 0) {
            continue;
        }

        const char *name_str = s->e.name;
		
        if (!name_str) {
            continue;
        }
        LOG_DEBUG("name_str: %s\n", name_str);

        
        if (!interface_name_matches(name_str, iftype)) {
			LOG_DEBUG("not match \n");
            continue;
        }
        
        const char *device_str = get_section_option_value(s, "device");
        const char *proto_str = get_section_option_value(s, "proto");
        char ipaddr_buf[32] = {0};
        char netmask_buf[32] = {0};
        const char *gateway_str = get_section_option_value(s, "gateway");
        get_interface_ipaddr_and_mask(ctx, s, ipaddr_buf, sizeof(ipaddr_buf), netmask_buf, sizeof(netmask_buf));
        
        LOG_DEBUG("get_interface_list_by_type: device=%s, proto=%s, ipaddr=%s\n", 
                 device_str ? device_str : "NULL",
                 proto_str ? proto_str : "NULL",
                 ipaddr_buf[0] ? ipaddr_buf : "NULL");
        

        struct json_object *dns_array = json_object_new_array();
        if (!dns_array) {
            LOG_ERROR("get_interface_list_by_type: Failed to create dns_array\n");
            continue;
        }
        get_section_list_values(s, "dns", dns_array);
        
        LOG_DEBUG("get_interface_list_by_type: Creating interface object\n");
        struct json_object *iface_obj = json_object_new_object();
        if (!iface_obj) {
            LOG_ERROR("get_interface_list_by_type: Failed to create iface_obj\n");
            json_object_put(dns_array);
            continue;
        }
        
        json_object_object_add(iface_obj, "name", json_object_new_string(name_str));
        json_object_object_add(iface_obj, "device", json_object_new_string(device_str ? device_str : ""));
        json_object_object_add(iface_obj, "proto", json_object_new_string(proto_str ? proto_str : ""));
        json_object_object_add(iface_obj, "ipaddr", json_object_new_string(ipaddr_buf));
        json_object_object_add(iface_obj, "netmask", json_object_new_string(netmask_buf));
        json_object_object_add(iface_obj, "gateway", json_object_new_string(gateway_str ? gateway_str : ""));
        json_object_object_add(iface_obj, "dns", dns_array);
        
        LOG_DEBUG("get_interface_list_by_type: Added interface %s to array\n", name_str);
        json_object_array_add(interfaces_array, iface_obj);
        LOG_DEBUG("222222222222\n");
    }
    
	LOG_DEBUG("22222222\n");
	
	
    uci_free_context(ctx);
    
	
    json_object_object_add(data_obj, "list", interfaces_array);
    LOG_DEBUG("data_obj: %s\n", json_object_to_json_string(data_obj));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_get_lan_list(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_lan_list: called\n");
    struct json_object *result = get_interface_list_by_type("lan");
    LOG_DEBUG("fwx_api_get_lan_list: returning result\n");
    return result;
}


struct json_object *fwx_api_get_wan_list(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_wan_list: called\n");
    struct json_object *result = get_interface_list_by_type("wan");
    LOG_DEBUG("fwx_api_get_wan_list: returning result\n");
    return result;
}


static struct json_object *add_or_mod_interface(struct json_object *req_obj, const char *iftype, int is_add) {
	int i;
	if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    struct json_object *device_obj = json_object_object_get(req_obj, "device");
    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    
    if (!name_obj || !device_obj || !proto_obj) {
        LOG_ERROR("Missing required fields: name, device, proto\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *name = json_object_get_string(name_obj);
    const char *device = json_object_get_string(device_obj);
    const char *proto = json_object_get_string(proto_obj);
    

    if (!interface_name_matches(name, iftype)) {
        LOG_ERROR("Interface name '%s' must start with '%s'\n", name, iftype);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    if (strcmp(proto, "dhcp") != 0 && strcmp(proto, "static") != 0 && 
        (strcmp(iftype, "wan") != 0 || strcmp(proto, "pppoe") != 0)) {
        LOG_ERROR("Invalid protocol '%s' for %s interface\n", proto, iftype);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    if (strcmp(proto, "static") == 0) {
        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        if (!ipaddr_obj || !netmask_obj) {
            LOG_ERROR("ipaddr and netmask are required for static protocol\n");
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_ptr ptr;
    char uci_path[256];
    snprintf(uci_path, sizeof(uci_path), "network.%s", name);
    
    int exists = (uci_lookup_ptr(ctx, &ptr, uci_path, true) == UCI_OK);
    
    if (is_add) {

        if (exists) {
            LOG_ERROR("Interface '%s' already exists\n", name);
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else {

        if (!exists) {
            LOG_ERROR("Interface '%s' not found\n", name);
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    

    if (is_add) {


        char section_path[256];
        snprintf(section_path, sizeof(section_path), "network.%s=interface", name);
        
        struct uci_ptr ptr;
        if (uci_lookup_ptr(ctx, &ptr, section_path, true) != UCI_OK) {
            LOG_ERROR("Failed to create interface section '%s'\n", name);
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (uci_set(ctx, &ptr) != UCI_OK) {
            LOG_ERROR("Failed to set interface section '%s'\n", name);
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (uci_save(ctx, ptr.p) != UCI_OK) {
            LOG_ERROR("Failed to save network package\n");
            if (ptr.p) uci_unload(ctx, ptr.p);
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        
        if (ptr.p) uci_unload(ctx, ptr.p);
    }
    

    snprintf(uci_path, sizeof(uci_path), "network.%s.device", name);
    fwx_uci_set_value(ctx, uci_path, (char *)device);
    

    snprintf(uci_path, sizeof(uci_path), "network.%s.proto", name);
    fwx_uci_set_value(ctx, uci_path, (char *)proto);
    

    if (strcmp(proto, "static") == 0) {
        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
        
        if (ipaddr_obj) {
            if (strcmp(iftype, "lan") == 0) {
                const char *ipaddr = json_object_get_string(ipaddr_obj);
                const char *netmask = netmask_obj ? json_object_get_string(netmask_obj) : NULL;
                int prefix = netmask_to_prefix(netmask ? netmask : "");
                char ipaddr_with_prefix[64] = {0};

                if (prefix < 0) {
                    prefix = 24;
                }
                snprintf(uci_path, sizeof(uci_path), "network.%s.ipaddr", name);
                if (ipaddr && ipaddr[0] != '\0') {
                    snprintf(ipaddr_with_prefix, sizeof(ipaddr_with_prefix), "%s/%d", ipaddr, prefix);
                    replace_first_list_item(ctx, uci_path, ipaddr_with_prefix);
                }
            } else {
                snprintf(uci_path, sizeof(uci_path), "network.%s.ipaddr", name);
                fwx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(ipaddr_obj));
            }
        }
        
        if (strcmp(iftype, "lan") == 0) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.netmask", name);
            fwx_uci_delete(ctx, uci_path);
        } else if (netmask_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.netmask", name);
            fwx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(netmask_obj));
        }
        
        if (gateway_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.gateway", name);
            fwx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(gateway_obj));
        }
        

        struct json_object *dns_obj = json_object_object_get(req_obj, "dns");
        if (dns_obj && json_object_is_type(dns_obj, json_type_array)) {

            char dns_path[256];
            snprintf(dns_path, sizeof(dns_path), "network.%s.dns", name);
            fwx_uci_delete(ctx, dns_path);
            

            struct uci_ptr ptr;
            memset(&ptr, 0, sizeof(ptr));
            ptr.package = "network";
            ptr.section = name;
            ptr.option = "dns";
            
            int dns_len = json_object_array_length(dns_obj);
            for (i = 0; i < dns_len; i++) {
                struct json_object *dns_item = json_object_array_get_idx(dns_obj, i);
                const char *dns_str = json_object_get_string(dns_item);
                if (dns_str && strlen(dns_str) > 0) {
                    ptr.value = (char *)dns_str;
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS to list: %s\n", dns_str);
                    }
                }
            }
        }
    } else if (strcmp(proto, "pppoe") == 0 && strcmp(iftype, "wan") == 0) {

        struct json_object *username_obj = json_object_object_get(req_obj, "username");
        struct json_object *password_obj = json_object_object_get(req_obj, "password");
        
        if (username_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.username", name);
            fwx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(username_obj));
        }
        
        if (password_obj) {
            snprintf(uci_path, sizeof(uci_path), "network.%s.password", name);
            fwx_uci_set_value(ctx, uci_path, (char *)json_object_get_string(password_obj));
        }
    }
    
    fwx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    
    LOG_DEBUG("%s interface '%s' %s successfully\n", iftype, name, is_add ? "added" : "modified");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_add_lan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_add_lan called\n");
    return add_or_mod_interface(req_obj, "lan", 1);
}


struct json_object *fwx_api_mod_lan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_mod_lan called\n");
    return add_or_mod_interface(req_obj, "lan", 0);
}


struct json_object *fwx_api_add_wan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_add_wan called\n");
    return add_or_mod_interface(req_obj, "wan", 1);
}


struct json_object *fwx_api_mod_wan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_mod_wan called\n");
    return add_or_mod_interface(req_obj, "wan", 0);
}


static struct json_object *del_interface(struct json_object *req_obj, const char *iftype) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    if (!name_obj) {
        LOG_ERROR("Missing required field: name\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *name = json_object_get_string(name_obj);
    

    if (!interface_name_matches(name, iftype)) {
        LOG_ERROR("Interface name '%s' must start with '%s'\n", name, iftype);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    struct uci_ptr ptr;
    char uci_path[256];
    snprintf(uci_path, sizeof(uci_path), "network.%s", name);
    
    if (uci_lookup_ptr(ctx, &ptr, uci_path, true) != UCI_OK) {
        LOG_ERROR("Interface '%s' not found\n", name);
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    fwx_uci_delete(ctx, uci_path);
    
    fwx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    
    LOG_DEBUG("%s interface '%s' deleted successfully\n", iftype, name);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_del_lan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_del_lan called\n");
    return del_interface(req_obj, "lan");
}


struct json_object *fwx_api_del_wan(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_del_wan called\n");
    return del_interface(req_obj, "wan");
}


struct json_object *fwx_api_get_lan_info(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_lan_info called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char ipaddr_str[32] = {0};
    char netmask_str[32] = {0};
    char proto_str[32] = {0};
    char gateway_str[32] = {0};
    char dns1_str[32] = {0};
    char dns2_str[32] = {0};
    
    {
        char ipaddr_list_buf[128] = {0};
        int list_ok = 0;

        if (fwx_uci_get_list_value(ctx, "network.lan.ipaddr", ipaddr_list_buf, sizeof(ipaddr_list_buf), " ") == 0 &&
            ipaddr_list_buf[0] != '\0') {
            char *saveptr = NULL;
            char *token = strtok_r(ipaddr_list_buf, " ", &saveptr);
            if (token && parse_ipaddr_list_token(token, ipaddr_str, sizeof(ipaddr_str), netmask_str, sizeof(netmask_str)) == 0) {
                list_ok = 1;
            }
        }

        if (!list_ok) {
            fwx_uci_get_value(ctx, "network.lan.ipaddr", ipaddr_str, sizeof(ipaddr_str));
            fwx_uci_get_value(ctx, "network.lan.netmask", netmask_str, sizeof(netmask_str));
        }
    }
    fwx_uci_get_value(ctx, "network.lan.proto", proto_str, sizeof(proto_str));
    fwx_uci_get_value(ctx, "network.lan.gateway", gateway_str, sizeof(gateway_str));
    

    char dns_list_buf[128] = {0};
    if (fwx_uci_get_list_value(ctx, "network.lan.dns", dns_list_buf, sizeof(dns_list_buf), " ") == 0) {
        char *saveptr = NULL;
        char *p = strtok_r(dns_list_buf, " ", &saveptr);
        if (p) {
            strncpy(dns1_str, p, sizeof(dns1_str) - 1);
            p = strtok_r(NULL, " ", &saveptr);
            if (p) {
                strncpy(dns2_str, p, sizeof(dns2_str) - 1);
            }
        }
    }
    
    json_object_object_add(data_obj, "ipaddr", json_object_new_string(ipaddr_str));
    json_object_object_add(data_obj, "netmask", json_object_new_string(netmask_str));
    json_object_object_add(data_obj, "proto", json_object_new_string(proto_str));
    json_object_object_add(data_obj, "gateway", json_object_new_string(gateway_str));
    json_object_object_add(data_obj, "dns1", json_object_new_string(dns1_str));
    json_object_object_add(data_obj, "dns2", json_object_new_string(dns2_str));
    append_lan_dhcp_to_response(data_obj);
    
    uci_free_context(ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_lan_info(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_set_lan_info called22\n");
    
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    char test_buf[32] = {0};
    if (fwx_uci_get_value(ctx, "network.lan.proto", test_buf, sizeof(test_buf)) != 0) {

        if (fwx_uci_set_value(ctx, "network.lan", "interface") != 0) {
            LOG_ERROR("Failed to create lan section\n");
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    

    struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
    struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
    struct json_object *dns1_obj = json_object_object_get(req_obj, "dns1");
    struct json_object *dns2_obj = json_object_object_get(req_obj, "dns2");
    
    if (proto_obj) {
        const char *proto = json_object_get_string(proto_obj);
        if (proto && strcmp(proto, "pppoe") == 0) {
            LOG_ERROR("LAN interface does not support PPPoE protocol\n");
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        fwx_uci_set_value(ctx, "network.lan.proto", (char *)proto);
    }
    
    
    if (ipaddr_obj) {
        const char *ipaddr = json_object_get_string(ipaddr_obj);
        const char *netmask = netmask_obj ? json_object_get_string(netmask_obj) : NULL;
        int prefix = netmask_to_prefix(netmask ? netmask : "");

        if (ipaddr && ipaddr[0] != '\0') {
            char ipaddr_with_prefix[64] = {0};
            if (prefix < 0) {
                prefix = 24;
            }
            snprintf(ipaddr_with_prefix, sizeof(ipaddr_with_prefix), "%s/%d", ipaddr, prefix);
            /* 统一使用 list ipaddr（x.x.x.x/nn）格式，只替换第一项并保留其余项 */
            replace_first_list_item(ctx, "network.lan.ipaddr", ipaddr_with_prefix);
        }
    }
    
    fwx_uci_delete(ctx, "network.lan.netmask");
    
    if (gateway_obj) {
        fwx_uci_set_value(ctx, "network.lan.gateway", (char *)json_object_get_string(gateway_obj));
    }
    

    if (dns1_obj || dns2_obj) {
        fwx_uci_delete(ctx, "network.lan.dns");
        
        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        ptr.package = "network";
        ptr.section = "lan";
        ptr.option = "dns";
        
        if (dns1_obj) {
            const char *dns1 = json_object_get_string(dns1_obj);
            if (dns1 && strlen(dns1) > 0) {
                ptr.value = (char *)dns1;
                if (uci_add_list(ctx, &ptr) != UCI_OK) {
                    LOG_ERROR("Failed to add DNS1 to list\n");
                }
            }
        }
        
        if (dns2_obj) {
            const char *dns2 = json_object_get_string(dns2_obj);
            if (dns2 && strlen(dns2) > 0) {
                ptr.value = (char *)dns2;
                if (uci_add_list(ctx, &ptr) != UCI_OK) {
                    LOG_ERROR("Failed to add DNS2 to list\n");
                }
            }
        }
    }
    fwx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    update_lan_dhcp_from_req(json_object_object_get(req_obj, "dhcp"));
    system("/etc/init.d/network restart");
    system("/etc/init.d/dnsmasq restart");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_get_wan_info(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_get_wan_info called\n");
    
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char ipaddr_str[32] = {0};
    char netmask_str[32] = {0};
    char proto_str[32] = {0};
    char gateway_str[32] = {0};
    char dns1_str[32] = {0};
    char dns2_str[32] = {0};
    char username_str[128] = {0};
    char password_str[128] = {0};
    
    fwx_uci_get_value(ctx, "network.wan.ipaddr", ipaddr_str, sizeof(ipaddr_str));
    fwx_uci_get_value(ctx, "network.wan.netmask", netmask_str, sizeof(netmask_str));
    fwx_uci_get_value(ctx, "network.wan.proto", proto_str, sizeof(proto_str));
    fwx_uci_get_value(ctx, "network.wan.gateway", gateway_str, sizeof(gateway_str));
    fwx_uci_get_value(ctx, "network.wan.username", username_str, sizeof(username_str));
    fwx_uci_get_value(ctx, "network.wan.password", password_str, sizeof(password_str));
    

    char dns_list_buf[128] = {0};
    if (fwx_uci_get_list_value(ctx, "network.wan.dns", dns_list_buf, sizeof(dns_list_buf), " ") == 0) {
        char *saveptr = NULL;
        char *p = strtok_r(dns_list_buf, " ", &saveptr);
        if (p) {
            strncpy(dns1_str, p, sizeof(dns1_str) - 1);
            p = strtok_r(NULL, " ", &saveptr);
            if (p) {
                strncpy(dns2_str, p, sizeof(dns2_str) - 1);
            }
        }
    }
    
    json_object_object_add(data_obj, "ipaddr", json_object_new_string(ipaddr_str));
    json_object_object_add(data_obj, "netmask", json_object_new_string(netmask_str));
    json_object_object_add(data_obj, "proto", json_object_new_string(proto_str));
    json_object_object_add(data_obj, "gateway", json_object_new_string(gateway_str));
    json_object_object_add(data_obj, "dns1", json_object_new_string(dns1_str));
    json_object_object_add(data_obj, "dns2", json_object_new_string(dns2_str));
    json_object_object_add(data_obj, "username", json_object_new_string(username_str));
    json_object_object_add(data_obj, "password", json_object_new_string(password_str));
    
    uci_free_context(ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_wan_info(struct json_object *req_obj) {
    LOG_DEBUG("fwx_api_set_wan_info called\n");
    
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    char test_buf[32] = {0};
    if (fwx_uci_get_value(ctx, "network.wan.proto", test_buf, sizeof(test_buf)) != 0) {

        if (fwx_uci_set_value(ctx, "network.wan", "interface") != 0) {
            LOG_ERROR("Failed to create wan section\n");
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    

    struct json_object *proto_obj = json_object_object_get(req_obj, "proto");
    const char *proto = NULL;
    if (proto_obj) {
        proto = json_object_get_string(proto_obj);
        fwx_uci_set_value(ctx, "network.wan.proto", (char *)proto);
    } else {

        char proto_buf[32] = {0};
        if (fwx_uci_get_value(ctx, "network.wan.proto", proto_buf, sizeof(proto_buf)) == 0) {
            proto = proto_buf;
        }
    }
    
    if (!proto) {
        LOG_ERROR("Protocol not specified and cannot be determined\n");
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_DEBUG("proto: %s\n", proto);

    if (strcmp(proto, "static") == 0) {

        struct json_object *ipaddr_obj = json_object_object_get(req_obj, "ipaddr");
        struct json_object *netmask_obj = json_object_object_get(req_obj, "netmask");
        struct json_object *gateway_obj = json_object_object_get(req_obj, "gateway");
        struct json_object *dns1_obj = json_object_object_get(req_obj, "dns1");
        struct json_object *dns2_obj = json_object_object_get(req_obj, "dns2");
        
        if (ipaddr_obj) {
            fwx_uci_set_value(ctx, "network.wan.ipaddr", (char *)json_object_get_string(ipaddr_obj));
        }
        
        if (netmask_obj) {
            fwx_uci_set_value(ctx, "network.wan.netmask", (char *)json_object_get_string(netmask_obj));
        }
        
        if (gateway_obj) {
            fwx_uci_set_value(ctx, "network.wan.gateway", (char *)json_object_get_string(gateway_obj));
        }

        if (dns1_obj || dns2_obj) {
            fwx_uci_delete(ctx, "network.wan.dns");
            
            struct uci_ptr ptr;
            memset(&ptr, 0, sizeof(ptr));
            ptr.package = "network";
            ptr.section = "wan";
            ptr.option = "dns";
            
            if (dns1_obj) {
                const char *dns1 = json_object_get_string(dns1_obj);
                if (dns1 && strlen(dns1) > 0) {
                    ptr.value = (char *)dns1;
                    
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS1 to list\n");
                    }
                }
            }
            
            if (dns2_obj) {
                
                const char *dns2 = json_object_get_string(dns2_obj);
                if (dns2 && strlen(dns2) > 0) {
                    
                    ptr.value = (char *)dns2;
                    if (uci_add_list(ctx, &ptr) != UCI_OK) {
                        LOG_ERROR("Failed to add DNS2 to list\n");
                    }
                }
            }
            
        }
    } else if (strcmp(proto, "pppoe") == 0) {
        struct json_object *username_obj = json_object_object_get(req_obj, "username");
        struct json_object *password_obj = json_object_object_get(req_obj, "password");
        if (username_obj) {
            const char *username = json_object_get_string(username_obj);
            if (username && strlen(username) > 0) {
                
                fwx_uci_set_value(ctx, "network.wan.username", (char *)username);
            }
        }
    
        if (password_obj) {
            const char *password = json_object_get_string(password_obj);
            if (password && strlen(password) > 0) {
                
                fwx_uci_set_value(ctx, "network.wan.password", (char *)password);
            }
        }
         
    } else if (strcmp(proto, "dhcp") == 0) {
        
    }
    
    fwx_uci_commit(ctx, "network");
    uci_free_context(ctx);
    

    LOG_DEBUG("Reloading network configuration...\n");
    int ret = system("/etc/init.d/network reload");
    if (ret != 0) {
        LOG_ERROR("Failed to reload network, return code: %d\n", ret);
    }
    
    LOG_DEBUG("WAN interface info updated successfully\n");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_get_work_mode(struct json_object *req_obj)
{
    LOG_DEBUG("fwx_api_get_work_mode called\n");
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("fwx_api_get_work_mode: alloc ctx failed\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    int work_mode = fwx_uci_get_int_value(ctx, "fwx.network.work_mode");
    if (work_mode != 0 && work_mode != 1) {
        work_mode = 0;
    }
    struct json_object *data_obj = json_object_new_object();
    if (!data_obj) {
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    json_object_object_add(data_obj, "work_mode", json_object_new_int(work_mode));
    uci_free_context(ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_work_mode(struct json_object *req_obj)
{
    LOG_DEBUG("fwx_api_set_work_mode called\n");
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    struct json_object *wm_obj = json_object_object_get(req_obj, "work_mode");
    if (!wm_obj) {
        LOG_ERROR("fwx_api_set_work_mode: missing work_mode\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    int work_mode = json_object_get_int(wm_obj);
    if (work_mode != 0 && work_mode != 1) {
        LOG_ERROR("fwx_api_set_work_mode: invalid work_mode %d\n", work_mode);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("fwx_api_set_work_mode: alloc ctx failed\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    fwx_uci_set_int_value(ctx, "fwx.network.work_mode", work_mode);
    fwx_uci_commit(ctx, "fwx");
    uci_free_context(ctx);

	update_fwx_proc_u32_value("work_mode", work_mode);

    LOG_DEBUG("fwx_api_set_work_mode: work_mode=%d\n", work_mode);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


static int parse_leasetime_to_minutes(const char *lt)
{
    if (!lt || lt[0] == '\0') return 0;
    int len = strlen(lt);
    char unit = lt[len - 1];
    int val = atoi(lt);
    if (val < 0) val = 0;
    if (unit == 'h' || unit == 'H') {
        return val * 60;
    } else if (unit == 'm' || unit == 'M') {
        return val;
    }
    return val; 
}


static void format_minutes_to_leasetime(int minutes, char *out, size_t out_len)
{
    if (minutes < 0) minutes = 0;
    if (minutes > 60) {
        int hours = minutes / 60; 
        snprintf(out, out_len, "%dh", hours > 0 ? hours : 1);
    } else {
        snprintf(out, out_len, "%dm", minutes);
    }
}


static void fill_lan_dhcp_info(struct json_object *data_obj)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("fill_lan_dhcp_info: alloc ctx failed\n");
        return;
    }

    int enable = 1;
    int start = 0;
    int limit = 0;
    int lease_minutes = 0;
    char lease_str[32] = {0};
    char val_buf[32] = {0};

    if (fwx_uci_get_value(ctx, "dhcp.lan.ignore", val_buf, sizeof(val_buf)) == 0) {
        if (strcmp(val_buf, "1") == 0) enable = 0;
    }
    if (fwx_uci_get_value(ctx, "dhcp.lan.start", val_buf, sizeof(val_buf)) == 0) {
        start = atoi(val_buf);
    }
    if (fwx_uci_get_value(ctx, "dhcp.lan.limit", val_buf, sizeof(val_buf)) == 0) {
        limit = atoi(val_buf);
    }
    if (fwx_uci_get_value(ctx, "dhcp.lan.leasetime", lease_str, sizeof(lease_str)) == 0) {
        lease_minutes = parse_leasetime_to_minutes(lease_str);
    }

    struct json_object *dhcp_obj = json_object_new_object();
    if (dhcp_obj) {
        json_object_object_add(dhcp_obj, "enable", json_object_new_int(enable));
        json_object_object_add(dhcp_obj, "start", json_object_new_int(start));
        json_object_object_add(dhcp_obj, "limit", json_object_new_int(limit));
        json_object_object_add(dhcp_obj, "leasetime", json_object_new_int(lease_minutes));
        json_object_object_add(data_obj, "dhcp", dhcp_obj);
    }

    uci_free_context(ctx);
}


static int ensure_dhcp_lan_section(struct uci_context *ctx)
{
    struct uci_ptr ptr;
    if (uci_lookup_ptr(ctx, &ptr, "dhcp.lan", true) == UCI_OK) {
        return 0;
    }
    struct uci_package *pkg = NULL;
    if (uci_load(ctx, "dhcp", &pkg) != UCI_OK) {
        LOG_ERROR("ensure_dhcp_lan_section: load dhcp failed\n");
        return -1;
    }
    char path[64];
    snprintf(path, sizeof(path), "dhcp.lan=dhcp");
    if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) {
        LOG_ERROR("ensure_dhcp_lan_section: lookup ptr failed\n");
        uci_unload(ctx, pkg);
        return -1;
    }
    if (uci_set(ctx, &ptr) != UCI_OK) {
        LOG_ERROR("ensure_dhcp_lan_section: set failed\n");
        if (ptr.p) uci_unload(ctx, ptr.p);
        return -1;
    }
    if (uci_save(ctx, ptr.p) != UCI_OK) {
        LOG_ERROR("ensure_dhcp_lan_section: save failed\n");
        if (ptr.p) uci_unload(ctx, ptr.p);
        return -1;
    }
    if (ptr.p) uci_unload(ctx, ptr.p);
    
    fwx_uci_set_value(ctx, "dhcp.lan.interface", "lan");
    return 0;
}


static void append_lan_dhcp_to_response(struct json_object *data_obj)
{
    if (!data_obj) return;
    fill_lan_dhcp_info(data_obj);
}


static int update_lan_dhcp_from_req(struct json_object *dhcp_obj)
{
    

    if (!dhcp_obj) return 0; 
	
    
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("update_lan_dhcp_from_req: alloc ctx failed\n");
        return -1;
    }
	
    

    struct json_object *enable_obj = json_object_object_get(dhcp_obj, "enable");
    struct json_object *start_obj = json_object_object_get(dhcp_obj, "start");
    struct json_object *limit_obj = json_object_object_get(dhcp_obj, "limit");
    struct json_object *lt_obj = json_object_object_get(dhcp_obj, "leasetime");
    

    if (enable_obj) {
        int en = json_object_get_int(enable_obj);
        fwx_uci_set_value(ctx, "dhcp.lan.ignore", en ? "0" : "1");
    }
    if (start_obj) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", json_object_get_int(start_obj));
        fwx_uci_set_value(ctx, "dhcp.lan.start", buf);
    }
    if (limit_obj) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", json_object_get_int(limit_obj));
        fwx_uci_set_value(ctx, "dhcp.lan.limit", buf);
    }
    if (lt_obj) {
        int minutes = json_object_get_int(lt_obj);
        char lease_buf[32];
        format_minutes_to_leasetime(minutes, lease_buf, sizeof(lease_buf));
        fwx_uci_set_value(ctx, "dhcp.lan.leasetime", lease_buf);
    }
    

    fwx_uci_commit(ctx, "dhcp");
    uci_free_context(ctx);
    return 0;
}

