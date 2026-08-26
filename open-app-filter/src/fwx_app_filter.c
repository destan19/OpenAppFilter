// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>
#include "fwx_user.h"
#include "fwx_netlink.h"
#include "fwx_ubus.h"
#include "fwx_config.h"
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fwx.h"
#include <stdio.h>
#include <json-c/json.h>

#include "fwx_utils.h"


#define APPFILTER_RULES_STATE_FILE "/tmp/appfilter_rules_state"
#define APPFILTER_WHITELIST_STATE_FILE "/tmp/appfilter_whitelist_state"


static void set_state_file(const char *file_path) {
    FILE *fd = fopen(file_path, "w");
    if (fd) {
        fprintf(fd, "1");
        fclose(fd);
        LOG_DEBUG("Set state file: %s\n", file_path);
    } else {
        LOG_ERROR("Failed to set state file: %s\n", file_path);
    }
}

fwx_run_time_status_t g_af_status;

void dev_list_timeout_handler(struct uloop_timeout *t);


static int find_rule_index_by_id(struct uci_context *uci_ctx, int id) {
    char id_str_uci[32];
	int i;
    int num = fwx_uci_get_list_num(uci_ctx, "appfilter", "rule");
    for (i = 0; i < num; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].id", i);
        if (fwx_uci_get_value(uci_ctx, buf, id_str_uci, sizeof(id_str_uci)) != 0) {
            continue;
        }
        if (atoi(id_str_uci) == id) {
            return i;
        }
    }
    return -1; // Not found
}

// Helper function to get option value from uci section
static const char *get_option_value(struct uci_section *s, const char *option_name) {
    if (!s || !option_name) return NULL;
    struct uci_option *o = uci_lookup_option(s->package->ctx, s, option_name);
    if (!o || o->type != UCI_TYPE_STRING) {
        return NULL;
    }
    return o->v.string;
}

static int normalize_app_id_token(const char *raw, char *out, int out_len) {
    int start = 0, end = 0, val = 0;
    char extra = '\0';
    if (!raw || !out || out_len <= 0) return 0;

    if (sscanf(raw, "%d-%d%c", &start, &end, &extra) == 2) {
        if (start > 0 && end > 0 && start <= end) {
            snprintf(out, out_len, "%d-%d", start, end);
            return 1;
        }
        return 0;
    }

    if (sscanf(raw, "%d%c", &val, &extra) == 1 && val > 0) {
        snprintf(out, out_len, "%d", val);
        return 1;
    }
    return 0;
}

struct json_object *fwx_api_get_filter_rules(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *rules_array = json_object_new_array();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    // Load appfilter package once
    struct uci_package *pkg = NULL;
    if (uci_load(uci_ctx, "appfilter", &pkg) != UCI_OK) {
        LOG_ERROR("Failed to load appfilter package\n");
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    // Traverse all sections using uci_foreach_element
    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        
        // Only process "rule" type sections
        if (strcmp(s->type, "rule") != 0) {
            continue;
        }

        LOG_DEBUG("Loading rule: %s\n", s->e.name);

        // Get id - required field
        const char *id_str = get_option_value(s, "id");
        if (!id_str) {
            LOG_ERROR("Failed to get id for rule %s, skipping\n", s->e.name);
            continue;
        }

        // Get other fields with defaults
        const char *name_str = get_option_value(s, "name");
        const char *mode_str = get_option_value(s, "mode");
        const char *user_mac_str = get_option_value(s, "user_mac");
        const char *user_name_str = get_option_value(s, "user_name");
        const char *enabled_str = get_option_value(s, "enabled");
        const char *filter_quic_str = get_option_value(s, "filter_quic");

        struct json_object *rule_obj = json_object_new_object();
        if (!rule_obj) {
            LOG_ERROR("Failed to create rule_obj for rule %s\n", s->e.name);
            continue;
        }
        
        json_object_object_add(rule_obj, "id", json_object_new_int(atoi(id_str)));
        json_object_object_add(rule_obj, "name", json_object_new_string(name_str ? name_str : ""));
        json_object_object_add(rule_obj, "mode", json_object_new_int(mode_str ? atoi(mode_str) : 1));
        json_object_object_add(rule_obj, "user_mac", json_object_new_string(user_mac_str ? user_mac_str : ""));
        json_object_object_add(rule_obj, "user_name", json_object_new_string(user_name_str ? user_name_str : ""));
        json_object_object_add(rule_obj, "enabled", json_object_new_int(enabled_str ? atoi(enabled_str) : 1));
        json_object_object_add(rule_obj, "filter_quic", json_object_new_int(filter_quic_str ? atoi(filter_quic_str) : 0));

        // Process time_rule list
        struct json_object *time_rules_array = json_object_new_array();
        struct uci_option *time_rule_opt = uci_lookup_option(uci_ctx, s, "time_rule");
        if (time_rule_opt && time_rule_opt->type == UCI_TYPE_LIST) {
            struct uci_element *time_elem;
            uci_foreach_element(&time_rule_opt->v.list, time_elem) {
                const char *time_rule_str = time_elem->name;
                if (!time_rule_str) continue;

                LOG_DEBUG("Loading time_rule: %s\n", time_rule_str);
                struct json_object *time_rule_obj = json_object_new_object();
                struct json_object *weekdays_array = json_object_new_array();

                // Parse time_rule string: "weekday1,weekday2,...,start_time,end_time"
                char *time_rule_copy = strdup(time_rule_str);
                if (time_rule_copy) {
                    char *saveptr;
                    char *token = strtok_r(time_rule_copy, ",", &saveptr);
                    char *start_time = NULL;
                    char *end_time = NULL;

                    while (token) {
                        if (strchr(token, ':') != NULL) {
                            // This is a time string (HH:MM format)
                            if (start_time == NULL) {
                                start_time = token;
                            } else if (end_time == NULL) {
                                end_time = token;
                                break;
                            }
                        } else {
                            // This is a weekday number
                            int weekday = atoi(token);
                            if (weekday >= 0 && weekday <= 6) {
                                json_object_array_add(weekdays_array, json_object_new_int(weekday));
                            }
                        }
                        token = strtok_r(NULL, ",", &saveptr);
                    }

                    if (start_time) {
                        json_object_object_add(time_rule_obj, "start_time", json_object_new_string(start_time));
                    }
                    if (end_time) {
                        json_object_object_add(time_rule_obj, "end_time", json_object_new_string(end_time));
                    }
                    free(time_rule_copy);
                }

                json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
                json_object_array_add(time_rules_array, time_rule_obj);
            }
        }
        json_object_object_add(rule_obj, "time_rules", time_rules_array);

        // Process app_id list（支持字符串段格式：1001-1005）
        struct json_object *app_ids_array = json_object_new_array();
        struct uci_option *app_id_opt = uci_lookup_option(uci_ctx, s, "app_id");
        if (app_id_opt && app_id_opt->type == UCI_TYPE_LIST) {
            struct uci_element *app_elem;
            uci_foreach_element(&app_id_opt->v.list, app_elem) {
                const char *app_id_str = app_elem->name;
                if (!app_id_str) continue;
                json_object_array_add(app_ids_array, json_object_new_string(app_id_str));
            }
        }
        json_object_object_add(rule_obj, "app_ids", app_ids_array);
        
        json_object_array_add(rules_array, rule_obj);
        LOG_DEBUG("Successfully loaded rule: id=%s, name=%s\n", id_str, name_str ? name_str : "");
    }
    
    // Unload package
    uci_unload(uci_ctx, pkg);
    uci_free_context(uci_ctx);
    
    json_object_object_add(data_obj, "list", rules_array);
    
    LOG_DEBUG("Returning %d rules\n", json_object_array_length(rules_array));

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_add_filter_rule(struct json_object *req_obj) {
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    struct json_object *filter_quic_obj = json_object_object_get(req_obj, "filter_quic");
    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
    struct json_object *app_ids_obj = json_object_object_get(req_obj, "app_ids");
    int i, j;
    if (!name_obj || !mode_obj || !time_rules_obj || !app_ids_obj) {
        LOG_ERROR("Missing required fields\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    int rule_id = (int)time(NULL);
    

    fwx_uci_add_section(uci_ctx, "appfilter", "rule");
    
    char buf[256];
    snprintf(buf, sizeof(buf), "appfilter.@rule[-1].id");
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", rule_id);
    fwx_uci_set_value(uci_ctx, buf, id_str);
    
    snprintf(buf, sizeof(buf), "appfilter.@rule[-1].name");
    fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    
    snprintf(buf, sizeof(buf), "appfilter.@rule[-1].mode");
    char mode_str[16];
    snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
    fwx_uci_set_value(uci_ctx, buf, mode_str);
    
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[-1].user_mac");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[-1].user_name");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    snprintf(buf, sizeof(buf), "appfilter.@rule[-1].enabled");
    char enabled_str[16];
    int enabled = enabled_obj ? json_object_get_int(enabled_obj) : 1;
    snprintf(enabled_str, sizeof(enabled_str), "%d", enabled);
    fwx_uci_set_value(uci_ctx, buf, enabled_str);

    snprintf(buf, sizeof(buf), "appfilter.@rule[-1].filter_quic");
    {
        char filter_quic_str[16];
        int filter_quic = filter_quic_obj ? json_object_get_int(filter_quic_obj) : 0;
        snprintf(filter_quic_str, sizeof(filter_quic_str), "%d", filter_quic ? 1 : 0);
        fwx_uci_set_value(uci_ctx, buf, filter_quic_str);
    }
    

    int time_rules_len = json_object_array_length(time_rules_obj);
    for (i = 0; i < time_rules_len; i++) {
        struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
        struct json_object *weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
        struct json_object *start_time_obj = json_object_object_get(time_rule_obj, "start_time");
        struct json_object *end_time_obj = json_object_object_get(time_rule_obj, "end_time");
        
        if (!weekdays_obj || !start_time_obj || !end_time_obj) {
            continue;
        }
        

        char time_rule_str[256] = {0};
        int weekdays_len = json_object_array_length(weekdays_obj);
        for (j = 0; j < weekdays_len; j++) {
            struct json_object *weekday_obj = json_object_array_get_idx(weekdays_obj, j);
            char weekday_str[16];
            snprintf(weekday_str, sizeof(weekday_str), "%d", json_object_get_int(weekday_obj));
            if (j > 0) strcat(time_rule_str, ",");
            strcat(time_rule_str, weekday_str);
        }
        strcat(time_rule_str, ",");
        strcat(time_rule_str, json_object_get_string(start_time_obj));
        strcat(time_rule_str, ",");
        strcat(time_rule_str, json_object_get_string(end_time_obj));
        
        snprintf(buf, sizeof(buf), "appfilter.@rule[-1].time_rule");
        fwx_uci_add_list(uci_ctx, buf, time_rule_str);
    }
    

    int app_ids_len = json_object_array_length(app_ids_obj);
    for (i = 0; i < app_ids_len; i++) {
        struct json_object *app_id_obj = json_object_array_get_idx(app_ids_obj, i);
        const char *raw = json_object_get_string(app_id_obj);
        char app_id_str[64] = {0};
        if (normalize_app_id_token(raw, app_id_str, sizeof(app_id_str))) {
            snprintf(buf, sizeof(buf), "appfilter.@rule[-1].app_id");
            fwx_uci_add_list(uci_ctx, buf, app_id_str);
        }
    }
    
    fwx_uci_commit(uci_ctx, "appfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(APPFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Added filter rule: id=%d, name=%s\n", rule_id, json_object_get_string(name_obj));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_update_filter_rule(struct json_object *req_obj) {
    struct json_object *id_obj = json_object_object_get(req_obj, "id");
	int i, j;
    if (!id_obj) {
        LOG_ERROR("Missing id field\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int rule_id = json_object_get_int(id_obj);
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int index = find_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[256];
    

    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    if (name_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    }
    
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    if (mode_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].mode", index);
        char mode_str[16];
        snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
        fwx_uci_set_value(uci_ctx, buf, mode_str);
    }
    
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].user_mac", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].user_name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    if (enabled_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].enabled", index);
        char enabled_str[16];
        snprintf(enabled_str, sizeof(enabled_str), "%d", json_object_get_int(enabled_obj));
        fwx_uci_set_value(uci_ctx, buf, enabled_str);
    }

    struct json_object *filter_quic_obj = json_object_object_get(req_obj, "filter_quic");
    if (filter_quic_obj) {
        snprintf(buf, sizeof(buf), "appfilter.@rule[%d].filter_quic", index);
        char filter_quic_str[16];
        snprintf(filter_quic_str, sizeof(filter_quic_str), "%d", json_object_get_int(filter_quic_obj) ? 1 : 0);
        fwx_uci_set_value(uci_ctx, buf, filter_quic_str);
    }
    

    snprintf(buf, sizeof(buf), "appfilter.@rule[%d].time_rule", index);
    fwx_uci_delete(uci_ctx, buf);
    
    snprintf(buf, sizeof(buf), "appfilter.@rule[%d].app_id", index);
    fwx_uci_delete(uci_ctx, buf);
    

    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
    if (time_rules_obj) {
        int time_rules_len = json_object_array_length(time_rules_obj);
        for (i = 0; i < time_rules_len; i++) {
            struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
            struct json_object *weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
            struct json_object *start_time_obj = json_object_object_get(time_rule_obj, "start_time");
            struct json_object *end_time_obj = json_object_object_get(time_rule_obj, "end_time");
            
            if (!weekdays_obj || !start_time_obj || !end_time_obj) {
                continue;
            }
            
            char time_rule_str[256] = {0};
            int weekdays_len = json_object_array_length(weekdays_obj);
            for (j = 0; j < weekdays_len; j++) {
                struct json_object *weekday_obj = json_object_array_get_idx(weekdays_obj, j);
                char weekday_str[16];
                snprintf(weekday_str, sizeof(weekday_str), "%d", json_object_get_int(weekday_obj));
                if (j > 0) strcat(time_rule_str, ",");
                strcat(time_rule_str, weekday_str);
            }
            strcat(time_rule_str, ",");
            strcat(time_rule_str, json_object_get_string(start_time_obj));
            strcat(time_rule_str, ",");
            strcat(time_rule_str, json_object_get_string(end_time_obj));
            
            snprintf(buf, sizeof(buf), "appfilter.@rule[%d].time_rule", index);
            fwx_uci_add_list(uci_ctx, buf, time_rule_str);
        }
    }
    

    struct json_object *app_ids_obj = json_object_object_get(req_obj, "app_ids");
    if (app_ids_obj) {
        int app_ids_len = json_object_array_length(app_ids_obj);
        for (i = 0; i < app_ids_len; i++) {
            struct json_object *app_id_obj = json_object_array_get_idx(app_ids_obj, i);
            const char *raw = json_object_get_string(app_id_obj);
            char app_id_str[64] = {0};
            if (normalize_app_id_token(raw, app_id_str, sizeof(app_id_str))) {
                snprintf(buf, sizeof(buf), "appfilter.@rule[%d].app_id", index);
                fwx_uci_add_list(uci_ctx, buf, app_id_str);
            }
        }
    }
    
    fwx_uci_commit(uci_ctx, "appfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(APPFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Updated filter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_delete_filter_rule(struct json_object *req_obj) {
    struct json_object *id_obj = json_object_object_get(req_obj, "id");
    if (!id_obj) {
        LOG_ERROR("Missing id field\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int rule_id = json_object_get_int(id_obj);
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int index = find_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[128];
    snprintf(buf, sizeof(buf), "appfilter.@rule[%d]", index);
    fwx_uci_delete(uci_ctx, buf);
    
    fwx_uci_commit(uci_ctx, "appfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(APPFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Deleted filter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_get_appfilter_whitelist(struct json_object *req_obj){

	int i;
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct json_object *mac_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "appfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "appfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        
        struct json_object *mac_obj = json_object_new_object();
        json_object_object_add(mac_obj, "mac", json_object_new_string(mac_str));
        client_node_t *dev = find_client_node(mac_str);
        if (dev){
            json_object_object_add(mac_obj, "nickname", json_object_new_string(dev->nickname));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(dev->hostname));
        }else{
            json_object_object_add(mac_obj, "nickname", json_object_new_string(""));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(""));
        }
        json_object_array_add(mac_array, mac_obj);
    }

    json_object_object_add(data_obj, "list", mac_array);
    uci_free_context(uci_ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_del_appfilter_whitelist(struct json_object *req_obj){
	int i;
    LOG_DEBUG("fwx_api_del_appfilter_whitelist\n");
    struct json_object *mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        LOG_ERROR("mac_obj is NULL\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_DEBUG("mac: %s\n", json_object_get_string(mac_obj));

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "appfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "appfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            LOG_DEBUG("delete appfilter_whitelist_mac[%d]\n", i);
            char buf[128] = {0};
            sprintf(buf, "appfilter_whitelist.@whitelist_mac[%d]", i);
            fwx_uci_delete(uci_ctx, buf);
            break;
        }
    }

    fwx_uci_commit(uci_ctx, "appfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(APPFILTER_WHITELIST_STATE_FILE);

    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_add_appfilter_whitelist(struct json_object *req_obj){
	int i;
    LOG_DEBUG("fwx_api_add_appfilter_whitelist\n");
    struct json_object *mac_array = json_object_object_get(req_obj, "mac_list");
    if (!mac_array) {
        LOG_ERROR("mac_list not found\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int len = json_object_array_length(mac_array);
    for (i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(mac_array, i);
        fwx_uci_add_section(uci_ctx, "appfilter_whitelist", "whitelist_mac");
        fwx_uci_set_value(uci_ctx, "appfilter_whitelist.@whitelist_mac[-1].mac", json_object_get_string(mac_obj));
    }
    fwx_uci_commit(uci_ctx, "appfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(APPFILTER_WHITELIST_STATE_FILE);

    LOG_DEBUG("Added %d MAC addresses to appfilter whitelist\n", len);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_get_app_filter_adv(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int enable = fwx_uci_get_int_value(uci_ctx, "fwx.appfilter.enable");
    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    uci_free_context(uci_ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_app_filter_adv(struct json_object *req_obj) {
    if (!req_obj) {
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *enable_obj = json_object_object_get(req_obj, "enable");
    if (!enable_obj) {
        LOG_ERROR("Missing enable parameter\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int enable_value = json_object_get_int(enable_obj);
    fwx_uci_set_int_value(uci_ctx, "fwx.appfilter.enable", enable_value);
    fwx_uci_commit(uci_ctx, "fwx");

    set_state_file(APPFILTER_RULES_STATE_FILE);
    uci_free_context(uci_ctx);
    LOG_DEBUG("Set appfilter advanced settings\n");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
