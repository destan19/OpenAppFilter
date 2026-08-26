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
#include "fwx_mac_filter.h"


#define MACFILTER_RULES_STATE_FILE "/tmp/macfilter_rules_state"
#define MACFILTER_WHITELIST_STATE_FILE "/tmp/macfilter_whitelist_state"
#define MACFILTER_TIME_MODE_RANGE 1
#define MACFILTER_TIME_MODE_DURATION 2
#define MACFILTER_TIME_MODE_FLOW 3


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


static int find_mac_filter_rule_index_by_id(struct uci_context *uci_ctx, int id) {
	int i;
    char id_str_uci[32];
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter", "rule");
    for (i = 0; i < num; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].id", i);
        if (fwx_uci_get_value(uci_ctx, buf, id_str_uci, sizeof(id_str_uci)) != 0) {
            continue;
        }
        if (atoi(id_str_uci) == id) {
            return i;
        }
    }
    return -1; // Not found
}

static int normalize_macfilter_time_mode(int time_mode)
{
    if (time_mode == MACFILTER_TIME_MODE_DURATION || time_mode == MACFILTER_TIME_MODE_FLOW) {
        return time_mode;
    }
    return MACFILTER_TIME_MODE_RANGE;
}

static int parse_uint_token(const char *token, int *value)
{
    int i;
    int v = 0;

    if (!token || token[0] == '\0') {
        return 0;
    }

    for (i = 0; token[i] != '\0'; i++) {
        if (token[i] < '0' || token[i] > '9') {
            return 0;
        }
        v = v * 10 + (token[i] - '0');
    }

    if (value) {
        *value = v;
    }
    return 1;
}

static int macfilter_rule_mode_to_time_mode(int rule_mode, int fallback_time_mode)
{
    if (rule_mode == 1) {
        return MACFILTER_TIME_MODE_DURATION;
    }
    if (rule_mode == 2) {
        return MACFILTER_TIME_MODE_FLOW;
    }
    if (rule_mode == 0) {
        return MACFILTER_TIME_MODE_RANGE;
    }
    return normalize_macfilter_time_mode(fallback_time_mode);
}

static int append_time_rule_obj(struct json_object *time_rules_array, const char *rule_str, int fallback_time_mode)
{
    char rule_buf[256] = {0};
    char *parts[32] = {0};
    int part_count = 0;
    char *token = NULL;
    char *saveptr = NULL;
    int parse_time_mode = normalize_macfilter_time_mode(fallback_time_mode);
    int i;

    if (!time_rules_array || !rule_str || rule_str[0] == '\0') {
        return 0;
    }

    if (strchr(rule_str, ';') != NULL) {
        char sem_buf[256] = {0};
        char *weekday_part = NULL;
        char *mode_part = NULL;
        char *value_part = NULL;
        char *sem_saveptr = NULL;
        struct json_object *time_rule_obj = NULL;
        struct json_object *weekdays_array = NULL;
        int weekday_count = 0;
        int parsed_rule_mode = 0;
        int parsed_time_mode = parse_time_mode;
        char weekday_buf[128] = {0};
        char *weekday_token = NULL;
        char *weekday_saveptr = NULL;

        strncpy(sem_buf, rule_str, sizeof(sem_buf) - 1);
        weekday_part = strtok_r(sem_buf, ";", &sem_saveptr);
        mode_part = strtok_r(NULL, ";", &sem_saveptr);
        value_part = strtok_r(NULL, ";", &sem_saveptr);
        if (weekday_part && mode_part && value_part) {
            parsed_rule_mode = atoi(mode_part);
            parsed_time_mode = macfilter_rule_mode_to_time_mode(parsed_rule_mode, parse_time_mode);

            time_rule_obj = json_object_new_object();
            weekdays_array = json_object_new_array();
            if (!time_rule_obj || !weekdays_array) {
                if (time_rule_obj) json_object_put(time_rule_obj);
                if (weekdays_array) json_object_put(weekdays_array);
                return 0;
            }

            strncpy(weekday_buf, weekday_part, sizeof(weekday_buf) - 1);
            weekday_token = strtok_r(weekday_buf, ",", &weekday_saveptr);
            while (weekday_token) {
                int weekday = -1;
                if (parse_uint_token(weekday_token, &weekday) && weekday >= 0 && weekday <= 6) {
                    json_object_array_add(weekdays_array, json_object_new_int(weekday));
                    weekday_count++;
                }
                weekday_token = strtok_r(NULL, ",", &weekday_saveptr);
            }

            if (weekday_count <= 0) {
                json_object_put(weekdays_array);
                json_object_put(time_rule_obj);
                return 0;
            }

            json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
            if (parsed_time_mode == MACFILTER_TIME_MODE_DURATION) {
                int duration_minutes = atoi(value_part);
                if (duration_minutes <= 0) {
                    json_object_put(time_rule_obj);
                    return 0;
                }
                json_object_object_add(time_rule_obj, "duration_minutes", json_object_new_int(duration_minutes));
            } else if (parsed_time_mode == MACFILTER_TIME_MODE_FLOW) {
                int flow_mb = atoi(value_part);
                if (flow_mb <= 0) {
                    json_object_put(time_rule_obj);
                    return 0;
                }
                json_object_object_add(time_rule_obj, "flow_mb", json_object_new_int(flow_mb));
            } else {
                char value_copy[128] = {0};
                char *sep = NULL;
                char *start_time = NULL;
                char *end_time = NULL;

                strncpy(value_copy, value_part, sizeof(value_copy) - 1);
                sep = strchr(value_copy, '-');
                if (!sep) {
                    json_object_put(time_rule_obj);
                    return 0;
                }
                *sep = '\0';
                start_time = value_copy;
                end_time = sep + 1;
                if (!start_time[0] || !end_time[0]) {
                    json_object_put(time_rule_obj);
                    return 0;
                }
                json_object_object_add(time_rule_obj, "start_time", json_object_new_string(start_time));
                json_object_object_add(time_rule_obj, "end_time", json_object_new_string(end_time));
            }

            json_object_array_add(time_rules_array, time_rule_obj);
            return parsed_time_mode;
        }
    }

    strncpy(rule_buf, rule_str, sizeof(rule_buf) - 1);
    token = strtok_r(rule_buf, ",", &saveptr);
    while (token && part_count < (int)(sizeof(parts) / sizeof(parts[0]))) {
        parts[part_count++] = token;
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (part_count <= 0) {
        return 0;
    }

    if (parse_time_mode == MACFILTER_TIME_MODE_DURATION) {
        int duration_minutes = 0;
        int weekday_end = part_count - 1;
        int weekday_count = 0;
        struct json_object *time_rule_obj = NULL;
        struct json_object *weekdays_array = NULL;

        if (part_count >= 3) {
            int maybe_rule_mode = 0;
            if (parse_uint_token(parts[part_count - 2], &maybe_rule_mode) && maybe_rule_mode == 1) {
                weekday_end = part_count - 2;
            }
        }

        if (!parse_uint_token(parts[part_count - 1], &duration_minutes)) {
            return 0;
        }
        if (duration_minutes <= 0) {
            return 0;
        }

        time_rule_obj = json_object_new_object();
        weekdays_array = json_object_new_array();
        if (!time_rule_obj || !weekdays_array) {
            if (time_rule_obj) json_object_put(time_rule_obj);
            if (weekdays_array) json_object_put(weekdays_array);
            return 0;
        }

        for (i = 0; i < weekday_end; i++) {
            int weekday = -1;
            if (parse_uint_token(parts[i], &weekday) && weekday >= 0 && weekday <= 6) {
                json_object_array_add(weekdays_array, json_object_new_int(weekday));
                weekday_count++;
            }
        }

        if (weekday_count <= 0) {
            json_object_put(weekdays_array);
            json_object_put(time_rule_obj);
            return 0;
        }

        json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
        json_object_object_add(time_rule_obj, "duration_minutes", json_object_new_int(duration_minutes));
        json_object_array_add(time_rules_array, time_rule_obj);
        return MACFILTER_TIME_MODE_DURATION;
    }

    if (parse_time_mode == MACFILTER_TIME_MODE_FLOW) {
        int flow_mb = 0;
        int weekday_end = part_count - 1;
        int weekday_count = 0;
        struct json_object *time_rule_obj = NULL;
        struct json_object *weekdays_array = NULL;

        if (part_count >= 3) {
            int maybe_rule_mode = 0;
            if (parse_uint_token(parts[part_count - 2], &maybe_rule_mode) && maybe_rule_mode == 2) {
                weekday_end = part_count - 2;
            }
        }

        if (!parse_uint_token(parts[part_count - 1], &flow_mb)) {
            return 0;
        }
        if (flow_mb <= 0) {
            return 0;
        }

        time_rule_obj = json_object_new_object();
        weekdays_array = json_object_new_array();
        if (!time_rule_obj || !weekdays_array) {
            if (time_rule_obj) json_object_put(time_rule_obj);
            if (weekdays_array) json_object_put(weekdays_array);
            return 0;
        }

        for (i = 0; i < weekday_end; i++) {
            int weekday = -1;
            if (parse_uint_token(parts[i], &weekday) && weekday >= 0 && weekday <= 6) {
                json_object_array_add(weekdays_array, json_object_new_int(weekday));
                weekday_count++;
            }
        }

        if (weekday_count <= 0) {
            json_object_put(weekdays_array);
            json_object_put(time_rule_obj);
            return 0;
        }

        json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
        json_object_object_add(time_rule_obj, "flow_mb", json_object_new_int(flow_mb));
        json_object_array_add(time_rules_array, time_rule_obj);
        return MACFILTER_TIME_MODE_FLOW;
    }

    if (part_count >= 3) {
        struct json_object *time_rule_obj = NULL;
        struct json_object *weekdays_array = NULL;
        char *start_time = NULL;
        char *end_time = NULL;

        time_rule_obj = json_object_new_object();
        weekdays_array = json_object_new_array();
        if (!time_rule_obj || !weekdays_array) {
            if (time_rule_obj) json_object_put(time_rule_obj);
            if (weekdays_array) json_object_put(weekdays_array);
            return 0;
        }

        for (i = 0; i < part_count; i++) {
            if (strchr(parts[i], ':') != NULL) {
                if (!start_time) {
                    start_time = parts[i];
                } else if (!end_time) {
                    end_time = parts[i];
                    break;
                }
            } else {
                int weekday = -1;
                if (parse_uint_token(parts[i], &weekday) && weekday >= 0 && weekday <= 6) {
                    json_object_array_add(weekdays_array, json_object_new_int(weekday));
                }
            }
        }

        if (!start_time || !end_time || json_object_array_length(weekdays_array) <= 0) {
            json_object_put(weekdays_array);
            json_object_put(time_rule_obj);
            return 0;
        }

        json_object_object_add(time_rule_obj, "start_time", json_object_new_string(start_time));
        json_object_object_add(time_rule_obj, "end_time", json_object_new_string(end_time));
        json_object_object_add(time_rule_obj, "weekdays", weekdays_array);
        json_object_array_add(time_rules_array, time_rule_obj);
        return MACFILTER_TIME_MODE_RANGE;
    }

    return 0;
}

static char *trim_space(char *str)
{
    char *end = NULL;
    if (!str) {
        return str;
    }
    while (*str == ' ' || *str == '\t' || *str == '\r' || *str == '\n') {
        str++;
    }
    if (*str == '\0') {
        return str;
    }
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return str;
}

static int get_limit_max_value(int time_mode)
{
    if (time_mode == MACFILTER_TIME_MODE_DURATION) {
        return 1440;
    }
    return 1048576;
}

static int normalize_limit_str(const char *input_str, int time_mode, char *output_str, int output_len)
{
    int values[7] = {0, 0, 0, 0, 0, 0, 0};
    int order[7] = {1, 2, 3, 4, 5, 6, 0};
    int i;
    int offset = 0;
    int max_value = get_limit_max_value(time_mode);
    char buf[512] = {0};
    char *token = NULL;
    char *saveptr = NULL;

    if (!output_str || output_len <= 0) {
        return -1;
    }
    output_str[0] = '\0';

    if (input_str && input_str[0] != '\0') {
        strncpy(buf, input_str, sizeof(buf) - 1);
        token = strtok_r(buf, ",", &saveptr);
        while (token) {
            char pair_buf[64] = {0};
            char *pair = NULL;
            char *day_str = NULL;
            char *val_str = NULL;
            char *sep = NULL;
            int day = -1;
            int value = 0;

            strncpy(pair_buf, token, sizeof(pair_buf) - 1);
            pair = trim_space(pair_buf);
            sep = strchr(pair, ':');
            if (sep) {
                *sep = '\0';
                day_str = trim_space(pair);
                val_str = trim_space(sep + 1);
                if (parse_uint_token(day_str, &day) &&
                    parse_uint_token(val_str, &value) &&
                    day >= 0 && day <= 6) {
                    if (value < 0) {
                        value = 0;
                    }
                    if (value > max_value) {
                        value = max_value;
                    }
                    values[day] = value;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    for (i = 0; i < 7; i++) {
        int day = order[i];
        int n = snprintf(output_str + offset, output_len - offset, "%d:%d", day, values[day]);
        if (n < 0 || n >= output_len - offset) {
            return -1;
        }
        offset += n;
        if (i < 6) {
            if (offset + 1 >= output_len) {
                return -1;
            }
            output_str[offset++] = ',';
            output_str[offset] = '\0';
        }
    }
    return 0;
}

static int build_limit_str_from_time_rules(struct json_object *time_rules_obj, int time_mode, char *output_str, int output_len)
{
    int values[7] = {0, 0, 0, 0, 0, 0, 0};
    int order[7] = {1, 2, 3, 4, 5, 6, 0};
    int max_value = get_limit_max_value(time_mode);
    int i;
    int offset = 0;
    int len = 0;

    if (!time_rules_obj || !json_object_is_type(time_rules_obj, json_type_array) || !output_str || output_len <= 0) {
        return -1;
    }

    len = json_object_array_length(time_rules_obj);
    for (i = 0; i < len; i++) {
        struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
        struct json_object *weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
        int value = 0;
        int j;
        int weekdays_len = 0;
        if (!weekdays_obj || !json_object_is_type(weekdays_obj, json_type_array)) {
            continue;
        }

        if (time_mode == MACFILTER_TIME_MODE_DURATION) {
            struct json_object *duration_obj = json_object_object_get(time_rule_obj, "duration_minutes");
            value = duration_obj ? json_object_get_int(duration_obj) : 0;
        } else {
            struct json_object *flow_obj = json_object_object_get(time_rule_obj, "flow_mb");
            value = flow_obj ? json_object_get_int(flow_obj) : 0;
        }
        if (value < 0) {
            value = 0;
        }
        if (value > max_value) {
            value = max_value;
        }

        weekdays_len = json_object_array_length(weekdays_obj);
        for (j = 0; j < weekdays_len; j++) {
            int day = json_object_get_int(json_object_array_get_idx(weekdays_obj, j));
            if (day >= 0 && day <= 6) {
                values[day] = value;
            }
        }
    }

    output_str[0] = '\0';
    for (i = 0; i < 7; i++) {
        int day = order[i];
        int n = snprintf(output_str + offset, output_len - offset, "%d:%d", day, values[day]);
        if (n < 0 || n >= output_len - offset) {
            return -1;
        }
        offset += n;
        if (i < 6) {
            if (offset + 1 >= output_len) {
                return -1;
            }
            output_str[offset++] = ',';
            output_str[offset] = '\0';
        }
    }
    return 0;
}

static void append_limit_rules_to_array(struct json_object *time_rules_array, const char *limit_str, int time_mode)
{
    char buf[512] = {0};
    char *token = NULL;
    char *saveptr = NULL;

    if (!time_rules_array || !limit_str || limit_str[0] == '\0') {
        return;
    }

    strncpy(buf, limit_str, sizeof(buf) - 1);
    token = strtok_r(buf, ",", &saveptr);
    while (token) {
        char pair_buf[64] = {0};
        char *pair = NULL;
        char *day_str = NULL;
        char *val_str = NULL;
        char *sep = NULL;
        int day = -1;
        int value = 0;

        strncpy(pair_buf, token, sizeof(pair_buf) - 1);
        pair = trim_space(pair_buf);
        sep = strchr(pair, ':');
        if (sep) {
            struct json_object *rule_obj = NULL;
            struct json_object *weekdays_array = NULL;
            *sep = '\0';
            day_str = trim_space(pair);
            val_str = trim_space(sep + 1);
            if (parse_uint_token(day_str, &day) &&
                parse_uint_token(val_str, &value) &&
                day >= 0 && day <= 6) {
                if (value < 0) {
                    value = 0;
                }
                rule_obj = json_object_new_object();
                weekdays_array = json_object_new_array();
                json_object_array_add(weekdays_array, json_object_new_int(day));
                json_object_object_add(rule_obj, "weekdays", weekdays_array);
                if (time_mode == MACFILTER_TIME_MODE_DURATION) {
                    json_object_object_add(rule_obj, "duration_minutes", json_object_new_int(value));
                } else {
                    json_object_object_add(rule_obj, "flow_mb", json_object_new_int(value));
                }
                json_object_array_add(time_rules_array, rule_obj);
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
}

static int build_time_list_item_str(struct json_object *time_rule_obj, char *time_rule_str, int str_len)
{
    struct json_object *weekdays_obj = NULL;
    struct json_object *start_time_obj = NULL;
    struct json_object *end_time_obj = NULL;
    int weekdays_len = 0;
    int i;
    int offset = 0;
    int appended = 0;

    if (!time_rule_obj || !time_rule_str || str_len <= 0) {
        return -1;
    }

    weekdays_obj = json_object_object_get(time_rule_obj, "weekdays");
    start_time_obj = json_object_object_get(time_rule_obj, "start_time");
    end_time_obj = json_object_object_get(time_rule_obj, "end_time");
    if (!weekdays_obj || !start_time_obj || !end_time_obj || !json_object_is_type(weekdays_obj, json_type_array)) {
        return -1;
    }

    time_rule_str[0] = '\0';
    weekdays_len = json_object_array_length(weekdays_obj);
    for (i = 0; i < weekdays_len; i++) {
        int day = json_object_get_int(json_object_array_get_idx(weekdays_obj, i));
        int n;
        if (day < 0 || day > 6) {
            continue;
        }
        n = snprintf(time_rule_str + offset, str_len - offset, "%s%d", appended > 0 ? "," : "", day);
        if (n < 0 || n >= str_len - offset) {
            return -1;
        }
        offset += n;
        appended++;
    }
    if (appended <= 0) {
        return -1;
    }

    if (offset + 1 >= str_len) {
        return -1;
    }
    time_rule_str[offset++] = ',';
    time_rule_str[offset] = '\0';

    {
        const char *start_time = json_object_get_string(start_time_obj);
        const char *end_time = json_object_get_string(end_time_obj);
        int n = snprintf(time_rule_str + offset, str_len - offset, "%s,%s", start_time ? start_time : "", end_time ? end_time : "");
        if (n < 0 || n >= str_len - offset) {
            return -1;
        }
        offset += n;
    }

    return 0;
}


struct json_object *fwx_api_get_mac_filter_rules(struct json_object *req_obj) {
    int i;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *rules_array = json_object_new_array();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int num = fwx_uci_get_list_num(uci_ctx, "macfilter", "rule");
    LOG_DEBUG("Found %d rules in macfilter\n", num);
    
    for (i = 0; i < num; i++) {
        char buf[256];
        char name_str[128] = {0};
        char mode_str[16] = {0};
        char time_mode_str[16] = {0};
        int time_mode = MACFILTER_TIME_MODE_RANGE;
        char user_mac_str[32] = {0};
        char user_name_str[128] = {0};
        char enabled_str[16] = {0};
        char id_str[32] = {0};
        

        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].id", i);
        if (fwx_uci_get_value(uci_ctx, buf, id_str, sizeof(id_str)) != 0) {
            LOG_ERROR("Failed to get id for rule[%d], skipping\n", i);
            continue; 
        }
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].name", i);
        fwx_uci_get_value(uci_ctx, buf, name_str, sizeof(name_str));
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].mode", i);
        if (fwx_uci_get_value(uci_ctx, buf, mode_str, sizeof(mode_str)) != 0) {
            strcpy(mode_str, "1");
        }

        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_mode", i);
        if (fwx_uci_get_value(uci_ctx, buf, time_mode_str, sizeof(time_mode_str)) != 0) {
            strcpy(time_mode_str, "1");
        }
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_mac", i);
        fwx_uci_get_value(uci_ctx, buf, user_mac_str, sizeof(user_mac_str));
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_name", i);
        fwx_uci_get_value(uci_ctx, buf, user_name_str, sizeof(user_name_str)); 
        
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].enabled", i);
        if (fwx_uci_get_value(uci_ctx, buf, enabled_str, sizeof(enabled_str)) != 0) {
            strcpy(enabled_str, "1"); 
        }
        
        struct json_object *rule_obj = json_object_new_object();
        struct json_object *time_rules_array = json_object_new_array();
        struct json_object *time_list_array = json_object_new_array();
        char time_list_buf[2048] = {0};
        char limit_buf[512] = {0};
        if (!rule_obj || !time_rules_array || !time_list_array) {
            LOG_ERROR("Failed to create rule_obj for rule[%d]\n", i);
            if (rule_obj) json_object_put(rule_obj);
            if (time_rules_array) json_object_put(time_rules_array);
            if (time_list_array) json_object_put(time_list_array);
            continue;
        }
        
        json_object_object_add(rule_obj, "id", json_object_new_int(atoi(id_str)));
        json_object_object_add(rule_obj, "name", json_object_new_string(name_str));
        json_object_object_add(rule_obj, "mode", json_object_new_int(atoi(mode_str)));
        time_mode = normalize_macfilter_time_mode(atoi(time_mode_str));
        json_object_object_add(rule_obj, "user_mac", json_object_new_string(user_mac_str));
        json_object_object_add(rule_obj, "user_name", json_object_new_string(user_name_str));
        json_object_object_add(rule_obj, "enabled", json_object_new_int(atoi(enabled_str)));

        if (time_mode == MACFILTER_TIME_MODE_RANGE) {
            int loaded_from_new = 0;
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_list", i);
            if (fwx_uci_get_list_value(uci_ctx, buf, time_list_buf, sizeof(time_list_buf), " ") == 0) {
                char *p = strtok(time_list_buf, " ");
                loaded_from_new = 1;
                while (p) {
                    json_object_array_add(time_list_array, json_object_new_string(p));
                    append_time_rule_obj(time_rules_array, p, MACFILTER_TIME_MODE_RANGE);
                    p = strtok(NULL, " ");
                }
            }
            if (!loaded_from_new) {
                char old_time_rule_buf[2048] = {0};
                snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", i);
                if (fwx_uci_get_list_value(uci_ctx, buf, old_time_rule_buf, sizeof(old_time_rule_buf), " ") == 0) {
                    char *p = strtok(old_time_rule_buf, " ");
                    while (p) {
                        append_time_rule_obj(time_rules_array, p, MACFILTER_TIME_MODE_RANGE);
                        if (strchr(p, ';') == NULL) {
                            json_object_array_add(time_list_array, json_object_new_string(p));
                        }
                        p = strtok(NULL, " ");
                    }
                }
            }
            json_object_object_add(rule_obj, "time_limit", json_object_new_string(""));
            json_object_object_add(rule_obj, "flow_limit", json_object_new_string(""));
        } else if (time_mode == MACFILTER_TIME_MODE_DURATION) {
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_limit", i);
            if (fwx_uci_get_value(uci_ctx, buf, limit_buf, sizeof(limit_buf)) != 0 || limit_buf[0] == '\0') {
                char old_time_rule_buf[2048] = {0};
                char normalized_limit[512] = {0};
                snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", i);
                if (fwx_uci_get_list_value(uci_ctx, buf, old_time_rule_buf, sizeof(old_time_rule_buf), " ") == 0) {
                    char *p = strtok(old_time_rule_buf, " ");
                    while (p) {
                        append_time_rule_obj(time_rules_array, p, MACFILTER_TIME_MODE_DURATION);
                        p = strtok(NULL, " ");
                    }
                }
                if (build_limit_str_from_time_rules(time_rules_array, MACFILTER_TIME_MODE_DURATION, normalized_limit, sizeof(normalized_limit)) == 0) {
                    strncpy(limit_buf, normalized_limit, sizeof(limit_buf) - 1);
                }
            } else {
                char normalized_limit[512] = {0};
                if (normalize_limit_str(limit_buf, MACFILTER_TIME_MODE_DURATION, normalized_limit, sizeof(normalized_limit)) == 0) {
                    strncpy(limit_buf, normalized_limit, sizeof(limit_buf) - 1);
                }
                append_limit_rules_to_array(time_rules_array, limit_buf, MACFILTER_TIME_MODE_DURATION);
            }
            json_object_object_add(rule_obj, "time_limit", json_object_new_string(limit_buf));
            json_object_object_add(rule_obj, "flow_limit", json_object_new_string(""));
        } else {
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].flow_limit", i);
            if (fwx_uci_get_value(uci_ctx, buf, limit_buf, sizeof(limit_buf)) != 0 || limit_buf[0] == '\0') {
                char old_time_rule_buf[2048] = {0};
                char normalized_limit[512] = {0};
                snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", i);
                if (fwx_uci_get_list_value(uci_ctx, buf, old_time_rule_buf, sizeof(old_time_rule_buf), " ") == 0) {
                    char *p = strtok(old_time_rule_buf, " ");
                    while (p) {
                        append_time_rule_obj(time_rules_array, p, MACFILTER_TIME_MODE_FLOW);
                        p = strtok(NULL, " ");
                    }
                }
                if (build_limit_str_from_time_rules(time_rules_array, MACFILTER_TIME_MODE_FLOW, normalized_limit, sizeof(normalized_limit)) == 0) {
                    strncpy(limit_buf, normalized_limit, sizeof(limit_buf) - 1);
                }
            } else {
                char normalized_limit[512] = {0};
                if (normalize_limit_str(limit_buf, MACFILTER_TIME_MODE_FLOW, normalized_limit, sizeof(normalized_limit)) == 0) {
                    strncpy(limit_buf, normalized_limit, sizeof(limit_buf) - 1);
                }
                append_limit_rules_to_array(time_rules_array, limit_buf, MACFILTER_TIME_MODE_FLOW);
            }
            json_object_object_add(rule_obj, "time_limit", json_object_new_string(""));
            json_object_object_add(rule_obj, "flow_limit", json_object_new_string(limit_buf));
        }

        json_object_object_add(rule_obj, "time_mode", json_object_new_int(time_mode));
        json_object_object_add(rule_obj, "time_rules", time_rules_array);
        json_object_object_add(rule_obj, "time_list", time_list_array);
        
        json_object_array_add(rules_array, rule_obj);
        LOG_DEBUG("Successfully loaded macfilter rule[%d]: id=%s, name=%s\n", i, id_str, name_str);
    }
    
    json_object_object_add(data_obj, "list", rules_array);
    uci_free_context(uci_ctx);
    
    LOG_DEBUG("Returning %d macfilter rules\n", json_object_array_length(rules_array));

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_add_mac_filter_rule(struct json_object *req_obj) {
    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    struct json_object *time_mode_obj = json_object_object_get(req_obj, "time_mode");
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
    struct json_object *time_list_obj = json_object_object_get(req_obj, "time_list");
    struct json_object *time_limit_obj = json_object_object_get(req_obj, "time_limit");
    struct json_object *flow_limit_obj = json_object_object_get(req_obj, "flow_limit");
	int i;
    int time_mode = MACFILTER_TIME_MODE_RANGE;
    
    if (!name_obj || !mode_obj) {
        LOG_ERROR("Missing required fields\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (time_mode_obj) {
        time_mode = json_object_get_int(time_mode_obj);
    }
    time_mode = normalize_macfilter_time_mode(time_mode);

    if (time_mode == MACFILTER_TIME_MODE_RANGE) {
        int has_time_list = time_list_obj && json_object_is_type(time_list_obj, json_type_array) && json_object_array_length(time_list_obj) > 0;
        int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
        if (!has_time_list && !has_time_rules) {
            LOG_ERROR("Missing required time list for range mode\n");
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else if (time_mode == MACFILTER_TIME_MODE_DURATION) {
        int has_time_limit = time_limit_obj && json_object_is_type(time_limit_obj, json_type_string);
        int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
        if (!has_time_limit && !has_time_rules) {
            LOG_ERROR("Missing required time_limit for duration mode\n");
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    } else {
        int has_flow_limit = flow_limit_obj && json_object_is_type(flow_limit_obj, json_type_string);
        int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
        if (!has_flow_limit && !has_time_rules) {
            LOG_ERROR("Missing required flow_limit for flow mode\n");
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    

    int rule_id = (int)time(NULL);
    

    fwx_uci_add_section(uci_ctx, "macfilter", "rule");
    
    char buf[256];
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].id");
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", rule_id);
    fwx_uci_set_value(uci_ctx, buf, id_str);
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].name");
    fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].mode");
    char mode_str[16];
    snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
    fwx_uci_set_value(uci_ctx, buf, mode_str);
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_mode");
    char time_mode_str[16];
    snprintf(time_mode_str, sizeof(time_mode_str), "%d", time_mode);
    fwx_uci_set_value(uci_ctx, buf, time_mode_str);
    
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].user_mac");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].user_name");
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].enabled");
    char enabled_str[16];
    int enabled = enabled_obj ? json_object_get_int(enabled_obj) : 1;
    snprintf(enabled_str, sizeof(enabled_str), "%d", enabled);
    fwx_uci_set_value(uci_ctx, buf, enabled_str);
    
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_rule");
    fwx_uci_delete(uci_ctx, buf);
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_list");
    fwx_uci_delete(uci_ctx, buf);
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_limit");
    fwx_uci_delete(uci_ctx, buf);
    snprintf(buf, sizeof(buf), "macfilter.@rule[-1].flow_limit");
    fwx_uci_delete(uci_ctx, buf);

    if (time_mode == MACFILTER_TIME_MODE_RANGE) {
        if (time_list_obj && json_object_is_type(time_list_obj, json_type_array) && json_object_array_length(time_list_obj) > 0) {
            int time_list_len = json_object_array_length(time_list_obj);
            for (i = 0; i < time_list_len; i++) {
                struct json_object *time_item = json_object_array_get_idx(time_list_obj, i);
                const char *time_rule_str = time_item ? json_object_get_string(time_item) : NULL;
                if (!time_rule_str || time_rule_str[0] == '\0') {
                    continue;
                }
                snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_list");
                fwx_uci_add_list(uci_ctx, buf, time_rule_str);
            }
        } else if (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) {
            int time_rules_len = json_object_array_length(time_rules_obj);
            for (i = 0; i < time_rules_len; i++) {
                struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
                char time_rule_str[256] = {0};
                if (build_time_list_item_str(time_rule_obj, time_rule_str, sizeof(time_rule_str)) != 0) {
                    continue;
                }
                snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_list");
                fwx_uci_add_list(uci_ctx, buf, time_rule_str);
            }
        }
    } else if (time_mode == MACFILTER_TIME_MODE_DURATION) {
        char limit_str[512] = {0};
        if (time_limit_obj && json_object_is_type(time_limit_obj, json_type_string)) {
            normalize_limit_str(json_object_get_string(time_limit_obj), MACFILTER_TIME_MODE_DURATION, limit_str, sizeof(limit_str));
        } else if (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) {
            build_limit_str_from_time_rules(time_rules_obj, MACFILTER_TIME_MODE_DURATION, limit_str, sizeof(limit_str));
        }
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].time_limit");
        fwx_uci_set_value(uci_ctx, buf, limit_str);
    } else {
        char limit_str[512] = {0};
        if (flow_limit_obj && json_object_is_type(flow_limit_obj, json_type_string)) {
            normalize_limit_str(json_object_get_string(flow_limit_obj), MACFILTER_TIME_MODE_FLOW, limit_str, sizeof(limit_str));
        } else if (time_rules_obj && json_object_is_type(time_rules_obj, json_type_array)) {
            build_limit_str_from_time_rules(time_rules_obj, MACFILTER_TIME_MODE_FLOW, limit_str, sizeof(limit_str));
        }
        snprintf(buf, sizeof(buf), "macfilter.@rule[-1].flow_limit");
        fwx_uci_set_value(uci_ctx, buf, limit_str);
    }
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Added macfilter rule: id=%d, name=%s\n", rule_id, json_object_get_string(name_obj));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_update_mac_filter_rule(struct json_object *req_obj) {
    int i;
    int time_mode = MACFILTER_TIME_MODE_RANGE;
    int has_time_payload = 0;
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
    
    int index = find_mac_filter_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[256];
    

    struct json_object *name_obj = json_object_object_get(req_obj, "name");
    if (name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(name_obj));
    }
    
    struct json_object *mode_obj = json_object_object_get(req_obj, "mode");
    if (mode_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].mode", index);
        char mode_str[16];
        snprintf(mode_str, sizeof(mode_str), "%d", json_object_get_int(mode_obj));
        fwx_uci_set_value(uci_ctx, buf, mode_str);
    }

    char time_mode_str[16] = {0};
    struct json_object *time_mode_obj = json_object_object_get(req_obj, "time_mode");
    struct json_object *time_rules_obj = json_object_object_get(req_obj, "time_rules");
    struct json_object *time_list_obj = json_object_object_get(req_obj, "time_list");
    struct json_object *time_limit_obj = json_object_object_get(req_obj, "time_limit");
    struct json_object *flow_limit_obj = json_object_object_get(req_obj, "flow_limit");
    if (time_mode_obj || time_rules_obj || time_list_obj || time_limit_obj || flow_limit_obj) {
        has_time_payload = 1;
    }

    if (time_mode_obj) {
        time_mode = normalize_macfilter_time_mode(json_object_get_int(time_mode_obj));
    } else {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_mode", index);
        if (fwx_uci_get_value(uci_ctx, buf, time_mode_str, sizeof(time_mode_str)) == 0) {
            time_mode = atoi(time_mode_str);
        }
        time_mode = normalize_macfilter_time_mode(time_mode);
    }

    if (has_time_payload) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_mode", index);
        snprintf(time_mode_str, sizeof(time_mode_str), "%d", time_mode);
        fwx_uci_set_value(uci_ctx, buf, time_mode_str);
    }
    
    struct json_object *user_mac_obj = json_object_object_get(req_obj, "user_mac");
    if (user_mac_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_mac", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_mac_obj));
    }
    
    struct json_object *user_name_obj = json_object_object_get(req_obj, "user_name");
    if (user_name_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].user_name", index);
        fwx_uci_set_value(uci_ctx, buf, json_object_get_string(user_name_obj));
    }
    
    struct json_object *enabled_obj = json_object_object_get(req_obj, "enabled");
    if (enabled_obj) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].enabled", index);
        char enabled_str[16];
        snprintf(enabled_str, sizeof(enabled_str), "%d", json_object_get_int(enabled_obj));
        fwx_uci_set_value(uci_ctx, buf, enabled_str);
    }
    

    if (has_time_payload) {
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_rule", index);
        fwx_uci_delete(uci_ctx, buf);
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_list", index);
        fwx_uci_delete(uci_ctx, buf);
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_limit", index);
        fwx_uci_delete(uci_ctx, buf);
        snprintf(buf, sizeof(buf), "macfilter.@rule[%d].flow_limit", index);
        fwx_uci_delete(uci_ctx, buf);

        if (time_mode == MACFILTER_TIME_MODE_RANGE) {
            int has_time_list = time_list_obj && json_object_is_type(time_list_obj, json_type_array) && json_object_array_length(time_list_obj) > 0;
            int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
            if (!has_time_list && !has_time_rules) {
                LOG_ERROR("Missing required time list for range mode on update\n");
                uci_free_context(uci_ctx);
                return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
            }
            if (has_time_list) {
                int time_list_len = json_object_array_length(time_list_obj);
                for (i = 0; i < time_list_len; i++) {
                    struct json_object *time_item = json_object_array_get_idx(time_list_obj, i);
                    const char *time_rule_str = time_item ? json_object_get_string(time_item) : NULL;
                    if (!time_rule_str || time_rule_str[0] == '\0') {
                        continue;
                    }
                    snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_list", index);
                    fwx_uci_add_list(uci_ctx, buf, time_rule_str);
                }
            } else {
                int time_rules_len = json_object_array_length(time_rules_obj);
                for (i = 0; i < time_rules_len; i++) {
                    struct json_object *time_rule_obj = json_object_array_get_idx(time_rules_obj, i);
                    char time_rule_str[256] = {0};
                    if (build_time_list_item_str(time_rule_obj, time_rule_str, sizeof(time_rule_str)) != 0) {
                        continue;
                    }
                    snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_list", index);
                    fwx_uci_add_list(uci_ctx, buf, time_rule_str);
                }
            }
        } else if (time_mode == MACFILTER_TIME_MODE_DURATION) {
            char limit_str[512] = {0};
            int has_time_limit = time_limit_obj && json_object_is_type(time_limit_obj, json_type_string);
            int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
            if (!has_time_limit && !has_time_rules) {
                LOG_ERROR("Missing time_limit for duration mode on update\n");
                uci_free_context(uci_ctx);
                return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
            }
            if (has_time_limit) {
                normalize_limit_str(json_object_get_string(time_limit_obj), MACFILTER_TIME_MODE_DURATION, limit_str, sizeof(limit_str));
            } else {
                build_limit_str_from_time_rules(time_rules_obj, MACFILTER_TIME_MODE_DURATION, limit_str, sizeof(limit_str));
            }
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].time_limit", index);
            fwx_uci_set_value(uci_ctx, buf, limit_str);
        } else {
            char limit_str[512] = {0};
            int has_flow_limit = flow_limit_obj && json_object_is_type(flow_limit_obj, json_type_string);
            int has_time_rules = time_rules_obj && json_object_is_type(time_rules_obj, json_type_array) && json_object_array_length(time_rules_obj) > 0;
            if (!has_flow_limit && !has_time_rules) {
                LOG_ERROR("Missing flow_limit for flow mode on update\n");
                uci_free_context(uci_ctx);
                return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
            }
            if (has_flow_limit) {
                normalize_limit_str(json_object_get_string(flow_limit_obj), MACFILTER_TIME_MODE_FLOW, limit_str, sizeof(limit_str));
            } else {
                build_limit_str_from_time_rules(time_rules_obj, MACFILTER_TIME_MODE_FLOW, limit_str, sizeof(limit_str));
            }
            snprintf(buf, sizeof(buf), "macfilter.@rule[%d].flow_limit", index);
            fwx_uci_set_value(uci_ctx, buf, limit_str);
        }
    }
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Updated macfilter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_delete_mac_filter_rule(struct json_object *req_obj) {
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
    
    int index = find_mac_filter_rule_index_by_id(uci_ctx, rule_id);
    if (index < 0) {
        LOG_ERROR("Rule not found: id=%d\n", rule_id);
        uci_free_context(uci_ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    char buf[128];
    snprintf(buf, sizeof(buf), "macfilter.@rule[%d]", index);
    fwx_uci_delete(uci_ctx, buf);
    
    fwx_uci_commit(uci_ctx, "macfilter");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_RULES_STATE_FILE);
    
    LOG_DEBUG("Deleted macfilter rule: id=%d\n", rule_id);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}


struct json_object *fwx_api_get_mac_filter_whitelist(struct json_object *req_obj) {
	int i;
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct json_object *mac_array = json_object_new_array();
    char mac_str[128] = {0};
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        
        struct json_object *mac_obj = json_object_new_object();
        json_object_object_add(mac_obj, "mac", json_object_new_string(mac_str));
        client_node_t *dev = find_client_node(mac_str);
        if (dev) {
            json_object_object_add(mac_obj, "nickname", json_object_new_string(dev->nickname));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(dev->hostname));
        } else {
            json_object_object_add(mac_obj, "nickname", json_object_new_string(""));
            json_object_object_add(mac_obj, "hostname", json_object_new_string(""));
        }
        json_object_array_add(mac_array, mac_obj);
    }

    json_object_object_add(data_obj, "list", mac_array);
    uci_free_context(uci_ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_del_mac_filter_whitelist(struct json_object *req_obj) {
	int i;
    LOG_DEBUG("fwx_api_del_mac_filter_whitelist\n");
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
    int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
    for (i = 0; i < num; i++) {
        fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", i, mac_str, sizeof(mac_str));
        if (strcmp(mac_str, json_object_get_string(mac_obj)) == 0) {
            LOG_DEBUG("delete macfilter_whitelist_mac[%d]\n", i);
            char buf[128] = {0};
            sprintf(buf, "macfilter_whitelist.@whitelist_mac[%d]", i);
            fwx_uci_delete(uci_ctx, buf);
            break;
        }
    }

    fwx_uci_commit(uci_ctx, "macfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_WHITELIST_STATE_FILE);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_add_mac_filter_whitelist(struct json_object *req_obj) {
	int i, j;
    LOG_DEBUG("fwx_api_add_mac_filter_whitelist\n");
    struct json_object *mac_list_obj = json_object_object_get(req_obj, "mac_list");
    if (!mac_list_obj) {
        LOG_ERROR("mac_list_obj is NULL\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    int mac_list_len = json_object_array_length(mac_list_obj);
    for (i = 0; i < mac_list_len; i++) {
        struct json_object *mac_item = json_object_array_get_idx(mac_list_obj, i);
        const char *mac = json_object_get_string(mac_item);
        if (!mac || strlen(mac) == 0) {
            continue;
        }
        

        char mac_str[128] = {0};
        int num = fwx_uci_get_list_num(uci_ctx, "macfilter_whitelist", "whitelist_mac");
        int exists = 0;
        for (j = 0; j < num; j++) {
            fwx_uci_get_array_value(uci_ctx, "macfilter_whitelist.@whitelist_mac[%d].mac", j, mac_str, sizeof(mac_str));
            if (strcmp(mac_str, mac) == 0) {
                exists = 1;
                break;
            }
        }
        
        if (!exists) {
            fwx_uci_add_section(uci_ctx, "macfilter_whitelist", "whitelist_mac");
            char buf[128];
            snprintf(buf, sizeof(buf), "macfilter_whitelist.@whitelist_mac[-1].mac");
            fwx_uci_set_value(uci_ctx, buf, mac);
            LOG_DEBUG("Added macfilter whitelist: %s\n", mac);
        }
    }

    fwx_uci_commit(uci_ctx, "macfilter_whitelist");
    uci_free_context(uci_ctx);
    

    set_state_file(MACFILTER_WHITELIST_STATE_FILE);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_get_mac_filter_adv(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    
    struct uci_context *uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    int enable = fwx_uci_get_int_value(uci_ctx, "fwx.macfilter.enable");
    json_object_object_add(data_obj, "enable", json_object_new_int(enable));
    uci_free_context(uci_ctx);
    
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}


struct json_object *fwx_api_set_mac_filter_adv(struct json_object *req_obj) {
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
    fwx_uci_set_int_value(uci_ctx, "fwx.macfilter.enable", enable_value);
    fwx_uci_commit(uci_ctx, "fwx");

    set_state_file(MACFILTER_RULES_STATE_FILE);
    uci_free_context(uci_ctx);
    LOG_DEBUG("Set macfilter advanced settings\n");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
