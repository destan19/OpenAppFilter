// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
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
#include "fwx_record.h"

#define RECORD_WHITELIST_STATE_FILE "/tmp/record_whitelist_state"
#define RECORD_WHITELIST_SECTION_TYPE "whitelist"
#define RECORD_WHITELIST_UCI_KEY "fwx_record.@whitelist[0].whitelist"
#define RECORD_WHITELIST_LEGACY_SECTION_TYPE "record"
#define RECORD_WHITELIST_LEGACY_UCI_KEY "fwx_record.@record[0].whitelist"

static void set_state_file(const char *file_path)
{
    FILE *fd = fopen(file_path, "w");
    if (fd) {
        fprintf(fd, "1");
        fclose(fd);
        LOG_DEBUG("Set state file: %s\n", file_path);
    } else {
        LOG_ERROR("Failed to set state file: %s\n", file_path);
    }
}

static void normalize_mac(const char *src, char *dst, int dst_len)
{
    int i = 0;
    int start = 0;
    int end = 0;

    if (!src || !dst || dst_len <= 0) {
        return;
    }

    while (src[start] == ' ' || src[start] == '\t' || src[start] == '\r' || src[start] == '\n') {
        start++;
    }

    end = (int)strlen(src);
    while (end > start &&
           (src[end - 1] == ' ' || src[end - 1] == '\t' || src[end - 1] == '\r' || src[end - 1] == '\n')) {
        end--;
    }

    for (i = start; i < end && (i - start) < (dst_len - 1); i++) {
        dst[i - start] = (char)toupper((unsigned char)src[i]);
    }
    dst[i - start] = '\0';
}

static int is_valid_mac(const char *mac)
{
    int i;
    if (!mac || strlen(mac) != 17) {
        return 0;
    }

    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') {
                return 0;
            }
        } else if (!isxdigit((unsigned char)mac[i])) {
            return 0;
        }
    }
    return 1;
}

static int mac_exists_in_array(struct json_object *array_obj, const char *mac)
{
    int i;
    int len;
    if (!array_obj || !mac) {
        return 0;
    }

    len = json_object_array_length(array_obj);
    for (i = 0; i < len; i++) {
        struct json_object *mac_obj = json_object_array_get_idx(array_obj, i);
        const char *exist_mac = json_object_get_string(mac_obj);
        if (exist_mac && strcasecmp(exist_mac, mac) == 0) {
            return 1;
        }
    }
    return 0;
}

static int ensure_record_section(struct uci_context *uci_ctx)
{
    int num = 0;
    int legacy_num = 0;
    char whitelist_buf[4096] = {0};
    char token_buf[4096] = {0};
    char *token = NULL;
    char *save_ptr = NULL;
    char norm_mac[32] = {0};

    if (!uci_ctx) {
        return -1;
    }

    num = fwx_uci_get_list_num(uci_ctx, "fwx_record", RECORD_WHITELIST_SECTION_TYPE);
    if (num > 0) {
        return 0;
    }

    legacy_num = fwx_uci_get_list_num(uci_ctx, "fwx_record", RECORD_WHITELIST_LEGACY_SECTION_TYPE);

    if (fwx_uci_add_section(uci_ctx, "fwx_record", RECORD_WHITELIST_SECTION_TYPE) != UCI_OK) {
        LOG_ERROR("Failed to add fwx_record whitelist section\n");
        return -1;
    }

    if (legacy_num > 0 &&
        fwx_uci_get_list_value(uci_ctx, RECORD_WHITELIST_LEGACY_UCI_KEY,
                               whitelist_buf, sizeof(whitelist_buf), " ") == 0) {
        snprintf(token_buf, sizeof(token_buf), "%s", whitelist_buf);
        token = strtok_r(token_buf, " ", &save_ptr);
        while (token) {
            memset(norm_mac, 0, sizeof(norm_mac));
            normalize_mac(token, norm_mac, sizeof(norm_mac));
            if (is_valid_mac(norm_mac)) {
                fwx_uci_add_list(uci_ctx, RECORD_WHITELIST_UCI_KEY, norm_mac);
            }
            token = strtok_r(NULL, " ", &save_ptr);
        }
    }

    if (fwx_uci_commit(uci_ctx, "fwx_record") != UCI_OK) {
        LOG_ERROR("Failed to commit fwx_record section\n");
        return -1;
    }

    return 0;
}

static int load_record_whitelist_from_uci(struct uci_context *uci_ctx, struct json_object *mac_array)
{
    char whitelist_buf[4096] = {0};
    char norm_mac[32] = {0};
    char *token = NULL;
    char *save_ptr = NULL;
    int count = 0;

    if (!uci_ctx || !mac_array) {
        return 0;
    }

    if (fwx_uci_get_list_value(uci_ctx, RECORD_WHITELIST_UCI_KEY, whitelist_buf, sizeof(whitelist_buf), " ") != 0) {
        return 0;
    }

    token = strtok_r(whitelist_buf, " ", &save_ptr);
    while (token) {
        memset(norm_mac, 0, sizeof(norm_mac));
        normalize_mac(token, norm_mac, sizeof(norm_mac));
        if (is_valid_mac(norm_mac) && !mac_exists_in_array(mac_array, norm_mac)) {
            json_object_array_add(mac_array, json_object_new_string(norm_mac));
            count++;
        }
        token = strtok_r(NULL, " ", &save_ptr);
    }

    return count;
}

struct json_object *fwx_api_get_record_whitelist(struct json_object *req_obj)
{
    int i;
    int page = 1;
    int page_size = 15;
    int total_num = 0;
    int total_page = 1;
    int start_idx = 0;
    int end_idx = 0;
    struct json_object *page_obj = NULL;
    struct json_object *page_size_obj = NULL;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *all_list_obj = json_object_new_array();
    struct json_object *page_list_obj = json_object_new_array();
    struct uci_context *uci_ctx = NULL;

    if (req_obj) {
        page_obj = json_object_object_get(req_obj, "page");
        page_size_obj = json_object_object_get(req_obj, "page_size");
        if (page_obj) {
            page = json_object_get_int(page_obj);
            if (page < 1) {
                page = 1;
            }
        }
        if (page_size_obj) {
            page_size = json_object_get_int(page_size_obj);
            if (page_size < 1) {
                page_size = 15;
            }
            if (page_size > 200) {
                page_size = 200;
            }
        }
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(data_obj);
        json_object_put(all_list_obj);
        json_object_put(page_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    ensure_record_section(uci_ctx);
    load_record_whitelist_from_uci(uci_ctx, all_list_obj);
    uci_free_context(uci_ctx);

    total_num = json_object_array_length(all_list_obj);
    total_page = (total_num + page_size - 1) / page_size;
    if (total_page < 1) {
        total_page = 1;
    }
    if (page > total_page) {
        page = total_page;
    }

    start_idx = (page - 1) * page_size;
    end_idx = start_idx + page_size;
    if (end_idx > total_num) {
        end_idx = total_num;
    }

    for (i = start_idx; i < end_idx; i++) {
        struct json_object *item_obj = json_object_new_object();
        const char *mac = NULL;
        client_node_t *dev = NULL;

        mac = json_object_get_string(json_object_array_get_idx(all_list_obj, i));
        if (!mac) {
            continue;
        }
        dev = find_client_node((char *)mac);

        json_object_object_add(item_obj, "mac", json_object_new_string(mac));
        if (dev) {
            json_object_object_add(item_obj, "nickname", json_object_new_string(dev->nickname));
            json_object_object_add(item_obj, "hostname", json_object_new_string(dev->hostname));
        } else {
            json_object_object_add(item_obj, "nickname", json_object_new_string(""));
            json_object_object_add(item_obj, "hostname", json_object_new_string(""));
        }
        json_object_array_add(page_list_obj, item_obj);
    }

    json_object_object_add(data_obj, "total_num", json_object_new_int(total_num));
    json_object_object_add(data_obj, "total_page", json_object_new_int(total_page));
    json_object_object_add(data_obj, "page", json_object_new_int(page));
    json_object_object_add(data_obj, "page_size", json_object_new_int(page_size));
    json_object_object_add(data_obj, "list", page_list_obj);

    json_object_put(all_list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_add_record_whitelist(struct json_object *req_obj)
{
    int i;
    int added = 0;
    int mac_list_len = 0;
    char norm_mac[32] = {0};
    struct json_object *mac_list_obj = NULL;
    struct json_object *exist_list_obj = json_object_new_array();
    struct uci_context *uci_ctx = NULL;

    if (!req_obj) {
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    mac_list_obj = json_object_object_get(req_obj, "mac_list");
    if (!mac_list_obj) {
        LOG_ERROR("mac_list_obj is NULL\n");
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (ensure_record_section(uci_ctx) != 0) {
        uci_free_context(uci_ctx);
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    load_record_whitelist_from_uci(uci_ctx, exist_list_obj);
    mac_list_len = json_object_array_length(mac_list_obj);

    for (i = 0; i < mac_list_len; i++) {
        struct json_object *mac_item = json_object_array_get_idx(mac_list_obj, i);
        const char *raw_mac = json_object_get_string(mac_item);

        memset(norm_mac, 0, sizeof(norm_mac));
        normalize_mac(raw_mac, norm_mac, sizeof(norm_mac));
        if (!is_valid_mac(norm_mac)) {
            continue;
        }
        if (mac_exists_in_array(exist_list_obj, norm_mac)) {
            continue;
        }
        fwx_uci_add_list(uci_ctx, RECORD_WHITELIST_UCI_KEY, norm_mac);
        json_object_array_add(exist_list_obj, json_object_new_string(norm_mac));
        added++;
    }

    if (added > 0) {
        fwx_uci_commit(uci_ctx, "fwx_record");
        set_state_file(RECORD_WHITELIST_STATE_FILE);
    }

    uci_free_context(uci_ctx);
    json_object_put(exist_list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_del_record_whitelist(struct json_object *req_obj)
{
    int found = 0;
    char norm_mac[32] = {0};
    struct json_object *mac_obj = NULL;
    struct json_object *exist_list_obj = json_object_new_array();
    struct uci_context *uci_ctx = NULL;

    if (!req_obj) {
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    mac_obj = json_object_object_get(req_obj, "mac");
    if (!mac_obj) {
        LOG_ERROR("mac_obj is NULL\n");
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    normalize_mac(json_object_get_string(mac_obj), norm_mac, sizeof(norm_mac));
    if (!is_valid_mac(norm_mac)) {
        LOG_ERROR("invalid mac: %s\n", norm_mac);
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (ensure_record_section(uci_ctx) != 0) {
        uci_free_context(uci_ctx);
        json_object_put(exist_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    load_record_whitelist_from_uci(uci_ctx, exist_list_obj);
    if (mac_exists_in_array(exist_list_obj, norm_mac)) {
        fwx_uci_del_list(uci_ctx, RECORD_WHITELIST_UCI_KEY, norm_mac);
        fwx_uci_commit(uci_ctx, "fwx_record");
        set_state_file(RECORD_WHITELIST_STATE_FILE);
        found = 1;
    }

    uci_free_context(uci_ctx);
    json_object_put(exist_list_obj);
    LOG_DEBUG("Delete record whitelist mac=%s, found=%d\n", norm_mac, found);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_set_record_whitelist(struct json_object *req_obj)
{
    int i;
    int mac_list_len = 0;
    struct json_object *mac_list_obj = NULL;
    struct json_object *new_list_obj = json_object_new_array();
    struct uci_context *uci_ctx = NULL;

    if (!req_obj) {
        json_object_put(new_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    mac_list_obj = json_object_object_get(req_obj, "mac_list");
    if (!mac_list_obj) {
        LOG_ERROR("mac_list_obj is NULL\n");
        json_object_put(new_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        LOG_ERROR("Failed to allocate UCI context\n");
        json_object_put(new_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (ensure_record_section(uci_ctx) != 0) {
        uci_free_context(uci_ctx);
        json_object_put(new_list_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    fwx_uci_delete(uci_ctx, RECORD_WHITELIST_UCI_KEY);
    mac_list_len = json_object_array_length(mac_list_obj);

    for (i = 0; i < mac_list_len; i++) {
        char norm_mac[32] = {0};
        struct json_object *mac_item = json_object_array_get_idx(mac_list_obj, i);
        const char *raw_mac = json_object_get_string(mac_item);

        normalize_mac(raw_mac, norm_mac, sizeof(norm_mac));
        if (!is_valid_mac(norm_mac)) {
            continue;
        }
        if (mac_exists_in_array(new_list_obj, norm_mac)) {
            continue;
        }
        fwx_uci_add_list(uci_ctx, RECORD_WHITELIST_UCI_KEY, norm_mac);
        json_object_array_add(new_list_obj, json_object_new_string(norm_mac));
    }

    fwx_uci_commit(uci_ctx, "fwx_record");
    set_state_file(RECORD_WHITELIST_STATE_FILE);

    uci_free_context(uci_ctx);
    json_object_put(new_list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
