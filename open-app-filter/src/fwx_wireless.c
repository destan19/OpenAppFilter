// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <json-c/json.h>
#include <uci.h>
#include "fwx.h"
#include "fwx_wireless.h"

#define MAX_WIRELESS_SECTION_NUM 64
#define MAX_WIRELESS_NAME_LEN 64

static int get_wireless_option_value(struct uci_context *ctx, const char *section_name, const char *option_name, char *out, size_t out_len)
{
    char uci_key[128] = {0};

    if (!ctx || !section_name || !option_name || !out || out_len == 0) {
        return -1;
    }

    snprintf(uci_key, sizeof(uci_key), "wireless.%s.%s", section_name, option_name);
    if (fwx_uci_get_value(ctx, uci_key, out, (int)out_len) == 0) {
        return 0;
    }

    out[0] = '\0';
    return -1;
}

static int set_wireless_option_value(struct uci_context *ctx, const char *section_name, const char *option_name, const char *value)
{
    char uci_key[128] = {0};

    if (!ctx || !section_name || !option_name || !value) {
        return -1;
    }

    snprintf(uci_key, sizeof(uci_key), "wireless.%s.%s", section_name, option_name);
    return fwx_uci_set_value(ctx, uci_key, (char *)value);
}

static int delete_wireless_option_value(struct uci_context *ctx, const char *section_name, const char *option_name)
{
    char uci_key[128] = {0};

    if (!ctx || !section_name || !option_name) {
        return -1;
    }

    snprintf(uci_key, sizeof(uci_key), "wireless.%s.%s", section_name, option_name);
    return fwx_uci_delete(ctx, uci_key);
}

static int collect_wireless_sections(struct uci_context *ctx,
                                     char radio_names[][MAX_WIRELESS_NAME_LEN], int *radio_num,
                                     char iface_names[][MAX_WIRELESS_NAME_LEN], int *iface_num)
{
    struct uci_package *pkg = NULL;
    struct uci_element *e = NULL;

    if (!ctx || !radio_names || !radio_num || !iface_names || !iface_num) {
        return -1;
    }

    *radio_num = 0;
    *iface_num = 0;
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        return -1;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "wifi-device") == 0) {
            if (*radio_num < MAX_WIRELESS_SECTION_NUM) {
                snprintf(radio_names[*radio_num], MAX_WIRELESS_NAME_LEN, "%s", e->name);
                (*radio_num)++;
            }
            continue;
        }

        if (strcmp(s->type, "wifi-iface") == 0) {
            if (*iface_num < MAX_WIRELESS_SECTION_NUM) {
                snprintf(iface_names[*iface_num], MAX_WIRELESS_NAME_LEN, "%s", e->name);
                (*iface_num)++;
            }
        }
    }

    if (pkg) {
        uci_unload(ctx, pkg);
    }
    return 0;
}

static int find_first_iface_by_radio(struct uci_context *ctx, const char *radio_name,
                                     char iface_names[][MAX_WIRELESS_NAME_LEN], int iface_num,
                                     char *out_iface, size_t out_iface_len)
{
    int i = 0;

    if (!ctx || !radio_name || !iface_names || !out_iface || out_iface_len == 0) {
        return -1;
    }

    for (i = 0; i < iface_num; i++) {
        char device[64] = {0};
        if (get_wireless_option_value(ctx, iface_names[i], "device", device, sizeof(device)) == 0 &&
            strcmp(device, radio_name) == 0) {
            snprintf(out_iface, out_iface_len, "%s", iface_names[i]);
            return 0;
        }
    }

    return -1;
}

static int is_iface_exists(char iface_names[][MAX_WIRELESS_NAME_LEN], int iface_num, const char *section_name)
{
    int i = 0;

    if (!iface_names || !section_name) {
        return 0;
    }

    for (i = 0; i < iface_num; i++) {
        if (strcmp(iface_names[i], section_name) == 0) {
            return 1;
        }
    }

    return 0;
}

static const char *format_band_label(const char *band, const char *hwmode, char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0) {
        return "Unknown";
    }

    if (band && band[0] != '\0') {
        if (strcmp(band, "2g") == 0) {
            snprintf(buf, buf_len, "2.4G");
        } else if (strcmp(band, "5g") == 0) {
            snprintf(buf, buf_len, "5G");
        } else if (strcmp(band, "6g") == 0) {
            snprintf(buf, buf_len, "6G");
        } else if (strcmp(band, "60g") == 0) {
            snprintf(buf, buf_len, "60G");
        } else {
            snprintf(buf, buf_len, "%s", band);
        }

        return buf;
    }

    if (hwmode && hwmode[0] != '\0') {
        if (strstr(hwmode, "11ad") || strstr(hwmode, "11ay")) {
            snprintf(buf, buf_len, "60G");
        } else if (strstr(hwmode, "11a")) {
            snprintf(buf, buf_len, "5G");
        } else {
            snprintf(buf, buf_len, "2.4G");
        }

        return buf;
    }

    snprintf(buf, buf_len, "Unknown");
    return buf;
}

static int parse_hidden_value(const char *hidden)
{
    if (!hidden) {
        return 0;
    }

    if (strcmp(hidden, "1") == 0 ||
        strcasecmp(hidden, "true") == 0 ||
        strcasecmp(hidden, "yes") == 0 ||
        strcasecmp(hidden, "on") == 0) {
        return 1;
    }

    return 0;
}

static int json_to_bool(struct json_object *obj, int default_value)
{
    enum json_type type;
    const char *val_str = NULL;

    if (!obj) {
        return default_value;
    }

    type = json_object_get_type(obj);
    if (type == json_type_boolean || type == json_type_int) {
        return json_object_get_int(obj) ? 1 : 0;
    }

    if (type == json_type_string) {
        val_str = json_object_get_string(obj);
        return parse_hidden_value(val_str);
    }

    return default_value;
}

static int is_open_encryption(const char *encryption)
{
    if (!encryption || encryption[0] == '\0') {
        return 1;
    }

    if (strcmp(encryption, "none") == 0) {
        return 1;
    }

    if (strncmp(encryption, "owe", 3) == 0) {
        return 1;
    }

    return 0;
}

static int apply_ssid_item(struct uci_context *ctx, struct json_object *item,
                           char iface_names[][MAX_WIRELESS_NAME_LEN], int iface_num)
{
    struct json_object *radio_obj = NULL;
    struct json_object *section_obj = NULL;
    struct json_object *ssid_obj = NULL;
    struct json_object *password_obj = NULL;
    struct json_object *encryption_obj = NULL;
    struct json_object *hidden_obj = NULL;
    struct json_object *isolate_obj = NULL;
    const char *radio_name = NULL;
    const char *section_name = NULL;
    const char *password = NULL;
    char encryption[64] = {0};
    char iface_name[MAX_WIRELESS_NAME_LEN] = {0};
    int has_password = 0;
    int has_encryption = 0;
    int has_change = 0;
    int hidden = 0;
    int isolate = 0;
    char hidden_str[4] = {0};
    char isolate_str[4] = {0};

    if (!ctx || !item || json_object_get_type(item) != json_type_object) {
        return 0;
    }

    json_object_object_get_ex(item, "radio", &radio_obj);
    json_object_object_get_ex(item, "section", &section_obj);
    json_object_object_get_ex(item, "ssid", &ssid_obj);
    has_password = json_object_object_get_ex(item, "password", &password_obj);
    has_encryption = json_object_object_get_ex(item, "encryption", &encryption_obj);
    json_object_object_get_ex(item, "hidden", &hidden_obj);
    json_object_object_get_ex(item, "isolate", &isolate_obj);

    radio_name = radio_obj ? json_object_get_string(radio_obj) : NULL;
    section_name = section_obj ? json_object_get_string(section_obj) : NULL;

    if (section_name && section_name[0] != '\0' && is_iface_exists(iface_names, iface_num, section_name)) {
        snprintf(iface_name, sizeof(iface_name), "%s", section_name);
    }

    if (iface_name[0] == '\0' && radio_name && radio_name[0] != '\0') {
        find_first_iface_by_radio(ctx, radio_name, iface_names, iface_num, iface_name, sizeof(iface_name));
    }

    if (iface_name[0] == '\0') {
        LOG_WARN("set_wireless_base_setting skip item, iface not found, radio=%s section=%s\n",
                 radio_name ? radio_name : "", section_name ? section_name : "");
        return 0;
    }

    if (ssid_obj) {
        const char *ssid = json_object_get_string(ssid_obj);
        if (set_wireless_option_value(ctx, iface_name, "ssid", ssid ? ssid : "") == 0) {
            has_change = 1;
        }
    }

    if (has_encryption) {
        const char *enc_value = json_object_get_string(encryption_obj);
        if (!enc_value || enc_value[0] == '\0') {
            enc_value = "none";
        }
        snprintf(encryption, sizeof(encryption), "%s", enc_value);
        if (set_wireless_option_value(ctx, iface_name, "encryption", encryption) == 0) {
            has_change = 1;
        }
    } else {
        if (get_wireless_option_value(ctx, iface_name, "encryption", encryption, sizeof(encryption)) != 0 ||
            encryption[0] == '\0') {
            snprintf(encryption, sizeof(encryption), "none");
        }
    }

    if (hidden_obj) {
        hidden = json_to_bool(hidden_obj, 0);
        snprintf(hidden_str, sizeof(hidden_str), "%d", hidden ? 1 : 0);
        if (set_wireless_option_value(ctx, iface_name, "hidden", hidden_str) == 0) {
            has_change = 1;
        }
    }
    if (isolate_obj) {
        isolate = json_to_bool(isolate_obj, 0);
        snprintf(isolate_str, sizeof(isolate_str), "%d", isolate ? 1 : 0);
        if (set_wireless_option_value(ctx, iface_name, "isolate", isolate_str) == 0) {
            has_change = 1;
        }
    }

    if (is_open_encryption(encryption)) {
        int del_key = delete_wireless_option_value(ctx, iface_name, "key");
        int del_key1 = delete_wireless_option_value(ctx, iface_name, "key1");
        if (del_key == 0 || del_key1 == 0) {
            has_change = 1;
        }
    } else if (has_password) {
        password = json_object_get_string(password_obj);
        if (password && password[0] != '\0') {
            if (set_wireless_option_value(ctx, iface_name, "key", password) == 0) {
                has_change = 1;
            }
        } else {
            if (delete_wireless_option_value(ctx, iface_name, "key") == 0) {
                has_change = 1;
            }
        }
    }

    return has_change;
}

struct json_object *fwx_api_get_wireless_base_setting(struct json_object *req_obj)
{
    struct uci_context *ctx = NULL;
    struct json_object *data_obj = NULL;
    struct json_object *ssid_list_obj = NULL;
    char radio_names[MAX_WIRELESS_SECTION_NUM][MAX_WIRELESS_NAME_LEN] = {{0}};
    char iface_names[MAX_WIRELESS_SECTION_NUM][MAX_WIRELESS_NAME_LEN] = {{0}};
    int radio_num = 0;
    int iface_num = 0;
    int i = 0;

    (void)req_obj;

    data_obj = json_object_new_object();
    ssid_list_obj = json_object_new_array();
    if (!data_obj || !ssid_list_obj) {
        if (ssid_list_obj) {
            json_object_put(ssid_list_obj);
        }
        if (data_obj) {
            json_object_put(data_obj);
        }
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    ctx = uci_alloc_context();
    if (!ctx) {
        json_object_put(ssid_list_obj);
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (collect_wireless_sections(ctx, radio_names, &radio_num, iface_names, &iface_num) != 0) {
        uci_free_context(ctx);
        json_object_put(ssid_list_obj);
        json_object_put(data_obj);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    for (i = 0; i < radio_num; i++) {
        struct json_object *ssid_obj = NULL;
        char iface_name[MAX_WIRELESS_NAME_LEN] = {0};
        char ssid[128] = {0};
        char key[128] = {0};
        char encryption[64] = {0};
        char hidden[16] = {0};
        char isolate[16] = {0};
        char band[16] = {0};
        char hwmode[32] = {0};
        char band_label[16] = {0};

        if (find_first_iface_by_radio(ctx, radio_names[i], iface_names, iface_num, iface_name, sizeof(iface_name)) != 0) {
            continue;
        }

        get_wireless_option_value(ctx, iface_name, "ssid", ssid, sizeof(ssid));
        get_wireless_option_value(ctx, iface_name, "key", key, sizeof(key));
        get_wireless_option_value(ctx, iface_name, "encryption", encryption, sizeof(encryption));
        get_wireless_option_value(ctx, iface_name, "hidden", hidden, sizeof(hidden));
        get_wireless_option_value(ctx, iface_name, "isolate", isolate, sizeof(isolate));
        get_wireless_option_value(ctx, radio_names[i], "band", band, sizeof(band));
        get_wireless_option_value(ctx, radio_names[i], "hwmode", hwmode, sizeof(hwmode));

        ssid_obj = json_object_new_object();
        if (!ssid_obj) {
            continue;
        }

        json_object_object_add(ssid_obj, "radio", json_object_new_string(radio_names[i]));
        json_object_object_add(ssid_obj, "section", json_object_new_string(iface_name));
        json_object_object_add(ssid_obj, "band", json_object_new_string(format_band_label(band, hwmode, band_label, sizeof(band_label))));
        json_object_object_add(ssid_obj, "ssid", json_object_new_string(ssid));
        json_object_object_add(ssid_obj, "password", json_object_new_string(key));
        json_object_object_add(ssid_obj, "encryption", json_object_new_string(encryption[0] ? encryption : "none"));
        json_object_object_add(ssid_obj, "hidden", json_object_new_int(parse_hidden_value(hidden)));
        json_object_object_add(ssid_obj, "isolate", json_object_new_int(parse_hidden_value(isolate)));
        json_object_array_add(ssid_list_obj, ssid_obj);
    }

    json_object_object_add(data_obj, "ssid_list", ssid_list_obj);
    uci_free_context(ctx);

    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

struct json_object *fwx_api_set_wireless_base_setting(struct json_object *req_obj)
{
    struct uci_context *ctx = NULL;
    struct json_object *ssid_list_obj = NULL;
    enum json_type ssid_list_type;
    char radio_names[MAX_WIRELESS_SECTION_NUM][MAX_WIRELESS_NAME_LEN] = {{0}};
    char iface_names[MAX_WIRELESS_SECTION_NUM][MAX_WIRELESS_NAME_LEN] = {{0}};
    int radio_num = 0;
    int iface_num = 0;
    int i = 0;
    int list_len = 0;
    int has_change = 0;
    int processed_num = 0;

    if (!req_obj) {
        LOG_ERROR("set_wireless_base_setting: req_obj is null\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_INFO("set_wireless_base_setting req=%s\n", json_object_to_json_string_ext(req_obj, JSON_C_TO_STRING_PLAIN));

    ssid_list_obj = json_object_object_get(req_obj, "ssid_list");
    if (!ssid_list_obj) {
        LOG_ERROR("set_wireless_base_setting: missing ssid_list\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    ssid_list_type = json_object_get_type(ssid_list_obj);
    if (ssid_list_type != json_type_array && ssid_list_type != json_type_object) {
        LOG_ERROR("set_wireless_base_setting: invalid ssid_list type=%d\n", ssid_list_type);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    ctx = uci_alloc_context();
    if (!ctx) {
        LOG_ERROR("set_wireless_base_setting: alloc uci ctx failed\n");
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (collect_wireless_sections(ctx, radio_names, &radio_num, iface_names, &iface_num) != 0) {
        LOG_ERROR("set_wireless_base_setting: collect_wireless_sections failed\n");
        uci_free_context(ctx);
        return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
    }

    if (ssid_list_type == json_type_array) {
        list_len = json_object_array_length(ssid_list_obj);
        for (i = 0; i < list_len; i++) {
            struct json_object *item = json_object_array_get_idx(ssid_list_obj, i);
            has_change |= apply_ssid_item(ctx, item, iface_names, iface_num);
            processed_num++;
        }
    } else {
        json_object_object_foreach(ssid_list_obj, key, val) {
            (void)key;
            has_change |= apply_ssid_item(ctx, val, iface_names, iface_num);
            processed_num++;
        }
    }
    LOG_INFO("set_wireless_base_setting: list_type=%d processed=%d changed=%d\n",
             ssid_list_type, processed_num, has_change);

    if (has_change) {
        if (fwx_uci_commit(ctx, "wireless") != UCI_OK) {
            LOG_ERROR("set_wireless_base_setting: commit wireless failed\n");
            uci_free_context(ctx);
            return fwx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
        system("wifi reload");
    }

    uci_free_context(ctx);

    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
