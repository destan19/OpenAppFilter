// SPDX-License-Identifier: GPL-2.0-or-later
#include "fwx_custom_feature.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fwx.h"
#include "fwx_config.h"

#define CUSTOM_FALLBACK_CLASS_COUNT 5
#define CUSTOM_APP_MIN_SUFFIX 900
#define CUSTOM_APP_MAX_SUFFIX 999
#define CUSTOM_MAX_FEATURES 16
#define CUSTOM_MAX_PAYLOADS 15
#define CUSTOM_MAX_FEATURE_TEXT 127
#define CUSTOM_MAX_APP_LINE 799

typedef struct custom_class {
    int id;
    const char *name;
} custom_class_t;

typedef struct custom_payload {
    int position;
    unsigned int value;
} custom_payload_t;

typedef struct custom_feature {
    char protocol[4];
    char dest_port[16];
    char domain[32];
    char uri[64];
    custom_payload_t payload[CUSTOM_MAX_PAYLOADS];
    int payload_count;
} custom_feature_t;

typedef struct custom_app {
    int appid;
    int class_id;
    char name[64];
    custom_feature_t features[CUSTOM_MAX_FEATURES];
    int feature_count;
} custom_app_t;

typedef struct custom_config {
    custom_app_t *apps;
    size_t count;
    size_t capacity;
} custom_config_t;

static const custom_class_t fallback_classes[CUSTOM_FALLBACK_CLASS_COUNT] = {
    {1, "Chat"},
    {2, "Game"},
    {3, "Video"},
    {4, "Shopping"},
    {5, "Music"}
};

static custom_config_t custom_config;
extern int reload_feature(void);
extern int add_app_name_to_table(int id, const char *name);
extern int get_base_app_count(void);

static void set_error(char *error, size_t error_len, const char *message)
{
    if (error && error_len > 0)
        snprintf(error, error_len, "%s", message);
}

static void config_free(custom_config_t *config)
{
    if (!config)
        return;
    free(config->apps);
    memset(config, 0, sizeof(*config));
}

static custom_app_t *config_add_app(custom_config_t *config)
{
    custom_app_t *apps;
    size_t capacity;

    if (config->count >= MAX_SUPPORT_APP_NUM)
        return NULL;
    if (config->count == config->capacity) {
        capacity = config->capacity ? config->capacity * 2 : 16;
        if (capacity > MAX_SUPPORT_APP_NUM)
            capacity = MAX_SUPPORT_APP_NUM;
        apps = realloc(config->apps, capacity * sizeof(*apps));
        if (!apps)
            return NULL;
        config->apps = apps;
        config->capacity = capacity;
    }
    memset(&config->apps[config->count], 0, sizeof(config->apps[config->count]));
    return &config->apps[config->count++];
}

static char *trim_space(char *text)
{
    char *end;

    if (!text)
        return NULL;
    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int has_builtin_classes(void)
{
    int i;

    for (i = 0; i < MAX_APP_TYPE; i++) {
        if (CLASS_NAME_TABLE[i][0])
            return 1;
    }
    return 0;
}

static int class_is_available(int class_id)
{
    int i;

    if (has_builtin_classes())
        return class_id >= 1 && class_id <= MAX_APP_TYPE &&
               CLASS_NAME_TABLE[class_id - 1][0];
    for (i = 0; i < CUSTOM_FALLBACK_CLASS_COUNT; i++) {
        if (fallback_classes[i].id == class_id)
            return 1;
    }
    return 0;
}

static int has_forbidden_text_char(const char *text, int app_name)
{
    const unsigned char *p = (const unsigned char *)text;

    while (*p) {
        if ((!app_name && isspace(*p)) || strchr(app_name ? ":~[];," : ";,[]", *p))
            return 1;
        p++;
    }
    return 0;
}

static int parse_integer(const char *text, int minimum, int maximum, int *value)
{
    char *end = NULL;
    long number;

    if (!text || !text[0])
        return -1;
    errno = 0;
    number = strtol(text, &end, 10);
    if (errno || !end || *end || number < minimum || number > maximum)
        return -1;
    *value = (int)number;
    return 0;
}

static int normalize_dest_port(const char *text, char *output, size_t output_len)
{
    char buffer[16];
    char *separator;
    int start;
    int end;
    int written;

    if (!text || !output || output_len == 0)
        return -1;
    if (!text[0]) {
        output[0] = '\0';
        return 0;
    }
    if (strlen(text) >= sizeof(buffer))
        return -1;
    snprintf(buffer, sizeof(buffer), "%s", text);
    separator = strchr(buffer, '-');
    if (!separator) {
        if (parse_integer(buffer, 1, 65535, &start) < 0)
            return -1;
        written = snprintf(output, output_len, "%d", start);
        return written >= 0 && written < (int)output_len ? 0 : -1;
    }
    if (strchr(separator + 1, '-'))
        return -1;
    *separator++ = '\0';
    if (parse_integer(buffer, 1, 65535, &start) < 0 ||
        parse_integer(separator, 1, 65535, &end) < 0 || start > end)
        return -1;
    written = snprintf(output, output_len, "%d-%d", start, end);
    return written >= 0 && written < (int)output_len ? 0 : -1;
}

static int split_exact(char *text, char delimiter, char **fields, int field_count)
{
    int i;
    char *separator;

    fields[0] = text;
    for (i = 1; i < field_count; i++) {
        separator = strchr(fields[i - 1], delimiter);
        if (!separator)
            return -1;
        *separator = '\0';
        fields[i] = separator + 1;
    }
    return strchr(fields[field_count - 1], delimiter) ? -1 : 0;
}

static int parse_payload_text(char *text, custom_feature_t *feature)
{
    char *item = text;
    size_t length = strlen(text);

    if (!text[0])
        return 0;
    if (text[length - 1] == '|')
        return -1;
    while (item && item[0]) {
        char *next = strchr(item, '|');
        char *colon;
        char *end = NULL;
        long position;
        unsigned long value;

        if (feature->payload_count >= CUSTOM_MAX_PAYLOADS)
            return -1;
        if (next)
            *next++ = '\0';
        colon = strchr(item, ':');
        if (!colon || strchr(colon + 1, ':'))
            return -1;
        *colon++ = '\0';
        errno = 0;
        position = strtol(item, &end, 10);
        if (errno || !end || *end || position < INT_MIN || position > INT_MAX)
            return -1;
        if (strlen(colon) != 2 || !isxdigit((unsigned char)colon[0]) ||
            !isxdigit((unsigned char)colon[1]))
            return -1;
        errno = 0;
        value = strtoul(colon, &end, 16);
        if (errno || !end || *end || value > 0xff)
            return -1;
        feature->payload[feature->payload_count].position = (int)position;
        feature->payload[feature->payload_count].value = (unsigned int)value;
        feature->payload_count++;
        item = next;
    }
    return 0;
}

static int validate_feature(custom_feature_t *feature, char *error, size_t error_len)
{
    char normalized_port[sizeof(feature->dest_port)];

    if (strcmp(feature->protocol, "tcp") && strcmp(feature->protocol, "udp")) {
        set_error(error, error_len, "protocol must be tcp or udp");
        return -1;
    }
    if (normalize_dest_port(feature->dest_port, normalized_port,
                            sizeof(normalized_port)) < 0) {
        set_error(error, error_len, "dest_port is invalid");
        return -1;
    }
    snprintf(feature->dest_port, sizeof(feature->dest_port), "%s", normalized_port);
    if (strlen(feature->domain) > 31 || has_forbidden_text_char(feature->domain, 0)) {
        set_error(error, error_len, "domain is invalid");
        return -1;
    }
    if (strlen(feature->uri) > 63 || has_forbidden_text_char(feature->uri, 0)) {
        set_error(error, error_len, "uri is invalid");
        return -1;
    }
    if (!feature->dest_port[0] && !feature->domain[0] && !feature->uri[0] &&
        !feature->payload_count) {
        set_error(error, error_len, "feature match fields are empty");
        return -1;
    }
    return 0;
}

static int parse_feature_text(const char *text, custom_feature_t *feature,
                              char *error, size_t error_len)
{
    char buffer[CUSTOM_MAX_FEATURE_TEXT + 1];
    char *fields[6];
    size_t i;

    if (!text || !text[0] || strlen(text) > CUSTOM_MAX_FEATURE_TEXT) {
        set_error(error, error_len, "feature text is too long");
        return -1;
    }
    memset(feature, 0, sizeof(*feature));
    snprintf(buffer, sizeof(buffer), "%s", text);
    if (split_exact(buffer, ';', fields, 6) < 0 || fields[1][0]) {
        set_error(error, error_len, "feature field format is invalid");
        return -1;
    }
    if (strlen(fields[0]) != 3) {
        set_error(error, error_len, "protocol is invalid");
        return -1;
    }
    for (i = 0; i < 3; i++)
        feature->protocol[i] = (char)tolower((unsigned char)fields[0][i]);
    if (normalize_dest_port(fields[2], feature->dest_port,
                            sizeof(feature->dest_port)) < 0) {
        set_error(error, error_len, "dest_port is invalid");
        return -1;
    }
    if (strlen(fields[3]) >= sizeof(feature->domain) ||
        strlen(fields[4]) >= sizeof(feature->uri)) {
        set_error(error, error_len, "domain or uri is too long");
        return -1;
    }
    snprintf(feature->domain, sizeof(feature->domain), "%s", fields[3]);
    snprintf(feature->uri, sizeof(feature->uri), "%s", fields[4]);
    if (parse_payload_text(fields[5], feature) < 0) {
        set_error(error, error_len, "payload format is invalid");
        return -1;
    }
    return validate_feature(feature, error, error_len);
}

static int feature_to_text(const custom_feature_t *feature, char *buffer, size_t length)
{
    int written;
    int i;
    size_t used;

    written = snprintf(buffer, length, "%s;;%s;%s;%s;", feature->protocol,
                       feature->dest_port, feature->domain, feature->uri);
    if (written < 0 || (size_t)written >= length)
        return -1;
    used = (size_t)written;
    for (i = 0; i < feature->payload_count; i++) {
        written = snprintf(buffer + used, length - used, "%s%d:%02x",
                           i ? "|" : "", feature->payload[i].position,
                           feature->payload[i].value);
        if (written < 0 || (size_t)written >= length - used)
            return -1;
        used += (size_t)written;
    }
    return used <= CUSTOM_MAX_FEATURE_TEXT ? 0 : -1;
}

static int app_to_line(const custom_app_t *app, char *line, size_t length)
{
    char feature_text[CUSTOM_MAX_FEATURE_TEXT + 1];
    int written;
    int i;
    size_t used;

    written = snprintf(line, length, "%d~%s:[", app->appid, app->name);
    if (written < 0 || (size_t)written >= length)
        return -1;
    used = (size_t)written;
    for (i = 0; i < app->feature_count; i++) {
        if (feature_to_text(&app->features[i], feature_text, sizeof(feature_text)) < 0)
            return -1;
        written = snprintf(line + used, length - used, "%s%s", i ? "," : "",
                           feature_text);
        if (written < 0 || (size_t)written >= length - used)
            return -1;
        used += (size_t)written;
    }
    written = snprintf(line + used, length - used, "]");
    if (written != 1 || used + 1 > CUSTOM_MAX_APP_LINE)
        return -1;
    return 0;
}

static int validate_app_identity(custom_config_t *config, custom_app_t *app,
                                 int current_index, char *error, size_t error_len)
{
    size_t i;
    int suffix;

    if (!class_is_available(app->class_id)) {
        set_error(error, error_len, "class_id is invalid");
        return -1;
    }
    if (!app->name[0] || strlen(app->name) > 63 || has_forbidden_text_char(app->name, 1)) {
        set_error(error, error_len, "application name is invalid");
        return -1;
    }
    if (app->appid) {
        suffix = app->appid - app->class_id * 1000;
        if (suffix < CUSTOM_APP_MIN_SUFFIX || suffix > CUSTOM_APP_MAX_SUFFIX) {
            set_error(error, error_len, "appid is outside the custom range");
            return -1;
        }
    }
    for (i = 0; i < (size_t)current_index; i++) {
        if (!strcmp(config->apps[i].name, app->name) ||
            (app->appid && config->apps[i].appid == app->appid)) {
            set_error(error, error_len, "appid or application name is duplicated");
            return -1;
        }
    }
    return 0;
}

static int app_compare(const void *left, const void *right)
{
    const custom_app_t *a = left;
    const custom_app_t *b = right;

    if (a->class_id != b->class_id)
        return a->class_id - b->class_id;
    return a->appid - b->appid;
}

static int allocate_appids(custom_config_t *config, char *error, size_t error_len)
{
    unsigned char used[MAX_APP_TYPE + 1][100] = {{0}};
    size_t i;
    int suffix;

    for (i = 0; i < config->count; i++) {
        if (!config->apps[i].appid)
            continue;
        suffix = config->apps[i].appid % 1000;
        if (used[config->apps[i].class_id][suffix - CUSTOM_APP_MIN_SUFFIX]) {
            set_error(error, error_len, "appid is duplicated");
            return -1;
        }
        used[config->apps[i].class_id][suffix - CUSTOM_APP_MIN_SUFFIX] = 1;
    }
    for (i = 0; i < config->count; i++) {
        if (config->apps[i].appid)
            continue;
        for (suffix = CUSTOM_APP_MIN_SUFFIX; suffix <= CUSTOM_APP_MAX_SUFFIX; suffix++) {
            if (!used[config->apps[i].class_id][suffix - CUSTOM_APP_MIN_SUFFIX])
                break;
        }
        if (suffix > CUSTOM_APP_MAX_SUFFIX) {
            set_error(error, error_len, "custom appid range is full");
            return -1;
        }
        used[config->apps[i].class_id][suffix - CUSTOM_APP_MIN_SUFFIX] = 1;
        config->apps[i].appid = config->apps[i].class_id * 1000 + suffix;
    }
    qsort(config->apps, config->count, sizeof(*config->apps), app_compare);
    return 0;
}

static int parse_payload_json(struct json_object *array, custom_feature_t *feature,
                              char *error, size_t error_len)
{
    size_t i;

    if (!array)
        return 0;
    if (!json_object_is_type(array, json_type_array) ||
        json_object_array_length(array) > CUSTOM_MAX_PAYLOADS) {
        set_error(error, error_len, "payload is invalid");
        return -1;
    }
    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        struct json_object *position_obj;
        struct json_object *value_obj;
        const char *value_text;
        int64_t position;
        char *end = NULL;
        unsigned long value;

        if (!item || !json_object_is_type(item, json_type_object) ||
            !json_object_object_get_ex(item, "position", &position_obj) ||
            !json_object_is_type(position_obj, json_type_int) ||
            !json_object_object_get_ex(item, "value", &value_obj) ||
            !json_object_is_type(value_obj, json_type_string)) {
            set_error(error, error_len, "payload item is invalid");
            return -1;
        }
        position = json_object_get_int64(position_obj);
        value_text = json_object_get_string(value_obj);
        if (position < INT_MIN || position > INT_MAX || strlen(value_text) != 2 ||
            !isxdigit((unsigned char)value_text[0]) || !isxdigit((unsigned char)value_text[1])) {
            set_error(error, error_len, "payload position or value is invalid");
            return -1;
        }
        value = strtoul(value_text, &end, 16);
        if (!end || *end || value > 0xff)
            return -1;
        feature->payload[i].position = (int)position;
        feature->payload[i].value = (unsigned int)value;
        feature->payload_count++;
    }
    return 0;
}

static int parse_feature_json(struct json_object *object, custom_feature_t *feature,
                              char *error, size_t error_len)
{
    struct json_object *value;
    const char *text;
    size_t i;

    memset(feature, 0, sizeof(*feature));
    if (!object || !json_object_is_type(object, json_type_object) ||
        !json_object_object_get_ex(object, "protocol", &value) ||
        !json_object_is_type(value, json_type_string)) {
        set_error(error, error_len, "protocol is required");
        return -1;
    }
    text = json_object_get_string(value);
    if (strlen(text) != 3) {
        set_error(error, error_len, "protocol is invalid");
        return -1;
    }
    for (i = 0; i < 3; i++)
        feature->protocol[i] = (char)tolower((unsigned char)text[i]);
    if (json_object_object_get_ex(object, "dest_port", &value)) {
        if (json_object_is_type(value, json_type_int)) {
            int64_t port = json_object_get_int64(value);
            if (port < 0 || port > 65535 ||
                (port > 0 && snprintf(feature->dest_port,
                                      sizeof(feature->dest_port), "%lld",
                                      (long long)port) >= (int)sizeof(feature->dest_port))) {
                set_error(error, error_len, "dest_port is invalid");
                return -1;
            }
        } else if (json_object_is_type(value, json_type_string)) {
            if (normalize_dest_port(json_object_get_string(value), feature->dest_port,
                                    sizeof(feature->dest_port)) < 0) {
                set_error(error, error_len, "dest_port is invalid");
                return -1;
            }
        } else {
            set_error(error, error_len, "dest_port is invalid");
            return -1;
        }
    }
    if (json_object_object_get_ex(object, "domain", &value)) {
        if (!json_object_is_type(value, json_type_string) ||
            json_object_get_string_len(value) > 31) {
            set_error(error, error_len, "domain is invalid");
            return -1;
        }
        snprintf(feature->domain, sizeof(feature->domain), "%s", json_object_get_string(value));
    }
    if (json_object_object_get_ex(object, "uri", &value)) {
        if (!json_object_is_type(value, json_type_string) ||
            json_object_get_string_len(value) > 63) {
            set_error(error, error_len, "uri is invalid");
            return -1;
        }
        snprintf(feature->uri, sizeof(feature->uri), "%s", json_object_get_string(value));
    }
    if (json_object_object_get_ex(object, "payload", &value) &&
        parse_payload_json(value, feature, error, error_len) < 0)
        return -1;
    return validate_feature(feature, error, error_len);
}

static int config_from_json(struct json_object *request, custom_config_t *config,
                            char *error, size_t error_len)
{
    struct json_object *app_list;
    size_t i;

    if (!request || !json_object_is_type(request, json_type_object) ||
        !json_object_object_get_ex(request, "app_list", &app_list) ||
        !json_object_is_type(app_list, json_type_array)) {
        set_error(error, error_len, "app_list is required");
        return -1;
    }
    for (i = 0; i < json_object_array_length(app_list); i++) {
        struct json_object *item = json_object_array_get_idx(app_list, i);
        struct json_object *value;
        struct json_object *features;
        custom_app_t *app = config_add_app(config);
        size_t feature_index;
        int64_t number;

        if (!app || !item || !json_object_is_type(item, json_type_object))
            goto invalid_app;
        if (json_object_object_get_ex(item, "appid", &value)) {
            if (!json_object_is_type(value, json_type_int))
                goto invalid_app;
            number = json_object_get_int64(value);
            if (number < 0 || number > INT_MAX)
                goto invalid_app;
            app->appid = (int)number;
        }
        if (!json_object_object_get_ex(item, "class_id", &value) ||
            !json_object_is_type(value, json_type_int))
            goto invalid_app;
        app->class_id = json_object_get_int(value);
        if (!json_object_object_get_ex(item, "name", &value) ||
            !json_object_is_type(value, json_type_string) || json_object_get_string_len(value) > 63)
            goto invalid_app;
        snprintf(app->name, sizeof(app->name), "%s", json_object_get_string(value));
        {
            char *trimmed_name = trim_space(app->name);
            if (trimmed_name && trimmed_name != app->name)
                memmove(app->name, trimmed_name, strlen(trimmed_name) + 1);
        }
        if (validate_app_identity(config, app, (int)i, error, error_len) < 0)
            return -1;
        if (!json_object_object_get_ex(item, "features", &features) ||
            !json_object_is_type(features, json_type_array) ||
            json_object_array_length(features) < 1 ||
            json_object_array_length(features) > CUSTOM_MAX_FEATURES)
            goto invalid_features;
        app->feature_count = (int)json_object_array_length(features);
        for (feature_index = 0; feature_index < (size_t)app->feature_count; feature_index++) {
            if (parse_feature_json(json_object_array_get_idx(features, feature_index),
                                   &app->features[feature_index], error, error_len) < 0)
                return -1;
        }
    }
    if (get_base_app_count() + (int)config->count > MAX_SUPPORT_APP_NUM) {
        set_error(error, error_len, "application table capacity is exceeded");
        return -1;
    }
    if (allocate_appids(config, error, error_len) < 0)
        return -1;
    for (i = 0; i < config->count; i++) {
        char line[CUSTOM_MAX_APP_LINE + 2];
        if (app_to_line(&config->apps[i], line, sizeof(line)) < 0) {
            set_error(error, error_len, "serialized application line is too long");
            return -1;
        }
    }
    return 0;

invalid_features:
    set_error(error, error_len, "features must contain 1 to 16 items");
    return -1;
invalid_app:
    set_error(error, error_len, "application item is invalid");
    return -1;
}

static int parse_app_line(char *line, custom_config_t *config,
                          char *error, size_t error_len)
{
    custom_app_t *app;
    char *open = strstr(line, ":[");
    char *close;
    char *feature_text;
    char *next;
    char *slash;
    char *id_text;
    char *name_text;
    char *endptr;
    long appid;

    if (!open || strlen(line) > CUSTOM_MAX_APP_LINE)
        goto invalid;
    close = strrchr(open + 2, ']');
    if (!close || close[1])
        goto invalid;
    *open = '\0';
    app = config_add_app(config);
    if (!app)
        goto invalid;
    slash = strchr(line, '~');
    if (!slash)
        goto invalid;
    *slash = '\0';
    id_text = trim_space(line);
    name_text = trim_space(slash + 1);
    if (!id_text || !id_text[0] || !name_text || !name_text[0])
        goto invalid;
    appid = strtol(id_text, &endptr, 10);
    endptr = trim_space(endptr);
    if (appid <= 0 || appid > INT_MAX || (endptr && endptr[0] != '\0') ||
        strlen(name_text) >= sizeof(app->name))
        goto invalid;
    app->appid = (int)appid;
    snprintf(app->name, sizeof(app->name), "%s", name_text);
    app->class_id = app->appid / 1000;
    if (validate_app_identity(config, app, (int)config->count - 1,
                              error, error_len) < 0)
        return -1;
    *close = '\0';
    feature_text = open + 2;
    if (!feature_text[0] || feature_text[strlen(feature_text) - 1] == ',')
        goto invalid_features;
    while (feature_text && feature_text[0]) {
        if (app->feature_count >= CUSTOM_MAX_FEATURES)
            goto invalid_features;
        next = strchr(feature_text, ',');
        if (next)
            *next++ = '\0';
        if (parse_feature_text(feature_text, &app->features[app->feature_count],
                               error, error_len) < 0)
            return -1;
        app->feature_count++;
        feature_text = next;
    }
    if (!app->feature_count)
        goto invalid_features;
    return 0;

invalid_features:
    set_error(error, error_len, "features must contain 1 to 16 items");
    return -1;
invalid:
    set_error(error, error_len, "custom feature line is invalid");
    return -1;
}

static int config_read_file(const char *path, custom_config_t *config,
                            char *error, size_t error_len)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    int line_number = 0;

    if (!file) {
        if (errno == ENOENT)
            return 0;
        set_error(error, error_len, "failed to open custom feature file");
        return -1;
    }
    while (fgets(line, sizeof(line), file)) {
        size_t length;

        line_number++;
        length = strlen(line);
        if (length && line[length - 1] != '\n' && !feof(file))
            goto invalid_line;
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (!line[0])
            continue;
        if (!strncmp(line, "#class ", 7))
            continue;
        if (parse_app_line(line, config, error, error_len) < 0)
            goto failed;
    }
    if (ferror(file)) {
        set_error(error, error_len, "failed to read custom feature file");
        goto failed;
    }
    fclose(file);
    if (get_base_app_count() + (int)config->count > MAX_SUPPORT_APP_NUM) {
        set_error(error, error_len, "application table capacity is exceeded");
        return -1;
    }
    qsort(config->apps, config->count, sizeof(*config->apps), app_compare);
    return 0;

invalid_line:
    snprintf(error, error_len, "invalid custom feature file at line %d", line_number);
failed:
    fclose(file);
    return -1;
}

static int config_write_file(const custom_config_t *config, char *error, size_t error_len)
{
    char temporary[256];
    char line[CUSTOM_MAX_APP_LINE + 2];
    FILE *file;
    size_t app_index;
    int failed = 0;

    snprintf(temporary, sizeof(temporary), "%s.tmp", FWX_CUSTOM_FEATURE_PATH);
    file = fopen(temporary, "w");
    if (!file) {
        set_error(error, error_len, "failed to create temporary custom feature file");
        return -1;
    }
    for (app_index = 0; app_index < config->count && !failed; app_index++) {
        if (app_to_line(&config->apps[app_index], line, sizeof(line)) < 0 ||
            fprintf(file, "%s\n", line) < 0)
            failed = 1;
    }
    if (!failed && fflush(file) < 0)
        failed = 1;
    if (!failed && fsync(fileno(file)) < 0)
        failed = 1;
    if (fclose(file) < 0)
        failed = 1;
    if (!failed && chmod(temporary, 0644) < 0)
        failed = 1;
    if (!failed && rename(temporary, FWX_CUSTOM_FEATURE_PATH) < 0)
        failed = 1;
    if (failed) {
        unlink(temporary);
        set_error(error, error_len, "failed to save custom feature file");
        return -1;
    }
    return 0;
}

static struct json_object *feature_to_json(const custom_feature_t *feature)
{
    struct json_object *object = json_object_new_object();
    struct json_object *payload = json_object_new_array();
    int i;
    char value[3];

    json_object_object_add(object, "protocol", json_object_new_string(feature->protocol));
    json_object_object_add(object, "dest_port", json_object_new_string(feature->dest_port));
    json_object_object_add(object, "domain", json_object_new_string(feature->domain));
    json_object_object_add(object, "uri", json_object_new_string(feature->uri));
    for (i = 0; i < feature->payload_count; i++) {
        struct json_object *item = json_object_new_object();
        snprintf(value, sizeof(value), "%02x", feature->payload[i].value);
        json_object_object_add(item, "position",
                               json_object_new_int(feature->payload[i].position));
        json_object_object_add(item, "value", json_object_new_string(value));
        json_object_array_add(payload, item);
    }
    json_object_object_add(object, "payload", payload);
    return object;
}

static struct json_object *config_to_data(const custom_config_t *config)
{
    struct json_object *data = json_object_new_object();
    struct json_object *app_list = json_object_new_array();
    size_t i;

    for (i = 0; i < config->count; i++) {
        struct json_object *item = json_object_new_object();
        struct json_object *features = json_object_new_array();
        int feature_index;

        json_object_object_add(item, "appid", json_object_new_int(config->apps[i].appid));
        if (!app_icon_exists_by_id(config->apps[i].appid))
            json_object_object_add(item, "icon", json_object_new_int(0));
        json_object_object_add(item, "class_id", json_object_new_int(config->apps[i].class_id));
        json_object_object_add(item, "name", json_object_new_string(config->apps[i].name));
        for (feature_index = 0; feature_index < config->apps[i].feature_count; feature_index++)
            json_object_array_add(features, feature_to_json(&config->apps[i].features[feature_index]));
        json_object_object_add(item, "features", features);
        json_object_array_add(app_list, item);
    }
    json_object_object_add(data, "app_list", app_list);
    return data;
}

static void add_class_json(struct json_object *class_list, int class_id,
                           const char *class_name)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "class_id", json_object_new_int(class_id));
    json_object_object_add(item, "class_name", json_object_new_string(class_name));
    json_object_array_add(class_list, item);
}

static struct json_object *class_list_to_data(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *class_list = json_object_new_array();
    int i;

    if (has_builtin_classes()) {
        for (i = 0; i < MAX_APP_TYPE; i++) {
            if (CLASS_NAME_TABLE[i][0])
                add_class_json(class_list, i + 1, CLASS_NAME_TABLE[i]);
        }
    } else {
        for (i = 0; i < CUSTOM_FALLBACK_CLASS_COUNT; i++)
            add_class_json(class_list, fallback_classes[i].id, fallback_classes[i].name);
    }
    json_object_object_add(data, "class_list", class_list);
    return data;
}

static struct json_object *error_response(const char *error, int saved)
{
    struct json_object *data = json_object_new_object();

    if (error && error[0])
        json_object_object_add(data, "error", json_object_new_string(error));
    if (saved) {
        json_object_object_add(data, "saved", json_object_new_int(1));
        json_object_object_add(data, "reloaded", json_object_new_int(0));
    }
    return fwx_gen_api_response_data(API_CODE_ERROR, data);
}

int fwx_custom_feature_reload(void)
{
    custom_config_t loaded = {0};
    char error[128] = {0};

    if (config_read_file(FWX_CUSTOM_FEATURE_PATH, &loaded, error, sizeof(error)) < 0) {
        LOG_ERROR("Failed to load custom features: %s\n", error);
        config_free(&loaded);
        return -1;
    }
    config_free(&custom_config);
    custom_config = loaded;
    return 0;
}

int fwx_custom_feature_send_to_kernel(int (*send_feature)(char *))
{
    char line[CUSTOM_MAX_APP_LINE + 2];
    size_t i;

    if (!send_feature)
        return -1;
    for (i = 0; i < custom_config.count; i++) {
        if (app_to_line(&custom_config.apps[i], line, sizeof(line)) < 0 ||
            send_feature(line) < 0)
            return -1;
    }
    return (int)custom_config.count;
}

int fwx_custom_feature_add_app_names(void)
{
    size_t i;

    if (get_base_app_count() + (int)custom_config.count > MAX_SUPPORT_APP_NUM)
        return -1;
    for (i = 0; i < custom_config.count; i++) {
        if (add_app_name_to_table(custom_config.apps[i].appid,
                                  custom_config.apps[i].name) < 0)
            return -1;
    }
    return 0;
}

void fwx_custom_feature_append_class_apps(struct json_object **class_map,
                                          size_t class_map_len)
{
    size_t i;

    for (i = 0; i < custom_config.count; i++) {
        struct json_object *app_list;
        char combined[256];
        int class_id = custom_config.apps[i].class_id;

        if (class_id < 0 || (size_t)class_id >= class_map_len || !class_map[class_id] ||
            !json_object_object_get_ex(class_map[class_id], "app_list", &app_list))
            continue;
        if (app_icon_exists_by_id(custom_config.apps[i].appid))
            snprintf(combined, sizeof(combined), "%d,%s", custom_config.apps[i].appid,
                     custom_config.apps[i].name);
        else
            snprintf(combined, sizeof(combined), "%d,%s,0", custom_config.apps[i].appid,
                     custom_config.apps[i].name);
        json_object_array_add(app_list, json_object_new_string(combined));
    }
}

struct json_object *fwx_api_get_custom_feature(struct json_object *req_obj)
{
    custom_config_t loaded = {0};
    char error[128] = {0};
    struct json_object *response;

    (void)req_obj;
    if (config_read_file(FWX_CUSTOM_FEATURE_PATH, &loaded, error, sizeof(error)) < 0) {
        config_free(&loaded);
        return error_response(error, 0);
    }
    response = fwx_gen_api_response_data(API_CODE_SUCCESS, config_to_data(&loaded));
    config_free(&loaded);
    return response;
}

struct json_object *fwx_api_get_custom_feature_class_list(struct json_object *req_obj)
{
    (void)req_obj;
    return fwx_gen_api_response_data(API_CODE_SUCCESS, class_list_to_data());
}

struct json_object *fwx_api_set_custom_feature(struct json_object *req_obj)
{
    custom_config_t submitted = {0};
    char error[128] = {0};
    struct json_object *response;

    if (config_from_json(req_obj, &submitted, error, sizeof(error)) < 0) {
        config_free(&submitted);
        return error_response(error, 0);
    }
    if (config_write_file(&submitted, error, sizeof(error)) < 0) {
        config_free(&submitted);
        return error_response(error, 0);
    }
    if (reload_feature() < 0) {
        config_free(&submitted);
        return error_response("custom feature file was saved but reload failed", 1);
    }
    response = fwx_gen_api_response_data(API_CODE_SUCCESS, config_to_data(&submitted));
    config_free(&submitted);
    return response;
}
