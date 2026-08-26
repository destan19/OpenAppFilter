// SPDX-License-Identifier: GPL-2.0-or-later
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include <libubox/uloop.h>
#include <uci.h>

#include "fwx.h"
#include "fwx_feature.h"
#include "fwx_feature_online.h"
#include "fwx_utils.h"

#define ONLINE_BASE_URL "https://api.openappfilter.com"
#define ONLINE_VERSION "v4.0"
#define ONLINE_STATUS_PATH "/tmp/feature_online_upgrade.status"
#define ONLINE_WORK_DIR "/tmp/feature_online"
#define ONLINE_ARCHIVE_PATH ONLINE_WORK_DIR "/feature_package.bin"
#define ONLINE_EXTRACT_DIR ONLINE_WORK_DIR "/extract"
#define ONLINE_FEATURE_TEMP ONLINE_WORK_DIR "/feature.bin"
#define ONLINE_ICON_DIR ONLINE_EXTRACT_DIR "/app_icons"
#define ONLINE_ICON_TARGET "/www/luci-static/resources/oaf/app_icons"
#define ONLINE_FAILED_ARCHIVE_PATH "/tmp/feature_online_failed.bin"
#define ONLINE_COMMAND_STATUS "/tmp/feature_online_command.status"
#define ONLINE_RESPONSE_MAX (256U * 1024U)
#define ONLINE_ARCHIVE_MAX FWX_FEATURE_MAX_SIZE
#define ONLINE_FILE_MAX 128
#define ONLINE_UPDATE_TIMEOUT 180
#define ONLINE_DOWNLOAD_TIMEOUT 300
#define ONLINE_TOKEN_MAX 256
#define ONLINE_HOSTNAME_MAX 64
#define ONLINE_DEVICE_LANG_MAX 64

typedef struct {
    char state[16];
    char stage[24];
    int status_code;
    char message[160];
    char id[65];
    int icons_skipped;
    curl_off_t download_total;
    curl_off_t download_now;
    time_t started_at;
    time_t updated_at;
} online_status_t;

typedef struct {
    char id[65];
    char token[ONLINE_TOKEN_MAX + 1];
    char device_id[33];
    char model[129];
    char lang[3];
    char expected_md5[33];
} online_worker_t;

typedef struct {
    char *data;
    size_t size;
    size_t limit;
} memory_buffer_t;

typedef struct {
    FILE *fp;
    size_t size;
    size_t limit;
    int too_large;
} file_buffer_t;

typedef struct {
    time_t last_update;
    curl_off_t last_now;
} progress_ctx_t;

static pthread_mutex_t online_mutex = PTHREAD_MUTEX_INITIALIZER;
static online_status_t online_status = {.state = "idle", .stage = "idle"};
static int online_pipe[2] = {-1, -1};
static int online_ready;
static int online_worker_running;
static struct uloop_fd online_uloop_fd;

extern int g_feature_update;

static void release_upgrade_lock(void);

static void free_worker(online_worker_t *worker)
{
    if (!worker)
        return;
    memset(worker, 0, sizeof(*worker));
    free(worker);
}

static int token_valid(const char *token)
{
    size_t i;
    size_t len = token ? strlen(token) : 0;

    if (!token || len > ONLINE_TOKEN_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        if (iscntrl((unsigned char)token[i]))
            return 0;
    }
    return 1;
}

static int id_valid(const char *id)
{
    size_t i;
    size_t len = id ? strlen(id) : 0;

    if (len == 0 || len > 64)
        return 0;
    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char)id[i]) && id[i] != '-' && id[i] != '_')
            return 0;
    }
    return 1;
}

static int lang_valid(const char *lang)
{
    return lang && (!strcmp(lang, "cn") || !strcmp(lang, "en"));
}

static int md5_text_valid(const char *md5)
{
    size_t i;

    if (!md5 || strlen(md5) != 32)
        return 0;
    for (i = 0; i < 32; i++) {
        if (!isxdigit((unsigned char)md5[i]))
            return 0;
    }
    return 1;
}

static void copy_md5_lower(char out[33], const char *md5)
{
    size_t i;

    for (i = 0; i < 32; i++)
        out[i] = (char)tolower((unsigned char)md5[i]);
    out[32] = '\0';
}

static int file_md5_hex(const char *path, char out[33])
{
    struct stat st;
    FILE *fp;
    unsigned char *data;
    unsigned char digest[16];
    size_t read_len;
    int i;

    if (!path || !out || stat(path, &st) != 0 || st.st_size <= 0 ||
        st.st_size > (off_t)ONLINE_ARCHIVE_MAX)
        return -1;
    data = malloc((size_t)st.st_size);
    if (!data)
        return -1;
    fp = fopen(path, "rb");
    if (!fp) {
        free(data);
        return -1;
    }
    read_len = fread(data, 1, (size_t)st.st_size, fp);
    fclose(fp);
    if (read_len != (size_t)st.st_size) {
        free(data);
        return -1;
    }
    fwx_md5(data, read_len, digest);
    free(data);
    for (i = 0; i < 16; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[32] = '\0';
    return 0;
}

static void trim_text(char *text)
{
    size_t len;

    if (!text)
        return;
    len = strlen(text);
    while (len > 0 && isspace((unsigned char)text[len - 1]))
        text[--len] = '\0';
    while (*text && isspace((unsigned char)*text))
        memmove(text, text + 1, strlen(text));
}

static int read_first_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (!path || !out || out_len < 2)
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, (int)out_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    trim_text(out);
    return out[0] ? 0 : -1;
}

static int query_text_valid(const char *text, size_t max_len)
{
    size_t i, len;

    if (!text)
        return 0;
    len = strlen(text);
    if (len > max_len)
        return 0;
    for (i = 0; i < len; i++) {
        if (iscntrl((unsigned char)text[i]))
            return 0;
    }
    return 1;
}

static void sanitize_query_text(char *text)
{
    size_t i;

    if (!text)
        return;
    trim_text(text);
    for (i = 0; text[i]; i++) {
        if (isspace((unsigned char)text[i]))
            text[i] = '-';
        else if (iscntrl((unsigned char)text[i]))
            text[i] = '_';
    }
}

static int get_system_hostname(char *hostname, size_t hostname_len)
{
    if (!hostname || hostname_len < 2)
        return -1;
    hostname[0] = '\0';
    if (read_first_line("/proc/sys/kernel/hostname", hostname, hostname_len) < 0)
        return -1;
    sanitize_query_text(hostname);
    return hostname[0] ? 0 : -1;
}
static int get_saved_token(char *token, size_t token_len)
{
    struct uci_context *ctx;
    int ret;

    if (!token || token_len == 0)
        return -1;
    token[0] = '\0';
    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    ret = fwx_uci_get_value(ctx, "fwx.global.feature_token", token, (int)token_len);
    uci_free_context(ctx);
    return ret;
}

static int get_device_id(char *device_id, size_t device_id_len)
{
    const char *ifnames[] = {"br-lan", "eth0", "eth1"};
    char path[96];
    char mac[32] = {0};
    char normalized[13] = {0};
    unsigned char digest[16];
    size_t i;
    size_t used = 0;

    if (!device_id || device_id_len < 33)
        return -1;
    for (i = 0; i < sizeof(ifnames) / sizeof(ifnames[0]); i++) {
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifnames[i]);
        if (read_first_line(path, mac, sizeof(mac)) == 0)
            break;
    }
    if (!mac[0])
        return -1;
    for (i = 0; mac[i]; i++) {
        if (isxdigit((unsigned char)mac[i])) {
            if (used >= sizeof(normalized) - 1)
                return -1;
            normalized[used++] = (char)tolower((unsigned char)mac[i]);
        }
    }
    if (used != 12)
        return -1;
    fwx_md5((const unsigned char *)normalized, used, digest);
    for (i = 0; i < 16; i++)
        snprintf(device_id + i * 2, device_id_len - i * 2, "%02x", digest[i]);
    device_id[32] = '\0';
    return 0;
}

static int get_device_model(char *model, size_t model_len)
{
    struct json_object *board;
    struct json_object *model_obj;
    struct json_object *name_obj;
    size_t i;

    if (!model || model_len < 2)
        return -1;
    model[0] = '\0';
    board = json_object_from_file("/etc/board.json");
    if (board && json_object_object_get_ex(board, "model", &model_obj) &&
        json_object_object_get_ex(model_obj, "name", &name_obj) &&
        json_object_is_type(name_obj, json_type_string))
        snprintf(model, model_len, "%s", json_object_get_string(name_obj));
    if (board)
        json_object_put(board);
    if (!model[0] && read_first_line("/proc/device-tree/model", model, model_len) < 0)
        read_first_line("/tmp/sysinfo/board_name", model, model_len);
    trim_text(model);
    if (!model[0])
        return -1;
    for (i = 0; model[i]; i++) {
        if (isspace((unsigned char)model[i]))
            model[i] = '-';
        else if (iscntrl((unsigned char)model[i]))
            model[i] = '_';
    }
    return 0;
}

static int write_status_file_locked(void)
{
    const char *temporary = ONLINE_STATUS_PATH ".tmp";
    const char *text;
    struct json_object *obj;
    FILE *fp;
    int ret = -1;

    obj = json_object_new_object();
    if (!obj)
        return -1;
    json_object_object_add(obj, "state", json_object_new_string(online_status.state));
    json_object_object_add(obj, "stage", json_object_new_string(online_status.stage));
    json_object_object_add(obj, "status_code", json_object_new_int(online_status.status_code));
    json_object_object_add(obj, "message", json_object_new_string(online_status.message));
    json_object_object_add(obj, "id", json_object_new_string(online_status.id));
    json_object_object_add(obj, "icons_skipped", json_object_new_int(online_status.icons_skipped));
    json_object_object_add(obj, "download_total", json_object_new_int64((int64_t)online_status.download_total));
    json_object_object_add(obj, "download_now", json_object_new_int64((int64_t)online_status.download_now));
    json_object_object_add(obj, "started_at", json_object_new_int64((int64_t)online_status.started_at));
    json_object_object_add(obj, "updated_at", json_object_new_int64((int64_t)online_status.updated_at));
    text = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    fp = fopen(temporary, "w");
    if (!fp || fwrite(text, 1, strlen(text), fp) != strlen(text) ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        goto out;
    if (fclose(fp) != 0) {
        fp = NULL;
        goto out;
    }
    fp = NULL;
    if (chmod(temporary, 0644) == 0 && rename(temporary, ONLINE_STATUS_PATH) == 0)
        ret = 0;
out:
    if (fp)
        fclose(fp);
    if (ret != 0)
        unlink(temporary);
    json_object_put(obj);
    return ret;
}

static void set_status(const char *state, const char *stage, int code,
                       const char *message, int icons_skipped)
{
    time_t now = time(NULL);

    pthread_mutex_lock(&online_mutex);
    if (state) {
        if (strcmp(state, "running") == 0 &&
            (strcmp(online_status.state, "running") != 0 || online_status.started_at == 0))
            online_status.started_at = now;
        else if (strcmp(state, "running") != 0)
            online_status.started_at = 0;
        snprintf(online_status.state, sizeof(online_status.state), "%s", state);
    }
    if (stage)
        snprintf(online_status.stage, sizeof(online_status.stage), "%s", stage);
    online_status.status_code = code;
    if (message)
        snprintf(online_status.message, sizeof(online_status.message), "%s", message);
    online_status.icons_skipped = icons_skipped;
    if (stage && strcmp(stage, "downloading") == 0) {
        online_status.download_total = 0;
        online_status.download_now = 0;
    } else if (state && strcmp(state, "running") != 0) {
        online_status.download_total = 0;
        online_status.download_now = 0;
    }
    online_status.updated_at = now;
    write_status_file_locked();
    pthread_mutex_unlock(&online_mutex);
    LOG_INFO("feature online status: state=%s stage=%s code=%d message=%s icons_skipped=%d",
             state ? state : "-", stage ? stage : "-", code,
             message ? message : "", icons_skipped);
}

static struct json_object *status_data(void)
{
    struct json_object *data = json_object_new_object();
    time_t now = time(NULL);
    int elapsed = 0;
    int timed_out = 0;

    pthread_mutex_lock(&online_mutex);
    if (strcmp(online_status.state, "running") == 0 && online_status.started_at > 0) {
        elapsed = (int)(now - online_status.started_at);
        if (elapsed > ONLINE_UPDATE_TIMEOUT) {
            snprintf(online_status.state, sizeof(online_status.state), "%s", "failed");
            snprintf(online_status.stage, sizeof(online_status.stage), "%s", "idle");
            online_status.status_code = 408;
            snprintf(online_status.message, sizeof(online_status.message), "%s",
                     "feature update timeout");
            online_status.icons_skipped = 0;
            online_status.download_total = 0;
            online_status.download_now = 0;
            online_status.started_at = 0;
            online_status.updated_at = now;
            online_worker_running = 0;
            write_status_file_locked();
            timed_out = 1;
        }
    }
    json_object_object_add(data, "state", json_object_new_string(online_status.state));
    json_object_object_add(data, "stage", json_object_new_string(online_status.stage));
    json_object_object_add(data, "status_code", json_object_new_int(online_status.status_code));
    json_object_object_add(data, "message", json_object_new_string(online_status.message));
    json_object_object_add(data, "id", json_object_new_string(online_status.id));
    json_object_object_add(data, "icons_skipped", json_object_new_int(online_status.icons_skipped));
    json_object_object_add(data, "download_total", json_object_new_int64((int64_t)online_status.download_total));
    json_object_object_add(data, "download_now", json_object_new_int64((int64_t)online_status.download_now));
    json_object_object_add(data, "elapsed", json_object_new_int(elapsed));
    pthread_mutex_unlock(&online_mutex);
    if (timed_out) {
        LOG_WARN("feature online update timeout, elapsed=%d", elapsed);
        release_upgrade_lock();
    }
    return data;
}

static struct json_object *error_response(int status_code, const char *message)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "status_code", json_object_new_int(status_code));
    json_object_object_add(data, "message", json_object_new_string(message ? message : "request failed"));
    return fwx_gen_api_response_data(API_CODE_ERROR, data);
}

static size_t memory_write(void *contents, size_t size, size_t count, void *userp)
{
    size_t bytes = size * count;
    memory_buffer_t *buffer = userp;
    char *next;

    if (!buffer || bytes > buffer->limit || buffer->size > buffer->limit - bytes)
        return 0;
    next = realloc(buffer->data, buffer->size + bytes + 1);
    if (!next)
        return 0;
    buffer->data = next;
    memcpy(buffer->data + buffer->size, contents, bytes);
    buffer->size += bytes;
    buffer->data[buffer->size] = '\0';
    return bytes;
}

static int download_progress_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                                curl_off_t ultotal, curl_off_t ulnow)
{
    progress_ctx_t *ctx = clientp;
    time_t now = time(NULL);

    (void)ultotal;
    (void)ulnow;
    if (!ctx)
        return 0;
    if (now == ctx->last_update && dlnow != dltotal)
        return 0;
    if (dlnow == ctx->last_now && dlnow != dltotal)
        return 0;
    ctx->last_update = now;
    ctx->last_now = dlnow;
    pthread_mutex_lock(&online_mutex);
    if (strcmp(online_status.state, "running") == 0 &&
        strcmp(online_status.stage, "downloading") == 0) {
        online_status.download_total = dltotal > 0 ? dltotal : 0;
        online_status.download_now = dlnow > 0 ? dlnow : 0;
        online_status.updated_at = now;
        write_status_file_locked();
    }
    pthread_mutex_unlock(&online_mutex);
    LOG_INFO("feature online download progress: now=%lld total=%lld",
             (long long)dlnow, (long long)dltotal);
    return 0;
}

static size_t file_write(void *contents, size_t size, size_t count, void *userp)
{
    size_t bytes = size * count;
    file_buffer_t *buffer = userp;

    if (!buffer || !buffer->fp || bytes > buffer->limit || buffer->size > buffer->limit - bytes) {
        if (buffer)
            buffer->too_large = 1;
        return 0;
    }
    if (fwrite(contents, 1, bytes, buffer->fp) != bytes)
        return 0;
    buffer->size += bytes;
    return bytes;
}

static void set_curl_options(CURL *curl, const char *url)
{
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "fwxd-feature-update/1.0");
}

static int build_url(CURL *curl, const char *path, const char *token,
                     const char *device_id, const char *model, const char *lang,
                     const char *hostname, const char *device_lang, const char *id,
                     char *url, size_t url_len)
{
    char *token_escaped = NULL;
    char *device_escaped = NULL;
    char *model_escaped = NULL;
    char *version_escaped = NULL;
    char *lang_escaped = NULL;
    char *hostname_escaped = NULL;
    char *device_lang_escaped = NULL;
    char *id_escaped = NULL;
    int ret = -1;

    token_escaped = curl_easy_escape(curl, token, 0);
    device_escaped = curl_easy_escape(curl, device_id, 0);
    model_escaped = curl_easy_escape(curl, model, 0);
    version_escaped = curl_easy_escape(curl, ONLINE_VERSION, 0);
    if (lang)
        lang_escaped = curl_easy_escape(curl, lang, 0);
    if (hostname)
        hostname_escaped = curl_easy_escape(curl, hostname, 0);
    if (device_lang)
        device_lang_escaped = curl_easy_escape(curl, device_lang, 0);
    if (id)
        id_escaped = curl_easy_escape(curl, id, 0);
    if (!token_escaped || !device_escaped || !model_escaped || !version_escaped ||
        (lang && !lang_escaped) || (hostname && !hostname_escaped) ||
        (device_lang && !device_lang_escaped) || (id && !id_escaped))
        goto out;
    if (snprintf(url, url_len,
                 "%s%s?token=%s&device_id=%s&model=%s&version=%s%s%s%s%s%s%s%s%s",
                 ONLINE_BASE_URL, path, token_escaped, device_escaped, model_escaped,
                 version_escaped, lang ? "&lang=" : "", lang ? lang_escaped : "",
                 hostname ? "&hostname=" : "", hostname ? hostname_escaped : "",
                 device_lang ? "&device_lang=" : "",
                 device_lang ? device_lang_escaped : "", id ? "&id=" : "",
                 id ? id_escaped : "") >= (int)url_len)
        goto out;
    ret = 0;
out:
    curl_free(token_escaped);
    curl_free(device_escaped);
    curl_free(model_escaped);
    curl_free(version_escaped);
    curl_free(lang_escaped);
    curl_free(hostname_escaped);
    curl_free(device_lang_escaped);
    curl_free(id_escaped);
    return ret;
}

static int parse_remote_json_error(const char *body, int *code,
                                   char *message, size_t message_len)
{
    struct json_object *root;
    struct json_object *code_obj;
    struct json_object *msg_obj;
    int remote_code;

    if (!body || !body[0])
        return -1;
    root = json_tokener_parse(body);
    if (!root)
        return -1;
    if (!json_object_is_type(root, json_type_object) ||
        !json_object_object_get_ex(root, "code", &code_obj)) {
        json_object_put(root);
        return -1;
    }
    remote_code = json_object_get_int(code_obj);
    if (remote_code == 20000) {
        json_object_put(root);
        return -1;
    }
    *code = remote_code;
    snprintf(message, message_len, "subscription request failed");
    if (json_object_object_get_ex(root, "msg", &msg_obj) &&
        json_object_is_type(msg_obj, json_type_string))
        snprintf(message, message_len, "%s", json_object_get_string(msg_obj));
    json_object_put(root);
    return 0;
}

static void parse_remote_error(const char *body, long http_code, int *code,
                               char *message, size_t message_len)
{
    *code = http_code >= 400 && http_code <= 599 ? (int)http_code : 400;
    snprintf(message, message_len, "subscription request failed");
    parse_remote_json_error(body, code, message, message_len);
}

static int get_request_credentials(char *token, size_t token_len,
                                   char *device_id, size_t device_len,
                                   char *model, size_t model_len)
{
    if (get_saved_token(token, token_len) < 0)
        token[0] = '\0';
    if (!token_valid(token))
        return -1;
    if (get_device_id(device_id, device_len) < 0)
        return -2;
    if (get_device_model(model, model_len) < 0)
        return -3;
    return 0;
}

static int acquire_upgrade_lock(void)
{
    struct stat st;
    time_t now = time(NULL);

    if (mkdir(FWX_FEATURE_UPGRADE_LOCK_PATH, 0700) == 0)
        return 0;
    if (errno != EEXIST || stat(FWX_FEATURE_UPGRADE_LOCK_PATH, &st) != 0 ||
        now - st.st_mtime < 600)
        return -1;
    rmdir(FWX_FEATURE_UPGRADE_LOCK_PATH);
    return mkdir(FWX_FEATURE_UPGRADE_LOCK_PATH, 0700) == 0 ? 0 : -1;
}

static int run_shell_command(const char *command, int timeout_seconds)
{
    const char *temporary = ONLINE_COMMAND_STATUS ".tmp";
    char wrapper[1024];
    char status[32] = {0};
    pid_t pid;
    int retry;

    if (!command || snprintf(wrapper, sizeof(wrapper),
        "%s; result=$?; printf '%%d' \"$result\" >%s; mv %s %s",
        command, temporary, temporary, ONLINE_COMMAND_STATUS) >= (int)sizeof(wrapper))
        return -1;
    unlink(temporary);
    unlink(ONLINE_COMMAND_STATUS);
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        setpgid(0, 0);
        execl("/bin/sh", "sh", "-c", wrapper, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    for (retry = 0; retry < timeout_seconds * 10; retry++) {
        if (read_first_line(ONLINE_COMMAND_STATUS, status, sizeof(status)) == 0) {
            unlink(ONLINE_COMMAND_STATUS);
            return atoi(status);
        }
        usleep(100000);
    }
    kill(-pid, SIGKILL);
    unlink(temporary);
    unlink(ONLINE_COMMAND_STATUS);
    return -1;
}

static void cleanup_work_files(void)
{
    run_shell_command("rm -rf " ONLINE_WORK_DIR, 10);
}

static void release_upgrade_lock(void)
{
    cleanup_work_files();
    rmdir(FWX_FEATURE_UPGRADE_LOCK_PATH);
}

static int icon_entry_valid(const char *entry)
{
    const char *name;
    size_t i;
    size_t len;

    if (!strcmp(entry, "app_icons") || !strcmp(entry, "app_icons/"))
        return 1;
    if (strncmp(entry, "app_icons/", 10) != 0)
        return 0;
    name = entry + 10;
    len = strlen(name);
    if (len < 5 || len > 128 || strcmp(name + len - 4, ".png") != 0)
        return 0;
    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char)name[i]) && name[i] != '.' &&
            name[i] != '_' && name[i] != '-')
            return 0;
    }
    return 1;
}

static int archive_entry_path_safe(const char *entry)
{
    const char *p;
    const char *part;
    size_t part_len;

    if (!entry || !entry[0] || entry[0] == '/' || strchr(entry, '\\'))
        return 0;
    p = entry;
    while (*p) {
        while (*p == '/')
            p++;
        part = p;
        while (*p && *p != '/')
            p++;
        part_len = (size_t)(p - part);
        if (part_len == 2 && part[0] == '.' && part[1] == '.')
            return 0;
    }
    return 1;
}

static void normalize_archive_entry(char *entry)
{
    while (entry && !strncmp(entry, "./", 2))
        memmove(entry, entry + 2, strlen(entry + 2) + 1);
}

static int feature_entry_valid(const char *entry)
{
    return entry && !strcmp(entry, "feature.bin");
}

static int validate_archive(int *icon_count)
{
    char line[512];
    FILE *pipe;

    *icon_count = 0;
    pipe = popen("tar -ztf " ONLINE_ARCHIVE_PATH " 2>/dev/null", "r");
    if (!pipe) {
        LOG_ERROR("feature online archive list command failed");
        return -1;
    }
    while (fgets(line, sizeof(line), pipe)) {
        trim_text(line);
        if (!archive_entry_path_safe(line)) {
            LOG_WARN("feature online archive unsafe entry: %s", line);
            pclose(pipe);
            return -1;
        }
        normalize_archive_entry(line);
        if (!line[0] || !strcmp(line, "."))
            continue;
        if (feature_entry_valid(line)) {
            LOG_INFO("feature online archive feature entry: %s", line);
        } else if (icon_entry_valid(line)) {
            if (strcmp(line, "app_icons") != 0 &&
                strcmp(line, "app_icons/") != 0 &&
                ++(*icon_count) > 4096) {
                LOG_WARN("feature online archive has too many icons");
                pclose(pipe);
                return -1;
            }
        } else {
            LOG_WARN("feature online archive invalid entry: %s", line);
            pclose(pipe);
            return -1;
        }
    }
    pclose(pipe);
    LOG_INFO("feature online archive validated, icons=%d", *icon_count);
    return 0;
}

static int validate_icon_tree(const char *path, int depth)
{
    struct stat st;
    struct dirent *entry;
    DIR *dir;
    char child[512];
    int ret = 0;

    if (depth > 2 || lstat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child) ||
            lstat(child, &st) != 0) {
            ret = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (validate_icon_tree(child, depth + 1) < 0) {
                ret = -1;
                break;
            }
        } else if (!S_ISREG(st.st_mode) || st.st_size > 2U * 1024U * 1024U) {
            ret = -1;
            break;
        }
    }
    closedir(dir);
    return ret;
}

static unsigned long long directory_size(const char *path);

static int prepare_archive_candidate(int icon_count)
{
    struct stat st;
    const char *feature_source = ONLINE_EXTRACT_DIR "/feature.bin";
    int ret;

    ret = run_shell_command("rm -rf " ONLINE_EXTRACT_DIR, 10);
    if (ret != 0) {
        LOG_ERROR("feature online cleanup extract dir failed, ret=%d", ret);
        return -1;
    }
    if (mkdir(ONLINE_EXTRACT_DIR, 0700) != 0) {
        LOG_ERROR("feature online create extract dir failed, errno=%d", errno);
        return -1;
    }
    ret = run_shell_command("tar -zxf " ONLINE_ARCHIVE_PATH
                            " -C " ONLINE_EXTRACT_DIR " >/dev/null 2>&1", 60);
    if (ret != 0) {
        LOG_WARN("feature online extract tar.gz failed, ret=%d", ret);
        return -1;
    }
    if (lstat(feature_source, &st) != 0) {
        LOG_WARN("feature online extracted feature file missing: %s errno=%d",
                 feature_source, errno);
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (size_t)st.st_size > FWX_FEATURE_MAX_SIZE + 24U) {
        LOG_WARN("feature online invalid candidate file, mode=%o size=%lld",
                 st.st_mode, (long long)st.st_size);
        return -1;
    }
    LOG_INFO("feature online candidate extracted, member=%s size=%lld",
             "feature.bin", (long long)st.st_size);
    unlink(ONLINE_FEATURE_TEMP);
    if (rename(feature_source, ONLINE_FEATURE_TEMP) != 0) {
        LOG_ERROR("feature online move extracted feature failed, errno=%d", errno);
        return -1;
    }
    if (chmod(ONLINE_FEATURE_TEMP, 0644) != 0 ||
        rename(ONLINE_FEATURE_TEMP, FWX_FEATURE_CANDIDATE_PATH) != 0) {
        LOG_ERROR("feature online stage candidate failed, errno=%d", errno);
        return -1;
    }
    if (stat(ONLINE_ICON_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (validate_icon_tree(ONLINE_ICON_DIR, 0) < 0 ||
            directory_size(ONLINE_ICON_DIR) > 50U * 1024U * 1024U) {
            LOG_WARN("feature online icon tree validation failed");
            return -1;
        }
        LOG_INFO("feature online icon tree validated, listed_icons=%d", icon_count);
    }
    LOG_INFO("feature online candidate ready: %s", FWX_FEATURE_CANDIDATE_PATH);
    return 0;
}

static unsigned long long directory_size(const char *path)
{
    struct stat st;
    struct dirent *entry;
    DIR *dir;
    char child[512];
    unsigned long long total = 0;

    dir = opendir(path);
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (lstat(child, &st) != 0)
            continue;
        if (S_ISREG(st.st_mode))
            total += (unsigned long long)st.st_size;
        else if (S_ISDIR(st.st_mode))
            total += directory_size(child);
    }
    closedir(dir);
    return total;
}

static int install_icons(void)
{
    struct stat st;
    struct statvfs space;
    unsigned long long required;
    unsigned long long available;

    if (stat(ONLINE_ICON_DIR, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    required = directory_size(ONLINE_ICON_DIR);
    if (statvfs("/overlay", &space) != 0)
        return 1;
    available = (unsigned long long)space.f_bavail * space.f_frsize;
    if (required > available)
        return 1;
    if (run_shell_command("mkdir -p " ONLINE_ICON_TARGET " && rm -rf " ONLINE_ICON_TARGET
                          "/* && cp -r " ONLINE_ICON_DIR "/. " ONLINE_ICON_TARGET "/", 60) != 0)
        return 1;
    if (directory_size(ONLINE_ICON_TARGET) < required)
        return 1;
    return 0;
}

static int read_small_file(const char *path, char *buffer, size_t buffer_len)
{
    FILE *fp;
    size_t len;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    len = fread(buffer, 1, buffer_len - 1, fp);
    fclose(fp);
    buffer[len] = '\0';
    return 0;
}

static int write_json_file_atomic(const char *path, struct json_object *obj)
{
    char temporary[256];
    const char *text;
    FILE *fp = NULL;
    int ret = -1;

    if (!path || !obj ||
        snprintf(temporary, sizeof(temporary), "%s.tmp", path) >= (int)sizeof(temporary))
        return -1;
    mkdir("/etc/fwxd", 0755);
    text = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    fp = fopen(temporary, "w");
    if (!fp || fwrite(text, 1, strlen(text), fp) != strlen(text) ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        goto out;
    if (fclose(fp) != 0) {
        fp = NULL;
        goto out;
    }
    fp = NULL;
    if (chmod(temporary, 0644) != 0 || rename(temporary, path) != 0)
        goto out;
    ret = 0;
out:
    if (fp)
        fclose(fp);
    if (ret != 0)
        unlink(temporary);
    return ret;
}

static int backup_download_archive(const char *reason)
{
    const char *temporary = ONLINE_FAILED_ARCHIVE_PATH ".tmp";
    FILE *in = NULL;
    FILE *out = NULL;
    char buffer[4096];
    size_t len;
    int ret = -1;

    in = fopen(ONLINE_ARCHIVE_PATH, "rb");
    if (!in)
        goto out;
    out = fopen(temporary, "wb");
    if (!out)
        goto out;
    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, len, out) != len)
            goto out;
    }
    if (ferror(in) || fflush(out) != 0 || fsync(fileno(out)) != 0)
        goto out;
    if (fclose(out) != 0) {
        out = NULL;
        goto out;
    }
    out = NULL;
    if (chmod(temporary, 0644) != 0 || rename(temporary, ONLINE_FAILED_ARCHIVE_PATH) != 0)
        goto out;
    ret = 0;
out:
    if (out)
        fclose(out);
    if (in)
        fclose(in);
    if (ret != 0)
        unlink(temporary);
    LOG_WARN("feature online backup downloaded package: reason=%s path=%s ret=%d",
             reason ? reason : "", ONLINE_FAILED_ARCHIVE_PATH, ret);
    return ret;
}

static void worker_failed(int code, const char *message)
{
    LOG_WARN("feature online update failed: code=%d message=%s", code,
             message ? message : "");
    set_status("failed", "idle", code, message, 0);
    pthread_mutex_lock(&online_mutex);
    online_worker_running = 0;
    pthread_mutex_unlock(&online_mutex);
    release_upgrade_lock();
}

static void *online_update_worker(void *arg)
{
    online_worker_t *worker = arg;
    file_buffer_t output = {0};
    progress_ctx_t progress = {0};
    char url[2048];
    char error_body[4096] = {0};
    char error_message[160] = {0};
    long http_code = 0;
    CURLcode curl_ret;
    CURL *curl;
    int error_code;
    int icon_count = 0;
    char event = '1';

    LOG_INFO("feature online update worker start: id=%s lang=%s model=%s device_id=%s timeout=%d",
             worker->id, worker->lang, worker->model, worker->device_id, ONLINE_UPDATE_TIMEOUT);
    set_status("running", "downloading", 0, "", 0);
    cleanup_work_files();
    if (mkdir(ONLINE_WORK_DIR, 0700) != 0) {
        LOG_ERROR("feature online create work dir failed, errno=%d", errno);
        worker_failed(400, "failed to prepare download directory");
        free_worker(worker);
        return NULL;
    }
    output.fp = fopen(ONLINE_ARCHIVE_PATH, "wb");
    output.limit = ONLINE_ARCHIVE_MAX;
    curl = curl_easy_init();
    if (!output.fp || !curl || build_url(curl, "/api/download_feature",
                                         worker->token, worker->device_id, worker->model,
                                         worker->lang, NULL, NULL, worker->id,
                                         url, sizeof(url)) < 0) {
        if (output.fp)
            fclose(output.fp);
        if (curl)
            curl_easy_cleanup(curl);
        worker_failed(400, "failed to initialize download");
        free_worker(worker);
        return NULL;
    }
    set_curl_options(curl, url);
    LOG_INFO("feature online download request prepared: id=%s", worker->id);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)ONLINE_DOWNLOAD_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, download_progress_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progress);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, file_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
    LOG_INFO("feature online download start: id=%s timeout=%d low_speed=1024B/s low_speed_time=30",
             worker->id, ONLINE_DOWNLOAD_TIMEOUT);
    curl_ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    fclose(output.fp);
    curl_easy_cleanup(curl);
    LOG_INFO("feature online download complete: id=%s curl=%d http=%ld size=%zu too_large=%d",
             worker->id, curl_ret, http_code, output.size, output.too_large);
    if (output.too_large) {
        backup_download_archive("file too large");
        worker_failed(402, "downloaded file is too large");
        free_worker(worker);
        return NULL;
    }
    if (curl_ret != CURLE_OK || http_code != 200 || output.size == 0) {
        if (output.size > 0)
            backup_download_archive("download failed");
        read_small_file(ONLINE_ARCHIVE_PATH, error_body, sizeof(error_body));
        parse_remote_error(error_body, http_code, &error_code, error_message, sizeof(error_message));
        LOG_WARN("feature online download failed: curl=%d(%s) http=%ld size=%zu remote_code=%d message=%s",
                 curl_ret, curl_easy_strerror(curl_ret), http_code, output.size,
                 error_code, error_message);
        worker_failed(error_code, error_message);
        free_worker(worker);
        return NULL;
    }
    if (read_small_file(ONLINE_ARCHIVE_PATH, error_body, sizeof(error_body)) == 0 &&
        parse_remote_json_error(error_body, &error_code, error_message,
                                sizeof(error_message)) == 0) {
        backup_download_archive("download remote error");
        LOG_WARN("feature online download got remote json error: code=%d message=%s",
                 error_code, error_message);
        worker_failed(error_code, error_message);
        free_worker(worker);
        return NULL;
    }
    if (worker->expected_md5[0]) {
        char actual_md5[33] = {0};
        if (file_md5_hex(ONLINE_ARCHIVE_PATH, actual_md5) < 0 ||
            strcmp(actual_md5, worker->expected_md5) != 0) {
            backup_download_archive("md5 mismatch");
            LOG_WARN("feature online md5 mismatch: id=%s expected=%s actual=%s",
                     worker->id, worker->expected_md5,
                     actual_md5[0] ? actual_md5 : "calc_failed");
            worker_failed(403, "feature library checksum verification failed");
            free_worker(worker);
            return NULL;
        }
        LOG_INFO("feature online md5 verified: id=%s md5=%s", worker->id, actual_md5);
    }
    set_status("running", "extracting", 0, "", 0);
    LOG_INFO("feature online archive validation start: id=%s path=%s size=%zu",
             worker->id, ONLINE_ARCHIVE_PATH, output.size);
    if (validate_archive(&icon_count) < 0) {
        backup_download_archive("archive validation failed");
        read_small_file(ONLINE_ARCHIVE_PATH, error_body, sizeof(error_body));
        parse_remote_error(error_body, http_code, &error_code, error_message, sizeof(error_message));
        unlink(FWX_FEATURE_CANDIDATE_PATH);
        if (error_code != 400) {
            LOG_WARN("feature online archive validation got remote error: code=%d message=%s",
                     error_code, error_message);
            worker_failed(error_code, error_message);
        } else {
            worker_failed(401, "invalid feature library package");
        }
        free_worker(worker);
        return NULL;
    }
    LOG_INFO("feature online archive extract start: id=%s icons=%d", worker->id, icon_count);
    if (prepare_archive_candidate(icon_count) < 0) {
        backup_download_archive("archive extract failed");
        unlink(FWX_FEATURE_CANDIDATE_PATH);
        worker_failed(401, "invalid feature library package");
        free_worker(worker);
        return NULL;
    }
    LOG_INFO("feature online notify main loop: id=%s", worker->id);
    if (write(online_pipe[1], &event, 1) != 1) {
        LOG_ERROR("feature online pipe notify failed: id=%s errno=%d", worker->id, errno);
        unlink(FWX_FEATURE_CANDIDATE_PATH);
        worker_failed(400, "failed to notify feature update");
    }
    LOG_INFO("feature online worker finished download/extract stage: id=%s", worker->id);
    free_worker(worker);
    return NULL;
}

static void candidate_stage_changed(const char *stage)
{
    set_status("running", stage, 0, "", 0);
}

static void online_pipe_handler(struct uloop_fd *fd, unsigned int events)
{
    char buffer[16];
    char version[64] = {0};
    char format[32] = {0};
    int status_code = 400;
    int icons_skipped = 0;

    (void)events;
    LOG_INFO("feature online pipe handler start");
    while (read(fd->fd, buffer, sizeof(buffer)) > 0)
        ;
    set_status("running", "validating", 0, "", 0);
    LOG_INFO("feature online candidate process start: path=%s", FWX_FEATURE_CANDIDATE_PATH);
    if (fwx_feature_process_candidate(version, sizeof(version), format, sizeof(format),
                                      &status_code, candidate_stage_changed) < 0) {
        backup_download_archive("candidate validation failed");
        LOG_WARN("feature online candidate validation failed: status=%d version=%s format=%s",
                 status_code, version, format);
        worker_failed(status_code, status_code == 401 ?
                      "feature library format error" : "failed to apply feature library");
        return;
    }
    g_feature_update = 1;
    LOG_INFO("feature online install icons start");
    icons_skipped = install_icons();
    LOG_INFO("feature online candidate applied: version=%s format=%s icons_skipped=%d",
             version, format, icons_skipped);
    set_status("success", "idle", 200, "feature library updated", icons_skipped);
    pthread_mutex_lock(&online_mutex);
    online_worker_running = 0;
    pthread_mutex_unlock(&online_mutex);
    release_upgrade_lock();
}

struct json_object *fwx_api_get_feature_online_config(struct json_object *req_obj)
{
    struct json_object *data = json_object_new_object();
    char token[ONLINE_TOKEN_MAX + 1] = {0};
    char device_id[33] = {0};
    char model[129] = {0};

    (void)req_obj;
    get_saved_token(token, sizeof(token));
    if (get_device_id(device_id, sizeof(device_id)) < 0 ||
        get_device_model(model, sizeof(model)) < 0) {
        json_object_put(data);
        return error_response(400, "failed to read device information");
    }
    json_object_object_add(data, "token", json_object_new_string(token));
    json_object_object_add(data, "device_id", json_object_new_string(device_id));
    json_object_object_add(data, "model", json_object_new_string(model));
    json_object_object_add(data, "version", json_object_new_string(ONLINE_VERSION));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *fwx_api_set_feature_online_config(struct json_object *req_obj)
{
    struct json_object *token_obj;
    struct uci_context *ctx;
    const char *token;

    if (!req_obj || !json_object_object_get_ex(req_obj, "token", &token_obj) ||
        !json_object_is_type(token_obj, json_type_string))
        return error_response(400, "token is required");
    token = json_object_get_string(token_obj);
    if (!token_valid(token))
        return error_response(400, "failed to save token");
    ctx = uci_alloc_context();
    if (!ctx)
        return error_response(400, "failed to save token");
    if (fwx_uci_set_value(ctx, "fwx.global.feature_token", (char *)token) != 0 ||
        fwx_uci_commit(ctx, "fwx") != 0) {
        uci_free_context(ctx);
        return error_response(400, "failed to save token");
    }
    uci_free_context(ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

static struct json_object *normalize_feature_online_list(struct json_object *files_obj,
                                                         const char *request_lang,
                                                         const char *announcement)
{
    struct json_object *result_data;
    struct json_object *result_files;
    int i;

    if (!files_obj || !json_object_is_type(files_obj, json_type_array))
        return NULL;
    result_data = json_object_new_object();
    result_files = json_object_new_array();
    if (!result_data || !result_files) {
        if (result_files)
            json_object_put(result_files);
        if (result_data)
            json_object_put(result_data);
        return NULL;
    }
    for (i = 0; i < json_object_array_length(files_obj) && i < ONLINE_FILE_MAX; i++) {
        struct json_object *item = json_object_array_get_idx(files_obj, i);
        struct json_object *id_obj, *version_obj, *type_obj = NULL;
        struct json_object *lang_obj = NULL, *count_obj = NULL;
        struct json_object *free_obj = NULL;
        struct json_object *md5_obj = NULL;
        struct json_object *desc_obj = NULL, *date_obj = NULL;
        const char *id;
        const char *version;
        const char *item_lang = request_lang;
        const char *description = "";
        const char *date = "";
        const char *md5 = "";
        int feature_type = 0;
        int feature_count = 0;
        int is_free = 0;
        struct json_object *normalized;

        if (!item || !json_object_object_get_ex(item, "id", &id_obj) ||
            !json_object_object_get_ex(item, "version", &version_obj))
            continue;
        id = json_object_get_string(id_obj);
        version = json_object_get_string(version_obj);
        if (!id_valid(id) || !version || !version[0] || strlen(version) > 64)
            continue;
        if (json_object_object_get_ex(item, "type", &type_obj)) {
            feature_type = json_object_get_int(type_obj);
            if (feature_type != 0 && feature_type != 1)
                feature_type = 0;
        }
        if (json_object_object_get_ex(item, "lang", &lang_obj) &&
            json_object_is_type(lang_obj, json_type_string) &&
            lang_valid(json_object_get_string(lang_obj)))
            item_lang = json_object_get_string(lang_obj);
        if (json_object_object_get_ex(item, "count", &count_obj)) {
            feature_count = json_object_get_int(count_obj);
            if (feature_count < 0)
                feature_count = 0;
        }
        if (json_object_object_get_ex(item, "free", &free_obj))
            is_free = json_object_get_int(free_obj) ? 1 : 0;
        if (!json_object_object_get_ex(item, "desc", &desc_obj))
            json_object_object_get_ex(item, "description", &desc_obj);
        json_object_object_get_ex(item, "date", &date_obj);
        if (desc_obj && json_object_is_type(desc_obj, json_type_string) &&
            strlen(json_object_get_string(desc_obj)) <= 256)
            description = json_object_get_string(desc_obj);
        if (date_obj && json_object_is_type(date_obj, json_type_string) &&
            strlen(json_object_get_string(date_obj)) <= 32)
            date = json_object_get_string(date_obj);
        if (json_object_object_get_ex(item, "md5", &md5_obj) &&
            json_object_is_type(md5_obj, json_type_string) &&
            md5_text_valid(json_object_get_string(md5_obj)))
            md5 = json_object_get_string(md5_obj);
        normalized = json_object_new_object();
        json_object_object_add(normalized, "id", json_object_new_string(id));
        json_object_object_add(normalized, "version", json_object_new_string(version));
        json_object_object_add(normalized, "type", json_object_new_int(feature_type));
        json_object_object_add(normalized, "free", json_object_new_int(is_free));
        json_object_object_add(normalized, "lang", json_object_new_string(item_lang));
        json_object_object_add(normalized, "md5", json_object_new_string(md5));
        json_object_object_add(normalized, "count", json_object_new_int(feature_count));
        json_object_object_add(normalized, "desc", json_object_new_string(description));
        json_object_object_add(normalized, "date", json_object_new_string(date));
        json_object_array_add(result_files, normalized);
    }
    json_object_object_add(result_data, "version", json_object_new_string(ONLINE_VERSION));
    json_object_object_add(result_data, "announcement",
                           json_object_new_string(announcement ? announcement : ""));
    json_object_object_add(result_data, "count",
                           json_object_new_int(json_object_array_length(result_files)));
    json_object_object_add(result_data, "files", result_files);
    return result_data;
}

static struct json_object *new_empty_feature_online_list(void)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "version", json_object_new_string(ONLINE_VERSION));
    json_object_object_add(data, "announcement", json_object_new_string(""));
    json_object_object_add(data, "count", json_object_new_int(0));
    json_object_object_add(data, "files", json_object_new_array());
    return data;
}

static struct json_object *read_feature_online_list_cache(void)
{
    struct json_object *root;
    struct json_object *files_obj;

    root = json_object_from_file(FWX_FEATURE_LIST_CACHE_PATH);
    if (!root)
        return NULL;
    if (!json_object_object_get_ex(root, "files", &files_obj) ||
        !json_object_is_type(files_obj, json_type_array)) {
        json_object_put(root);
        return NULL;
    }
    return root;
}

struct json_object *fwx_api_get_feature_online_list(struct json_object *req_obj)
{
    memory_buffer_t response = {.limit = ONLINE_RESPONSE_MAX};
    struct json_object *root = NULL;
    struct json_object *code_obj;
    struct json_object *data_obj;
    struct json_object *files_obj;
    struct json_object *announcement_obj = NULL;
    struct json_object *result_data;
    struct json_object *request_lang_obj;
    struct json_object *device_lang_obj;
    struct json_object *refresh_obj;
    char token[ONLINE_TOKEN_MAX + 1], device_id[33], model[129], url[2048], message[160];
    char hostname[ONLINE_HOSTNAME_MAX + 1] = {0};
    char device_lang[ONLINE_DEVICE_LANG_MAX + 1] = {0};
    const char *request_lang = "cn";
    long http_code = 0;
    int remote_code = 400;
    int refresh = 0;
    CURLcode curl_ret;
    CURL *curl;
    if (req_obj && json_object_object_get_ex(req_obj, "lang", &request_lang_obj) &&
        json_object_is_type(request_lang_obj, json_type_string) &&
        lang_valid(json_object_get_string(request_lang_obj)))
        request_lang = json_object_get_string(request_lang_obj);
    if (req_obj && json_object_object_get_ex(req_obj, "device_lang", &device_lang_obj) &&
        json_object_is_type(device_lang_obj, json_type_string) &&
        query_text_valid(json_object_get_string(device_lang_obj), ONLINE_DEVICE_LANG_MAX))
        snprintf(device_lang, sizeof(device_lang), "%s",
                 json_object_get_string(device_lang_obj));
    if (req_obj && json_object_object_get_ex(req_obj, "refresh", &refresh_obj))
        refresh = json_object_get_int(refresh_obj) ? 1 : 0;
    if (!refresh) {
        result_data = read_feature_online_list_cache();
        if (result_data)
            return fwx_gen_api_response_data(API_CODE_SUCCESS, result_data);
        return fwx_gen_api_response_data(API_CODE_SUCCESS, new_empty_feature_online_list());
    }
    if (get_request_credentials(token, sizeof(token), device_id, sizeof(device_id),
                                model, sizeof(model)) < 0)
        return error_response(400, "token or device information is invalid");
    get_system_hostname(hostname, sizeof(hostname));
    curl = curl_easy_init();
    if (!curl || build_url(curl, "/api/get_feature_list", token, device_id,
                           model, request_lang, hostname, device_lang, NULL,
                           url, sizeof(url)) < 0) {
        if (curl)
            curl_easy_cleanup(curl);
        return error_response(400, "failed to initialize subscription request");
    }
    LOG_INFO("feature online list request prepared: lang=%s device_lang=%s hostname=%s",
             request_lang, device_lang, hostname);
    set_curl_options(curl, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L); // 2min
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, memory_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    LOG_INFO("feature online list response: curl=%d http=%ld size=%zu",
             curl_ret, http_code, response.size);
    if (curl_ret != CURLE_OK || !response.data) {
        free(response.data);
        return error_response(400, "failed to request subscription server");
    }
    root = json_tokener_parse(response.data);
    if (http_code != 200 || !root || !json_object_object_get_ex(root, "code", &code_obj) ||
        json_object_get_int(code_obj) != 20000 ||
        !json_object_object_get_ex(root, "data", &data_obj) ||
        !json_object_object_get_ex(data_obj, "files", &files_obj) ||
        !json_object_is_type(files_obj, json_type_array)) {
        parse_remote_error(response.data, http_code, &remote_code, message, sizeof(message));
        if (root)
            json_object_put(root);
        free(response.data);
        return error_response(remote_code, message);
    }
    json_object_object_get_ex(data_obj, "announcement", &announcement_obj);
    if (!announcement_obj)
        json_object_object_get_ex(data_obj, "Announcement", &announcement_obj);
    if (!announcement_obj)
        json_object_object_get_ex(root, "announcement", &announcement_obj);
    if (!announcement_obj)
        json_object_object_get_ex(root, "Announcement", &announcement_obj);
    result_data = normalize_feature_online_list(
        files_obj, request_lang,
        announcement_obj && json_object_is_type(announcement_obj, json_type_string) &&
        strlen(json_object_get_string(announcement_obj)) <= 1024 ?
        json_object_get_string(announcement_obj) : "");
    if (!result_data) {
        json_object_put(root);
        free(response.data);
        return error_response(400, "invalid subscription file list");
    }
    if (json_object_array_length(files_obj) > 0) {
        struct json_object *result_files = NULL;
        if (!json_object_object_get_ex(result_data, "files", &result_files) ||
            json_object_array_length(result_files) == 0) {
            json_object_put(result_data);
            json_object_put(root);
            free(response.data);
            return error_response(400, "invalid subscription file list");
        }
    }
    if (write_json_file_atomic(FWX_FEATURE_LIST_CACHE_PATH, result_data) != 0)
        LOG_WARN("feature online list cache write failed: %s", FWX_FEATURE_LIST_CACHE_PATH);
    json_object_put(root);
    free(response.data);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, result_data);
}

struct json_object *fwx_api_start_feature_online_update(struct json_object *req_obj)
{
    struct json_object *id_obj;
    struct json_object *lang_obj;
    struct json_object *md5_obj;
    online_worker_t *worker;
    pthread_attr_t attr;
    pthread_t thread;
    const char *id;
    const char *lang = "cn";
    const char *md5 = "";
    int ret;

    if (!online_ready)
        return error_response(400, "online update service is unavailable");
    if (!req_obj || !json_object_object_get_ex(req_obj, "id", &id_obj))
        return error_response(400, "file id is required");
    id = json_object_get_string(id_obj);
    if (!id_valid(id))
        return error_response(400, "invalid file id");
    if (json_object_object_get_ex(req_obj, "lang", &lang_obj) &&
        json_object_is_type(lang_obj, json_type_string) &&
        lang_valid(json_object_get_string(lang_obj)))
        lang = json_object_get_string(lang_obj);
    if (json_object_object_get_ex(req_obj, "md5", &md5_obj) &&
        json_object_is_type(md5_obj, json_type_string)) {
        md5 = json_object_get_string(md5_obj);
        if (md5[0] && !md5_text_valid(md5))
            return error_response(400, "invalid feature library md5");
    }
    LOG_INFO("feature online start request: id=%s lang=%s md5=%s", id, lang,
             md5[0] ? "set" : "empty");
    pthread_mutex_lock(&online_mutex);
    if (online_worker_running) {
        pthread_mutex_unlock(&online_mutex);
        return error_response(400, "feature update is already running");
    }
    pthread_mutex_unlock(&online_mutex);
    if (acquire_upgrade_lock() < 0)
        return error_response(400, "another feature update is running");
    worker = calloc(1, sizeof(*worker));
    if (!worker) {
        release_upgrade_lock();
        return error_response(400, "failed to start feature update");
    }
    snprintf(worker->id, sizeof(worker->id), "%s", id);
    snprintf(worker->lang, sizeof(worker->lang), "%s", lang);
    if (md5[0])
        copy_md5_lower(worker->expected_md5, md5);
    ret = get_request_credentials(worker->token, sizeof(worker->token),
                                  worker->device_id, sizeof(worker->device_id),
                                  worker->model, sizeof(worker->model));
    if (ret < 0) {
        free_worker(worker);
        release_upgrade_lock();
        return error_response(400, "token or device information is invalid");
    }
    pthread_mutex_lock(&online_mutex);
    online_worker_running = 1;
    snprintf(online_status.id, sizeof(online_status.id), "%s", id);
    pthread_mutex_unlock(&online_mutex);
    set_status("running", "downloading", 0, "", 0);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&thread, &attr, online_update_worker, worker);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        free_worker(worker);
        pthread_mutex_lock(&online_mutex);
        online_worker_running = 0;
        pthread_mutex_unlock(&online_mutex);
        release_upgrade_lock();
        return error_response(400, "failed to start feature update");
    }
    return fwx_gen_api_response_data(API_CODE_SUCCESS, status_data());
}

struct json_object *fwx_api_get_feature_online_update_status(struct json_object *req_obj)
{
    (void)req_obj;
    return fwx_gen_api_response_data(API_CODE_SUCCESS, status_data());
}

int fwx_feature_online_init(void)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return -1;
    if (pipe(online_pipe) != 0) {
        curl_global_cleanup();
        return -1;
    }
    fcntl(online_pipe[0], F_SETFL, fcntl(online_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(online_pipe[1], F_SETFL, fcntl(online_pipe[1], F_GETFL) | O_NONBLOCK);
    online_uloop_fd.fd = online_pipe[0];
    online_uloop_fd.cb = online_pipe_handler;
    if (uloop_fd_add(&online_uloop_fd, ULOOP_READ) != 0) {
        close(online_pipe[0]);
        close(online_pipe[1]);
        online_pipe[0] = online_pipe[1] = -1;
        curl_global_cleanup();
        return -1;
    }
    set_status("idle", "idle", 0, "", 0);
    online_ready = 1;
    return 0;
}

void fwx_feature_online_cleanup(void)
{
    int running;

    if (!online_ready)
        return;
    pthread_mutex_lock(&online_mutex);
    running = online_worker_running;
    pthread_mutex_unlock(&online_mutex);
    if (running)
        return;
    online_ready = 0;
    if (online_pipe[0] >= 0) {
        uloop_fd_delete(&online_uloop_fd);
        close(online_pipe[0]);
        close(online_pipe[1]);
        online_pipe[0] = online_pipe[1] = -1;
    }
    curl_global_cleanup();
}
