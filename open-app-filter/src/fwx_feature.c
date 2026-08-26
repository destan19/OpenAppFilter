// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fwx_feature.h"

#define FEATURE_HEADER_SIZE 24U
#define FEATURE_FORMAT_VERSION 1U
#define FEATURE_ALGORITHM_XTEA_CTR 1U

static const unsigned char feature_magic[4] = {'F', 'W', 'X', 'B'};
static const uint32_t feature_key[4] = {
    0x8f4c29a1U, 0x73b6d502U, 0xc14e87f3U, 0x2ad95b60U
};
static char *g_feature_data;
static size_t g_feature_data_len;

static void clear_memory(void *data, size_t len)
{
    volatile unsigned char *p = data;

    while (p && len-- > 0)
        *p++ = 0;
}

static uint16_t get_le16(const unsigned char *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t get_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_le64(const unsigned char *p)
{
    return (uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32);
}

static void put_le16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
}

static void put_le32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void put_le64(unsigned char *p, uint64_t value)
{
    put_le32(p, (uint32_t)value);
    put_le32(p + 4, (uint32_t)(value >> 32));
}

static uint32_t feature_crc32(const unsigned char *data, size_t len)
{
    uint32_t crc = 0xffffffffU;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

static void xtea_encrypt_block(uint32_t block[2])
{
    uint32_t v0 = block[0];
    uint32_t v1 = block[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9e3779b9U;
    int round;

    for (round = 0; round < 32; round++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^
              (sum + feature_key[sum & 3U]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^
              (sum + feature_key[(sum >> 11) & 3U]);
    }
    block[0] = v0;
    block[1] = v1;
}

static void xtea_ctr_crypt(unsigned char *data, size_t len, uint64_t nonce)
{
    size_t offset = 0;
    uint64_t counter = nonce;

    while (offset < len) {
        unsigned char stream[8];
        uint32_t block[2];
        size_t i;

        block[0] = (uint32_t)counter;
        block[1] = (uint32_t)(counter >> 32);
        xtea_encrypt_block(block);
        put_le32(stream, block[0]);
        put_le32(stream + 4, block[1]);
        for (i = 0; i < sizeof(stream) && offset < len; i++, offset++)
            data[offset] ^= stream[i];
        counter++;
    }
}

static int read_file(const char *path, size_t max_len, unsigned char **data, size_t *len)
{
    FILE *fp;
    long file_len;
    unsigned char *buf;

    if (!path || !data || !len)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0 || (file_len = ftell(fp)) <= 0 ||
        (size_t)file_len > max_len || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    buf = malloc((size_t)file_len);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)file_len, fp) != (size_t)file_len) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *data = buf;
    *len = (size_t)file_len;
    return 0;
}

static int read_nonce(uint64_t *nonce)
{
    FILE *fp;
    unsigned char buf[8];

    fp = fopen("/dev/urandom", "rb");
    if (!fp)
        return -1;
    if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *nonce = get_le64(buf);
    return 0;
}


int fwx_feature_decrypt_file(const char *path, char **data, size_t *data_len)
{
    unsigned char *file_data = NULL;
    char *plain = NULL;
    size_t file_len = 0;
    uint32_t plain_len = 0;
    uint32_t expected_crc;
    uint64_t nonce;
    int ret = -1;

    if (!data || !data_len)
        return -1;
    *data = NULL;
    *data_len = 0;
    if (read_file(path, FEATURE_HEADER_SIZE + FWX_FEATURE_MAX_SIZE, &file_data, &file_len) != 0)
        return -1;
    if (file_len < FEATURE_HEADER_SIZE || memcmp(file_data, feature_magic, sizeof(feature_magic)) != 0 ||
        file_data[4] != FEATURE_FORMAT_VERSION || file_data[5] != FEATURE_ALGORITHM_XTEA_CTR ||
        get_le16(file_data + 6) != FEATURE_HEADER_SIZE)
        goto out;
    plain_len = get_le32(file_data + 8);
    expected_crc = get_le32(file_data + 12);
    nonce = get_le64(file_data + 16);
    if (plain_len == 0 || plain_len > FWX_FEATURE_MAX_SIZE ||
        file_len != FEATURE_HEADER_SIZE + (size_t)plain_len)
        goto out;
    plain = malloc((size_t)plain_len + 1U);
    if (!plain)
        goto out;
    memcpy(plain, file_data + FEATURE_HEADER_SIZE, plain_len);
    xtea_ctr_crypt((unsigned char *)plain, plain_len, nonce);
    plain[plain_len] = '\0';
    if (feature_crc32((const unsigned char *)plain, plain_len) != expected_crc)
        goto out;
    *data = plain;
    *data_len = plain_len;
    plain = NULL;
    ret = 0;
out:
    clear_memory(plain, plain_len);
    free(plain);
    free(file_data);
    return ret;
}

static int copy_file_atomic(const char *source, const char *target,
                            const char *temporary)
{
    unsigned char *data = NULL;
    size_t data_len = 0;
    FILE *fp = NULL;
    int ret = -1;

    if (read_file(source,
                  FEATURE_HEADER_SIZE + FWX_FEATURE_MAX_SIZE,
                  &data, &data_len) != 0)
        return -1;
    fp = fopen(temporary, "wb");
    if (!fp || fwrite(data, 1, data_len, fp) != data_len ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        goto out;
    if (fclose(fp) != 0) {
        fp = NULL;
        goto out;
    }
    fp = NULL;
    if (chmod(temporary, 0644) != 0 ||
        rename(temporary, target) != 0)
        goto out;
    ret = 0;
out:
    if (fp)
        fclose(fp);
    if (ret != 0)
        unlink(temporary);
    free(data);
    return ret;
}

int fwx_feature_validate_candidate(char *version, size_t version_len,
                                   char *format, size_t format_len)
{
    char *feature_data = NULL;
    size_t feature_len = 0;
    size_t offset = 0;
    char line[1024];
    char parsed_version[64] = {0};
    char parsed_format[32] = {0};
    int line_ret;
    int ret = -1;

    if (!version || version_len == 0 || !format || format_len == 0)
        return -1;
    version[0] = '\0';
    format[0] = '\0';
    if (fwx_feature_decrypt_file(FWX_FEATURE_CANDIDATE_PATH,
                                 &feature_data, &feature_len) < 0)
        return FWX_FEATURE_VALIDATE_DECRYPT_FAILED;
    while ((line_ret = fwx_feature_next_line(feature_data, feature_len,
                                             &offset, line, sizeof(line))) != 0) {
        if (line_ret < 0)
            continue;
        if (!strncmp(line, "#version ", 9))
            sscanf(line, "#version %63s", parsed_version);
        else if (!strncmp(line, "#format ", 8))
            sscanf(line, "#format %31s", parsed_format);
        if (parsed_version[0] && parsed_format[0])
            break;
    }
    snprintf(version, version_len, "%s", parsed_version);
    snprintf(format, format_len, "%s", parsed_format);
    if (parsed_version[0] && !strcmp(parsed_format, FWX_FEATURE_DATA_FORMAT))
        ret = 0;
    else
        ret = FWX_FEATURE_VALIDATE_INFO_INVALID;
    clear_memory(feature_data, feature_len);
    free(feature_data);
    return ret;
}

int fwx_feature_apply_candidate(void)
{
    const char *backup_temporary = FWX_FEATURE_BACKUP_PATH ".tmp";
    const char *target_temporary = FWX_FEATURE_BIN_PATH ".tmp";

    if (access(FWX_FEATURE_BIN_PATH, F_OK) == 0 &&
        copy_file_atomic(FWX_FEATURE_BIN_PATH, FWX_FEATURE_BACKUP_PATH,
                         backup_temporary) < 0)
        return FWX_FEATURE_APPLY_BACKUP_FAILED;
    if (copy_file_atomic(FWX_FEATURE_CANDIDATE_PATH, FWX_FEATURE_BIN_PATH,
                         target_temporary) < 0)
        return FWX_FEATURE_APPLY_TARGET_FAILED;
    unlink(FWX_FEATURE_CANDIDATE_PATH);
    return 0;
}

int fwx_feature_process_candidate(char *version, size_t version_len,
                                  char *format, size_t format_len,
                                  int *status_code,
                                  void (*stage_callback)(const char *stage))
{
    int ret;

    if (status_code)
        *status_code = 400;
    ret = fwx_feature_validate_candidate(version, version_len, format, format_len);
    if (ret < 0) {
        if (status_code)
            *status_code = 401;
        unlink(FWX_FEATURE_CANDIDATE_PATH);
        return ret;
    }
    if (stage_callback)
        stage_callback("applying");
    ret = fwx_feature_apply_candidate();
    if (ret < 0) {
        unlink(FWX_FEATURE_CANDIDATE_PATH);
        return ret;
    }
    if (status_code)
        *status_code = 200;
    return 0;
}

int fwx_feature_restore_backup(void)
{
    return copy_file_atomic(FWX_FEATURE_BACKUP_PATH, FWX_FEATURE_BIN_PATH,
                            FWX_FEATURE_BIN_PATH ".restore");
}


void fwx_feature_replace_data(char *data, size_t data_len)
{
    clear_memory(g_feature_data, g_feature_data_len);
    free(g_feature_data);
    g_feature_data = data;
    g_feature_data_len = data_len;
}

const char *fwx_feature_get_data(size_t *data_len)
{
    if (data_len)
        *data_len = g_feature_data_len;
    return g_feature_data;
}

int fwx_feature_next_line(const char *data, size_t data_len, size_t *offset,
                          char *line, size_t line_size)
{
    size_t start;
    size_t end;
    size_t line_len;

    if (!data || !offset || !line || line_size == 0 || *offset >= data_len)
        return 0;
    start = *offset;
    end = start;
    while (end < data_len && data[end] != '\n')
        end++;
    *offset = end < data_len ? end + 1U : end;
    line_len = end - start;
    if (line_len > 0 && data[start + line_len - 1U] == '\r')
        line_len--;
    if (line_len >= line_size) {
        line[0] = '\0';
        return -1;
    }
    memcpy(line, data + start, line_len);
    line[line_len] = '\0';
    return 1;
}
