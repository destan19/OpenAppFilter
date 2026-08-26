
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "fwx_utils.h"

char *str_trim(char *s) {
    char *start, *last, *bk;
    int len;

    start = s;
    while (isspace(*start))
        start++;

    bk = last = s + strlen(s) - 1;
    while (last > start && isspace(*last))
        last--;

    if ((s != start) || (bk != last)) {
        len = last - start + 1;
        strncpy(s, start, len);
        s[len] = '\0';
    }   
    return s;
}

int exec_with_result_line(char *cmd, char *result, int len)
{
    FILE *fp = NULL;
	if (!cmd || !result || !len)
		return -1;
    fp = popen(cmd, "r");
    if (!fp) 
        return -1;
    fgets(result, len, fp);   
    str_trim(result);
    pclose(fp);
	return 0;
}

int fwx_send_msg_to_kernel(char *buf){

    if (access("/dev/fwx", F_OK) != 0) {
        return 0; // Device doesn't exist, silently skip
    }
    
    FILE *fp = fopen("/dev/fwx", "w");
    if (fp) {
        fprintf(fp, "%s", buf);
        fclose(fp);
    }
    return 0;
}

int check_same_network(char *ip1, char *netmask, char *ip2) {
    struct in_addr addr1, addr2, mask;

    if (inet_pton(AF_INET, ip1, &addr1) != 1) {
        printf("Invalid IP address: %s\n", ip1);
        return -1;
    }
    if (inet_pton(AF_INET, netmask, &mask) != 1) {
        printf("Invalid netmask: %s\n", netmask);
        return -1;
    }
    if (inet_pton(AF_INET, ip2, &addr2) != 1) {
        printf("Invalid IP address: %s\n", ip2);
        return -1;
    }

    if ((addr1.s_addr & mask.s_addr) == (addr2.s_addr & mask.s_addr)) {
        return 1;
    } else {
        return 0;
    }
}


int af_read_file_value(const char *file_path, char *value, int value_len) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    if (fgets(value, value_len, file) == NULL) {
        perror("Failed to read line from file");
        fclose(file);
        return -1;
    }

    size_t len = strlen(value);
    if (len > 0 && value[len - 1] == '\n') {
        value[len - 1] = '\0';
    }

    fclose(file);
    return 0;
}

int af_read_file_int_value(const char *file_path, int *value) {
    char line_buf[128] = {0};
    if (af_read_file_value(file_path, line_buf, sizeof(line_buf)) < 0){
        return -1;
    }
    *value = atoi(line_buf);
    return 0;
}

/**
 * Parse time_str from UCI format into time period structures
 * Format: "HH:MM-HH:MM-w1,w2,w3 HH:MM-HH:MM-w4,w5 ..."
 * Example: "00:00-23:59-2,3,6 00:00-02:05-1,2,3,0"
 */
int fwx_parse_time_str(const char *time_str, fwx_time_period_t *periods, int max_periods) {
    if (!time_str || !periods || max_periods <= 0) {
        return -1;
    }

    int period_count = 0;
    char *save_ptr1 = NULL;
    char *save_ptr2 = NULL;
    
    
    char time_str_copy[512] = {0};
    strncpy(time_str_copy, time_str, sizeof(time_str_copy) - 1);
    
    
    char *time_period = strtok_r(time_str_copy, " ", &save_ptr1);
    while (time_period && period_count < max_periods) {
        fwx_time_period_t *period = &periods[period_count];
        memset(period, 0, sizeof(fwx_time_period_t));
        
        char start[16] = {0};
        char end[16] = {0};
        char weekdays[64] = {0};
        
        
        char *first_delim = strchr(time_period, '-');
        if (!first_delim) {
            
            time_period = strtok_r(NULL, " ", &save_ptr1);
            continue;
        }
        
        
        strncpy(start, time_period, first_delim - time_period);
        start[first_delim - time_period] = '\0';
        
        
        char *second_delim = strchr(first_delim + 1, '-');
        if (second_delim) {
            
            strncpy(end, first_delim + 1, second_delim - first_delim - 1);
            end[second_delim - first_delim - 1] = '\0';
            strncpy(weekdays, second_delim + 1, sizeof(weekdays) - 1);
        } else {
            
            strncpy(end, first_delim + 1, sizeof(end) - 1);
        }
        
        
        strncpy(period->start_time, start, sizeof(period->start_time) - 1);
        strncpy(period->end_time, end, sizeof(period->end_time) - 1);
        
        
        if (strlen(weekdays) > 0) {
            char weekdays_copy[64] = {0};
            strncpy(weekdays_copy, weekdays, sizeof(weekdays_copy) - 1);
            
            char *weekday_str = strtok_r(weekdays_copy, ",", &save_ptr2);
            while (weekday_str && period->weekday_count < MAX_WEEKDAYS) {
                int weekday = atoi(weekday_str);
                if (weekday >= 0 && weekday <= 6) {
                    period->weekdays[period->weekday_count] = weekday;
                    period->weekday_count++;
                }
                weekday_str = strtok_r(NULL, ",", &save_ptr2);
            }
        }
        
        period_count++;
        time_period = strtok_r(NULL, " ", &save_ptr1);
    }
    
    return period_count;
}


void update_fwx_proc_value(char *key, char *value){
    char cmd_buf[128] = {0};
    char file_path[128] = {0};
    char old_value[128] = {0};
    sprintf(file_path, "/proc/sys/fwx/%s", key);

    af_read_file_value(file_path, old_value, sizeof(old_value));    
    if (strcmp(old_value, value) != 0){
        sprintf(cmd_buf, "echo %s >/proc/sys/fwx/%s", value, key);
        system(cmd_buf);
    }
}

void update_fwx_proc_u32_value(char *key, u_int32_t value){
    char buf[32] = {0};
    sprintf(buf, "%u", value);
    update_fwx_proc_value(key, buf);
}

#define MD5_F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))
#define MD5_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t md5_load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void md5_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void md5_transform(uint32_t *state, const uint8_t block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = md5_load_le32(block + i * 4);

    for (i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = MD5_F(b, c, d);
            g = i;
        } else if (i < 32) {
            f = MD5_G(b, c, d);
            g = (5 * i + 1) & 15;
        } else if (i < 48) {
            f = MD5_H(b, c, d);
            g = (3 * i + 5) & 15;
        } else {
            f = MD5_I(b, c, d);
            g = (7 * i) & 15;
        }
        f = f + a + md5_k[i] + x[g];
        a = d;
        d = c;
        c = b;
        b = b + MD5_ROTL(f, md5_s[i]);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void fwx_md5(const unsigned char *data, size_t len, unsigned char digest[16])
{
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    uint64_t bit_len = (uint64_t)len * 8;
    uint8_t block[64];
    size_t rem;
    int i;

    while (len >= 64) {
        md5_transform(state, data);
        data += 64;
        len -= 64;
    }

    memset(block, 0, sizeof(block));
    memcpy(block, data, len);
    block[len] = 0x80;

    rem = len + 1;
    if (rem > 56) {
        md5_transform(state, block);
        memset(block, 0, sizeof(block));
    }
    md5_store_le32(block + 56, (uint32_t)bit_len);
    md5_store_le32(block + 60, (uint32_t)(bit_len >> 32));
    md5_transform(state, block);

    for (i = 0; i < 4; i++)
        md5_store_le32(digest + i * 4, state[i]);
}
