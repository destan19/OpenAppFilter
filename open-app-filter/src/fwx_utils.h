// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __UTILS_H__
#define __UTILS_H__
#include <sys/types.h>

#define MAX_WEEKDAYS 7


typedef struct fwx_time_period {
    char start_time[16];      
    char end_time[16];         
    int weekdays[MAX_WEEKDAYS]; 
    int weekday_count;         
} fwx_time_period_t;

char *str_trim(char *s);
int exec_with_result_line(char *cmd, char *result, int len);
int check_same_network(char *ip1, char *netmask, char *ip2);
int af_read_file_value(const char *file_path, char *value, int value_len);
int af_read_file_int_value(const char *file_path, int *value);
int fwx_send_msg_to_kernel(char *buf);
int fwx_parse_time_str(const char *time_str, fwx_time_period_t *periods, int max_periods);
void update_fwx_proc_value(char *key, char *value);
void update_fwx_proc_u32_value(char *key, u_int32_t value);
void fwx_md5(const unsigned char *data, size_t len, unsigned char digest[16]);
#endif
