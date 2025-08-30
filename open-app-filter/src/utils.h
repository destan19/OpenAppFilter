#ifndef __UTILS_H__
#define __UTILS_H__
char *str_trim(char *s);
int exec_with_result_line(char *cmd, char *result, int len);
int check_same_network(char *ip1, char *netmask, char *ip2);
int af_read_file_value(const char *file_path, char *value, int value_len);
int af_read_file_int_value(const char *file_path, int *value);
unsigned int get_timestamp(void);
#endif