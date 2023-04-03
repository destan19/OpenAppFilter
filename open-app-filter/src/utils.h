#ifndef __UTILS_H__
#define __UTILS_H__
char *str_trim(char *s);
int exec_with_result_line(char *cmd, char *result, int len);
int check_same_network(char *ip1, char *netmask, char *ip2);
#endif