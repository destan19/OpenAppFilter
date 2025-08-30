
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>


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
unsigned int get_timestamp(void)
{
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    return cur_time.tv_sec;
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
        //perror("Failed to open file");
        return -1;
    }

    if (fgets(value, value_len, file) == NULL) {
        perror("Failed to read line from file");
        fclose(file);
        return -2;
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
