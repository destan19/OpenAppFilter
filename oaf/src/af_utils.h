#ifndef AF_UTILS_H
#define AF_UTILS_H
u_int32_t af_get_timestamp_sec(void);

char *k_trim(char *s);

int check_local_network_ip(unsigned int ip);

void dump_str(char *name, unsigned char *p, int len);

void dump_hex(char *name, unsigned char *p, int len);

int k_sscanf(const char *buf, const char *fmt, ...);
int k_atoi(const char *str);
void print_hex_ascii(const unsigned char *data, size_t size);
int hash_mac(unsigned char *mac);
int mac_to_hex(u8 *mac, u8 *mac_hex);

#endif

