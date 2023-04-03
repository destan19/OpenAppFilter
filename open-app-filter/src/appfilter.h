#ifndef __APPFILTER_H__
#define __APPFILTER_H__
#define MIN_INET_ADDR_LEN 7
#define CMD_GET_LAN_IP   "ifconfig br-lan | grep 'inet addr' | awk '{print $2}' | awk -F: '{print $2}'"
#define CMD_GET_LAN_MASK "ifconfig br-lan | grep 'inet addr' | awk '{print $4}' | awk -F: '{print $2}'"

#endif