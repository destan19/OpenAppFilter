
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_NETLINK_H__
#define __FWX_NETLINK_H__
#define DEFAULT_FWX_NL_PID 999
#define FWX_NETLINK_ID 29
#define MAX_FWX_NETLINK_MSG_LEN 1024
#define MAX_AF_MSG_DATA_LEN 800
#define MAX_FEATURE_LINE_LEN 800

struct fwx_nl_msg_hdr
{
    int magic;
    int len;
};

enum E_FWX_NL_MSG_TYPE
{
    FWX_NL_MSG_INIT,
    FWX_NL_MSG_ADD_FEATURE,
    FWX_NL_MSG_CLEAN_FEATURE,
    FWX_NL_MSG_FEATURE_LOAD_DONE,
    FWX_NL_MSG_MAX
};

typedef struct fwx_nl_msg
{
    int action;
} fwx_nl_msg_t;

typedef struct fwx_nl_feature_msg{
    fwx_nl_msg_t hdr;
    char feature[MAX_FEATURE_LINE_LEN];
} fwx_nl_feature_msg_t;

int fwx_netlink_init(void);
void fwx_netlink_handler(struct uloop_fd *u, unsigned int ev);
int fwx_nl_send_msg_to_kernel(int fd, void *msg, int len);
#endif
