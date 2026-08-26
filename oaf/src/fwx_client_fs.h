
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __AF_CLIENT_FS_H__
#define __AF_CLIENT_FS_H__

int init_af_client_procfs(void);
void finit_af_client_procfs(void);
int create_client_proc_dir(af_client_info_t *client);
void remove_client_proc_dir(af_client_info_t *client);

#endif
