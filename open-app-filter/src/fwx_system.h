
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_SYSTEM_H__
#define __FWX_SYSTEM_H__

#include <json-c/json.h>

struct json_object *get_system_status(void);
int fwx_get_disable_hnat(void);
int fwx_get_notice_status(void);
struct json_object *fwx_api_get_system_info(struct json_object *req_obj);
struct json_object *fwx_api_set_system_info(struct json_object *req_obj);
struct json_object *fwx_api_get_tcp_rst(struct json_object *req_obj);
struct json_object *fwx_api_set_tcp_rst(struct json_object *req_obj);
struct json_object *fwx_api_get_advanced_settings(struct json_object *req_obj);
struct json_object *fwx_api_set_advanced_settings(struct json_object *req_obj);
struct json_object *fwx_api_set_dashboard_notice_status(struct json_object *req_obj);

#endif
