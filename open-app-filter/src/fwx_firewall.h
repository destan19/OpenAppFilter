// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __FWX_FIREWALL_H__
#define __FWX_FIREWALL_H__

#include <json-c/json.h>

struct json_object *fwx_api_get_firewall(struct json_object *req_obj);
struct json_object *fwx_api_set_firewall(struct json_object *req_obj);

#endif
