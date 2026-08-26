// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uci.h>
#include "fwx_uci.h"

const char *config_path = "./config";
static struct uci_context *uci_ctx = NULL;
static struct uci_package *uci_appfilter;


int fwx_uci_get_int_value(struct uci_context *ctx, char *key)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = -1;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
            ret = atoi(ptr.o->v.string);
			goto done;
        default:
            break;
    }
done:
	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int fwx_uci_get_value(struct uci_context *ctx, char *key, char *output, int out_len)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        ret = 1;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            snprintf(output, out_len, "%s", ptr.s->type);
            break;
        case UCI_TYPE_OPTION:
            snprintf(output, out_len, "%s", ptr.o->v.string);
			break;
        default:
			ret = 1;
            break;
    }
done:    
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int fwx_uci_delete(struct uci_context *ctx, char *key)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_delete(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}



int fwx_uci_add_list(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters;
    if (strlen(value) + strlen(key) >= MAX_PARAM_LIST_LEN  - 1) {
        printf("value too long\n");
        return -1;
    }
    char param_tmp[MAX_PARAM_LIST_LEN] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int fwx_uci_get_list_value(struct uci_context *ctx, char *key, char *output, int out_len, char *delimt)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = -1;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};
    strcpy(param_tmp, key);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        goto done;
    }
    int sep = 0;
    e = ptr.last;
	int len = 0;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
			if (UCI_TYPE_LIST == ptr.o->type){
				memset(output, 0x0, out_len);
				uci_foreach_element(&ptr.o->v.list, e) {
					len = strlen(output);
					if (sep){
						strncat(output + len, delimt, out_len);
					}
					len = strlen(output);
					sprintf(output + len, "%s", e->name);
					sep = 1;
				}
				ret = 0;
			}
			goto done;
        default:
            break;
    }
done:	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int fwx_uci_add_int_list(struct uci_context *ctx, char *key, int value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%d", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int fwx_uci_del_list(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_del_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int fwx_uci_set_value(struct uci_context *ctx, char *key, char *value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[2048] = {0};    
    sprintf(param_tmp, "%s=%s", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    e = ptr.last;
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int fwx_uci_set_int_value(struct uci_context *ctx, char *key, int value)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    int dummy;
    char *parameters ;
    char param_tmp[128] = {0};    
    sprintf(param_tmp, "%s=%d", key, value);
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    e = ptr.last;
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

    if (ptr.p)
        uci_unload(ctx, ptr.p);
    return ret;
}

int fwx_uci_del_array_value(struct uci_context *ctx, char *key_fmt, int index){
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return fwx_uci_delete(ctx, key);
}

int fwx_uci_set_array_value(struct uci_context *ctx, char *key_fmt, int index, char *value){
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return fwx_uci_set_value(ctx, key, value);
}

int fwx_uci_commit(struct uci_context *ctx, const char * package) {
    struct uci_ptr ptr;
    int ret = UCI_OK;
    if (!package){
        return -1;
    }
    if (uci_lookup_ptr(ctx, &ptr, package, true) != UCI_OK) {
        return -1;
    }   

    if (uci_commit(ctx, &ptr.p, false) != UCI_OK) {
    	ret = -1;
        goto done;
    }
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);

    return UCI_OK;
}

int fwx_uci_get_list_num(struct uci_context * ctx, char *package, char *section){
    int count = 0;
    struct uci_ptr p;
    struct uci_element *e; 
    struct uci_package *pkg = NULL;

    if (UCI_OK != uci_load(ctx, package, &pkg)){
        return -1; 
    }   
    uci_foreach_element(&pkg->sections, e){ 
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, section)){
            continue;
        }
        count++;
    }   
    uci_unload(ctx, pkg);
    return count;
}
int fwx_uci_get_array_value(struct uci_context *ctx, char *key_fmt, int index, char *output, int out_len)
{
    char key[128] = {0};
    sprintf(key, key_fmt, index);
    return fwx_uci_get_value(ctx, key, output, out_len);
}

int fwx_uci_add_section(struct uci_context * ctx, char *package_name, char *section)
{
    struct uci_section *s = NULL;
    struct uci_package *p = NULL;
    int ret;
    ret = uci_load(ctx, package_name , &p);
    if (ret != UCI_OK)
        goto done;

    ret = uci_add_section(ctx, p, section, &s);
    if (ret != UCI_OK)
        goto done;
    ret = uci_save(ctx, p); 
done:
    if (s) 
        fprintf(stdout, "%s\n", s->e.name);
    return ret;
}

static struct uci_package *fwx_uci_get_package(const char *config)
{
    struct uci_context *ctx = uci_ctx;
    struct uci_package *p = NULL;

    if (!ctx)
    {
        ctx = uci_alloc_context();
        uci_ctx = ctx;
        ctx->flags &= ~UCI_FLAG_STRICT;


    }
    else
    {
        p = uci_lookup_package(ctx, config);
        if (p)
            uci_unload(ctx, p);
    }

    if (uci_load(ctx, config, &p))
        return NULL;

    return p;
}
