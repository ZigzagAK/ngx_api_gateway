/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_H
#define NGX_API_GATEWAY_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_inet.h>


#include "ngx_template.h"


typedef struct {
    ngx_template_conf_t  base;
    ngx_str_t            url;
    ngx_array_t          lists;
} ngx_api_gateway_conf_t;


typedef struct {
    ngx_template_t       base;
    ngx_url_t            url;
} ngx_api_gateway_t;


typedef struct {
    ngx_array_t          templates;
    ngx_msec_t           timeout;
    ngx_msec_t           interval;
    ngx_int_t            request_path_index;
} ngx_api_gateway_main_conf_t;


void * ngx_api_gateway_create_main_conf(ngx_conf_t *cf);


char * ngx_api_gateway_init_main_conf(ngx_conf_t *cf, void *conf);


char * ngx_api_gateway_template_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


void ngx_api_gateway_fetch_keys(ngx_api_gateway_main_conf_t *amcf);


#endif /* NGX_API_GATEWAY_H */

