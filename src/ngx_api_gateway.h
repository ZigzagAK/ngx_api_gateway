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
    ngx_template_t  t;
    ngx_url_t       url;
} ngx_api_gateway_template_t;


typedef struct {
    ngx_array_t   templates;
    ngx_array_t   routers;
    ngx_msec_t    timeout;
    ngx_msec_t    interval;
    ngx_int_t     request_path_index;
    ngx_cycle_t  *cycle;
    ngx_pool_t   *pool;
    ngx_uint_t    generation;
    ngx_array_t   backends;
} ngx_api_gateway_main_conf_t;


void * ngx_api_gateway_create_main_conf(ngx_conf_t *cf);


char * ngx_api_gateway_init_main_conf(ngx_conf_t *cf, void *conf);


char * ngx_api_gateway_template_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


void ngx_api_gateway_sync(ngx_api_gateway_main_conf_t *amcf);

void ngx_api_gateway_update(ngx_template_main_conf_t *tmcf,
    ngx_api_gateway_main_conf_t *amcf);

#endif /* NGX_API_GATEWAY_H */

