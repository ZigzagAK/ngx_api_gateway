/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_ROUTER_H
#define NGX_API_GATEWAY_ROUTER_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_regex.h>


#include "ngx_template.h"


typedef struct {
    ngx_str_t     backend;
    ngx_str_t     pattern;
    ngx_regex_t  *re;
} ngx_mapping_regex_t;

typedef struct {
    ngx_array_t   regex;
} ngx_http_api_gateway_mapping_t;

typedef struct {
    ngx_array_t                     backends;
    ngx_str_t                       var;
    ngx_http_api_gateway_mapping_t  map;
} ngx_http_api_gateway_loc_conf_t;


char * ngx_api_gateway_router(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_int_t
ngx_api_gateway_router_build(ngx_pool_t *pool,
    ngx_http_api_gateway_mapping_t *m, ngx_str_t backend,
    ngx_template_list_t entries);


ngx_int_t
ngx_api_gateway_router_match(ngx_http_api_gateway_mapping_t *m,
    ngx_str_t *uri, ngx_str_t *upstream);

#endif /* NGX_API_GATEWAY_ROUTER_H */