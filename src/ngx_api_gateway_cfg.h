/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_CONFIG_H
#define NGX_API_GATEWAY_CONFIG_H

#include <ngx_config.h>
#include <ngx_core.h>


// upstreams

typedef struct {
    ngx_int_t  type;
    ngx_str_t  name;
    ngx_int_t  keepalive;
    ngx_int_t  keepalive_requests;
    ngx_int_t  keepalive_timeout;
    ngx_int_t  method;
    ngx_int_t  max_fails;
    ngx_int_t  max_conns;
    time_t     fail_timeout;
    ngx_int_t  dns_update;
} ngx_api_gateway_cfg_upstream_t;


ngx_int_t ngx_api_gateway_cfg_upstream_add(ngx_api_gateway_cfg_upstream_t *u);

ngx_int_t ngx_api_gateway_cfg_upstream_delete(ngx_str_t name, ngx_int_t type);

typedef ngx_int_t (*on_upstream_pt)(ngx_api_gateway_cfg_upstream_t *u,
    void *ctxp);

ngx_int_t ngx_api_gateway_cfg_upstreams(ngx_cycle_t *cycle,
    on_upstream_pt cb, void *ctxp);

// routes

ngx_int_t ngx_api_gateway_cfg_route_add(ngx_str_t var,
    ngx_str_t api, ngx_str_t upstream);

ngx_int_t ngx_api_gateway_cfg_route_delete(ngx_str_t var, ngx_str_t api);

typedef ngx_int_t (*on_route_pt)(ngx_str_t api, ngx_str_t upstream, void *ctxp);

ngx_int_t ngx_api_gateway_cfg_routes(ngx_cycle_t *cycle,
    ngx_str_t var, on_route_pt cb, void *ctxp);


#endif /* NGX_API_GATEWAY_CONFIG_MODULE_H */

