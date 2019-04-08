/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_ROUTER_H
#define NGX_API_GATEWAY_ROUTER_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_regex.h>


#include "ngx_template.h"
#include "ngx_trie.h"


typedef struct {
    ngx_str_t     backend;
    ngx_str_t     pattern;
    ngx_regex_t  *re;
    ngx_queue_t   queue;
} ngx_mapping_regex_t;

typedef struct {
    ngx_atomic_t  *lock;
    ngx_queue_t   *regex;
    ngx_trie_t    *trie;
} ngx_http_api_gateway_mapping_t;

typedef struct {
    ngx_http_api_gateway_mapping_t   map;
    ngx_slab_pool_t                 *slab;
} ngx_http_api_gateway_shctx_t;

typedef struct {
    ngx_array_t                      backends;
    ngx_str_t                        var;
    ngx_http_api_gateway_mapping_t   map;
    ngx_shm_zone_t                  *zone;
    ngx_http_api_gateway_shctx_t    *sh;
} ngx_http_api_gateway_router_t;

typedef struct {
    ngx_array_t  entries;
} ngx_http_api_gateway_loc_conf_t;


ngx_int_t
ngx_api_gateway_router_init_conf(ngx_conf_t *cf, ngx_pool_t *pool,
    ngx_http_api_gateway_router_t *router);

ngx_int_t
ngx_api_gateway_router_shm_init(ngx_http_api_gateway_router_t *router,
    ngx_http_api_gateway_shctx_t *sh);

char * ngx_api_gateway_router(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_int_t ngx_api_gateway_router_build(ngx_cycle_t *cycle, ngx_pool_t *pool,
    ngx_http_api_gateway_router_t *router, ngx_str_t backend,
    ngx_template_seq_t entries);

ngx_int_t ngx_api_gateway_router_match(ngx_pool_t *temp_pool,
    ngx_http_api_gateway_mapping_t *m,
    ngx_str_t *uri, ngx_str_t *path, ngx_str_t *upstream);

#endif /* NGX_API_GATEWAY_ROUTER_H */
