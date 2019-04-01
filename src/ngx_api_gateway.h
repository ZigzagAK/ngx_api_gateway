/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_H
#define NGX_API_GATEWAY_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_inet.h>


typedef struct {
    ngx_str_t      filename;
    ngx_str_t      url;
    ngx_keyval_t  *keys;
    ngx_int_t      nkeys;
    ngx_str_t     *api;
    ngx_int_t      napi;
    ngx_str_t      conf;
} ngx_api_gateway_template_t;


typedef struct {
    ngx_array_t    entries;
    ngx_str_t      keyfile;
    ngx_str_t      yaml;
    ngx_str_t      filename;
    ngx_url_t      url;
    ngx_str_t      template;
} ngx_api_gateway_t;


typedef struct {
    ngx_array_t    entrypoints;
    ngx_array_t    backends;
} ngx_api_gateway_main_conf_t;


void *
ngx_api_gateway_create_main_conf(ngx_conf_t *cf);


char *
ngx_api_gateway_entrypoints(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


char *
ngx_api_gateway_backends(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


void
ngx_api_gateway_fetch_keys(ngx_api_gateway_main_conf_t *amcf);


#endif /* NGX_API_GATEWAY_H */

