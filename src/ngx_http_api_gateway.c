/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway.h"
#include <ngx_http.h>


ngx_module_t ngx_http_api_gateway_module;

static ngx_int_t
ngx_http_api_gateway_init_worker(ngx_cycle_t *cycle);



static ngx_http_module_t ngx_http_api_gateway_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */
    ngx_api_gateway_create_main_conf,  /* create main configuration */
    ngx_api_gateway_init_main_conf,    /* init main configuration */
    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */
    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};


static ngx_command_t  ngx_http_api_gateway_commands[] = {

    { ngx_string("api_gateway_entrypoints"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_api_gateway_entrypoints,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("api_gateway_backends"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_api_gateway_backends,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("api_gateway_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_api_gateway_main_conf_t, timeout),
      NULL },

    { ngx_string("api_gateway_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_api_gateway_main_conf_t, interval),
      NULL },

      ngx_null_command
};


ngx_module_t ngx_http_api_gateway_module = {
    NGX_MODULE_V1,
    &ngx_http_api_gateway_ctx ,        /* module context */
    ngx_http_api_gateway_commands,     /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_http_api_gateway_init_worker,  /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_api_gateway_handler(ngx_event_t *ev)
{
    ngx_api_gateway_main_conf_t  *amcf;
    amcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
            ngx_http_api_gateway_module);
    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;
    ngx_api_gateway_fetch_keys(amcf);
    ngx_add_timer(ev, amcf->interval);
}


static ngx_int_t
ngx_http_api_gateway_init_worker(ngx_cycle_t *cycle)
{
    ngx_api_gateway_main_conf_t  *amcf;
    ngx_event_t                  *ev;
    static ngx_connection_t       c = { .fd = -1 };

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    if (ngx_worker != 0)
        return NGX_OK;

    amcf = ngx_http_cycle_get_module_main_conf(cycle,
            ngx_http_api_gateway_module);

    if (amcf == NULL || amcf->templates.nelts == 0)
        return NGX_OK;
    
    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL)
        return NGX_ERROR;

    ev->log = cycle->log;
    ev->data = &c;
    ev->handler = ngx_http_api_gateway_handler;

    ngx_add_timer(ev, 0);

    return NGX_OK;
}
