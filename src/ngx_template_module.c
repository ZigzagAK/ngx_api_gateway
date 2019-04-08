/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_template.h"

#include <ngx_event.h>


static ngx_int_t
ngx_template_init_worker(ngx_cycle_t *cycle);


static ngx_core_module_t ngx_template_ctx = {
    ngx_string("ngx_template_module"),
    ngx_template_create_main_conf,  /* create main configuration */
    NULL                            /* init main configuration */
};


static ngx_command_t  ngx_template_commands[] = {

    { ngx_string("template"),
      NGX_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_template_directive,
      0,
      0,
      NULL },

    ngx_null_command

};


ngx_module_t ngx_template_module = {
    NGX_MODULE_V1,
    &ngx_template_ctx,                 /* module context */
    ngx_template_commands,             /* module directives */
    NGX_CORE_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_template_init_worker,          /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_template_handler(ngx_event_t *ev)
{
    ngx_template_main_conf_t  *tmcf;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                     ngx_template_module);

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    ngx_template_check_updates(tmcf);

    ngx_add_timer(ev, 1000);
}


static ngx_int_t
ngx_template_init_worker(ngx_cycle_t *cycle)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_event_t               *ev;
    static ngx_connection_t    c = { .fd = -1 };

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                     ngx_template_module);

    if (tmcf->templates.nelts == 0)
        return NGX_OK;

    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL)
        return NGX_ERROR;

    ev->log = cycle->log;
    ev->data = &c;
    ev->handler = ngx_template_handler;

    ngx_add_timer(ev, 10000);

    return NGX_OK;
}
