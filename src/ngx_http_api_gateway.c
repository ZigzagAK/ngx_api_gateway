/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_http.h>

#include "ngx_api_gateway.h"
#include "ngx_api_gateway_router.h"


ngx_module_t ngx_http_api_gateway_module;

static ngx_int_t
ngx_http_api_gateway_init_worker(ngx_cycle_t *cycle);


static void * ngx_api_gateway_create_loc_conf(ngx_conf_t *cf);

static char * ngx_api_gateway_merge_loc_conf(ngx_conf_t *cf,
    void *prev, void *conf);


static ngx_http_module_t ngx_http_api_gateway_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */
    ngx_api_gateway_create_main_conf,  /* create main configuration */
    ngx_api_gateway_init_main_conf,    /* init main configuration */
    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */
    ngx_api_gateway_create_loc_conf,   /* create location configuration */
    ngx_api_gateway_merge_loc_conf     /* merge location configuration */
};


#define NGX_ALL_CONF (NGX_HTTP_MAIN_CONF |  \
                      NGX_HTTP_SRV_CONF  |  \
                      NGX_HTTP_LOC_CONF  |  \
                      NGX_HTTP_UPS_CONF  |  \
                      NGX_HTTP_SIF_CONF  |  \
                      NGX_HTTP_LIF_CONF  |  \
                      NGX_HTTP_LMT_CONF)


static char *
ngx_api_gateway_router_add_variable(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_api_gateway_router_post = {
    ngx_api_gateway_router_add_variable
};


static ngx_command_t  ngx_http_api_gateway_commands[] = {

    { ngx_string("template"),
      NGX_ALL_CONF|NGX_CONF_TAKE2,
      ngx_template_directive,
      0,
      0,
      NULL },

    { ngx_string("api_gateway_router"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_api_gateway_router,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &ngx_api_gateway_router_post },

    { ngx_string("api_gateway_template"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_api_gateway_template_directive,
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


static void *
ngx_api_gateway_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_api_gateway_loc_conf_t  *glcf;

    glcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_gateway_loc_conf_t));
    if (glcf == NULL)
        return NULL;

    if (NGX_ERROR == ngx_array_init(&glcf->backends, cf->pool,
                                    10, sizeof(ngx_str_t)))
        return NULL;

    if (NGX_ERROR == ngx_array_init(&glcf->map.regex, cf->pool,
                                    10, sizeof(ngx_mapping_regex_t)))
        return NULL;

    if (NGX_ERROR == ngx_trie_init(cf->pool, &glcf->map.tree))
        return NULL;
    
    return glcf;
}


static ngx_api_gateway_conf_t *
ngx_api_gateway_create_lookup_backend(ngx_api_gateway_main_conf_t *gmcf,
    ngx_str_t name)
{
    ngx_uint_t               j, i;
    ngx_api_gateway_t       *t;
    ngx_api_gateway_conf_t  *conf;

    t = gmcf->templates.elts;

    for (j = 0; j < gmcf->templates.nelts; j++) {

        conf = t[j].base.entries.elts;

        for (i = 0; i < t[j].base.entries.nelts; i++) {

            if (ngx_memn2cmp(conf[i].base.name.data, name.data,
                             conf[i].base.name.len, name.len) == 0)
                return conf + i;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_api_gateway_create_mappings(ngx_conf_t *cf,
    ngx_http_api_gateway_loc_conf_t *glcf)
{
    ngx_api_gateway_main_conf_t  *gmcf;
    ngx_api_gateway_conf_t       *conf;
    ngx_template_list_t          *list;
    ngx_uint_t                    j, i;
    ngx_str_t                    *backend;

    static ngx_str_t api = ngx_string("api");

    gmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_api_gateway_module);

    backend = glcf->backends.elts;

    for (j = 0; j < glcf->backends.nelts; j++) {

        conf = ngx_api_gateway_create_lookup_backend(gmcf, backend[j]);
        if (conf == NULL)
            continue;

        list = conf->lists.elts;

        for (i = 0; i < conf->lists.nelts; i++) {

            if (ngx_memn2cmp(list[i].key.data, api.data,
                             list[i].key.len, api.len) != 0)
                continue;

            if (ngx_api_gateway_router_build(cf->pool, &glcf->map,
                    conf->base.name, list[i]) == NGX_ERROR)
                return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static char *
ngx_api_gateway_merge_loc_conf(ngx_conf_t *cf,
    void *prev, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *parent;
    ngx_http_api_gateway_loc_conf_t  *child;
    ngx_str_t                        *backend, *c;
    ngx_uint_t                        j;

    parent = prev;
    child = conf;

    backend = parent->backends.elts;

    for (j = 0; j < parent->backends.nelts; j++) {
        c = ngx_array_push(&child->backends);
        if (c == NULL)
            return NGX_CONF_ERROR;
        *c = backend[j];
    }

    if (ngx_api_gateway_create_mappings(cf, child) == NGX_OK)
        return NGX_CONF_OK;

    return NGX_CONF_ERROR;
}


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


static ngx_int_t
ngx_api_gateway_router_map(ngx_http_request_t *r,
    ngx_http_variable_value_t *retval)
{
    ngx_http_api_gateway_loc_conf_t  *glcf;
    ngx_str_t                         upstream;

    glcf = ngx_http_get_module_loc_conf(r, ngx_http_api_gateway_module);

    switch (ngx_api_gateway_router_match(r->pool, &glcf->map,
                &r->uri, &upstream)) {

        case NGX_OK:

            retval->data = upstream.data;
            retval->len = upstream.len;

            return NGX_OK;

        case NGX_DECLINED:

            return NGX_DECLINED;
            
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_api_gateway_router_var(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->valid = 1;
    v->not_found = 0;

    if (ngx_api_gateway_router_map(r, v) == NGX_OK)
        return NGX_OK;

    v->not_found = 1;
    return NGX_OK;
}


static char *
ngx_api_gateway_router_add_variable(ngx_conf_t *cf, void *post, void *data)
{
    ngx_http_api_gateway_loc_conf_t  *glcf = data;
    ngx_http_variable_t              *var;

    var = ngx_http_add_variable(cf, &glcf->var, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL)
        return NGX_CONF_ERROR;

    var->get_handler = ngx_api_gateway_router_var;
    var->data = 0;

    return NGX_CONF_OK;
}
