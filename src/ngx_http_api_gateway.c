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


static ngx_int_t
ngx_api_gateway_pre_conf(ngx_conf_t *cf);

static ngx_int_t
ngx_api_gateway_post_conf(ngx_conf_t *cf);


static ngx_http_module_t ngx_http_api_gateway_ctx = {
    ngx_api_gateway_pre_conf,     /* preconfiguration */
    ngx_api_gateway_post_conf,         /* postconfiguration */
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
ngx_api_gateway_router_add_variable(ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t  ngx_api_gateway_router_post = {
    ngx_api_gateway_router_add_variable
};


static ngx_command_t  ngx_http_api_gateway_commands[] = {

    { ngx_string("template"),
      NGX_ALL_CONF|NGX_CONF_TAKE123,
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
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
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


static ngx_int_t
ngx_api_gateway_router_request_path_var(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return NGX_OK;
}

static ngx_http_variable_t
ngx_http_api_gateway_vars[] = {

    { ngx_string("request_path"), NULL,
      ngx_api_gateway_router_request_path_var, 0,
      NGX_HTTP_VAR_CHANGEABLE, 1 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }

};


static ngx_int_t
ngx_api_gateway_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_api_gateway_vars; v->name.len; v++) {

        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
            return NGX_ERROR;

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_post_conf(ngx_conf_t *cf)
{
    ngx_api_gateway_main_conf_t  *amcf;

    static ngx_str_t  request_path_var = ngx_string("request_path");

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_api_gateway_module);

    amcf->request_path_index = ngx_http_get_variable_index(cf,
        &request_path_var);

    return NGX_OK;
}


static void *
ngx_api_gateway_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_api_gateway_loc_conf_t  *glcf;

    glcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_gateway_loc_conf_t));
    if (glcf == NULL)
        return NULL;

    if (NGX_ERROR == ngx_array_init(&glcf->entries, cf->pool,
                                    10, sizeof(ngx_http_api_gateway_conf_t)))
        return NULL;

    return glcf;
}


static ngx_int_t
ngx_api_gateway_create_mappings(ngx_conf_t *cf,
    ngx_http_api_gateway_loc_conf_t *glcf)
{
    ngx_http_api_gateway_conf_t  *gateway_conf;
    ngx_template_conf_t          *conf;
    ngx_template_seq_t           *seq;
    ngx_uint_t                    k, j, i;
    ngx_str_t                    *backend;

    static ngx_str_t api = ngx_string("api");

    gateway_conf = glcf->entries.elts;

    for (k = 0; k < glcf->entries.nelts; k++) {

        backend = gateway_conf[k].backends.elts;

        for (j = 0; j < gateway_conf[k].backends.nelts; j++) {

            conf = ngx_template_lookup_by_name(cf->cycle, backend[j]);
            if (conf == NULL)
                continue;

            seq = conf->seqs.elts;

            for (i = 0; i < conf->seqs.nelts; i++) {

                if (ngx_memn2cmp(seq[i].key.data, api.data,
                                 seq[i].key.len, api.len) != 0)
                    continue;

                if (gateway_conf->zone == NULL) {
                    if (ngx_trie_init(gateway_conf[k].map.trie) == NGX_ERROR)
                        return NGX_ERROR;
                }

                if (ngx_api_gateway_router_build(cf->pool, &gateway_conf[k].map,
                        conf->name, seq[i]) == NGX_ERROR)
                    return NGX_ERROR;
            }
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
    ngx_http_api_gateway_conf_t      *gateway_conf, *c;
    ngx_uint_t                        j;

    parent = prev;
    child = conf;

    gateway_conf = parent->entries.elts;

    for (j = 0; j < parent->entries.nelts; j++) {
        c = ngx_array_push(&child->entries);
        if (c == NULL)
            return NGX_CONF_ERROR;
        *c = gateway_conf[j];
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
    ngx_http_api_gateway_conf_t *gateway_conf,
    ngx_http_variable_value_t *retval)
{
    ngx_api_gateway_main_conf_t  *amcf;
    ngx_variable_value_t         *request_path_var;
    ngx_str_t                     path;
    ngx_str_t                     upstream;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_gateway_module);

    switch (ngx_api_gateway_router_match(r->pool, &gateway_conf->map,
                &r->uri, &path, &upstream)) {

        case NGX_OK:

            retval->data = upstream.data;
            retval->len = upstream.len;

            request_path_var = ngx_http_get_indexed_variable(r,
                amcf->request_path_index);

            request_path_var->not_found = 0;
            request_path_var->valid = 1;
            request_path_var->data = path.data;
            request_path_var->len = path.len;

            return NGX_OK;

        case NGX_DECLINED:

            return NGX_DECLINED;
            
    }

    return NGX_ERROR;
}


typedef struct {
    ngx_http_api_gateway_loc_conf_t  *alcf;
    ngx_http_api_gateway_conf_t      *gateway_conf;
} router_var_ctx_t;


static ngx_int_t
ngx_api_gateway_router_var(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_api_gateway_loc_conf_t  *alcf;
    router_var_ctx_t                 *ctx;
    ngx_array_t                      *a;
    ngx_uint_t                        j;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_api_gateway_module);

    a = (ngx_array_t *) data;
    ctx = a->elts;

    for (j = 0; j < a->nelts; j++) {

        if (ctx[j].alcf == alcf) {
    
            v->valid = 1;
            v->not_found = 0;

            if (ngx_api_gateway_router_map(r, ctx[j].gateway_conf, v) == NGX_OK)
                return NGX_OK;
        }
    }

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_router_init_shtrie(ngx_shm_zone_t *zone, void *old);


static char *
ngx_api_gateway_router_add_variable(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *alcf = conf;
    ngx_http_api_gateway_conf_t      *gateway_conf = data;
    ngx_http_variable_t              *var;
    ngx_keyval_t                      kv;
    ssize_t                           shmsize;
    ngx_array_t                      *a;
    router_var_ctx_t                 *ctx;

    kv = ngx_split(gateway_conf->var, ':');

    var = ngx_http_add_variable(cf, &kv.key,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL)
        return NGX_CONF_ERROR;

    var->get_handler = ngx_api_gateway_router_var;

    if (var->data == 0) {

        a = ngx_array_create(cf->pool, 10, sizeof(router_var_ctx_t));
        if (a == NULL)
            return NGX_CONF_ERROR;

        var->data = (uintptr_t) a;
    } else
        a = (ngx_array_t *) var->data;

    ctx = ngx_array_push(a);
    if (ctx == NULL)
        return NGX_CONF_ERROR; 

    ctx->alcf = alcf;
    ctx->gateway_conf = gateway_conf;

    if (kv.value.data == NULL)
        return NGX_CONF_OK;

    shmsize = ngx_parse_size(&kv.value);
    if (shmsize == NGX_ERROR)
        return NGX_CONF_ERROR; 

    gateway_conf->zone = ngx_shared_memory_add(cf, &kv.key, shmsize,
        &ngx_http_api_gateway_module);

    if (gateway_conf->zone == NULL)
        return NGX_CONF_ERROR;

    gateway_conf->zone->data = gateway_conf;
    gateway_conf->zone->init = ngx_api_gateway_router_init_shtrie;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_api_gateway_router_init_shtrie(ngx_shm_zone_t *zone, void *old)
{
    ngx_http_api_gateway_conf_t   *ctx, *octx;
    ngx_http_api_gateway_shctx_t  *sh;
    ngx_slab_pool_t               *slab;
    ngx_trie_t                    *prev = NULL, *trie;
    uint32_t                       hash = 0;
    
    ctx = zone->data;

    slab = (ngx_slab_pool_t *) zone->shm.addr;

    if (old != NULL) {
        
        octx = old;
        sh = slab->data;

        hash = ngx_trie_hash(ctx->map.trie);

        if (octx->map.trie->hash == hash) {

            ctx->sh = sh;
            ctx->map = sh->map;

            return NGX_OK;
        }

        prev = sh->map.trie;

    } else {

        sh = ngx_slab_calloc(slab, sizeof(ngx_http_api_gateway_shctx_t));
        if (sh == NULL)
            return NGX_ERROR;

        sh->slab = slab;
        slab->data = sh;

        hash = ngx_trie_hash(ctx->map.trie);
    }

    trie = ngx_trie_shm_init(ctx->map.trie, slab);
    if (trie == NULL)
        return NGX_ERROR;

    if (prev != NULL) {
        // replace incapsulated data and free old
        ngx_trie_free(ngx_trie_swap(prev, trie));
    } else
        sh->map.trie = trie;

    ctx->sh = sh;
    ctx->map = sh->map;
    sh->map.trie->hash = hash;

    return NGX_OK;
}
