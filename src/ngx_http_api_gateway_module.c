/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_http.h>
#include <assert.h>

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


static char *
ngx_api_gateway_route(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_http_module_t ngx_http_api_gateway_ctx = {
    ngx_api_gateway_pre_conf,          /* preconfiguration */
    ngx_api_gateway_post_conf,         /* postconfiguration */
    ngx_api_gateway_create_main_conf,  /* create main configuration */
    ngx_api_gateway_init_main_conf,    /* init main configuration */
    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */
    ngx_api_gateway_create_loc_conf,   /* create location configuration */
    ngx_api_gateway_merge_loc_conf     /* merge location configuration */
};


#define NGX_ALL_CONF (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)


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

    { ngx_string("api_gateway_router_dynamic"),
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

    { ngx_string("route_conf"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_api_gateway_route,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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
    ngx_http_api_gateway_loc_conf_t  *alcf;

    alcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_gateway_loc_conf_t));
    if (alcf == NULL)
        return NULL;

    if (NGX_ERROR == ngx_array_init(&alcf->entries, cf->pool,
                                    10, sizeof(ngx_http_api_gateway_router_t)))
        return NULL;

    return alcf;
}


static char *
ngx_api_gateway_merge_loc_conf(ngx_conf_t *cf,
    void *prev, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *parent;
    ngx_http_api_gateway_loc_conf_t  *child;
    ngx_http_api_gateway_router_t    *router, *c;
    ngx_uint_t                        j;

    parent = prev;
    child = conf;

    router = parent->entries.elts;

    for (j = 0; j < parent->entries.nelts; j++) {
        c = ngx_array_push(&child->entries);
        if (c == NULL)
            return NGX_CONF_ERROR;
        *c = router[j];
    }

    return NGX_CONF_OK;
}


static void
ngx_http_api_gateway_handler_sync(ngx_event_t *ev)
{
    ngx_api_gateway_main_conf_t  *amcf;

    amcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_http_api_gateway_module);

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    ngx_api_gateway_sync(amcf);

    ngx_add_timer(ev, amcf->interval);
}


static void
ngx_http_api_gateway_handler_update(ngx_event_t *ev)
{
    extern ngx_module_t ngx_template_module;

    ngx_template_main_conf_t     *tmcf;
    ngx_api_gateway_main_conf_t  *amcf;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
        ngx_template_module);
    amcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_http_api_gateway_module);

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    ngx_api_gateway_update(tmcf, amcf);

    ngx_add_timer(ev, 5000);
}


static ngx_int_t
ngx_http_api_gateway_init_worker(ngx_cycle_t *cycle)
{
    ngx_api_gateway_main_conf_t  *amcf;
    ngx_event_t                  *ev;
    static ngx_connection_t       c = { .fd = -1 };

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    amcf = ngx_http_cycle_get_module_main_conf(cycle,
            ngx_http_api_gateway_module);

    if (amcf == NULL || amcf->templates.nelts == 0)
        return NGX_OK;

    if (ngx_worker == 0) {

        // sync event

        ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (ev == NULL)
            return NGX_ERROR;

        ev->log = cycle->log;
        ev->data = &c;
        ev->handler = ngx_http_api_gateway_handler_sync;

        ngx_add_timer(ev, 0);
    }

    // check changes event

    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL)
        return NGX_ERROR;

    ev->log = cycle->log;
    ev->data = &c;
    ev->handler = ngx_http_api_gateway_handler_update;

    ngx_add_timer(ev, 5000);

    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_router_map(ngx_http_request_t *r,
    ngx_http_api_gateway_router_t *router,
    ngx_http_variable_value_t *retval)
{
    ngx_api_gateway_main_conf_t     *amcf;
    ngx_variable_value_t            *request_path_var;
    ngx_str_t                        path;
    ngx_str_t                        upstream;
    ngx_http_api_gateway_mapping_t  *map = &router->map;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_gateway_module);

    if (router->sh != NULL)
        map = &router->sh->map;

    switch (ngx_api_gateway_router_match(r->pool, map, &r->uri,
            &path, &upstream)) {

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
    ngx_http_api_gateway_router_t    *router;
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

            if (ngx_api_gateway_router_map(r, ctx[j].router, v) == NGX_OK)
                return NGX_OK;
        }
    }

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_router_init_shm(ngx_shm_zone_t *zone, void *old);


static char *
ngx_api_gateway_router_add_variable(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *alcf = conf;
    ngx_http_api_gateway_router_t    *router = data;
    ngx_http_variable_t              *var;
    ngx_keyval_t                      kv;
    ssize_t                           size;
    ngx_array_t                      *a;
    router_var_ctx_t                 *ctx;
    ngx_str_t                         zone_name;
    ngx_str_t                         varname;

    kv = ngx_split(router->var, ':');

    router->var = varname = kv.key;

    var = ngx_http_add_variable(cf, &varname,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE);
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

    router->cycle = cf->cycle;

    ctx->alcf = alcf;
    ctx->router = router;

    if (kv.value.data == NULL) {

        if (router->dynamic) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "dynamic router requires shared zone, var=$%V", &router->var);
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    size = ngx_parse_size(&kv.value);
    if (size == NGX_ERROR)
        return NGX_CONF_ERROR; 

    zone_name.data = ngx_pcalloc(cf->pool, varname.len + 32);
    if (zone_name.data == NULL)
        return NGX_CONF_ERROR;
    zone_name.len = ngx_sprintf(zone_name.data, "$%V(%0Xd)", &varname,
        router->dynamic ? 0 : zone_name.data) - zone_name.data;

    router->zone = ngx_shared_memory_add(cf, &zone_name, size,
        &ngx_http_api_gateway_module);

    if (router->zone == NULL)
        return NGX_CONF_ERROR;

    router->zone->noreuse = !router->dynamic;
    router->zone->data = router;
    router->zone->init = ngx_api_gateway_router_init_shm;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_api_gateway_router_init_shm(ngx_shm_zone_t *zone, void *old)
{
    ngx_http_api_gateway_router_t  *ctx;
    ngx_http_api_gateway_shctx_t   *sh;
    ngx_slab_pool_t                *slab;

    ctx = zone->data;

    slab = (ngx_slab_pool_t *) zone->shm.addr;

    if (old != NULL) {

        ctx->sh = slab->data;
        return NGX_OK;
    }

    assert(ctx->sh == NULL);
    
    sh = ngx_slab_calloc(slab, sizeof(ngx_http_api_gateway_shctx_t));
    if (sh == NULL)
        return NGX_ERROR;

    sh->slab = slab;
    slab->data = sh;

    ctx->sh = sh;

    ngx_api_gateway_router_shm_init(ctx, sh);

    return NGX_OK;
}


static ngx_str_t
get_var(ngx_http_request_t *r, const char *v)
{
    ngx_str_t                   var = { ngx_strlen(v), (u_char *) v };
    ngx_http_variable_value_t  *value;
    u_char                     *dst, *src;
    ngx_str_t                   retval = ngx_null_string;

    value = ngx_http_get_variable(r, &var, ngx_hash_key(var.data, var.len));

    if (value->not_found)
        return retval;

    src = value->data;

    dst = ngx_pcalloc(r->pool, value->len + 1);
    if (dst == NULL)
        return retval;

    retval.data = dst;

    ngx_unescape_uri(&dst, &src, value->len, 0);

    retval.len = dst - retval.data;
    
    return retval;
}


static ngx_int_t
send_response(ngx_http_request_t *r, ngx_uint_t status,
    const char *text)
{
    ngx_http_complex_value_t  cv;

    static ngx_str_t TEXT_PLAIN = ngx_string("text/plain");

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.len = strlen(text);
    cv.value.data = (u_char *) text;

    return ngx_http_send_response(r, status, &TEXT_PLAIN, &cv);
}


static ngx_int_t
send_header(ngx_http_request_t *r, ngx_uint_t status)
{
    return send_response(r, status, "");
}


static ngx_int_t
send_no_content(ngx_http_request_t *r)
{
    ngx_http_complex_value_t  cv;

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    r->header_only = 1;

    return ngx_http_send_response(r, NGX_HTTP_NO_CONTENT, NULL, &cv);
}


static ngx_int_t
ngx_api_gateway_route_set_handler(ngx_http_request_t *r)
{
    ngx_api_gateway_main_conf_t     *amcf;
    ngx_str_t                        backend;
    ngx_str_t                        api;
    ngx_str_t                        var;
    ngx_http_api_gateway_router_t  **router;
    ngx_uint_t                       j;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_gateway_module);

    backend = get_var(r, "arg_backend");
    api = get_var(r, "arg_api");
    var = get_var(r, "arg_var");

    if (backend.data == NULL || api.data == NULL || var.data == NULL)
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "backend, api and var arguments required");

    if (var.data[0] != '$')
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "backend var value, required: var=$xxx");

    router = amcf->routers.elts;

    var.data++;
    var.len--;

    for (j = 0; j < amcf->routers.nelts; j++) {

        if (router[j]->var.len < var.len)
            continue;

        if (ngx_memn2cmp(router[j]->var.data, var.data,
                         var.len, var.len) == 0) {

            switch (ngx_api_gateway_router_set(router[j], backend, api)) {
                case NGX_OK:
                    return send_no_content(r);
                case NGX_DECLINED:
                    return send_header(r, NGX_HTTP_NOT_MODIFIED);
                case NGX_ABORT:
                    return send_response(r, NGX_HTTP_BAD_REQUEST,
                        "router is not dynamic");
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return send_response(r, NGX_HTTP_NOT_FOUND, "router not found");
}


static ngx_int_t
ngx_api_gateway_route_delete_handler(ngx_http_request_t *r)
{
    ngx_api_gateway_main_conf_t     *amcf;
    ngx_str_t                        api;
    ngx_str_t                        var;
    ngx_http_api_gateway_router_t  **router;
    ngx_uint_t                       j;

    amcf = ngx_http_get_module_main_conf(r, ngx_http_api_gateway_module);

    api = get_var(r, "arg_api");
    var = get_var(r, "arg_var");

    if (api.data == NULL || var.data == NULL)
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "api and var arguments required");

    if (var.data[0] != '$')
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "backend var value, required: var=$xxx");

    router = amcf->routers.elts;

    var.data++;
    var.len--;

    for (j = 0; j < amcf->routers.nelts; j++) {

        if (router[j]->var.len < var.len)
            continue;

        if (ngx_memn2cmp(router[j]->var.data, var.data,
                         var.len, var.len) == 0) {

            switch (ngx_api_gateway_router_delete(router[j], api)) {
                case NGX_OK:
                    return send_no_content(r);
                case NGX_DECLINED:
                    return send_header(r, NGX_HTTP_NOT_MODIFIED);
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return send_response(r, NGX_HTTP_NOT_FOUND, "router not found");
}


static ngx_int_t
ngx_api_gateway_route_handler(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_POST)
        return ngx_api_gateway_route_set_handler(r);

    if (r->method == NGX_HTTP_DELETE)
        return ngx_api_gateway_route_delete_handler(r);

    return send_response(r, NGX_HTTP_NOT_ALLOWED, "method not allowed");
}


static char *
ngx_api_gateway_route(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_api_gateway_route_handler;

    return NGX_CONF_OK;
}
