/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_http.h>
#include <ngx_stream.h>

#include "ngx_api_gateway_cfg.h"


static void *
ngx_dynamic_conf_create_main_conf(ngx_conf_t *cf);

static char *
ngx_dynamic_conf_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_int_t
ngx_dynamic_conf_init_worker(ngx_cycle_t *cycle);


static ngx_int_t
ngx_dynamic_conf_post_conf(ngx_conf_t *cf);


static ngx_http_module_t ngx_dynamic_conf_ctx = {
    NULL,                               /* preconfiguration */
    ngx_dynamic_conf_post_conf,         /* postconfiguration */
    ngx_dynamic_conf_create_main_conf,  /* create main configuration */
    ngx_dynamic_conf_init_main_conf,    /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};


static char *
ngx_dynamic_conf_upstream_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *
ngx_dynamic_conf_upstream_delete(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *
ngx_dynamic_conf_upstream_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


typedef struct {
    ngx_slab_pool_t  *slab;
    ngx_queue_t       upstreams;
} ngx_dynamic_conf_shm_t;


typedef struct {
    size_t                   size;
    ngx_shm_zone_t          *zone;
    ngx_dynamic_conf_shm_t  *shm;
    ngx_url_t                default_addr;
    ngx_cycle_t             *cycle;
} ngx_dynamic_conf_main_conf_t;


typedef enum {
    http = 0,
    stream
} upstream_type;

typedef enum {
    roundrobin = 0,
    leastconn,
    iphash
} balancer_type;


static ngx_str_t methods[] = {
    ngx_string(""),
    ngx_string("least_conn;"),
    ngx_string("ip_hash;")
};


typedef struct {
    upstream_type       type;
    ngx_str_t           name;
    ngx_int_t           keepalive;
    ngx_int_t           keepalive_requests;
    ngx_int_t           keepalive_timeout;
    balancer_type       method;
    ngx_int_t           max_fails;
    ngx_int_t           max_conns;
    time_t              fail_timeout;
    ngx_int_t           dns_update;
    ngx_int_t           count;
    void               *peers;
    ngx_shm_zone_t     *zone;
    ngx_queue_t         queue;
} ngx_dynamic_upstream_t;


static ngx_command_t  ngx_dynamic_conf_commands[] = {

    { ngx_string("dynamic_conf_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_dynamic_conf_main_conf_t, size),
      NULL },

    { ngx_string("upstream_add"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_conf_upstream_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_delete"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_conf_upstream_delete,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_list"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_conf_upstream_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command

};


ngx_module_t ngx_dynamic_conf_module = {
    NGX_MODULE_V1,
    &ngx_dynamic_conf_ctx ,            /* module context */
    ngx_dynamic_conf_commands,         /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_dynamic_conf_init_worker,      /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_dynamic_conf_create_main_conf(ngx_conf_t *cf)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;
    static ngx_str_t noaddr = ngx_string("0.0.0.0:1");

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_dynamic_conf_main_conf_t));
    if (dmcf == NULL)
        return NULL;

    dmcf->size = NGX_CONF_UNSET_SIZE;

    dmcf->default_addr.url = noaddr;
    dmcf->default_addr.default_port = 80;
    dmcf->default_addr.no_resolve = 1;

    ngx_parse_url(cf->pool, &dmcf->default_addr);

    dmcf->cycle = cf->cycle;

    return dmcf;
}


static ngx_int_t
upstream_add(ngx_api_gateway_cfg_upstream_t *u, void *ctxp)
{
    ngx_dynamic_conf_main_conf_t  *dmcf = ctxp;
    ngx_dynamic_upstream_t        *sh;

    sh = ngx_slab_calloc_locked(dmcf->shm->slab,
        sizeof(ngx_dynamic_upstream_t));
    if (sh == NULL) {
        ngx_log_error(NGX_LOG_EMERG, dmcf->cycle->log, 0,
                      "ngx_upstream_load() alloc failed");
        return NGX_ERROR;
    }

    sh->name.data = ngx_slab_alloc_locked(dmcf->shm->slab, u->name.len);
    if (sh->name.data == NULL) {
        ngx_log_error(NGX_LOG_EMERG, dmcf->cycle->log, 0,
                      "ngx_upstream_load() alloc failed");
        return NGX_ERROR;
    }
    sh->name.len = u->name.len;
    ngx_memcpy(sh->name.data, u->name.data, sh->name.len);

    sh->type = u->type;
    sh->method = u->method;
    sh->keepalive = u->keepalive;
    sh->keepalive_requests = u->keepalive_requests;
    sh->keepalive_timeout = u->keepalive_timeout;
    sh->max_fails = u->max_fails;
    sh->max_conns = u->max_conns;
    sh->fail_timeout = u->fail_timeout;
    sh->dns_update = u->dns_update;

    sh->zone = dmcf->zone;

    ngx_queue_insert_tail(&dmcf->shm->upstreams, &sh->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_init_shm_zone(ngx_shm_zone_t *zone, void *old)
{
    ngx_dynamic_conf_main_conf_t  *dmcf = zone->data;
    ngx_slab_pool_t               *slab;

    slab = (ngx_slab_pool_t *) zone->shm.addr;

    if (old) {
        dmcf->shm = slab->data;
    } else {

        dmcf->shm = ngx_slab_calloc(slab, sizeof(ngx_dynamic_conf_shm_t));
        if (dmcf->shm == NULL)
            return NGX_ERROR;

        dmcf->shm->slab = slab;

        slab->data = dmcf->shm;

        ngx_queue_init(&dmcf->shm->upstreams);

        ngx_api_gateway_cfg_upstreams(dmcf->cycle, upstream_add, dmcf);
    }

    return NGX_OK;
}


static ngx_str_t
ngx_str_shm(ngx_slab_pool_t *slab, ngx_str_t *s)
{
    ngx_str_t  sh;
    sh.data = ngx_slab_alloc_locked(slab, s->len);
    if (sh.data != NULL) {
        ngx_memcpy(sh.data, s->data, s->len);
        sh.len = s->len;
    }
    return sh;
}


static ngx_str_t *
ngx_str_shm_copy(ngx_slab_pool_t *slab, ngx_str_t *s)
{
    ngx_str_t  *sh;
    sh = ngx_slab_alloc_locked(slab, sizeof(ngx_str_t));
    if (sh != NULL) {
        *sh = ngx_str_shm(slab, s);
        if (sh->data == NULL) {
            ngx_slab_free_locked(slab, sh);
            sh = NULL;
        }
    }
    return sh;
}


static ngx_int_t
ngx_upstream_add(ngx_dynamic_conf_main_conf_t *dmcf,
    ngx_dynamic_upstream_t u)
{
    ngx_dynamic_upstream_t         *sh;
    ngx_queue_t                    *q;
    ngx_core_conf_t                *ccf;
    ngx_api_gateway_cfg_upstream_t  cfg;

    ccf = (ngx_core_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    ngx_shmtx_lock(&dmcf->shm->slab->mutex);

    for (q = ngx_queue_head(&dmcf->shm->upstreams);
         q != ngx_queue_sentinel(&dmcf->shm->upstreams);
         q = ngx_queue_next(q))
    {
        sh = ngx_queue_data(q, ngx_dynamic_upstream_t, queue);

        if (u.type == sh->type
            && ngx_memn2cmp(u.name.data, sh->name.data,
                            u.name.len, sh->name.len) == 0) {
            ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
            return NGX_DECLINED;
        }
    }

    sh = ngx_slab_alloc_locked(dmcf->shm->slab,
        sizeof(ngx_dynamic_upstream_t));
    if (sh == NULL) {
        ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
        return NGX_ERROR;
    }

    *sh = u;

    sh->name = ngx_str_shm(dmcf->shm->slab, &u.name);
    if (sh->name.data == NULL) {
        ngx_slab_free_locked(dmcf->shm->slab, sh);
        ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
        return NGX_ERROR;
    }
    sh->count = ccf->worker_processes;
    sh->peers = NULL;

    ngx_queue_insert_tail(&dmcf->shm->upstreams, &sh->queue);

    cfg.name = u.name;
    cfg.type = u.type;
    cfg.method = u.method;
    cfg.keepalive = u.keepalive;
    cfg.keepalive_requests = u.keepalive_requests;
    cfg.keepalive_timeout = u.keepalive_timeout;
    cfg.max_fails = u.max_fails;
    cfg.max_conns = u.max_conns;
    cfg.fail_timeout = u.fail_timeout;
    cfg.dns_update = u.dns_update;

    ngx_api_gateway_cfg_upstream_add(&cfg);

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "[%s] add upstream '%V'", u.type == http ? "http" : "stream", &u.name);

    return NGX_OK;
}


static ngx_int_t
ngx_upstream_delete(ngx_dynamic_conf_main_conf_t *dmcf,
    ngx_dynamic_upstream_t u)
{
    ngx_dynamic_upstream_t  *sh;
    ngx_queue_t             *q;
    ngx_core_conf_t         *ccf;

    ccf = (ngx_core_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    ngx_shmtx_lock(&dmcf->shm->slab->mutex);

    for (q = ngx_queue_head(&dmcf->shm->upstreams);
         q != ngx_queue_sentinel(&dmcf->shm->upstreams);
         q = ngx_queue_next(q))
    {
        sh = ngx_queue_data(q, ngx_dynamic_upstream_t, queue);

        if (u.type == sh->type
            && ngx_memn2cmp(u.name.data, sh->name.data,
                            u.name.len, sh->name.len) == 0
            && sh->count == 0) {

            sh->count = -ccf->worker_processes;

            ngx_api_gateway_cfg_upstream_delete(u.name, u.type);

            ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                "[%s] delete upstream '%V'",
                u.type == http ? "http" : "stream", &u.name);

            return NGX_OK;
        }
    }

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    return NGX_DECLINED;
}


static char *
ngx_dynamic_conf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_dynamic_conf_main_conf_t  *dmcf = conf;

    static ngx_str_t  mod = ngx_string("ngx_dynamic_conf");

    ngx_conf_init_size_value(dmcf->size, 8 * 1024 * 1024);

    dmcf->zone = ngx_shared_memory_add(cf, &mod, dmcf->size,
        &ngx_dynamic_conf_module);
    if (dmcf->zone == NULL)
        return NGX_CONF_ERROR;

    dmcf->zone->init = ngx_init_shm_zone;
    dmcf->zone->data = dmcf;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_dynamic_conf_post_conf(ngx_conf_t *cf)
{
    ngx_thread_pool_add(cf, NULL);
    return NGX_OK;
}


static ngx_flag_t
ngx_http_upstream_exists(ngx_dynamic_upstream_t *u)
{
    ngx_http_upstream_main_conf_t   *umcf;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_uint_t                       i;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (ngx_memn2cmp(u->name.data, uscfp[i]->host.data,
                         u->name.len, uscfp[i]->host.len) == 0)
            return 1;
    }

    return 0;
}


static ngx_flag_t
ngx_stream_upstream_exists(ngx_dynamic_upstream_t *u)
{
    ngx_stream_upstream_main_conf_t   *umcf;
    ngx_stream_upstream_srv_conf_t   **uscfp;
    ngx_uint_t                         i;

    umcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
        ngx_stream_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (ngx_memn2cmp(u->name.data, uscfp[i]->host.data,
                         u->name.len, uscfp[i]->host.len) == 0)
            return 1;
    }

    return 0;
}


static ngx_conf_t *
get_upstream_conf(ngx_dynamic_upstream_t *u)
{
    ngx_pool_t       *temp_pool;
    ngx_conf_t       *cf;
    ngx_cycle_t      *cycle = (ngx_cycle_t *) ngx_cycle;
    ngx_buf_t        *b;
    ngx_conf_file_t  *conf_file;

    temp_pool = ngx_create_pool(1024, cycle->log);
    if (temp_pool == NULL)
        return NULL;

    cf = ngx_pcalloc(temp_pool, sizeof(ngx_conf_t));
    if (cf == NULL)
        goto nomem;

    cf->temp_pool = temp_pool;
    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    cf->name = "ngx_dynamic_conf";
    cf->handler = NULL;
    cf->handler_conf = NULL;
    cf->pool = cycle->pool;
    cf->cycle = cycle;
    cf->log = cycle->log;
    cf->args = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (cf->args == NULL)
        goto nomem;

    conf_file = ngx_pcalloc(cf->temp_pool, sizeof(ngx_conf_file_t));
    if (conf_file == NULL)
        goto nomem;

    b = ngx_pcalloc(cf->temp_pool, sizeof(ngx_buf_t));
    if (b == NULL)
        goto nomem;

    b->start = ngx_palloc(cf->pool, ngx_pagesize * 10);
    if (b->start == NULL)
        goto nomem;

    b->pos = b->start;
    b->last = ngx_snprintf(b->start, ngx_pagesize * 10,
            "upstream %V {"
            "%V"
            "keepalive %d;"
            "keepalive_requests %d;"
            "keepalive_timeout %d;"
            "dynamic_state_file %V.peers;"
            "dns_update %d;"
            "}}", &u->name, &methods[u->method],
            u->keepalive, u->keepalive_requests, u->keepalive_timeout,
            &u->name,
            u->dns_update);
    b->end = b->last;
    b->temporary = 1;

    conf_file->file.fd = 0;
    conf_file->file.name = u->name;
    conf_file->line = 0;

    cf->conf_file = conf_file;
    cf->conf_file->buffer = b;

    return cf;

nomem:

    ngx_destroy_pool(temp_pool);
    return NULL;
}


static void
ngx_slab_free_safe(ngx_slab_pool_t *shpool, void *p)
{
    if (p != NULL)
        ngx_slab_free_locked(shpool, p);
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_copy_peer(ngx_slab_pool_t *slab,
    ngx_http_upstream_rr_peer_t *src)
{
    ngx_http_upstream_rr_peer_t  *dst;

    dst = ngx_slab_alloc_locked(slab, sizeof(ngx_http_upstream_rr_peer_t));
    if (dst == NULL)
        return NULL;

    ngx_memcpy(dst, src, sizeof(ngx_http_upstream_rr_peer_t));

    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    dst->sockaddr = ngx_slab_alloc_locked(slab, src->socklen);
    if (dst->sockaddr == NULL)
        goto failed;

    ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);

    dst->name = ngx_str_shm(slab, &src->name);
    if (dst->name.data == NULL)
        goto failed;

    dst->server = ngx_str_shm(slab, &src->server);
    if (dst->server.data == NULL)
        goto failed;

    return dst;

failed:

    ngx_slab_free_safe(slab, dst->server.data);
    ngx_slab_free_safe(slab, dst->name.data);
    ngx_slab_free_safe(slab, dst->sockaddr);
    ngx_slab_free_safe(slab, dst);

    return NULL;
}


static ngx_http_upstream_rr_peers_t *
ngx_http_upstream_copy_peers(ngx_slab_pool_t *slab, ngx_str_t *name,
    ngx_http_upstream_rr_peers_t *src)
{
    ngx_http_upstream_rr_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peers_t  *dst;

    dst = ngx_slab_alloc_locked(slab, sizeof(ngx_http_upstream_rr_peers_t));
    if (dst == NULL)
        return NULL;

    ngx_memcpy(dst, src, sizeof(ngx_http_upstream_rr_peers_t));

    dst->shpool = slab;
    dst->name = name;

    for (peerp = &dst->peer; *peerp; peerp = &peer->next) {

        peer = ngx_http_upstream_copy_peer(slab, *peerp);
        if (peer == NULL)
            return NULL;

        *peerp = peer;
    }

    if (src->next != NULL) {

        dst->next = ngx_http_upstream_copy_peers(slab, name, src->next);
        if (dst->next == NULL)
            return NULL;
    }

    return dst;
}


static ngx_http_upstream_rr_peers_t *
ngx_http_upstream_copy(ngx_slab_pool_t *slab,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_str_t                     *name;
    ngx_http_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    name = ngx_str_shm_copy(slab, peers->name);
    if (name == NULL)
        return NULL;

    return ngx_http_upstream_copy_peers(slab, name, peers);
}


static ngx_int_t
ngx_http_upstream_new(ngx_dynamic_upstream_t *u)
{
    ngx_http_upstream_main_conf_t     *umcf;
    ngx_http_upstream_srv_conf_t      *uscf, **uscfp;
    ngx_conf_t                        *cf;
    ngx_http_conf_ctx_t                ctx;
    ngx_slab_pool_t                   *slab;

    slab = (ngx_slab_pool_t *) u->zone->shm.addr;

    cf = get_upstream_conf(u);
    if (cf == NULL)
        return NGX_ERROR;

    ngx_memcpy(&ctx, ngx_cycle->conf_ctx[ngx_http_module.index],
        sizeof(ngx_http_conf_ctx_t));
    cf->ctx = &ctx;

    if (ngx_conf_parse(cf, NULL) == NGX_CONF_ERROR) {
        ngx_destroy_pool(cf->temp_pool);
        return NGX_ERROR;
    }

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;
    uscf = uscfp[umcf->upstreams.nelts - 1];

    if (uscf->peer.init_upstream(cf, uscf) == NGX_ERROR) {
        umcf->upstreams.nelts--;
        ngx_destroy_pool(cf->temp_pool);
        return NGX_ERROR;
    }

    if (u->peers == NULL) {
        u->peers = ngx_http_upstream_copy(slab, uscf);
        if (u->peers == NULL)
            return NGX_ERROR;
    }

    uscf->peer.data = u->peers;
    uscf->shm_zone = u->zone;

    ngx_destroy_pool(cf->temp_pool);

    return NGX_OK;
}


static ngx_stream_upstream_rr_peer_t *
ngx_stream_upstream_copy_peer(ngx_slab_pool_t *slab,
    ngx_stream_upstream_rr_peer_t *src)
{
    ngx_stream_upstream_rr_peer_t  *dst;

    dst = ngx_slab_alloc_locked(slab, sizeof(ngx_stream_upstream_rr_peer_t));
    if (dst == NULL)
        return NULL;

    ngx_memcpy(dst, src, sizeof(ngx_stream_upstream_rr_peer_t));

    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    dst->sockaddr = ngx_slab_alloc_locked(slab, src->socklen);
    if (dst->sockaddr == NULL)
        goto failed;

    ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);

    dst->name = ngx_str_shm(slab, &src->name);
    if (dst->name.data == NULL)
        goto failed;

    dst->server = ngx_str_shm(slab, &src->server);
    if (dst->server.data == NULL)
        goto failed;

    return dst;

failed:

    ngx_slab_free_safe(slab, dst->server.data);
    ngx_slab_free_safe(slab, dst->name.data);
    ngx_slab_free_safe(slab, dst->sockaddr);
    ngx_slab_free_safe(slab, dst);

    return NULL;
}


static ngx_stream_upstream_rr_peers_t *
ngx_stream_upstream_copy_peers(ngx_slab_pool_t *slab, ngx_str_t *name,
    ngx_stream_upstream_rr_peers_t *src)
{
    ngx_stream_upstream_rr_peer_t   *peer, **peerp;
    ngx_stream_upstream_rr_peers_t  *dst;

    dst = ngx_slab_alloc_locked(slab, sizeof(ngx_stream_upstream_rr_peers_t));
    if (dst == NULL)
        return NULL;

    ngx_memcpy(dst, src, sizeof(ngx_stream_upstream_rr_peers_t));

    dst->shpool = slab;
    dst->name = name;

    for (peerp = &dst->peer; *peerp; peerp = &peer->next) {

        peer = ngx_stream_upstream_copy_peer(slab, *peerp);
        if (peer == NULL)
            return NULL;

        *peerp = peer;
    }

    if (src->next != NULL) {

        dst->next = ngx_stream_upstream_copy_peers(slab, name, src->next);
        if (dst->next == NULL)
            return NULL;
    }

    return dst;
}


static ngx_stream_upstream_rr_peers_t *
ngx_stream_upstream_copy(ngx_slab_pool_t *slab,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_str_t                       *name;
    ngx_stream_upstream_rr_peers_t  *peers;

    peers = uscf->peer.data;

    name = ngx_str_shm_copy(slab, peers->name);
    if (name == NULL)
        return NULL;

    return ngx_stream_upstream_copy_peers(slab, name, peers);
}


static ngx_int_t
ngx_stream_upstream_new(ngx_dynamic_upstream_t *u)
{
    ngx_stream_upstream_main_conf_t  *umcf;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_conf_t                       *cf;
    ngx_stream_conf_ctx_t             ctx;
    ngx_slab_pool_t                  *slab;

    slab = (ngx_slab_pool_t *) u->zone->shm.addr;

    cf = get_upstream_conf(u);
    if (cf == NULL)
        return NGX_ERROR;

    ngx_memcpy(&ctx, ngx_cycle->conf_ctx[ngx_stream_module.index],
        sizeof(ngx_stream_conf_ctx_t));
    cf->ctx = &ctx;

    if (ngx_conf_parse(cf, NULL) == NGX_CONF_ERROR) {
        ngx_destroy_pool(cf->temp_pool);
        return NGX_ERROR;
    }

    umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);

    uscfp = umcf->upstreams.elts;
    uscf = uscfp[umcf->upstreams.nelts - 1];

    if (uscf->peer.init_upstream(cf, uscf) == NGX_ERROR) {
        umcf->upstreams.nelts--;
        ngx_destroy_pool(cf->temp_pool);
        return NGX_ERROR;
    }

    if (u->peers == NULL) {
        u->peers = ngx_stream_upstream_copy(slab, uscf);
        if (u->peers == NULL)
            return NGX_ERROR;
    }

    uscf->peer.data = u->peers;
    uscf->shm_zone = u->zone;

    ngx_destroy_pool(cf->temp_pool);

    return NGX_OK;
}


static void
ngx_http_upstream_delete(ngx_dynamic_upstream_t *u)
{
    ngx_http_upstream_main_conf_t   *umcf;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_uint_t                       i, j;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0, j = 0; i < umcf->upstreams.nelts; i++)
        if (ngx_memn2cmp(u->name.data, uscfp[i]->host.data,
                         u->name.len, uscfp[i]->host.len) != 0)
            uscfp[j++] = uscfp[i];

    umcf->upstreams.nelts = j;
}


static void
ngx_stream_upstream_delete(ngx_dynamic_upstream_t *u)
{
    ngx_stream_upstream_main_conf_t   *umcf;
    ngx_stream_upstream_srv_conf_t   **uscfp;
    ngx_uint_t                         i, j;

    umcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
        ngx_stream_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0, j = 0; i < umcf->upstreams.nelts; i++)
        if (ngx_memn2cmp(u->name.data, uscfp[i]->host.data,
                         u->name.len, uscfp[i]->host.len) != 0)
            uscfp[j++] = uscfp[i];

    umcf->upstreams.nelts = j;
}


static ngx_flag_t
ngx_http_upstream_free(ngx_slab_pool_t *slab, ngx_dynamic_upstream_t *u)
{
    ngx_http_upstream_rr_peers_t  *primary, *peers;
    ngx_http_upstream_rr_peer_t   *peer, *tmp;

    primary = (ngx_http_upstream_rr_peers_t *) u->peers;

    ngx_rwlock_rlock(&primary->rwlock);
    
    for (peers = primary; peers != NULL; peers = peers->next) {

        for (peer = peers->peer; peer != NULL; peer = peer->next) {

            if (peer->conns != 0) {

                ngx_rwlock_unlock(&primary->rwlock);
                return NGX_AGAIN;
            }
        }
    }

    // no references

    for (peers = primary; peers != NULL; peers = peers->next) {

        for (peer = peers->peer; peer != NULL;) {

            tmp = peer;
            peer = peer->next;

            ngx_slab_free_locked(slab, tmp->name.data);
            ngx_slab_free_locked(slab, tmp->server.data);
            ngx_slab_free_locked(slab, tmp->sockaddr);
            ngx_slab_free_locked(slab, tmp);
        }
    }

    primary->peer = NULL;
    primary->single = 0;

    if (primary->next != NULL) {
        ngx_slab_free_locked(slab, primary->next);
        primary->next = NULL;
    }

    // leaked: peers & peers->name

    ngx_rwlock_unlock(&primary->rwlock);

    return NGX_OK;
}


static ngx_flag_t
ngx_stream_upstream_free(ngx_slab_pool_t *slab, ngx_dynamic_upstream_t *u)
{
    ngx_stream_upstream_rr_peers_t  *primary, *peers;
    ngx_stream_upstream_rr_peer_t   *peer, *tmp;

    primary = (ngx_stream_upstream_rr_peers_t *) u->peers;

    ngx_rwlock_rlock(&primary->rwlock);
    
    for (peers = primary; peers != NULL; peers = peers->next) {

        for (peer = peers->peer; peer != NULL; peer = peer->next) {

            if (peer->conns != 0) {

                ngx_rwlock_unlock(&primary->rwlock);
                return NGX_AGAIN;
            }
        }
    }

    // no references

    for (peers = primary; peers != NULL; peers = peers->next) {

        for (peer = peers->peer; peer != NULL;) {

            tmp = peer;
            peer = peer->next;

            ngx_slab_free_locked(slab, tmp->name.data);
            ngx_slab_free_locked(slab, tmp->server.data);
            ngx_slab_free_locked(slab, tmp->sockaddr);
            ngx_slab_free_locked(slab, tmp);
        }
    }

    primary->peer = NULL;
    primary->single = 0;

    if (primary->next != NULL) {
        ngx_slab_free_locked(slab, primary->next);
        primary->next = NULL;
    }

    // leaked: peers & peers->name

    ngx_rwlock_unlock(&primary->rwlock);

    return NGX_OK;
}


typedef ngx_flag_t  (*upstream_exists_pt)(ngx_dynamic_upstream_t *u);
typedef ngx_int_t   (*upstream_new_pt)(ngx_dynamic_upstream_t *u);
typedef void        (*upstream_delete_pt)(ngx_dynamic_upstream_t *u);
typedef ngx_flag_t  (*upstream_free_pt)(ngx_slab_pool_t *slab,
                                        ngx_dynamic_upstream_t *u);

typedef struct {
    upstream_exists_pt  exists;
    upstream_new_pt     new;
    upstream_delete_pt  delete;
    upstream_free_pt    try_free;
} upstream_fun_t;


static upstream_fun_t funcs[] = {

    { ngx_http_upstream_exists,
      ngx_http_upstream_new,
      ngx_http_upstream_delete,
      ngx_http_upstream_free },

    { ngx_stream_upstream_exists,
      ngx_stream_upstream_new,
      ngx_stream_upstream_delete,
      ngx_stream_upstream_free }

};

typedef struct {
    ngx_connection_t               c;
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_flag_t                     init;
} ngx_dynamic_conf_sync_t;


static void
ngx_dynamic_conf_handler_sync(ngx_event_t *ev)
{
    ngx_dynamic_conf_sync_t       *udata;
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_queue_t                   *q;
    ngx_dynamic_upstream_t        *u;
    ngx_flag_t                     exists;

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    udata = ev->data;
    dmcf = udata->dmcf;

    ngx_shmtx_lock(&dmcf->shm->slab->mutex);

    for (q = ngx_queue_head(&dmcf->shm->upstreams);
         q != ngx_queue_sentinel(&dmcf->shm->upstreams);)
    {
        u = ngx_queue_data(q, ngx_dynamic_upstream_t, queue);
        exists = funcs[u->type].exists(u);

        if (udata->init)
            u->zone = dmcf->zone;

        if ((u->count > 0 || udata->init) && !exists) {

            funcs[u->type].new(u);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "[%s] #%d add upstream '%V'",
                u->type == http ? "http" : "stream", ngx_worker, &u->name);

            if (u->count > 0)
                u->count--;

            q = ngx_queue_next(q);

        } else if (u->count < 0 && exists) {

            funcs[u->type].delete(u);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "[%s] #%d delete upstream '%V'",
                u->type == http ? "http" : "stream", ngx_worker, &u->name);

            u->count++;

            q = ngx_queue_next(q);

        } else if (u->count == 0 && !exists) {

            q = ngx_queue_next(q);

            if (funcs[u->type].try_free(dmcf->shm->slab, u) == NGX_OK) {

                ngx_queue_remove(&u->queue);
                ngx_slab_free_locked(dmcf->shm->slab, u);
            } 
        } else {

            q = ngx_queue_next(q);
        }
    }

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    udata->init = 0;

    ngx_add_timer(ev, 1000);
}


static ngx_int_t
ngx_dynamic_conf_init_worker(ngx_cycle_t *cycle)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_dynamic_conf_sync_t       *udata;
    ngx_event_t                   *ev;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    dmcf = ngx_http_cycle_get_module_main_conf(cycle,
        ngx_dynamic_conf_module);

    // sync event

    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL)
        return NGX_ERROR;

    udata = ngx_pcalloc(cycle->pool, sizeof(ngx_dynamic_conf_sync_t));
    if (udata == NULL)
        return NGX_ERROR;

    udata->dmcf = dmcf;
    udata->c.fd = -1;
    udata->init = 1;

    ev->log = cycle->log;
    ev->data = udata;
    ev->handler = ngx_dynamic_conf_handler_sync;

    ngx_dynamic_conf_handler_sync(ev);

    return NGX_OK;
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
    static const char *empty = "";  
    return send_response(r, status, empty);
}


static ngx_str_t
get_var_str(ngx_http_request_t *r, const char *v, const char *def)
{
    ngx_str_t                   var = { ngx_strlen(v), (u_char *) v };
    ngx_http_variable_value_t  *value;
    ngx_str_t                   retval = ngx_null_string;

    value = ngx_http_get_variable(r, &var, ngx_hash_key(var.data, var.len));

    if (value->not_found) {
        retval.data = (u_char *) def;
        if (def != NULL)
            retval.len = strlen(def);
    } else {
        retval.data = value->data;
        retval.len = value->len;
    }

    return retval;
}


static ngx_int_t
get_var_num(ngx_http_request_t *r, const char *v, ngx_int_t def)
{
    ngx_str_t                   var = { ngx_strlen(v), (u_char *) v };
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_variable(r, &var, ngx_hash_key(var.data, var.len));

    if (value->not_found)
        return def;

    return ngx_atoi(value->data, value->len);
}


static ngx_int_t
ngx_dynamic_conf_upstream_add_handler(ngx_http_request_t *r)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_dynamic_upstream_t         u;
    ngx_str_t                      method;

    dmcf = ngx_http_get_module_main_conf(r, ngx_dynamic_conf_module);

    if (r->method != NGX_HTTP_POST)
        return send_header(r, NGX_HTTP_NOT_ALLOWED);

    u.name = get_var_str(r, "arg_name", NULL);
    if (u.name.data == NULL)
        return send_response(r, NGX_HTTP_BAD_REQUEST,  "name required");

    method = get_var_str(r, "arg_method", "roundrobin");
    if (ngx_strncmp(method.data, "roundrobin", method.len) == 0)
        u.method = roundrobin;
    else if (ngx_strncmp(method.data, "leastconn", method.len) == 0)
        u.method = leastconn;
    else if (ngx_strncmp(method.data, "iphash", method.len) == 0)
        u.method = iphash;
    else
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "bad method (roundrobin, leastconn, iphash)");

    u.type = get_var_str(r, "arg_stream", NULL).data != NULL ? stream : http;
    switch (u.type) {
        case http:
            if (!ngx_cycle->conf_ctx[ngx_http_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "http module is not configured");
            break;
        case stream:
            if (!ngx_cycle->conf_ctx[ngx_stream_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "stream module is not configured");
            break;
    }

    u.dns_update = get_var_num(r, "arg_dns_update", 60);
    if (u.dns_update < 1 || u.dns_update > 3600)
        return send_response(r, NGX_HTTP_BAD_REQUEST,
                             "bad dns_update [1,3600]");

    u.keepalive = get_var_num(r, "arg_keepalive", 1);
    if (u.keepalive == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad keepalive");

    u.keepalive_requests = get_var_num(r, "arg_keepalive_requests", 100);
    if (u.keepalive_requests == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad keepalive_requests");

    u.keepalive_timeout = get_var_num(r, "arg_keepalive_timeout", 60000);
    if (u.keepalive_timeout == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad keepalive_timeout");

    u.max_conns = get_var_num(r, "arg_max_conns", 0);
    if (u.max_conns == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad max_conns");

    u.max_fails = get_var_num(r, "arg_max_fails", 0);
    if (u.max_fails == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad max_fails");

    u.fail_timeout = get_var_num(r, "arg_fail_timeout", 0);
    if (u.fail_timeout == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad fail_timeout");

    u.zone = dmcf->zone;

    switch (ngx_upstream_add(dmcf, u)) {
        case NGX_OK:
            return send_header(r, NGX_HTTP_NO_CONTENT);
        case NGX_DECLINED:
            return send_header(r, NGX_HTTP_NOT_MODIFIED);
    }

    return send_response(r, NGX_HTTP_INTERNAL_SERVER_ERROR, "no memory");
}


char *
ngx_dynamic_conf_upstream_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_dynamic_conf_upstream_add_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_dynamic_conf_upstream_delete_handler(ngx_http_request_t *r)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_dynamic_upstream_t         u;
    ngx_str_t                      fname;

    dmcf = ngx_http_get_module_main_conf(r, ngx_dynamic_conf_module);

    if (r->method != NGX_HTTP_DELETE)
        return send_header(r, NGX_HTTP_NOT_ALLOWED);

    u.name = get_var_str(r, "arg_name", NULL);
    if (u.name.data == NULL)
        return send_response(r, NGX_HTTP_BAD_REQUEST,  "name required");

    u.type = get_var_str(r, "arg_stream", NULL).data != NULL ? stream : http;
    switch (u.type) {
        case http:
            if (!ngx_cycle->conf_ctx[ngx_http_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "http module is not configured");
            break;
        case stream:
            if (!ngx_cycle->conf_ctx[ngx_stream_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "stream module is not configured");
            break;
    }

    if (ngx_upstream_delete(dmcf, u) == NGX_OK) {
        fname.data = ngx_pcalloc(r->pool, u.name.len + 8);
        if (fname.data != NULL) {
            fname.len = ngx_snprintf(fname.data, u.name.len + 8,
                                     "%V.peers", &u.name) - fname.data;
            if (ngx_get_full_name(r->pool,
                    (ngx_str_t *) &ngx_cycle->conf_prefix, &fname) == NGX_OK)
                ngx_delete_file(fname.data);
        }
        return send_header(r, NGX_HTTP_NO_CONTENT);
    }
    
    return send_response(r, NGX_HTTP_NOT_FOUND, "upstream not found");
}


char *
ngx_dynamic_conf_upstream_delete(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_dynamic_conf_upstream_delete_handler;

    return NGX_CONF_OK;
}


static ngx_str_t  json = ngx_string("application/json");

static ngx_int_t
ngx_dynamic_conf_upstream_list_handler(ngx_http_request_t *r)
{
    ngx_dynamic_upstream_t        *sh;
    ngx_queue_t                   *q;
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_chain_t                   *out, start;
    off_t                          content_length = 0;
    ngx_int_t                      rc;

    static ngx_str_t upstream_type_text[] = {
        ngx_string("http"),
        ngx_string("stream")
    };

    static ngx_str_t methods_text[] = {
        ngx_string("roundrobin"),
        ngx_string("least_conn"),
        ngx_string("ip_hash")
    };

    dmcf = ngx_http_get_module_main_conf(r, ngx_dynamic_conf_module);

    if (r->method != NGX_HTTP_GET)
        return send_header(r, NGX_HTTP_NOT_ALLOWED);

    ngx_memzero(&start, sizeof(ngx_chain_t));
    out = &start;

    ngx_shmtx_lock(&dmcf->shm->slab->mutex);

    for (q = ngx_queue_head(&dmcf->shm->upstreams);
         q != ngx_queue_sentinel(&dmcf->shm->upstreams);
         q = ngx_queue_next(q))
    {
        sh = ngx_queue_data(q, ngx_dynamic_upstream_t, queue);

        if (sh->count < 0)
            continue;

        out->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (out->next == NULL) {
            ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        out->next->buf = ngx_create_temp_buf(r->pool, 1024);
        if (out->next->buf == NULL) {
            ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        out = out->next;

        out->buf->last = ngx_snprintf(out->buf->start,
            out->buf->end - out->buf->start,
            "{"
                "\"name\":\"%V\","
                "\"type\":\"%V\","
                "\"method\":\"%V\","
                "\"keepalive\":%d,"
                "\"keepalive_requests\":%d,"
                "\"keepalive_timeout\":%d,"
                "\"max_conns\":%d,"
                "\"max_fails\":%d,"
                "\"fail_timeout\":%d,"
                "\"dns_update\":%d"
            "},", &sh->name,
                 &upstream_type_text[sh->type],
                 &methods_text[sh->method],
                 sh->keepalive, sh->keepalive_requests, sh->keepalive_timeout,
                 sh->max_conns, sh->max_fails, sh->fail_timeout,
                 sh->dns_update);

        content_length += out->buf->last - out->buf->start;
    }

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    if (start.next == NULL)
        send_response(r, NGX_HTTP_OK, "[]");

    start.buf = ngx_create_temp_buf(r->pool, 8);
    if (start.buf == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    *start.buf->last++ = '[';
    *(out->buf->last - 1) = ']';

    out->buf->last_in_chain = 1;
    out->buf->last_buf = (r == r->main) ? 1 : 0;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = json;
    r->headers_out.content_length_n = content_length + 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK)
        return rc;

    return ngx_http_output_filter(r, &start);
}


char *
ngx_dynamic_conf_upstream_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_dynamic_conf_upstream_list_handler;

    return NGX_CONF_OK;
}
