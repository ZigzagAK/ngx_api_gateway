/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

extern "C" {

#include <ngx_http.h>
#include <ngx_stream.h>

}

#include "ngx_api_gateway_cfg.h"
#include "ngx_api_gateway_util.h"


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
ngx_dynamic_conf_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


typedef struct {
    ngx_slab_pool_t  *slab;
    ngx_queue_t       upstreams;
} ngx_dynamic_conf_shm_t;


typedef struct {
    size_t                   size;
    ngx_shm_zone_t          *zone;
    ngx_dynamic_conf_shm_t  *shm;
    ngx_cycle_t             *cycle;
} ngx_dynamic_conf_main_conf_t;


static ngx_str_t methods[] = {
    ngx_string(""),
    ngx_string("least_conn;"),
    ngx_string("ip_hash;")
};


static ngx_command_t  ngx_dynamic_conf_commands[] = {

    { ngx_string("upstream_conf_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_dynamic_conf_main_conf_t, size),
      NULL },

    { ngx_string("upstream_conf"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_conf_upstream,
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


typedef struct {
    ngx_str_t     name;
    ngx_int_t     type;
    void         *peers;
    ngx_queue_t   queue;
} ngx_upstream_t;


struct HttpModule {
    typedef ngx_http_upstream_main_conf_t  main;
    typedef ngx_http_upstream_srv_conf_t   srv;
    typedef ngx_http_upstream_rr_peers_t   peers;
    typedef ngx_http_upstream_rr_peer_t    peer;
    typedef ngx_http_conf_ctx_t            ctx;

    static const ngx_module_t  *module;
    static const upstream_type  type;

    static const ngx_uint_t     MODULE_TYPE;
    static const ngx_uint_t     TYPE;

    static ngx_http_upstream_init_pt  init_rr_upstream;

    static main *get_main_conf(volatile ngx_cycle_t *cycle) {
        return (main *) ngx_http_cycle_get_module_main_conf(cycle,
            ngx_http_upstream_module);
    }
};


struct StreamModule {
    typedef ngx_stream_upstream_main_conf_t  main;
    typedef ngx_stream_upstream_srv_conf_t   srv;
    typedef ngx_stream_upstream_rr_peers_t   peers;
    typedef ngx_stream_upstream_rr_peer_t    peer;
    typedef ngx_stream_conf_ctx_t            ctx;

    static const ngx_module_t  *module;
    static const upstream_type  type;

    static const ngx_uint_t     MODULE_TYPE;
    static const ngx_uint_t     TYPE;

    static ngx_stream_upstream_init_pt  init_rr_upstream;

    static main *get_main_conf(volatile ngx_cycle_t *cycle) {
        return (main *) ngx_stream_cycle_get_module_main_conf(cycle,
            ngx_stream_upstream_module);
    }
};


const ngx_module_t  *HttpModule::module = &ngx_http_module;
const upstream_type  HttpModule::type = http;
const ngx_uint_t     HttpModule::MODULE_TYPE = NGX_HTTP_MODULE;
const ngx_uint_t     HttpModule::TYPE = NGX_HTTP_MAIN_CONF;

const ngx_module_t  *StreamModule::module = &ngx_stream_module;
const upstream_type  StreamModule::type = stream;
const ngx_uint_t     StreamModule::MODULE_TYPE = NGX_STREAM_MODULE;
const ngx_uint_t     StreamModule::TYPE = NGX_STREAM_MAIN_CONF;

ngx_http_upstream_init_pt
    HttpModule::init_rr_upstream = ngx_http_upstream_init_round_robin;
ngx_stream_upstream_init_pt
    StreamModule::init_rr_upstream = ngx_stream_upstream_init_round_robin;


static void
ngx_shared_free(ngx_slab_pool_t *shpool, void *p)
{
    if (p != NULL)
        ngx_slab_free_locked(shpool, p);
}


template <class T> static T *
ngx_shared_calloc(ngx_slab_pool_t *shpool, size_t n = 1)
{
    return (T *) ngx_slab_calloc_locked(shpool, sizeof(T) * n);
}


template <class T> static T *
ngx_pool_calloc(ngx_pool_t *pool, size_t n = 1)
{
    return (T *) ngx_pcalloc(pool, sizeof(T) * n);
}


static ngx_str_t
ngx_str_shm(ngx_slab_pool_t *slab, ngx_str_t *s)
{
    ngx_str_t  sh;
    sh.data = ngx_shared_calloc<u_char>(slab, s->len);
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
    sh = ngx_shared_calloc<ngx_str_t>(slab);
    if (sh != NULL) {
        *sh = ngx_str_shm(slab, s);
        if (sh->data == NULL) {
            ngx_shared_free(slab, sh);
            sh = NULL;
        }
    }
    return sh;
}


template <class M> static ngx_upstream_t *
new_shm_upstream(ngx_dynamic_conf_shm_t *cfg, ngx_str_t name)
{
    ngx_upstream_t  *u;

    u = ngx_shared_calloc<ngx_upstream_t>(cfg->slab);
    if (u == NULL)
        goto nomem;
    u->type = M::type;
    u->name = ngx_str_shm(cfg->slab, &name);
    if (u->name.data == NULL)
        goto nomem;
    u->peers = ngx_shared_calloc<typename M::peers>(cfg->slab);
    if (u->peers == NULL)
        goto nomem;

    ngx_queue_insert_tail(&cfg->upstreams, &u->queue);

    return u;

nomem:

    ngx_shared_free(cfg->slab, u->name.data);
    ngx_shared_free(cfg->slab, u->peers);
    ngx_shared_free(cfg->slab, u);

    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "new_shm_upstream() alloc failed");

    return NULL;
}


template <class M> static ngx_upstream_t *
get_shm_upstream(ngx_dynamic_conf_shm_t *cfg, ngx_str_t name)
{
    ngx_queue_t     *q;
    ngx_upstream_t  *u;

    for (q = ngx_queue_head(&cfg->upstreams);
         q != ngx_queue_sentinel(&cfg->upstreams);
         q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_upstream_t, queue);
        if (u->type == M::type
            && ngx_memn2cmp(u->name.data, name.data,
                            u->name.len, name.len) == 0)
            return u;
    }

    return new_shm_upstream<M>(cfg, name);
}


template <class M> static ngx_int_t
del_shm_upstream(ngx_dynamic_conf_shm_t *cfg, ngx_str_t name)
{
    ngx_queue_t     *q;
    ngx_upstream_t  *u;

    for (q = ngx_queue_head(&cfg->upstreams);
         q != ngx_queue_sentinel(&cfg->upstreams);
         q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_upstream_t, queue);
        if (u->type == M::type
            && ngx_memn2cmp(u->name.data, name.data,
                            u->name.len, name.len) == 0) {
            ngx_queue_remove(q);
            ngx_shared_free(cfg->slab, u->name.data);
            ngx_shared_free(cfg->slab, u);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void *
ngx_dynamic_conf_create_main_conf(ngx_conf_t *cf)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;

    dmcf = ngx_pool_calloc<ngx_dynamic_conf_main_conf_t>(cf->pool);
    if (dmcf == NULL)
        return NULL;

    dmcf->size = NGX_CONF_UNSET_SIZE;
    dmcf->cycle = cf->cycle;

    return dmcf;
}


static ngx_int_t
upstream_add(ngx_api_gateway_cfg_upstream_t *u, void *ctxp)
{
    ngx_dynamic_conf_main_conf_t  *dmcf = (ngx_dynamic_conf_main_conf_t *) ctxp;
    ngx_upstream_t                *sh;

    if (u->type == HttpModule::type)
        sh = new_shm_upstream<HttpModule>(dmcf->shm, u->name);
    if (u->type == StreamModule::type)
        sh = new_shm_upstream<StreamModule>(dmcf->shm, u->name);

    return sh != NULL ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_init_shm_zone(ngx_shm_zone_t *zone, void *old)
{
    ngx_dynamic_conf_main_conf_t  *dmcf;
    ngx_slab_pool_t               *slab;

    dmcf = (ngx_dynamic_conf_main_conf_t *) zone->data;
    slab = (ngx_slab_pool_t *) zone->shm.addr;

    dmcf->shm = ngx_shared_calloc<ngx_dynamic_conf_shm_t>(slab);
    if (dmcf->shm == NULL) {
        ngx_log_error(NGX_LOG_EMERG, dmcf->cycle->log, 0,
                          "ngx_init_shm_zone() alloc failed");
        return NGX_ERROR;
    }

    dmcf->shm->slab = slab;

    slab->data = dmcf->shm;

    ngx_queue_init(&dmcf->shm->upstreams);

    ngx_api_gateway_cfg_upstreams(dmcf->cycle, upstream_add, dmcf);

    return NGX_OK;
}


static char *
ngx_dynamic_conf_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_dynamic_conf_main_conf_t  *dmcf = (ngx_dynamic_conf_main_conf_t *) conf;

    static ngx_str_t  mod = ngx_string("ngx_dynamic_conf");

    ngx_conf_init_size_value(dmcf->size, 8 * 1024 * 1024);

    dmcf->zone = ngx_shared_memory_add(cf, &mod, dmcf->size,
        &ngx_dynamic_conf_module);
    if (dmcf->zone == NULL)
        return (char *) NGX_CONF_ERROR;

    dmcf->zone->init = ngx_init_shm_zone;
    dmcf->zone->data = dmcf;
    dmcf->zone->noreuse = 1;

    return (char *) NGX_CONF_OK;
}


static ngx_int_t
ngx_dynamic_conf_post_conf(ngx_conf_t *cf)
{
    ngx_thread_pool_add(cf, NULL);
    return NGX_OK;
}


template <class M> static ngx_conf_t *
get_upstream_conf(ngx_api_gateway_cfg_upstream_t *u)
{
    ngx_pool_t         *temp_pool;
    ngx_conf_t         *cf;
    ngx_cycle_t        *cycle = (ngx_cycle_t *) ngx_cycle;
    ngx_buf_t          *b;
    ngx_conf_file_t    *conf_file;

    temp_pool = ngx_create_pool(1024, cycle->log);
    if (temp_pool == NULL)
        return NULL;

    cf = ngx_pool_calloc<ngx_conf_t>(temp_pool);
    if (cf == NULL)
        goto nomem;

    cf->temp_pool = temp_pool;
    cf->module_type = M::MODULE_TYPE;
    cf->cmd_type = M::TYPE;
    cf->name = (char *) u->name.data;
    cf->handler = NULL;
    cf->handler_conf = NULL;
    cf->pool = cycle->pool;
    cf->cycle = cycle;
    cf->log = cycle->log;
    cf->args = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (cf->args == NULL)
        goto nomem;

    conf_file = ngx_pool_calloc<ngx_conf_file_t>(cf->temp_pool);
    if (conf_file == NULL)
        goto nomem;

    b = ngx_create_temp_buf(cf->temp_pool, ngx_pagesize);
    if (b == NULL)
        goto nomem;

    b->last = ngx_snprintf(b->last, b->end - b->last,
        "upstream %V {"
        "%V"
        "dynamic_state_file %V.peers;",
        &u->name, &methods[u->method], &u->name);
    if (u->dns_update != NGX_DECLINED)
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "dns_update %d;", u->dns_update);
    if (u->keepalive != NGX_DECLINED)
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "keepalive %d;", u->keepalive);
    if (u->keepalive_requests != NGX_DECLINED)
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "keepalive_requests %d;", u->keepalive_requests);
    if (u->keepalive_timeout != NGX_DECLINED)
        b->last = ngx_snprintf(b->last, b->end - b->last,
            "keepalive_timeout %d;", u->keepalive_timeout);
    b->last = ngx_snprintf(b->last, b->end - b->last, "}}");

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


template <class M> static ngx_flag_t
ngx_upstream_exists(ngx_api_gateway_cfg_upstream_t *u)
{
    typename M::main   *umcf;
    typename M::srv   **uscfp;
    ngx_uint_t          i;

    if (u->type != M::type)
        return 0;

    umcf = M::get_main_conf(ngx_cycle);
    uscfp = (typename M::srv **) umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (ngx_memn2cmp(u->name.data, uscfp[i]->host.data,
                         u->name.len, uscfp[i]->host.len) == 0)
            return 1;
    }

    return 0;
}


template <class M> static typename M::peer *
ngx_upstream_copy_peer(ngx_slab_pool_t *slab, typename M::peer *src)
{
    typename M::peer  *dst;

    dst = ngx_shared_calloc<typename M::peer>(slab);
    if (dst == NULL)
        return NULL;

    ngx_memcpy(dst, src, sizeof(typename M::peer));

    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    dst->sockaddr = (sockaddr *) ngx_slab_alloc_locked(slab, src->socklen);
    if (dst->sockaddr == NULL)
        goto nomem;

    ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);

    dst->name = ngx_str_shm(slab, &src->name);
    if (dst->name.data == NULL)
        goto nomem;

    dst->server = ngx_str_shm(slab, &src->server);
    if (dst->server.data == NULL)
        goto nomem;

    return dst;

nomem:

    ngx_shared_free(slab, dst->server.data);
    ngx_shared_free(slab, dst->name.data);
    ngx_shared_free(slab, dst->sockaddr);
    ngx_shared_free(slab, dst);

    return NULL;
}


template <class M> static typename M::peers *
ngx_upstream_copy_peers(ngx_slab_pool_t *slab, ngx_str_t *name,
    typename M::peers *dst, typename M::peers *src)
{
    typename M::peer  *peer, **peerp;

    if (dst == NULL) {
        dst = ngx_shared_calloc<typename M::peers>(slab);
        if (dst == NULL)
            return NULL;
    }

    ngx_memcpy(dst, src, sizeof(typename M::peers));

    dst->shpool = slab;
    dst->name = name;

    for (peerp = &dst->peer; *peerp; peerp = &peer->next) {
        peer = ngx_upstream_copy_peer<M>(slab, *peerp);
        if (peer == NULL)
            return NULL;

        *peerp = peer;
    }

    if (src->next != NULL) {
        dst->next = ngx_upstream_copy_peers<M>(slab, name, NULL, src->next);
        if (dst->next == NULL)
            return NULL;
    }

    return dst;
}


template <class M> static typename M::peers *
ngx_upstream_copy(ngx_slab_pool_t *slab, void *peers,
    typename M::srv *uscf)
{
    ngx_str_t          *name;
    typename M::peers  *src, *dst;

    dst = (typename M::peers *) peers;
    src = (typename M::peers *) uscf->peer.data;

    name = ngx_str_shm_copy(slab, src->name);
    if (name == NULL)
        return NULL;

    return ngx_upstream_copy_peers<M>(slab, name, dst, src);
}


template <class M> static ngx_int_t
ngx_upstream_new(ngx_api_gateway_cfg_upstream_t *u,
    ngx_dynamic_conf_main_conf_t *dmcf)
{
    typename M::main  *umcf;
    typename M::srv   *uscf, **uscfp;
    typename M::ctx    ctx;
    ngx_conf_t        *cf;
    ngx_upstream_t    *sh;
    
    umcf = M::get_main_conf(dmcf->cycle);
    if (umcf == NULL)
        return NGX_OK;

    if (ngx_upstream_exists<M>(u))
        return NGX_DECLINED;

    cf = get_upstream_conf<M>(u);
    if (cf == NULL)
        return NGX_ERROR;

    ngx_memcpy(&ctx, ngx_cycle->conf_ctx[M::module->index],
        sizeof(typename M::ctx));
    cf->ctx = &ctx;

    if (ngx_conf_parse(cf, NULL) == NGX_CONF_ERROR)
        goto fail;

    uscfp = (typename M::srv **) umcf->upstreams.elts;
    uscf = uscfp[umcf->upstreams.nelts - 1];

    if (uscf->peer.init_upstream == NULL)
        uscf->peer.init_upstream = M::init_rr_upstream;

    if (uscf->peer.init_upstream(cf, uscf) == NGX_ERROR) {
        umcf->upstreams.nelts--;
        goto fail;
    }

    ngx_shmtx_lock(&dmcf->shm->slab->mutex);

    sh = get_shm_upstream<M>(dmcf->shm, u->name);
    if (sh != NULL)
        sh->peers = ngx_upstream_copy<M>(dmcf->shm->slab, sh->peers, uscf);

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    if (sh == NULL || sh->peers == NULL) {
        umcf->upstreams.nelts--;
        goto fail;
    }

    uscf->peer.data = sh->peers;
    uscf->shm_zone = dmcf->zone;

    ngx_destroy_pool(cf->temp_pool);

    return NGX_OK;

fail:

    ngx_destroy_pool(cf->temp_pool);

    return NGX_ERROR;
}


template <class M> struct Free {

    static ngx_flag_t
    free(ngx_slab_pool_t *slab, void *p)
    {
        typename M::peers  *primary, *peers;
        typename M::peer   *peer;

        primary = (typename M::peers *) p;

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
        // delete resources

        ngx_shmtx_lock(&slab->mutex);

        for (peers = primary; peers != NULL; peers = peers->next) {
            for (peer = peers->peer; peer != NULL;) {
                typename M::peer  *tmp = peer;
                peer = peer->next;
                ngx_shared_free(slab, tmp->name.data);
                ngx_shared_free(slab, tmp->server.data);
                ngx_shared_free(slab, tmp->sockaddr);
                ngx_shared_free(slab, tmp);
            }
        }

        ngx_shared_free(slab, primary->name->data);
        ngx_shared_free(slab, primary->name);
        ngx_shared_free(slab, primary->next);
        ngx_shared_free(slab, primary);

        ngx_shmtx_unlock(&slab->mutex);

        return NGX_OK;
    }
};


typedef ngx_flag_t (*upstream_free_pt)(ngx_slab_pool_t *slab, void *peers);

typedef struct {
    ngx_connection_t   c;
    ngx_pool_t        *pool;
    upstream_free_pt   free;
    ngx_slab_pool_t   *slab;
    void              *peers;
} free_context_t;


typedef struct {
    ngx_connection_t               c;
    ngx_dynamic_conf_main_conf_t  *dmcf;
} ngx_dynamic_conf_sync_t;


typedef struct {
    ngx_array_t                    upstreams;
    ngx_dynamic_conf_main_conf_t  *dmcf;
} sync_context_t;


static void
try_free(ngx_event_t *ev)
{
    free_context_t  *ctx = (free_context_t *) ev->data;

    if (ctx->free(ctx->slab, ctx->peers) == NGX_OK) {
        ngx_destroy_pool(ctx->pool);
        return;
    }

    ngx_add_timer(ev, 60000);
}


template <class M> static void
free_upstream(ngx_slab_pool_t *slab, void *peers)
{
    ngx_pool_t      *pool;
    free_context_t  *ctx;
    ngx_event_t     *ev;

    pool = ngx_create_pool(256, ngx_cycle->log);
    if (pool == NULL)
        return;

    ctx = ngx_pool_calloc<free_context_t>(pool);
    if (ctx == NULL)
        return;

    ctx->c.fd = -1;
    ctx->pool = pool;
    ctx->slab = slab;
    ctx->free = &Free<M>::free;
    ctx->peers = peers;

    ev = ngx_pool_calloc<ngx_event_t>(pool);
    if (ev == NULL)
        return;

    ev->data = ctx;
    ev->handler = try_free;

    ngx_add_timer(ev, 0);
}


template <class M> static void
ngx_upstream_delete(sync_context_t *ctx)
{
    typename M::main                *umcf;
    typename M::srv                **uscfp;
    ngx_uint_t                       i, j, k;
    ngx_api_gateway_cfg_upstream_t  *u;
    ngx_slab_pool_t                 *slab;

    umcf = M::get_main_conf(ngx_cycle);
    if (umcf == NULL)
        return;

    uscfp = (typename M::srv **) umcf->upstreams.elts;

    u = (ngx_api_gateway_cfg_upstream_t *) ctx->upstreams.elts;

    for (i = 0, j = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->shm_zone == NULL
            || uscfp[i]->shm_zone->tag != &ngx_dynamic_conf_module) {
            uscfp[j++] = uscfp[i];
            continue;
        }
        for (k = 0; k < ctx->upstreams.nelts; k++) {
            if (u[k].type == M::type
                && ngx_memn2cmp(u[k].name.data, uscfp[i]->host.data,
                                u[k].name.len, uscfp[i]->host.len) == 0) {
                uscfp[j++] = uscfp[i];
                break;
            }
        }
        if (k == ctx->upstreams.nelts) {
            slab = ctx->dmcf->shm->slab;
            ngx_shmtx_lock(&slab->mutex);
            if (del_shm_upstream<M>(ctx->dmcf->shm, uscfp[i]->host) == NGX_OK)
                free_upstream<M>(slab, uscfp[i]->peer.data);
            ngx_shmtx_unlock(&slab->mutex);
        }
    }

    umcf->upstreams.nelts = j;
}


static ngx_int_t
add(ngx_api_gateway_cfg_upstream_t *u, void *ctxp)
{
    sync_context_t                  *ctx = (sync_context_t *) ctxp;
    ngx_dynamic_conf_main_conf_t    *dmcf = ctx->dmcf;
    ngx_api_gateway_cfg_upstream_t  *cp;

    cp = (ngx_api_gateway_cfg_upstream_t *) ngx_array_push(&ctx->upstreams);
    if (cp == NULL)
        return NGX_ERROR;

    ngx_memcpy(cp, u, ctx->upstreams.size);
    cp->name = ngx_dupstr(ctx->upstreams.pool, u->name.data, u->name.len);
    if (cp->name.data == NULL)
        return NGX_ERROR;

    if (u->type == HttpModule::type)
        return ngx_upstream_new<HttpModule>(cp, dmcf);
    
    return ngx_upstream_new<StreamModule>(cp, dmcf);
}


static void
ngx_dynamic_conf_handler_sync(ngx_event_t *ev)
{
    ngx_dynamic_conf_sync_t       *udata;
    sync_context_t                 ctx;

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    udata = (ngx_dynamic_conf_sync_t *) ev->data;
    ctx.dmcf = udata->dmcf;
    ctx.upstreams.pool = ngx_create_pool(1024, ngx_cycle->log);

    if (ctx.upstreams.pool == NULL)
        goto settimer;

    if (ngx_array_init(&ctx.upstreams, ctx.upstreams.pool, 10,
            sizeof(ngx_api_gateway_cfg_upstream_t)) == NGX_ERROR)
        goto fail;

    if (ngx_api_gateway_cfg_upstreams(ngx_cycle, add, &ctx) == NGX_ERROR)
        goto fail;

    ngx_upstream_delete<HttpModule>(&ctx);
    ngx_upstream_delete<StreamModule>(&ctx);

fail:

    ngx_destroy_pool(ctx.upstreams.pool);

settimer:

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

    dmcf = (ngx_dynamic_conf_main_conf_t *)
        ngx_http_cycle_get_module_main_conf(cycle, ngx_dynamic_conf_module);

    // sync event

    ev = ngx_pool_calloc<ngx_event_t>(cycle->pool);
    if (ev == NULL)
        return NGX_ERROR;

    udata = ngx_pool_calloc<ngx_dynamic_conf_sync_t>(cycle->pool);
    if (udata == NULL)
        return NGX_ERROR;

    udata->dmcf = dmcf;
    udata->c.fd = -1;

    ev->log = cycle->log;
    ev->data = udata;
    ev->handler = ngx_dynamic_conf_handler_sync;

    ngx_dynamic_conf_handler_sync(ev);

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_conf_upstream_add_handler(ngx_http_request_t *r)
{
    ngx_api_gateway_cfg_upstream_t  u;
    ngx_str_t                       method;
    ngx_uint_t                      rc;
    ngx_str_t                       type;

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

    type = get_var_str(r, "arg_stream", NULL);
    u.type = type.data != NULL ? StreamModule::type : HttpModule::type;

    switch (u.type) {

        case HttpModule::type:

            if (!ngx_cycle->conf_ctx[ngx_http_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "http module is not configured");

            u.keepalive = get_var_num(r, "arg_keepalive", NGX_DECLINED);
            if (u.keepalive == NGX_ERROR)
                return send_response(r, NGX_HTTP_BAD_REQUEST, "bad keepalive");

            u.keepalive_requests = get_var_num(r, "arg_keepalive_requests",
                                               NGX_DECLINED);
            if (u.keepalive_requests == NGX_ERROR)
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "bad keepalive_requests");

            u.keepalive_timeout = get_var_num(r, "arg_keepalive_timeout",
                                              NGX_DECLINED);
            if (u.keepalive_timeout == NGX_ERROR)
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "bad keepalive_timeout");

            break;

        case StreamModule::type:

            if (!ngx_cycle->conf_ctx[ngx_stream_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "stream module is not configured");

            break;
    }

    u.dns_update = get_var_num(r, "arg_dns_update", NGX_DECLINED);
    if (u.dns_update != NGX_DECLINED) {
        if (u.dns_update < 1 || u.dns_update > 3600)
            return send_response(r, NGX_HTTP_BAD_REQUEST,
                                 "bad dns_update [1,3600]");
    }

    u.max_conns = get_var_num(r, "arg_max_conns", 0);
    if (u.max_conns == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad max_conns");

    u.max_fails = get_var_num(r, "arg_max_fails", 0);
    if (u.max_fails == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad max_fails");

    u.fail_timeout = get_var_num(r, "arg_fail_timeout", 0);
    if (u.fail_timeout == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad fail_timeout");

    switch (ngx_api_gateway_cfg_upstream_add(&u)) {

        case NGX_OK:

            rc = NGX_HTTP_NO_CONTENT;
            break;

        case NGX_DECLINED:

            rc = NGX_HTTP_NOT_MODIFIED;
            break;

        case NGX_ERROR:
        default:

            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return send_header(r, rc);
}


static ngx_int_t
ngx_dynamic_conf_upstream_delete_handler(ngx_http_request_t *r)
{
    ngx_str_t     name;
    ngx_str_t     tp;
    ngx_str_t     fname;
    ngx_int_t     type;
    ngx_cycle_t  *cycle = (ngx_cycle_t *) ngx_cycle;

    name = get_var_str(r, "arg_name", NULL);
    if (name.data == NULL)
        return send_response(r, NGX_HTTP_BAD_REQUEST,  "name required");

    tp = get_var_str(r, "arg_stream", NULL);
    type = tp.data != NULL ? StreamModule::type : HttpModule::type;

    switch (type) {

        case HttpModule::type:
            if (!cycle->conf_ctx[ngx_http_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "http module is not configured");
            break;

        case StreamModule::type:
            if (!cycle->conf_ctx[ngx_stream_module.index])
                return send_response(r, NGX_HTTP_BAD_REQUEST,
                    "stream module is not configured");
            break;

    }

    switch (ngx_api_gateway_cfg_upstream_delete(name, type)) {

        case NGX_OK:

            fname.data = ngx_pool_calloc<u_char>(r->pool, name.len + 8);

            if (fname.data != NULL) {

                fname.len = ngx_snprintf(fname.data, name.len + 8,
                                         "%V.peers", &name) - fname.data;
                if (ngx_get_full_name(r->pool, &cycle->conf_prefix, &fname)
                        == NGX_OK)
                    ngx_delete_file(fname.data);
            }

            return send_no_content(r);

        case NGX_DECLINED:

            return send_not_modified(r);
    }

    return send_header(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}


typedef struct {
    ngx_chain_t         *out;
    ngx_http_request_t  *r;
    off_t                content_length;
} userdata_t;


static ngx_int_t
upstream_print(ngx_api_gateway_cfg_upstream_t *u, void *ctxp)
{
    userdata_t   *ctx = (userdata_t *) ctxp;
    ngx_chain_t  *next;

    static ngx_str_t upstream_type_text[] = {
        ngx_string("http"),
        ngx_string("stream")
    };

    static ngx_str_t methods_text[] = {
        ngx_string("roundrobin"),
        ngx_string("least_conn"),
        ngx_string("ip_hash")
    };

    next = ngx_pool_calloc<ngx_chain_t>(ctx->r->pool);
    if (next == NULL)
        return NGX_ERROR;

    next->buf = ngx_create_temp_buf(ctx->r->pool, 512);
    if (next->buf == NULL)
        return NGX_ERROR;

    next->buf->last = ngx_snprintf(next->buf->last,
                                   next->buf->end - next->buf->last,
            "{\"name\":\"%V\","
            "\"type\":\"%V\","
            "\"method\":\"%V\","
#if 0
        ,   "\"max_conns\":%d,"
            "\"max_fails\":%d,"
            "\"fail_timeout\":%d,"
#endif
        ,   &u->name,
            &upstream_type_text[u->type],
            &methods_text[u->method]
#if 0
            , u->max_conns, u->max_fails, u->fail_timeout
#endif
            );

    if (u->keepalive != NGX_DECLINED)
        next->buf->last = ngx_snprintf(next->buf->last,
                                       next->buf->end - next->buf->last,
                "\"keepalive\":%d,", u->keepalive);
          
    if (u->keepalive_requests != NGX_DECLINED)
        next->buf->last = ngx_snprintf(next->buf->last,
                                       next->buf->end - next->buf->last,
                "\"keepalive_requests\":%d,", u->keepalive_requests);

    if (u->keepalive_timeout != NGX_DECLINED)
        next->buf->last = ngx_snprintf(next->buf->last,
                                       next->buf->end - next->buf->last,
                "\"keepalive_timeout\":%d,", u->keepalive_timeout);
    
    if (u->dns_update != NGX_DECLINED)
        next->buf->last = ngx_snprintf(next->buf->last,
                                       next->buf->end - next->buf->last,
                "\"dns_update\":%d,", u->dns_update);
    next->buf->last--;
    next->buf->last = ngx_snprintf(next->buf->last,
                                   next->buf->end - next->buf->last, "},");

    ctx->content_length += next->buf->last - next->buf->start;
    ctx->out->next = next;
    ctx->out = next;

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_conf_upstream_list_handler(ngx_http_request_t *r)
{
    ngx_chain_t  start;
    ngx_int_t    rc;
    userdata_t   ctx;

    static ngx_str_t  json = ngx_string("application/json");

    ngx_memzero(&start, sizeof(ngx_chain_t));

    ctx.r = r;
    ctx.out = &start;
    ctx.content_length = 0;

    if (ngx_api_gateway_cfg_upstreams(ngx_cycle, upstream_print, &ctx)
            == NGX_ERROR)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (start.next == NULL)
        send_response(r, NGX_HTTP_OK, "[]");

    start.buf = ngx_create_temp_buf(r->pool, 8);
    if (start.buf == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    *start.buf->last++ = '[';
    *(ctx.out->buf->last - 1) = ']';

    ctx.out->buf->last_in_chain = 1;
    ctx.out->buf->last_buf = (r == r->main) ? 1 : 0;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = json;
    r->headers_out.content_length_n = ctx.content_length + 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK)
        return rc;

    return ngx_http_output_filter(r, &start);
}


static ngx_int_t
ngx_dynamic_conf_upstream_handler(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_GET)
        return ngx_dynamic_conf_upstream_list_handler(r);

    if (r->method == NGX_HTTP_POST)
        return ngx_dynamic_conf_upstream_add_handler(r);

    if (r->method == NGX_HTTP_DELETE)
        return ngx_dynamic_conf_upstream_delete_handler(r);

    return send_response(r, NGX_HTTP_NOT_ALLOWED, "method not allowed");
}


static char *
ngx_dynamic_conf_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_dynamic_conf_upstream_handler;

    return NGX_CONF_OK;
}
