/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_http.h>
#include <ngx_stream.h>


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


typedef struct {
    ngx_slab_pool_t  *slab;
    ngx_queue_t       upstreams;
} ngx_dynamic_conf_shm_t;


typedef struct {
    size_t                   size;
    ngx_shm_zone_t          *zone;
    ngx_dynamic_conf_shm_t  *shm;
    ngx_url_t                default_addr;
} ngx_dynamic_conf_main_conf_t;


typedef enum {
    http = 0,
    stream
} upstream_type;

typedef enum {
    roundrobin = 0,
    leastconn
} balancer_type;


static ngx_str_t methods[] = {
    ngx_string(""),
    ngx_string("least_conn;")
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

    return dmcf;
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


static void *
ngx_http_rr_peers_new(ngx_dynamic_conf_main_conf_t *dmcf,
    ngx_dynamic_upstream_t u)
{
    ngx_http_upstream_rr_peers_t  *peers;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_slab_pool_t               *slab = dmcf->shm->slab;

    peers = ngx_slab_calloc_locked(slab, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL)
        return NULL;

    peer = ngx_slab_calloc_locked(slab, sizeof(ngx_http_upstream_rr_peer_t));
    if (peer == NULL) {
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }

    peers->name = ngx_slab_calloc_locked(slab, sizeof(ngx_str_t));
    if (peers->name == NULL) {
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }
    *peers->name = ngx_str_shm(slab, &u.name);
    peers->number = 1;
    peers->shpool = slab;
    peers->single = 1;
    peers->total_weight = 1;
    peers->weighted = 1;
    peers->peer = peer;

    peer->current_weight = 0;
    peer->effective_weight = 1;
    peer->server = ngx_str_shm(slab, &dmcf->default_addr.url);
    peer->name = ngx_str_shm(slab, &dmcf->default_addr.url);
    peer->weight = 1;
    peer->max_conns = u.max_conns;
    peer->max_fails = u.max_fails;
    peer->fail_timeout = u.fail_timeout;
    peer->down = 1;

    peer->sockaddr = ngx_slab_calloc_locked(slab, dmcf->default_addr.socklen);
    if (peer->sockaddr == NULL) {
        ngx_slab_free_locked(slab, peer->server.data);
        ngx_slab_free_locked(slab, peer->name.data);
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }

    ngx_memcpy(peer->sockaddr, &dmcf->default_addr.sockaddr,
        dmcf->default_addr.socklen);

    return peers;
}


static void *
ngx_stream_rr_peers_new(ngx_dynamic_conf_main_conf_t *dmcf,
    ngx_dynamic_upstream_t u)
{
    ngx_stream_upstream_rr_peers_t  *peers;
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_slab_pool_t                 *slab = dmcf->shm->slab;

    peers = ngx_slab_calloc_locked(slab,
        sizeof(ngx_stream_upstream_rr_peers_t));
    if (peers == NULL)
        return NULL;

    peer = ngx_slab_calloc_locked(slab, sizeof(ngx_stream_upstream_rr_peer_t));
    if (peer == NULL) {
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }

    peers->name = ngx_slab_calloc_locked(slab, sizeof(ngx_str_t));
    if (peers->name == NULL) {
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }
    *peers->name = ngx_str_shm(slab, &u.name);
    peers->number = 1;
    peers->shpool = slab;
    peers->single = 1;
    peers->total_weight = 1;
    peers->weighted = 1;
    peers->peer = peer;

    peer->current_weight = 0;
    peer->effective_weight = 1;
    peer->server = ngx_str_shm(slab, &dmcf->default_addr.url);
    peer->name = ngx_str_shm(slab, &dmcf->default_addr.url);
    peer->weight = 1;
    peer->max_conns = u.max_conns;
    peer->max_fails = u.max_fails;
    peer->fail_timeout = u.fail_timeout;
    peer->down = 1;

    peer->sockaddr = ngx_slab_calloc_locked(slab, dmcf->default_addr.socklen);
    if (peer->sockaddr == NULL) {
        ngx_slab_free_locked(slab, peer->server.data);
        ngx_slab_free_locked(slab, peer->name.data);
        ngx_slab_free_locked(slab, peers);
        return NULL;
    }

    ngx_memcpy(peer->sockaddr, &dmcf->default_addr.sockaddr,
        dmcf->default_addr.socklen);

    return peers;
}


static void *
ngx_rr_peers_new(ngx_dynamic_conf_main_conf_t *dmcf,
    ngx_dynamic_upstream_t u)
{
    void  *peers = NULL;

    switch (u.type) {
        case http:
            peers = ngx_http_rr_peers_new(dmcf, u);
            break;

        case stream:
            peers = ngx_stream_rr_peers_new(dmcf, u);
            break;
    }

    return peers;
}


static ngx_int_t
ngx_add_upstream(ngx_dynamic_conf_main_conf_t *dmcf,
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
    sh->peers = ngx_rr_peers_new(dmcf, u);

    if (sh->peers == NULL) {
        ngx_slab_free_locked(dmcf->shm->slab, sh->name.data);
        ngx_slab_free_locked(dmcf->shm->slab, sh);
        ngx_shmtx_unlock(&dmcf->shm->slab->mutex);
        return NGX_ERROR;
    }

    ngx_queue_insert_tail(&dmcf->shm->upstreams, &sh->queue);

    ngx_shmtx_unlock(&dmcf->shm->slab->mutex);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "[%s] add upstream '%V'", u.type == http ? "http" : "stream", &u.name);

    return NGX_OK;
}


static ngx_int_t
ngx_delete_upstream(ngx_dynamic_conf_main_conf_t *dmcf,
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
                            u.name.len, sh->name.len) == 0) {

            sh->count = -ccf->worker_processes;

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
            "server 0.0.0.0:1 down;"
            "%V"
            "keepalive %d;"
            "keepalive_requests %d;"
            "keepalive_timeout %d;"
            "dns_update %d;"
            "}}", &u->name, &methods[u->method],
            u->keepalive, u->keepalive_requests, u->keepalive_timeout,
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


static ngx_int_t
ngx_http_upstream_new(ngx_dynamic_upstream_t *u)
{
    ngx_http_upstream_main_conf_t     *umcf;
    ngx_http_upstream_srv_conf_t      *uscf, **uscfp;
    ngx_conf_t                        *cf;
    ngx_http_conf_ctx_t                ctx;

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

    uscf->peer.data = u->peers;
    uscf->shm_zone = u->zone;

    ngx_destroy_pool(cf->temp_pool);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_upstream_new(ngx_dynamic_upstream_t *u)
{
    ngx_stream_upstream_main_conf_t  *umcf;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_conf_t                       *cf;
    ngx_stream_conf_ctx_t             ctx;

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

    // 8 bytes leaked

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

    // 8 bytes leaked

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
    else
        return send_response(r, NGX_HTTP_BAD_REQUEST,
            "bad method (roundrobin, leastconn)");

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
    if (u.dns_update == NGX_ERROR)
        return send_response(r, NGX_HTTP_BAD_REQUEST, "bad dns_update");

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

    switch (ngx_add_upstream(dmcf, u)) {
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

    if (ngx_delete_upstream(dmcf, u) == NGX_OK)
        return send_header(r, NGX_HTTP_NO_CONTENT);
    
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
