/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway.h"
#include "ngx_api_gateway_router.h"
#include <ngx_http.h>


#define DEFAULT_TIMEOUT  (10000)
#define DEFAULT_INTERVAL (60000)


typedef void (*ngx_http_send_request_pt)(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *data);


extern ngx_int_t
ngx_http_send_request(ngx_pool_t *pool, ngx_str_t method, ngx_url_t *url,
    ngx_keyval_t *args, ngx_uint_t nargs,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body,
    ngx_msec_t timeout,
    ngx_http_send_request_pt handler,
    void *data);


void *
ngx_api_gateway_create_main_conf(ngx_conf_t *cf)
{
    ngx_api_gateway_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->cycle->pool, sizeof(ngx_api_gateway_main_conf_t));
    if (amcf == NULL)
        return NULL;

    if (ngx_array_init(&amcf->templates, cf->cycle->pool, 10,
                       sizeof(ngx_api_gateway_template_t)) == NGX_ERROR)
        return NULL;

    if (ngx_array_init(&amcf->routers, cf->cycle->pool, 10,
                       sizeof(ngx_http_api_gateway_router_t *)) == NGX_ERROR)
        return NULL;

    if (ngx_array_init(&amcf->backends, cf->cycle->pool, 100,
                       sizeof(ngx_str_t)) == NGX_ERROR)
        return NULL;

    amcf->interval = NGX_CONF_UNSET_MSEC;
    amcf->timeout = NGX_CONF_UNSET_MSEC;
    amcf->request_path_index = NGX_ERROR;
    amcf->cycle = cf->cycle;
    amcf->pool = ngx_create_pool(1024, cf->cycle->log);
    if (amcf->pool == NULL)
        return NULL;

    return amcf;
}


static ngx_int_t
ngx_api_gateway_create_mappings(ngx_cycle_t *cycle,
    ngx_http_api_gateway_router_t *router, ngx_pool_t *pool)
{
    ngx_template_conf_t  *conf;
    ngx_template_seq_t   *seq;
    ngx_uint_t            j, i;
    ngx_str_t            *backend;

    static ngx_str_t api = ngx_string("api");

    if (router->dynamic)
        return NGX_OK;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "rebuild routes for var=$%V",
            &router->var);

    backend = router->backends.elts;

    for (j = 0; j < router->backends.nelts; j++) {

        conf = ngx_template_lookup_by_name(cycle, backend[j]);
        if (conf == NULL)
            continue;

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                "rebuild routes for backend=%V", &conf->fullname);

        seq = conf->seqs.elts;

        for (i = 0; i < conf->seqs.nelts; i++) {

            if (ngx_memn2cmp(seq[i].key.data, api.data,
                             seq[i].key.len, api.len) != 0)
                continue;

            if (ngx_api_gateway_router_build(cycle, pool, router,
                    conf->fullname, seq[i].elts, seq[i].nelts) == NGX_ERROR)
                return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_collect(ngx_template_t *t, void *data)
{
    ngx_api_gateway_main_conf_t  *amcf = data;
    ngx_template_conf_t          *conf;
    ngx_uint_t                    j, i, k;
    ngx_template_seq_t           *seq;
    ngx_str_t                    *backend;

    for (i = 0; i < t->entries.nelts; i++) {

        conf = (ngx_template_conf_t *)
                ((u_char *) t->entries.elts + i * t->entries.size);

        seq = conf->seqs.elts;

        for (j = 0; j < conf->seqs.nelts; j++) {

            if (!ngx_eqstr(seq[j].key, "backends"))
                continue;

            for (k = 0; k < seq[j].nelts; k++) {

                backend = ngx_array_push(&amcf->backends);
                if (backend == NULL)
                    goto nomem;
                
                *backend = ngx_strdup(amcf->cycle->pool, seq[j].elts[k].data,
                                      seq[j].elts[k].len);
                if (backend->data == NULL)
                    goto nomem;
            }
        }
    }

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_NOTICE, amcf->cycle->log, 0, "no memory");
    return NGX_ERROR;
}

char *
ngx_api_gateway_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_api_gateway_main_conf_t     *amcf = conf;
    ngx_http_api_gateway_router_t  **router;
    ngx_uint_t                       j;

    ngx_conf_init_msec_value(amcf->interval, DEFAULT_INTERVAL);
    ngx_conf_init_msec_value(amcf->timeout, DEFAULT_TIMEOUT);

    router = amcf->routers.elts;

    if (ngx_template_scan(cf->cycle, ngx_api_gateway_collect, amcf)
            == NGX_ERROR)
        return NGX_CONF_ERROR;

    for (j = 0; j < amcf->routers.nelts; j++) {

        if (!router[j]->dynamic && router[j]->backends.nelts == 0)
            router[j]->backends = amcf->backends;

        if (ngx_api_gateway_create_mappings(cf->cycle, router[j],
                amcf->pool) == NGX_ERROR)
            return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_str_t  KEYS_seq[] = {

    ngx_string("api"),
    ngx_string("backends"),
    ngx_string("directives"),
    ngx_string("locations")

};
static ngx_int_t KEYS_seqn = sizeof(KEYS_seq) / sizeof(KEYS_seq[0]);


static ngx_int_t
ngx_api_gateway_handle_key(ngx_str_t path, yaml_char_t *key, size_t key_len,
    ngx_pool_t *pool, yaml_parser_t *parser, ngx_template_conf_t *conf)
{
    ngx_int_t  j;

    for (j = 0; j < KEYS_seqn; j++)
        if (ngx_memn2cmp(KEYS_seq[j].data, key,
                         KEYS_seq[j].len, key_len) == 0)
            return NGX_OK;

    return NGX_DECLINED;
}


char *
ngx_api_gateway_template_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_template_t               *t;
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_api_gateway_template_t   *gw;
    ngx_uint_t                    j;

    t = ngx_template_add(cf, ngx_api_gateway_handle_key);
    if (t == NULL)
        return NGX_CONF_ERROR;

    gw = ngx_array_push(&amcf->templates);
    if (gw == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(gw, sizeof(ngx_api_gateway_template_t));

    for (j = 0; j < t->args.nelts; j++) {

        if (ngx_eqstr(t->args.elts[j].key, "url")) {

            gw->url.url = t->args.elts[j].value;
            gw->url.uri_part = 1;
            gw->url.default_port = 80;

            if (ngx_parse_url(cf->cycle->pool, &gw->url) != NGX_OK) {

                ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                    "failed to parse url: %V, %s", &gw->url.url, gw->url.err);
                return NGX_CONF_ERROR;
            }
        }
    }

    gw->t = *t;
    
    return NGX_CONF_OK;
}


typedef struct {
    ngx_api_gateway_template_t  *t;
    ngx_pool_t                  *temp_pool;
    ngx_cycle_t                 *cycle;
} context_t;


static void
ngx_api_gateway_fetch_handler(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *pctx)
{
    context_t          *ctx = pctx;
    ngx_str_t           keyfile = ctx->t->t.keyfile;
    FILE               *f;
    ngx_file_t          file;
    ngx_template_t      t;
    ngx_tm_t            tm;
    u_char             *backup;
    ngx_cycle_t        *cycle = ctx->cycle;
    u_char             *c;

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "ngx_api_gateway upsync failed, url=%V",
                      &ctx->t->url.url);
        goto done;
    } else if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "ngx_api_gateway upsync timeout, url=%V",
                      &ctx->t->url.url);
        goto done;
    } else if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NO_CONTENT) {

        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "ngx_api_gateway upsync status=%d "
                      "(not 200, 204), url=%V", rc, &ctx->t->url.url);
        goto done;
    }

    if (rc != NGX_HTTP_OK)
        goto done;

    t.group = ctx->t->t.group;
    t.filename = ctx->t->t.filename;
    t.keyfile = ctx->t->t.keyfile;
    t.template = ctx->t->t.template;
    t.filename = ctx->t->t.filename;
    t.pfkey = ngx_api_gateway_handle_key;
    t.pool = ctx->temp_pool;

    ngx_array_init(&t.entries, t.pool, 10, sizeof(ngx_template_conf_t));

    f = fmemopen(body->data, body->len, "r");
    rc = ngx_template_conf_parse_yaml(cycle, f, &t);
    fclose(f);

    if (rc != NGX_OK)
        goto done;

    if (ngx_memn2cmp(body->data, ctx->t->t.yaml.data,
                     body->len, ctx->t->t.yaml.len) == 0)
        goto done;

    if (ngx_conf_full_name(cycle, &keyfile, 1) != NGX_OK)
        goto done;

    ngx_localtime(ngx_cached_time->sec, &tm);

    backup = ngx_pcalloc(ctx->temp_pool, keyfile.len + 64);
    if (backup == NULL)
        goto done;

    ngx_sprintf(backup, "%V.%4d%02d%02d%02d%02d%02d", &keyfile,
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (ngx_rename_file(keyfile.data, backup) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno,
                      ngx_rename_file_n " backup \"%V\" failed", &keyfile);
        goto done;
    }

    file.name = keyfile;
    file.log = cycle->log;

    file.fd = ngx_open_file(keyfile.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                            NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &keyfile);
        goto done;
    }

    if (ngx_write_file(&file, body->data, body->len, 0) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      ngx_write_fd_n " \"%V\" failed", &keyfile);
        goto done;
    }

    ngx_close_file(file.fd);

    c = ngx_alloc(body->len, cycle->log);
    if (c != NULL) {
        ngx_free(ctx->t->t.yaml.data);
        ngx_memcpy(c, body->data, body->len);
        ctx->t->t.yaml.data = c;
        ctx->t->t.yaml.len = body->len;
    } else {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
    }

done:

    ngx_destroy_pool(ctx->temp_pool);
}


static void
ngx_api_gateway_fetch_gw(ngx_cycle_t *cycle, ngx_api_gateway_template_t *t,
    ngx_msec_t timeout)
{
    ngx_pool_t        *pool;
    context_t         *ctx;
    static ngx_str_t   GET = ngx_string("GET");

    if (t->url.url.data == NULL)
        return;

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(context_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
        return;
    }

    ctx->cycle = cycle;
    ctx->temp_pool = pool;
    ctx->t = t;

    if (ngx_http_send_request(pool, GET, &t->url, NULL, 0, NULL, 0, NULL,
            timeout, ngx_api_gateway_fetch_handler, ctx) == NGX_ERROR)
            ngx_destroy_pool(pool);
}


static void
ngx_api_gateway_fetch(ngx_cycle_t *cycle, ngx_array_t a, ngx_msec_t timeout)
{
    ngx_api_gateway_template_t  *t;
    ngx_uint_t                   j;

    t = a.elts;
    for (j = 0; j < a.nelts; j++)
        ngx_api_gateway_fetch_gw(cycle, t + j, timeout);
}


void
ngx_api_gateway_sync(ngx_api_gateway_main_conf_t *amcf)
{
    ngx_api_gateway_fetch(amcf->cycle, amcf->templates, amcf->timeout);
}


void
ngx_api_gateway_update(ngx_template_main_conf_t *tmcf,
    ngx_api_gateway_main_conf_t *amcf)
{
    ngx_http_api_gateway_router_t  **router;
    ngx_uint_t                       j;
    ngx_pool_t                      *pool;

    if (!tmcf->changed)
        return;

    router = amcf->routers.elts;

    pool = ngx_create_pool(1024, amcf->cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, amcf->cycle->log, 0, "no memory");
        return;
    }

    for (j = 0; j < amcf->routers.nelts; j++) {

        if (router[j]->dynamic)
            continue;

        if (ngx_api_gateway_create_mappings(amcf->cycle, router[j], pool)
                == NGX_ERROR)
            continue;

        if (router[j]->sh == NULL)
            continue;

        if (ngx_worker != 0)
            continue;

        ngx_api_gateway_router_shm_init(router[j], router[j]->sh);
    }

    ngx_destroy_pool(amcf->pool);
    amcf->pool = pool;

    tmcf->changed = 0;
}
