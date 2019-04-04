/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway.h"
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

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_api_gateway_main_conf_t));
    if (amcf == NULL)
        return NULL;

    if (ngx_array_init(&amcf->templates, cf->pool, 10,
                       sizeof(ngx_api_gateway_template_t)) == NGX_ERROR)
        return NULL;

    amcf->interval = NGX_CONF_UNSET_MSEC;
    amcf->timeout = NGX_CONF_UNSET_MSEC;
    amcf->request_path_index = NGX_ERROR;

    return amcf;
}


char *
ngx_api_gateway_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_conf_init_msec_value(amcf->interval, DEFAULT_INTERVAL);
    ngx_conf_init_msec_value(amcf->timeout, DEFAULT_TIMEOUT);
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
    ngx_pool_t *pool, yaml_parser_t *parser, ngx_template_conf_t *conf,
    ngx_str_t *retval)
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
    ngx_str_t                    *value = cf->args->elts;
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_template_t               *t;
    ngx_api_gateway_template_t   *tgw;

    tgw = ngx_array_push(&amcf->templates);
    if (tgw == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(tgw, sizeof(ngx_api_gateway_template_t));

    if (cf->args->nelts > 3) {

        tgw->url.url = value[3];
        tgw->url.uri_part = 1;
        tgw->url.default_port = 80;

        if (ngx_parse_url(cf->pool, &tgw->url) != NGX_OK) {

            ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                    "failed to parse url: %V", &tgw->url.url);
            return NGX_CONF_ERROR;
        }
    }

    t = ngx_template_add(cf, ngx_api_gateway_handle_key);
    if (t == NULL) {
        amcf->templates.nelts--;
        return NGX_CONF_ERROR;
    }

    tgw->t = *t;

    return NGX_CONF_OK;
}


typedef struct {
    ngx_api_gateway_template_t  *t;
    ngx_pool_t                  *pool;
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

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ngx_api_gateway upsync failed, url=%V",
                      &ctx->t->url.url);
        goto done;
    } else if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ngx_api_gateway upsync timeout, url=%V",
                      &ctx->t->url.url);
        goto done;
    } else if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NO_CONTENT) {

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "ngx_api_gateway upsync status=%d "
                      "(not 200, 204), url=%V", rc, &ctx->t->url.url);
        goto done;
    }

    if (rc != NGX_HTTP_OK)
        goto done;

    t.tag = ctx->t->t.tag;
    t.filename = ctx->t->t.filename;
    t.keyfile = ctx->t->t.keyfile;
    t.template = ctx->t->t.template;
    t.filename = ctx->t->t.filename;
    t.pfkey = ngx_api_gateway_handle_key;

    ngx_array_init(&t.entries, ctx->pool, 10, sizeof(ngx_template_conf_t));

    f = fmemopen(body->data, body->len, "r");
    rc = ngx_template_conf_parse_yaml(ctx->pool, f, &t);
    fclose(f);

    if (rc != NGX_OK)
        goto done;

    if (ngx_memn2cmp(body->data, ctx->t->t.yaml.data,
                     body->len, ctx->t->t.yaml.len) == 0)
        goto done;

    if (ngx_conf_full_name((ngx_cycle_t *) ngx_cycle, &keyfile, 1) != NGX_OK)
        goto done;

    ngx_localtime(ngx_cached_time->sec, &tm);

    backup = ngx_pcalloc(ctx->pool, keyfile.len + 64);
    if (backup == NULL)
        goto done;

    ngx_sprintf(backup, "%V.%4d%02d%02d%02d%02d%02d", &keyfile,
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (ngx_rename_file(keyfile.data, backup) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, errno,
                      ngx_rename_file_n " backup \"%V\" failed", &keyfile);
        goto done;
    }

    file.name = keyfile;
    file.log = ngx_cycle->log;

    file.fd = ngx_open_file(keyfile.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                            NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &keyfile);
        goto done;
    }

    if (ngx_write_file(&file, body->data, body->len, 0) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                      ngx_write_fd_n " \"%V\" failed", &keyfile);
        goto done;
    }

    ngx_close_file(file.fd);

    ctx->t->t.yaml.data = ngx_palloc(ngx_cycle->pool, body->len);
    if (ctx->t->t.yaml.data != NULL) {
        ngx_memcpy(ctx->t->t.yaml.data, body->data, body->len);
        ctx->t->t.yaml.len = body->len;
    }

done:

    ngx_destroy_pool(ctx->pool);
}


static void
ngx_api_gateway_fetch_gw(ngx_api_gateway_template_t *t, ngx_msec_t timeout)
{
    ngx_pool_t        *pool;
    context_t         *ctx;
    static ngx_str_t   GET = ngx_string("GET");

    if (t->url.url.data == NULL)
        return;

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(context_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");
        return;
    }

    ctx->pool = pool;
    ctx->t = t;

    ngx_http_send_request(pool, GET, &t->url, NULL, 0, NULL, 0, NULL,
        timeout, ngx_api_gateway_fetch_handler, ctx);
}


static void
ngx_api_gateway_fetch(ngx_array_t a, ngx_msec_t timeout)
{
    ngx_api_gateway_template_t  *t;
    ngx_uint_t                   j;

    t = a.elts;
    for (j = 0; j < a.nelts; j++)
        ngx_api_gateway_fetch_gw(t + j, timeout);
}


void
ngx_api_gateway_fetch_keys(ngx_api_gateway_main_conf_t *amcf)
{
    ngx_api_gateway_fetch(amcf->templates, amcf->timeout);
}
