/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway.h"
#include <ngx_http.h>


#define DEFAULT_TIMEOUT  (10000)
#define DEFAULT_INTERVAL (60000)


const char *GW_Entrypoints = "entrypoints";
const char *GW_Backends = "backends";


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
                       sizeof(ngx_api_gateway_t)) == NGX_ERROR)
        return NULL;

    amcf->interval = NGX_CONF_UNSET_MSEC;
    amcf->timeout = NGX_CONF_UNSET_MSEC;

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


static ngx_str_t  KEY_expose = ngx_string("expose");


static ngx_int_t
ngx_api_gateway_parse_expose(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_api_gateway_conf_t *conf, ngx_str_t *retval)
{
    ngx_array_t         exposes;
    ngx_str_t          *expose;
    yaml_event_t        event;
    yaml_event_type_t   type;
    size_t              size = 0;
    ngx_int_t           j;
    u_char             *c;
    
    if (ngx_array_init(&exposes, pool, 10, sizeof(ngx_str_t)) != NGX_OK)
        goto nomem;

    if (!yaml_parser_parse(parser, &event))
        return NGX_ERROR;

    type = event.type;
    yaml_event_delete(&event);

    if (type != YAML_SEQUENCE_START_EVENT)
        return NGX_ABORT;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;
        
        switch (type) {
            
            case YAML_SCALAR_EVENT:

                expose = ngx_array_push(&exposes);
                if (expose == NULL)
                    goto nomem_local;

                *expose = ngx_strdup(pool, event.data.scalar.value,
                                  event.data.scalar.length);
                if (expose->data == NULL)
                    goto nomem_local;

                size += expose->len + 1;
                
                break;

            case YAML_SEQUENCE_END_EVENT:

                break;

            default:

                yaml_event_delete(&event);
                return NGX_ABORT;
        }

        yaml_event_delete(&event);
        continue;

nomem_local:

        yaml_event_delete(&event);
        goto nomem;

    } while (type != YAML_SEQUENCE_END_EVENT);

    conf->expose = exposes.elts;
    conf->nexpose = exposes.nelts;

    if (retval != NULL) {

        retval->len = size - 1;
        retval->data = ngx_palloc(pool, size);
        if (retval->data == NULL)
            goto nomem;

        c = retval->data;

        for (j = 0; j < conf->nexpose; j++)
            c = ngx_sprintf(c, "%V ", &conf->expose[j]);
        retval->data[retval->len] = 0;
    }

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_api_gateway_handle_key(yaml_char_t *key, size_t length,
    ngx_pool_t *pool, yaml_parser_t *parser, ngx_template_conf_t *conf,
    ngx_str_t *retval)
{
    if (ngx_memn2cmp(KEY_expose.data, key, KEY_expose.len, length) == 0)
        return ngx_api_gateway_parse_expose(pool, parser,
                (ngx_api_gateway_conf_t *) conf, retval);

    return NGX_DONE;
}


static ngx_int_t
ngx_api_gateway_template_apply(ngx_conf_t *cf, ngx_api_gateway_t *t,
    const char *tag)
{
    ngx_api_gateway_conf_t  *conf;
    FILE                    *f;
    ngx_int_t                rc = NGX_OK;
    ngx_int_t                i;
    ngx_uint_t               j;
    char                    *rv;
    ngx_conf_file_t          conf_file;
    ngx_conf_file_t         *prev = cf->conf_file;
    ngx_str_t                keyfile = t->base.keyfile;
    ngx_str_t                dump_name;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "%V:%V", &t->base.filename,
                  &keyfile);

    if (ngx_template_read_template(cf, t->base.filename,
            &t->base.template, NULL) != NGX_OK)
        return NGX_ERROR;

    if (ngx_conf_full_name(cf->cycle, &keyfile, 1) != NGX_OK)
        return NGX_ERROR;

    f = fopen((const char *) keyfile.data, "r");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno, "can't open file: %V",
                           &t->base.filename);
        return NGX_ERROR;
    }

    if (ngx_array_init(&t->base.entries, cf->pool, 10,
            sizeof(ngx_api_gateway_conf_t)) == NGX_ERROR) {
        rc = NGX_ERROR;
        goto done;
    }

    rc = ngx_template_conf_parse_yaml(cf->pool, f, &t->base, tag,
        ngx_api_gateway_handle_key);
    if (rc != NGX_OK)
        goto done;

    t->base.yaml.len = ftell(f);
    t->base.yaml.data = ngx_palloc(cf->pool, t->base.yaml.len);
    if (t->base.yaml.data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    fseek(f, 0, SEEK_SET);
    fread(t->base.yaml.data, t->base.yaml.len, 1, f);

    conf = t->base.entries.elts;

    for (j = 0; j < t->base.entries.nelts; j++) {

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  keys");
        for (i = 0; i < conf[j].base.nkeys; i++)
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V:%V",
                &conf[j].base.keys[i].key, &conf[j].base.keys[i].value);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  expose");
        for (i = 0; i < conf[j].nexpose; i++) {
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V",
                          &conf[j].expose[i]);
        }

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  template\n%V", &t->base.template);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  text\n%V", &conf[j].base.conf);

        ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));

        cf->conf_file = &conf_file;

        conf_file.buffer = ngx_create_temp_buf(cf->temp_pool,
            conf[j].base.conf.len + 1);
        conf_file.file.log = cf->log;
        conf_file.file.name = t->base.filename;
        conf_file.line = 1;
        conf_file.file.info.st_size = conf[j].base.conf.len + 1;
        conf_file.file.offset = conf_file.file.info.st_size;
        conf_file.buffer->last = ngx_cpymem(conf_file.buffer->start,
                conf[j].base.conf.data, conf[j].base.conf.len);

        if (ngx_dump_config
#if (NGX_DEBUG)
            || 1
#endif
           )
        {
            dump_name.data = ngx_pcalloc(cf->temp_pool,
                conf[j].base.name.len + ngx_strlen(tag) + 2);
            if (dump_name.data == NULL) {
                rc = NGX_ERROR;
                goto done;
            }
            dump_name.len = ngx_sprintf(dump_name.data, "%s:%V",
                                        tag, &conf[j].base.name) - dump_name.data;
            if (ngx_conf_add_dump(cf, &dump_name) != NGX_OK) {
                rc = NGX_ERROR;
                goto done;
            }

            if (conf_file.dump != NULL)
                conf_file.dump->last = ngx_cpymem(conf_file.dump->last,
                    conf[j].base.conf.data, conf[j].base.conf.len);
        }

        *conf_file.buffer->last++ = '}';

        rv = ngx_conf_parse(cf, NULL);

        if (rv != NGX_CONF_OK)
            rc = NGX_ERROR;
    }

    
done:

    cf->conf_file = prev;

    fclose(f);

    switch (rc) {

        case NGX_OK:
            break;

        case NGX_ABORT:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid structure");
            return NGX_ERROR;

        default:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
            return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_api_gateway_template(ngx_conf_t *cf, ngx_api_gateway_t *t, const char *tag)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    t->base.filename = value[1];
    t->base.keyfile = value[2];

    if (cf->args->nelts == 4) {

        t->url.url = value[3];
        t->url.uri_part = 1;
        t->url.default_port = 80;

        if (ngx_parse_url(cf->pool, &t->url) != NGX_OK) {

            ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                    "failed to parse url: %V", &t->url.url);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_api_gateway_template_apply(cf, t, tag) == NGX_OK) 
        return NGX_CONF_OK;

    return NGX_CONF_ERROR;
}


static char *
ngx_api_gateway_template_directive(ngx_conf_t *cf, void *conf, const char *tag)
{
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_api_gateway_t            *t = ngx_array_push(&amcf->templates);
    char                         *rv;

    if (t == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(t, sizeof(ngx_api_gateway_t));

    t->tag = tag;

    rv = ngx_api_gateway_template(cf, t, tag);
    if (rv == NGX_CONF_ERROR)
        amcf->templates.nelts--;

    return rv;
}


char *
ngx_api_gateway_entrypoints(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ngx_api_gateway_template_directive(cf, conf, GW_Entrypoints);
}


char *
ngx_api_gateway_backends(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ngx_api_gateway_template_directive(cf, conf, GW_Backends);
}


typedef struct {
    ngx_api_gateway_t  *t;
    ngx_pool_t         *pool;
} context_t;


static void
ngx_api_gateway_fetch_handler(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *pctx)
{
    context_t          *ctx = pctx;
    ngx_str_t           keyfile = ctx->t->base.keyfile;
    FILE               *f;
    ngx_api_gateway_t   t;
    ngx_tm_t            tm;
    u_char              backup[10240];

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], failed to upsync",
                     &ctx->t->url.url);
        goto done;
    } else if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], upsync timeout",
                     &ctx->t->url.url);
        goto done;
    } else if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NO_CONTENT) {

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], upsync status=%d "
                     "(not 200, 204)", &ctx->t->url.url, rc);
        goto done;
    }

    if (rc != NGX_HTTP_OK)
        goto done;

    t.base.filename = ctx->t->base.filename;
    t.base.keyfile = ctx->t->base.keyfile;
    t.base.template = ctx->t->base.template;
    t.base.filename = ctx->t->base.filename;

    ngx_array_init(&t.base.entries, ctx->pool,
        10, sizeof(ngx_api_gateway_conf_t));

    f = fmemopen(body->data, body->len, "r");
    rc = ngx_template_conf_parse_yaml(ctx->pool, f, &t.base, ctx->t->tag,
        ngx_api_gateway_handle_key);
    fclose(f);

    if (rc != NGX_OK)
        goto done;

    if (ngx_memn2cmp(body->data, ctx->t->base.yaml.data,
                     body->len, ctx->t->base.yaml.len) == 0)
        goto done;

    if (ngx_conf_full_name((ngx_cycle_t *) ngx_cycle, &keyfile, 1) != NGX_OK)
        goto done;

    ngx_localtime(ngx_cached_time->sec, &tm);
    ngx_sprintf(backup, "%V.%4d%02d%02d%02d%02d%02d", &keyfile,
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (rename((const char *) keyfile.data, (const char *) backup) != 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, errno,
                      "ngx_api_gateway: can't backup %V", &keyfile);
        goto done;
    }

    f = fopen((const char *) keyfile.data, "w+");
    if (f == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ngx_api_gateway: can't open %V", &keyfile);
        goto done;
    }

    fwrite(body->data, body->len, 1, f);

    fclose(f);

    ngx_signal_process((ngx_cycle_t *) ngx_cycle, "reload");

done:

    ngx_destroy_pool(ctx->pool);
}


static void
ngx_api_gateway_fetch_gw(ngx_api_gateway_t *t, ngx_msec_t timeout)
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
    ngx_api_gateway_t  *t;
    ngx_uint_t          j;

    t = a.elts;
    for (j = 0; j < a.nelts; j++)
        ngx_api_gateway_fetch_gw(t + j, timeout);
}


void
ngx_api_gateway_fetch_keys(ngx_api_gateway_main_conf_t *amcf)
{
    ngx_api_gateway_fetch(amcf->templates, amcf->timeout);
}
