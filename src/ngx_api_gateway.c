/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway.h"

#include <ngx_http.h>
#include <sys/stat.h>
#include <yaml.h>


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
    ngx_api_gateway_main_conf_t  *gmcf;

    gmcf = ngx_pcalloc(cf->pool, sizeof(ngx_api_gateway_main_conf_t));
    if (gmcf == NULL)
        return NULL;

    if (ngx_array_init(&gmcf->entrypoints, cf->pool, 10,
                       sizeof(ngx_api_gateway_t)) == NGX_ERROR)
        return NULL;

    if (ngx_array_init(&gmcf->backends, cf->pool, 10,
                       sizeof(ngx_api_gateway_t)) == NGX_ERROR)
        return NULL;

    return gmcf;
}


static ngx_int_t
ngx_api_gateway_read_template(ngx_conf_t *cf, ngx_str_t filename,
    ngx_str_t *content)
{
    FILE         *f;
    struct stat   attr;

    if (ngx_conf_full_name(cf->cycle, &filename, 1) != NGX_OK)
        return NGX_ERROR;

    f = fopen((const char *) filename.data, "r");
    if (f == NULL || -1 == fstat(fileno(f), &attr)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno, "can't open file: %V",
                           &filename);
        return NGX_ERROR;
    }

    content->data = ngx_palloc(cf->pool, attr.st_size + 1);
    if (content->data == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "no memory");
        goto fails;
    }

    if ((size_t) attr.st_size != fread(content->data, 1, attr.st_size, f)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno, "can't read file: %V",
                           &filename);
        goto fails;
    }

    content->data[attr.st_size] = 0;
    content->len = attr.st_size;

    fclose(f);
    return NGX_OK;

fails:

    fclose(f);
    return NGX_ERROR;
}


static ngx_str_t
concat_path(ngx_pool_t *pool, ngx_str_t *path, ngx_int_t n)
{
    ngx_str_t   s = { 0, NULL }, tmp;
    ngx_int_t   j;
    u_char     *c;

    for (j = 0; j <= n; j++)
        s.len += 1 + path[j].len;

    s.data = ngx_pcalloc(pool, s.len);
    if (s.data == NULL)
        return s;

    c = s.data;

    for (j = 0; j <= n; j++) {
        tmp.data = path[j].data;
        tmp.len = path[j].len;
        c = ngx_sprintf(c, "%V.", &tmp);
    }

    s.data[--s.len] = 0;

    return s;
}


static ngx_str_t
ngx_strdup(ngx_pool_t *pool, u_char *s, size_t len)
{
    ngx_str_t  dst;

    dst.data = ngx_pcalloc(pool, len + 1);
    if (dst.data)
        ngx_memcpy(dst.data, s, len);
    dst.len = len;

    return dst;
}


static ngx_str_t
lookup_env(ngx_str_t key)
{
    ngx_str_t         s = key;
    char              var[key.len];
    static ngx_str_t  env = ngx_string("env(");

    if (ngx_strncasecmp(env.data, key.data, env.len) != 0)
        return s;

    ngx_memzero(var, key.len);
    ngx_memcpy(var, key.data + 4, key.len - 4 - 1);

    s.data = (u_char *) getenv(var);
    if (s.data != NULL)
        s.len = ngx_strlen(s.data);
    else
        s = key;

    return s;
}


static ngx_str_t
lookup_key(ngx_api_gateway_template_t *conf, ngx_str_t key)
{
    ngx_str_t  s = { 0, NULL };
    ngx_int_t  j;

    for (j = 0; j < conf->nkeys; j++) {
        if (ngx_memn2cmp(conf->keys[j].key.data, key.data,
                         conf->keys[j].key.len, key.len) == 0) {
            s = conf->keys[j].value;
            break;
        }
    }

    return lookup_env(s.data != NULL ? s : key);
}


static ngx_chain_t *
new_chain(ngx_pool_t *pool, size_t size)
{
    ngx_chain_t *out = ngx_pcalloc(pool, sizeof(ngx_chain_t));
    if (out == NULL)
        return NULL;
    out->buf = ngx_create_temp_buf(pool, size);
    if (out->buf == NULL)
        return NULL;
    return out;
}


static ngx_str_t
transform(ngx_pool_t *pool, ngx_api_gateway_template_t *conf,
    ngx_str_t template)
{
    ngx_chain_t  start, *out;
    ngx_str_t    key, val, s;
    u_char      *c1, *c2;
    ngx_int_t    undefined = 0;

    c2 = template.data;

    out = &start;
    out->buf = NULL;
    out->next = NULL;

    for (c1 = (u_char *) ngx_strstr(c2, "{{");
         c1 != NULL;
         c1 = (u_char *) ngx_strstr(c2, "{{")) {

        out->next = new_chain(pool, c1 - c2 + 2);
        if (out->next == NULL)
            goto nomem;

        out->next->buf->last = ngx_cpymem(out->next->buf->last, c2, c1 - c2);

        c2 = (u_char *) ngx_strstr(c1, "}}");
        if (c2 == NULL) {
            out->next->buf->last = ngx_sprintf(out->next->buf->last, "{{");
            c2 = c1 + 2;
            out = out->next;
            continue;
        }

        key.data = c1 + 2;
        key.len = c2 - c1 - 2;

        // trim

        for (; isspace(key.data[0]); key.data++, key.len--);
        for (; isspace(key.data[key.len - 1]); key.len--);

        out = out->next;

        val = lookup_key(conf, key);
        if (val.data == NULL) {
            val.data = c1;
            val.len = c2 - c1 + 2;
            ngx_log_error(NGX_LOG_ERR, pool->log, 0, "undefined: %V", &key);
            undefined++;
        }

        out->next = new_chain(pool, val.len);
        if (out->next == NULL)
            goto nomem;

        out->next->buf->last = ngx_cpymem(out->next->buf->last,
                                          val.data, val.len);

        c2 += 2;
        out = out->next;
    }

    if (c2 < template.data + template.len) {
        out->next = new_chain(pool, template.data + template.len - c2);
        if (out->next == NULL)
            goto nomem;
        out->next->buf->last = ngx_cpymem(out->next->buf->last, c2,
            template.data + template.len - c2);
    }

    s.len = 0;
    for (out = start.next; out != NULL; out = out->next)
        s.len += out->buf->last - out->buf->start;

    s.data = ngx_pcalloc(pool, s.len + 1);
    if (s.data == NULL)
        goto nomem;
    c1 = s.data;
    for (out = start.next; out != NULL; out = out->next)
        c1 = ngx_cpymem(c1, out->buf->start, out->buf->last - out->buf->start);

    if (undefined != 0) {
        ngx_str_null(&s);
    }

    return s;

nomem:

    ngx_str_null(&s);
    return s;
}


static ngx_int_t
ngx_api_gateway_parse_apilist(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_api_gateway_template_t *conf)
{
    ngx_array_t        apis;
    ngx_str_t         *api;
    yaml_event_t       event;
    yaml_event_type_t  type;
    
    if (ngx_array_init(&apis, pool, 10, sizeof(ngx_str_t)) != NGX_OK)
        goto nomem;

    if (!yaml_parser_parse(parser, &event))
        return NGX_ERROR;

    type = event.type;
    yaml_event_delete(&event);

    if (type != YAML_SEQUENCE_START_EVENT)
        return NGX_DECLINED;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;
        
        switch (type) {
            
            case YAML_SCALAR_EVENT:

                api = ngx_array_push(&apis);
                if (api == NULL)
                    goto nomem_local;

                *api = ngx_strdup(pool, event.data.scalar.value,
                                  event.data.scalar.length);
                if (api->data == NULL)
                    goto nomem_local;

                break;

            case YAML_SEQUENCE_END_EVENT:

                break;

            default:

                yaml_event_delete(&event);
                return NGX_DECLINED;
        }

        yaml_event_delete(&event);
        continue;

nomem_local:

        yaml_event_delete(&event);
        goto nomem;

    } while (type != YAML_SEQUENCE_END_EVENT);

    conf->api = apis.elts;
    conf->napi = apis.nelts;

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_api_gateway_parse_entry(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_api_gateway_template_t *conf)
{
    ngx_array_t        keys;
    ngx_keyval_t      *kv;
    yaml_event_t       event;
    ngx_flag_t         is_key = 1;
    ngx_str_t          path[100];
    ngx_int_t          level = 0;
    ngx_int_t          rc;
    yaml_event_type_t  type;
    static ngx_str_t   apis = ngx_string("apis");

    if (ngx_array_init(&keys, pool, 10, sizeof(ngx_keyval_t)) != NGX_OK)
        goto nomem;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;

        switch (type) {

            case YAML_SCALAR_EVENT:

                if (is_key) {

                    if (ngx_memn2cmp(apis.data, event.data.scalar.value,
                                     apis.len, event.data.scalar.length) == 0) {

                        // api list

                        rc = ngx_api_gateway_parse_apilist(pool, parser, conf);
                        if (rc != NGX_OK) {
                            yaml_event_delete(&event);
                            return rc;
                        }
                        break;

                    } else {

                        // simple key

                        path[level] = ngx_strdup(pool,
                            event.data.scalar.value, event.data.scalar.length);
                        if (path[level].data == NULL)
                            goto nomem_local;
                    }

                } else {

                    kv = ngx_array_push(&keys);
                    if (kv == NULL)
                        goto nomem_local;

                    kv->key = concat_path(pool, path, level);
                    if (kv->key.data == NULL)
                        goto nomem_local;

                    kv->value = ngx_strdup(pool,
                        event.data.scalar.value, event.data.scalar.length);
                    if (kv->value.data == NULL)
                        goto nomem_local;
                }

                is_key = !is_key;
                break;

            case YAML_MAPPING_START_EVENT:

                level++;
                is_key = 1;
                break;

            case YAML_MAPPING_END_EVENT:

                level--;
                is_key = 1;
                break;

            default:

                yaml_event_delete(&event);
                return NGX_DECLINED;
        }

        yaml_event_delete(&event);
        continue;

nomem_local:

        yaml_event_delete(&event);
        goto nomem;

    } while (level >= 0);

    conf->keys = keys.elts;
    conf->nkeys = keys.nelts;

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_api_gateway_parse_entries(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_array_t *a)
{
    ngx_api_gateway_template_t  *conf;
    yaml_event_t                 event;
    yaml_event_type_t            type;
    ngx_int_t                    rc;

    if (!yaml_parser_parse(parser, &event))
        return NGX_ERROR;

    type = event.type;
    yaml_event_delete(&event);

    if (type != YAML_SEQUENCE_START_EVENT)
        return NGX_DECLINED;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;

        switch (type) {

            case YAML_MAPPING_START_EVENT:

                conf = ngx_array_push(a);
                if (conf == NULL) {
                    yaml_event_delete(&event);
                    goto nomem;
                }
                ngx_memzero(conf, sizeof(ngx_api_gateway_template_t));

                rc = ngx_api_gateway_parse_entry(pool, parser, conf);
                if (rc != NGX_OK) {
                    yaml_event_delete(&event);
                    return rc;
                }
                break;

            case YAML_SEQUENCE_END_EVENT:

                break;

            default:

                yaml_event_delete(&event);
                return NGX_DECLINED;
        }

        yaml_event_delete(&event);

    } while (type != YAML_SEQUENCE_END_EVENT);

    yaml_event_delete(&event);

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_api_gateway_template_parse_yaml(ngx_pool_t *pool, FILE *f,
    ngx_api_gateway_t *gw, const char *tag)
{
    ngx_api_gateway_template_t  *conf;
    yaml_parser_t                parser;
    yaml_event_t                 event;
    yaml_event_type_t            type;
    ngx_int_t                    rc = NGX_OK;
    ngx_uint_t                   j;

    if (!yaml_parser_initialize(&parser)) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0, "can't initialize yaml");
        return NGX_ERROR;
    }

    yaml_parser_set_input_file(&parser, f);

    do {
        if (!yaml_parser_parse(&parser, &event)) {

            rc = NGX_ERROR;
            goto done;
        }

        type = event.type;
        
        switch (type) {

            case YAML_SCALAR_EVENT:

                if (ngx_memn2cmp((u_char *) tag, event.data.scalar.value,
                                 strlen(tag), event.data.scalar.length) == 0) {
                    rc = ngx_api_gateway_parse_entries(pool, &parser,
                            &gw->entries);
                    if (rc != NGX_OK)
                        goto done;
                }
                break;

            default:
                break;
        }

        yaml_event_delete(&event);

    } while (type != YAML_STREAM_END_EVENT);

    conf = gw->entries.elts;

    for (j = 0; j < gw->entries.nelts; j++) {
        conf[j].filename = gw->filename;
        conf[j].conf = transform(pool, conf + j, gw->template);
        if (conf[j].conf.data == NULL)
            rc = NGX_ERROR;
    }

done:

    yaml_parser_delete(&parser);
    return rc;
}


static ngx_int_t
ngx_api_gateway_template_apply(ngx_conf_t *cf, ngx_api_gateway_t *gw,
    const char *tag)
{
    ngx_api_gateway_template_t  *conf;
    FILE                        *f;
    ngx_int_t                    rc = NGX_OK;
    ngx_int_t                    i;
    ngx_uint_t                   j;
    char                        *rv;
    ngx_conf_file_t              conf_file;
    ngx_conf_file_t             *prev;
    ngx_str_t                    keyfile = gw->keyfile;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "%V:%V", &gw->filename, &keyfile);

    if (ngx_api_gateway_read_template(cf, gw->filename, &gw->template)
            != NGX_OK)
        return NGX_ERROR;

    if (ngx_conf_full_name(cf->cycle, &keyfile, 1) != NGX_OK)
        return NGX_ERROR;

    f = fopen((const char *) keyfile.data, "r");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, errno, "can't open file: %V",
                           &gw->filename);
        return NGX_DECLINED;
    }

    if (ngx_array_init(&gw->entries, cf->pool, 10,
            sizeof(ngx_api_gateway_template_t)) == NGX_ERROR) {
        rc = NGX_ERROR;
        goto done;
    }

    rc = ngx_api_gateway_template_parse_yaml(cf->pool, f, gw, tag);
    if (rc != NGX_OK)
        goto done;

    gw->yaml.len = ftell(f);
    gw->yaml.data = ngx_palloc(cf->pool, gw->yaml.len);
    if (gw->yaml.data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    fseek(f, 0, SEEK_SET);
    fread(gw->yaml.data, gw->yaml.len, 1, f);

    conf = gw->entries.elts;

    for (j = 0; j < gw->entries.nelts; j++) {

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  keys");
        for (i = 0; i < conf[j].nkeys; i++)
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V:%V",
                          &conf[j].keys[i].key, &conf[j].keys[i].value);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  apis");
        for (i = 0; i < conf[j].napi; i++)
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V",
                          &conf[j].api[i]);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  template\n%V", &gw->template);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  text\n%V", &conf[j].conf);

        ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));

        conf_file.buffer = ngx_create_temp_buf(cf->temp_pool,
            conf[j].conf.len + 1);
        conf_file.file.log = cf->log;
        conf_file.file.name = gw->filename;
        conf_file.line = 1;
        conf_file.file.fd = 0;
        conf_file.file.info.st_size = conf[j].conf.len + 1;
        conf_file.file.offset = conf_file.file.info.st_size;
        conf_file.buffer->last = ngx_cpymem(conf_file.buffer->start,
                conf[j].conf.data, conf[j].conf.len);
        *conf_file.buffer->last++ = '}';

        prev = cf->conf_file;
        cf->conf_file = &conf_file;
        rv = ngx_conf_parse(cf, NULL);
        cf->conf_file = prev;

        if (rv != NGX_CONF_OK)
            rc = NGX_ERROR;
    }

done:

    fclose(f);

    switch (rc) {

        case NGX_OK:
            break;

        case NGX_DECLINED:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid structure");
            return NGX_ERROR;

        default:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
            return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_api_gateway_template(ngx_conf_t *cf, ngx_api_gateway_t *gw, const char *tag)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    gw->filename = value[1];
    gw->keyfile = value[2];

    if (cf->args->nelts == 4) {

        gw->url.url = value[3];
        gw->url.uri_part = 1;
        gw->url.default_port = 80;

        if (ngx_parse_url(cf->pool, &gw->url) != NGX_OK) {

            ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                    "failed to parse url: %V", &gw->url.url);
            return NGX_CONF_ERROR;
        }
    }

    switch (ngx_api_gateway_template_apply(cf, gw, tag)) {

        case NGX_OK:
            return NGX_CONF_OK;

        case NGX_DECLINED:
            return NGX_OK;

        default:
            break;
    }

    return NGX_CONF_ERROR;
}


char *
ngx_api_gateway_entrypoints(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_api_gateway_t            *ep = ngx_array_push(&amcf->entrypoints);
    char                         *rv;

    if (ep == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ep, sizeof(ngx_api_gateway_t));

    rv = ngx_api_gateway_template(cf, ep, "entrypoints");
    if (rv == NGX_CONF_ERROR)
        amcf->entrypoints.nelts--;

    return rv;
}


char *
ngx_api_gateway_backends(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_api_gateway_main_conf_t  *amcf = conf;
    ngx_api_gateway_t            *be = ngx_array_push(&amcf->backends);
    char                         *rv;

    if (be == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(be, sizeof(ngx_api_gateway_t));

    rv = ngx_api_gateway_template(cf, be, "backends");
    if (rv == NGX_CONF_ERROR)
        amcf->backends.nelts--;

    return rv;
}


typedef struct {
    const char         *tag;
    ngx_api_gateway_t  *gw;
    ngx_pool_t         *pool;
} context_t;


static void
ngx_api_gateway_fetch_handler(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *pctx)
{
    context_t          *ctx = pctx;
    ngx_str_t           keyfile = ctx->gw->keyfile;
    FILE               *f;
    ngx_api_gateway_t   gw;
    ngx_tm_t            tm;
    u_char              backup[10240];

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], failed to upsync",
                     &ctx->gw->url.url);
        goto done;
    } else if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], upsync timeout",
                     &ctx->gw->url.url);
        goto done;
    } else if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NO_CONTENT) {

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                     "ngx_api_gateway: [%V], upsync status=%d "
                     "(not 200, 204)", &ctx->gw->url.url, rc);
        goto done;
    }

    if (rc != NGX_HTTP_OK)
        goto done;

    gw.filename = ctx->gw->filename;
    gw.keyfile = ctx->gw->keyfile;
    gw.template = ctx->gw->template;
    gw.filename = ctx->gw->filename;

    ngx_array_init(&gw.entries, ctx->pool,
        10, sizeof(ngx_api_gateway_template_t));

    f = fmemopen(body->data, body->len, "r");
    rc = ngx_api_gateway_template_parse_yaml(ctx->pool, f, &gw, ctx->tag);
    fclose(f);

    if (rc != NGX_OK)
        goto done;

    if (ngx_memn2cmp(body->data, ctx->gw->yaml.data,
                     body->len, ctx->gw->yaml.len) == 0)
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
ngx_api_gateway_fetch_gw(ngx_api_gateway_t *gw, const char *tag)
{
    ngx_pool_t        *pool;
    context_t         *ctx;
    static ngx_str_t   GET = ngx_string("GET");

    if (gw->url.url.data == NULL)
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
    ctx->gw = gw;
    ctx->tag = tag;

    ngx_http_send_request(pool, GET, &gw->url, NULL, 0, NULL, 0, NULL,
        10000, ngx_api_gateway_fetch_handler, ctx);
}


static void
ngx_api_gateway_fetch(ngx_array_t a, const char *tag)
{
    ngx_api_gateway_t  *gw;
    ngx_uint_t          j;

    gw = a.elts;
    for (j = 0; j < a.nelts; j++)
        ngx_api_gateway_fetch_gw(gw + j, tag);
}


void
ngx_api_gateway_fetch_keys(ngx_api_gateway_main_conf_t *amcf)
{
    ngx_api_gateway_fetch(amcf->backends, "backends");
    ngx_api_gateway_fetch(amcf->entrypoints, "entrypoints");
}
