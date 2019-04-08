/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway_router.h"
#include "ngx_template.h"
#include "ngx_regex_shm.h"

#include <ngx_http.h>


extern ngx_str_t ngx_strdup(ngx_pool_t *pool, u_char *s, size_t len);


ngx_int_t
ngx_api_gateway_router_init_conf(ngx_conf_t *cf,
    ngx_http_api_gateway_conf_t *gateway_conf)
{
    if (NGX_ERROR == ngx_array_init(&gateway_conf->backends, cf->pool,
                                    10, sizeof(ngx_str_t)))
        return NGX_ERROR;

    gateway_conf->map.trie = ngx_trie_create(cf);
    if (gateway_conf->map.trie == NULL)
        return NGX_ERROR;

    gateway_conf->map.regex = ngx_pcalloc(cf->pool, sizeof(ngx_queue_t));
    if (gateway_conf->map.regex == NULL)
        return NGX_ERROR;

    ngx_queue_init(gateway_conf->map.regex);

    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_router_check_var(ngx_str_t var, ngx_array_t a)
{
    ngx_uint_t                    j;
    ngx_http_api_gateway_conf_t  *gateway_conf;

    gateway_conf = a.elts;
    
    for (j = 0; j < a.nelts; j++) {
        if (ngx_memn2cmp(gateway_conf[j].var.data, var.data,
                         gateway_conf[j].var.len, var.len) == 0)
            return NGX_ERROR;
    }

    return NGX_OK;
}


char *
ngx_api_gateway_router(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *alcf = conf;
    ngx_str_t                        *value, *s, var;
    ngx_uint_t                        j;
    ngx_conf_post_t                  *post = cmd->post;
    ngx_http_api_gateway_conf_t      *gateway_conf;

    value = cf->args->elts;

    var = value[1];
    if (var.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "required '$' as variable prefix");
        return NGX_CONF_ERROR;
    }

    var.data++;
    var.len--;

    if (ngx_api_gateway_router_check_var(var, alcf->entries) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "duplicate location router variable '$%V'", &var);
        return NGX_CONF_ERROR;
    }

    gateway_conf = ngx_array_push(&alcf->entries);
    if (gateway_conf == NULL
        || ngx_api_gateway_router_init_conf(cf, gateway_conf) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    gateway_conf->var = var;

    for (j = 2; j < cf->args->nelts; j++) {
        s = ngx_array_push(&gateway_conf->backends);
        if (s == NULL)
            return NGX_CONF_ERROR;
        *s = value[j];
    }

    return post->post_handler(cf, gateway_conf, conf);
}


ngx_int_t
ngx_api_gateway_router_build(ngx_cycle_t *cycle, ngx_pool_t *pool,
    ngx_http_api_gateway_mapping_t *m, ngx_str_t backend,
    ngx_template_seq_t entries)
{
    ngx_mapping_regex_t  *regex;
    ngx_uint_t            j;
    ngx_str_t             path;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    for (j = 0; j < entries.nelts; j++) {

        path = entries.elts[j];

        if (path.data[0] != '~') {

            if (ngx_trie_set(m->trie, path, backend) == NGX_ERROR)
                goto nomem;

            continue;
        }

        regex = ngx_pcalloc(pool, sizeof(ngx_mapping_regex_t));
        if (regex == NULL)
            goto nomem;

        path.data++;
        path.len--;

        ngx_trim(&path);

        if (path.len == 0) {

            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                "%V: empty regex", &backend);
            return NGX_ERROR;
        }

        regex->backend = backend;
        regex->pattern = path;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = regex->pattern;
        rc.pool = pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.options = PCRE_UNGREEDY;

        if (ngx_regex_compile(&rc) != NGX_OK) {

            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                "%V: failed to compile %V, %V",
                &regex->backend, &rc.pattern, &rc.err);
            return NGX_ERROR;
        }

        regex->re = rc.regex;

        ngx_queue_insert_tail(m->regex, &regex->queue);
    }

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_router_init(ngx_http_api_gateway_conf_t *gateway_conf,
    ngx_http_api_gateway_shctx_t *sh)
{
    ngx_mapping_regex_t     *regex, *regex_shm;
    ngx_queue_t             *q;
    ngx_regex_shm_compile_t  rc;
    u_char                   errstr[NGX_MAX_CONF_ERRSTR];

    sh->map.lock = ngx_slab_calloc(sh->slab, sizeof(ngx_atomic_t));
    if (sh->map.lock == NULL)
        goto nomem;

    sh->map.trie = ngx_trie_shm_init(gateway_conf->map.trie, sh->slab);
    if (sh->map.trie == NULL)
        goto nomem;

    sh->map.regex = ngx_slab_alloc(sh->slab, sizeof(ngx_queue_t));
    if (sh->map.regex == NULL)
        goto nomem;

    ngx_queue_init(sh->map.regex);

    for (q = ngx_queue_head(gateway_conf->map.regex);
         q != ngx_queue_sentinel(gateway_conf->map.regex);
         q = ngx_queue_next(q))
    {
        regex = ngx_queue_data(q, ngx_mapping_regex_t, queue);

        ngx_memzero(&rc, sizeof(ngx_regex_shm_compile_t));

        rc.pattern = regex->pattern;
        rc.slab = sh->slab;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.options = PCRE_UNGREEDY;

        if (ngx_regex_shm_compile(&rc) != NGX_OK) {

            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                "%V: failed to compile %V, %V",
                &regex->backend, &rc.pattern, &rc.err);
            return NGX_ERROR;
        }

        regex_shm = ngx_slab_alloc(sh->slab, sizeof(ngx_mapping_regex_t));
        if (regex_shm == NULL)
            goto nomem;

        regex_shm->backend.data = ngx_slab_alloc(sh->slab, regex->backend.len);
        regex_shm->pattern.data = ngx_slab_alloc(sh->slab, regex->pattern.len);

        if (regex_shm->backend.data == NULL || regex_shm->pattern.data == NULL)
            goto nomem;

        ngx_memcpy(regex_shm->backend.data, regex->backend.data,
                   regex->backend.len);
        ngx_memcpy(regex_shm->pattern.data, regex->pattern.data,
                   regex->pattern.len);

        regex_shm->backend.len = regex->backend.len;
        regex_shm->pattern.len = regex->pattern.len;
        regex_shm->re = regex->re;

        ngx_queue_insert_tail(sh->map.regex, &regex_shm->queue);
    }

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "%V: no shared memory", &regex->backend);
    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_router_match(ngx_pool_t *temp_pool,
    ngx_http_api_gateway_mapping_t *m,
    ngx_str_t *uri, ngx_str_t *path, ngx_str_t *upstream)
{
    ngx_mapping_regex_t  *regex;
    ngx_queue_t          *q;
    int                   captures[3];
    ngx_keyval_t          retval = { ngx_null_string, ngx_null_string };

    ngx_str_null(path);
    ngx_str_null(upstream);

    if (m->lock != NULL)
        ngx_rwlock_rlock(m->lock);

    switch (ngx_trie_find(m->trie, uri, &retval)) {

        case NGX_OK:
            goto done;

        case NGX_DECLINED:
            break;

        case NGX_ERROR:
        default:
            goto done;
    }

    for (q = ngx_queue_head(m->regex);
         q != ngx_queue_sentinel(m->regex);
         q = ngx_queue_next(q))
    {
        regex = ngx_queue_data(q, ngx_mapping_regex_t, queue);

        if (ngx_regex_exec(regex->re, uri, captures, 3) > 0) {

            retval.key = regex->pattern;
            retval.value = regex->backend;

            break;
        }
    }

done:

    if (retval.key.data != NULL) {

        path->data = ngx_pstrdup(temp_pool, &retval.key);

        if (path->data != NULL) {

            upstream->data = ngx_pstrdup(temp_pool, &retval.value);

            if (upstream->data != NULL) {

                path->len = retval.key.len;
                upstream->len = retval.value.len;
            }
        }
    }

    if (m->lock != NULL)
        ngx_rwlock_unlock(m->lock);

    return upstream->data != NULL ? NGX_OK : NGX_DECLINED;
}
