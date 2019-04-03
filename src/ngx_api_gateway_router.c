#include "ngx_api_gateway_router.h"
#include "ngx_template.h"

#include <ngx_http.h>


ngx_int_t
ngx_api_gateway_router_init_conf(ngx_conf_t *cf,
    ngx_http_api_gateway_conf_t *conf)
{
    if (NGX_ERROR == ngx_array_init(&conf->backends, cf->pool,
                                    10, sizeof(ngx_str_t)))
        return NGX_ERROR;

    if (NGX_ERROR == ngx_array_init(&conf->map.regex, cf->pool,
                                    10, sizeof(ngx_mapping_regex_t)))
        return NGX_ERROR;

    if (NGX_ERROR == ngx_trie_init(cf->pool, &conf->map.tree))
        return NGX_ERROR;

    return NGX_OK;
}
    

char *
ngx_api_gateway_router(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *glcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        j;
    ngx_conf_post_t                  *post = cmd->post;
    ngx_http_api_gateway_conf_t      *gateway_conf;

    gateway_conf = ngx_array_push(&glcf->entries);
    if (gateway_conf == NULL
        || ngx_api_gateway_router_init_conf(cf, gateway_conf) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    gateway_conf->var = value[1];
    if (gateway_conf->var.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "required '$' as variable prefix");
        return NGX_CONF_ERROR;
    }

    gateway_conf->var.data++;
    gateway_conf->var.len--;

    for (j = 2; j < cf->args->nelts; j++) {
        s = ngx_array_push(&gateway_conf->backends);
        if (s == NULL)
            return NGX_CONF_ERROR;
        *s = value[j];
    }

    return post->post_handler(cf, cmd, gateway_conf);
}


ngx_int_t
ngx_api_gateway_router_build(ngx_pool_t *pool,
    ngx_http_api_gateway_mapping_t *m, ngx_str_t backend,
    ngx_template_list_t entries)
{
    ngx_mapping_regex_t  *regex;
    ngx_uint_t            j;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t   rc;
    ngx_str_t             path;

    for (j = 0; j < entries.nelts; j++) {

        path = entries.elts[j];

        if (path.data[0] != '~') {

            if (ngx_trie_set(&m->tree, path, backend) == NGX_ERROR)
                goto nomem;

            continue;
        }

        regex = ngx_array_push(&m->regex);
        if (regex == NULL)
            goto nomem;

        path.data++;
        path.len--;

        while (path.len > 0 && isspace(*path.data)) {
            path.data++;
            path.len--;
        }

        if (path.len == 0) {

            ngx_log_error(NGX_LOG_EMERG, pool->log, 0,
                "%V: empty regex", &backend);
            return NGX_ERROR;
        }

        regex->backend = backend;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = path;
        rc.pool = pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.options = PCRE_UNGREEDY;

        if (ngx_regex_compile(&rc) != NGX_OK) {

            ngx_log_error(NGX_LOG_EMERG, pool->log, 0,
                "%V: failed to compile %V, %V",
                &backend, &rc.pattern, &rc.err);
            return NGX_ERROR;
        }

        regex->re = rc.regex;
        regex->pattern = rc.pattern;
    }

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_router_match(ngx_pool_t *temp_pool,
    ngx_http_api_gateway_mapping_t *m,
    ngx_str_t *uri, ngx_str_t *upstream)
{
    ngx_uint_t            j;
    ngx_mapping_regex_t  *regex;
    int                   captures[3];

    switch (ngx_trie_find(&m->tree, uri, upstream, temp_pool))  {

        case NGX_OK:

            return NGX_OK;

        case NGX_DECLINED:

            break;

        case NGX_ERROR:
        default:

            return NGX_ERROR;
    }

    regex = m->regex.elts;

    for (j = 0; j < m->regex.nelts; j++) {

        if (ngx_regex_exec(regex[j].re, uri, captures, 3) > 0) {

            *upstream = regex[j].backend;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
