#include "ngx_api_gateway_router.h"
#include "ngx_template.h"

#include <ngx_http.h>



char *
ngx_api_gateway_router(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_api_gateway_loc_conf_t  *glcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        j;
    ngx_conf_post_t                  *post = cmd->post;

    value = cf->args->elts;

    glcf->var = value[1];
    if (glcf->var.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "required '$' as variable prefix");
        return NGX_CONF_ERROR;
    }

    glcf->var.data++;
    glcf->var.len--;

    for (j = 2; j < cf->args->nelts; j++) {
        s = ngx_array_push(&glcf->backends);
        if (s == NULL)
            return NGX_CONF_ERROR;
        *s = value[j];
    }

    return post->post_handler(cf, cmd, conf);
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

    for (j = 0; j < entries.nelts; j++) {

        regex = ngx_array_push(&m->regex);
        if (regex == NULL)
            goto nomem;

        regex->backend = backend;

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = entries.elts[j];
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
ngx_api_gateway_router_match(ngx_http_api_gateway_mapping_t *m,
    ngx_str_t *uri, ngx_str_t *upstream)
{
    ngx_uint_t            j;
    ngx_mapping_regex_t  *regex;
    int                   captures[3];

    regex = m->regex.elts;

    for (j = 0; j < m->regex.nelts; j++) {

        if (ngx_regex_exec(regex[j].re, uri, captures, 3) > 0) {

            *upstream = regex[j].backend;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
