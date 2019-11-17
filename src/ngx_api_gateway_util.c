#include "ngx_api_gateway_util.h"

ngx_int_t
send_response(ngx_http_request_t *r, ngx_uint_t status, const char *text)
{
    ngx_http_complex_value_t   cv;
    ngx_str_t                 *ct = NULL;

    static ngx_str_t TEXT_PLAIN = ngx_string("text/plain");

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    if (text == NULL || text[0] == 0) {
        r->header_only = 1;
    } else {
        ct = &TEXT_PLAIN;
        cv.value.len = strlen(text);
        cv.value.data = (u_char *) text;
    }

    return ngx_http_send_response(r, status, ct, &cv);
}


ngx_int_t
send_header(ngx_http_request_t *r, ngx_uint_t status)
{
    return send_response(r, status, NULL);
}


ngx_int_t
send_no_content(ngx_http_request_t *r)
{
    return send_header(r, NGX_HTTP_NO_CONTENT);
}


ngx_int_t
send_not_modified(ngx_http_request_t *r)
{
    return send_header(r, NGX_HTTP_NOT_MODIFIED);
}


static ngx_str_t
get_var_unescape(ngx_http_request_t *r, const char *v)
{
    ngx_str_t                   var = { ngx_strlen(v), (u_char *) v };
    ngx_http_variable_value_t  *value;
    u_char                     *dst, *src;
    ngx_str_t                   retval = ngx_null_string;

    value = ngx_http_get_variable(r, &var, ngx_hash_key(var.data, var.len));

    if (value->not_found)
        return retval;

    src = value->data;

    dst = ngx_pcalloc(r->pool, value->len + 1);
    if (dst == NULL)
        return retval;

    retval.data = dst;

    ngx_unescape_uri(&dst, &src, value->len, 0);

    retval.len = dst - retval.data;

    return retval;
}


ngx_str_t
get_var_str(ngx_http_request_t *r, const char *v, const char *def)
{
    ngx_str_t  retval = get_var_unescape(r, v);

    if (retval.data == NULL) {
        retval.data = (u_char *) def;
        if (def != NULL)
            retval.len = strlen(def);
    }

    return retval;
}


ngx_int_t
get_var_num(ngx_http_request_t *r, const char *v, ngx_int_t def)
{
    ngx_str_t                   var = { ngx_strlen(v), (u_char *) v };
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_variable(r, &var, ngx_hash_key(var.data, var.len));

    if (value->not_found)
        return def;

    return ngx_atoi(value->data, value->len);
}


ngx_str_t
ngx_dupstr(ngx_pool_t *pool, u_char *s, size_t len)
{
    ngx_str_t  retval = ngx_null_string;

    retval.data = ngx_pcalloc(pool, len + 1);

    if (retval.data) {
        ngx_memcpy(retval.data, s, len);
        retval.len = len;
        retval.data[retval.len] = 0;
    }

    return retval;
}
