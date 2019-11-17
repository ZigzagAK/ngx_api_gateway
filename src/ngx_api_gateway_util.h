/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_API_GATEWAY_UTIL_H
#define NGX_API_GATEWAY_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t send_response(ngx_http_request_t *r, ngx_uint_t status,
    const char *text);

ngx_int_t send_header(ngx_http_request_t *r, ngx_uint_t status);

ngx_int_t send_no_content(ngx_http_request_t *r);

ngx_int_t send_not_modified(ngx_http_request_t *r);

ngx_str_t get_var_str(ngx_http_request_t *r, const char *v, const char *def);

ngx_int_t get_var_num(ngx_http_request_t *r, const char *v, ngx_int_t def);

ngx_str_t ngx_dupstr(ngx_pool_t *pool, u_char *s, size_t len);


#ifdef __cplusplus
}
#endif

#endif /* NGX_API_GATEWAY_UTIL_H */
