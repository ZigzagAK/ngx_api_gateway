/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_REGEX_SHM_H
#define NGX_REGEX_SHM_H


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_str_t         pattern;
    ngx_slab_pool_t  *slab;
    ngx_int_t         options;
    ngx_regex_t      *regex;
    int               captures;
    int               named_captures;
    int               name_size;
    u_char           *names;
    ngx_str_t         err;
} ngx_regex_shm_compile_t;


ngx_int_t ngx_regex_shm_compile(ngx_regex_shm_compile_t *rc);


#endif /* NGX_REGEX_SHM_H */

