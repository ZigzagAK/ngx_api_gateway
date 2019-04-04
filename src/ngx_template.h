/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_TEMPLATE_H
#define NGX_TEMPLATE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <yaml.h>


typedef struct {
    ngx_str_t      key;
    ngx_str_t     *elts;
    ngx_uint_t     nelts;
} ngx_template_seq_t;


typedef struct {
    ngx_keyval_t  *keys;
    ngx_uint_t     nkeys;
    ngx_str_t      conf;
    ngx_str_t      name;
    ngx_array_t    seqs;
} ngx_template_conf_t;


typedef struct {
    ngx_str_t      tag;
    ngx_array_t    entries;
    ngx_str_t      keyfile;
    ngx_str_t      yaml;
    ngx_str_t      filename;
    ngx_str_t      template;
    time_t         updated;
} ngx_template_t;


typedef struct {
    ngx_array_t    templates;
} ngx_template_main_conf_t;


void * ngx_template_create_main_conf(ngx_cycle_t *cycle);

char * ngx_template_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void ngx_template_check_updates(ngx_template_main_conf_t *tmcf);


/* helpers */

ngx_int_t ngx_template_tag(ngx_conf_t *cf, ngx_str_t keyfile, ngx_str_t *tag);

ngx_str_t ngx_strdup(ngx_pool_t *pool, u_char *s, size_t len);

typedef ngx_int_t (*on_key_t)(ngx_str_t path, yaml_char_t *key, size_t key_len,
    ngx_pool_t *pool, yaml_parser_t *parser, ngx_template_conf_t *conf,
    ngx_str_t *retval);

ngx_int_t
ngx_template_conf_apply(ngx_conf_t *cf, ngx_template_t *t, on_key_t pfkey);

ngx_int_t ngx_template_conf_parse_yaml(ngx_pool_t *pool, FILE *f,
    ngx_template_t *t, on_key_t pfkey);

ngx_int_t lookup(ngx_array_t *templates, ngx_str_t key, ngx_str_t *retval);

ngx_template_conf_t *
ngx_template_lookup_by_name(ngx_template_main_conf_t *tmcf, ngx_str_t name);

#endif /* NGX_TEMPLATE_H */
