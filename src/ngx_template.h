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
    ngx_str_t      group;
    ngx_keyval_t  *keys;
    ngx_uint_t     nkeys;
    ngx_str_t      conf;
    ngx_str_t      name;
    ngx_array_t    seqs;
} ngx_template_conf_t;


typedef ngx_int_t (*on_key_t)(ngx_str_t path, yaml_char_t *key, size_t key_len,
    ngx_pool_t *pool, yaml_parser_t *parser, ngx_template_conf_t *conf,
    ngx_str_t *retval);


typedef struct {
    ngx_keyval_t  *elts;
    ngx_uint_t     nelts;
} ngx_args_t;

typedef struct {
    ngx_str_t      group;
    ngx_args_t     args;
    ngx_array_t    entries;
    ngx_str_t      keyfile;
    ngx_str_t      yaml;
    ngx_str_t      filename;
    ngx_str_t      template;
    time_t         updated;
    on_key_t       pfkey;
    ngx_pool_t    *pool;
} ngx_template_t;


typedef struct {
    ngx_array_t    templates;
    ngx_cycle_t   *cycle;
    ngx_flag_t     changed;
} ngx_template_main_conf_t;


void * ngx_template_create_main_conf(ngx_cycle_t *cycle);

char * ngx_template_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void ngx_template_check_updates(ngx_template_main_conf_t *tmcf);


/* helpers */

void ngx_trim(ngx_str_t *s);

ngx_keyval_t ngx_split(ngx_str_t s, u_char c);

ngx_int_t ngx_parse_args(ngx_conf_t *cf, ngx_keyval_t **args,
    ngx_uint_t *nargs);

ngx_flag_t ngx_eqstr(ngx_str_t s, const char *c);

ngx_str_t ngx_strdup(ngx_pool_t *pool, u_char *s, size_t len);

ngx_template_t * ngx_template_add(ngx_conf_t *cf, on_key_t pfkey);

ngx_int_t ngx_template_conf_parse_yaml(ngx_cycle_t *cycle, FILE *f,
    ngx_template_t *t);

ngx_int_t lookup(ngx_cycle_t *cycle, ngx_str_t key, ngx_str_t *retval);

ngx_template_conf_t * ngx_template_lookup_by_name(ngx_cycle_t *cycle,
    ngx_str_t name);

typedef ngx_int_t (*scan_fun_t)(ngx_template_t *t, void *data);

ngx_int_t ngx_template_scan(ngx_cycle_t *cycle, scan_fun_t cb, void *data);

#endif /* NGX_TEMPLATE_H */
