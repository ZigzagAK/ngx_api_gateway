/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_TRIE_H
#define NGX_TRIE_H


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_str_node_t    word;
    ngx_str_t         value;
    ngx_rbtree_t      next;
} ngx_trie_node_t;


typedef struct {
    ngx_pool_t       *pool;
    ngx_trie_node_t   root;
} ngx_trie_t;


ngx_int_t ngx_trie_init(ngx_pool_t *pool, ngx_trie_t *trie);

ngx_int_t ngx_trie_set(ngx_trie_t *trie, ngx_str_t path, ngx_str_t value);

ngx_int_t ngx_trie_find(ngx_trie_t *trie, ngx_str_t *path, ngx_str_t *retval,
    ngx_pool_t *temp_pool);


#endif /* NGX_TRIE_H */
