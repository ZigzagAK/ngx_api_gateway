/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_TRIE_H
#define NGX_TRIE_H


#include <ngx_config.h>
#include <ngx_core.h>


#define MAX_URI_PARTS (1000)


struct ngx_trie_node_s {
    ngx_str_node_t           word;
    ngx_str_t                path;
    ngx_str_t                value;
    ngx_rbtree_t             next;
    struct ngx_trie_node_s  *parent;
};
typedef struct ngx_trie_node_s ngx_trie_node_t;


typedef struct {
    ngx_trie_node_t   root;
    ngx_pool_t       *pool;
    ngx_slab_pool_t  *slab;
    ngx_array_t       data;
} ngx_trie_t;


ngx_trie_t * ngx_trie_create(ngx_pool_t *pool);

ngx_int_t ngx_trie_init(ngx_trie_t *trie);

ngx_trie_t * ngx_trie_shm_init(ngx_trie_t *trie, ngx_slab_pool_t *slab);

ngx_int_t ngx_trie_set(ngx_trie_t *trie, ngx_str_t path, ngx_str_t value);

ngx_int_t ngx_trie_delete(ngx_trie_t *trie, ngx_str_t path);

ngx_int_t ngx_trie_find(ngx_trie_t *trie, ngx_str_t *path,
    ngx_keyval_t *retval);

void ngx_trie_destroy(ngx_trie_t *trie);

void ngx_trie_clear(ngx_trie_t *trie);

void ngx_trie_swap(ngx_trie_t *l, ngx_trie_t *r);

typedef ngx_int_t (*ngx_trie_scan_fun_t)(ngx_str_t path, ngx_str_t value,
    void *data);

ngx_int_t ngx_trie_scan(ngx_trie_t *trie, ngx_trie_scan_fun_t f, void *data);

#endif /* NGX_TRIE_H */
