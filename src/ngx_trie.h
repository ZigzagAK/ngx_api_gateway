/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_TRIE_H
#define NGX_TRIE_H


#include <ngx_config.h>
#include <ngx_core.h>


#define MAX_URI_PARTS (1000)


typedef struct {
    ngx_str_node_t    word;
    ngx_str_t         path;
    ngx_str_t         value;
    ngx_rbtree_t      next;
} ngx_trie_node_t;


typedef struct {
    ngx_trie_node_t   root;
    ngx_pool_t       *pool;
    ngx_slab_pool_t  *slab;
    ngx_atomic_t      lock;
    ngx_array_t       data;
    uint32_t          hash;
} ngx_trie_t;


ngx_trie_t * ngx_trie_create(ngx_conf_t *cf);

ngx_int_t ngx_trie_init(ngx_trie_t *trie);

ngx_trie_t * ngx_trie_shm_init(ngx_trie_t *trie, ngx_slab_pool_t *slab);

ngx_int_t ngx_trie_set(ngx_trie_t *trie, ngx_str_t path, ngx_str_t value);

ngx_int_t ngx_trie_delete(ngx_trie_t *trie, ngx_str_t path);

ngx_int_t ngx_trie_find(ngx_trie_t *trie, ngx_str_t *path, ngx_keyval_t *retval,
    ngx_pool_t *temp_pool);

void ngx_trie_free(ngx_trie_t *trie);

ngx_trie_t * ngx_trie_swap(ngx_trie_t *dst, ngx_trie_t *src);

uint32_t ngx_trie_hash(ngx_trie_t *trie);

#endif /* NGX_TRIE_H */
