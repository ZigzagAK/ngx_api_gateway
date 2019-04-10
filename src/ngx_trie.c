/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_trie.h"


ngx_trie_t *
ngx_trie_create(ngx_pool_t *pool)
{
    ngx_trie_t  *trie;

    trie = ngx_pcalloc(pool, sizeof(ngx_trie_t));
    if (trie == NULL)
        return NULL;

    trie->pool = pool;

    if (ngx_array_init(&trie->data, pool, 1000, sizeof(ngx_keyval_t))
            == NGX_ERROR)
        return NULL;

    return trie;
}


static void *
ngx_trie_alloc(ngx_trie_t *trie, size_t size)
{
    if (trie->slab != NULL)
        return ngx_slab_alloc(trie->slab, size);

    return ngx_palloc(trie->pool, size);
}


static void
ngx_trie_free(ngx_trie_t *trie, void *p)
{
    if (p == NULL)
        return;

    if (trie->slab != NULL) {
        ngx_slab_free(trie->slab, p);
        return;
    }

    ngx_pfree(trie->pool, p);
}


static ngx_str_t
ngx_trie_dupstr(ngx_trie_t *trie, ngx_str_t s)
{
    ngx_str_t  dup = ngx_null_string;
    dup.data = ngx_trie_alloc(trie, s.len);
    if (dup.data == NULL)
        return dup;
    ngx_memcpy(dup.data, s.data, s.len);
    dup.len = s.len;
    return dup;
}


ngx_int_t
ngx_trie_init(ngx_trie_t *trie)
{
    ngx_rbtree_node_t  *sentinel;
    ngx_uint_t          j;
    ngx_keyval_t       *kv;

    if (trie->root.next.root != NULL)
        return NGX_OK;

    sentinel = ngx_trie_alloc(trie, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL)
        return NGX_ERROR;

    ngx_rbtree_init(&trie->root.next, sentinel, ngx_str_rbtree_insert_value);

    kv = trie->data.elts;

    for (j = 0; j < trie->data.nelts; j++)
        if (ngx_trie_set(trie, kv[j].key, kv[j].value) == NGX_ERROR)
            return NGX_ERROR;

    ngx_memzero(trie->data.elts, trie->data.size * trie->data.nalloc);
    trie->data.nelts = 0;

    return NGX_OK;
}


ngx_trie_t *
ngx_trie_shm_init(ngx_trie_t *trie, ngx_slab_pool_t *slab)
{
    ngx_trie_t  *shtrie;

    shtrie = ngx_slab_calloc(slab, sizeof(ngx_trie_t));
    if (shtrie == NULL)
        return NULL;

    if (trie != NULL)
        shtrie->data = trie->data;
    shtrie->slab = slab;

    if (ngx_trie_init(shtrie) == NGX_ERROR)
        return NULL;

    return shtrie;
}


static ngx_trie_node_t *
ngx_trie_lookup(ngx_trie_node_t *parent, ngx_str_t word)
{
    return (ngx_trie_node_t *) ngx_str_rbtree_lookup(&parent->next, &word,
        ngx_crc32_short(word.data, word.len));
}


static ngx_trie_node_t *
ngx_trie_insert_node(ngx_trie_t *trie, ngx_trie_node_t *parent, ngx_str_t word)
{
    ngx_rbtree_node_t  *node;
    ngx_trie_node_t    *next;
    uint32_t            hash;
    ngx_rbtree_node_t  *sentinel;

    hash = ngx_crc32_short(word.data, word.len);

    next = (ngx_trie_node_t *)
            ngx_str_rbtree_lookup(&parent->next, &word, hash);

    if (next != NULL)
        return next;

    next = ngx_trie_alloc(trie, sizeof(ngx_trie_node_t));
    if (next == NULL)
        return NULL;

    ngx_memzero(next, sizeof(ngx_trie_node_t));

    next->word.str = ngx_trie_dupstr(trie, word);
    if (next->word.str.data == NULL)
        return NULL;

    sentinel = ngx_trie_alloc(trie, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL)
        return NULL;

    ngx_rbtree_init(&next->next, sentinel, ngx_str_rbtree_insert_value);

    next->parent = parent;

    node = (ngx_rbtree_node_t *) next;
    node->key = hash;

    ngx_rbtree_insert(&parent->next, node);

    return next;
}


static ngx_int_t
split(ngx_str_t path, ngx_str_t *word, ngx_uint_t n)
{
    u_char  *c1, *c2;

    for (c1 = c2 = path.data + 1; c2 <= path.data + path.len; c2++) {

        if (c2 == path.data + path.len || *c2 == '/') {

            if (n-- == 0)
                return NGX_ERROR;

            word->data = c1;
            word->len = c2 - c1;

            c1 = ++c2;
            word++;
        }
    }

    word->data = NULL;
    word->len = 0;

    return NGX_OK;
}


ngx_int_t
ngx_trie_set(ngx_trie_t *trie, ngx_str_t path, ngx_str_t value)
{
    ngx_uint_t        j;
    ngx_trie_node_t  *node = &trie->root, *next;
    ngx_keyval_t     *kv;
    ngx_str_t         word[MAX_URI_PARTS + 1];

    if (trie->root.next.root == NULL) {

        kv = ngx_array_push(&trie->data);
        if (kv == NULL)
            return NGX_ERROR;

        kv->key = path;
        kv->value = value;

        return NGX_OK;
    }

    if (split(path, word, MAX_URI_PARTS) == NGX_ERROR)
        return NGX_ERROR;

    for (j = 0; word[j].data != NULL; j++, node = next) {

        if (value.data != NULL) {

            // insert

            next = ngx_trie_insert_node(trie, node, word[j]);
            if (next == NULL)
                return NGX_ERROR;

        } else {

            // delete

            next = ngx_trie_lookup(node, word[j]);
            if (next == NULL)
                break;

        }

        if (word[j + 1].data == NULL) {

            // free old value

            ngx_trie_free(trie, next->value.data);
            ngx_str_null(&next->value);

            if (next->path.data == NULL) {

                // new node added

                next->path = ngx_trie_dupstr(trie, path);
                if (next->path.data == NULL)
                    return NGX_ERROR;
            }

            if (value.data != NULL) {

                // insert

                next->value = ngx_trie_dupstr(trie, value);
                if (next->value.data == NULL)
                    return NGX_ERROR;

            } else {

                // delete

                for (node = next;
                     node->next.root == node->next.sentinel
                             && NULL == node->value.data;
                     node = next) {

                    ngx_rbtree_delete(&node->parent->next,
                        (ngx_rbtree_node_t *) node);

                    ngx_trie_free(trie, node->path.data);
                    ngx_trie_free(trie, node->word.str.data);
                    ngx_trie_free(trie, node->next.sentinel);

                    next = node->parent;

                    ngx_trie_free(trie, node);

                    if (next->parent == NULL)
                        break;
                }
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_trie_delete(ngx_trie_t *trie, ngx_str_t path)
{
    static ngx_str_t  null = ngx_null_string;
    return ngx_trie_set(trie, path, null);
}


ngx_int_t
ngx_trie_find(ngx_trie_t *trie, ngx_str_t *path, ngx_keyval_t *retval)
{
    ngx_uint_t        j;
    ngx_trie_node_t  *node = &trie->root, *next;
    ngx_trie_node_t  *last = NULL;
    ngx_str_t         word[MAX_URI_PARTS + 1];
    ngx_int_t         rc = NGX_DECLINED;

    static ngx_str_t  star = ngx_string("*");

    if (split(*path, word, MAX_URI_PARTS) == NGX_ERROR)
        return NGX_ERROR;

    for (j = 0; word[j].data != NULL; j++) {

        next = ngx_trie_lookup(node, word[j]);
        if (next == NULL) {
            next = ngx_trie_lookup(node, star);
            if (next == NULL)
                break;
        }

        if (next->value.data != NULL)
            last = next;

        node = next;
    }

    if (last != NULL) {

        retval->key = last->path;
        retval->value = last->value;
        rc = NGX_OK;
    }

    return rc;
}


void
ngx_trie_free_node(ngx_trie_t *trie, ngx_trie_node_t *parent)
{
    ngx_rbtree_t     *rbtree = &parent->next;
    ngx_trie_node_t  *node;

again:

    if (rbtree->root == rbtree->sentinel)
        return;

    node = (ngx_trie_node_t *) ngx_rbtree_min(rbtree->root, rbtree->sentinel);

    ngx_rbtree_delete(rbtree, (ngx_rbtree_node_t *) node);

    ngx_trie_free(trie, node->path.data);
    ngx_trie_free(trie, node->value.data);
    ngx_trie_free(trie, node->word.str.data);
    ngx_trie_free(trie, node->next.sentinel);
    ngx_trie_free(trie, node);

    goto again;
}


void
ngx_trie_destroy(ngx_trie_t *trie)
{
    if (trie != NULL) {
        ngx_trie_free_node(trie, &trie->root);
        ngx_trie_free(trie, trie);
    }
}


void
ngx_trie_clear(ngx_trie_t *trie)
{
    if (trie != NULL)
        ngx_trie_free_node(trie, &trie->root);
}


void
ngx_trie_swap(ngx_trie_t *l, ngx_trie_t *r)
{
    ngx_trie_t  tmp;

    tmp.root = r->root;
    tmp.pool = r->pool;
    tmp.slab = r->slab;
    tmp.data = r->data;

    r->root = l->root;
    r->pool = l->pool;
    r->slab = l->slab;
    r->data = l->data;

    l->root = tmp.root;
    l->pool = tmp.pool;
    l->slab = tmp.slab;
    l->data = tmp.data;
}
