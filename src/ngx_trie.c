#include "ngx_trie.h"

ngx_int_t
ngx_trie_init(ngx_pool_t *pool, ngx_trie_t *trie)
{
    ngx_rbtree_node_t  *sentinel;

    trie->pool = pool;
    
    sentinel = ngx_pcalloc(pool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL)
        return NGX_ERROR;

    ngx_rbtree_init(&trie->root.next, sentinel, ngx_str_rbtree_insert_value);

    return NGX_OK;
}


static ngx_trie_node_t *
ngx_trie_lookup(ngx_rbtree_t *rbtree, ngx_str_t word)
{
    return (ngx_trie_node_t *) ngx_str_rbtree_lookup(rbtree, &word,
        ngx_crc32_short(word.data, word.len));
}


static ngx_trie_node_t *
ngx_trie_insert_node(ngx_pool_t *pool, ngx_rbtree_t *rbtree, ngx_str_t word)
{
    ngx_rbtree_node_t  *node;
    ngx_trie_node_t    *trie_node;
    uint32_t            hash;
    ngx_rbtree_node_t  *sentinel;

    hash = ngx_crc32_short(word.data, word.len);

    trie_node = (ngx_trie_node_t *) ngx_str_rbtree_lookup(rbtree, &word, hash);

    if (trie_node != NULL)
        return trie_node;

    trie_node = ngx_pcalloc(pool, sizeof(ngx_trie_node_t));
    if (trie_node == NULL)
        return NULL;

    trie_node->word.str = word;

    sentinel = ngx_pcalloc(pool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL)
        return NULL;

    ngx_rbtree_init(&trie_node->next, sentinel, ngx_str_rbtree_insert_value);

    node = (ngx_rbtree_node_t *) trie_node;
    node->key = hash;

    ngx_rbtree_insert(rbtree, node);

    return trie_node;
}


static ngx_int_t
split(ngx_pool_t *pool, ngx_str_t path, ngx_array_t *parts)
{
    u_char     *c1, *c2;
    ngx_str_t  *word;

    if (ngx_array_init(parts, pool, 10, sizeof(ngx_str_t)) == NGX_ERROR)
        return NGX_ERROR;

    for (c1 = c2 = path.data + 1; c2 <= path.data + path.len; c2++) {

        if (c2 == path.data + path.len || *c2 == '/') {

            word = ngx_array_push(parts);
            if (word == NULL)
                return NGX_ERROR;

            word->data = c1;
            word->len = c2 - c1;

            c1 = ++c2;
        }
    }

    return NGX_OK;
}


static ngx_str_t  star = ngx_string("*");


ngx_int_t
ngx_trie_set(ngx_trie_t *trie, ngx_str_t path, ngx_str_t value)
{
    ngx_array_t       parts;
    ngx_str_t        *word;
    ngx_uint_t        j;
    ngx_trie_node_t  *node = &trie->root, *next;

    if (split(trie->pool, path, &parts) == NGX_ERROR)
        return NGX_ERROR;

    word = parts.elts;

    for (j = 0; node != NULL && j < parts.nelts; j++) {

        if (value.data != NULL) {

            // insert

            next = ngx_trie_insert_node(trie->pool, &node->next, word[j]);
            if (next == NULL)
                return NGX_ERROR;

        } else {

            // delete

            next = ngx_trie_lookup(&node->next, word[j]);
            if (next == NULL)
                break;

        }

        if (j == parts.nelts - 1) {
            next->path = path;
            next->value = value;
        }

        node = next;
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
ngx_trie_find(ngx_trie_t *trie, ngx_str_t *path, ngx_keyval_t *retval,
    ngx_pool_t *temp_pool)
{
    ngx_array_t       parts;
    ngx_str_t        *word;
    ngx_uint_t        j;
    ngx_trie_node_t  *node = &trie->root, *next;
    ngx_trie_node_t  *last = NULL;

    if (split(temp_pool, *path, &parts) == NGX_ERROR)
        return NGX_ERROR;

    word = parts.elts;

    for (j = 0; j < parts.nelts; j++) {

        next = ngx_trie_lookup(&node->next, word[j]);
        if (next == NULL) {
            next = ngx_trie_lookup(&node->next, star);
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
        return NGX_OK;
    }

    return NGX_DECLINED;
}
