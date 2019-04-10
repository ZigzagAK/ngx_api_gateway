/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_template.h"

#include <ngx_http.h>


extern ngx_module_t  ngx_template_module;


#define GSEP "@"


void *
ngx_template_create_main_conf(ngx_cycle_t *cycle)
{
    ngx_template_main_conf_t  *tmcf;

    tmcf = ngx_pcalloc(cycle->pool, sizeof(ngx_template_main_conf_t));
    if (tmcf == NULL)
        return NULL;

    if (ngx_array_init(&tmcf->templates, cycle->pool, 10,
                       sizeof(ngx_template_t)) == NGX_ERROR)
        return NULL;

    tmcf->cycle = cycle;

    return tmcf;
}


static ngx_int_t
ngx_template_read_template(ngx_conf_t *cf, ngx_template_t *t)
{
    ngx_file_t   file;
    ngx_int_t    rc = NGX_ERROR;
    ngx_str_t    filename = t->filename;

    if (t->filename.data[0] == '-') {
        t->updated = 0;
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, &filename, 1) != NGX_OK)
        return NGX_ERROR;

    file.name = t->filename;
    file.log = cf->log;

    file.fd = ngx_open_file(filename.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &filename);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &file.info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", &filename);
        goto done;
    }

    t->template.len = ngx_file_size(&file.info);
    t->template.data = ngx_palloc(t->pool, t->template.len);
    if (t->template.data == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "no memory");
        goto done;
    }

    if (ngx_read_file(&file, t->template.data, t->template.len, 0)
            == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                      ngx_fd_info_n " \"%V\" read failed", &filename);
        goto done;
    }

    t->updated = file.info.st_mtim.tv_sec;

    rc = NGX_OK;

done:

    ngx_close_file(file.fd);
    return rc;
}


ngx_str_t
concat_path(ngx_pool_t *pool, ngx_str_t *path, ngx_int_t n)
{
    ngx_str_t   s = { 0, NULL }, tmp;
    ngx_int_t   j;
    u_char     *c;

    for (j = 0; j <= n; j++)
        s.len += 1 + path[j].len;

    s.data = ngx_pcalloc(pool, s.len);
    if (s.data == NULL)
        return s;

    c = s.data;

    for (j = 0; j <= n; j++) {
        tmp.data = path[j].data;
        tmp.len = path[j].len;
        c = ngx_sprintf(c, "%V.", &tmp);
    }

    s.data[--s.len] = 0;

    return s;
}


ngx_str_t
ngx_strdup(ngx_pool_t *pool, u_char *s, size_t len)
{
    ngx_str_t  retval = ngx_null_string;

    retval.data = ngx_palloc(pool, len + 1);

    if (retval.data) {
        ngx_memcpy(retval.data, s, len);
        retval.len = len;
        retval.data[retval.len] = 0;
    }

    return retval;
}


typedef ngx_str_t (*lookup_fun_t)(ngx_str_t key, ngx_str_t def);
typedef struct {
    ngx_str_t     key;
    lookup_fun_t  fun;
} lookup_t;


static ngx_str_t lookup_default(ngx_str_t key, ngx_str_t def);
static ngx_str_t lookup_env(ngx_str_t key, ngx_str_t def);


static lookup_t funcs[] = {

    { ngx_string("default("),
      lookup_default },

    { ngx_string("env("),
      lookup_env },

    { ngx_null_string, NULL }

};


static ngx_str_t
lookup_fun(ngx_str_t key, ngx_str_t def)
{
    ngx_uint_t        j;
    lookup_t          f;
    static ngx_str_t  null = ngx_null_string;

    if (key.data == NULL)
        return def;

    if (key.data[key.len - 1] != ')')
        return def;

    for (j = 0, f = funcs[j]; f.fun != NULL; f = funcs[++j]) {

        if (key.len < f.key.len + 1)
            continue;

        if (ngx_memn2cmp(key.data, f.key.data, f.key.len, f.key.len) != 0)
            continue;

        key.data += f.key.len;
        key.len -= f.key.len + 1;

        return (*f.fun)(key, null);
    }

    return null;
}


static ngx_str_t
lookup_env(ngx_str_t key, ngx_str_t def)
{
    ngx_str_t  rv;
    char       var[key.len + 1];

    ngx_memcpy(var, key.data, key.len);
    var[key.len] = 0;

    rv.data = (u_char *) getenv(var);
    if (rv.data != NULL) {
        rv.len = ngx_strlen(rv.data);
        return rv;
    }

    return def;
}


static ngx_str_t
lookup_default(ngx_str_t key, ngx_str_t def)
{
    return key.data != NULL ? key : def;
}


static ngx_str_t
transform(ngx_cycle_t *cycle, ngx_pool_t *pool, ngx_template_conf_t *conf,
    ngx_str_t template);


static ngx_str_t
lookup_key(ngx_cycle_t *cycle, ngx_template_conf_t *conf, ngx_str_t key)
{
    ngx_str_t            rv = { 0, NULL };
    ngx_uint_t           j;
    ngx_template_seq_t  *seq;
    static ngx_str_t     null = ngx_null_string;

    for (j = 0; j < conf->nkeys; j++) {
        if (ngx_memn2cmp(conf->keys[j].key.data, key.data,
                         conf->keys[j].key.len, key.len) == 0) {
            rv = conf->keys[j].value;
            break;
        }
    }

    seq = conf->seqs.elts;

    for (j = 0; j < conf->seqs.nelts; j++) {
        if (ngx_memn2cmp(seq[j].key.data, key.data,
                         seq[j].key.len, key.len) == 0) {
            rv = seq[j].value;
            break;
        }
    }

    if (rv.data == NULL)
        // global search
        lookup(cycle, key, &rv);

    if (rv.data == NULL)
        // no value
        rv = lookup_fun(key, null);

    // transform by value

    return lookup_fun(rv, rv);
}


static ngx_chain_t *
new_chain(ngx_pool_t *pool, size_t size)
{
    ngx_chain_t *out = ngx_pcalloc(pool, sizeof(ngx_chain_t));
    if (out == NULL)
        return NULL;
    out->buf = ngx_create_temp_buf(pool, size);
    if (out->buf == NULL)
        return NULL;
    return out;
}


static void
unescape(ngx_str_t *s)
{
    u_char  *c;
    for (c = s->data; c < s->data + s->len; c++) {
        if (*c == '\\' && *(c + 1) == 'n') {
            *c = LF;
            ngx_memmove(c + 1, c + 2, s->data + s->len-- - c - 1);
        }
    }
}


static ngx_str_t
transform(ngx_cycle_t *cycle, ngx_pool_t *pool, ngx_template_conf_t *conf,
    ngx_str_t template)
{
    ngx_chain_t   start, *out;
    ngx_str_t     key, val, s;
    u_char       *c1, *c2, *end = template.data + template.len;
    ngx_int_t     undefined = 0;
    ngx_keyval_t  k;

    c2 = template.data;

    out = &start;
    out->buf = NULL;
    out->next = NULL;

    for (c1 = (u_char *) ngx_strnstr(c2, "{{", end - c2);
         c1 != NULL;
         c1 = (u_char *) ngx_strnstr(c2, "{{", end - c2)) {

        out->next = new_chain(pool, c1 - c2 + 2);
        if (out->next == NULL)
            goto nomem;

        out->next->buf->last = ngx_cpymem(out->next->buf->last, c2, c1 - c2);

        c2 = (u_char *) ngx_strnstr(c1, "}}", end - c1);
        if (c2 == NULL) {
            out->next->buf->last = ngx_sprintf(out->next->buf->last, "{{");
            c2 = c1 + 2;
            out = out->next;
            continue;
        }

        key.data = c1 + 2;
        key.len = c2 - c1 - 2;

        ngx_trim(&key);

        out = out->next;

        k.key = key;

        do {
            k = ngx_split(k.key, '|');
            ngx_trim(&k.key);
            val = lookup_key(cycle, conf, k.key);
            if (val.data != NULL)
                val = transform(cycle, pool, conf, val);
            k.key = k.value;
        } while (val.data == NULL && k.value.data != NULL);

        if (val.data == NULL) {
            val.data = c1;
            val.len = c2 - c1 + 2;
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "undefined: %V", &key);
            undefined++;
        } else
            unescape(&val);

        out->next = new_chain(pool, val.len);
        if (out->next == NULL)
            goto nomem;

        out->next->buf->last = ngx_cpymem(out->next->buf->last,
                                          val.data, val.len);

        c2 += 2;
        out = out->next;
    }

    if (c2 < template.data + template.len) {
        out->next = new_chain(pool, template.data + template.len - c2);
        if (out->next == NULL)
            goto nomem;
        out->next->buf->last = ngx_cpymem(out->next->buf->last, c2,
            template.data + template.len - c2);
    }

    s.len = 0;
    for (out = start.next; out != NULL; out = out->next)
        s.len += out->buf->last - out->buf->start;

    s.data = ngx_pcalloc(pool, s.len + 1);
    if (s.data == NULL)
        goto nomem;
    c1 = s.data;
    for (out = start.next; out != NULL; out = out->next)
        c1 = ngx_cpymem(c1, out->buf->start, out->buf->last - out->buf->start);

    if (undefined != 0) {
        ngx_str_set(&s, "");
    }

    return s;

nomem:

    ngx_str_null(&s);
    return s;
}


static ngx_str_t  KEYS_seq[] = {

    ngx_string("map"),
    ngx_string("servers")

};
static ngx_int_t KEYS_seqn = sizeof(KEYS_seq) / sizeof(KEYS_seq[0]);


static ngx_int_t
ngx_template_handle_key(yaml_char_t *key, size_t key_len)
{
    ngx_int_t  j;

    for (j = 0; j < KEYS_seqn; j++)
        if (ngx_memn2cmp(KEYS_seq[j].data, key,
                         KEYS_seq[j].len, key_len) == 0)
            return NGX_OK;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_template_parse_seq(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_template_conf_t *conf, ngx_str_t path)
{
    ngx_array_t           entries;
    ngx_str_t            *entry;
    yaml_event_t          event;
    yaml_event_type_t     type;
    size_t                size = 0;
    ngx_uint_t            j;
    u_char               *c, sep;
    ngx_template_seq_t   *seq_entry;
    
    if (ngx_array_init(&entries, pool, 10, sizeof(ngx_str_t)) != NGX_OK)
        goto nomem;

    if (!yaml_parser_parse(parser, &event))
        return NGX_ERROR;

    type = event.type;
    yaml_event_delete(&event);

    if (type != YAML_SEQUENCE_START_EVENT)
        return NGX_ABORT;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;
        
        switch (type) {
            
            case YAML_SCALAR_EVENT:

                entry = ngx_array_push(&entries);
                if (entry == NULL)
                    goto nomem_local;

                *entry = ngx_strdup(pool, event.data.scalar.value,
                                  event.data.scalar.length);
                if (entry->data == NULL)
                    goto nomem_local;

                ngx_trim(entry);

                size += entry->len + 1;
                
                break;

            case YAML_SEQUENCE_END_EVENT:

                break;

            default:

                yaml_event_delete(&event);
                return NGX_ABORT;
        }

        yaml_event_delete(&event);
        continue;

nomem_local:

        yaml_event_delete(&event);
        goto nomem;

    } while (type != YAML_SEQUENCE_END_EVENT);

    if (conf->seqs.elts == NULL) {
        if (ngx_array_init(&conf->seqs, pool, 10,
                sizeof(ngx_template_seq_t)) != NGX_OK)
            goto nomem;
    }

    seq_entry = ngx_array_push(&conf->seqs);
    if (seq_entry == NULL)
        goto nomem;

    seq_entry->key = path;
    seq_entry->elts = entries.elts;
    seq_entry->nelts = entries.nelts;

    if (size != 0) {

        seq_entry->value.data = ngx_palloc(pool, size);
        if (seq_entry->value.data == NULL)
            goto nomem;

        c = seq_entry->value.data;
        switch (seq_entry->elts[0].data[seq_entry->elts[0].len - 1]) {
            case '}':
            case ';':
                sep = LF;
                break;
            default:
                sep = ' ';
        }

        for (j = 0; j < seq_entry->nelts; j++)
            c = ngx_sprintf(c, "%V%c", &seq_entry->elts[j], sep);
        seq_entry->value.len = --c - seq_entry->value.data;
        seq_entry->value.data[seq_entry->value.len] = 0;

    } else {

        ngx_str_set(&seq_entry->value, "");
    }

    return NGX_DONE;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_template_parse_entry(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_template_conf_t *conf, on_key_t pfkey)
{
    ngx_array_t        keys;
    ngx_keyval_t      *kv;
    yaml_event_t       event;
    ngx_flag_t         is_key = 1;
    ngx_str_t          path[1000];
    ngx_str_t          key;
    ngx_int_t          level = 0;
    yaml_event_type_t  type;
    ngx_int_t          rc;

    static ngx_str_t   name = ngx_string("name");

    if (ngx_array_init(&keys, pool, 12, sizeof(ngx_keyval_t)) != NGX_OK)
        goto nomem;

    kv = ngx_array_push(&keys);
    ngx_str_set(&kv->key, "__group");
    kv->value = conf->group;

    kv = ngx_array_push(&keys);
    ngx_str_set(&kv->key, "__fullname");

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;

        switch (type) {

            case YAML_SCALAR_EVENT:

                if (is_key) {

                    path[level] = ngx_strdup(pool,
                        event.data.scalar.value, event.data.scalar.length);
                    if (path[level].data == NULL)
                        goto nomem_local;

                    key = concat_path(pool, path, level);

                    rc = NGX_DECLINED;

                    if (pfkey != NULL)
                        rc = (*pfkey)(key, event.data.scalar.value,
                                event.data.scalar.length,
                                pool, parser, conf);

                    if (rc == NGX_DECLINED)
                        rc = ngx_template_handle_key(event.data.scalar.value,
                            event.data.scalar.length);

                    if (rc == NGX_OK || rc == NGX_DONE) {

                        if (rc == NGX_OK)
                            rc = ngx_template_parse_seq(pool, parser, conf,
                                key);

                        if (rc == NGX_DONE)
                            // parsed in callback
                            break;

                        if (rc == NGX_OK)
                            break;

                        if (rc == NGX_ERROR || rc == NGX_ABORT)
                            return rc;

                        // rc == NGX_DECLINED
                    }

                } else {

                    kv = ngx_array_push(&keys);
                    if (kv == NULL)
                        goto nomem_local;

                    kv->key = key;
                    if (kv->key.data == NULL)
                        goto nomem_local;

                    kv->value = ngx_strdup(pool,
                        event.data.scalar.value, event.data.scalar.length);
                    if (kv->value.data == NULL)
                        goto nomem_local;

                    if (level == 0
                        && ngx_memn2cmp(name.data, path[level].data,
                                        name.len, path[level].len) == 0) {

                        conf->name = kv->value;
                        
                        // add group to name
                        conf->fullname.data = ngx_pcalloc(pool,
                                kv->value.len + conf->group.len + 2);
                        if (conf->fullname.data == NULL)
                            goto nomem_local;

                        conf->fullname.len = ngx_sprintf(conf->fullname.data,
                                "%V"GSEP"%V", &conf->group,  &kv->value)
                              - conf->fullname.data;

                        ((ngx_keyval_t *) keys.elts)[1].value = conf->fullname;
                    }
                }

                is_key = !is_key;
                break;

            case YAML_MAPPING_START_EVENT:

                level++;
                is_key = 1;
                break;

            case YAML_MAPPING_END_EVENT:

                level--;
                is_key = 1;
                break;

            case YAML_SEQUENCE_START_EVENT:

                ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                        "yaml sequences are unsupported, path=%V", &key);

            default:

                yaml_event_delete(&event);
                return NGX_ABORT;
        }

        yaml_event_delete(&event);
        continue;

nomem_local:

        yaml_event_delete(&event);
        goto nomem;

    } while (level >= 0);

    conf->keys = keys.elts;
    conf->nkeys = keys.nelts;

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


static ngx_int_t
ngx_template_parse_entries(yaml_parser_t *parser, ngx_template_t *t)
{
    ngx_template_conf_t  *conf;
    yaml_event_t          event;
    yaml_event_type_t     type;
    ngx_int_t             rc;

    if (!yaml_parser_parse(parser, &event))
        return NGX_ERROR;

    type = event.type;
    yaml_event_delete(&event);

    if (type != YAML_SEQUENCE_START_EVENT)
        return NGX_ABORT;

    do {
        if (!yaml_parser_parse(parser, &event))
            return NGX_ERROR;

        type = event.type;

        switch (type) {

            case YAML_MAPPING_START_EVENT:

                conf = ngx_array_push(&t->entries);
                if (conf == NULL) {
                    yaml_event_delete(&event);
                    goto nomem;
                }
                ngx_memzero(conf, t->entries.size);

                conf->group = t->group;

                rc = ngx_template_parse_entry(t->pool, parser, conf, t->pfkey);
                if (rc != NGX_OK) {
                    yaml_event_delete(&event);
                    return rc;
                }

                if (conf->fullname.data == NULL) {
                    ngx_log_error(NGX_LOG_ERR, t->pool->log, 0,
                                  "mandatory tag \"name\" not found in \"%V\"",
                                  &t->keyfile);
                    return NGX_ABORT;
                }

                break;

            case YAML_SEQUENCE_END_EVENT:

                break;

            default:

                yaml_event_delete(&event);
                return NGX_ABORT;
        }

        yaml_event_delete(&event);

    } while (type != YAML_SEQUENCE_END_EVENT);

    yaml_event_delete(&event);

    return NGX_OK;

nomem:

    ngx_log_error(NGX_LOG_ERR, t->pool->log, 0, "no memory");
    return NGX_ERROR;
}


ngx_int_t
ngx_template_conf_parse_yaml(ngx_cycle_t *cycle, FILE *f, ngx_template_t *t)
{
    ngx_template_conf_t  *conf;
    yaml_parser_t         parser;
    yaml_event_t          event;
    yaml_event_type_t     type;
    ngx_int_t             rc = NGX_OK;
    ngx_uint_t            j;

    if (fseek(f, 0, SEEK_END) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "seek() \"%V\" failed", &t->keyfile);
        return NGX_ERROR;
    }

    t->yaml.len = ftell(f);
    if (t->yaml.len == (size_t) NGX_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "tell() \"%V\" failed", &t->keyfile);
        return NGX_ERROR;
    }
    t->yaml.data = ngx_alloc(t->yaml.len, cycle->log);
    if (t->yaml.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
        return NGX_ERROR;
    }

    rewind(f);

    if (fread(t->yaml.data, t->yaml.len, 1, f) != 1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "read() \"%V\" failed", &t->keyfile);
        return NGX_ERROR;
    }

    rewind(f);

    if (!yaml_parser_initialize(&parser)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "can't initialize yaml");
        return NGX_ERROR;
    }

    yaml_parser_set_input_file(&parser, f);

    do {
        if (!yaml_parser_parse(&parser, &event)) {

            rc = NGX_ERROR;
            goto done;
        }

        type = event.type;
        
        switch (type) {

            case YAML_SCALAR_EVENT:

                if (ngx_memn2cmp(t->group.data, event.data.scalar.value,
                                 t->group.len, event.data.scalar.length) == 0) {
                    rc = ngx_template_parse_entries(&parser, t);
                    if (rc != NGX_OK)
                        goto done;
                }
                break;

            default:
                break;
        }

        yaml_event_delete(&event);

    } while (type != YAML_STREAM_END_EVENT);

    for (j = 0; j < t->entries.nelts; j++) {
        conf = (ngx_template_conf_t *)
                ((u_char *) t->entries.elts + j * t->entries.size);
        if (t->template.data != NULL) {
            conf->conf = transform(cycle, t->pool, conf, t->template);
            if (conf->conf.data == NULL)
                rc = NGX_ERROR;
            if (conf->conf.len == 0)
                rc = NGX_ABORT;
        }
    }

done:

    if (rc == NGX_ABORT) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "invalid structure \"%V\"", &t->keyfile);
    }

    yaml_parser_delete(&parser);

    return rc;
}


ngx_int_t
ngx_conf_add_dump(ngx_conf_t *cf, ngx_str_t *filename)
{
    off_t             size;
    u_char           *p;
    uint32_t          hash;
    ngx_buf_t        *buf;
    ngx_str_node_t   *sn;
    ngx_conf_dump_t  *cd;

    hash = ngx_crc32_long(filename->data, filename->len);

    sn = ngx_str_rbtree_lookup(&cf->cycle->config_dump_rbtree, filename, hash);

    if (sn) {
        cf->conf_file->dump = NULL;
        return NGX_OK;
    }

    p = ngx_pstrdup(cf->cycle->pool, filename);
    if (p == NULL) {
        return NGX_ERROR;
    }

    cd = ngx_array_push(&cf->cycle->config_dump);
    if (cd == NULL) {
        return NGX_ERROR;
    }

    size = ngx_file_size(&cf->conf_file->file.info);

    buf = ngx_create_temp_buf(cf->cycle->pool, (size_t) size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    cd->name.data = p;
    cd->name.len = filename->len;
    cd->buffer = buf;

    cf->conf_file->dump = buf;

    sn = ngx_palloc(cf->temp_pool, sizeof(ngx_str_node_t));
    if (sn == NULL) {
        return NGX_ERROR;
    }

    sn->node.key = hash;
    sn->str = cd->name;

    ngx_rbtree_insert(&cf->cycle->config_dump_rbtree, &sn->node);

    return NGX_OK;
}


static ngx_int_t
ngx_template_conf_apply(ngx_conf_t *cf, ngx_template_t *t)
{
    ngx_template_conf_t   *conf;
    ngx_file_t             file;
    ngx_int_t              rc = NGX_OK;
    ngx_uint_t             i, j, n;
    char                  *rv;
    ngx_conf_file_t        conf_file;
    ngx_conf_file_t       *prev = cf->conf_file;
    ngx_str_t              keyfile = t->keyfile;
    ngx_template_seq_t    *seqs;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "%V:%V", &t->filename, &keyfile);

    if (ngx_template_read_template(cf, t) != NGX_OK)
        return NGX_ERROR;

    if (ngx_conf_full_name(cf->cycle, &keyfile, 1) != NGX_OK)
        return NGX_ERROR;

    file.name = keyfile;
    file.log = cf->log;

    file.fd = ngx_open_file(keyfile.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &keyfile);
        return NGX_ERROR;
    }

    if (ngx_array_init(&t->entries, t->pool, 10,
            sizeof(ngx_template_conf_t)) == NGX_ERROR)
        goto nomem;

    rc = ngx_template_conf_parse_yaml(cf->cycle, fdopen(file.fd, "r"), t);

    for (j = 0; j < t->entries.nelts; j++) {

        conf = (ngx_template_conf_t *)
                    ((u_char *) t->entries.elts + j * t->entries.size);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  keys");
        for (i = 0; i < conf->nkeys; i++)
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V:%V",
                          &conf->keys[i].key, &conf->keys[i].value);

        seqs = conf->seqs.elts;
        
        for (n = 0; n < conf->seqs.nelts; n++) {

            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  %V", &seqs[n].key);

            for (i = 0; i < seqs[n].nelts; i++)
                ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V",
                              &seqs[n].elts[i]);
        }

        if (rc == NGX_ABORT)
            continue;

        if (t->template.data == NULL)
            continue;

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  template\n%V", &t->template);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  text\n%V", &conf->conf);

        ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));

        cf->conf_file = &conf_file;

        conf_file.buffer = ngx_create_temp_buf(cf->temp_pool,
            conf->conf.len + 1);
        if (conf_file.buffer == NULL)
            goto nomem;
        conf_file.file.log = cf->log;
        conf_file.file.name.data = ngx_pcalloc(cf->temp_pool,
            conf->fullname.len + t->group.len + 2);
        if (conf_file.file.name.data == NULL)
            goto nomem;
        conf_file.file.name.len = ngx_sprintf(conf_file.file.name.data, "%V:%V",
            &t->filename, &conf->fullname) - conf_file.file.name.data;
        conf_file.line = 1;
        conf_file.file.info.st_size = conf->conf.len + 1;
        conf_file.file.offset = conf_file.file.info.st_size;
        conf_file.buffer->last = ngx_cpymem(conf_file.buffer->start,
                conf->conf.data, conf->conf.len);

        if (ngx_dump_config
#if (NGX_DEBUG)
            || 1
#endif
           )
        {
            if (ngx_conf_add_dump(cf, &conf_file.file.name) != NGX_OK) {
                rc = NGX_ERROR;
                goto done;
            }

            if (conf_file.dump != NULL)
                conf_file.dump->last = ngx_cpymem(conf_file.dump->last,
                    conf->conf.data, conf->conf.len);
        }

        *conf_file.buffer->last++ = '}';

        rv = ngx_conf_parse(cf, NULL);

        if (rv != NGX_CONF_OK)
            rc = NGX_ERROR;
    }

    if (rc == NGX_OK)
        t->updated = ngx_max(file.info.st_mtim.tv_sec, t->updated);

done:

    cf->conf_file = prev;

    ngx_close_file(file.fd);

    switch (rc) {

        case NGX_OK:

            break;

        case NGX_ABORT:

            return NGX_ERROR;

        case NGX_ERROR:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "parse fails");
            return NGX_ERROR;

        default:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "unexpected, rc=%d", rc);
            return NGX_ERROR;
    }

    return NGX_OK;

nomem:

    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
    rc = NGX_ERROR;
    goto done;
}


static u_char *
ngx_strchrr(ngx_str_t *s, u_char ch)
{
    u_char  *c;
    for (c = s->data + s->len - 1; c > s->data && *c != ch; c--);
    return *c == ch ? c : s->data + s->len;
}


static ngx_int_t
ngx_template_group(ngx_conf_t *cf, ngx_str_t keyfile, ngx_str_t *group)
{
    u_char  *c;
    group->data = ngx_pcalloc(cf->cycle->pool, keyfile.len + 1);
    if (group->data == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_ERROR;
    }
    group->len = keyfile.len;
    ngx_memcpy(group->data, keyfile.data, keyfile.len);
    c = ngx_strchrr(group, '.');
    *c = 0;
    group->len = c - group->data;
    return NGX_OK;
}


ngx_flag_t
ngx_eqstr(ngx_str_t s, const char *c)
{
    return ngx_memn2cmp(s.data, (u_char *) c, s.len, ngx_strlen(c)) == 0;
}


static char *
ngx_template_conf(ngx_conf_t *cf, ngx_template_t *t)
{
    ngx_uint_t  j;

    if (ngx_parse_args(cf, &t->args.elts, &t->args.nelts) == NGX_ERROR)
        return NGX_CONF_ERROR;

    for (j = 0; j < t->args.nelts; j++) {

        if (ngx_eqstr(t->args.elts[j].key, "template"))
            t->filename = t->args.elts[j].value;

        if (ngx_eqstr(t->args.elts[j].key, "keyfile"))
            t->keyfile = t->args.elts[j].value;

        if (ngx_eqstr(t->args.elts[j].key, "group"))
            t->group = t->args.elts[j].value;
    }

    if (t->filename.data == NULL) {
        // template may be empty
        ngx_str_set(&t->filename, "-");
    }

    if (t->group.data == NULL) {
        if (ngx_template_group(cf, t->keyfile, &t->group) == NGX_ERROR)
            return NGX_CONF_ERROR;
    }

    if (t->keyfile.data == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "\"keyfile\" parameter required");
        return NGX_CONF_ERROR;
    }

    if (ngx_template_conf_apply(cf, t) == NGX_OK)
        return NGX_CONF_OK;

    return NGX_CONF_ERROR;
}


ngx_template_t *
ngx_template_add(ngx_conf_t *cf, on_key_t pfkey)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_template_t            *t;

    extern ngx_module_t ngx_template_module;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                     ngx_template_module);

    t = ngx_array_push(&tmcf->templates);

    if (t == NULL)
        goto nomem;

    ngx_memzero(t, sizeof(ngx_template_t));

    t->pool = ngx_create_pool(1024, cf->log);
    if (t->pool == NULL)
        goto nomem;
    t->pfkey = pfkey;

    if (ngx_template_conf(cf, t) == NGX_CONF_ERROR) {
        tmcf->templates.nelts--;
        ngx_destroy_pool(t->pool);
        return NULL;
    }

    return t;

nomem:

    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
    return NULL;
}


char *
ngx_template_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    if (ngx_template_add(cf, NULL) != NULL)
        return NGX_CONF_OK;

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_template_check_template(ngx_cycle_t *cycle, ngx_template_t *old)
{
    ngx_file_t            file;
    ngx_conf_t            cf;
    ngx_template_t        t;
    ngx_uint_t            j;
    ngx_template_conf_t  *conf, *old_conf;
    ngx_int_t             rc = NGX_ERROR;

    ngx_memzero(&t, sizeof(ngx_template_t));

    t.group = old->group;
    t.filename = old->filename;
    t.keyfile = old->keyfile;
    t.pfkey = old->pfkey;
    t.pool = ngx_create_pool(1024, cycle->log);
    if (t.pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
        return NGX_ERROR;
    }

    t.pool->log = cycle->log;

    if (ngx_array_init(&t.entries, t.pool, 10,
            sizeof(ngx_template_conf_t)) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no memory");
        goto done;
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));

    cf.log = cycle->log;
    cf.pool = t.pool;
    cf.temp_pool = t.pool;
    cf.cycle = cycle;

    file.fd = NGX_INVALID_FILE;
    file.name = t.keyfile;
    file.log = cycle->log;

    if (ngx_conf_full_name(cycle, &file.name, 1) != NGX_OK)
        goto done;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &t.keyfile);
        goto done;
    }

    if (ngx_fd_info(file.fd, &file.info) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", &t.keyfile);
        goto done;
    }

    if (ngx_template_read_template(&cf, &t) != NGX_OK)
        goto done;

    if (ngx_max(file.info.st_mtim.tv_sec, t.updated) == old->updated) {

        rc = NGX_DECLINED;
        goto done;
    }

    rc = ngx_template_conf_parse_yaml(cycle, fdopen(file.fd, "r"), &t);
    if (rc != NGX_OK)
        goto done;

    // rc == NGX_OK

    if (t.entries.nelts != old->entries.nelts)
        goto reload;

    conf = t.entries.elts;
    old_conf = old->entries.elts;

    for (j = 0; j < t.entries.nelts; j++)
        if (ngx_memn2cmp(conf[j].conf.data, old_conf[j].conf.data,
                         conf[j].conf.len, old_conf[j].conf.len) != 0)
            goto reload;

    // no changes

    old->updated = ngx_max(file.info.st_mtim.tv_sec, t.updated);

    goto done;

reload:

    if (ngx_worker != 0)
        goto done;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, ngx_errno,
                  "ngx_api_gateway RELOAD");
    ngx_signal_process(cycle, "reload");

done:

    if (file.fd != NGX_INVALID_FILE)
        ngx_close_file(file.fd);

    if (rc == NGX_DECLINED)

        ngx_destroy_pool(t.pool);

    else if (rc == NGX_OK) {

        ngx_destroy_pool(old->pool);

        old->entries = t.entries;
        old->pool = t.pool;
        old->yaml = t.yaml;
        old->template = t.template;
    }

    return rc;
}


void
ngx_template_check_updates(ngx_template_main_conf_t *tmcf)
{
    ngx_template_t  *t;
    ngx_uint_t       j;

    t = tmcf->templates.elts;

    for (j = 0; j < tmcf->templates.nelts; j++)
        if (ngx_template_check_template(tmcf->cycle, t + j) == NGX_OK)
            tmcf->changed = 1;
}


typedef struct {
    ngx_str_t  group;
    ngx_str_t  name;
    ngx_str_t  key;
} lookup_key_t;


static lookup_key_t
split_key(ngx_str_t key)
{
    lookup_key_t  opts = {
        ngx_null_string, ngx_null_string, ngx_null_string
    };
    ngx_keyval_t  kv;
    
    kv = ngx_split(key, GSEP[0]);
    if (kv.value.data == NULL)
        return opts;

    opts.group = kv.key;

    kv = ngx_split(key, '.');

    opts.name = kv.key;
    opts.key = kv.value;

    return opts;
}


ngx_int_t
lookup(ngx_cycle_t *cycle, ngx_str_t key, ngx_str_t *retval)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_template_t            *t;
    ngx_template_conf_t       *conf;
    ngx_uint_t                 j, i;
    lookup_key_t               opts = split_key(key);

    if (opts.key.data == NULL)
        return NGX_DECLINED;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                     ngx_template_module);

    for (j = 0; j < tmcf->templates.nelts; j++) {

        t = (ngx_template_t *)
                ((u_char *) tmcf->templates.elts + j * tmcf->templates.size);

        if (ngx_memn2cmp(opts.group.data, t->group.data,
                         opts.group.len, t->group.len) == 0) {

            for (i = 0; i < t->entries.nelts; i++) {

                conf = (ngx_template_conf_t *)
                        ((u_char *) t->entries.elts + i * t->entries.size);

                if (ngx_memn2cmp(opts.name.data, conf->fullname.data,
                                 opts.name.len, conf->fullname.len) == 0) {

                    *retval = lookup_key(cycle, conf, opts.key);
                    if (retval->data != NULL)
                        return NGX_OK;

                    break;
                }
            }
        }
    }

    return NGX_DECLINED;
}


ngx_template_conf_t *
ngx_template_lookup_by_name(ngx_cycle_t *cycle, ngx_str_t name)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_uint_t                 j, i;
    ngx_template_t            *t;
    ngx_template_conf_t       *conf;
    ngx_array_t               *templates;
    ngx_keyval_t               kv;

    kv = ngx_split(name, '@');

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                     ngx_template_module);

    templates = &tmcf->templates;

    for (j = 0; j < templates->nelts; j++) {

        t = (ngx_template_t *)
                ((u_char *) templates->elts + j * templates->size);

        if (ngx_memn2cmp(t->group.data, kv.key.data,
                         t->group.len, kv.key.len) != 0)
            continue;

        for (i = 0; i < t->entries.nelts; i++) {

            conf = (ngx_template_conf_t *)
                    ((u_char *) t->entries.elts + i * t->entries.size);

            if (ngx_memn2cmp(conf->fullname.data, name.data,
                             conf->fullname.len, name.len) == 0)
                return conf;
        }
    }

    return NULL;
}


ngx_int_t
ngx_template_scan(ngx_cycle_t *cycle, scan_fun_t cb, void *data)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_uint_t                 j;
    ngx_template_t            *t;
    ngx_array_t               *templates;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                     ngx_template_module);

    templates = &tmcf->templates;

    for (j = 0; j < templates->nelts; j++) {

        t = (ngx_template_t *)
                ((u_char *) templates->elts + j * templates->size);

        if (NGX_ERROR == (*cb)(t, data))
            return NGX_ERROR;
    }

    return NGX_OK;
}


void 
ngx_trim(ngx_str_t *s)
{
    for (; isspace(s->data[0]); s->data++, s->len--);
    for (; isspace(s->data[s->len - 1]); s->len--);
}


ngx_keyval_t
ngx_split(ngx_str_t s, u_char c)
{
    ngx_keyval_t   kv = { s, ngx_null_string };
    u_char        *size;

    size = ngx_strlchr(s.data, s.data + s.len, c);
    if (size == NULL)
        return kv;

    kv.key.len = size - kv.key.data;
    kv.value.data = ++size;
    kv.value.len = s.data + s.len - kv.value.data;

    return kv;
}


ngx_int_t
ngx_parse_args(ngx_conf_t *cf, ngx_keyval_t **elts,
    ngx_uint_t *nelts)
{
    ngx_array_t    a;
    ngx_keyval_t  *kv;
    ngx_uint_t     j;
    ngx_str_t     *value;

    if (ngx_array_init(&a, cf->pool, cf->args->nelts, sizeof(ngx_keyval_t))
            == NGX_ERROR)
        return NGX_ERROR;

    value = cf->args->elts;

    for (j = 1; j < cf->args->nelts; j++) {

        kv = ngx_array_push(&a);
        if (kv == NULL)
            return NGX_ERROR;

        *kv = ngx_split(value[j], '=');
    }

    *elts = a.elts;
    *nelts = a.nelts;

    return NGX_OK;
}
