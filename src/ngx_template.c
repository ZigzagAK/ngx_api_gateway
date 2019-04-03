/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_template.h"

#include <ngx_http.h>


extern ngx_module_t  ngx_template_module;


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

    return tmcf;
}


ngx_int_t
ngx_template_read_template(ngx_conf_t *cf, ngx_str_t filename,
    ngx_str_t *content, time_t *updated)
{
    ngx_file_t  file;
    ngx_int_t   rc = NGX_ERROR;

    if (ngx_conf_full_name(cf->cycle, &filename, 1) != NGX_OK)
        return NGX_ERROR;

    file.name = filename;
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

    content->len = ngx_file_size(&file.info);
    content->data = ngx_palloc(cf->pool, content->len + 1);
    if (content->data == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "no memory");
        goto done;
    }

    if (NGX_ERROR == ngx_read_file(&file, content->data, content->len, 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                      ngx_fd_info_n " \"%V\" read failed", &filename);
        goto done;
    }

    content->data[content->len] = 0;

    if (updated != NULL)
        *updated = file.info.st_mtim.tv_sec;
    
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
    ngx_str_t  dst;

    dst.data = ngx_pcalloc(pool, len + 1);
    if (dst.data)
        ngx_memcpy(dst.data, s, len);
    dst.len = len;

    return dst;
}


static ngx_str_t
lookup_env(ngx_str_t key)
{
    ngx_str_t         s = key;
    char              var[key.len];
    static ngx_str_t  env = ngx_string("env(");

    if (ngx_strncasecmp(env.data, key.data, env.len) != 0)
        return s;

    ngx_memzero(var, key.len);
    ngx_memcpy(var, key.data + 4, key.len - 4 - 1);

    s.data = (u_char *) getenv(var);
    if (s.data != NULL)
        s.len = ngx_strlen(s.data);
    else
        s = key;

    return s;
}


static ngx_str_t
lookup_key(ngx_pool_t *pool, ngx_template_conf_t *conf, ngx_str_t key)
{
    ngx_str_t   s = { 0, NULL };
    ngx_uint_t  j;

    if (pool != NULL)
        key = ngx_strdup(pool, key.data, key.len);

    for (j = 0; j < conf->nkeys; j++) {
        if (ngx_memn2cmp(conf->keys[j].key.data, key.data,
                         conf->keys[j].key.len, key.len) == 0) {
            s = conf->keys[j].value;
            break;
        }
    }

    if (s.data == NULL) {
        // global search
        lookup(NULL, key, &s);
    }

    if (s.data != NULL)
        return lookup_env(s);

    // key not found
    
    s = lookup_env(key);

    if (s.data == key.data) {
        // environment variable not found
        ngx_str_null(&s);
    }

    return s;
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


ngx_str_t
transform(ngx_pool_t *pool, ngx_template_conf_t *conf,
    ngx_str_t template)
{
    ngx_chain_t  start, *out;
    ngx_str_t    key, val, s;
    u_char      *c1, *c2;
    ngx_int_t    undefined = 0;

    c2 = template.data;

    out = &start;
    out->buf = NULL;
    out->next = NULL;

    for (c1 = (u_char *) ngx_strstr(c2, "{{");
         c1 != NULL;
         c1 = (u_char *) ngx_strstr(c2, "{{")) {

        out->next = new_chain(pool, c1 - c2 + 2);
        if (out->next == NULL)
            goto nomem;

        out->next->buf->last = ngx_cpymem(out->next->buf->last, c2, c1 - c2);

        c2 = (u_char *) ngx_strstr(c1, "}}");
        if (c2 == NULL) {
            out->next->buf->last = ngx_sprintf(out->next->buf->last, "{{");
            c2 = c1 + 2;
            out = out->next;
            continue;
        }

        key.data = c1 + 2;
        key.len = c2 - c1 - 2;

        // trim

        for (; isspace(key.data[0]); key.data++, key.len--);
        for (; isspace(key.data[key.len - 1]); key.len--);

        out = out->next;

        val = lookup_key(pool, conf, key);
        if (val.data == NULL) {
            val.data = c1;
            val.len = c2 - c1 + 2;
            ngx_log_error(NGX_LOG_ERR, pool->log, 0, "undefined: %V", &key);
            undefined++;
        } else {
            val = transform(pool, conf, val);
            unescape(&val);
        }

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
        ngx_str_null(&s);
    }

    return s;

nomem:

    ngx_str_null(&s);
    return s;
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
    ngx_str_t          retval;

    static ngx_str_t   name = ngx_string("name");

    if (ngx_array_init(&keys, pool, 10, sizeof(ngx_keyval_t)) != NGX_OK)
        goto nomem;

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
                    
                    if (pfkey) {

                        ngx_str_null(&retval);

                        rc = (*pfkey)(key, event.data.scalar.value,
                                event.data.scalar.length,
                                pool, parser, conf, &retval);

                        if (rc == NGX_OK) {

                            if (retval.data != NULL) {

                                kv = ngx_array_push(&keys);
                                if (kv == NULL)
                                    goto nomem_local;

                                kv->key = key;
                                if (kv->key.data == NULL)
                                    goto nomem_local;

                                kv->value = retval;
                            }

                            break;
                        }

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
                                        name.len, path[level].len) == 0)
                        conf->name = kv->value;
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
                        "yaml sequences are unsupported");

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
ngx_template_parse_entries(ngx_pool_t *pool, yaml_parser_t *parser,
    ngx_template_t *t, on_key_t pfkey)
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

                rc = ngx_template_parse_entry(pool, parser, conf, pfkey);
                if (rc != NGX_OK) {
                    yaml_event_delete(&event);
                    return rc;
                }

                if (conf->name.data == NULL) {
                    ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                                  "mandatory tag \"name\" not found in \"%V\"",
                                  &t->filename);
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

    ngx_log_error(NGX_LOG_ERR, pool->log, 0, "no memory");
    return NGX_ERROR;
}


ngx_int_t
ngx_template_conf_parse_yaml(ngx_pool_t *pool, FILE *f,
    ngx_template_t *t, on_key_t pfkey)
{
    ngx_template_conf_t  *conf;
    yaml_parser_t         parser;
    yaml_event_t          event;
    yaml_event_type_t     type;
    ngx_int_t             rc = NGX_OK;
    ngx_uint_t            j;

    if (!yaml_parser_initialize(&parser)) {
        ngx_log_error(NGX_LOG_WARN, pool->log, 0, "can't initialize yaml");
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

                if (ngx_memn2cmp(t->tag.data, event.data.scalar.value,
                                 t->tag.len, event.data.scalar.length) == 0) {
                    rc = ngx_template_parse_entries(pool, &parser, t, pfkey);
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
        conf->conf = transform(pool, conf, t->template);
        if (conf->conf.data == NULL)
            rc = NGX_ERROR;
    }

done:

    if (rc == NGX_ABORT) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "invalid structure \"%V\"", &t->filename);
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
    ngx_template_conf_t  *conf;
    ngx_file_t            file;
    ngx_int_t             rc = NGX_OK;
    ngx_uint_t            i, j;
    char                 *rv;
    ngx_conf_file_t       conf_file;
    ngx_conf_file_t      *prev = cf->conf_file;
    ngx_str_t             keyfile = t->keyfile;
    
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%V:%V", &t->filename, &keyfile);

    if (ngx_template_read_template(cf, t->filename, &t->template, &t->updated)
            != NGX_OK)
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

    if (ngx_array_init(&t->entries, cf->pool, 10,
            sizeof(ngx_template_conf_t)) == NGX_ERROR) {
        rc = NGX_ERROR;
        goto done;
    }

    rc = ngx_template_conf_parse_yaml(cf->pool, fdopen(file.fd, "r"),
        t, NULL);
    if (rc != NGX_OK)
        goto done;

    t->yaml.len = lseek(file.fd, 0, SEEK_END);
    t->yaml.data = ngx_palloc(cf->pool, t->yaml.len);
    if (t->yaml.data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    if (NGX_ERROR == ngx_read_file(&file, t->yaml.data, t->yaml.len, 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "read \"%V\" failed", &keyfile);
        rc = NGX_ERROR;
        goto done;
    }

    conf = t->entries.elts;

    for (j = 0; j < t->entries.nelts; j++) {

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "  keys");
        for (i = 0; i < conf[j].nkeys; i++)
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "    %V:%V",
                          &conf[j].keys[i].key, &conf[j].keys[i].value);

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  template\n%V", &t->template);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "  text\n%V", &conf[j].conf);

        ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));

        cf->conf_file = &conf_file;

        conf_file.buffer = ngx_create_temp_buf(cf->temp_pool,
            conf[j].conf.len + 1);
        if (conf_file.buffer == NULL) {
            rc = NGX_ERROR;
            goto done;
        }
        conf_file.file.log = cf->log;
        conf_file.file.name.data = ngx_pcalloc(cf->temp_pool,
            conf[j].name.len + t->tag.len + 2);
        if (conf_file.file.name.data == NULL) {
            rc = NGX_ERROR;
            goto done;
        }
        conf_file.file.name.len = ngx_sprintf(conf_file.file.name.data, "%V:%V",
            &t->tag, &conf[j].name) - conf_file.file.name.data;
        conf_file.line = 1;
        conf_file.file.info.st_size = conf[j].conf.len + 1;
        conf_file.file.offset = conf_file.file.info.st_size;
        conf_file.buffer->last = ngx_cpymem(conf_file.buffer->start,
                conf[j].conf.data, conf[j].conf.len);

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
                    conf[j].conf.data, conf[j].conf.len);
        }

        *conf_file.buffer->last++ = '}';

        rv = ngx_conf_parse(cf, NULL);

        if (rv != NGX_CONF_OK)
            rc = NGX_ERROR;
    }

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

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
            return NGX_ERROR;

        default:

            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "unexpected, rc=%d", rc);
            return NGX_ERROR;
    }

    return NGX_OK;
}


static u_char *
ngx_strchrr(ngx_str_t *s)
{
    u_char  *c;
    for (c = s->data + s->len - 1; c > s->data && *c != '.'; c--);
    return *c == '.' ? c : s->data + s->len;
}


ngx_int_t
ngx_template_tag(ngx_conf_t *cf, ngx_str_t keyfile, ngx_str_t *tag)
{
    u_char  *c;
    tag->data = ngx_pcalloc(cf->pool, keyfile.len + 1);
    if (tag->data == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_ERROR;
    }
    tag->len = keyfile.len;
    ngx_memcpy(tag->data, keyfile.data, keyfile.len);
    c = ngx_strchrr(tag);
    *c = 0;
    tag->len = c - tag->data;
    return NGX_OK;
}


static char *
ngx_template_conf(ngx_conf_t *cf, ngx_template_t *t)
{
    ngx_str_t  *value;

    value = cf->args->elts;

    t->filename = value[1];
    t->keyfile = value[2];

    if (ngx_template_tag(cf, t->keyfile, &t->tag) == NGX_OK) {
        if (ngx_template_conf_apply(cf, t) == NGX_OK)
            return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


char *
ngx_template_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_template_t            *t;
    char                      *rv;

    extern ngx_module_t ngx_template_module;

    tmcf = (ngx_template_main_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                     ngx_template_module);

    t = ngx_array_push(&tmcf->templates);

    if (t == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "no memory");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(t, sizeof(ngx_template_t));

    rv = ngx_template_conf(cf, t);
    if (rv == NGX_CONF_ERROR)
        tmcf->templates.nelts--;

    return rv;
}


static void
ngx_template_check_template(ngx_template_t *old)
{
    ngx_pool_t           *pool;
    ngx_file_t            file;
    ngx_conf_t            cf;
    ngx_template_t        t;
    ngx_uint_t            j;
    ngx_template_conf_t  *conf, *old_conf;

    t.filename = old->filename;
    t.keyfile = old->keyfile;

    ngx_str_null(&t.template);
    ngx_str_null(&t.yaml);

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");
        return;
    }

    pool->log = ngx_cycle->log;

    if (ngx_array_init(&t.entries, pool, 10,
            sizeof(ngx_template_conf_t)) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");
        goto done;
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));

    cf.log = ngx_cycle->log;
    cf.pool = pool;
    cf.cycle = (ngx_cycle_t *) ngx_cycle;

    file.fd = NGX_INVALID_FILE;
    file.name = t.keyfile;
    file.log = ngx_cycle->log;

    if (ngx_conf_full_name((ngx_cycle_t *) ngx_cycle, &file.name, 1) != NGX_OK)
        goto done;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &t.keyfile);
        goto done;
    }

    if (ngx_fd_info(file.fd, &file.info) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", &t.keyfile);
        goto done;
    }

    ngx_template_tag(&cf, t.keyfile, &t.tag);

    if (ngx_template_read_template(&cf, t.filename, &t.template, &t.updated)
            != NGX_OK)
        goto done;

    if (ngx_max(file.info.st_mtim.tv_sec, t.updated) == old->updated)
        goto done;
    
    if (ngx_template_conf_parse_yaml(pool, fdopen(file.fd, "r"), &t, NULL)
            != NGX_OK)
        goto done;

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

    ngx_signal_process((ngx_cycle_t *) ngx_cycle, "reload");

done:

    if (file.fd != NGX_INVALID_FILE)
        ngx_close_file(file.fd);

    ngx_destroy_pool(pool);
}


static void
ngx_template_check(ngx_array_t a)
{
    ngx_template_t  *t;
    ngx_uint_t       j;

    t = a.elts;
    for (j = 0; j < a.nelts; j++)
        ngx_template_check_template(t + j);
}


void
ngx_template_check_updates(ngx_template_main_conf_t *tmcf)
{
    ngx_template_check(tmcf->templates);
}


typedef struct {
    ngx_str_t  tag;
    ngx_str_t  name;
    ngx_str_t  key;
} lookup_key_t;


static lookup_key_t
split(ngx_str_t key)
{
    lookup_key_t  lk;
    u_char       *c = key.data;

    // tag

    lk.tag.data = key.data;
    while (c < key.data + key.len && *c != '.')
        c++;
    lk.tag.len = c - lk.tag.data;

    if (c == key.data + key.len)
        return lk;

    // name

    lk.name.data = ++c;
    while (c < key.data + key.len && *c != '.')
        c++;
    lk.name.len = c - lk.name.data;

    if (c == key.data + key.len) {
        lk.key = lk.name;
        return lk;
    }
 
    // key

    lk.key.data = ++c;
    lk.key.len = key.data + key.len - lk.key.data;

    return lk;
}


ngx_int_t
lookup(ngx_array_t *templates, ngx_str_t key, ngx_str_t *retval)
{
    ngx_template_main_conf_t  *tmcf;
    ngx_template_t            *t;
    ngx_template_conf_t       *conf;
    ngx_uint_t                 j, i;
    lookup_key_t               lk = split(key);
    
    if (lk.key.data == NULL)
        return NGX_DECLINED;

    if (templates == NULL) {
        tmcf = (ngx_template_main_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                         ngx_template_module);
        templates = &tmcf->templates;
    }

    for (j = 0; j < templates->nelts; j++) {

        t = (ngx_template_t *)
                ((u_char *) templates->elts + j * templates->size);

        if (ngx_memn2cmp(lk.tag.data, t->tag.data,
                         lk.tag.len, t->tag.len) == 0) {

            for (i = 0; i < t->entries.nelts; i++) {

            conf = (ngx_template_conf_t *)
                    ((u_char *) t->entries.elts + i * t->entries.size);

                if (ngx_memn2cmp(lk.name.data, conf->name.data,
                                 lk.name.len, conf->name.len) == 0) {

                    *retval = lookup_key(NULL, conf, lk.key);
                    if (retval->data != NULL)
                        return NGX_OK;

                    break;
                }
            }
        }
    }

    return NGX_DECLINED;
}
