/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include "ngx_api_gateway_cfg.h"

#include <ngx_event.h>
#include <sqlite3.h>


static ngx_int_t
ngx_api_gateway_cfg_init_worker(ngx_cycle_t *cycle);


static void
ngx_api_gateway_cfg_exit(ngx_cycle_t *cycle);


static void *
ngx_api_gateway_cfg_create_main_conf(ngx_cycle_t *cycle);


static char *
ngx_api_gateway_cfg_init_main_conf(ngx_cycle_t *cycle, void *conf);


static ngx_core_module_t ngx_api_gateway_cfg_ctx = {
    ngx_string("ngx_api_gateway_cfg_module"),
    ngx_api_gateway_cfg_create_main_conf,      /* create main configuration */
    ngx_api_gateway_cfg_init_main_conf         /* init main configuration */
};


typedef struct {
    ngx_str_t      filename;
    sqlite3       *sqlite;
    sqlite3_stmt  *upstream_add;
    sqlite3_stmt  *upstream_delete;
    sqlite3_stmt  *route_add;
    sqlite3_stmt  *route_delete;
} ngx_api_gateway_cfg_main_conf_t;


static ngx_command_t  ngx_api_gateway_cfg_commands[] = {

    { ngx_string("api_gateway_config"),
      NGX_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_api_gateway_cfg_main_conf_t, filename),
      NULL },

    ngx_null_command

};


ngx_module_t ngx_api_gateway_cfg_module = {
    NGX_MODULE_V1,
    &ngx_api_gateway_cfg_ctx,          /* module context */
    ngx_api_gateway_cfg_commands,      /* module directives */
    NGX_CORE_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_api_gateway_cfg_init_worker,   /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    ngx_api_gateway_cfg_exit,          /* exit process */
    ngx_api_gateway_cfg_exit,          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t types[] = {

    ngx_string("http"),
    ngx_string("stream")

};


static ngx_api_gateway_cfg_main_conf_t *
ngx_api_gateway_cfg_conf(volatile ngx_cycle_t *cycle)
{
    return (ngx_api_gateway_cfg_main_conf_t *) ngx_get_conf(cycle->conf_ctx,
        ngx_api_gateway_cfg_module);
}


static ngx_int_t
open_database(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf = ngx_api_gateway_cfg_conf(cycle);
    char                              filename[cmcf->filename.len + 1];
    char                             *err = NULL;

    ngx_memcpy(filename, cmcf->filename.data, cmcf->filename.len);
    filename[cmcf->filename.len] = 0;

    if (sqlite3_open_v2(filename, &cmcf->sqlite,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "Failed to open api gateway database %V", &cmcf->filename);
        return NGX_ERROR;
    }

    if (SQLITE_OK != sqlite3_exec(cmcf->sqlite, "PRAGMA journal_mode=WAL",
                                  0, 0, &err))
        goto fail;

    if (SQLITE_OK != sqlite3_exec(cmcf->sqlite, "PRAGMA busy_timeout=30000",
                                  0, 0, &err))
        goto fail;

    if (SQLITE_OK != sqlite3_wal_autocheckpoint(cmcf->sqlite, 1))
        goto fail;

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
        "Failed to init api gateway database, %s", err);
    sqlite3_close(cmcf->sqlite);

    return NGX_ERROR;
}

                
static ngx_int_t
init_database(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf = ngx_api_gateway_cfg_conf(cycle);
    char                             *err = NULL;

    if (SQLITE_OK != sqlite3_exec(cmcf->sqlite,
                                  "CREATE TABLE IF NOT EXISTS UPSTREAMS ("
                                  "  name TEXT,"
                                  "  type INT,"
                                  "  method INT,"
                                  "  keepalive INT,"
                                  "  keepalive_requests INT,"
                                  "  keepalive_timeout INT,"
                                  "  max_conns INT,"
                                  "  max_fails INT,"
                                  "  fail_timeout INT,"
                                  "  dns_update INT,"
                                  "  PRIMARY KEY (name, type)"
                                  ")", 0, 0, &err)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "Failed to init api gateway database, %s", err);
        return NGX_ERROR;
    }

    if (SQLITE_OK != sqlite3_exec(cmcf->sqlite,
                                  "CREATE TABLE IF NOT EXISTS ROUTES ("
                                  "  var TEXT,"
                                  "  api TEXT,"
                                  "  upstream TEXT,"
                                  "  PRIMARY KEY (var, api)"
                                  ")", 0, 0, &err)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "Failed to init api gateway database, %s", err);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_api_gateway_cfg_init_database(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf;

    cmcf = ngx_api_gateway_cfg_conf(cycle);

    if (open_database(cycle) == NGX_ERROR) {
        cmcf->sqlite = NULL;
        return NGX_ERROR;
    }

    if (init_database(cycle) == NGX_ERROR) {
        sqlite3_close(cmcf->sqlite);
        cmcf->sqlite = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_api_gateway_cfg_create_main_conf(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cycle->pool, sizeof(ngx_api_gateway_cfg_main_conf_t));
    if (cmcf == NULL)
        return NULL;

    return cmcf;
}


static char *
ngx_api_gateway_cfg_init_main_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf = conf;

    static ngx_str_t  default_filename = ngx_string("api_gateway_config.db");

    if (cmcf->filename.data == NULL)
        cmcf->filename = default_filename;

    if (ngx_conf_full_name(cycle, &cmcf->filename, 1) != NGX_OK)
        return NGX_CONF_ERROR;

    if (ngx_api_gateway_cfg_init_database(cycle) == NGX_ERROR)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}


static void
ngx_api_gateway_cfg_handler(ngx_event_t *ev)
{
//    ngx_api_gateway_cfg_main_conf_t  *cmcf = ngx_api_gateway_cfg_main_conf();

    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    ngx_add_timer(ev, 1000);
}


static ngx_int_t
ngx_api_gateway_cfg_init_worker(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    ngx_event_t                      *ev;
    static ngx_connection_t           c = { .fd = -1 };

    cmcf = ngx_api_gateway_cfg_conf(cycle);

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    cmcf->sqlite = NULL;

    if (ngx_api_gateway_cfg_init_database(cycle) == NGX_ERROR)
        return NGX_ERROR;

    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL) {
        sqlite3_close(cmcf->sqlite);
        cmcf->sqlite = NULL;
        return NGX_ERROR;
    }

    ev->log = cycle->log;
    ev->data = &c;
    ev->handler = ngx_api_gateway_cfg_handler;

    ngx_add_timer(ev, 10000);

    return NGX_OK;
}


static void
ngx_api_gateway_cfg_exit(ngx_cycle_t *cycle)
{
    ngx_api_gateway_cfg_main_conf_t  *cmcf;

    cmcf = ngx_api_gateway_cfg_conf(cycle);

    if (cmcf->sqlite != NULL)
        sqlite3_close(cmcf->sqlite);
}


ngx_int_t
ngx_api_gateway_cfg_upstream_add(ngx_api_gateway_cfg_upstream_t *u)
{
    static const char *SQL = "INSERT INTO UPSTREAMS ("
                             "  name,"
                             "  type,"
                             "  method,"
                             "  keepalive,"
                             "  keepalive_requests,"
                             "  keepalive_timeout,"
                             "  max_conns,"
                             "  max_fails,"
                             "  fail_timeout,"
                             "  dns_update"
                             ") VALUES ("
                             "  @name,"
                             "  @type,"
                             "  @method,"
                             "  @keepalive,"
                             "  @keepalive_requests,"
                             "  @keepalive_timeout,"
                             "  @max_conns,"
                             "  @max_fails,"
                             "  @fail_timeout,"
                             "  @dns_update"
                             ")";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt;
    int                               rc;

    cmcf = ngx_api_gateway_cfg_conf(ngx_cycle);

    if (cmcf->upstream_add != NULL) {
        sqlite3_clear_bindings(cmcf->upstream_add);
        goto add;
    }

    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1,
                                        &cmcf->upstream_add, 0))
        goto fail;
    
add:

    stmt = cmcf->upstream_add;

    if (SQLITE_OK != sqlite3_bind_text(stmt, 1, (char *) u->name.data,
                                       u->name.len, 0))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 2, u->type))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 3, u->method))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 4, u->keepalive))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 5, u->keepalive_requests))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 6, u->keepalive_timeout))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 7, u->max_conns))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 8, u->max_fails))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 9, u->fail_timeout))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int(stmt, 10, u->dns_update))
        goto fail;

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
        goto fail;

    sqlite3_reset(stmt);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "[%V] add upstream '%V'", &types[u->type], &u->name);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to add upstream to database, %s", sqlite3_errmsg(cmcf->sqlite));

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        cmcf->upstream_add = NULL;
    }

    if (rc == SQLITE_CONSTRAINT)
        return NGX_DECLINED;

    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_cfg_upstream_delete(ngx_str_t name, ngx_int_t type)
{
    static const char *SQL = "DELETE FROM UPSTREAMS WHERE"
                             "  name = @name AND type = @type";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt;
    int                               affected;
    
    cmcf = ngx_api_gateway_cfg_conf(ngx_cycle);

    if (cmcf->upstream_delete != NULL) {
        sqlite3_clear_bindings(cmcf->upstream_delete);
        goto delete;
    }
    
    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1,
                                        &cmcf->upstream_delete, 0))
        goto fail;

delete:

    stmt = cmcf->upstream_delete;

    if (SQLITE_OK != sqlite3_bind_text(stmt, 1, (char *) name.data,
                                       name.len, 0))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_int64(stmt, 2, type))
        goto fail;

    if (sqlite3_step(stmt) != SQLITE_DONE)
        goto fail;

    affected = sqlite3_changes(cmcf->sqlite);

    sqlite3_reset(stmt);

    if (affected == 0)
        return NGX_DECLINED;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "[%V] delete upstream '%V'", &types[type], &name);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to remove upstream from database, %s",
        sqlite3_errmsg(cmcf->sqlite));

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        cmcf->upstream_delete = NULL;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_cfg_upstreams(volatile ngx_cycle_t *cycle,
    on_upstream_pt cb, void *ctxp)
{
    static const char *SQL = "SELECT"
                             "  name,"
                             "  type,"
                             "  method,"
                             "  keepalive,"
                             "  keepalive_requests,"
                             "  keepalive_timeout,"
                             "  max_conns,"
                             "  max_fails,"
                             "  fail_timeout,"
                             "  dns_update "
                             "FROM UPSTREAMS";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt = NULL;
    ngx_api_gateway_cfg_upstream_t    u;
    int                               ok;

    cmcf = ngx_api_gateway_cfg_conf(cycle);

    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1, &stmt, 0))
        goto fail;

    while ((ok = sqlite3_step(stmt)) == SQLITE_ROW) {

        u.name.data = (u_char *) sqlite3_column_text(stmt, 0); 
        u.name.len = ngx_strlen(u.name.data);
        u.type = sqlite3_column_int64(stmt, 1);
        u.method = sqlite3_column_int64(stmt, 2);
        u.keepalive = sqlite3_column_int64(stmt, 3);
        u.keepalive_requests = sqlite3_column_int64(stmt, 4);
        u.keepalive_timeout = sqlite3_column_int64(stmt, 5);
        u.max_conns = sqlite3_column_int64(stmt, 6);
        u.max_fails = sqlite3_column_int64(stmt, 7);
        u.fail_timeout = sqlite3_column_int64(stmt, 8);
        u.dns_update = sqlite3_column_int(stmt, 9);

        if ((*cb)(&u, ctxp) == NGX_ERROR) {
            ok = SQLITE_ERROR;
            break;
        }
    }

    sqlite3_finalize(stmt);
    stmt = NULL;

    if (ok == SQLITE_DONE)
        return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to list upstreams, %s", sqlite3_errmsg(cmcf->sqlite));

    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_cfg_route_add(ngx_str_t var, ngx_str_t api, ngx_str_t upstream)
{
    static const char *SQL = "INSERT INTO ROUTES ("
                             "  var,"
                             "  api,"
                             "  upstream"
                             ") VALUES ("
                             "  @var,"
                             "  @api,"
                             "  @upstream"
                             ")";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt;
    int                               rc;

    cmcf = ngx_api_gateway_cfg_conf(ngx_cycle);

    if (cmcf->route_add != NULL) {
        sqlite3_clear_bindings(cmcf->route_add);
        goto add;
    }

    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1,
                                        &cmcf->route_add, 0))
        goto fail;
    
add:

    stmt = cmcf->route_add;

    if (SQLITE_OK != sqlite3_bind_text(stmt, 1, (char *) var.data,
                                       var.len, 0))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_text(stmt, 2, (char *) api.data,
                                       api.len, 0))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_text(stmt, 3, (char *) upstream.data,
                                       upstream.len, 0))
        goto fail;

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
        goto fail;

    sqlite3_reset(stmt);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "add route var=%V api=%V upstream=%V", &var, &api, &upstream);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to add route to database, %s", sqlite3_errmsg(cmcf->sqlite));

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        cmcf->route_add = NULL;
    }

    if (rc == SQLITE_CONSTRAINT)
        return NGX_DECLINED;

    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_cfg_route_delete(ngx_str_t var, ngx_str_t api)
{
    static const char *SQL = "DELETE FROM ROUTES WHERE"
                             "  var = @var AND api = @api";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt;
    int                               affected;
    
    cmcf = ngx_api_gateway_cfg_conf(ngx_cycle);

    if (cmcf->route_delete != NULL) {
        sqlite3_clear_bindings(cmcf->route_delete);
        goto del;
    }

    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1,
                                        &cmcf->route_delete, 0))
        goto fail;

del:

    stmt = cmcf->route_delete;

    if (SQLITE_OK != sqlite3_bind_text(stmt, 1, (char *) var.data,
                                       var.len, 0))
        goto fail;
    if (SQLITE_OK != sqlite3_bind_text(stmt, 2, (char *) api.data,
                                       api.len, 0))
        goto fail;

    if (sqlite3_step(stmt) != SQLITE_DONE)
        goto fail;

    affected = sqlite3_changes(cmcf->sqlite);

    sqlite3_reset(stmt);

    if (affected == 0)
        return NGX_DECLINED;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
        "delete route var=%V api=%V", &var, &api);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to remove route from database, %s",
        sqlite3_errmsg(cmcf->sqlite));

    if (stmt != NULL) {
        sqlite3_finalize(stmt);
        cmcf->route_delete = NULL;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_api_gateway_cfg_routes(ngx_cycle_t *cycle,
    ngx_str_t var, on_route_pt cb, void *ctxp)
{
    static const char *SQL = "SELECT"
                             "  api,"
                             "  upstream "
                             "FROM ROUTES WHERE var = @var";

    ngx_api_gateway_cfg_main_conf_t  *cmcf;
    sqlite3_stmt                     *stmt = NULL;
    ngx_str_t                         api, upstream;
    int                               ok;

    cmcf = ngx_api_gateway_cfg_conf(cycle);

    if (SQLITE_OK != sqlite3_prepare_v2(cmcf->sqlite, SQL, -1, &stmt, 0))
        goto fail;

    if (SQLITE_OK != sqlite3_bind_text(stmt, 1, (char *) var.data,
                                       var.len, 0))
        goto fail;

    while ((ok = sqlite3_step(stmt)) == SQLITE_ROW) {

        api.data = (u_char *) sqlite3_column_text(stmt, 0);
        api.len = ngx_strlen(api.data);

        upstream.data = (u_char *) sqlite3_column_text(stmt, 1);
        upstream.len = ngx_strlen(upstream.data);

        if ((*cb)(api, upstream, ctxp) != NGX_OK)
            break;
    }

    sqlite3_finalize(stmt);
    stmt = NULL;

    if (ok == SQLITE_DONE)
        return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "Failed to list routes, %s", sqlite3_errmsg(cmcf->sqlite));

    return NGX_ERROR;
}
