# Nginx Api Gateway module

`ngx_api_gateway` is a dynamically configurable solution for routing requests.

## Key features

- Dynamically add and remove upstreams.
- Dynamically modify routes between URLs and backends.
- Synchronization with external provider.
- Templating.
- Environment may be used in configuration inventory.
- Configuration persistance.

# Build status
[![Build Status](https://travis-ci.org/ZigzagAK/ngx_api_gateway.svg)](https://travis-ci.org/ZigzagAK/ngx_api_gateway)

# Dependencies

## Modules

[ngx_template_module](https://github.com/ZigzagAK/ngx_template_module).
[ngx_dynamic_upstream](https://github.com/ZigzagAK/ngx_dynamic_upstream).
[ngx_dynamic_healthcheck 2.X.X branch](https://github.com/ZigzagAK/ngx_dynamic_healthcheck).
[ngx_http_upsync_upstream](https://github.com/ZigzagAK/ngx_http_upsync_upstream).

## Other

SQLite for persistance.

# Status

Development.

# Overview

## Upstreams

You may dynamically add and remove upstreams to nginx in runtime without reloads.

This feature is very important because reloads of nginx needs to close all active connections and create another ones. Websockets and tcp streams may prevent fast reloads.

## Routes

As you know, locations in nginx is a configuration time feature and routing can't be changed in runtime dynamically.

With dynamic routes you may add and remove routes based on prefix tree and regular expression patterns.

You may associate URLs to upstream in runtime without chaning nginx cnfiguration with REST without reloads.

Configurations is stored to internal sqlite database and on reload is loaded to nginx configuration.

## Synchronization with external provirers

Routes and upstreams configuration may be fetched from external http server and applied. Some of changes may needs to reload nginx.

## Templating

For detailed templating possibilities you may look [ngx_template_module](https://github.com/ZigzagAK/ngx_template_module).

# Dynamic upstreams

## dynamic_conf_zone

|Syntax |dynamic_conf_zone <zone size>|
|-------|----------------|
|Default|8m|
|Context|http|

## upstream_add

|Syntax |upstream_add|
|-------|----------------|
|Default|-|
|Context|location|

Location handler for adding upstream.

Method: `POST`
Arguments:
  - method - roundrobin, leastconn, ip_hash.
  - stream - add stream upstream.
  - keepalive - number of keepalived connections.
  - keepalive_requests - number of keepalived requests.
  - keepalive_timeout - timeout for keepalived connection.
  - dns_update - background synchronization hosts addresses by DNS in seconds. Looking for details in [ngx_dynamic_upstream](https://github.com/ZigzagAK/ngx_dynamic_upstream#dns_update).

Example: `curl -X POST 'localhost:6000/upstream/add?name=test&keepalive=600&keepalive_requests=10'`.

## upstream_delete

|Syntax |upstream_delete|
|-------|----------------|
|Default|-|
|Context|location|

Location handler for deleting upstream.

Example: `curl -X DELETE 'localhost:6000/upstream/delete?name=test'`.

## upstream_list

|Syntax |upstream_list|
|-------|----------------|
|Default|-|
|Context|location|

Location handler for list dynamic upstreams.

Example: `curl localhost:6000/upstream/list`.

Output:
```
[
    {
        "fail_timeout": 0,
        "keepalive": 600,
        "keepalive_requests": 10,
        "max_conns": 0,
        "max_fails": 0,
        "method": "roundrobin",
        "name": "test1",
        "type": "http"
    },
    {
        "fail_timeout": 0,
        "keepalive": 600,
        "keepalive_requests": 10,
        "max_conns": 0,
        "max_fails": 0,
        "method": "roundrobin",
        "name": "test2",
        "type": "http"
    }
]
```

# Dynamic routes

