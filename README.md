# Nginx Api Gateway module

`ngx_api_gateway` is a dynamically configurable solution for routing requests.

## Key features

- Dynamically add and remove upstreams.
- Dynamically modify routes between URLs and backends.
- Synchronization with external registry.
- Templating.
- Environment may be used in configuration inventory.
- Internal configuration persistent storage.

# Build status
[![Build Status](https://travis-ci.org/ZigzagAK/ngx_api_gateway.svg)](https://travis-ci.org/ZigzagAK/ngx_api_gateway)

# Dependencies

## Modules

- [ngx_template_module](https://github.com/ZigzagAK/ngx_template_module).
- [ngx_dynamic_upstream](https://github.com/ZigzagAK/ngx_dynamic_upstream).
- [ngx_dynamic_healthcheck 2.X.X branch](https://github.com/ZigzagAK/ngx_dynamic_healthcheck).
- [ngx_http_upsync_upstream](https://github.com/ZigzagAK/ngx_http_upsync_upstream).

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

# Synopsis

**env.template:**

```
env {{name}};
```

**env.yml:**

```yaml
---
env:
  - name: LISTEN_PORT
```

**dynamic.template:**

```nginx
server {
    listen {{listen}} reuseport;

    default_type text/plain;

    location / {
        auth_request {{auth.request}};

        api_gateway_router_dynamic {{dynamic_var}}:5m;

        proxy_connect_timeout {{proxy.connect_timeout}};
        proxy_read_timeout {{proxy.read_timeout}};

        if ({{dynamic_var}} = '') {
            return 404 'No route';
        }

        proxy_pass {{proxy.protocol}}://{{dynamic_var}};
    }

    location = /auth_stub {
        internal;
        return 200;
    }
}
```

**dynamic.yml:**

```yaml
---
dynamic:
  - name: dynamic_entrypoint1
    listen: "{{env(LISTEN_PORT1)|default(9000)}}"
    dynamic_var: $dynamic1
    auth:
      request: /auth_stub
    proxy:
      connect_timeout: 10s
      read_timeout: 60s
      protocol: http

  - name: dynamic_entrypoint2
    listen: "{{env(LISTEN_PORT2)|default(9001)}}"
    dynamic_var: $dynamic2
    auth:
      request: /auth_stub
    proxy:
      connect_timeout: 10s
      read_timeout: 60s
      protocol: http
```

**check.temlate:**

```
healthcheck passive type=http rise={{rise}} fall={{fall}} timeout={{timeout}} interval={{interval}};
healthcheck_request_uri {{request.method}} {{request.uri}};
healthcheck_response_codes {{response.codes}};
healthcheck_response_body {{response.match}};
```

**check.yml:**

```yaml
---
check:
  - name: http
    rise: 1
    fall: 2
    timeout: 10000
    interval: 10
    request:
      method: GET
      uri: /healthz
    response:
      codes: 200 204
      match: .*
```

**nginx.conf:**

```nginx
template keyfile=env.yml template=env.template;

http {
    dynamic_conf_zone 8m;

    template keyfile=check.yml template=check.template;

    api_gateway_template keyfile=dynamic.yml template=dynamic.template;

    server {
        listen 8888;

        location = /healthcheck/get {
            healthcheck_get;
        }

        location = /healthcheck/status {
            healthcheck_status;
        }

        location = /route/set {
            api_gateway_route_set;
        }

        location = /route/delete {
            api_gateway_route_delete;
        }

        location = /dynamic {
            dynamic_upstream;
        }

        location = /upstream/add {
            upstream_add;
        }

        location = /upstream/delete {
            upstream_delete;
        }

        location = /upstream/list {
            upstream_list;
        }
    }
}
```

For more examples look into `example` folder.

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

Dynamic routes is implemented via `api_gateway_router_dynamic` directive.

## Declare dynamic router

|Syntax |api_gateway_router_dynamic `<variable>:<mem>`|
|-------|----------------|
|Default|-|
|Context|http,location|

Example: 

```nginx
location / {
    api_gateway_router_dynamic $backend:5m;
    proxy_pass http://$backend;
```

Routes associated with nginx variable, declared with `api_gateway_router_dynamic` directive.

## Set route handler

|Syntax |api_gateway_route_set|
|-------|----------------|
|Default|-|
|Context|location|

Register location handler for setup new route.

Method: `POST`

Arguments:
  - backend - upstream name.
  - api - route. May be uri mask (/a/b/*/c/d) or regular expression.
  - var - variable name.

Example: `curl -X POST localhost:8888/route/set?backend=app1&api=/a/b/*/c&var=$backend`.

## Delete route handler

|Syntax |api_gateway_route_set|
|-------|----------------|
|Default|-|
|Context|location|

Register location handler for delete route.

Method: `DELETE`

Arguments:
  - api - route. May be uri mask (/a/b/*/c/d) or regular expression.
  - var - variable name.

Example: `curl -X DELETE localhost:8888/route/set?api=/a/b/*/c&var=$backend`.

# Static routes

Static routes is implemented via `api_gateway_router` directive.

It injects backend's configuration into server or location.

## Declare static router

|Syntax |`api_gateway_router <variable>:<mem> <backends>`|
|-------|----------------|
|Default|-|
|Context|server,location|

Example:

**check.yml:**

```yaml
---
check:
  - name: http
    rise: 1
    fall: 2
    timeout: 10000
    interval: 10
    request:
      method: GET
      uri: /healthz
    response:
      codes: 200 204
      match: .*
```

**backend.template:**

```
upstream {{__group}}@{{name}} {
    zone shm_{{name}} 256k;

    dns_update {{dns.update}};
    dns_add_down on;

    {{servers}}

    check passive type=http rise={{check@http.rise}} fall={{check@http.fall}} timeout={{check@http.timeout}} interval={{check@http.interval}};
    check_request_uri {{check@http.request.method}} {{check@http.request.uri}};
    check_response_codes {{check@http.response.codes}};
    check_response_body {{check.response.match}};
}
```

**backends.yml:**

```
---
backends:

  - name: backend1
    api:
      - /app1/fun1
      - ~ ^/app3/fun2
      - /app1/fun3
      - /app1/*/hello/*
      - /app1/0000000
    dns:
      update: 60s
    server:
      max_conns: 10
      max_fails: 2
      fail_timeout: 30s
    upsync:
      interval: 60s
      timeout: 10s
    check:
      response:
        match: pong
    servers:
      - server 127.0.0.1:3333 max_conns={{server.max_conns}} max_fails={{server.max_fails}} fail_timeout={{server.fail_timeout}};
      - server 127.0.0.1:4444 max_conns={{server.max_conns}} max_fails={{server.max_fails}} fail_timeout={{server.fail_timeout}};

  - name: backend2
    api:
      - /app2/fun1
      - ~ ^/app2/fun2
      - /app2/fun3
      - /app2/*/hello/*
      - /app2/0000000
    dns:
      update: 60s
    server:
      max_conns: 10
      max_fails: 2
      fail_timeout: 30s
    upsync:
      interval: 60s
      timeout: 10s
    check:
      response:
        match: pong
    servers:
      - server 127.0.0.1:5555 max_conns={{server.max_conns}} max_fails={{server.max_fails}} fail_timeout={{server.fail_timeout}};
      - server 127.0.0.1:6666 max_conns={{server.max_conns}} max_fails={{server.max_fails}} fail_timeout={{server.fail_timeout}};
```

**entrypoint.template:**

```
server {
    listen {{listen}} reuseport;

    default_type text/plain;

    {{server.directives|default()}}

    {{server.locations|default()}}

    location / {
        auth_request {{auth.request}};

        {{location.directives|default()}}

        api_gateway_router $backend:1m {{backends}};

        proxy_connect_timeout {{proxy.connect_timeout}};
        proxy_read_timeout {{proxy.read_timeout}};

        proxy_pass {{proxy.protocol}}://$backend;
    }

    location = /auth_stub {
        internal;
        return 200;
    }
}
```

**entrypoints.yml:**

```
---
entrypoints:

  - name: app
    listen: 11111
    server:
      directives:
        - set $variable1 1;
        - set $variable2 2;
      locations:
        - location ~* ^/app1/.+\.(jpg|gif|png)$ { proxy_pass http://backends@backend1; }
        - location ~* ^/app2/.+\.(jpg|gif|png)$ { proxy_pass http://backends@backend2; }
    location:
      directives:
        - set $variable3 3;
        - set $variable4 4;
    auth:
      request: /auth_stub
    proxy:
      connect_timeout: 100s
      read_timeout: 600s
      protocol: http
    backends:
      - backends@backend1
      - backends@backend2
```

**nginx:**

```nginx
http {
    template keyfile=check.yml;
    api_gateway_template keyfile=backends.yml template=backend.template;
    api_gateway_template keyfile=entrypoints.yml template=entrypoint.template;
}
```

# Synchronization with external registry

## api_gateway_template

|Syntax |api_gateway_template keyfile=keys.yml template=template_file url=host:port/url|
|-------|----------------|
|Context|http|

Synchronization inventory with external registry.

Example: `api_gateway_template keyfile=backends.yml template=backend.template url=127.0.0.1:7777/registry/backends;`

See example for details.

# Update timeout

|Syntax |api_gateway_timeout `<timeout>`|
|-------|----------------|
|Context|http|

# Update interval

|Syntax |api_gateway_interval `<interval>`|
|-------|----------------|
|Context|http|
