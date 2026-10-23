---
title: Path & Header Matching
description: How Ophan matches requests to routes by path, hosts, and methods
tags: ["routing"]
order: 300
---

Routes define how incoming requests are matched and forwarded to backends.

Routes are declared one path at a time with `path` (or `route`), or grouped by host with a
`host` block.

---

## Route Definition

```hcl
routes {
    path "/api/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        backend = upstream("api")
    }
}
```

## Route Pattern Reference

| Type                   | DSL Pattern          | Example Match                          | Example No Match  |
| ---------------------- | -------------------- | -------------------------------------- | ----------------- |
| Exact                  | `/api/users`         | `/api/users`                           | `/api/users/123`  |
| Param simple           | `/api/users/:id`     | `/api/users/1`                         | `/api/users/1/x`  |
| Multi-segment wildcard | `/api/files/*`       | `/api/files/a/b/c`, `/api/files`       | `/api/filesystem` |
| Param + wildcard mix   | `/users/:id/posts/*` | `/users/1/posts/a/b`, `/users/1/posts` | `/users/1/x`      |
| Catch-all              | `/*`                 | any path                               | —                 |

- `/x/*` also matches `/x` and `/x/`, for the methods that `/x` does not route itself.
- A trailing slash is ignored on both the pattern and the request (`/users/` ≡ `/users`).
- Before routing, the request path is normalized: `.` and `..` segments are resolved,
  repeated slashes are merged and percent-encoded unreserved characters are decoded.
  Upstreams and policies see the normalized path.

## Host Filtering

Restrict a route to specific hostnames via the `Host` header. The route is registered on
every listed host; host matching ignores case, the port and a trailing dot:

```hcl
path "/" {
    hosts = ["blob.domain.com", "storage.domain.com"]
    backend = static("/var/www/public")
}
```

## HTTP Methods

Restrict the allowed HTTP methods:

```hcl
path "/api/*" {
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    backend = upstream("api")
}
```

## Backend Targets

A route must define exactly one backend target.

### Upstream Backend

```hcl
backend = upstream("api")
```

### Static Backend

```hcl
backend = static("/var/www/public")
```

## Route Options

```hcl
path "/api/*" {
    hosts   = ["api.example.me"]
    methods = ["GET", "POST"]

    backend = upstream("api")

    timeouts {
        connect = "600s"
        read    = "3600s"
        send    = "3600s"
    }

    streaming {
        buffering = false
        chunked   = false
    }

    policies {
        auth  = "default"
        cors  = "cors-default"
        waf   = "waf-default"
    }
}
```

## Host Blocks

A `host` block declares the routes of one or more hosts. Everything written at the host level
(backend, policies, headers, rewrite, timeouts, streaming, methods) is inherited by its `match`
blocks, which only state what changes:

```hcl
routes {
    host ["example.com", "www.example.com"] {
        backend = upstream("api")
        policies { limiter = "default" cors = "web" }

        match "GET /users/*" { }                     # inherits everything
        match "POST|PUT /users" {
            backend = upstream("users")
            policies { auth = "oauth" }              # adds auth; limiter and cors stay
        }
        match "/health" {                            # no method: every method
            policies { limiter = off }               # drops the inherited limiter
        }
    }

    host "static.example.com" {                      # one host: a string; no match blocks: "/*"
        backend = static("/var/www")
    }
}
```

- `host` takes one host as a string (`host "example.com"`) or several as an array
  (`host ["example.com", "www.example.com"]`); wildcards like `*.example.com` work in both.
- A `match` pattern is `"<METHOD|METHOD> /path"` or just `"/path"`; the path uses the same
  syntax as `path` routes. Without methods the match accepts every method (or the host's
  `methods`, when the block sets them).
- A host block without `match` blocks serves every path (`/*`). With `match` blocks, paths
  that match none of them get `404`.
- The same path may appear in several matches as long as their methods do not overlap:
  `GET /users` and `POST /users` can have different backends and policies. A request with
  another method gets `405`. CORS preflights (`OPTIONS`) of that path are answered by the
  first match that has a CORS policy.
- **Inheritance:** `backend` (with its `static_config`), `rewrite`, `timeouts`, `streaming` and
  `protocols` are replaced as a whole by the match. `policies` are merged by kind, and
  `<kind> = off` removes an inherited one. `inbound_headers`/`outbound_headers` are merged by
  header name; on the same header the match wins.
- `hosts` is not allowed inside a host block, and `methods` is not allowed inside a match:
  write them after `host` and in the pattern.
- A path of a host cannot be declared both by a `path` route and by a host block, nor twice
  with a common method; the configuration is rejected with the conflicting host and path.

## Full Example

```hcl
routes {
    path "/api/v1/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        backend = upstream("api")
        policies {
            auth = "default"
            waf  = "waf-default"
        }
    }
}
```

## Next Steps

- [URL & Header Rewriting](/rewriting)
- [Configuration Reference](/configuration)
