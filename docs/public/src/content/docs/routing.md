---
title: Path & Header Matching
description: How Ophan matches requests to routes by path, hosts, and methods
tags: ["routing"]
order: 300
---

Routes define how incoming requests are matched and forwarded to backends.

> **⚠️ In development** — Matching is being implemented. Route groups are planned.

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

| Type                   | DSL Pattern          | Example Match        | Example No Match |
| ---------------------- | -------------------- | -------------------- | ---------------- |
| Exact                  | `/api/users`         | `/api/users`         | `/api/users/123` |
| Param simple           | `/api/users/:id`     | `/api/users/1`       | `/api/users/1/x` |
| Multi-segment wildcard | `/api/files/*`       | `/api/files/a/b/c`   | —                |
| Param + wildcard mix   | `/users/:id/posts/*` | `/users/1/posts/a/b` | `/users/1/posts` |
| Catch-all              | `/*`                 | any path             | —                |

## Host Filtering

Restrict a route to specific hostnames via the `Host` header:

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

## Route Groups (planned) <span class="status-badge badge-planned">Planned</span>

Shared route configuration will be expressible as reusable groups:

```hcl
group "public-api" {
    hosts   = ["api.example.me"]
    methods = ["GET", "POST"]
    backend = upstream("api")

    policies {
        cors = "cors-default"
    }

    match "GET /*" {
        backend = upstream("api")
    }
}
```

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
