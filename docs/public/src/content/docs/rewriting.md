---
title: URL & Header Rewriting
description: Rewrite request paths and manipulate inbound/outbound headers
tags: ["routing"]
order: 301
---

Ophan can rewrite request URLs and transform headers before forwarding to a backend, and sanitize headers before returning a response.

> **⚠️ In development** — Rewriting is being implemented.

---

## URL Rewriting

```hcl
path "/api/*" {
    backend = upstream("api")

    rewrite {
        strip_prefix "/api"
        strip_suffix ".json"

        replace "/v1/*" -> "/v2/$1"
        replace "/users/(.*)/posts" -> "/posts?user=$1"

        trailing_slash "ensure"   # or "strip", "keep"
    }
}
```

| Directive          | Purpose                                   |
| ------------------ | ----------------------------------------- |
| `strip_prefix`     | Remove a leading path segment             |
| `strip_suffix`     | Remove a trailing extension               |
| `replace`          | Regex/path pattern replacement with `$1`  |
| `trailing_slash`   | `ensure`, `strip`, or `keep`              |

## Inbound Headers

Transform headers before forwarding to the upstream:

```hcl
path "/api/*" {
    backend = upstream("api")

    inbound_headers {
        set = { "X-Client-Layer" = "edge" }
        remove = ["X-Bad-Header"]

        to_upstream {
            set = { "X-Forwarded-By" = "Ophan-Edge" }
            remove = ["Authorization"]   # e.g. the edge already validated the token
        }
    }
}
```

| Block          | Purpose                                        |
| -------------- | ---------------------------------------------- |
| `inbound_headers` | Applies to the client → gateway request    |
| `to_upstream`  | Applies to the gateway → backend request        |

## Outbound Headers

Sanitize or augment headers before the response is returned to the client:

```hcl
path "/api/*" {
    backend = upstream("api")

    outbound_headers {
        from_upstream {
            remove = ["X-Internal-Cluster-ID"]
        }

        set = {
            "Cache-Control" = "no-store"
        }
        remove = ["Server", "X-Powered-By"]
    }
}
```

| Block             | Purpose                                          |
| ----------------- | ------------------------------------------------ |
| `outbound_headers`  | Applies to the final response                |
| `from_upstream`   | Applies to the backend → gateway response         |

## Common Use Cases

- Strip an `/api` prefix before forwarding to an internal service
- Remove sensitive internal headers (`Server`, `X-Powered-By`) before responding
- Set cache control on responses

## Next Steps

- [Path & Header Matching](/routing)
- [Configuration Reference](/configuration)