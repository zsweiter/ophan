---
title: CORS & Security Headers
description: Cross-origin policies and helmet security header profiles
tags: ["security"]
order: 403
---

Ophan handles Cross-Origin Resource Sharing and injects hardened security headers through the `cors` and `helmet` policies.

---

## CORS

### Minimal Policy

```hcl
policy cors "default" {
    allow_origins = ["https://example.com"]
}
```

### Full Policy

```hcl
policy cors "default" {
    allow_origins      = ["app.example.me", "api.example.me"]
    allow_methods      = ["GET", "POST", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS"]
    allow_headers      = ["Authorization", "X-Request-Id"]
    expose_headers     = ["X-Request-Id"]
    allow_credentials  = true
    max_age            = "2h"

    exclude_paths = [
        "/health",
    ]
}
```

### Schema

| Property            | Type            | Description                      |
| ------------------- | --------------- | -------------------------------- |
| `allow_origins`     | `Array<String>` | Allowed origins, support wilcard |
| `allow_methods`     | `Array<String>` | Allowed HTTP methods             |
| `allow_headers`     | `Array<String>` | Allowed request headers          |
| `expose_headers`    | `Array<String>` | Headers exposed to the client    |
| `allow_credentials` | `Boolean`       | Allow credentials                |
| `max_age`           | `Duration`      | Preflight cache duration         |
| `exclude_paths`     | `Array`         | Glob paths skipped               |

CORS preflight is processed during `on_request` and answered by the gateway.

---

## Security Headers (helmet)

Helmet adds HTTP security headers to responses. It is configured with a **target** (`web` or
`api`) and a **level** (`standard`, `strict` or `disabled`). Routes without a helmet policy use
`web` / `standard`. Headers the upstream already set are kept.

```hcl
policy helmet "api-strict" {
    target = "api"
    level  = "strict"
}
```

### Headers by profile

Every response, even with `level = "disabled"`:

```http
X-Content-Type-Options: nosniff
```

Unless disabled, every response also gets:

```http
Cross-Origin-Resource-Policy: same-origin
```

`api` + `strict` adds:

```http
Referrer-Policy: no-referrer
```

`web` adds the browser headers only to documents (`text/html`, `application/xhtml+xml`,
`image/svg+xml`), where they have an effect:

| Header                         | `standard`                        | `strict`       |
| ------------------------------ | --------------------------------- | -------------- |
| `Cross-Origin-Opener-Policy`   | `same-origin`                     | `same-origin`  |
| `Origin-Agent-Cluster`         | `?1`                              | `?1`           |
| `X-DNS-Prefetch-Control`       | `off`                             | `off`          |
| `X-Frame-Options`              | `SAMEORIGIN`                      | `DENY`         |
| `Referrer-Policy`              | `strict-origin-when-cross-origin` | `no-referrer`  |
| `Cross-Origin-Embedder-Policy` | —                                 | `require-corp` |

> **Recommendation:** for the strict profiles, send a **Content-Security-Policy** tailored to
> the application from the application itself.

## Assigning to Routes

```hcl
path "/api/*" {
    backend = upstream("api")
    policies {
        cors   = "default"
        helmet = "api-strict"                               # a named policy
    }
}

path "/docs/*" {
    backend = upstream("docs")
    policies {
        helmet extends "api-strict" { level = "standard" }  # a named policy with overrides
    }
}

path "/legacy/*" {
    backend = upstream("legacy")
    policies {
        helmet = off                                        # only X-Content-Type-Options
    }
}
```

Inside a `host` block, a `match` can replace the host's helmet policy or turn it `off` the same way.

## Next Steps

- [Authentication](/authentication)
- [WAF](/waf)
- [Configuration Reference](/configuration)
