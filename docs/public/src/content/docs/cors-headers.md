---
title: CORS & Security Headers
description: Cross-origin policies and helmet security header profiles
tags: ["security"]
order: 403
---

Ophan handles Cross-Origin Resource Sharing and injects hardened security headers through the `cors` and `helmet` policies.

> **⚠️ In development** — CORS and helmet header injection are being implemented.

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

Helmet injects a hardened set of HTTP security headers. It is configured with a **target** (`api` or `web`) and a **level** (`disabled`, `standard`, `strict`).

```hcl
policy helmet "web-strict" {
    target = "web"
    level  = "strict"
}
```

### Profiles Matrix

| Target  | Standard                                                                                                                                                               | Strict                                                                                                               |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **API** | Headers tailored for JSON/REST APIs — isolates execution (`nosniff`, `COOP`, `CORP`, `Origin-Agent-Cluster`); excludes browser vectors like CSP and `X-Frame-Options`. | Adds stronger runtime isolation (`COEP: require-corp`) and a strict `Referrer-Policy`.                               |
| **Web** | Browser defaults — clickjacking & referrer protections (`X-Frame-Options: SAMEORIGIN`, `strict-origin-when-cross-origin`). CSP managed by the app.                     | Maximum browser hardening — `X-Frame-Options: DENY`, strict `COEP`, restrictive `Permissions-Policy`, `no-referrer`. |

### API Standard

```http
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
X-DNS-Prefetch-Control: off
X-Permitted-Cross-Domain-Policies: none
X-Download-Options: noopen
X-XSS-Protection: 0
```

### API Strict

Adds to the above:

```http
Cross-Origin-Embedder-Policy: require-corp
Referrer-Policy: no-referrer
```

### Web Strict

```http
X-Frame-Options: DENY
Cross-Origin-Embedder-Policy: require-corp
Referrer-Policy: no-referrer
Permissions-Policy: ...
```

> **Recommendation:** For the strict profiles, explicitly inject a tailored **Content-Security-Policy (CSP)** at the application level.

## Assigning to Routes

```hcl
path "/api/*" {
    backend = upstream("api")
    policies {
        cors   = "default"
        helmet = "web-strict"
    }
}
```

## Next Steps

- [Authentication](/authentication)
- [WAF](/waf)
- [Configuration Reference](/configuration)
