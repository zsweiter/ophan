---
title: Configuration Schema Spec
description: Complete reference of the Ophan configuration language, inspired by HCL
tags: ["reference"]
order: 800
---

Ophan uses a declarative configuration language **inspired by HCL**. It is not HCL — the syntax is similar, but Ophan implements its own parser and semantics. This is the complete schema reference.

> **⚠️ Work in progress** — The configuration language is under active development. Some blocks are planned. Syntax and behavior may change without notice.

---

## Global Rules

### Identifier Naming

Named entities use lowercase, `kebab-case`, or `snake_case`.

**Valid:** `edge-gateway-prod`, `oauth_core`, `waf-hardened`
**Invalid:** `EdgeGateway`, `oauth core`, `MyPolicy`

### Statement Terminators

Statements are terminated by a newline or a comma `,`. Both are identical.

### Comments

Lines beginning with `#` are ignored.

---

## Type System

Ophan infers native types from literal suffixes. Do not wrap durations or memory sizes in quotes.

### Primitives

| Type       | Description          | Example                |
| ---------- | -------------------- | ---------------------- |
| `String`   | UTF-8 text value     | `"hello"`              |
| `Boolean`  | True or false        | `true`                 |
| `Integer`  | Signed integer       | `42`                   |
| `Float`    | Decimal number       | `0.75`                 |
| `Array<T>` | Ordered collection   | `["GET", "POST"]`      |
| `Map<K,V>` | Inline key-value map | `{ path = "/health" }` |

### Duration

Format: `<number><unit>` — time value.

| Unit | Meaning     | Example |
| ---- | ----------- | ------- |
| `ms` | millisecond | `250ms` |
| `s`  | second      | `15s`   |
| `m`  | minute      | `10m`   |
| `h`  | hour        | `2h`    |

### Size

Format: `<number><unit>` — data size.

| Unit | Meaning  | Example |
| ---- | -------- | ------- |
| `b`  | byte     | `512b`  |
| `kb` | kilobyte | `512kb` |
| `mb` | megabyte | `10mb`  |
| `gb` | gigabyte | `2gb`   |

### Rate

Format: `<number>/<unit>` — number of requests per time unit.

| Example   | Meaning                  |
| --------- | ------------------------ |
| `10/s`    | 10 requests per second   |
| `500/m`   | 500 requests per minute  |
| `10000/h` | 10,000 requests per hour |

### Address

Three supported formats:

| Format         | Example                        | Use case           |
| -------------- | ------------------------------ | ------------------ |
| TCP/IP         | `"0.0.0.0:443"`                | Network bindings   |
| UNIX socket    | `"unix:///var/run/ophan.sock"` | Local IPC          |
| Plain hostname | `"api.example.me"`             | Backend references |

---

## Top-Level Blocks

| Block       | Description                   |
| ----------- | ----------------------------- |
| `name`      | Gateway name                  |
| `master`    | Process-level settings        |
| `listeners` | Physical ingress points       |
| `upstreams` | Backend server clusters       |
| `routes`    | Request routing rules         |
| `policy`    | Reusable security definitions |

---

## master

```hcl
master "ophan-01" {
    user      = "www-data"
    workers   = "auto"          # or a number
    pid       = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes  = "/etc/ophan/gateways/*.conf"
}
```

| Property    | Type     | Description                            |
| ----------- | -------- | -------------------------------------- |
| `user`      | `String` | Drop privileges to this user           |
| `workers`   | `String` | `"auto"` or an explicit count          |
| `pid`       | `String` | PID file path                          |
| `error_log` | `String` | Error log path                         |
| `includes`  | `String` | Additional config files end in \*.conf |

---

## listeners

### listener "<unique-name>"

```hcl
listeners {
    listener "public-https" {
        address   = "0.0.0.0:443"
        protocols = ["http1", "http2", "grpc", "websocket"]

        tls {
            cert        = "/etc/certs/public.pem"
            key         = "/etc/certs/private.key"
            versions    = ["TLS1.2", "TLS1.3"]
            client_auth = "optional"        # mTLS
            client_ca   = "/etc/certs/ca.pem"
            ciphers     = ["TLS_AES_256_GCM_SHA384"]   # planned
        }

        network_policy {
            allowed_ip_ranges = ["10.0.0.0/8"]
            blocked_ip_ranges = ["10.0.0.0/8"]
            real_ip_header    = "X-Forwarded-For"
            proxy_allowed_ips = ["173.245.48.0/20"]
        }

        limits {      # planned
            connections  = 100000
            request_size = "10mb"
        }

        timeouts {    # planned
            idle      = "60s"
            keepalive = "30s"
        }
    }
}
```

| Property         | Type            | Required | Description                                           |
| ---------------- | --------------- | -------- | ----------------------------------------------------- |
| `address`        | `Address`       | Yes      | Bind address or UNIX socket                           |
| `protocols`      | `Array<String>` | Yes      | `http1`, `http2`, `grpc`, `websocket`, `https`, `wss` |
| `tls`            | `Block`         | No       | TLS/mTLS (required on `:443`)                         |
| `network_policy` | `Block`         | No       | L4 IP filtering                                       |
| `limits`         | `Block`         | No       | Connection / size limits (planned)                    |
| `timeouts`       | `Block`         | No       | Idle / keepalive (planned)                            |

---

## upstreams

### upstream `"<unique-name>"`

```hcl
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            { address = "api-2:8080", weight = 50 }
        ]

        security { ... }        # planned — upstream TLS
        health_check { ... }    # planned
        circuit_breaker { ... } # planned
        discovery { ... }       # planned
        registry { ... }        # planned
    }
}
```

| Property           | Type     | Required | Description                                   |
| ------------------ | -------- | -------- | --------------------------------------------- |
| `balance_strategy` | `String` | No       | `round_robin`, `ip_hash`, `least_connections` |
| `static_servers`   | `Array`  | Yes      | Plain addresses and/or weighted objects       |

`static_servers` item variants:

| Variant         | Example                                   |
| --------------- | ----------------------------------------- |
| Plain address   | `"api-1:8080"`                            |
| Weighted object | `{ address = "api-2:8080", weight = 50 }` |

See [Load Balancing](/load-balancing) for `security`, `health_check`, `circuit_breaker`, `discovery`, and `registry` details.

---

## routes

### path `"<path-pattern>"`

```hcl
routes {
    path "/api/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        backend = upstream("api")

        static_config { ... }    # when backend is static

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
            waf   = "waf-default"
            cors  = "cors-default"
            limiter = "api-limits"
        }

        rewrite {
            strip_prefix "/api"
            replace "/v1/*" -> "/v2/$1"
        }

        inbound_headers {
            set   = { "X-Client-Layer" = "edge" }
            remove = ["X-Bad-Header"]
            to_upstream {
                set    = { "X-Forwarded-By" = "Ophan-Edge" }
                remove = ["Authorization"]
            }
        }

        outbound_headers {
            from_upstream { remove = ["X-Internal-Cluster-ID"] }
            set    = { "Cache-Control" = "no-store" }
            remove = ["Server", "X-Powered-By"]
        }
    }
}
```

| Property           | Type            | Required | Description                             |
| ------------------ | --------------- | -------- | --------------------------------------- |
| `hosts`            | `Array<String>` | No       | Host header filter                      |
| `methods`          | `Array<String>` | No       | Allowed HTTP methods                    |
| `backend`          | `BackendTarget` | Yes      | `upstream("name")` or `static("/path")` |
| `static_config`    | `Block`         | No       | Static serving options                  |
| `timeouts`         | `Block`         | No       | Connect/read/send                       |
| `streaming`        | `Block`         | No       | Buffering / chunked                     |
| `policies`         | `Block`         | No       | Policy references                       |
| `rewrite`          | `Block`         | No       | URL rewriting                           |
| `inbound_headers`  | `Block`         | No       | Request header transforms               |
| `outbound_headers` | `Block`         | No       | Response header transforms              |

### Backend Targets

```hcl
backend = upstream("api")          # forward to a pool
backend = static("/var/www/public")  # serve local files
```

A route must define **exactly one** backend target.

---

## policies

Policies are declared globally and referenced by name from routes. They may be used directly, extended, or defined inline.

```hcl
policy auth "default" {
    issuer   = "https://auth.example.com"
    audience = "api"
}

# Direct assignment
policies {
    auth = "default"
}

# Extends — clone and override specific fields
policies {
    auth extends "default" {
        sources {
            cookie { name = "access_token" }
        }
    }
}

# Local inline policy
policies {
    limiter {
        rate = "50/m"
    }
}
```

### policy auth

```hcl
policy auth "default" {
    issuer    = "https://auth.example.com"
    audience  = "api"
    client_id = "edge"

    mode "jwks" {
        uri        = "https://auth.example.com/.well-known/jwks.json"
        ttl        = "1h"
        algorithms = ["RS256", "ES256"]
    }

    dpop_proof = "required"

    sources {
        header { name = "Authorization", prefix = "Bearer " }
        cookie { name = "access_token" }
        query  { name = "access_token" }
    }

    exclude_paths = ["/health"]
}
```

See [Authentication](/authentication) for the full reference including `oidc` and `static` (HMAC) modes and `refresh`.

### policy waf

```hcl
policy waf "default" {
    mode              = "block"      # or "detection_only"
    ruleset           = "owasp"
    max_body_size     = "10mb"
    anomaly_threshold = 5
    exclude_paths     = ["/health"]
}
```

See [WAF](/waf) for custom `rule` blocks.

### policy limiter

```hcl
policy limiter "default" {
    rate       = "100/s"
    burst      = 50
    identifier = "ip"            # or "header:{name}", "token:{dotted path}"
    strategy   = "sliding_window"
    exclude_paths = ["/health"]
}
```

### policy cors

```hcl
policy cors "default" {
    allow_origins      = ["app.example.me"]
    allow_methods      = ["GET", "POST", "OPTIONS"]
    allow_headers      = ["Authorization"]
    expose_headers     = ["X-Request-Id"]
    allow_credentials  = true
    max_age            = "2h"
    exclude_paths      = ["/health"]
}
```

### policy helmet

```hcl
policy helmet "web-strict" {
    target = "web"   # or "api"
    level  = "strict" # or "disabled", "standard"
}
```

---

## Complete Example

```hcl
name = "edge-gateway-prod"

master "ophan-01" {
    user      = "www-data"
    workers   = "auto"
    pid       = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes  = "/etc/ophan/gateways/*.conf"
}

listeners {
    listener "ingress-https" {
        address    = "0.0.0.0:443"
        protocols  = ["http1", "http2"]

        tls {
            cert = "/etc/ophan/certs/cert.pem"
            key  = "/etc/ophan/certs/key.pem"
        }
    }
}

upstreams {
    upstream "api-main" {
        balance_strategy = "least_connections"
        static_servers = [
            "10.0.1.10:4040",
            { address = "10.0.1.11:8080", weight = 50 }
        ]

        health_check {
            path                = "/healthz"
            interval            = "10s"
            timeout             = "250ms"
            healthy_threshold   = 2
            unhealthy_threshold = 3
        }
    }
}

routes {
    path "/api/v1/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        backend = upstream("api-main")

        policies {
            auth  = "default"
            waf   = "waf-default"
            cors  = "cors-default"
        }

        rewrite {
            strip_prefix "/api"
        }
    }
}

policy auth "default" {
    issuer   = "https://auth.example.com"
    audience = "api"
}

policy waf "waf-default" {
    mode    = "block"
    ruleset = "owasp"
}

policy cors "cors-default" {
    allow_origins = ["https://app.example.com"]
}
```
