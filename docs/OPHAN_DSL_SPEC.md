# OPHAN CONFIGURATION REFERENCE MANUAL (v0.1.0) (DEV)

This document defines the syntax, semantic rules, business constraints, and configuration model for **Ophan Api Gateway**.

Ophan is designed with a **secure-by-default** architecture. Every configuration directive exists either to orchestrate gateway behavior or to explicitly and surgically relax specific protections when operationally required.

---

# 1. GLOBAL RULES AND NAMING CONVENTIONS

To ensure parser consistency and deterministic behavior, all identifiers inside configuration files must follow these strict rules.

---

## 1.1 Identifier Naming Rules

All named entities must use:

- lowercase only
- `kebab-case`
- `snake_case`

### Valid Examples

```hcl
"edge-gateway-prod"
"oauth_core"
"waf-hardened"
```

### Invalid Examples

```hcl
"EdgeGateway"
"oauth core"
"MyPolicy"
```

---

## 1.2 Statement Terminators

Ophan accepts either:

- a newline
- a comma `,`

Both are treated identically by the parser.

### Example

```hcl
address = "0.0.0.0:443"
protocols = ["http1", "http2"]
```

Equivalent to:

```hcl
address = "0.0.0.0:443",
protocols = ["http1", "http2"],
```

---

## 1.3 Comments

Any line beginning with `#` is ignored.

```hcl
# This is a comment
```

---

# 2. TYPE SYSTEM AND LITERAL FORMATS

Ophan automatically infers native types from literal suffixes.

Do not wrap durations or memory sizes in quotes.

---

# 2.1 Primitive Types

| Type       | Description          | Example                |
| ---------- | -------------------- | ---------------------- |
| `String`   | UTF-8 text value     | `"hello"`              |
| `Boolean`  | True or false        | `true`                 |
| `Integer`  | Signed integer       | `42`                   |
| `Float`    | Decimal number       | `0.75`                 |
| `Array<T>` | Ordered collection   | `["GET", "POST"]`      |
| `Map<K,V>` | Inline key-value map | `{ path = "/health" }` |

---

# 2.2 Duration

Represents a time interval.

## Syntax

```text
<number><unit>
```

## Supported Units

| Unit | Meaning      |
| ---- | ------------ |
| `ms` | milliseconds |
| `s`  | seconds      |
| `m`  | minutes      |
| `h`  | hours        |

## Examples

```hcl
250ms
15s
10m
2h
```

---

# 2.3 Size

Represents a memory or payload size.

## Syntax

```text
<number><unit>
```

## Supported Units

| Unit | Meaning   |
| ---- | --------- |
| `b`  | bytes     |
| `kb` | kilobytes |
| `mb` | megabytes |
| `gb` | gigabytes |

## Examples

```hcl
512kb
10mb
2gb
```

---

# 2.4 Address

Represents a network endpoint.

Supports three formats.

---

## TCP/IP Address

```hcl
"0.0.0.0:443"
"localhost:8080"
```

---

## UNIX Domain Socket (UDS)

Must begin with the `unix:` prefix.

```hcl
"unix:/var/run/ophan.sock"
```

---

## Plain Hostname

Used for HTTP host matching.

```hcl
"api.example.me"
```

---

# 2.5 Union Types

Some directives support multiple possible shapes.

These are represented as union types.

Example:

```text
String | Object | Array<Object>
```

This means the field accepts any of the listed forms.

---

# 3. RESERVED KEYWORDS

These keywords are reserved internally by the Ophan parser and cannot be used as identifiers.

| Category        | Reserved Keywords                                 |
| --------------- | ------------------------------------------------- |
| Root Containers | `listeners`, `upstreams`, `routes`, `policies`    |
| Declarations    | `listener`, `upstream`, `route`, `policy`, `rule` |
| Backend Targets | `static`, `backend`                               |
| Infrastructure  | `extends`, `server`, `ssl`, `refresh`, `sources`  |
| Policy Types    | `auth`, `waf`, `cors`, `limiter`                  |

---

# 4. CONFIGURATION MODEL

---

# 4.1 listeners

Defines physical ingress points into the gateway.

---

## listener "<NAME>"

### Properties

| Property    | Type            | Required | Description                 |
| ----------- | --------------- | -------- | --------------------------- |
| `address`   | `Address`       | Yes      | Bind address or UNIX socket |
| `protocols` | `Array<String>` | Yes      | Supported protocols         |
| `ssl`       | `Block`         | No       | Enables TLS                 |

---

## Supported Protocols

| Value     |
| --------- |
| `"http1"` |
| `"http2"` |
| `"grpc"`  |

---

## ssl Block

| Property | Type     | Required | Description                         |
| -------- | -------- | -------- | ----------------------------------- |
| `cert`   | `String` | Yes      | Absolute path to `.pem` certificate |
| `key`    | `String` | Yes      | Absolute path to `.pem` private key |

---

## Example

```hcl
listener "ingress-secure" {
    address = "0.0.0.0:443"

    protocols = [
        "http1",
        "http2"
    ]

    ssl {
        cert = "/etc/certs/fullchain.pem"
        key  = "/etc/certs/privkey.pem"
    }
}
```

---

# 4.2 upstreams

Defines backend server clusters.

---

## upstream "<NAME>"

### Properties

| Property       | Type                                | Required | Description              |
| -------------- | ----------------------------------- | -------- | ------------------------ |
| `load_balance` | `String`                            | No       | Load balancing strategy  |
| `servers`      | `String \| Object \| Array<Object>` | Yes      | Backend targets          |
| `health_check` | `Object`                            | No       | Active health monitoring |

---

## Load Balancing Algorithms

| Algorithm             |
| --------------------- |
| `"round_robin"`       |
| `"least_connections"` |
| `"ip_hash"`           |
| `"random"`            |

Default:

```text
least_connections
```

---

## servers Union Type

The `servers` field supports three distinct forms.

---

### Variant 1 — Simple String

```hcl
servers = "localhost:4040"
```

---

### Variant 2 — Inline Object

```hcl
servers = {
    endpoint = "10.0.0.5:80"
    weight   = 50
}
```

---

### Variant 3 — Array of Objects

```hcl
servers = [
    {
        endpoint = "srv-1.internal:8080"
        weight   = 100
    },

    {
        endpoint = "srv-2.internal:8080"
        weight   = 50
        protocol = "http2"
    }
]
```

---

## Server Object Schema

| Field      | Type      | Required | Description           |
| ---------- | --------- | -------- | --------------------- |
| `endpoint` | `Address` | Yes      | Backend target        |
| `weight`   | `Integer` | No       | Load balancing weight |
| `protocol` | `String`  | No       | Upstream protocol     |

---

## health_check Schema

| Field                 | Type       |
| --------------------- | ---------- |
| `path`                | `String`   |
| `interval`            | `Duration` |
| `timeout`             | `Duration` |
| `unhealthy_threshold` | `Integer`  |
| `healthy_threshold`   | `Integer`  |

---

# 4.3 routes

Defines request routing behavior.

---

## route "<PATH_PATTERN>"

### Properties

| Property  | Type                 | Required | Description          |
| --------- | -------------------- | -------- | -------------------- |
| `hosts`   | `Array<String>`      | No       | Host header filter   |
| `methods` | `Array<String>`      | No       | Allowed HTTP methods |
| `rewrite` | `Map<String,String>` | No       | URL rewrite rules    |
| `backend` | `BackendTarget`      | Yes      | Route destination    |

---

## Backend Target Types

A route may define only one backend target.

Declaring multiple backend targets is invalid.

---

## upstream() Backend

```hcl
backend = upstream("api-cluster")
```

---

## static Backend

Transforms the route into a local static file server.

### Properties

| Property   | Type            | Description              |
| ---------- | --------------- | ------------------------ |
| `root`     | `String`        | Public root directory    |
| `listing`  | `Boolean`       | Enable directory listing |
| `dotfiles` | `Boolean`       | Allow hidden files       |
| `disallow` | `Array<String>` | Glob block patterns      |

---

## Example

```hcl
backend = static {
    root     = "/var/www/public"
    listing  = false
    dotfiles = false

    disallow = [
        "/config/*"
    ]
}
```

---

# 4.4 policies

Defines reusable security policies.

Policies are globally declared and may be:

- directly assigned
- extended
- locally defined

---

# 4.4.1 Direct Assignment

Uses the policy exactly as declared.

```hcl
auth = "oauth-core"
```

---

# 4.4.2 extends Inheritance

Clones and overrides specific fields.

```hcl
waf extends "waf-hardened" {
    max_body_size = 100mb
}
```

---

# 4.4.3 Local Inline Policy

Defines a route-local policy.

```hcl
headers {
    add = {
        "X-Forwarded-By" = "Ophan"
    }
}
```

---

# 5. POLICY CATALOG

---

# 5.1 policy auth

JWT and identity validation.

---

## Schema

| Property   | Type       |
| ---------- | ---------- |
| `issuer`   | `String`   |
| `jwks_uri` | `String`   |
| `jwks_ttl` | `Duration` |

---

## sources Block

Defines where access tokens are extracted from.

Supports:

- `header`
- `cookie`
- `query`

---

## header Source

| Property | Type     |
| -------- | -------- |
| `name`   | `String` |
| `prefix` | `String` |

---

## cookie Source

| Property | Type     |
| -------- | -------- |
| `name`   | `String` |

---

# 5.2 policy waf

Application firewall.

---

## Schema

| Property            | Type      |
| ------------------- | --------- |
| `enabled`           | `Boolean` |
| `mode`              | `String`  |
| `max_body_size`     | `Size`    |
| `anomaly_threshold` | `Integer` |

---

## Modes

| Mode               | Description        |
| ------------------ | ------------------ |
| `"blocking"`       | Active blocking    |
| `"detection_only"` | Audit/logging only |

---

# 5.3 policy cors

Cross-Origin Resource Sharing.

| Property            | Type            |
| ------------------- | --------------- |
| `allow_origin`      | `Array<String>` |
| `allow_methods`     | `Array<String>` |
| `allow_headers`     | `Array<String>` |
| `allow_credentials` | `Boolean`       |
| `max_age`           | `Duration`      |

---

# 5.4 policy limiter

Traffic shaping and rate limiting.

| Property     | Type     |
| ------------ | -------- |
| `rate`       | `String` |
| `identifier` | `String` |

---

## Rate Format

```text
<requests>/<unit>
```

Examples:

```hcl
10/s
500/m
10000/h
```

---

# 6. MAIN CONFIGURATION FILE

```hcl
master "ophan-01" {
    user    = "www-data"
    workers = "auto"

    pid = "/run/ophan.pid"

    error_log = "/var/log/ophan/error.log"

    includes = "/etc/ophan/gateways/*.conf"
}
```

---

# 7. COMPLETE PRODUCTION CONFIGURATION EXAMPLE

```hcl
name = "edge-gateway-prod"

listeners {
    listener "ingress-secure" {
        address = "0.0.0.0:443"

        protocols = [
            "http1",
            "http2"
        ]

        ssl {
            cert = "/etc/ophan/certs/cert.pem"
            key  = "/etc/ophan/certs/key.pem"
        }
    }
}

upstreams {
    upstream "api-main-cluster" {
        load_balance = "least_connections"

        servers = [
            {
                endpoint = "10.0.1.10:4040"
                weight   = 100
            },

            {
                endpoint = "10.0.1.11:8080"
                weight   = 50
                protocol = "http2"
            }
        ]

        health_check = {
            path = "/healthz"
            interval = 10s
            timeout = 250ms
        }
    }
}

routes {
    route "/api/v1/*" {
        hosts = [
            "api.example.me"
        ]

        methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE"
        ]

        backend = upstream("api-main-cluster")

        policies {
            auth = "oauth-core"
            waf  = "waf-hardened"
        }
    }
}
```
