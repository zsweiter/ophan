---
title: Rate Limiting
description: Control traffic with per-IP or per-token rate limits
tags: ["security"]
order: 402
---

Ophan applies rate limits at the edge to protect upstream services and enforce quotas.

> **⚠️ In development** — The limiter is being implemented. Distributed strategies are planned.

---

## Minimal Policy

```hcl
policy limiter "default" {
    rate = "100/s"
}
```

## Full Policy

```hcl
policy limiter "default" {
    rate       = "100/s"
    burst      = 50
    identifier = "ip"                    # or "header:{name}", "token:{dotted json path}"
    strategy   = "sliding_window"        # or "fixed_window", "token_bucket"

    exclude_paths = [
        "/health",
    ]
}
```

## Schema

| Property        | Type      | Description                                       |
| --------------- | --------- | ------------------------------------------------- |
| `rate`          | `String`  | Rate in format `<requests>/<unit>`                |
| `burst`         | `Integer` | Allowance of burst requests over the rate         |
| `identifier`    | `String`  | Key: `ip`, `header:{name}`, `token:{dotted path}` |
| `strategy`      | `String`  | `sliding_window`, `fixed_window`, `token_bucket`  |
| `exclude_paths` | `Array`   | Glob paths skipped by the limiter                 |

## Rate Format

```
<requests>/<unit>
```

| Example   | Meaning                  |
| --------- | ------------------------ |
| `10/s`    | 10 requests per second   |
| `500/m`   | 500 requests per minute  |
| `10000/h` | 10,000 requests per hour |

## Identifiers

- `ip` — per client IP (honors trusted proxies)
- `header:{name}` — per value of a header (e.g. `header:X-Api-Key`)
- `token:{dotted json path}` — per value inside an authenticated token claim (e.g `token:user.plan`)

## Assigning to Routes

```hcl
path "/api/*" {
    backend = upstream("api")
    policies {
        limiter = "default"
    }
}
```

## Local Inline Policy

```hcl
path "/api/*" {
    backend = upstream("api")
    policies {
        limiter {
            rate = "50/m"
        }
    }
}
```

## Response Headers

The limiter exposes remaining quota via response headers (set in `prepare_response`):

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

## Next Steps

- [Authentication](/authentication)
- [WAF](/waf)
