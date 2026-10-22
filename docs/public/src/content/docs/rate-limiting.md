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

The limiter exposes remaining quota via response headers:

| Header                  | Value                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------- |
| `X-RateLimit-Limit`     | Requests per window (`rate + burst` for the token bucket)                               |
| `X-RateLimit-Remaining` | Requests left                                                                           |
| `X-RateLimit-Reset`     | Seconds until the quota is fully restored; on a `429`, seconds until the next request is allowed |
| `Retry-After`           | Sent with `429`, same value as `X-RateLimit-Reset`                                       |

Counters are kept per policy: routes that reference the same named policy share them, and a
reload keeps them unless the policy changes. Each gateway tracks up to about one million
clients; beyond that, new clients share an overflow bucket until idle entries are evicted
(every 10 seconds).

## Next Steps

- [Authentication](/authentication)
- [WAF](/waf)
