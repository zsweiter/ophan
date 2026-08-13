---
title: Health Checks & Resiliency
description: Active health monitoring, thresholds, and circuit breaking
tags: ["upstreams"]
order: 502
---

Ophan monitors backend availability with active health checks. Unhealthy servers are removed from the load balancing pool; circuit breaking ejects them temporarily.

> **⚠️ In development** — Active health checks are being implemented; circuit breaking is planned.

---

## Configuration

Health checks are defined inside an upstream block:

```hcl
upstreams {
    upstream "api" {
        static_servers = [
            "10.0.1.10:4040",
            { address = "10.0.1.11:8080", weight = 50 }
        ]

        health_check {
            path                = "/health"   # omit for TCP-only checks
            interval            = "10s"
            timeout             = "2s"
            healthy_threshold   = 2
            unhealthy_threshold = 3
        }
    }
}
```

## Schema

| Field                | Type       | Description                                        |
| -------------------- | ---------- | -------------------------------------------------- |
| `path`               | `String`   | Health check endpoint (omit for TCP-only checks)   |
| `interval`           | `Duration` | How often to check                                 |
| `timeout`            | `Duration` | Request timeout                                    |
| `healthy_threshold`  | `Integer`  | Consecutive successes before marking healthy       |
| `unhealthy_threshold`| `Integer`  | Consecutive failures before marking unhealthy      |

## Behavior

- Servers failing health checks are excluded from load balancing
- Servers that recover are automatically re-added to the pool
- Health checks use HTTP GET requests to the configured path (or TCP connect when `path` is omitted)
- `on_finish` updates health state on every request

## Circuit Breaking <span class="status-badge badge-planned">Planned</span>

```hcl
circuit_breaker {
    consecutive_failures = 5
    ejection_time        = "30s"
    max_ejection_percent = 50
}
```

| Property              | Type      | Description                           |
| --------------------- | --------- | ------------------------------------- |
| `consecutive_failures`| `Integer` | Failures before ejection              |
| `ejection_time`       | `Duration`| How long a server is ejected          |
| `max_ejection_percent`| `Integer` | Max percentage of the pool to eject   |

## Next Steps

- [Backend Pools & Load Balancing](/load-balancing)
- [Service Discovery](/service-discovery)
- [Configuration Reference](/configuration)