---
title: Backend Pools & Load Balancing
description: Define upstream clusters and balance traffic across servers
tags: ["upstreams"]
order: 500
---

Ophan distributes traffic across backend servers using configurable load balancing algorithms. Load balancing is a property of the **upstream**, not the route.

> **⚠️ In development** — Balancing strategies are being implemented.

---

## Minimal Upstream

```hcl
upstreams {
    upstream "api" {
        static_servers = ["127.1.0.2:8080"]
    }
}
```

## Full Upstream

```hcl
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            {
                address = "api-2:8080"
                weight  = 50
            }
        ]

        # Planned
        security {
            cert        = "/etc/certs/public.pem"
            key         = "/etc/certs/private.key"
            client_ca   = "/etc/certs/ca.pem"
            client_auth = "optional"
            versions    = ["TLS1.2", "TLS1.3"]
        }

        # Planned
        health_check {
            path                = "/health"
            interval            = "10s"
            timeout             = "2s"
            healthy_threshold   = 2
            unhealthy_threshold = 3
        }

        # Planned
        circuit_breaker {
            consecutive_failures   = 5
            ejection_time          = "30s"
            max_ejection_percent   = 50
        }
    }
}
```

## Balancing Strategies

| Strategy            | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `round_robin`       | Distributes requests sequentially across servers (default)  |
| `ip_hash`           | Routes requests from the same client IP to the same server  |
| `least_connections` | Sends requests to the server with fewest active connections |

| Strategy            | Type    | Adapts to load |
| ------------------- | ------- | -------------- |
| `round_robin`       | Static  | No             |
| `ip_hash`           | Static  | No             |
| `least_connections` | Dynamic | Yes            |

- Use **static** strategies when servers are similar and traffic is predictable.
- Use **dynamic** (`least_connections`) when request cost varies or capacity is uneven.

## Weighted Balancing

Servers can carry a weight to control traffic distribution. Higher weights receive proportionally more traffic:

```hcl
static_servers = [
    "srv-1:8080",
    { address = "srv-2:8080", weight = 50 },
    { address = "srv-3:8080", weight = 100 }
]
```

## Server List

`static_servers` accepts a list of plain addresses and/or objects:

| Variant         | Example                                   |
| --------------- | ----------------------------------------- |
| Plain address   | `"api-1:8080"`                            |
| Weighted object | `{ address = "api-2:8080", weight = 50 }` |

## Simple Upstream

For a single backend server:

```hcl
upstream "example" {
    static_servers = ["localhost:4040"]
}
```

## Circuit Breaking <span class="status-badge badge-planned">Planned</span>

```hcl
circuit_breaker {
    consecutive_failures = 5
    ejection_time        = "30s"
    max_ejection_percent = 50
}
```

Failures eject the server from the pool temporarily, protecting the cluster during outages.

## Next Steps

- [Service Discovery](/service-discovery)
- [Health Checks & Resiliency](/health-checks)
- [Configuration Reference](/configuration)
