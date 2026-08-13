---
title: Service Discovery (Active & Passive)
description: Static servers, and planned active/passive discovery drivers
tags: ["upstreams"]
order: 501
---

Ophan currently supports **static** server lists. Active discovery (polling a registry/DNS) and passive discovery (external registration) are planned.

> **⚠️ Planned** — Active and passive discovery drivers are on the roadmap.

---

## Static Discovery

Backend servers are defined explicitly in the configuration:

```hcl
upstreams {
    upstream "api" {
        static_servers = [
            "10.0.1.10:4040",
            { address = "10.0.1.11:8080", weight = 50 }
        ]
    }
}
```

## Single Server

```hcl
upstream "example" {
    static_servers = ["localhost:4040"]
}
```

---

## Active Discovery <span class="status-badge badge-planned">Planned</span>

Ophan will poll a discovery source and refresh the server pool on an interval:

```hcl
upstream "api" {
    balance_strategy = "round_robin"

    discovery {
        driver           = "kubernetes"        # or "dns", "consul"
        dns              = "api.internal.company.com"
        refresh_interval = "15m"
    }
}
```

| Property          | Type     | Description                |
| ----------------- | -------- | -------------------------- |
| `driver`          | `String` | `kubernetes`, `dns`, `consul` |
| `dns`             | `String` | DNS name or discovery endpoint |
| `refresh_interval`| `Duration` | How often to refresh     |

## Passive Discovery <span class="status-badge badge-planned">Planned</span>

Servers register themselves with the gateway via a registry, optionally secured with mTLS or API keys:

```hcl
upstream "api" {
    registry {
        driver = "..."
        security "mtls" {
            cert = "/etc/certs/upstream/public.pem"
            key  = "/etc/certs/upstream/private.key"
            client_ca = "/etc/certs/upstream/ca.pem"
        }

        # security "api-key" {
        #     key  = "base64_secret_key"
        #     algo = "HMAC"   # RSA, Ed25519
        # }
    }
}
```

## Next Steps

- [Backend Pools & Load Balancing](/load-balancing)
- [Health Checks & Resiliency](/health-checks)
- [Configuration Reference](/configuration)