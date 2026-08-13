---
title: Core Model
description: Listeners, routes, policies, and upstreams — the four pillars of Ophan
tags: ["architecture"]
order: 100
---

Ophan is built around four first-class entities: **listeners**, **routes**, **policies**, and **upstreams**. Everything else in the configuration composes around them.

```
tls
listeners ── physical ingress points
upstreams ── backend pools
routes ───── request routing
policies ── reusable security & behavior
```

---

## Listeners

A listener defines a physical ingress point: a TCP address, a set of protocols, and optional TLS. Optional `network_policy` filtering can be applied at the L4 layer.

```hcl
listeners {
    listener "ingress-https" {
        address    = "0.0.0.0:443"
        protocols  = ["http1", "http2"]

        tls {
            cert = "/etc/certs/public.pem"
            key  = "/etc/certs/private.key"
        }
    }
}
```

See [Listeners & TLS/mTLS](/listeners) and [Network Filtering](/network-filtering).

---

## Upstreams

An upstream is a backend pool. It owns load balancing, health checks, and resiliency — these are properties of the **upstream**, not the route.

```hcl
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            { address = "api-2:8080", weight = 50 }
        ]
    }
}
```

See [Backend Pools & Load Balancing](/load-balancing).

---

## Routes

A route matches requests by path and hosts and forwards them to a backend. Routes can also attach policies and rewriting.

```hcl
routes {
    path "/api/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        backend = upstream("api")

        policies {
            auth    = "default"
            limiter = "api-limits"
        }
    }
}
```

See [Routing & Rewriting](/routing).

---

## Policies

Policies are reusable security and behavior definitions. They are declared globally and referenced (or extended) from routes.

```hcl
policy auth "default" {
    issuer   = "https://auth.example.com"
    audience = "api"
}

policy limiter "api-limits" {
    rate = "100/s"
}
```

A route can use a policy directly, extend it to override specific fields, or define one inline:

```hcl
policies {
    auth extends "default" {
        sources {
            cookie { name = "access_token" }
        }
    }
}
```

Policy types: `auth`, `waf`, `limiter`, `cors`, `helmet`. See the [Security & Policies](/authentication) section.

---

## Top-Level Structure

```hcl
name = "edge-gateway-prod"   # gateway name

listeners {
    # listener blocks
}

upstreams {
    # upstream blocks
}

routes {
    # path blocks
}

# global policy definitions
policy auth "default" { ... }
policy waf "waf-default" { ... }
```
---

## Design Principles

1. **Clear separation of concerns** — networking, routing, auth, and policies are independent concepts.
2. **Reusable policies** — define once, reference everywhere; override via `extends`.
3. **Dedicated upstreams** — load balancing and health are upstream properties.
4. **Composable pipeline** — the gateway behaves as a predictable middleware pipeline.

## Next Steps

- [Request Lifecycle](/request-lifecycle)
- [Configuration Reference](/configuration)