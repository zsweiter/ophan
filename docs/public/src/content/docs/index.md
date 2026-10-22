---
title: Ophan API Gateway
description: A lightweight, high-performance API gateway built on Cloudflare Pingora
tags: ["getting-started"]
order: 0
---

<!-- Hero -->
<section class="not-content hero-section">

# Ophan API Gateway

**A lightweight, high-performance API gateway** built on [Cloudflare Pingora](https://github.com/cloudflare/pingora).

Ophan combines **reverse proxy**, **API gateway**, **load balancer**, and **static content delivery** into a single modular platform.

> **Status:** Active development. APIs, configuration formats, and behavior may change without notice. Not recommended for production use yet.

<div class="hero-cta">
    <a href="/quickstart">Quickstart →</a>
    <a href="/installation">Installation</a>
</div>

</section>

---

## What is Ophan?

Ophan is an all-in-one edge platform that handles ingress traffic, enforces security policies, balances load across backends, and serves static content. It is designed for **simplicity**, **performance**, and **hot-reloadable configuration**.

Inspired by Envoy, Kong, Traefik, and NGINX, Ophan distills their capabilities into a single binary with a declarative configuration language (inspired by HCL) and a composable middleware pipeline.

> **Heads-up:** The documentation distinguishes between what is **implemented**, what is **in development**, and what is **planned**. See [Authorization Roadmap](/authorization) and [Contributing](/contributing) for the project status.

---

## Core Model

Ophan is built around four first-class entities:

| Entity        | Description                                       |
| ------------- | ------------------------------------------------- |
| **Listeners** | Physical ingress points (TCP, TLS, HTTP/2, gRPC)  |
| **Upstreams** | Backend pools with balancing and health checks    |
| **Routes**    | Path/host matching that ties requests to backends |
| **Policies**  | Reusable security & behavior (auth, waf, cors, …) |

See the [Core Model](/core-model) guide for a deep dive.

---

## Feature Status

<span class="badge-legend">
    <span class="status-badge badge-dev">In development</span> being actively built
    <span class="status-badge badge-planned">Planned</span> specified but not implemented yet
</span>

| Capability                     | Status                                                     |
| ------------------------------ | ---------------------------------------------------------- |
| HTTP/1.1, HTTP/2, WebSocket    | <span class="status-badge badge-dev">In development</span> |
| gRPC                           | <span class="status-badge badge-dev">In development</span> |
| Unix Domain Sockets            | <span class="status-badge badge-dev">In development</span> |
| TLS / mTLS                     | <span class="status-badge badge-dev">In development</span> |
| Network filtering (XDP)        | <span class="status-badge badge-dev">In development</span> |
| JWT / OAuth2 authentication    | <span class="status-badge badge-dev">In development</span> |
| WAF (OWASP anomaly scoring)    | <span class="status-badge badge-dev">In development</span> |
| Rate limiting                  | <span class="status-badge badge-dev">In development</span> |
| CORS & security headers        | <span class="status-badge badge-dev">In development</span> |
| Load balancing & health checks | <span class="status-badge badge-dev">In development</span> |
| Static file serving            | <span class="status-badge badge-dev">In development</span> |
| Dynamic service discovery      | <span class="status-badge badge-planned">Planned</span>    |
| RBAC / ABAC authorization      | <span class="status-badge badge-planned">Planned</span>    |

---

## Architecture at a Glance

```
Client Request
    ↓
Listener ─── TLS termination, protocol negotiation, L4 filtering
    ↓
Router ──── Path & host matching
    ↓
Policies ── Auth, WAF, rate limit, CORS, helmet
    ↓
Backend ─── Static files or upstream proxy
    ↓
Response
```

Every request flows through a predictable [Request Lifecycle](/request-lifecycle), where each stage is independently configurable and replaceable.

---

## ⚡ Performance Benchmark

Ophan is engineered for high-throughput, low-latency API proxying through four core design principles:

- **Zero-Copy Pipeline** — Minimal memory allocations along the critical path.
- **Lock-Free Hot Path** — Concurrent processing without thread contention.
- **Kernel-Level Dropping** — XDP/eBPF discards malicious traffic directly at the NIC (in development; the software firewall is used meanwhile).
- **Atomic Hot-Reload** — Zero-downtime updates without dropping active connections.

### Reverse proxy: Ophan vs NGINX vs Pingora

One route proxying to a Go HTTP backend that answers 3 bytes, on the same machine, with
64 keep-alive client connections. Each proxy is pinned to the same 4 CPU threads (2 physical
cores of an Intel i5-12500H laptop), the backend and the load generator ([`hey`](https://github.com/rakyll/hey))
to other cores. "CPU / request" is the proxy's own CPU time divided by the requests it served,
which does not depend on how fast the load generator is.

| Proxy                                                      | Requests/s | p50     | p99     | CPU / request | RSS      |
| ---------------------------------------------------------- | ---------- | ------- | ------- | ------------- | -------- |
| NGINX, upstream `keepalive`                                | 47,504     | 1.00 ms | 5.30 ms | 54 µs         | 24.5 MiB |
| NGINX, default `proxy_pass`                                | 23,828     | 2.50 ms | 6.00 ms | 153 µs        | 24.1 MiB |
| Pingora, minimal proxy                                     | 34,708     | 1.70 ms | 4.75 ms | 96 µs         | 25.1 MiB |
| **Ophan** (rate limit, rewrite, metrics, security headers) | 27,710     | 2.15 ms | 5.45 ms | 134 µs        | 28.8 MiB |

What the numbers say:

- With its default configuration, NGINX opens a new connection to the backend for every
  request; Ophan reuses upstream connections out of the box and is faster than that setup.
- NGINX configured with an upstream `keepalive` pool is the most efficient proxy for this
  minimal workload.
- Most of Ophan's cost is Pingora's own per-request cost; Ophan's routing, policies, metrics
  and headers add about 37 µs per request on top of it. Rate limiting and URL rewriting are
  below the measurement noise.

NGINX configuration used:

```nginx
upstream api { server 127.0.0.1:18081; keepalive 128; }   # omitted in the default run

server {
    listen 127.0.0.1:18080;
    location /api/ {
        proxy_pass http://api/;          # http://127.0.0.1:18081/ in the default run
        proxy_http_version 1.1;          # omitted in the default run
        proxy_set_header Connection "";  # omitted in the default run
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

These are loopback numbers with tiny responses, where per-request overhead dominates. With
real backends that take milliseconds, TLS to the upstream, or many upstreams, the proxy is a
much smaller share of the total.

---

## 🎯 Project Vision

| Principle             | Core Idea                                                                       |
| --------------------- | ------------------------------------------------------------------------------- |
| **Simplicity**        | Clean, HCL-inspired syntax — no complex YAML or XML configurations.             |
| **Performance**       | Sub-millisecond overhead on the hot path outperforming legacy proxies.          |
| **Memory Safe**       | Built in Rust — zero buffer overflows, use-after-free, or data races by design. |
| **Secure by Default** | Strict TLS defaults, secure headers, and zero trust pipeline out of the box.    |
| **Hot Reload**        | Apply runtime configuration updates without dropping active TCP connections.    |
| **Modularity**        | Fully decoupled architecture (Listeners, Routes, Policies, Upstreams).          |

---

## Next Steps

| Guide                                     | What you'll learn                           |
| ----------------------------------------- | ------------------------------------------- |
| [Quickstart](/quickstart)                 | Minimal configuration and first run         |
| [Installation](/installation)             | Install on Linux, macOS, Windows, or Docker |
| [Core Model](/core-model)                 | Listeners, routes, policies, upstreams      |
| [Configuration Reference](/configuration) | Full schema spec                            |

---

## License

MIT — see the repository for details.
