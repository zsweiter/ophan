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
- **Kernel-Level Dropping** — XDP/eBPF discards malicious traffic directly at the NIC.
- **Atomic Hot-Reload** — Zero-downtime updates without dropping active connections.

### ⚔️ Direct Passthrough: Ophan vs NGINX

Tested under high concurrency (**300 active connections, 8 threads, 30s**) proxying directly to a single Go HTTP echo backend in raw passthrough mode.

| Metric              | NGINX (Passthrough) | Ophan (Passthrough) | Delta                |
| ------------------- | ------------------- | ------------------- | -------------------- |
| **Throughput**      | 15,509 req/s        | **20,029 req/s**    | 🚀 **+29.1% higher** |
| **Average Latency** | 19.30 ms            | **15.18 ms**        | ⚡ **-21.3% lower**  |
| **P50 Latency**     | 17.93 ms            | **13.86 ms**        | **-22.7%**           |
| **P75 Latency**     | 23.34 ms            | **18.83 ms**        | **-19.3%**           |
| **P90 Latency**     | 30.46 ms            | **24.67 ms**        | **-19.0%**           |
| **P99 Latency**     | 49.09 ms            | **44.04 ms**        | **-10.2%**           |
| **Total Processed** | 466,445 reqs        | **602,610 reqs**    | **+136,165 reqs**    |

#### Ophan Benchmark Log

```bash
wrk -t8 -c300 -d30s --latency http://api.example.me:8080/echo
Running 30s test @ http://api.example.me:8080/echo
  8 threads and 300 connections
  Thread Stats    Avg      Stdev      Max     +/- Stdev
    Latency     15.18ms    8.43ms  119.81ms    77.54%
    Req/Sec      2.52k   380.19      4.90k     80.43%

  Latency Distribution
     50%   13.86ms
     75%   18.83ms
     90%   24.67ms
     99%   44.04ms

  602,610 requests in 30.09s, 315.51MB read
Requests/sec:  20,029.34
Transfer/sec:     10.49MB

```

#### NGINX Benchmark Log

```bash
wrk -t8 -c300 -d30s --latency http://api.example.me/echo
Running 30s test @ http://api.example.me/echo
  8 threads and 300 connections
  Thread Stats    Avg      Stdev      Max     +/- Stdev
    Latency     19.30ms    8.97ms  108.64ms    74.67%
    Req/Sec      1.95k   151.10      2.58k     69.48%

  Latency Distribution
     50%   17.93ms
     75%   23.34ms
     90%   30.46ms
     99%   49.09ms

  466,445 requests in 30.08s, 136.12MB read
Requests/sec:  15,509.02
Transfer/sec:      4.53MB

```

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
