---
title: Architecture
description: System design and core components of the Ophan gateway
tags: ["architecture"]
order: 99
---

Ophan is a single binary that combines traffic routing, security, and observability into a declarative, config-driven gateway. This page describes the high-level architecture and the components behind it.

---

## Design Goals

- **Single binary** — no external dependencies, easy to deploy
- **Declarative configuration** — a language inspired by HCL, hot-reloadable without dropping connections
- **Layered security** — filtering at both L4 (kernel/XDP) and L7 (policies)
- **Composable pipeline** — every request flows through a predictable middleware pipeline

## Component Overview

Ophan is built as a workspace of focused libraries:

| Component      | Responsibility                                  |
| -------------- | ----------------------------------------------- |
| `ophan-router` | Configuration parsing, route matching, pipeline |
| `ophan-net`    | Networking, connections, HTTP protocol handling |
| `ophan-bpf`    | Kernel-level L4 filtering via eBPF/XDP          |
| `ophan-sec`    | WAF engine, anomaly scoring, reputation         |
| `ophan-auth`   | Token validation (JWT, OAuth2, HMAC, OIDC)      |
| `ophan-static` | Static file serving from the filesystem         |

Each library is independently testable; the gateway binary assembles them behind a single configuration.

## Layered Architecture

```text
                 ┌─────────────────────────────────────────┐
 Client ────────►│ L3/L4 Packet Filtering                  │  ophan-bpf / ophan-sec
                 │       (XDP / Software Fallback)         │
                 ├─────────────────────────────────────────┤
                 │ Listener & TLS / mTLS Termination       │  ophan-net
                 ├─────────────────────────────────────────┤
                 │ Route Matching                          │  ophan-router
                 │       (Host & Path matching)            │
                 ├─────────────────────────────────────────┤
                 │ Middleware Pipeline                     │  ophan / ophan-auth
                 │       (CORS → WAF → Auth → Limiter)     │
                 ├─────────────────────────────────────────┤
                 │ Request Rewriting                       │  ophan
                 │       (URL & Header mutation)           │
                 ├─────────────────────────────────────────┤
                 │ Upstream Dispatch & Load Balancing      │  ophan-net / ophan-static
                 │       (or Static File Serving)          │
                 └─────────────────────────────────────────┘
                                      │
                                      ▼
                               [ Upstream Target ]
                                      │
                                      ▼ (Response Path)
                ┌─────────────────────────────────────────┐
 Client ◄────── │ Response Header Rewrite & Compression   │  ophan / ophan-router
                │       (TLS Encryption & Flush)          │  ophan-net
                └─────────────────────────────────────────┘
```

### Layer 4 — Network Filtering

Before any TLS termination, traffic can be filtered in-kernel via eBPF/XDP:

- EtherType classification and per-listener lookup using LPM tries
- `ALLOW` / `DENY` defaults with explicit per-port rules
- A planned feedback loop promotes malicious L7 clients into the L4 blocklist

See [Network Filtering](/network-filtering).

### Layer 4/7 — Listeners & TLS

Listeners are the physical ingress points. They define protocols, TLS/mTLS, and IP policies:

- HTTP/1.1, HTTP/2, gRPC, and WebSocket protocol support
- TLS with version pinning and optional mutual TLS
- IP allow/deny ranges and trusted-proxy resolution

See [Listeners & TLS/mTLS](/listeners).

### Layer 7 — Policy Pipeline

Each request flows through a configurable middleware pipeline. Policies are reusable definitions that attach to routes:

| Policy    | Layer 7 concern     |
| --------- | ------------------- |
| `auth`    | Token validation    |
| `waf`     | Attack detection    |
| `limiter` | Rate limiting       |
| `cors`    | Cross-origin policy |
| `helmet`  | Security headers    |

See [Security & Policies](/authentication) and [Request Lifecycle](/request-lifecycle).

### Routing & Backends

Routes match on path, host, and method, then forward to an upstream pool or serve static files. Headers can be rewritten at the edge.

See [Path & Header Matching](/routing) and [Backend Pools & Load Balancing](/load-balancing).

## Configuration-Driven

Everything is expressed in the Ophan configuration language (inspired by HCL). The gateway master process watches its configuration and supports atomic reload on `SIGHUP`.

See the [Configuration Reference](/configuration).

## Status

The architecture is being assembled incrementally. See the [Roadmap](/roadmap) for component status.

## Next Steps

- [Core Model](/core-model)
- [Request Lifecycle](/request-lifecycle)
- [Roadmap](/roadmap)
