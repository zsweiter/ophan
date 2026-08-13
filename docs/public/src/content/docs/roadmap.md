---
title: Roadmap
description: Project status and what's coming next for Ophan
tags: ["project"]
order: 902
---

Ophan is early-stage and under active development. This page tracks what is implemented, what is in development, and what is planned.

> **Heads-up:** Feature status is also called out on every documentation page via status badges.

---

## Current Status

| Area                      | Status                                                     |
| ------------------------- | ---------------------------------------------------------- |
| Configuration & routing   | <span class="status-badge badge-dev">In development</span> |
| Listeners & TLS/mTLS      | <span class="status-badge badge-dev">In development</span> |
| Network filtering (XDP)   | <span class="status-badge badge-dev">In development</span> |
| Authentication            | <span class="status-badge badge-dev">In development</span> |
| WAF                       | <span class="status-badge badge-dev">In development</span> |
| Rate limiting             | <span class="status-badge badge-dev">In development</span> |
| CORS & security headers   | <span class="status-badge badge-dev">In development</span> |
| Static file serving       | <span class="status-badge badge-dev">In development</span> |
| Health checks             | <span class="status-badge badge-planned">Planned</span>    |
| Service discovery         | <span class="status-badge badge-planned">Planned</span>    |
| Observability             | <span class="status-badge badge-planned">Planned</span>    |
| Authorization (RBAC/ABAC) | <span class="status-badge badge-planned">Planned</span>    |

## What's In Development

- The configuration language (inspired by HCL) and hot reload (`SIGHUP`)
- Listener model with TLS/mTLS and network policies
- L4 filtering in XDP and software modes
- Policy pipeline: authentication, WAF, rate limiting, CORS, helmet
- Static file serving with hardened defaults

## What's Planned

| Feature           | Details                                      | See                                     |
| ----------------- | -------------------------------------------- | --------------------------------------- |
| Health checks     | Active probes, thresholds                    | [Health Checks](/health-checks)         |
| Circuit breaking  | Ejecting failing upstreams                   | [Load Balancing](/load-balancing)       |
| Service discovery | Active (DNS/K8s/Consul) & passive (registry) | [Service Discovery](/service-discovery) |
| Observability     | Metrics, structured logs, tracing            | [Observability](/observability)         |
| Authorization     | Fine-grained RBAC & ABAC                     | [Authorization Roadmap](/authorization) |
| Upstream security | mTLS between gateway and backends            | [Load Balancing](/load-balancing)       |
| WAF custom rules  | Declarative rule language                    | [WAF](/waf)                             |

## Feedback

Every piece of feedback helps shape the roadmap. Reach out at **zsweiter@gmail.com** or see [Contributing](/contributing).

## Next Steps

- [Authorization Roadmap](/authorization)
- [Contributing](/contributing)
