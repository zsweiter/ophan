---
title: Observability (Metrics & Logs)
description: Logging, metrics, and health endpoints
tags: ["operations"]
order: 700
---

Ophan provides observability for monitoring gateway health and traffic patterns.

> **⚠️ Planned** — Most observability features are on the roadmap. Error logging is partially available.

---

## Logging

Error logs are configured in the main `master` block:

```hcl
master "ophan-01" {
    error_log = "/var/log/ophan/error.log"
}
```

## Metrics

Planned metrics include:

- Request rate, latency, and error rate
- Upstream health and response time
- Active connection monitoring
- Cache hit/miss ratios
- Rate limit counter metrics

## Integrations <span class="status-badge badge-planned">Planned</span>

- Prometheus metrics export
- Structured JSON logging
- Distributed tracing (OpenTelemetry)
- Admin dashboard

## Health Endpoint

Ophan exposes health check endpoints for monitoring gateway status and load balancer integration.

## Runtime Signals

- **SIGHUP** — triggers a config reload (see [Deployment](/deployment))
- **PID file** — written to the path configured in `master { pid }`

## Next Steps

- [Deployment & Hot Reload](/deployment)
- [Configuration Reference](/configuration)