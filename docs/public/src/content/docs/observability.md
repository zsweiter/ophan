---
title: Observability (Metrics & Logs)
description: Logging, metrics, and health endpoints
tags: ["operations"]
order: 700
---

Ophan provides observability for monitoring gateway health and traffic patterns.

> **⚠️ Partial** — Prometheus metrics and error logging are available; structured logs and tracing are on the roadmap.

---

## Logging

Error logs are configured in the main `master` block:

```hcl
master "ophan-01" {
    error_log = "/var/log/ophan/error.log"
}
```

## Metrics

Ophan exposes Prometheus metrics in the text exposition format. The endpoint is
disabled unless a `metrics` block is present in the `master` block:

```hcl
master "ophan-01" {
    metrics {
        listen = "127.0.0.1:9100"                # TCP address
        # listen = "unix:/run/ophan/metrics.sock" # or a Unix domain socket (Unix only)
        path   = "/metrics"                       # optional, defaults to /metrics
    }
}
```

| Property | Type     | Description                                                         |
| -------- | -------- | ------------------------------------------------------------------- |
| `listen` | `String` | `ip:port` or `unix:/path/to/socket`. Required.                      |
| `path`   | `String` | HTTP path that serves the metrics. Defaults to `/metrics`.          |

The endpoint runs as its own listener, separate from the gateway listeners, so it is
never exposed through a gateway route. Changing the `metrics` block on reload triggers
a graceful upgrade.

Scraping over a Unix socket with Prometheus requires a proxy or an agent that can read
from Unix sockets (for example the OpenTelemetry Collector or Grafana Alloy).

### Exported metrics

| Metric                              | Type      | Labels                                 |
| ----------------------------------- | --------- | -------------------------------------- |
| `ophan_requests_total`              | Counter   | `gateway`, `route`, `method`, `status` |
| `ophan_request_duration_seconds`    | Histogram | `gateway`, `route`                     |
| `ophan_policy_rejections_total`     | Counter   | `gateway`, `policy`                    |
| `ophan_upstream_requests_total`     | Counter   | `gateway`, `upstream`, `backend`       |
| `ophan_upstream_failures_total`     | Counter   | `gateway`, `upstream`, `backend`       |
| `ophan_upstream_active_requests`    | Gauge     | `gateway`, `upstream`, `backend`       |
| `ophan_upstream_healthy`            | Gauge     | `gateway`, `upstream`, `backend`       |
| `ophan_rate_limit_tracked_clients`  | Gauge     | `gateway`                              |
| `ophan_config_reloads_total`        | Counter   | `outcome`                              |

- `route` is the route path pattern as written in the configuration; requests that
  match no route use an empty value.
- `method` is one of the standard HTTP methods, or `OTHER`.
- `status` is the response status code, or `0` when the client went away before a
  response was written.
- `policy` is `rate_limit`, `auth`, or `other`.

## Request IDs

Every request gets an `X-Request-Id`. A client-supplied value is kept when it is at most 128
visible ASCII characters; otherwise a UUID v4 is generated. The id is forwarded to the
upstream and returned on every response, including error pages.

## Integrations

- Prometheus metrics export
- Structured JSON logging <span class="status-badge badge-planned">Planned</span>
- Distributed tracing (OpenTelemetry) <span class="status-badge badge-planned">Planned</span>
- Admin dashboard <span class="status-badge badge-planned">Planned</span>

## Health Endpoint

Ophan exposes health check endpoints for monitoring gateway status and load balancer integration.

## Runtime Signals

- **SIGHUP** — triggers a config reload (see [Deployment](/deployment))
- **PID file** — written to the path configured in `master { pid }`

## Next Steps

- [Deployment & Hot Reload](/deployment)
- [Configuration Reference](/configuration)