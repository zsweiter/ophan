---
title: Quickstart
description: Write your first Ophan configuration and run the gateway
tags: ["getting-started"]
order: 2
---

This guide gets you from zero to a running gateway proxying requests to an upstream service.

> **Heads-up:** Ophan is in active development. Some features are planned or in development — check the [Configuration Reference](/configuration) for status.

## Prerequisites

- A working Ophan binary — see [Installation](/installation)
- Basic understanding of reverse proxies and API gateways

## Minimal Configuration

Create a file named `ophan.conf`:

```hcl
name = "quickstart"

listeners {
    listener "http" {
        address   = "0.0.0.0:8080"
        protocols = ["http1", "http2"]
    }
}

upstreams {
    upstream "example" {
        static_servers = ["httpbin.org:80"]
    }
}

routes {
    path "/" {
        backend = upstream("example")
    }
}
```

## Run Ophan

```bash
ophan -c ophan.conf
```

The gateway starts on port `8080` and proxies requests to the upstream server.

```bash
curl http://localhost:8080/get
```

## Adding a Policy

Policies are declared globally and referenced by name from a route:

```hcl
routes {
    path "/api/*" {
        backend = upstream("example")
        policies {
            limiter = "api-limits"
        }
    }
}

policy limiter "api-limits" {
    rate = "100/s"
}
```

## What's Next

- Understand the [Core Model](/core-model): listeners, routes, policies, and upstreams
- Follow the [Request Lifecycle](/request-lifecycle) to see how a request flows
- Explore the full [Configuration Reference](/configuration)