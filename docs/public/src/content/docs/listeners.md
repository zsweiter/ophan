---
title: Listeners & TLS/mTLS
description: Define ingress points, protocol negotiation, TLS, and mTLS
tags: ["ingress"]
order: 200
---

Listeners define the physical ingress points of the gateway: an address, the set of supported protocols, and optional TLS.

> **⚠️ In development** — TLS termination and mTLS are partially implemented. Cipher suites and connection limits are planned.

---

## Minimal Listener

```hcl
listeners {
    listener "ingress-http" {
        address = "0.0.0.0:8080"
    }
}
```

An HTTP listener with no `protocols` field defaults to `http1`.

## HTTPS Listener

```hcl
listener "ingress-https" {
    address    = "0.0.0.0:443"
    protocols  = ["http1", "http2"]

    tls {
        cert = "/etc/certs/public.pem"
        key  = "/etc/certs/private.key"
    }
}
```

TLS is **required** when the listener is served on port `443` or when using the `https`/`wss` protocols.

## Unix Domain Socket

```hcl
listener "ingress-unix" {
    address = "unix://run/process.sock"
}
```

UNIX sockets do not support TLS.

## Full Listener Block

```hcl
listener "public-https" {
    address   = "0.0.0.0:443"
    protocols = ["http1", "http2", "grpc", "websocket"]

    tls {
        cert        = "/etc/certs/public.pem"
        key         = "/etc/certs/private.key"
        versions    = ["TLS1.2", "TLS1.3"]
        client_auth = "optional"            # or "required"
        client_ca   = "/etc/certs/ca.pem"

        ciphers = ["TLS_AES_256_GCM_SHA384"]   # planned
    }

    # Optional L4 access control
    network_policy {
        allowed_ip_ranges = ["10.0.0.0/8"]
        blocked_ip_ranges = ["10.0.0.0/8"]
    }

    # Optional (planned)
    limits {
        connections  = 100000
        request_size = "10mb"
    }

    timeouts {
        idle      = "60s"
        keepalive = "30s"
    }
}
```

## Protocols

| Value         | Description                         | Status |
| ------------- | ----------------------------------- | ------ |
| `http1`       | HTTP/1.1                            | <span class="status-badge badge-dev">In development</span> |
| `http2`       | HTTP/2 (h2, h2c)                    | <span class="status-badge badge-dev">In development</span> |
| `websocket`   | WebSocket upgrade                   | <span class="status-badge badge-dev">In development</span> |
| `grpc`        | gRPC (HTTP/2 based)                 | <span class="status-badge badge-dev">In development</span> |
| `https` / `wss` | TLS-enabled aliases               | <span class="status-badge badge-dev">In development</span> |

## TLS Block

| Property      | Type       | Required | Description                        |
| ------------- | ---------- | -------- | ---------------------------------- |
| `cert`        | `String`   | Yes      | Absolute path to `.pem` cert       |
| `key`         | `String`   | Yes      | Absolute path to `.pem` private key |
| `versions`    | `Array`    | No       | `TLS1.2`, `TLS1.3`                 |
| `client_auth` | `String`   | No       | `optional` or `required` (mTLS)    |
| `client_ca`   | `String`   | No       | CA bundle for client certs         |
| `ciphers`     | `Array`    | No       | Cipher suites (planned)            |

## Mutual TLS (mTLS) <span class="status-badge badge-dev">In development</span>

mTLS provides mutual authentication where the client also presents a certificate:

```hcl
tls {
    cert        = "/etc/certs/public.pem"
    key         = "/etc/certs/private.key"
    client_auth = "required"
    client_ca   = "/etc/certs/ca.pem"
}
```

## Best Practices

- Store certificates outside the gateway root directory
- Use absolute paths for cert and key files
- Restrict permissions on private keys (`chmod 600`)
- Rotate certificates before expiration

## Next Steps

- [Network Filtering](/network-filtering) — L4 XDP & software filtering
- [Configuration Reference](/configuration)