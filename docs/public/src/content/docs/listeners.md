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

    # Connection access control (see Network Filtering)
    firewall {
        allow = ["10.0.0.0/8"]
        deny  = ["10.0.0.66/32"]
    }

    # Original client address behind an edge proxy
    trusted_proxies {
        allowed_ips    = ["173.245.48.0/20"]
        real_ip_header = "CF-Connecting-IP"
        on_untrusted   = "degrade"
    }

    limits {
        connections  = 100000   # planned, not enforced yet
        request_size = "10mb"   # larger bodies get 413
    }

    timeouts {
        idle      = "60s"       # downstream read/write timeout
        keepalive = "30s"       # idle time between requests (default 60s)
    }
}
```

`http2` in `protocols` enables HTTP/2 through ALPN on TLS listeners and h2c (prior
knowledge) on plaintext listeners. An HTTP/1 connection is recycled after 10,000 requests.

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
| `client_auth` | `String`   | No       | `required` (default when `client_ca` is set) or `none`; `optional` behaves as `none` |
| `client_ca`   | `String`   | No       | Path to the CA bundle for client certs |
| `ciphers`     | `Array`    | No       | Ignored; the suite follows `versions` |

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