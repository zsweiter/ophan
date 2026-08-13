---
title: Network Filtering (XDP & Software Mode)
description: Layer 4 traffic filtering with eBPF/XDP and a user-space fallback
tags: ["ingress"]
order: 201
---

Ophan filters traffic at **Layer 4** (before TLS termination and HTTP parsing) to drop malicious traffic as early and cheaply as possible.

> **⚠️ In development** — The XDP program and software-mode filter are actively being built.

---

## Two Execution Modes

| Mode            | Where it runs | When to use                                |
| --------------- | ------------- | ------------------------------------------ |
| **XDP / eBPF**  | In the kernel | Dedicated NICs, bare metal, privileged containers |
| **Software Mode** | User space | Shared hosting, restricted containers, legacy kernels, unsupported NICs |

### XDP / eBPF

The preferred model executes directly inside the network driver:

- Zero socket allocation
- Zero context switches
- Zero user-space wakeups
- Predictable latency

Typical structures: `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_LPM_TRIE`, LRU hash maps, per-CPU maps. Complexity stays constant for most operations.

### Software Mode

When XDP cannot be attached, traffic is accepted through the traditional kernel stack before inspection. Packet memory is handled via preallocated pools and ring buffers to reduce allocation overhead.

---

## Policy Model

Traffic targeting a monitored port is classified in three steps, all handled in-kernel:

1. **Listener lookup** — a map from destination port to its default `ListenerPolicy` (`ALLOW` pass / `DENY` drop).
2. **Per-port rule lookup** — LPM tries (`PORT_RULES_V4`, `PORT_RULES_V6`) store explicit `PASS`/`DROP` rules keyed by `port + client_ip/CIDR`.
3. **Fallback** — an explicit rule wins; otherwise the listener's `default_action` decides. Ports without a listener entry are passed.

```hcl
Packet
  → classify EtherType (IPv4, IPv6, VLAN/QinQ unwrap, ARP)
  → listener lookup by dst port
  → explicit per-port rule? (LPM trie)
  → listener default (ALLOW | DENY)
  → XDP_PASS | XDP_DROP
```

### Ethernet Frame Handling

| EtherType | Action |
| --------- | ------ |
| `ARP`     | Always passed (required for L2 resolution) |
| `IPv4`    | Passed/dropped by `evaluate_ingress_v4` |
| `IPv6`    | Passed/dropped by `evaluate_ingress_v6` |
| `VLAN` / `QinQ` | Unwrapped (up to 2 nested tags) to find the real inner EtherType |
| Anything else | Passed through unmodified |

### Parse Safety

- Length checks on every header access
- IPv4: never assume `IHL = 20`, reject truncated headers, explicit fragment policy
- IPv6: walk extension headers with a hard hop limit (max 8); fragmented/ESP passed without port classification
- **Never treat "failed parsing" as an implicit allow**

---

## Configuration

Filtering is configured per listener via `network_policy`:

```hcl
listener "ingress-https" {
    address   = "0.0.0.0:443"
    protocols = ["http1", "http2"]

    network_policy {
        allowed_ip_ranges = ["10.0.0.0/8"]
        blocked_ip_ranges = ["192.168.1.5/32"]
    }
}
```

### Trusting Proxy Headers

When the gateway sits behind a CDN or L4 load balancer (Cloudflare, Fastly, ALB), the network address seen at L4 belongs to the proxy, not the real client. Configure the trusted proxy ranges so Ophan can safely resolve the real client IP:

```hcl
network_policy {
    # Both rules are required when behind a proxy
    real_ip_header = "X-Forwarded-For"
    proxy_allowed_ips = [
        "173.245.48.0/20",
        "104.16.0.0/13",
        # ... your CDN's IP ranges
    ]
}
```

> **Security rule:** never add `0.0.0.0/0` to `proxy_allowed_ips`. Anyone could then forge `X-Forwarded-For` and bypass IP-based controls.

---

## Adaptive Reputation <span class="status-badge badge-planned">Planned</span>

Layer 7 intelligence (WAF) will feed back into Layer 4: when a client exceeds a risk threshold, its IP is promoted into an XDP map with a TTL, so subsequent packets are dropped in-kernel before they ever reach user space.

```hcl
HTTP Request → L7 Inspection → Reputation Score ≥ threshold
        → insert IP into eBPF map → future packets XDP_DROP
```

## Next Steps

- [Listeners & TLS/mTLS](/listeners)
- [WAF](/waf)
- [Configuration Reference](/configuration)