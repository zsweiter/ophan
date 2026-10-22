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

| Mode              | Where it runs | When to use                                                             |
| ----------------- | ------------- | ----------------------------------------------------------------------- |
| **XDP / eBPF**    | In the kernel | Dedicated NICs, bare metal, privileged containers                       |
| **Software Mode** | User space    | Shared hosting, restricted containers, legacy kernels, unsupported NICs |

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

| EtherType       | Action                                                           |
| --------------- | ---------------------------------------------------------------- |
| `ARP`           | Always passed (required for L2 resolution)                       |
| `IPv4`          | Passed/dropped by `evaluate_ingress_v4`                          |
| `IPv6`          | Passed/dropped by `evaluate_ingress_v6`                          |
| `VLAN` / `QinQ` | Unwrapped (up to 2 nested tags) to find the real inner EtherType |
| Anything else   | Passed through unmodified                                        |

### Parse Safety

- Length checks on every header access
- IPv4: never assume `IHL = 20`, reject truncated headers, explicit fragment policy
- IPv6: walk extension headers with a hard hop limit (max 8); fragmented/ESP passed without port classification
- **Never treat "failed parsing" as an implicit allow**

---

## Configuration

Each listener has two independent blocks:

| Block             | Layer | Question it answers                        | Used by                       |
| ----------------- | ----- | ------------------------------------------ | ----------------------------- |
| `firewall`        | L4    | Who may open a connection to this listener | Connection acceptance         |
| `trusted_proxies` | L7    | Who the client is once connected           | Rate limiting, logs, upstream |

```hcl
listener "public" {
    address = "0.0.0.0:443"

    # Connection access control
    firewall {
        allow = []                     # empty = everyone
        deny  = ["203.0.113.0/24"]
    }

    # Original client address
    trusted_proxies {
        allowed_ips    = ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"]
        real_ip_header = "CF-Connecting-IP"
        on_untrusted   = "degrade"     # degrade | reject
    }
}
```

### `firewall`

Evaluated against the socket address, never against a header:

1. an address in `deny` is rejected;
2. if `allow` is not empty, only its networks get in;
3. everyone else gets in.

### `trusted_proxies`

`real_ip_header` is read **only** from peers in `allowed_ips`. Multi-hop headers
(`X-Forwarded-For`, `Forwarded`) are read from the right: trusted hops are skipped and the
first untrusted address is the client. Entries a client adds on the left are ignored.

| `on_untrusted`      | Peer in `allowed_ips`         | Any other peer                                  |
| ------------------- | ----------------------------- | ----------------------------------------------- |
| `degrade` (default) | Address from `real_ip_header` | Its socket address; the header is ignored       |
| `reject`            | Address from `real_ip_header` | Connection rejected, with or without the header |

Use `degrade` when the listener is reachable from the internet as well as through the edge;
use `reject` when only the edge (Cloudflare, a load balancer) should reach it.

### Unix socket listeners

A Unix socket has no peer address. Access is restricted with the socket file mode, and the
client address always comes from the header:

```hcl
listener "tunnel" {
    address     = "unix:/run/ophan/edge.sock"
    permissions = "0660"

    trusted_proxies {
        real_ip_header = "CF-Connecting-IP"   # required
    }
}
```

A request without a valid `real_ip_header` gets `400`.

### Validation

These configurations are rejected when the configuration is loaded:

- `real_ip_header` without `allowed_ips` on a TCP listener (the header would never be read);
- `on_untrusted = "reject"` without `allowed_ips` (every connection would be rejected);
- `0.0.0.0/0` or `::/0` in `allowed_ips` (anyone could forge the client address);
- a Unix socket listener without `real_ip_header`, or with `firewall` or `allowed_ips`;
- `permissions` on a TCP listener;
- two listeners with the same `address`.

### Where the rules are enforced

| Listener     | `firewall` and `on_untrusted = "reject"`                           |
| ------------ | ------------------------------------------------------------------ |
| TCP with TLS | After accept, before the TLS handshake (the connection is dropped) |
| Plain TCP    | When each request arrives (`403`)                                  |
| Unix socket  | Not applicable; use `permissions`                                  |

A listener is identified by its full `address`. A connection is matched to the listener bound
to its local address, or to the `0.0.0.0` / `[::]` listener on the same port. Rules follow
hot reloads.

### Headers sent to the upstream

| Header              | Value                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------- |
| `X-Forwarded-For`   | The peer address, appended to the received value only when the peer is a trusted proxy |
| `X-Real-IP`         | The resolved client address                                                            |
| `X-Forwarded-Proto` | `https` or `http` (kept from a trusted proxy)                                          |
| `X-Forwarded-Host`  | The original `Host` (kept from a trusted proxy)                                        |
| `X-Request-Id`      | The request id (see [Observability](/observability))                                   |

### Deprecated `network_policy`

The previous `network_policy` block is still accepted with a warning and maps to the new blocks:

| `network_policy`                          | New                                    |
| ----------------------------------------- | -------------------------------------- |
| `allowed_ip_ranges` / `blocked_ip_ranges` | `firewall.allow` / `firewall.deny`     |
| `proxy_allowed_ips`                       | `trusted_proxies.allowed_ips`          |
| `real_ip_header`                          | `trusted_proxies.real_ip_header`       |
| `policy = "degrade" \| "deny"`            | `on_untrusted = "degrade" \| "reject"` |

It cannot be combined with `firewall` or `trusted_proxies` in the same listener, and it is
not accepted at gateway level.

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
