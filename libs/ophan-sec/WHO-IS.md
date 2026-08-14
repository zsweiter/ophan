# Comprehensive WAF Lifecycle Architecture

## From Layer 4 Packet Filtering to Layer 7 Application Inspection

> **Abstract**
>
> This document presents the architecture of a modern Web Application Firewall (WAF) designed around a layered execution model. Rather than treating Layer 4 and Layer 7 as isolated security domains, the architecture introduces a feedback mechanism in which application-layer intelligence continuously improves transport-layer filtering. The design emphasizes predictable CPU utilization, memory efficiency, and scalability through Rust's zero-cost abstractions, eBPF/XDP, and cache-friendly data structures. The objective is to minimize unnecessary work by terminating malicious traffic as early as possible while preserving complete Layer 7 inspection for legitimate requests.

---

# Table of Contents

1. Introduction
2. Architectural Principles
3. Deployment Models
4. Global Request Lifecycle
5. Layer 4 Processing
6. Layer 7 Processing
7. Adaptive Layer 4 Reputation Promotion
8. Rust Phase Model
9. Operational Matrix
10. References

---

# 1. Introduction

Traditional WAF implementations perform every inspection inside user space after the operating system has already accepted the TCP connection.

While this provides extensive visibility into HTTP traffic, it also means that every malicious request consumes operating system resources before a security decision can be made.

Modern Linux networking introduces technologies such as eBPF and XDP, allowing packet filtering to occur directly inside the network driver before socket allocation.

This architecture combines both approaches:

- Layer 4 performs extremely inexpensive binary decisions.
- Layer 7 performs deep protocol-aware inspection.
- Layer 7 continuously feeds intelligence back into Layer 4.

The result is a system that gradually learns which clients should never reach user space again.

---

# 2. Architectural Principles

The architecture follows five principles.

## Early Rejection

Traffic should be discarded as early as possible.

Every stage that successfully blocks a request prevents subsequent CPU and memory consumption.

---

## Layer Separation

Each execution phase has a clearly defined responsibility.

Network filtering never parses HTTP.

HTTP inspection never manipulates driver memory.

---

## Zero-Copy Processing

Whenever possible, packet buffers are referenced instead of copied.

Rust lifetimes are used to borrow slices directly from parsing buffers.

---

## Predictable Complexity

Algorithms with deterministic complexity are preferred.

Examples include:

- Hash tables
- Radix trees
- LPM tries
- Aho-Corasick automata
- Bloom filters

---

## Adaptive Reputation

Application intelligence continuously improves network filtering by promoting malicious clients into Layer 4 blocklists.

---

# 3. Deployment Models

The architecture supports two deployment models.

---

## Internet-Facing Deployment

```
                 Internet
                     │
                     ▼
              XDP / eBPF Program
                     │
                     ▼
                WAF Engine
                     │
                     ▼
                 Backend
```

The Layer 4 source address corresponds to the real client IP.

Every reputation decision is based directly on the network source address.

This deployment allows dynamic promotion of malicious clients into XDP maps.

---

## Reverse Proxy / CDN Deployment

```
             Internet
                  │
                  ▼
          Cloudflare / CDN
                  │
                  ▼
            WAF Layer 4
                  │
                  ▼
      Validate Proxy Whitelist
                  │
                  ▼
      Read Client IP Header
                  │
                  ▼
             Layer 7 Engine
```

In this deployment the Layer 4 address belongs to the reverse proxy infrastructure.

Only requests arriving from previously trusted proxy ranges are allowed to provide the real client address through standardized HTTP headers such as:

- CF-Connecting-IP
- True-Client-IP
- X-Forwarded-For

This is considered a deployment adaptation rather than a WAF feature.
With this deployment not support promoting ip to Layer 4, because trafic only acepted by your reverse proxy exposed to internet

---

# 4. Global Request Lifecycle

```text
                     Incoming Packet
                            │
                            ▼
               Layer 4 (XDP or Listener)
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
       Block immediately            Allow Connection
                                          │
                                          ▼
                               Layer 7 Connection Context
                                          │
                                          ▼
                             Resolve Real Client Identity
                                          │
                                          ▼
                          Early Reputation Evaluation
                                          │
                      ┌───────────────────┴─────────────────┐
                      │                                     │
                      ▼                                     ▼
                 Reject Request                     Continue Inspection
                                                          │
                                                          ▼
                                         Request Line / Headers / Body
                                                          │
                                                          ▼
                                                Reputation Score
                                                          │
                          ┌───────────────────────────────┴────────────────────────────┐
                          │                                                            │
                          ▼                                                            ▼
                  Forward to Backend                                  Promote IP to XDP Map
                                                                               │
                                                                               ▼
                                                            Future packets dropped at Layer 4
```

---

# 5. Layer 4 Processing

The objective of Layer 4 is making immediate binary decisions while consuming the smallest possible amount of CPU cycles.

No HTTP parsing occurs.

No TLS inspection occurs.

Only transport-level metadata is evaluated.

---

## Scenario A — XDP / eBPF

The preferred execution model executes directly inside the network driver.

Advantages include:

- zero socket allocation
- zero context switches
- zero user-space wakeups
- predictable latency

Typical structures:

- BPF_MAP_TYPE_HASH
- BPF_MAP_TYPE_LPM_TRIE
- LRU Hash Maps
- Per-CPU Maps

Complexity remains constant for most operations.

---

## Scenario B — User Space Listener

Some environments cannot attach XDP programs.

Examples include:

- shared hosting
- restricted containers
- legacy Linux distributions
- unsupported NIC drivers

Traffic is accepted through the traditional kernel stack before inspection.

To reduce allocation overhead, packet memory is handled through preallocated pools and ring buffers.

---

# 6. Layer 7 Processing

Once Layer 4 approves the connection, HTTP inspection begins.

Each phase has a specialized objective.

---

## Phase 1 — Connection Context

Responsibilities:

- deployment detection
- reverse proxy validation
- client IP resolution
- TLS metadata collection

---

## Phase 2 — Early Request Filter

Responsibilities:

- GeoIP
- reputation lookup
- bot intelligence
- behavioral scoring
- rate limiting

A request rejected here never reaches body inspection.

---

## Phase 3 — Request Line

Evaluates:

- HTTP method
- URI
- routing policies
- administrative endpoints

---

## Phase 4 — Request Headers

Inspects:

- User-Agent
- Cookies
- Authentication
- Protocol compliance

---

## Phase 5 — Request Body

Performs expensive inspection.

Examples include:

- SQL Injection
- Cross Site Scripting
- Path Traversal
- Remote Code Execution
- Command Injection

Aho-Corasick automata are used to keep complexity linear.

---

## Phase 6 — Response Headers

Removes implementation details.

Examples:

- Server
- X-Powered-By

---

## Phase 7 — Response Body

Implements outbound protection.

Examples include:

- PII detection
- Credit card masking
- API key leakage
- Token leakage

---

# 7. Adaptive Layer 4 Reputation Promotion

One of the architectural innovations of this design is the continuous feedback loop between Layer 7 and Layer 4.

Traditional WAFs repeatedly inspect the same malicious client because every request must traverse the complete networking stack.

Instead, this architecture promotes persistent attackers directly into the Layer 4 filtering engine.

---

## Reputation Flow

```text
              HTTP Request
                    │
                    ▼
          Layer 7 Inspection
                    │
                    ▼
        Behavioral Reputation Engine
                    │
          Compute Risk Score
                    │
         Score >= Threshold?
          │                 │
         No                Yes
          │                 │
          ▼                 ▼
 Continue normally    Insert IP into
                     eBPF Hash Map
                            │
                            ▼
                  Future packets
                   XDP_DROP
```

---

## Reputation Sources

A score may incorporate:

- protocol violations
- attack signatures
- request frequency
- bot detection
- historical reputation
- anomaly detection
- repeated policy violations

---

## Dynamic Promotion

When the score exceeds a configurable threshold, the IP address is inserted into a shared eBPF map.

Subsequent packets are rejected directly inside XDP using:

```
XDP_DROP
```

The packet never reaches:

- TCP socket allocation
- user space
- HTTP parser
- routing logic

---

## TTL-based Expiration

Each promoted address receives an expiration timestamp.

```
IP
 │
 ├── Score
 ├── First Seen
 ├── Last Seen
 └── TTL
```

Once the TTL expires, the entry is automatically removed.

This prevents permanent blocking while allowing temporary attackers to be forgotten over time.

---

## Scope

The mechanism is designed to mitigate:

- common HTTP floods
- automated scanners
- credential stuffing
- low-volume DDoS attacks
- persistent bots

It is **not** intended to replace globally distributed DDoS mitigation providers.

Large volumetric attacks require globally distributed edge infrastructure capable of absorbing traffic before it reaches the protected network.

---

# 8. Rust Phase Model

```rust
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer4Phase {
    IngressXdp {
        peer_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    },

    IngressUserSpace {
        peer_ip: IpAddr,
        src_port: u16,
        packet_buffer_size: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer7Phase<'a> {

    ConnectionContext {
        peer_ip: IpAddr,
        tls_cipher: Option<&'a str>,
    },

    EarlyRequestFilter {
        real_client_ip: IpAddr,
        method: &'a str,
        path: &'a str,
    },

    RequestLine {
        method: &'a str,
        path: &'a str,
        query_string: Option<&'a str>,
    },

    RequestHeader {
        name: &'a str,
        value: &'a str,
    },

    RequestBody {
        chunk: &'a [u8],
        content_type: &'a str,
    },

    ResponseHeader {
        status_code: u16,
        name: &'a str,
        value: &'a str,
    },

    ResponseBody {
        chunk: &'a [u8],
    },
}

pub fn process_waf_lifecycle(
    phase: &Layer7Phase
) -> Result<(), &'static str> {

    match phase {

        Layer7Phase::ConnectionContext { peer_ip, .. } => {
            println!("Connection Context {}", peer_ip);
            Ok(())
        }

        Layer7Phase::EarlyRequestFilter {
            real_client_ip,
            path,
            ..
        } => {

            if real_client_ip.is_loopback()
                && path.starts_with("/external-api")
            {
                return Err("BLOCK");
            }

            Ok(())
        }

        Layer7Phase::RequestLine { path, .. } => {

            if path.contains("../") {
                return Err("Traversal");
            }

            Ok(())
        }

        Layer7Phase::RequestHeader {
            name,
            value
        } => {

            if name.eq_ignore_ascii_case("user-agent")
                && value.contains("scanner")
            {
                return Err("Bot");
            }

            Ok(())
        }

        Layer7Phase::RequestBody { chunk, .. } => {

            if let Ok(text) = std::str::from_utf8(chunk) {

                if text.contains("UNION SELECT") {
                    return Err("SQLi");
                }

                if text.contains("<script>") {
                    return Err("XSS");
                }
            }

            Ok(())
        }

        Layer7Phase::ResponseHeader { .. } => Ok(()),

        Layer7Phase::ResponseBody { .. } => Ok(())
    }
}
```

---

# 9. Operational Resource Matrix

| Layer                    | Execution Context | Main Algorithms    | Time Complexity | CPU Cost | Memory Strategy     | Primary Objective     |
| ------------------------ | ----------------- | ------------------ | --------------- | -------- | ------------------- | --------------------- |
| Layer4::IngressXdp       | Kernel            | Hash Map, LPM Trie | O(1) / O(W)     | Very Low | Zero Allocation     | Immediate packet drop |
| Layer4::IngressUserSpace | User Space        | Bloom Filter, Hash | O(1)            | Medium   | Memory Pools        | Legacy deployments    |
| ConnectionContext        | User Space        | Hash Lookup        | O(1)            | Low      | Borrowed References | Deployment adaptation |
| EarlyRequestFilter       | User Space        | Hash Lookup        | O(1)            | Low      | Zero Copy           | Reputation filtering  |
| RequestLine              | User Space        | Radix Tree         | O(N)            | Low      | Borrowed Slices     | Routing validation    |
| RequestHeader            | User Space        | DFA / Aho-Corasick | O(N)            | Medium   | Zero Copy           | Header inspection     |
| RequestBody              | User Space        | Aho-Corasick       | O(N+M)          | High     | Streaming Buffers   | Payload inspection    |
| ResponseHeader           | User Space        | Lookup             | O(1)            | Low      | Mutable Buffers     | Cloaking              |
| ResponseBody             | User Space        | Streaming Scan     | O(N)            | Medium   | Chunked Buffers     | DLP                   |

---

# 10. References

1. Høiland-Jørgensen, T., Brouer, J., Borkmann, D., et al. **The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel.** ACM CoNEXT, 2018.

2. Linux Foundation. **eBPF Documentation.**

3. Cilium Project. **BPF and XDP Reference Architecture.**

4. RFC 9110 — HTTP Semantics.

5. RFC 7239 — Forwarded HTTP Extension.

6. OWASP Foundation. **OWASP Top Ten.**

7. OWASP Foundation. **Web Security Testing Guide.**

8. Intel. **DPDK Programmer's Guide.**

9. Linux Kernel Documentation. **BPF_MAP_TYPE_HASH.**

10. Linux Kernel Documentation. **BPF_MAP_TYPE_LPM_TRIE.**

11. Aho, A. V., Corasick, M. J. (1975). _Efficient String Matching: An Aid to Bibliographic Search._

12. Bloom, B. H. (1970). _Space/Time Trade-offs in Hash Coding with Allowable Errors._
