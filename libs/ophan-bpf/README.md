# Ophan eBPF program

This document lists the Ethernet frame `EtherType` values recognized by the
`network-types` crate and used by this XDP program to classify traffic
before applying firewall policy.

## EtherType reference table

| Hex value | Decimal | Crate variant      | Common name                        | Description                                                 |
| --------- | ------- | ------------------ | ---------------------------------- | ----------------------------------------------------------- |
| `0x0060`  | 96      | `Loop`             | Loopback                           | Used for testing network interfaces.                        |
| `0x0800`  | 2048    | `Ipv4`             | IPv4                               | Internet Protocol version 4 payload.                        |
| `0x0806`  | 2054    | `Arp`              | ARP                                | Address Resolution Protocol.                                |
| `0x8100`  | 33024   | `Ieee8021q`        | VLAN (802.1Q)                      | Single VLAN tag. **Aliased as `VLAN`.**                     |
| `0x86DD`  | 34525   | `Ipv6`             | IPv6                               | Internet Protocol version 6 payload.                        |
| `0x88A8`  | 34984   | `Ieee8021ad`       | QinQ / Provider Bridging (802.1ad) | Double VLAN tagging (outer tag). **Aliased as `QINQ`.**     |
| `0x88E5`  | 35045   | `Ieee8021MacSec`   | MACsec (802.1AE)                   | Media Access Control Security.                              |
| `0x88E7`  | 35047   | `Ieee8021ah`       | PBB (802.1ah)                      | Provider Backbone Bridges ("MAC-in-MAC").                   |
| `0x88F5`  | 35061   | `Ieee8021mvrp`     | MVRP (802.1ak)                     | Multiple VLAN Registration Protocol.                        |
| `0x8906`  | 35078   | `FibreChannel`     | FCoE                               | Fibre Channel over Ethernet.                                |
| `0x8915`  | 35093   | `Infiniband`       | InfiniBand                         | InfiniBand over Ethernet.                                   |
| `0x9000`  | 36864   | `LoopbackIeee8023` | Loopback (802.3)                   | Configuration Test Protocol loopback.                       |
| `0x9100`  | 37120   | `Ieee8021QinQ1`    | QinQ (legacy variant 1)            | Non-standard double-tagging EtherType used by some vendors. |
| `0x9200`  | 37376   | `Ieee8021QinQ2`    | QinQ (legacy variant 2)            | Non-standard double-tagging EtherType used by some vendors. |
| `0x9300`  | 37632   | `Ieee8021QinQ3`    | QinQ (legacy variant 3)            | Non-standard double-tagging EtherType used by some vendors. |

> All values above are stored **big-endian** (`.to_be()`) in the crate, matching
> network byte order as found on the wire.

## Traffic handled by this XDP program

| EtherType       | Action                                                                     |
| --------------- | -------------------------------------------------------------------------- |
| `Arp`           | Always passed (`XDP_PASS`) — ARP is required for L2 resolution to work.    |
| `Ipv4`          | Passed or dropped by `evaluate_ingress_v4` (listener + per-port IP rules). |
| `Ipv6`          | Passed or dropped by `evaluate_ingress_v6` (listener + per-port IP rules). |
| `VLAN` / `QINQ` | Unwrapped (up to 2 nested tags) to find the real inner EtherType.          |
| Anything else   | Passed through unmodified (`XDP_PASS`).                                    |

## Policy model

Traffic targeting a monitored port is classified in three steps, all handled in-kernel:

1. **Listener lookup** — `LISTENER_POLICIES` (`HashMap<u16, ListenerPolicy>`) maps a
   destination port (home byte order as extracted from the wire) to its default
   `ListenerPolicy`. `default_action` is `DefaultPolicy::ALLOW` (0, pass) or
   `DefaultPolicy::DENY` (1, drop).
2. **Per-port rule lookup** — `PORT_RULES_V4` (`LpmTrie<PortRuleKeyV4, u8>`) and
   `PORT_RULES_V6` (`LpmTrie<PortRuleKeyV6, u8>`) store explicit `RuleAction`
   values (`DROP` = 1, `PASS` = 2). Keys are composite LPM keys:
   * IPv4: `PortRuleKeyV4 { port, client_ip }` — prefix is **48** for a `/32`
     (16 bits port + 32 bits IP), or `16 + cidr` for subnets.
   * IPv6: `PortRuleKeyV6 { port, client_ip }` — prefix is **144** for a `/128`
     (16 bits port + 128 bits IP), or `16 + cidr` for subnets.
3. **Fallback** — if an explicit rule matches it wins; otherwise the listener's
   `default_action` decides (`DENY` → `XDP_DROP`, `ALLOW` → `XDP_PASS`). If the
   destination port has no listener policy entry, the packet is passed
   (`XDP_PASS`).

Parsing helpers in `ingress_filter::packet` are used for L4 port extraction and
IPv6 extension header walking:

* `parse_l4_dst_port` reads the TCP/UDP destination port in network byte order.
* `strip_vlan_tags` unwraps up to 2 `802.1Q` / `802.1ad` / legacy QinQ tags.
* `resolve_ipv6_l4` walks the IPv6 extension header chain (max `MAX_EH_HOPS`,
  i.e. 8 hops); fragmented or ESP traffic is passed without port classification.

## XDP validation checklist

### Layer 2: Ethernet

- Verify the packet is long enough for the Ethernet header before reading it.
- Check `data + offset + len <= data_end` before every header access.
- Treat unknown EtherTypes explicitly instead of falling through accidentally.
- Decide and document how ARP and other non-IP frames should behave. [github](https://github.com/xdp-project/xdp-tutorial/blob/master/packet01-parsing/README.org)

### VLAN

- Support at least 0, 1, and 2 VLAN tags if your environment uses QinQ.
- Recompute EtherType after each VLAN header.
- Validate each VLAN header before reading the next one.
- Decide what to do if more encapsulation appears than you support. [github](https://github.com/xdp-project/xdp-tutorial/blob/main/packet02-rewriting/README.org)

### IPv4

- Never assume `IHL = 20`; use the real IHL from the packet.
- Reject truncated IPv4 headers.
- Detect fragmentation before trying to read TCP/UDP ports.
- Define a stable policy for fragments: pass, drop, or exception. [github](https://github.com/xdp-project/xdp-tutorial/blob/main/packet-solutions/README.org)

### IPv6

- Do not assume `next_hdr` is TCP or UDP.
- Walk extension headers with a hard hop limit.
- Handle Hop-by-Hop, Routing, Fragment, Destination Options, AH, and ESP as explicit cases.
- If you cannot safely reach L4, do not silently allow the packet. [research](https://research.google/pubs/rfc-9098-operational-implications-of-ipv6-packets-with-extension-headers/)

### Layer 4: TCP/UDP

- Confirm the full TCP/UDP header is present before reading ports.
- Use destination port only when the policy really depends on service classification.
- Make non-TCP/UDP behavior explicit.
- Never treat “failed parsing” as an implicit allow. [github](https://github.com/xdp-project/xdp-tutorial/blob/master/packet01-parsing/README.org)

### Fragmentation

- For IPv4, detect non-initial fragments and avoid reading L4 as if it were present.
- For IPv6, treat the Fragment header as a special case because it can hide L4.
- Choose one consistent fragment policy and test it.
- Ensure fragments do not fall through to an unintended `PASS`. [dl.acm](https://dl.acm.org/doi/abs/10.17487/RFC9098)

### Policy behavior

- Define a strict default action (`DefaultPolicy::DENY`) for protected listeners.
- Store per-port IP/CIDR rules in `PORT_RULES_V4` / `PORT_RULES_V6` (LPM trie)
  and listener defaults in `LISTENER_POLICIES`.
- An explicit per-port rule (PASS/DROP) takes precedence over the listener default.
- If the destination port has no listener entry, packet is passed (`XDP_PASS`).
- Document exceptions for ICMP/ICMPv6, PMTU, and management traffic. [research](https://research.google/pubs/rfc-9098-operational-implications-of-ipv6-packets-with-extension-headers/)

### Program robustness

- Keep the XDP fast path small and deterministic.
- Avoid verbose logging on hot traffic paths.
- Add counters for each drop reason.
- Test malformed packets, VLAN, IPv6 EH, and fragments regularly. [labs.iximiuz](https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e)

### Operational safety

- Serialize policy updates from userspace.
- Avoid mixing old and new rules during multi-map updates.
- Verify that rule changes are not partially applied.
- Review behavior for protocols your parser does not explicitly cover. [dl.acm](https://dl.acm.org/doi/abs/10.17487/RFC9098)
