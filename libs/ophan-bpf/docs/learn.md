# Network Frame Structure in Bytes and Black-Box Testing Methodology for eBPF/XDP Filters with Aya in Rust

Designing and validating high-performance network filters with eXpress Data Path (XDP) and eBPF requires a precise understanding of packet topology at the byte level. Because XDP runs at the lowest level of the Linux kernel's networking subsystem, immediately after the frame is received by the Network Interface Card (NIC), an XDP program receives a direct reference to an unstructured memory region (`xdp_buff`). Unlike traditional userspace network daemons or the upper kernel layers that operate on abstracted `sk_buff` structures, XDP requires the parsing logic to manually inspect memory offsets and validate buffer bounds.

To guarantee the robustness, stability, and security of an eBPF filter written in Rust with the Aya library, it is essential to build a black-box testing environment capable of injecting synthetic frames structured in network byte order (Big-Endian). This methodology makes it possible to verify the behavior of the eBPF code both against legit, standards-compliant traffic according to the Internet Assigned Numbers Authority (IANA), and against complex attack vectors, malformed frames, anomalous flags, and bounds violations.

## eBPF/XDP Network Parsing Fundamentals and L2 Topology

The XDP execution model delegates the entire responsibility of packet analysis to the eBPF program. The program receives start (`data`) and end (`data_end`) pointers of the packet memory. The kernel's compile-time verification (the eBPF verifier) requires that every memory access be preceded by an explicit check that the header offset does not exceed `data_end`, preventing buffer overflows in kernel space.

Data ordering on the network uses the Big-Endian convention (most significant byte first). Since most modern x86_64 architectures execute instructions in Little-Endian, interpreting 16- and 32-bit fields requires explicit byte-order conversions.

The data link layer (L2) is dominated by the Ethernet II specification. However, the presence of virtual LAN multiplexing via IEEE 802.1Q (VLAN) tags or double IEEE 802.1ad (QinQ) encapsulation dynamically alters the length of the link header, shifting the start of the Layer 3 (L3) header.

| **Layer Structure**    | **Field**              | **Offset (Bytes)** | **Length**  | **Hexadecimal Value / IANA Assignment**                        |
| ---------------------- | ---------------------- | ------------------ | ----------- | -------------------------------------------------------------- |
| **Ethernet II Base**   | Destination MAC        | 0                  | 6 Bytes     | Destination physical address (`ff:ff:ff:ff:ff:ff` for Broadcast). |
| **Ethernet II Base**   | Source MAC             | 6                  | 6 Bytes     | Sender's source physical address.                              |
| **Ethernet II Base**   | EtherType              | 12                 | 2 Bytes     | `0x0800` (IPv4), `0x86DD` (IPv6), `0x8100` (802.1Q Tagged).    |
| **IEEE 802.1Q (VLAN)** | TPID                   | 12                 | 2 Bytes     | Tag Protocol Identifier: `0x8100`.                             |
| **IEEE 802.1Q (VLAN)** | TCI (PCP/DEI/VID)      | 14                 | 2 Bytes     | Priority (3 bits), Drop (1 bit), VLAN ID (12 bits).            |
| **IEEE 802.1Q (VLAN)** | Encapsulated EtherType | 16                 | 2 Bytes     | Real L3 EtherType (e.g. `0x0800` for IPv4 after VLAN).         |
| **IEEE 802.1ad (QinQ)**| Outer TPID             | 12                 | 2 Bytes     | Provider Identifier: `0x88A8`.                                 |
| **IEEE 802.1ad (QinQ)**| Outer TCI              | 14                 | 2 Bytes     | Provider outer tag content.                                    |
| **IEEE 802.1ad (QinQ)**| Inner TPID             | 16                 | 2 Bytes     | Customer Identifier: `0x8100`.                                 |
| **IEEE 802.1ad (QinQ)**| Inner TCI              | 18                 | 2 Bytes     | Customer inner tag content.                                    |
| **IEEE 802.1ad (QinQ)**| Encapsulated EtherType | 20                 | 2 Bytes     | Final Layer 3 EtherType.                                       |

An XDP parser must iteratively verify the EtherType value. If it detects `0x8100` or `0x88A8`, the L3 header offset must be shifted 4 or 8 bytes respectively before inspecting the network layer protocol.

## Network Header Specification (IPv4 and IPv6) and IANA Registries

Layer 3 analysis requires distinguishing between the variable-length format of IPv4 and the fixed-length format with extension header chains of IPv6.

### IPv4 Header and Fragmentation Fields

A standard IPv4 header has a base length of 20 bytes when the _Internet Header Length_ (IHL) field has a value of 5 (representing five 32-bit words). If IP options are present, the IHL field takes a value between 6 and 15 (up to 60 bytes in total).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The _Flags_ field (3 bits at byte offset 6) breaks down into: Bit 0 (Reserved, must be 0), Bit 1 (DF - Don't Fragment), and Bit 2 (MF - More Fragments). The _Fragment Offset_ (13 bits) indicates the position of the fragment in units of 8 octets. An active MF bit or a _Fragment Offset_ greater than zero identifies a fragmented datagram.

### IPv6 Header and Extension Header Chaining

IPv6 simplifies the main header to a fixed length of 40 bytes, removing the L3 checksum and delegating fragmentation control or options to extension headers chained through the _Next Header_ field.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                           (128 bits)                          |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                           (128 bits)                          |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The values of the IPv4 _Protocol_ field and the IPv6 _Next Header_ field are centralized in the official IANA registries.

| **IANA Registry**     | **Protocol / Type Name**       | **Hexadecimal Value** | **Decimal Value** | **Use and Description**                       |
| --------------------- | ------------------------------ | --------------------- | ----------------- | --------------------------------------------- |
| **EtherType (L2)**    | IPv4 Protocol                  | `0x0800`              | 2048              | Standard IPv4 encapsulation.                  |
| **EtherType (L2)**    | ARP Protocol                   | `0x0806`              | 2054              | Address Resolution Protocol.                  |
| **EtherType (L2)**    | IEEE 802.1Q                    | `0x8100`              | 33024             | Standard VLAN tagging.                        |
| **EtherType (L2)**    | IPv6 Protocol                  | `0x86DD`              | 34525             | Standard IPv6 encapsulation.                  |
| **EtherType (L2)**    | IEEE 802.1ad                   | `0x88A8`              | 34984             | QinQ encapsulation (Provider Bridging).       |
| **IP Protocol (L3)**  | ICMP                           | `0x01`                | 1                 | IPv4 control messages.                        |
| **IP Protocol (L3)**  | IGMP                           | `0x02`                | 2                 | Multicast group management.                   |
| **IP Protocol (L3)**  | TCP                            | `0x06`                | 6                 | Transmission Control Protocol.                |
| **IP Protocol (L3)**  | UDP                            | `0x17`                | 17                | User Datagram Protocol.                       |
| **IP Protocol (L3)**  | GRE                            | `0x2D`                | 47                | Generic Routing Encapsulation.                |
| **IP Protocol (L3)**  | ESP                            | `0x32`                | 50                | Encapsulating Security Payload (IPsec).       |
| **IP Protocol (L3)**  | AH                             | `0x33`                | 51                | Authentication Header (IPsec).                |
| **IP Protocol (L3)**  | ICMPv6                         | `0x3A`                | 58                | IPv6 control messages and NDP.                |
| **IPv6 Extension**    | Hop-by-Hop Options             | `0x00`                | 0                 | Options processed at every hop.               |
| **IPv6 Extension**    | Routing Header                 | `0x2B`                | 43                | Source routing.                               |
| **IPv6 Extension**    | Fragment Header                | `0x2C`                | 44                | Fragmentation parameters in IPv6.             |
| **IPv6 Extension**    | Destination Options            | `0x3C`                | 60                | Options processed by the final destination.   |

## L4 Headers, Anomalous Flags, and Vulnerability/DDoS Vectors

Deep Packet Inspection (DPI) in eBPF analyzes the transport layer (L4) to apply port- and control-flag-based filtering policies.

### TCP and UDP Header Structure

The UDP header has a fixed size of 8 bytes (16-bit source and destination ports, 16-bit Length, and 16-bit Checksum).

The TCP header has a minimum length of 20 bytes. Byte offset 12 contains the _Data Offset_ (upper 4 bits) which specifies the header size in 32-bit words, followed by 3 reserved bits and the NS (Nonce Sum) flag. Byte offset 13 contains the main TCP control flags:

- Bit 7: CWR (Congestion Window Reduced)
- Bit 6: ECE (ECN-Echo)
- Bit 5: URG (Urgent Pointer Valid)
- Bit 4: ACK (Acknowledgment Valid)
- Bit 3: PSH (Push Function)
- Bit 2: RST (Reset Connection)
- Bit 1: SYN (Synchronize Sequence Numbers)
- Bit 0: FIN (No More Data from Sender)

### Taxonomy of Attack Vectors and Malformed Frames

For black-box testing of an XDP program, it is necessary to construct vectors that exploit edge cases in the parsing code or vulnerabilities in the system stack.

- **Overlapping Fragmentation Attacks (Teardrop)**: IPv4 datagrams are transmitted where the second fragment specifies a _Fragment Offset_ that overlaps with the data of the first fragment. A faulty eBPF filter that attempts to compute the total payload size by adding fragments without validating ranges can lead to integer overflows.
- **Anomalous TCP Flag Scanning (Xmas, Null, SYN-FIN)**: This involves sending segments with illegal flag combinations. An _Xmas Tree_ scan activates URG, PSH, and FIN simultaneously (`Byte 13 = 0x29` or `0x3F`), while a _Null Scan_ keeps all flags at zero (`Byte 13 = 0x00`). A _SYN-FIN_ segment (`Byte 13 = 0x03`) violates RFC 793 and attempts to evade stateful firewalls.
- **LAND Attack (Local Area Network Denial)**: An IP frame where the source address is identical to the destination address, and the TCP/UDP source port matches the destination port (`Src_IP == Dst_IP` and `Src_Port == Dst_Port`), designed to induce infinite loops in socket connections.
- **UDP Amplification Vectors (NTP Monlist, DNS Any, Memcached)**: UDP requests to well-known service ports (NTP `123`, DNS `53`, Memcached `11211`) eliciting responses substantially larger than the original request, sent to spoofed source IP addresses.
- **Invalid IHL and Boundary Truncation Violation**: IPv4 frames where IHL is set below 5 (`IHL < 5`, e.g. `0x42`), or where the total packet length indicated in the header exceeds the actual length consumed by the physical frame data. If the XDP filter dereferences L4 by blindly trusting IHL without checking against `data_end`, the kernel verifier will abort or reject execution.

| **Attack Vector / Anomaly**  | **Indicator in Key Bytes**        | **Detection Condition**                | **Expected XDP Action** |
| ---------------------------- | --------------------------------- | -------------------------------------- | ----------------------- |
| **TCP Xmas Scan**            | TCP Flags (Byte 13) = `0x29` / `0x3F` | `(flags & (URG | PSH | FIN)) == (URG | PSH | FIN)` | `XDP_DROP`              |
| **TCP Null Scan**            | TCP Flags (Byte 13) = `0x00`      | `flags == 0` on active-state packets   | `XDP_DROP`              |
| **TCP SYN-FIN Scan**         | TCP Flags (Byte 13) = `0x03`      | `(flags & (SYN | FIN)) == (SYN | FIN)` | `XDP_DROP`              |
| **LAND Attack**              | IP Src == IP Dst, Port Src == Port Dst | `ip_src == ip_dst && port_src == port_dst` | `XDP_DROP`        |
| **Teardrop Fragment**        | IPv4 Flags/Offset (Bytes 6-7)     | `frag_offset < prev_offset + prev_len` | `XDP_DROP` / Alert      |
| **Anomalous IHL**            | IPv4 Version/IHL (Byte 0) = `0x42` | `(byte_0 & 0x0F) < 5`                 | `XDP_DROP`              |
| **NTP Amplification**        | UDP Dst Port = `0x007B` (123)     | `udp_dst_port == 123` with Monlist Payload | `XDP_DROP`          |
| **Truncated Frame**          | Buffer length &lt; IP header      | `(data + ihl_bytes) > data_end`       | `XDP_DROP` (Bounds Check) |
