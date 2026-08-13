//! Black-box test suite for the `xdp_ingress` eBPF program.
//!
//! Unlike `black_box.rs` (baseline + attack vectors), this file organises the
//! coverage around the policy model implemented in `ingress_filter`:
//!
//! * correctly formed packets — every EtherType path the parser must accept;
//! * malformed packets — truncation and out-of-bounds triggers;
//! * unknown protocols — EtherTypes/IP protocols with no policy branch;
//! * invalid protocols — reserved / illegal field combinations;
//! * VLAN tags — single, QinQ and legacy nested tags;
//! * edge cases — fragmentation, IPv6 extension headers, jumbo frames;
//! * policy rules — listener defaults + per-port PASS/DROP rules (v4/v6).
//!
//! Packets are injected via `BPF_PROG_TEST_RUN`; only the XDP return action is
//! asserted. `data_out` is not exercised because the filter does not rewrite
//! packets in place.

use aya::Ebpf;
use aya::Pod;
use aya::maps::HashMap;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::programs::{TestRun, TestRunOptions, Xdp};
use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};

// ---------------------------------------------------------------------------
// Policy types (must mirror the eBPF map key/value layouts byte-for-byte)
// ---------------------------------------------------------------------------

/// `ListenerPolicy` as stored in the `LISTENER_POLICIES` map.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ListenerPolicy {
    /// `DefaultPolicy`: ALLOW (0) or DENY (1).
    default_action: u8,
}

unsafe impl Pod for ListenerPolicy {}

/// Inner key payload for the `PORT_RULES_V4` LPM trie.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PortRuleKeyV4 {
    port: u16,
    client_ip: u32,
}

unsafe impl Pod for PortRuleKeyV4 {}

/// Inner key payload for the `PORT_RULES_V6` LPM trie.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PortRuleKeyV6 {
    port: u16,
    client_ip: [u8; 16],
}

unsafe impl Pod for PortRuleKeyV6 {}

const RULE_ACTION_DROP: u8 = 1;
const RULE_ACTION_PASS: u8 = 2;
const DEFAULT_ALLOW: u8 = 0;
const DEFAULT_DENY: u8 = 1;

// ---------------------------------------------------------------------------
// BPF program loader
// ---------------------------------------------------------------------------

pub const XDP_BYTES: &[u8] = include_bytes!("../../../target/bpfel-unknown-none/release/ophan-bpf");

fn run(packet: &[u8]) -> u32 {
    let mut bpf = Ebpf::load(XDP_BYTES).expect("failed to load BPF object");
    let program = bpf.program_mut("xdp_ingress").expect("failed to find xdp_ingress program");
    let program: &mut Xdp = program.try_into().expect("failed to convert to Xdp");
    program.load().expect("failed to load XDP program");

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(packet);
    program.test_run(opts).expect("BPF_PROG_TEST_RUN failed").return_value
}

// ---------------------------------------------------------------------------
// Packet builder helpers (big-endian / network byte order)
// ---------------------------------------------------------------------------

fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn eth(dst: [u8; 6], src: [u8; 6], ether_type: u16) -> Vec<u8> {
    let mut buf = [0u8; 14];
    let mut i = 0;
    while i < 6 {
        buf[i] = dst[i];
        buf[6 + i] = src[i];
        i += 1;
    }
    let et = ether_type.to_be_bytes();
    buf[12] = et[0];
    buf[13] = et[1];
    buf.to_vec()
}

fn vlan(tci: u16, inner: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&u16be(tci));
    buf.extend_from_slice(&u16be(inner));
    buf
}

fn ipv4(proto: u8, total_len: u16, flags_frag: u16, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut buf = [0u8; 20];
    buf[0] = 0x45; // Version 4, IHL 5
    buf[2..4].copy_from_slice(&u16be(total_len));
    buf[4..6].copy_from_slice(&u16be(0));
    buf[6..8].copy_from_slice(&u16be(flags_frag));
    buf[8] = 64; // TTL
    buf[9] = proto;
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    buf.to_vec()
}

fn ipv6(next_hdr: u8, payload_len: u16, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut buf = [0u8; 40];
    buf[0] = 0x60; // Version 6
    buf[4..6].copy_from_slice(&u16be(payload_len));
    buf[6] = next_hdr;
    buf[7] = 64; // Hop limit
    buf[8..24].copy_from_slice(&src);
    buf[24..40].copy_from_slice(&dst);
    buf.to_vec()
}

fn tcp(sport: u16, dport: u16, doff_flags: u16) -> Vec<u8> {
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&u16be(sport));
    buf[2..4].copy_from_slice(&u16be(dport));
    buf[12..14].copy_from_slice(&u16be(doff_flags));
    buf.to_vec()
}

fn udp(sport: u16, dport: u16, len: u16) -> Vec<u8> {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&u16be(sport));
    buf[2..4].copy_from_slice(&u16be(dport));
    buf[4..6].copy_from_slice(&u16be(len));
    buf.to_vec()
}

fn doff_flags(data_offset_words: u8, flags: u8) -> u16 {
    ((data_offset_words as u16) << 12) | (flags as u16)
}

const DMAC: [u8; 6] = [0x00, 0x15, 0x5D, 0x01, 0x02, 0x03];
const SMAC: [u8; 6] = [0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC];
const SRC_V4: [u8; 4] = [192, 168, 1, 50];
const DST_V4: [u8; 4] = [10, 0, 0, 1];
const SRC_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const DST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86DD;
const ETH_ARP: u16 = 0x0806;
const ETH_VLAN: u16 = 0x8100;
const ETH_QINQ: u16 = 0x88A8;
const ETH_QINQ_LEGACY1: u16 = 0x9100;
const ETH_QINQ_LEGACY2: u16 = 0x9200;
const ETH_QINQ_LEGACY3: u16 = 0x9300;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// IPv6 extension header next-header values (mirrored from packet.rs)
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_ESP: u8 = 50;
const IPV6_AUTH: u8 = 51;
const IPV6_DEST_OPTS: u8 = 60;

/// Convenience assertion used across the suite: the program must never abort
/// on synthetic input, and the verdict must be one of the meaningful actions.
fn assert_verdict(ret: u32, label: &str) {
    assert_ne!(ret, XDP_ABORTED, "{label}: program ABORTED (verifier rejected packet)");
    assert!(
        ret == XDP_PASS || ret == XDP_DROP,
        "{label}: unexpected return {ret} (expected PASS or DROP)"
    );
}

// ===========================================================================
// 1. Correctly formed packets
// ===========================================================================

const SYN: u8 = 0x02;

#[test]
fn valid_arp_passes() {
    let mut pkt = eth(DMAC, SMAC, ETH_ARP);
    pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
    assert_eq!(run(&pkt), XDP_PASS, "ARP is always passed for L2 resolution");
}

#[test]
fn valid_ipv4_tcp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    let l4 = tcp(12345, 80, doff_flags(5, SYN));
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&l4);
    assert_verdict(run(&pkt), "valid IPv4/TCP");
}

#[test]
fn valid_ipv4_udp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(54321, 53, 8));
    pkt.extend_from_slice(b"\x00\x01\x01\x00");
    assert_verdict(run(&pkt), "valid IPv4/UDP");
}

#[test]
fn valid_ipv4_with_options_ihl_6() {
    // IHL 6 (24 bytes) — parser must respect the real IHL, not assume 20.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    let mut ip = vec![0u8; 24];
    ip[0] = 0x46;
    ip[2..4].copy_from_slice(&u16be(44));
    ip[6..8].copy_from_slice(&u16be(0x4000));
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    ip[12..16].copy_from_slice(&SRC_V4);
    ip[16..20].copy_from_slice(&DST_V4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "valid IPv4 with options");
}

#[test]
fn valid_ipv6_tcp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(IPPROTO_TCP, 20, SRC_V6, DST_V6));
    pkt.extend_from_slice(&tcp(12345, 443, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "valid IPv6/TCP");
}

#[test]
fn valid_ipv6_udp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(IPPROTO_UDP, 8, SRC_V6, DST_V6));
    pkt.extend_from_slice(&udp(54321, 53, 8));
    assert_verdict(run(&pkt), "valid IPv6/UDP");
}

// ===========================================================================
// 2. Malformed packets
// ===========================================================================

#[test]
fn malformed_empty_frame() {
    assert_ne!(run(&[]), XDP_PASS, "empty frame must not be passed as valid traffic");
}

#[test]
fn malformed_truncated_ethernet() {
    // Ethernet needs 14 bytes; feed only 12.
    assert_ne!(
        run(&[0u8; 12]),
        XDP_PASS,
        "truncated Ethernet must not parse as a valid packet"
    );
}

#[test]
fn malformed_ethernet_only_no_ip() {
    let pkt = eth(DMAC, SMAC, ETH_IPV4);
    assert_ne!(run(&pkt), XDP_PASS, "Ethernet without an IP header must not be classified");
}

#[test]
fn malformed_partial_ipv4_header() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06]);
    // only 10 of the 20 IPv4 bytes present
    assert_ne!(run(&pkt), XDP_PASS, "partial IPv4 header must not be treated as valid");
}

#[test]
fn malformed_ipv4_ihl_under_5() {
    // First byte 0x41 = Version 4, IHL 1 — below the minimum of 5.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.push(0x41);
    pkt.extend_from_slice(&[0u8; 19]);
    assert_verdict(run(&pkt), "IPv4 IHL < 5");
}

#[test]
fn malformed_ipv4_total_length_exceeds_frame() {
    // Header advertises 65535 bytes but the frame is far smaller.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    assert_ne!(
        run(&pkt),
        XDP_PASS,
        "inflated total length must not yield a PASS classification"
    );
}

#[test]
fn malformed_truncated_l4() {
    // IPv4 header complete, but fewer bytes than a TCP header requires.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 30, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&[0u8; 10]);
    assert_ne!(run(&pkt), XDP_PASS, "truncated L4 must not be classified against a listener");
}

#[test]
fn malformed_icmpv4() {
    // ICMP is neither TCP nor UDP — parser returns no port; must not abort.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_ICMP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&[0u8; 8]);
    assert_ne!(run(&pkt), XDP_ABORTED, "ICMP must never abort the verifier");
}

// ===========================================================================
// 3. Unknown protocols
// ===========================================================================

#[test]
fn unknown_ethertype_passed() {
    // 0x1234 is not IPv4/IPv6/ARP/VLAN — non-IP EtherTypes pass through.
    let mut pkt = eth(DMAC, SMAC, 0x1234);
    pkt.extend_from_slice(b"\x00\x01\x02\x03\x04\x05\x06\x07");
    assert_eq!(run(&pkt), XDP_PASS, "unknown EtherType is passed through unmodified");
}

#[test]
fn unknown_ip_protocol_zero() {
    // IP protocol 0 (HOPOPT) is not TCP/UDP — parser must not abort, no port.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(0, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&[0u8; 8]);
    assert_ne!(run(&pkt), XDP_ABORTED, "reserved IP protocol 0 must not abort");
}

#[test]
fn unknown_ip_protocol_255() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(255, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&[0u8; 8]);
    assert_ne!(run(&pkt), XDP_ABORTED, "reserved IP protocol 255 must not abort");
}

#[test]
fn unknown_ipv6_next_header_no_l4() {
    // Next-header 59 (no next header) terminates the chain without an L4 port.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(59, 0, SRC_V6, DST_V6));
    assert_ne!(run(&pkt), XDP_ABORTED, "IPv6 No Next Header must not abort");
}

// ===========================================================================
// 4. Invalid protocols
// ===========================================================================

#[test]
fn invalid_tcp_data_offset_below_5() {
    // doff = 4 (0x40) is illegal; must be >= 5.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    let tcp = tcp(12345, 80, doff_flags(4, SYN));
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp);
    assert_verdict(run(&pkt), "TCP data offset < 5");
}

#[test]
fn invalid_tcp_flags_all_zero_null_scan() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, 0x00)));
    assert_verdict(run(&pkt), "TCP null scan (flags=0)");
}

#[test]
fn invalid_tcp_flags_syn_fin() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, 0x03))); // SYN|FIN
    assert_verdict(run(&pkt), "TCP SYN|FIN");
}

#[test]
fn invalid_tcp_flags_xmas() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, 0x29))); // URG|PSH|FIN
    assert_verdict(run(&pkt), "TCP xmas scan");
}

#[test]
fn invalid_udp_length_mismatch() {
    // UDP header length (0) does not cover the 8-byte UDP header itself.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 0));
    assert_verdict(run(&pkt), "UDP length = 0");
}

#[test]
fn invalid_land_attack() {
    // src == dst IP and sport == dport.
    let local: [u8; 4] = [10, 0, 0, 1];
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, local, local));
    pkt.extend_from_slice(&tcp(80, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "LAND attack");
}

// ===========================================================================
// 5. VLAN tags
// ===========================================================================

fn vlan_ipv4_udp(tci: u16) -> Vec<u8> {
    let mut pkt = eth(DMAC, SMAC, ETH_VLAN);
    pkt.extend_from_slice(&vlan(tci, ETH_IPV4));
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 8));
    pkt
}

#[test]
fn vlan_single_tag_ipv4() {
    assert_verdict(run(&vlan_ipv4_udp(0x0064)), "single 802.1Q tag");
}

#[test]
fn vlan_qinq_double_tag() {
    // 0x88A8 outer (provider) + 0x8100 inner (customer).
    let mut pkt = eth(DMAC, SMAC, ETH_QINQ);
    pkt.extend_from_slice(&vlan(0x0001, ETH_VLAN));
    pkt.extend_from_slice(&vlan(0x0064, ETH_IPV4));
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 8));
    assert_verdict(run(&pkt), "QinQ double tag");
}

#[test]
fn vlan_legacy_qinq_variants() {
    // Legacy non-standard QinQ EtherTypes are stripped too.
    for et in [ETH_QINQ_LEGACY1, ETH_QINQ_LEGACY2, ETH_QINQ_LEGACY3] {
        let mut pkt = eth(DMAC, SMAC, et);
        pkt.extend_from_slice(&vlan(0x0001, ETH_VLAN));
        pkt.extend_from_slice(&vlan(0x0064, ETH_IPV4));
        pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
        pkt.extend_from_slice(&udp(12345, 53, 8));
        assert_verdict(run(&pkt), &format!("legacy QinQ {et:#06x}"));
    }
}

#[test]
fn vlan_inner_unknown_ethertype() {
    // Tagged, but the inner EtherType is unknown — must not abort or PASS as IP.
    let mut pkt = eth(DMAC, SMAC, ETH_VLAN);
    pkt.extend_from_slice(&vlan(0x0064, 0x1234));
    assert_ne!(run(&pkt), XDP_ABORTED, "VLAN with unknown inner EtherType must not abort");
}

#[test]
fn vlan_truncated_tag() {
    // Only half a VLAN tag (2 of 4 bytes) present after the TPID.
    let mut pkt = eth(DMAC, SMAC, ETH_VLAN);
    pkt.extend_from_slice(&[0x00, 0x64]);
    assert_ne!(run(&pkt), XDP_PASS, "truncated VLAN tag must not be parsed as a valid packet");
}

#[test]
fn vlan_then_arp_passed() {
    // A VLAN-tagged ARP frame still needs L2 resolution and passes.
    let mut pkt = eth(DMAC, SMAC, ETH_VLAN);
    pkt.extend_from_slice(&vlan(0x0064, ETH_ARP));
    pkt.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
    assert_eq!(run(&pkt), XDP_PASS, "VLAN-tagged ARP must pass for L2 resolution");
}

// ===========================================================================
// 6. Edge cases
// ===========================================================================

/// Generic IPv6 extension header: next header byte + Hdr Ext Len.
fn ipv6_eh_generic(next_hdr: u8, ext_len: u8) -> Vec<u8> {
    let actual = ((ext_len as usize) + 1) * 8;
    let mut buf = vec![0u8; actual];
    buf[0] = next_hdr;
    buf[1] = ext_len;
    buf
}

#[test]
fn edge_ipv6_hop_by_hop_then_tcp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    let eh = ipv6_eh_generic(IPPROTO_TCP, 0);
    pkt.extend_from_slice(&ipv6(IPV6_HOP_BY_HOP, (eh.len() + 20) as u16, SRC_V6, DST_V6));
    pkt.extend_from_slice(&eh);
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "IPv6 hop-by-hop + TCP");
}

#[test]
fn edge_ipv6_routing_header_then_udp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    let eh = ipv6_eh_generic(IPPROTO_UDP, 0);
    pkt.extend_from_slice(&ipv6(IPV6_ROUTING, (eh.len() + 8) as u16, SRC_V6, DST_V6));
    pkt.extend_from_slice(&eh);
    pkt.extend_from_slice(&udp(12345, 53, 8));
    assert_verdict(run(&pkt), "IPv6 routing header + UDP");
}

#[test]
fn edge_ipv6_dest_opts_then_tcp() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    let eh = ipv6_eh_generic(IPPROTO_TCP, 1);
    pkt.extend_from_slice(&ipv6(IPV6_DEST_OPTS, (eh.len() + 20) as u16, SRC_V6, DST_V6));
    pkt.extend_from_slice(&eh);
    pkt.extend_from_slice(&tcp(12345, 443, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "IPv6 dest options + TCP");
}

#[test]
fn edge_ipv6_fragment_non_first() {
    // IPv6 fragment header, non-first fragment → L4 unreachable; must not abort
    // and must not be classified as TCP (which would be unsafe).
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(IPV6_FRAGMENT, 8, SRC_V6, DST_V6));
    // frag header: next header TCP, offset=1 (0x0008), M=0
    pkt.extend_from_slice(&[IPPROTO_TCP, 0, 0x00, 0x08, 0, 0, 0, 0]);
    assert_ne!(run(&pkt), XDP_ABORTED, "IPv6 non-first fragment must not abort");
}

#[test]
fn edge_ipv6_auth_header() {
    // AH length in 4-octet units: (len + 2) * 4.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    let ah_len: usize = 12;
    pkt.extend_from_slice(&ipv6(IPV6_AUTH, ah_len as u16, SRC_V6, DST_V6));
    let mut ah = vec![0u8; ah_len];
    ah[0] = IPPROTO_TCP;
    ah[1] = 1; // (1 + 2) * 4 = 12
    pkt.extend_from_slice(&ah);
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "IPv6 AH + TCP");
}

#[test]
fn edge_ipv6_esp_terminates_chain() {
    // ESP is opaque — parser must return without port classification, not abort.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(IPV6_ESP, 8, SRC_V6, DST_V6));
    pkt.extend_from_slice(&[0u8; 8]);
    assert_ne!(run(&pkt), XDP_ABORTED, "IPv6 ESP must not abort");
}

#[test]
fn edge_ipv4_fragmented_first() {
    // MF flag set (0x2000): first fragment; parser should avoid trusting L4 ports.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x2000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "IPv4 first fragment");
}

#[test]
fn edge_ipv4_fragment_offset_nonzero() {
    // Fragment offset = 1 (0x00 0x0→ 0x0008 in 8-byte units).
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x0008, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_ne!(run(&pkt), XDP_ABORTED, "non-zero fragment offset must not abort");
}

#[test]
fn edge_oversized_jumbo_frame() {
    // Well-formed beyond standard MTU (1500); should remain a normal verdict.
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 8 + 1600, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 8 + 1600));
    pkt.extend_from_slice(&vec![0x42; 1600]);
    assert_verdict(run(&pkt), "jumbo frame");
}

#[test]
fn edge_broadcast_dmac() {
    let mut pkt = eth([0xFF; 6], SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));
    assert_verdict(run(&pkt), "broadcast DMAC");
}

#[test]
fn edge_multicast_dmac() {
    let mut pkt = eth([0x01, 0x00, 0x5E, 0x00, 0x00, 0x01], SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 8));
    assert_verdict(run(&pkt), "multicast DMAC");
}

// ===========================================================================
// 7. Policy rules (LISTENER_POLICIES + PORT_RULES_V4/V6)
// ===========================================================================

/// Runs a packet against a program whose maps are seeded by `seed`.
fn run_with_maps(packet: &[u8], seed: impl FnOnce(&mut Ebpf)) -> u32 {
    let mut bpf = Ebpf::load(XDP_BYTES).expect("failed to load BPF object");
    seed(&mut bpf);
    let program = bpf.program_mut("xdp_ingress").expect("failed to find xdp_ingress program");
    let program: &mut Xdp = program.try_into().expect("failed to convert to Xdp");
    program.load().expect("failed to load XDP program");

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(packet);
    program.test_run(opts).expect("BPF_PROG_TEST_RUN failed").return_value
}

/// Seeds `LISTENER_POLICIES` for `port` with the given default action.
fn seed_listener(bpf: &mut Ebpf, port: u16, default_action: u8) {
    let mut map: HashMap<&mut aya::maps::MapData, u16, ListenerPolicy> =
        HashMap::try_from(bpf.map_mut("LISTENER_POLICIES").expect("LISTENER_POLICIES map"))
            .expect("LISTENER_POLICIES must be a HashMap");
    map.insert(port, ListenerPolicy { default_action }, 0).expect("insert listener policy");
}

/// Seeds `PORT_RULES_V4` with a PASS/DROP rule for `(port, cidr)`.
fn seed_rule_v4(bpf: &mut Ebpf, port: u16, cidr: ([u8; 4], u8), action: u8) {
    let mut map: LpmTrie<&mut aya::maps::MapData, PortRuleKeyV4, u8> =
        LpmTrie::try_from(bpf.map_mut("PORT_RULES_V4").expect("PORT_RULES_V4 map")).expect("PORT_RULES_V4 must be an LpmTrie");
    let client_ip = u32::from_be_bytes(cidr.0);
    let prefix = 16 + cidr.1; // 16 bits port + CIDR bits
    let key = Key::new(prefix as u32, PortRuleKeyV4 { port, client_ip });
    map.insert(&key, action, 0).expect("insert PORT_RULES_V4 rule");
}

/// Seeds `PORT_RULES_V6` with a PASS/DROP rule for `(port, cidr)`.
fn seed_rule_v6(bpf: &mut Ebpf, port: u16, cidr: ([u8; 16], u8), action: u8) {
    let mut map: LpmTrie<&mut aya::maps::MapData, PortRuleKeyV6, u8> =
        LpmTrie::try_from(bpf.map_mut("PORT_RULES_V6").expect("PORT_RULES_V6 map")).expect("PORT_RULES_V6 must be an LpmTrie");
    let prefix = 16 + cidr.1; // 16 bits port + CIDR bits
    let key = Key::new(prefix as u32, PortRuleKeyV6 { port, client_ip: cidr.0 });
    map.insert(&key, action, 0).expect("insert PORT_RULES_V6 rule");
}

/// IPv4/TCP frame toward `dport` from `src`.
fn tcp_v4(src: [u8; 4], dport: u16) -> Vec<u8> {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, src, DST_V4));
    pkt.extend_from_slice(&tcp(12345, dport, doff_flags(5, SYN)));
    pkt
}

/// IPv6/TCP frame toward `dport` from `src`.
fn tcp_v6(src: [u8; 16], dport: u16) -> Vec<u8> {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV6);
    pkt.extend_from_slice(&ipv6(IPPROTO_TCP, 20, src, DST_V6));
    pkt.extend_from_slice(&tcp(12345, dport, doff_flags(5, SYN)));
    pkt
}

const OTHER_V4: [u8; 4] = [10, 0, 0, 99];
const OTHER_V6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

#[test]
fn policy_no_listener_passes() {
    // Destination port has no listener entry → default PASS.
    assert_eq!(run(&tcp_v4(SRC_V4, 80)), XDP_PASS, "port without listener policy must PASS");
}

#[test]
fn policy_listener_allow_passes() {
    // Listener default ALLOW → PASS with no explicit rule.
    let ret = run_with_maps(&tcp_v4(SRC_V4, 80), |bpf| seed_listener(bpf, 80, DEFAULT_ALLOW));
    assert_eq!(ret, XDP_PASS, "listener default ALLOW must PASS");
}

#[test]
fn policy_listener_deny_drops() {
    // Listener default DENY → DROP with no explicit rule.
    let ret = run_with_maps(&tcp_v4(SRC_V4, 80), |bpf| seed_listener(bpf, 80, DEFAULT_DENY));
    assert_eq!(ret, XDP_DROP, "listener default DENY must DROP");
}

#[test]
fn policy_v4_host_pass_rule_wins() {
    // DENY listener + explicit /32 PASS for SRC_V4 → only that IP passes.
    let ret = run_with_maps(&tcp_v4(SRC_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_DENY);
        seed_rule_v4(bpf, 80, (SRC_V4, 32), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_PASS, "explicit /32 PASS must override listener DENY");

    let ret = run_with_maps(&tcp_v4(OTHER_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_DENY);
        seed_rule_v4(bpf, 80, (SRC_V4, 32), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_DROP, "non-matching source must fall back to listener DENY");
}

#[test]
fn policy_v4_host_drop_rule_wins() {
    // ALLOW listener + explicit /32 DROP for SRC_V4 → only that IP drops.
    let ret = run_with_maps(&tcp_v4(SRC_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_ALLOW);
        seed_rule_v4(bpf, 80, (SRC_V4, 32), RULE_ACTION_DROP);
    });
    assert_eq!(ret, XDP_DROP, "explicit /32 DROP must override listener ALLOW");

    let ret = run_with_maps(&tcp_v4(OTHER_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_ALLOW);
        seed_rule_v4(bpf, 80, (SRC_V4, 32), RULE_ACTION_DROP);
    });
    assert_eq!(ret, XDP_PASS, "non-matching source must fall back to listener ALLOW");
}

#[test]
fn policy_v4_cidr_pass_rule() {
    // DENY listener + /24 PASS covering SRC_V4's subnet.
    let ret = run_with_maps(&tcp_v4(SRC_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_DENY);
        seed_rule_v4(bpf, 80, ([192, 168, 1, 0], 24), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_PASS, "source inside /24 must match the CIDR PASS rule");

    let ret = run_with_maps(&tcp_v4(OTHER_V4, 80), |bpf| {
        seed_listener(bpf, 80, DEFAULT_DENY);
        seed_rule_v4(bpf, 80, ([192, 168, 1, 0], 24), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_DROP, "source outside /24 must fall back to listener DENY");
}

#[test]
fn policy_v6_host_pass_rule_wins() {
    let ret = run_with_maps(&tcp_v6(SRC_V6, 443), |bpf| {
        seed_listener(bpf, 443, DEFAULT_DENY);
        seed_rule_v6(bpf, 443, (SRC_V6, 128), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_PASS, "explicit /128 PASS must override listener DENY");

    let ret = run_with_maps(&tcp_v6(OTHER_V6, 443), |bpf| {
        seed_listener(bpf, 443, DEFAULT_DENY);
        seed_rule_v6(bpf, 443, (SRC_V6, 128), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_DROP, "non-matching IPv6 source must fall back to listener DENY");
}

#[test]
fn policy_v6_cidr_pass_rule() {
    // DENY listener + /64 PASS covering SRC_V6 (2001:db8::/64).
    let mut subnet = [0u8; 16];
    subnet[..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);

    let ret = run_with_maps(&tcp_v6(SRC_V6, 443), |bpf| {
        seed_listener(bpf, 443, DEFAULT_DENY);
        seed_rule_v6(bpf, 443, (subnet, 64), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_PASS, "source inside /64 must match the CIDR PASS rule");

    let ret = run_with_maps(&tcp_v6(OTHER_V6, 443), |bpf| {
        seed_listener(bpf, 443, DEFAULT_DENY);
        seed_rule_v6(bpf, 443, (subnet, 64), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_DROP, "source outside /64 must fall back to listener DENY");
}

#[test]
fn policy_v4_vlan_tagged_packet() {
    // VLAN-tagged packet must strip the tag before evaluating the port policy.
    let mut pkt = eth(DMAC, SMAC, ETH_VLAN);
    pkt.extend_from_slice(&vlan(0x0064, ETH_IPV4));
    pkt.extend_from_slice(&ipv4(IPPROTO_TCP, 40, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&tcp(12345, 80, doff_flags(5, SYN)));

    let ret = run_with_maps(&pkt, |bpf| {
        seed_listener(bpf, 80, DEFAULT_DENY);
        seed_rule_v4(bpf, 80, (SRC_V4, 32), RULE_ACTION_PASS);
    });
    assert_eq!(
        ret, XDP_PASS,
        "VLAN-tagged IPv4/TCP must be evaluated against the port policy"
    );
}

#[test]
fn policy_v4_udp_to_listener() {
    let mut pkt = eth(DMAC, SMAC, ETH_IPV4);
    pkt.extend_from_slice(&ipv4(IPPROTO_UDP, 28, 0x4000, SRC_V4, DST_V4));
    pkt.extend_from_slice(&udp(12345, 53, 8));

    let ret = run_with_maps(&pkt, |bpf| {
        seed_listener(bpf, 53, DEFAULT_DENY);
        seed_rule_v4(bpf, 53, (SRC_V4, 32), RULE_ACTION_PASS);
    });
    assert_eq!(ret, XDP_PASS, "UDP to a listener port must be evaluated by policy");

    let ret = run_with_maps(&pkt, |bpf| {
        seed_listener(bpf, 53, DEFAULT_DENY);
        seed_rule_v4(bpf, 53, (SRC_V4, 32), RULE_ACTION_DROP);
    });
    assert_eq!(ret, XDP_DROP, "UDP to a denied source must DROP");
}
