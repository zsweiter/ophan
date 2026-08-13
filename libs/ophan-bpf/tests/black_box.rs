//! Black-box tests for the `xdp_ingress` eBPF program.
//!
//! All packets are constructed manually as raw byte slices (big-endian network
//! byte order) and injected via `BPF_PROG_TEST_RUN`. The tests only inspect
//! the return value (`XDP_PASS` / `XDP_DROP` / `XDP_ABORTED`) — no effort is
//! made to fix or patch the program under test.

use aya::Ebpf;
use aya::programs::Xdp;
use aya::programs::{TestRun, TestRunOptions};
use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};

// ---------------------------------------------------------------------------
// BPF program loader
// ---------------------------------------------------------------------------

pub const XDP_BYTES: &[u8] = include_bytes!("../../../target/bpfel-unknown-none/release/ophan-bpf");

fn with_xdp_program<T>(f: impl FnOnce(&mut Xdp) -> T) -> T {
    let mut bpf = Ebpf::load(XDP_BYTES).expect("failed to load BPF object");
    let program = bpf.program_mut("xdp_ingress").expect("failed to find xdp_ingress program");
    let program: &mut Xdp = program.try_into().expect("failed to convert to Xdp");
    program.load().expect("failed to load XDP program");
    f(program)
}

fn run(packet: &[u8]) -> u32 {
    with_xdp_program(|program| {
        let mut opts = TestRunOptions::default();
        opts.data_in = Some(packet);
        program.test_run(opts).expect("BPF_PROG_TEST_RUN failed").return_value
    })
}

// ---------------------------------------------------------------------------
// Low-level packet building helpers
// ---------------------------------------------------------------------------

fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

const fn mac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> [u8; 6] {
    [a, b, c, d, e, f]
}

const fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

const ETH_IPV4: [u8; 2] = [0x08, 0x00];
const ETH_IPV6: [u8; 2] = [0x86, 0xDD];
const ETH_ARP: [u8; 2] = [0x08, 0x06];
const ETH_VLAN: [u8; 2] = [0x81, 0x00];
const ETH_QINQ: [u8; 2] = [0x88, 0xA8];

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// ---- Ethernet II ----------------------------------------------------------

fn eth_hdr(dst: &[u8; 6], src: &[u8; 6], ethertype: &[u8; 2]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14);
    buf.extend_from_slice(dst);
    buf.extend_from_slice(src);
    buf.extend_from_slice(ethertype);
    buf
}

fn vlan_tag(tci: &[u8; 2], inner_ethertype: &[u8; 2]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(tci);
    buf.extend_from_slice(inner_ethertype);
    buf
}

// ---- IPv4 -----------------------------------------------------------------

fn ipv4_hdr(ihl: u8, total_len: u16, ident: u16, flags_frag: u16, ttl: u8, proto: u8, src: &[u8; 4], dst: &[u8; 4]) -> Vec<u8> {
    let hdr_len = (ihl as u16) * 4;
    let mut buf = vec![0u8; hdr_len as usize];
    buf[0] = (4 << 4) | (ihl & 0x0F);
    buf[1] = 0; // DSCP/ECN
    buf[2..4].copy_from_slice(&u16be(total_len));
    buf[4..6].copy_from_slice(&u16be(ident));
    buf[6..8].copy_from_slice(&u16be(flags_frag));
    buf[8] = ttl;
    buf[9] = proto;
    // checksum bytes 10-11 left as 0
    buf[12..16].copy_from_slice(src);
    buf[16..20].copy_from_slice(dst);
    buf
}

// ---- IPv6 -----------------------------------------------------------------

fn ipv6_hdr(payload_len: u16, next_hdr: u8, hop_limit: u8, src: &[u8; 16], dst: &[u8; 16]) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    // Version 6, Traffic Class 0, Flow Label 0
    buf[0] = 0x60;
    buf[4..6].copy_from_slice(&u16be(payload_len));
    buf[6] = next_hdr;
    buf[7] = hop_limit;
    buf[8..24].copy_from_slice(src);
    buf[24..40].copy_from_slice(dst);
    buf
}

// ---- TCP ------------------------------------------------------------------

fn tcp_hdr(sport: u16, dport: u16, seq: u32, ack: u32, data_offset_flags: u16, window: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 20];
    buf[0..2].copy_from_slice(&u16be(sport));
    buf[2..4].copy_from_slice(&u16be(dport));
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12..14].copy_from_slice(&u16be(data_offset_flags));
    buf[14..16].copy_from_slice(&u16be(window));
    // checksum bytes 16-18 left as 0
    // urgent pointer bytes 18-20 left as 0
    buf
}

/// Build a TCP flags byte for the tcp header.
/// flags goes in the lower 8 bits of data_offset_flags.
fn tcp_flags(urg: bool, ack: bool, psh: bool, rst: bool, syn: bool, fin: bool) -> u8 {
    let mut f = 0u8;
    if fin {
        f |= 0x01;
    }
    if syn {
        f |= 0x02;
    }
    if rst {
        f |= 0x04;
    }
    if psh {
        f |= 0x08;
    }
    if ack {
        f |= 0x10;
    }
    if urg {
        f |= 0x20;
    }
    f
}

fn tcp_data_offset_flags(data_offset_4b: u8, flags: u8) -> u16 {
    ((data_offset_4b as u16) << 12) | (flags as u16)
}

// ---- UDP ------------------------------------------------------------------

fn udp_hdr(sport: u16, dport: u16, len: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 8];
    buf[0..2].copy_from_slice(&u16be(sport));
    buf[2..4].copy_from_slice(&u16be(dport));
    buf[4..6].copy_from_slice(&u16be(len));
    // checksum bytes 6-8 left as 0
    buf
}

// ---------------------------------------------------------------------------
// Full frame builders
// ---------------------------------------------------------------------------

fn build_ipv4_tcp(
    dmac: &[u8; 6],
    smac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    sport: u16,
    dport: u16,
    tcp_data_offset_flags: u16,
    tcp_window: u16,
    tcp_payload: &[u8],
) -> Vec<u8> {
    let tcp = tcp_hdr(sport, dport, 0, 0, tcp_data_offset_flags, tcp_window);
    let total_len = 20 + tcp.len() + tcp_payload.len();
    let ip = ipv4_hdr(5, total_len as u16, 0, 0x4000, 64, IPPROTO_TCP, src_ip, dst_ip);

    let mut frame = eth_hdr(dmac, smac, &ETH_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(tcp_payload);
    frame
}

fn build_ipv4_udp(
    dmac: &[u8; 6],
    smac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len() as u16;
    let udp = udp_hdr(sport, dport, udp_len);
    let total_len = 20 + udp.len() + payload.len();
    let ip = ipv4_hdr(5, total_len as u16, 0, 0x4000, 64, IPPROTO_UDP, src_ip, dst_ip);

    let mut frame = eth_hdr(dmac, smac, &ETH_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame.extend_from_slice(payload);
    frame
}

fn build_ipv6_tcp(
    dmac: &[u8; 6],
    smac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    sport: u16,
    dport: u16,
    tcp_data_offset_flags: u16,
    tcp_window: u16,
    tcp_payload: &[u8],
) -> Vec<u8> {
    let tcp = tcp_hdr(sport, dport, 0, 0, tcp_data_offset_flags, tcp_window);
    let payload_len = tcp.len() + tcp_payload.len();
    let ip = ipv6_hdr(payload_len as u16, IPPROTO_TCP, 64, src_ip, dst_ip);

    let mut frame = eth_hdr(dmac, smac, &ETH_IPV6);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame.extend_from_slice(tcp_payload);
    frame
}

fn build_vlan_ipv4_udp(
    dmac: &[u8; 6],
    smac: &[u8; 6],
    vlan_tci: &[u8; 2],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp = udp_hdr(sport, dport, 8 + payload.len() as u16);
    let total_len = 20 + udp.len() + payload.len();
    let ip = ipv4_hdr(5, total_len as u16, 0, 0x4000, 64, IPPROTO_UDP, src_ip, dst_ip);

    let mut frame = eth_hdr(dmac, smac, &ETH_VLAN);
    frame.extend_from_slice(&vlan_tag(vlan_tci, &ETH_IPV4));
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame.extend_from_slice(payload);
    frame
}

// ---------------------------------------------------------------------------
// Common MAC / IP constants
// ---------------------------------------------------------------------------

const DMAC: [u8; 6] = mac(0x00, 0x15, 0x5D, 0x01, 0x02, 0x03);
const SMAC: [u8; 6] = mac(0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC);
const SRC_V4: [u8; 4] = ipv4(192, 168, 1, 50);
const DST_V4: [u8; 4] = ipv4(10, 0, 0, 1);
const SRC_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const DST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

// ===========================================================================
// TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Valid traffic (baseline)
// ---------------------------------------------------------------------------

#[test]
fn valid_tcp_v4_to_port_80() {
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false)); // SYN
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    // Expect PASS or DROP depending on installed port/CIDR rules
    eprintln!("[RESULT] valid_tcp_v4_to_port_80 = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn valid_tcp_v4_to_port_443() {
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 443, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] valid_tcp_v4_to_port_443 = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn valid_udp_v4_dns_query() {
    let pkt = build_ipv4_udp(
        &DMAC,
        &SMAC,
        &SRC_V4,
        &DST_V4,
        54321,
        53,
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
    );
    let ret = run(&pkt);
    eprintln!("[RESULT] valid_udp_v4_dns_query = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn valid_tcp_v6_to_port_443() {
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv6_tcp(&DMAC, &SMAC, &SRC_V6, &DST_V6, 12345, 443, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] valid_tcp_v6_to_port_443 = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn valid_vlan_tagged_udp() {
    let pkt = build_vlan_ipv4_udp(&DMAC, &SMAC, &[0x00, 0x64], &SRC_V4, &DST_V4, 54321, 53, b"PING");
    let ret = run(&pkt);
    eprintln!("[RESULT] valid_vlan_tagged_udp = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

// ---------------------------------------------------------------------------
// Attack vectors
// ---------------------------------------------------------------------------

#[test]
fn tcp_xmas_scan_all_flags() {
    // All flags set: URG|ACK|PSH|RST|SYN|FIN = 0x3F
    let flags = tcp_data_offset_flags(5, 0x3F);
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_xmas_scan_all_flags = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: Xmas scan (all flags) not dropped");
    }
}

#[test]
fn tcp_xmas_scan_urg_psh_fin() {
    // URG|PSH|FIN = 0x29
    let flags = tcp_data_offset_flags(5, 0x29);
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_xmas_scan_urg_psh_fin = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: Xmas scan (URG|PSH|FIN=0x29) not dropped");
    }
}

#[test]
fn tcp_null_scan() {
    // All flags cleared
    let flags = tcp_data_offset_flags(5, 0x00);
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_null_scan = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: Null scan (flags=0x00) not dropped");
    }
}

#[test]
fn tcp_syn_fin_scan() {
    // SYN|FIN = 0x03
    let flags = tcp_data_offset_flags(5, 0x03);
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_syn_fin_scan = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: SYN-FIN scan (0x03) not dropped");
    }
}

#[test]
fn tcp_land_attack() {
    // src_ip == dst_ip, sport == dport
    let local: [u8; 4] = ipv4(10, 0, 0, 1);
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &local, &local, 80, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_land_attack = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: LAND attack not dropped");
    }
}

#[test]
fn udp_land_attack() {
    let local: [u8; 4] = ipv4(10, 0, 0, 1);
    let pkt = build_ipv4_udp(&DMAC, &SMAC, &local, &local, 53, 53, b"\x00\x01\x01\x00");
    let ret = run(&pkt);
    eprintln!("[RESULT] udp_land_attack = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: UDP LAND attack not dropped");
    }
}

// ---------------------------------------------------------------------------
// Malformed / truncated packets
// ---------------------------------------------------------------------------

#[test]
fn empty_packet() {
    let ret = run(&[]);
    eprintln!("[RESULT] empty_packet = {ret}");
    // Should be DROP or ABORTED, never PASS
    assert_ne!(ret, XDP_PASS, "empty packet must not PASS");
}

#[test]
fn truncated_ethernet() {
    // Only 13 bytes instead of 14
    let pkt = &[0x00u8; 13];
    let ret = run(pkt);
    eprintln!("[RESULT] truncated_ethernet = {ret}");
    assert_ne!(ret, XDP_PASS, "truncated ethernet must not PASS");
}

#[test]
fn ethernet_only_no_ip() {
    // Valid Ethernet but EtherType is ARP (not IP)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_ARP);
    pkt.extend_from_slice(b"\x00\x01\x08\x00\x06\x04\x00\x01");
    let ret = run(&pkt);
    eprintln!("[RESULT] ethernet_only_no_ip = {ret}");
    if ret == XDP_PASS {
        eprintln!("  NOTE: ARP packets are passed through (expected if filter only inspects IP)");
    }
}

#[test]
fn truncated_ipv4_no_header() {
    // Ethernet header only, no IP
    let pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    let ret = run(&pkt);
    eprintln!("[RESULT] truncated_ipv4_no_header = {ret}");
    assert_ne!(ret, XDP_PASS, "Ethernet without IP data must not PASS");
}

#[test]
fn truncated_ipv4_partial() {
    // Ethernet + only 10 bytes of IPv4 header (needs 20)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06]);
    let ret = run(&pkt);
    eprintln!("[RESULT] truncated_ipv4_partial = {ret}");
    assert_ne!(ret, XDP_PASS, "partial IPv4 header must not PASS");
}

#[test]
fn ipv4_ihl_less_than_5() {
    // IHL=4 (byte 0 = 0x44) — invalid, minimum is 5
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.push(0x44);
    pkt.extend_from_slice(&[0x00; 19]); // rest of "header"
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_ihl_less_than_5 = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: IHL<5 not dropped");
    }
}

#[test]
fn ipv4_ihl_zero() {
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.push(0x40); // IHL=0
    pkt.extend_from_slice(&[0x00; 19]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_ihl_zero = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: IHL=0 not dropped");
    }
}

#[test]
fn ipv4_ihl_larger_than_packet() {
    // IHL=15 (60 bytes) but packet is only 34 bytes
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.push(0x4F); // Version=4, IHL=15
    pkt.extend_from_slice(&[0x00; 19]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_ihl_larger_than_packet = {ret}");
    assert_ne!(ret, XDP_PASS, "IHL exceeding packet size must not PASS");
}

#[test]
fn ipv4_total_length_exceeds_packet() {
    // Set total_len = 65535 but packet is much smaller
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    // Version=4, IHL=5, total_len=0xFFFF
    pkt.extend_from_slice(&[0x45, 0x00, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_total_length_exceeds_packet = {ret}");
    assert_ne!(ret, XDP_PASS, "packet with inflated total_len must not PASS");
}

#[test]
fn ipv4_total_length_less_than_ihl() {
    // total_len = 8, IHL = 5 (minimum 20 bytes header)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_total_length_less_than_ihl = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: total_len < ihl not dropped");
    }
}

#[test]
fn ipv4_fragmented() {
    // MF flag set, fragment offset = 0 (first fragment)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x20, 0x00, 0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    // Fake TCP header (may not be parsed since it's a fragment)
    pkt.extend_from_slice(&[0x00; 8]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_fragmented = {ret}");
    if ret != XDP_DROP {
        eprintln!("  NOTE: fragmented packet passed (program may allow first fragments)");
    }
}

#[test]
fn ipv4_non_zero_fragment_offset() {
    // Fragment offset = 1 (0x00 0x02 in flags/frag field = 0x0002)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x02, 0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    pkt.extend_from_slice(&[0x00; 8]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_non_zero_fragment_offset = {ret}");
    if ret != XDP_DROP {
        eprintln!("  NOTE: non-zero fragment offset passed");
    }
}

#[test]
fn truncated_ipv4_no_l4() {
    // IHL=5 (20 bytes), total_len=20 — no room for L4
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&SRC_V4);
    pkt.extend_from_slice(&DST_V4);
    let ret = run(&pkt);
    eprintln!("[RESULT] truncated_ipv4_no_l4 = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: IPv4 with no room for L4 not dropped");
    }
}

#[test]
fn truncated_tcp_header() {
    // Only 10 bytes of TCP header (needs 20)
    let ip = ipv4_hdr(5, 30, 0, 0x4000, 64, IPPROTO_TCP, &SRC_V4, &DST_V4);
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&[0x00; 10]); // truncated TCP
    let ret = run(&pkt);
    eprintln!("[RESULT] truncated_tcp_header = {ret}");
    assert_ne!(ret, XDP_PASS, "truncated TCP header must not PASS");
}

#[test]
fn truncated_udp_header() {
    // Only 4 bytes of UDP header (needs 8)
    let ip = ipv4_hdr(5, 24, 0, 0x4000, 64, IPPROTO_UDP, &SRC_V4, &DST_V4);
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&[0x00; 4]); // truncated UDP
    let ret = run(&pkt);
    eprintln!("[RESULT] truncated_udp_header = {ret}");
    assert_ne!(ret, XDP_PASS, "truncated UDP header must not PASS");
}

#[test]
fn tcp_data_offset_less_than_5() {
    // data_offset = 4 (0x40 in the flags byte) — minimum is 5
    // data_offset_flags = (4 << 12) | SYN
    let doff_flags = tcp_data_offset_flags(4, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, doff_flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_data_offset_less_than_5 = {ret}");
    if ret != XDP_DROP {
        eprintln!("  WARNING: TCP data_offset < 5 not dropped");
    }
}

// ---------------------------------------------------------------------------
// Unusual / edge-case protocol fields
// ---------------------------------------------------------------------------

#[test]
fn ipv4_ttl_zero() {
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let mut pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    // Overwrite TTL at offset 14+8 = 22
    pkt[22] = 0;
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_ttl_zero = {ret}");
    // TTL=0 is technically invalid but may be passed by a stateless filter
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn ipv4_protocol_zero() {
    // Protocol 0 (HOPOPT / IPv6 Hop-by-Hop) — should not crash
    let ip = ipv4_hdr(5, 28, 0, 0x4000, 64, 0, &SRC_V4, &DST_V4);
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&[0x00; 8]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_protocol_zero = {ret}");
    assert_ne!(ret, XDP_ABORTED, "protocol 0 must not ABORT");
}

#[test]
fn ipv4_protocol_255() {
    // Protocol 255 (Reserved) — should not crash
    let ip = ipv4_hdr(5, 28, 0, 0x4000, 64, 255, &SRC_V4, &DST_V4);
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_IPV4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&[0x00; 8]);
    let ret = run(&pkt);
    eprintln!("[RESULT] ipv4_protocol_255 = {ret}");
    assert_ne!(ret, XDP_ABORTED, "protocol 255 must not ABORT");
}

#[test]
fn udp_port_zero() {
    let pkt = build_ipv4_udp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 0, 0, b"data");
    let ret = run(&pkt);
    eprintln!("[RESULT] udp_port_zero = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn tcp_port_zero() {
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&DMAC, &SMAC, &SRC_V4, &DST_V4, 0, 0, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] tcp_port_zero = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn broadcast_dmac() {
    let bcast = [0xFFu8; 6];
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&bcast, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] broadcast_dmac = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn multicast_dmac() {
    let mcast = mac(0x01, 0x00, 0x5E, 0x00, 0x00, 0x01);
    let flags = tcp_data_offset_flags(5, tcp_flags(false, false, false, false, true, false));
    let pkt = build_ipv4_tcp(&mcast, &SMAC, &SRC_V4, &DST_V4, 12345, 80, flags, 65535, b"");
    let ret = run(&pkt);
    eprintln!("[RESULT] multicast_dmac = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn invalid_ethertype() {
    // Random EtherType 0x1234 (not IP/ARP/VLAN)
    let mut pkt = eth_hdr(&DMAC, &SMAC, &[0x12, 0x34]);
    pkt.extend_from_slice(b"\x00\x01\x02\x03\x04\x05\x06\x07");
    let ret = run(&pkt);
    eprintln!("[RESULT] invalid_ethertype = {ret}");
    // Likely PASS since the filter probably only inspects IP packets
    if ret != XDP_DROP {
        eprintln!("  NOTE: non-IP EtherType not dropped (program may only parse IPv4/IPv6)");
    }
}

// ---------------------------------------------------------------------------
// VLAN / QinQ edge cases
// ---------------------------------------------------------------------------

#[test]
fn qinq_double_tagged_udp() {
    // Outer S-Tag (0x88A8), Inner C-Tag (0x8100), then IPv4
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_QINQ);
    pkt.extend_from_slice(&vlan_tag(&[0x00, 0x01], &ETH_VLAN)); // S-tag
    pkt.extend_from_slice(&vlan_tag(&[0x00, 0x64], &ETH_IPV4)); // C-tag (with IPv4)
    let ip = ipv4_hdr(5, 28, 0, 0x4000, 64, IPPROTO_UDP, &SRC_V4, &DST_V4);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp_hdr(12345, 53, 8));
    let ret = run(&pkt);
    eprintln!("[RESULT] qinq_double_tagged_udp = {ret}");
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

#[test]
fn vlan_with_unknown_ethertype() {
    // VLAN tag but inner EtherType is not IP
    let mut pkt = eth_hdr(&DMAC, &SMAC, &ETH_VLAN);
    pkt.extend_from_slice(&vlan_tag(&[0x00, 0x64], &ETH_ARP));
    let ret = run(&pkt);
    eprintln!("[RESULT] vlan_with_unknown_ethertype = {ret}");
    assert_ne!(ret, XDP_ABORTED, "must not ABORT on unknown inner EtherType");
}

// ---------------------------------------------------------------------------
// Jumbo frames / size edge cases
// ---------------------------------------------------------------------------

#[test]
fn oversized_packet() {
    // Build a jumbo-ish frame (2000 bytes) with valid headers
    let big_payload = vec![0x42u8; 1972]; // 14 + 4(vlan) + 20(ip) + 8(udp) + 1972 = 2018
    let pkt = build_vlan_ipv4_udp(&DMAC, &SMAC, &[0x00, 0x64], &SRC_V4, &DST_V4, 12345, 53, &big_payload);
    let ret = run(&pkt);
    eprintln!("[RESULT] oversized_packet = {ret}");
    // Standard MTU is 1500, XDP may drop >MTU or the verifier may allow it
    assert!(ret == XDP_PASS || ret == XDP_DROP, "expected PASS(2) or DROP(1), got {ret}");
}

// ---------------------------------------------------------------------------
// Reproducibility / the original test
// ---------------------------------------------------------------------------

#[test]
fn original_test_lpm_and_port() {
    // This is the original test: 4 raw bytes [10, 0, 5, 23]
    let ret = run(&[10u8, 0, 5, 23]);
    eprintln!("[RESULT] original_test_lpm_and_port = {ret}");
    // Original assertion was ret == 1 (XDP_DROP)
    assert_eq!(ret, XDP_DROP, "original 4-byte test expected DROP(1)");
}
