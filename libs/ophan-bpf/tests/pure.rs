use ophan_bpf::pure;

// ---------------------------------------------------------------------------
// Packet builder helpers — build raw Ethernet frames byte-by-byte
// ---------------------------------------------------------------------------

/// Minimal Ethernet header (14 bytes): dst(6) + src(6) + ether_type(2).
fn build_eth(dst: &[u8; 6], src: &[u8; 6], ether_type: u16) -> [u8; 14] {
    let mut buf = [0u8; 14];
    buf[..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    buf[12..14].copy_from_slice(&ether_type.to_be_bytes());
    buf
}

/// IPv4 header (20 bytes, no options).
fn build_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, total_len: u16) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0] = 0x45; // Version=4, IHL=5
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + frag offset
    buf[8] = 64; // TTL
    buf[9] = proto;
    buf[10] = 0; // checksum (omitted — not validated by XDP)
    buf[11] = 0;
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    buf
}

/// IPv6 header (40 bytes).
fn build_ipv6(src: &[u8; 16], dst: &[u8; 16], next_hdr: u8, payload_len: u16) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0] = 0x60; // Version=6
    buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
    buf[6] = next_hdr;
    buf[7] = 64; // Hop Limit
    buf[8..24].copy_from_slice(src);
    buf[24..40].copy_from_slice(dst);
    buf
}

/// TCP header (20 bytes) with a given destination port.
fn build_tcp(dst_port: u16) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[12] = 0x50; // Data offset = 5 (20 bytes)
    buf[13] = 0x02; // SYN flag
    buf
}

/// UDP header (8 bytes) with a given destination port.
fn build_udp(dst_port: u16) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&12345u16.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&8u16.to_be_bytes()); // length
    buf
}

/// Single VLAN tag (4 bytes) wrapping an inner EtherType.
fn build_vlan_tag(tci: u16, inner_ether_type: u16) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&tci.to_be_bytes());
    buf[2..4].copy_from_slice(&inner_ether_type.to_be_bytes());
    buf
}

// ---------------------------------------------------------------------------
// IPv6 Extension Header builders
// ---------------------------------------------------------------------------

/// Hop-by-Hop / Routing / Destination Options extension header (generic).
fn build_eh_generic(next_hdr: u8, ext_len: u8) -> Vec<u8> {
    let actual_len = ((ext_len as usize) + 1) * 8;
    let mut buf = vec![0u8; actual_len];
    buf[0] = next_hdr;
    buf[1] = ext_len;
    buf
}

/// IPv6 Fragment header (8 bytes).
fn build_ipv6_frag(next_hdr: u8, frag_offset: u16, more_fragments: bool) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = next_hdr;
    let mut fields = frag_offset & 0xFFF8;
    if more_fragments {
        fields |= 0x0001;
    }
    buf[2..4].copy_from_slice(&fields.to_be_bytes());
    buf
}

/// IPv6 Auth header. Length = (raw_len_field + 2) × 4 bytes.
fn build_ah(next_hdr: u8, len_field: u8) -> Vec<u8> {
    let actual_len = ((len_field as usize) + 2) * 4;
    let mut buf = vec![0u8; actual_len];
    buf[0] = next_hdr;
    buf[1] = len_field;
    buf
}

// ---------------------------------------------------------------------------
// Pure function tests
// ---------------------------------------------------------------------------

#[test]
fn is_ipv6_ext_header_all_variants() {
    let expected_true = [
        pure::IPV6_HOP_BY_HOP,
        pure::IPV6_ROUTING,
        pure::IPV6_FRAGMENT,
        pure::IPV6_ESP,
        pure::IPV6_AUTH,
        pure::IPV6_DEST_OPTS,
        pure::IPV6_MOBILITY,
        pure::IPV6_HIP,
        pure::IPV6_SHIM6,
        pure::IPV6_EXPERIMENTAL1,
        pure::IPV6_EXPERIMENTAL2,
    ];
    for &nh in &expected_true {
        assert!(pure::is_ipv6_ext_header(nh), "nh={nh} should be ext header");
    }
}

#[test]
fn is_ipv6_ext_header_rejects_l4() {
    assert!(!pure::is_ipv6_ext_header(pure::IP_PROTO_TCP));
    assert!(!pure::is_ipv6_ext_header(pure::IP_PROTO_UDP));
    assert!(!pure::is_ipv6_ext_header(59)); // No Next Header
    assert!(!pure::is_ipv6_ext_header(133)); // ICMPv6
}

// ---------------------------------------------------------------------------
// Packet builder sanity checks
// ---------------------------------------------------------------------------

#[test]
fn eth_header_length() {
    let eth = build_eth(&[0xff; 6], &[0xaa; 6], 0x0800);
    assert_eq!(eth.len(), 14);
    assert_eq!(&eth[12..14], &0x0800u16.to_be_bytes());
}

#[test]
fn ipv4_header_length() {
    let ip = build_ipv4([10, 0, 0, 1], [10, 0, 0, 2], pure::IP_PROTO_TCP, 60);
    assert_eq!(ip.len(), 20);
    assert_eq!(ip[0], 0x45);
    assert_eq!(ip[9], pure::IP_PROTO_TCP);
}

#[test]
fn ipv6_header_length() {
    let src = [0u8; 16];
    let dst = [0u8; 16];
    let ip6 = build_ipv6(&src, &dst, pure::IP_PROTO_UDP, 48);
    assert_eq!(ip6.len(), 40);
    assert_eq!(ip6[0] >> 4, 6);
    assert_eq!(ip6[4], 0); // payload len high byte
    assert_eq!(ip6[5], 48); // payload len low byte
    assert_eq!(ip6[6], pure::IP_PROTO_UDP);
}

#[test]
fn tcp_header_dst_port() {
    let tcp = build_tcp(443);
    let port = u16::from_be_bytes([tcp[2], tcp[3]]);
    assert_eq!(port, 443);
}

#[test]
fn udp_header_dst_port() {
    let udp = build_udp(53);
    let port = u16::from_be_bytes([udp[2], udp[3]]);
    assert_eq!(port, 53);
}

#[test]
fn vlan_tag_inner_ether_type() {
    let tag = build_vlan_tag(0x0064, 0x0800);
    let inner = u16::from_be_bytes([tag[2], tag[3]]);
    assert_eq!(inner, 0x0800);
}

#[test]
fn ipv6_frag_header_fields() {
    let frag = build_ipv6_frag(pure::IP_PROTO_TCP, 0, false);
    assert_eq!(frag[0], pure::IP_PROTO_TCP);
    let fields = u16::from_be_bytes([frag[2], frag[3]]);
    assert_eq!(fields & 0x0001, 0); // MF=0
    assert_eq!(fields & 0xFFF8, 0); // offset=0

    let frag2 = build_ipv6_frag(pure::IP_PROTO_TCP, 8, true);
    let fields2 = u16::from_be_bytes([frag2[2], frag2[3]]);
    assert_eq!(fields2 & 0x0001, 1); // MF=1
    assert_eq!(fields2 & 0xFFF8, 8); // offset=8
}

#[test]
fn eh_generic_length_formula() {
    let eh = build_eh_generic(pure::IPV6_ROUTING, 1);
    // (1 + 1) * 8 = 16 bytes
    assert_eq!(eh.len(), 16);
    assert_eq!(eh[0], pure::IPV6_ROUTING);
    assert_eq!(eh[1], 1);
}

#[test]
fn ah_length_formula() {
    let ah = build_ah(pure::IPV6_AUTH, 4);
    // (4 + 2) * 4 = 24 bytes
    assert_eq!(ah.len(), 24);
    assert_eq!(ah[0], pure::IPV6_AUTH);
    assert_eq!(ah[1], 4);
}

// ---------------------------------------------------------------------------
// Full frame assembly (for future BPF integration tests)
// ---------------------------------------------------------------------------

/// Build a complete IPv4+TCP frame: Eth + IPv4 + TCP.
fn frame_ipv4_tcp(src: [u8; 4], dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let eth = build_eth(&[0xff; 6], &[0xaa; 6], 0x0800);
    let tcp = build_tcp(dst_port);
    let total_len = 20 + tcp.len() as u16;
    let ip = build_ipv4(src, dst, pure::IP_PROTO_TCP, total_len);

    let mut frame = Vec::with_capacity(14 + 20 + 20);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// Build a complete IPv6+UDP frame: Eth + IPv6 + UDP.
fn frame_ipv6_udp(src: &[u8; 16], dst: &[u8; 16], dst_port: u16) -> Vec<u8> {
    let eth = build_eth(&[0xff; 6], &[0xaa; 6], 0x86DD);
    let udp = build_udp(dst_port);
    let ip6 = build_ipv6(src, dst, pure::IP_PROTO_UDP, udp.len() as u16);

    let mut frame = Vec::with_capacity(14 + 40 + 8);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&ip6);
    frame.extend_from_slice(&udp);
    frame
}

#[test]
fn frame_ipv4_tcp_total_length() {
    let frame = frame_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 80);
    // Eth(14) + IPv4(20) + TCP(20) = 54
    assert_eq!(frame.len(), 54);
    assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
}

#[test]
fn frame_ipv6_udp_total_length() {
    let src = [0u8; 16];
    let dst = [0u8; 16];
    let frame = frame_ipv6_udp(&src, &dst, 53);
    // Eth(14) + IPv6(40) + UDP(8) = 62
    assert_eq!(frame.len(), 62);
    assert_eq!(&frame[12..14], &0x86DDu16.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Full frame with VLAN tagging
// ---------------------------------------------------------------------------

fn frame_ipv4_tcp_vlan(src: [u8; 4], dst: [u8; 4], dst_port: u16, vlan_id: u16) -> Vec<u8> {
    let eth = build_eth(&[0xff; 6], &[0xaa; 6], 0x8100); // outer: VLAN
    let vlan = build_vlan_tag(vlan_id, 0x0800); // inner: IPv4
    let tcp = build_tcp(dst_port);
    let total_len = 20 + tcp.len() as u16;
    let ip = build_ipv4(src, dst, pure::IP_PROTO_TCP, total_len);

    let mut frame = Vec::with_capacity(14 + 4 + 20 + 20);
    frame.extend_from_slice(&eth);
    frame.extend_from_slice(&vlan);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

#[test]
fn frame_vlan_single_tag() {
    let frame = frame_ipv4_tcp_vlan([10, 0, 0, 1], [10, 0, 0, 2], 443, 100);
    // Eth(14) + VLAN(4) + IPv4(20) + TCP(20) = 58
    assert_eq!(frame.len(), 58);
    // Outer EtherType = 0x8100 (VLAN)
    assert_eq!(&frame[12..14], &0x8100u16.to_be_bytes());
    // Inner EtherType after VLAN tag = 0x0800 (IPv4)
    assert_eq!(&frame[16..18], &0x0800u16.to_be_bytes());
}
