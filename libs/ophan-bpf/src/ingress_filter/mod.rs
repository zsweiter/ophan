pub mod errors;
mod maps;
mod packet;
mod policies;
mod types;

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use crate::ingress_filter::errors::ErrorKind;

/// Classifies an ingress XDP packet against the network policy defined in
/// [`policy`].
///
/// 1. Parse Ethernet → optional VLAN tags → IPv4 / IPv6.
/// 2. Check source IP against the deny-list — **drop** immediately if matched.
/// 3. For each IP version, resolve the L4 protocol and destination port.
/// 4. If the destination port is a *listener port*, check the source IP
///    against the allow-list / CIDR trie — **drop** if not allowed.
/// 5. ARP, fragments, ESP, and any non-listener traffic are passed through.
pub fn classify_packet(ctx: &XdpContext) -> Result<u32, ErrorKind> {
    let ethhdr: *const EthHdr = unsafe { packet::ptr_at_offset(&ctx, 0)? };
    let offset = EthHdr::LEN;
    let ether_type = unsafe { (*ethhdr).ether_type() }?;

    let (ether_type, offset) = packet::strip_vlan_tags(ether_type, &ctx, offset)?;

    match ether_type {
        // ARP is required for L2 resolution — always pass
        EtherType::Arp => Ok(xdp_action::XDP_PASS),

        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { packet::ptr_at_offset(&ctx, offset)? };
            let ihl = unsafe { (*ipv4hdr).ihl() } as usize;

            // Minimum IPv4 header without options is 20 bytes (IHL = 5)
            if ihl < Ipv4Hdr::LEN {
                return Err(ErrorKind::InvalidIpv4Header);
            }

            let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
            let proto = unsafe { (*ipv4hdr).proto };
            let l4_off = offset + ihl;

            // Fragments: pass to host OS for reassembly
            let frag_off = unsafe { (*ipv4hdr).frag_offset() };
            let is_fragment = (frag_off & 0x3FFF) != 0;
            if is_fragment {
                return Ok(xdp_action::XDP_PASS);
            }

            if let Some(dst_port_be) = packet::parse_l4_dst_port(&ctx, proto, l4_off) {
                match policies::evaluate_ingress_v4(source, dst_port_be) {
                    xdp_action::XDP_DROP => {
                        debug!(ctx, "DROP IPv4 port: {}", dst_port_be);
                        return Ok(xdp_action::XDP_DROP);
                    },
                    _ => return Ok(xdp_action::XDP_PASS),
                }
            }

            Ok(xdp_action::XDP_PASS)
        },

        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { packet::ptr_at_offset(&ctx, offset)? };
            let source = unsafe { (*ipv6hdr).src_addr };
            let next_hdr = unsafe { (*ipv6hdr).next_hdr };

            let parsed = packet::resolve_ipv6_l4(&ctx, offset, next_hdr)?;
            let Some((proto, l4_off)) = parsed else {
                // ESP or fragmented — pass without port-level checks
                return Ok(xdp_action::XDP_PASS);
            };

            if let Some(dst_port_be) = packet::parse_l4_dst_port(&ctx, proto, l4_off) {
                match policies::evaluate_ingress_v6(&source, dst_port_be) {
                    xdp_action::XDP_DROP => {
                        debug!(ctx, "DROP IPv6 port: {}", dst_port_be);
                        return Ok(xdp_action::XDP_DROP);
                    },
                    _ => return Ok(xdp_action::XDP_PASS),
                }
            }

            Ok(xdp_action::XDP_PASS)
        },

        // Unknown EtherType — fail-open
        _ => Ok(xdp_action::XDP_PASS),
    }
}
