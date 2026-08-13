use core::mem;

use aya_ebpf::programs::XdpContext;
use network_types::{eth::EtherType, ip::Ipv6Hdr, tcp::TcpHdr, udp::UdpHdr, vlan::VlanHdr};

use crate::ingress_filter::errors::ErrorKind;

// --- Layer 4 Protocol Identifiers (IPv4 ip_p / IPv6 Next Header) ---

/// IPv4 protocol number for TCP.
const IPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IPROTO_UDP: u8 = 17;

// --- IPv6 Extension Header Next-Header values ---

/// Hop-by-Hop Options header.
const IPV6_HOP_BY_HOP: u8 = 0;
/// Routing header.
const IPV6_ROUTING: u8 = 43;
/// Fragment header.
const IPV6_FRAGMENT: u8 = 44;
/// Encapsulating Security Payload.
const IPV6_ESP: u8 = 50;
/// Authentication Header.
const IPV6_AUTH: u8 = 51;
/// Destination Options header.
const IPV6_DEST_OPTS: u8 = 60;
/// Mobility header.
const IPV6_MOBILITY: u8 = 135;
/// Host Identity Protocol.
const IPV6_HIP: u8 = 139;
/// Shim6 protocol.
const IPV6_SHIM6: u8 = 140;
/// Experimentation 1.
const IPV6_EXPERIMENTAL1: u8 = 253;
/// Experimentation 2.
const IPV6_EXPERIMENTAL2: u8 = 254;

/// Maximum number of extension-header hops the parser will follow
/// before rejecting the packet (verifier safety).
const MAX_EH_HOPS: u32 = 8;

// ---------------------------------------------------------------------------
// Packet parsing helpers
// ---------------------------------------------------------------------------

/// Returns a raw pointer to a structure `T` at `offset` bytes from the start
/// of the XDP packet buffer, or `Err(())` if the region is out of bounds.
#[inline(always)]
pub unsafe fn ptr_at_offset<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ErrorKind> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if (start + offset + len) > end {
        return Err(ErrorKind::Truncated);
    }

    Ok((start + offset) as *const T)
}

/// Returns `true` when `nh` is an IPv6 Extension Header type that must be
/// skipped before reaching the actual L4 payload.
#[inline(always)]
pub fn is_ipv6_ext_header(nh: u8) -> bool {
    matches!(
        nh,
        IPV6_HOP_BY_HOP
            | IPV6_ROUTING
            | IPV6_FRAGMENT
            | IPV6_ESP
            | IPV6_AUTH
            | IPV6_DEST_OPTS
            | IPV6_MOBILITY
            | IPV6_HIP
            | IPV6_SHIM6
            | IPV6_EXPERIMENTAL1
            | IPV6_EXPERIMENTAL2
    )
}

/// Parses the Layer-4 (L4) destination port from a TCP or UDP packet header.
///
/// Reads the header at the specified byte offset `l4_off` relative to the
/// start of the packet frame.
///
/// # Arguments
///
/// * `ctx` - Pointer to the `XdpContext` containing packet bounds (`data` and `data_end`).
/// * `proto` - L4 protocol identifier extracted from the IP header (`IPROTO_TCP` or `IPROTO_UDP`).
/// * `l4_off` - Byte offset from the start of the frame where the L4 header begins.
///
/// # Returns
///
/// * `Some(u16)` - The destination port in **Big-Endian / Network Byte Order**.
/// * `None` - Returned if the protocol is unsupported or the packet fails the BPF bounds check.
///
/// # Safety
///
/// Performs `unsafe` raw pointer dereferencing on the packet buffer. Memory safety
/// and out-of-bound access prevention are strictly guaranteed at runtime by
/// the BPF verifier via bounds checking in `ptr_at_offset`.
#[inline(always)]
pub fn parse_l4_dst_port(ctx: &XdpContext, proto: u8, l4_off: usize) -> Option<u16> {
    match proto {
        IPROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at_offset(ctx, l4_off).ok()? };
            Some(u16::from_be_bytes(unsafe { (*tcphdr).dest }))
        },
        IPROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at_offset(ctx, l4_off).ok()? };
            Some(u16::from_be_bytes(unsafe { (*udphdr).dst }))
        },
        _ => None,
    }
}

/// Strips up to 2 nested VLAN tags (802.1Q / 802.1ad / QinQ variants) to
/// reveal the inner EtherType and the payload offset that follows the last tag.
///
/// Returns `(inner_ether_type, payload_offset)`.
#[inline(always)]
pub fn strip_vlan_tags(mut ether_type: EtherType, ctx: &XdpContext, mut offset: usize) -> Result<(EtherType, usize), ErrorKind> {
    for _ in 0..2 {
        match ether_type {
            EtherType::Ieee8021q
            | EtherType::Ieee8021ad
            | EtherType::Ieee8021QinQ1
            | EtherType::Ieee8021QinQ2
            | EtherType::Ieee8021QinQ3 => {
                let vlanhdr: *const VlanHdr = unsafe { ptr_at_offset(ctx, offset)? };
                ether_type = unsafe { (*vlanhdr).ether_type() }?;
                offset += VlanHdr::LEN;
            },
            _ => break,
        }
    }

    Ok((ether_type, offset))
}

/// Walks the IPv6 Extension Header chain to find the L4 protocol and its
/// byte offset inside the packet.
///
/// Returns:
/// - `Ok(Some((proto, offset)))` — L4 protocol and offset found.
/// - `Ok(None)` — L4 is unreachable (fragmented or ESP); caller should
///   pass the packet through without port-level policy.
/// - `Err(())` — packet could not be parsed.
#[inline(always)]
pub fn resolve_ipv6_l4(ctx: &XdpContext, offset: usize, mut next_hdr: u8) -> Result<Option<(u8, usize)>, ErrorKind> {
    let mut off = offset + Ipv6Hdr::LEN;
    let mut hops = 0u32;

    while is_ipv6_ext_header(next_hdr) {
        hops += 1;
        if hops > MAX_EH_HOPS {
            return Err(ErrorKind::Ipv6ExtensionLimitExceeded);
        }

        match next_hdr {
            IPV6_FRAGMENT => {
                let frag: *const [u8; 8] = unsafe { ptr_at_offset(ctx, off)? };
                let raw = unsafe { *frag };
                let frag_fields = u16::from_be_bytes([raw[2], raw[3]]);

                let more_fragments = (frag_fields & 0x0001) != 0;
                let is_non_first = (frag_fields & 0xFFF8) != 0;

                // Cannot inspect L4 on fragmented traffic — pass to host stack
                if is_non_first || more_fragments {
                    return Ok(None);
                }
                next_hdr = raw[0];
                off += 8;
            },
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DEST_OPTS | IPV6_MOBILITY | IPV6_HIP | IPV6_SHIM6 | IPV6_EXPERIMENTAL1
            | IPV6_EXPERIMENTAL2 => {
                let hdr: *const [u8; 2] = unsafe { ptr_at_offset(ctx, off)? };
                let raw = unsafe { *hdr };
                next_hdr = raw[0];
                // Hdr Ext Len is in 8-octet units, excluding the first 8 octets
                let ext_len = ((raw[1] as usize) + 1) * 8;
                off += ext_len;
            },
            IPV6_AUTH => {
                let hdr: *const [u8; 2] = unsafe { ptr_at_offset(ctx, off)? };
                let raw = unsafe { *hdr };
                next_hdr = raw[0];
                // AH: length = (Payload Len + 2) × 4-octet words
                let ext_len = ((raw[1] as usize) + 2) * 4;
                off += ext_len;
            },
            // IPSec ESP payload is encrypted — cannot parse ports
            IPV6_ESP => return Ok(None),
            _ => return Err(ErrorKind::InvalidIpv6PayloadLength),
        }
    }

    Ok(Some((next_hdr, off)))
}
