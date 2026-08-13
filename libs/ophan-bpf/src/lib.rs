#![cfg_attr(not(test), no_std)]

/// Pure helper functions and constants that do not depend on BPF types,
/// making them testable on the host target.
pub mod pure {
    /// IPv4 protocol number for TCP.
    pub const IP_PROTO_TCP: u8 = 6;
    /// IPv4 protocol number for UDP.
    pub const IP_PROTO_UDP: u8 = 17;

    /// Hop-by-Hop Options header.
    pub const IPV6_HOP_BY_HOP: u8 = 0;
    /// Routing header.
    pub const IPV6_ROUTING: u8 = 43;
    /// Fragment header.
    pub const IPV6_FRAGMENT: u8 = 44;
    /// Encapsulating Security Payload.
    pub const IPV6_ESP: u8 = 50;
    /// Authentication Header.
    pub const IPV6_AUTH: u8 = 51;
    /// Destination Options header.
    pub const IPV6_DEST_OPTS: u8 = 60;
    /// Mobility header.
    pub const IPV6_MOBILITY: u8 = 135;
    /// Host Identity Protocol.
    pub const IPV6_HIP: u8 = 139;
    /// Shim6 protocol.
    pub const IPV6_SHIM6: u8 = 140;
    /// Experimentation 1.
    pub const IPV6_EXPERIMENTAL1: u8 = 253;
    /// Experimentation 2.
    pub const IPV6_EXPERIMENTAL2: u8 = 254;

    /// Maximum number of extension-header hops the parser will follow.
    pub const MAX_EH_HOPS: u32 = 8;

    /// Returns `true` when `nh` is an IPv6 Extension Header type.
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ext_header_known_values() {
            let ext_headers = [
                IPV6_HOP_BY_HOP,
                IPV6_ROUTING,
                IPV6_FRAGMENT,
                IPV6_ESP,
                IPV6_AUTH,
                IPV6_DEST_OPTS,
                IPV6_MOBILITY,
                IPV6_HIP,
                IPV6_SHIM6,
                IPV6_EXPERIMENTAL1,
                IPV6_EXPERIMENTAL2,
            ];
            for &nh in &ext_headers {
                assert!(is_ipv6_ext_header(nh), "expected ext header for nh={nh}");
            }
        }

        #[test]
        fn non_ext_headers() {
            assert!(!is_ipv6_ext_header(IP_PROTO_TCP));
            assert!(!is_ipv6_ext_header(IP_PROTO_UDP));
            assert!(!is_ipv6_ext_header(59)); // No Next Header
            assert!(!is_ipv6_ext_header(1)); // ICMPv6
        }

        #[test]
        fn proto_constants() {
            assert_eq!(IP_PROTO_TCP, 6);
            assert_eq!(IP_PROTO_UDP, 17);
        }

        #[test]
        fn eh_hop_limit() {
            assert_eq!(MAX_EH_HOPS, 8);
        }
    }
}
