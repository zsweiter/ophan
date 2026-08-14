mod host;
mod ipnet;
mod ipset;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use host::{HostAddr, HostAddrError, Scheme};
pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};
pub use ipset::{IpSet, IpSetBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxCidrBlock {
    /// Localhost loopback block for IPv4 (`127.0.0.1/8`)
    LocalhostV4,
    /// 24-bit private network block (`10.0.0.0/8`)
    Private24BitV4,
    /// 20-bit private network block (`172.16.0.0/12`)
    Private20BitV4,
    /// 16-bit private network block (`192.168.0.0/16`)
    Private16BitV4,
    /// Link-local autoconfiguration address block for IPv4 (`169.254.0.0/16`)
    LinkLocalV4,
    /// Localhost loopback address for IPv6 (`::1/128`)
    LocalhostV6,
    /// Unique local address block for private IPv6 routing (`fc00::/7`)
    UniqueLocalV6,
    /// Link-local unicast address block for IPv6 (`fe80::/10`)
    LinkLocalV6,
}

impl MaxCidrBlock {
    /// Returns the exact string literal representation of the CIDR block.
    pub fn as_str(&self) -> &'static str {
        match self {
            MaxCidrBlock::LocalhostV4 => "127.0.0.1/8",
            MaxCidrBlock::Private24BitV4 => "10.0.0.0/8",
            MaxCidrBlock::Private20BitV4 => "172.16.0.0/12",
            MaxCidrBlock::Private16BitV4 => "192.168.0.0/16",
            MaxCidrBlock::LinkLocalV4 => "169.254.0.0/16",
            MaxCidrBlock::LocalhostV6 => "::1/128",
            MaxCidrBlock::UniqueLocalV6 => "fc00::/7",
            MaxCidrBlock::LinkLocalV6 => "fe80::/10",
        }
    }

    pub const ALL: [MaxCidrBlock; 8] = [
        MaxCidrBlock::LocalhostV4,
        MaxCidrBlock::Private24BitV4,
        MaxCidrBlock::Private20BitV4,
        MaxCidrBlock::Private16BitV4,
        MaxCidrBlock::LinkLocalV4,
        MaxCidrBlock::LocalhostV6,
        MaxCidrBlock::UniqueLocalV6,
        MaxCidrBlock::LinkLocalV6,
    ];

    pub fn network(&self) -> IpNet {
        match self {
            MaxCidrBlock::LocalhostV4 => IpNet::new_v4(Ipv4Addr::new(127, 0, 0, 1), 8).unwrap(),
            MaxCidrBlock::Private24BitV4 => IpNet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            MaxCidrBlock::Private20BitV4 => IpNet::new_v4(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),

            MaxCidrBlock::Private16BitV4 => IpNet::new_v4(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
            MaxCidrBlock::LinkLocalV4 => IpNet::new_v4(Ipv4Addr::new(169, 254, 0, 0), 16).unwrap(),

            MaxCidrBlock::LocalhostV6 => IpNet::new_v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128).unwrap(),
            MaxCidrBlock::UniqueLocalV6 => IpNet::new_v6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7).unwrap(),
            MaxCidrBlock::LinkLocalV6 => IpNet::new_v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10).unwrap(),
        }
    }
}

impl std::fmt::Display for MaxCidrBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn hash_ip(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from_ne_bytes(v4.octets());
            let hash = ip_u32.wrapping_mul(0x6d2b79f5u32).rotate_left(7);
            hash as usize
        },
        IpAddr::V6(v6) => {
            let segments = v6.segments(); // [u16; 8]

            let mut h0 = segments[0] ^ segments[1] ^ segments[2] ^ segments[3];
            let mut h1 = segments[4] ^ segments[5] ^ segments[6] ^ segments[7];

            h0 = (h0 as u32).wrapping_mul(0x6d2b79f5u32) as u16;
            h1 = (h1 as u32).wrapping_mul(0x2b6ac22eu32) as u16;

            let combined = (h0 as u64) ^ ((h1 as u64) << 16);
            combined as usize
        },
    }
}

#[cfg(test)]
mod happy_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn as_str_returns_expected_literals() {
        assert_eq!(MaxCidrBlock::LocalhostV4.as_str(), "127.0.0.1/8");
        assert_eq!(MaxCidrBlock::Private24BitV4.as_str(), "10.0.0.0/8");
        assert_eq!(MaxCidrBlock::Private20BitV4.as_str(), "172.16.0.0/12");
        assert_eq!(MaxCidrBlock::Private16BitV4.as_str(), "192.168.0.0/16");
        assert_eq!(MaxCidrBlock::LinkLocalV4.as_str(), "169.254.0.0/16");
        assert_eq!(MaxCidrBlock::LocalhostV6.as_str(), "::1/128");
        assert_eq!(MaxCidrBlock::UniqueLocalV6.as_str(), "fc00::/7");
        assert_eq!(MaxCidrBlock::LinkLocalV6.as_str(), "fe80::/10");
    }

    #[test]
    fn all_lists_every_block() {
        assert_eq!(MaxCidrBlock::ALL.len(), 8);
        assert!(MaxCidrBlock::ALL.contains(&MaxCidrBlock::LocalhostV4));
        assert!(MaxCidrBlock::ALL.contains(&MaxCidrBlock::LinkLocalV6));
    }

    #[test]
    fn network_v4_blocks() {
        assert_eq!(
            MaxCidrBlock::LocalhostV4.network().ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        assert_eq!(MaxCidrBlock::LocalhostV4.network().prefix(), 8);

        assert_eq!(
            MaxCidrBlock::Private24BitV4.network().ip(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        );
        assert_eq!(MaxCidrBlock::Private24BitV4.network().prefix(), 8);

        assert_eq!(
            MaxCidrBlock::Private20BitV4.network().ip(),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        );
        assert_eq!(MaxCidrBlock::Private20BitV4.network().prefix(), 12);

        assert_eq!(
            MaxCidrBlock::Private16BitV4.network().ip(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        );
        assert_eq!(MaxCidrBlock::Private16BitV4.network().prefix(), 16);
    }

    #[test]
    fn network_v6_blocks() {
        assert_eq!(MaxCidrBlock::LocalhostV6.network().ip(), IpAddr::V6(Ipv6Addr::LOCALHOST),);
        assert_eq!(MaxCidrBlock::LocalhostV6.network().prefix(), 128);

        assert_eq!(
            MaxCidrBlock::UniqueLocalV6.network().ip(),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
        );
        assert_eq!(MaxCidrBlock::UniqueLocalV6.network().prefix(), 7);

        assert_eq!(
            MaxCidrBlock::LinkLocalV6.network().ip(),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        );
        assert_eq!(MaxCidrBlock::LinkLocalV6.network().prefix(), 10);
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(MaxCidrBlock::LocalhostV4.to_string(), "127.0.0.1/8");
        assert_eq!(MaxCidrBlock::LinkLocalV6.to_string(), "fe80::/10");
    }

    #[test]
    fn hash_ip_is_stable() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hash_ip(a), hash_ip(a));
    }

    #[test]
    fn hash_ip_v4_and_v6_produce_usize() {
        let _: usize = hash_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let _: usize = hash_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
}

#[cfg(test)]
mod fail_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn hash_differs_for_adjacent_v4() {
        let a = hash_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        let b = hash_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_differs_for_unspecified_and_loopback_v6() {
        let a = hash_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        let b = hash_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_ne!(a, b);
    }

    #[test]
    fn localhost_v4_network_excludes_public_ip() {
        let net = MaxCidrBlock::LocalhostV4.network();
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(127, 8, 8, 8))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 1))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(126, 255, 255, 255))));
    }

    #[test]
    fn private16_v4_network_excludes_neighbors() {
        let net = MaxCidrBlock::Private16BitV4.network();
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0))));
    }

    #[test]
    fn link_local_v6_network_excludes_unicast() {
        let net = MaxCidrBlock::LinkLocalV6.network();
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))));
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn hash_ip_zero_v4() {
        assert_eq!(hash_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))), 0);
    }

    #[test]
    fn hash_ip_max_v4() {
        let _ = hash_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn hash_ip_unspecified_v6() {
        assert_eq!(hash_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), 0);
    }

    #[test]
    fn hash_ip_all_ones_v6() {
        let _ = hash_ip(IpAddr::V6(Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        )));
    }

    #[test]
    fn hash_ip_v6_with_high_variation_segments() {
        let a = hash_ip(IpAddr::V6(Ipv6Addr::new(
            0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE, 0xFFFF, 0x1111, 0x2222,
        )));
        let b = hash_ip(IpAddr::V6(Ipv6Addr::new(
            0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE, 0xFFFF, 0x1111, 0x2223,
        )));
        assert_ne!(a, b);
    }

    #[test]
    fn localhost_v6_is_single_host_net() {
        let net = MaxCidrBlock::LocalhostV6.network();
        assert_eq!(net.network(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(net.broadcast(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn unique_local_v6_is_broad_block() {
        let net = MaxCidrBlock::UniqueLocalV6.network();
        assert!(net.contains(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0))));
        assert!(net.contains(IpAddr::V6(Ipv6Addr::new(
            0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        ))));
    }

    #[test]
    fn all_blocks_are_distinct_networks() {
        let mut nets = MaxCidrBlock::ALL.iter().map(|b| b.network());
        let first = nets.next().unwrap();
        for net in nets {
            assert_ne!(first, net);
        }
    }
}
