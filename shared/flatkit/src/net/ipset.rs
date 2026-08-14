use crate::net::{IpNet, ipnet::CidrParseError};

use std::{cmp::Ordering, net::IpAddr, str::FromStr};

fn merge_u32(sorted: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        #[allow(clippy::collapsible_if)]
        if let Some(last) = out.last_mut() {
            if start <= last.1 || (last.1 != u32::MAX && start == last.1 + 1) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

fn merge_u128(sorted: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        #[allow(clippy::collapsible_if)]
        if let Some(last) = out.last_mut() {
            if start <= last.1 || (last.1 != u128::MAX && start == last.1 + 1) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

/// A memory-optimized, **read-only** set of IPv4 and IPv6 CIDR ranges or address blocks.
///
/// This structure is strictly immutable after initialization and designed exclusively for
/// lookup, containment checks, and high-performance filtering. Mutation operations (such as
/// inserting or removing addresses) are not supported.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpSet {
    v4: Box<[(u32, u32)]>,
    v6: Box<[(u128, u128)]>,
}

impl IpSet {
    pub fn builder() -> IpSetBuilder {
        IpSetBuilder::default()
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    #[inline]
    pub fn contains(&self, client_ip: IpAddr) -> bool {
        match client_ip {
            IpAddr::V4(ip) => self
                .v4
                .binary_search_by(|&(start, end)| {
                    let ip = u32::from(ip);

                    if ip < start {
                        Ordering::Greater
                    } else if ip > end {
                        Ordering::Less
                    } else {
                        Ordering::Equal
                    }
                })
                .is_ok(),

            IpAddr::V6(ip) => self
                .v6
                .binary_search_by(|&(start, end)| {
                    let ip = u128::from(ip);

                    if ip < start {
                        Ordering::Greater
                    } else if ip > end {
                        Ordering::Less
                    } else {
                        Ordering::Equal
                    }
                })
                .is_ok(),
        }
    }
}

#[derive(Debug, Default)]
pub struct IpSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSetBuilder {
    pub fn insert(&mut self, cidr: &str) -> Result<(), CidrParseError> {
        let network = IpNet::from_str(cidr)?;
        self.insert_network(&network);

        Ok(())
    }

    #[inline]
    pub fn insert_network(&mut self, network: &IpNet) {
        match network {
            IpNet::V4(network) => {
                let start = u32::from(network.network());
                let end = u32::from(network.broadcast());

                self.v4.push((start, end));
            },

            IpNet::V6(network) => {
                let start = u128::from(network.network());
                let end = u128::from(network.broadcast());

                self.v6.push((start, end));
            },
        }
    }

    pub fn try_from_iter<S, I>(iter: I) -> Result<IpSet, CidrParseError>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let mut builder = IpSet::builder();

        for cidr in iter {
            builder.insert(cidr.as_ref())?;
        }

        Ok(builder.build())
    }

    pub const fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn build(mut self) -> IpSet {
        self.v4.sort_unstable();
        self.v6.sort_unstable();

        IpSet {
            v4: merge_u32(self.v4).into_boxed_slice(),
            v6: merge_u128(self.v6).into_boxed_slice(),
        }
    }
}

#[cfg(test)]
mod happy_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    fn v6(o: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(o))
    }

    #[test]
    fn contains_inside_single_cidr() {
        let mut builder = IpSet::builder();
        builder.insert("192.168.0.0/24").unwrap();
        let set = builder.build();

        assert!(set.contains(v4([192, 168, 0, 1])));
        assert!(set.contains(v4([192, 168, 0, 255])));
        assert!(!set.contains(v4([192, 168, 1, 1])));
    }

    #[test]
    fn contains_v4_and_v6_together() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        builder.insert("2001:db8::/32").unwrap();
        let set = builder.build();

        assert!(set.contains(v4([10, 1, 2, 3])));
        assert!(set.contains(v6([0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1])));
    }

    #[test]
    fn contains_boundary_network_and_broadcast() {
        let mut builder = IpSet::builder();
        builder.insert("172.16.0.0/12").unwrap();
        let set = builder.build();

        assert!(set.contains(v4([172, 16, 0, 0])));
        assert!(set.contains(v4([172, 31, 255, 255])));
    }

    #[test]
    fn try_from_iter_builds_set() {
        let set = IpSetBuilder::try_from_iter(["10.0.0.0/8", "192.168.0.0/24"]).unwrap();
        assert!(set.contains(v4([10, 9, 9, 9])));
        assert!(set.contains(v4([192, 168, 0, 10])));
        assert!(!set.contains(v4([172, 16, 0, 1])));
    }

    #[test]
    fn overlapping_cidrs_merge() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        builder.insert("10.1.0.0/16").unwrap();
        let set = builder.build();

        assert!(set.contains(v4([10, 200, 0, 1])));
    }

    #[test]
    fn default_builder_is_empty() {
        assert!(IpSet::builder().is_empty());
        assert!(IpSet::default().is_empty());
    }

    #[test]
    fn set_is_empty_before_insert_only() {
        let mut builder = IpSet::builder();
        assert!(builder.is_empty());
        builder.insert("10.0.0.0/8").unwrap();
        assert!(!builder.is_empty());
        assert!(!builder.build().is_empty());
    }

    #[test]
    fn exact_host_cidr_32() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.1/32").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([10, 0, 0, 1])));
        assert!(!set.contains(v4([10, 0, 0, 2])));
    }
}

#[cfg(test)]
mod fail_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    #[test]
    fn insert_invalid_cidr_returns_error() {
        let mut builder = IpSet::builder();
        assert!(builder.insert("not-a-cidr").is_err());
        assert!(builder.insert("10.0.0.0/33").is_err());
    }

    #[test]
    fn try_from_iter_stops_on_error() {
        assert!(IpSetBuilder::try_from_iter(["10.0.0.0/8", "broken"]).is_err());
    }

    #[test]
    fn empty_set_contains_nothing() {
        let set = IpSet::default();
        assert!(!set.contains(v4([1, 2, 3, 4])));
        assert!(!set.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ip_outside_range_not_contained() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        let set = builder.build();
        assert!(!set.contains(v4([11, 0, 0, 1])));
        assert!(!set.contains(v4([9, 255, 255, 255])));
    }

    #[test]
    fn v4_lookup_against_v6_only_set_is_false() {
        let mut builder = IpSet::builder();
        builder.insert("2001:db8::/32").unwrap();
        let set = builder.build();
        assert!(!set.contains(v4([200, 1, 219, 8])));
    }

    #[test]
    fn v6_lookup_against_v4_only_set_is_false() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        let set = builder.build();
        assert!(!set.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn empty_cidr_is_rejected() {
        let mut builder = IpSet::builder();
        assert!(builder.insert("").is_err());
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o))
    }

    #[test]
    fn zero_zero_zero_zero_net_contains_everything() {
        let mut builder = IpSet::builder();
        builder.insert("0.0.0.0/0").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([0, 0, 0, 0])));
        assert!(set.contains(v4([255, 255, 255, 255])));
        assert!(set.contains(v4([8, 8, 8, 8])));
    }

    #[test]
    fn adjacent_cidrs_merge_into_contiguous_range() {
        let mut builder = IpSet::builder();
        builder.insert("192.168.0.0/24").unwrap();
        builder.insert("192.168.1.0/24").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([192, 168, 0, 1])));
        assert!(set.contains(v4([192, 168, 1, 255])));
    }

    #[test]
    fn boundary_ip_just_inside_and_just_outside() {
        let mut builder = IpSet::builder();
        builder.insert("192.168.0.0/24").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([192, 168, 0, 0])));
        assert!(set.contains(v4([192, 168, 0, 255])));
        assert!(!set.contains(v4([192, 168, 1, 0])));
        assert!(!set.contains(v4([192, 167, 255, 255])));
    }

    #[test]
    fn max_ipv4_address_in_full_range() {
        let mut builder = IpSet::builder();
        builder.insert("0.0.0.0/0").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([255, 255, 255, 255])));
    }

    #[test]
    fn single_u32_range_before_overflow_boundary() {
        let mut builder = IpSet::builder();
        builder.insert("255.255.255.254/31").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([255, 255, 255, 254])));
        assert!(set.contains(v4([255, 255, 255, 255])));
        assert!(!set.contains(v4([255, 255, 255, 253])));
    }

    #[test]
    fn duplicate_inserts_are_idempotent() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        builder.insert("10.0.0.0/8").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([10, 0, 0, 1])));
    }

    #[test]
    fn nested_overlapping_ranges_reduce_to_one() {
        let mut builder = IpSet::builder();
        builder.insert("10.0.0.0/8").unwrap();
        builder.insert("10.1.0.0/16").unwrap();
        builder.insert("10.1.2.0/24").unwrap();
        let set = builder.build();
        assert!(set.contains(v4([10, 1, 2, 3])));
        assert!(set.contains(v4([10, 250, 0, 1])));
    }

    #[test]
    fn v6_full_range_contains_extremes() {
        let mut builder = IpSet::builder();
        builder.insert("::/0").unwrap();
        let set = builder.build();
        assert!(set.contains(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(set.contains(IpAddr::V6(Ipv6Addr::new(
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
        ))));
    }

    #[test]
    fn gap_between_ranges_kept_separate() {
        let mut builder = IpSet::builder();
        builder.insert("192.168.0.0/24").unwrap();
        builder.insert("192.168.2.0/24").unwrap();
        let set = builder.build();
        assert!(!set.contains(v4([192, 168, 1, 5])));
        assert!(set.contains(v4([192, 168, 0, 5])));
        assert!(set.contains(v4([192, 168, 2, 5])));
    }
}
