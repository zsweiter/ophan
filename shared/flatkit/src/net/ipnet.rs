use std::fmt;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Debug)]
pub enum CidrParseError {
    InvalidIp(AddrParseError),
    InvalidPrefix(ParseIntError),
    MultipleSlashes,

    /// Prefix length is outside the valid range for the IP version.
    InvalidPrefixLength {
        prefix: u8,
        max: u8,
    },
}

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIp(_) => {
                write!(f, "invalid IP address")
            },

            Self::InvalidPrefix(_) => {
                write!(f, "invalid CIDR prefix")
            },

            Self::MultipleSlashes => {
                write!(f, "CIDR must contain exactly one '/'")
            },

            Self::InvalidPrefixLength { prefix, max } => {
                write!(
                    f,
                    "CIDR prefix length {} exceeds the maximum allowed value of {}",
                    prefix, max
                )
            },
        }
    }
}

impl std::error::Error for CidrParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidIp(err) => Some(err),
            Self::InvalidPrefix(err) => Some(err),
            Self::MultipleSlashes | Self::InvalidPrefixLength { .. } => None,
        }
    }
}

pub fn cidr_parts<V>(cidr: &str) -> Result<(V, Option<u8>), CidrParseError>
where
    V: FromStr<Err = AddrParseError>,
{
    if let Some(sep) = cidr.find('/') {
        let (ip, prefix) = cidr.split_at(sep);
        let prefix = &prefix[1..];

        if prefix.contains('/') {
            return Err(CidrParseError::MultipleSlashes);
        }

        let ip = ip.parse::<V>().map_err(CidrParseError::InvalidIp)?;

        let prefix = prefix.parse::<u8>().map_err(CidrParseError::InvalidPrefix)?;

        Ok((ip, Some(prefix)))
    } else {
        let ip = cidr.parse::<V>().map_err(CidrParseError::InvalidIp)?;

        Ok((ip, None))
    }
}

const IPV4_BITS: u8 = 32;

/// Represents a network range where the IP addresses are of v4
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    /// Creates a network after validating the prefix length.
    pub const fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, CidrParseError> {
        if prefix > IPV4_BITS {
            return Err(CidrParseError::InvalidPrefixLength { prefix, max: IPV4_BITS });
        }

        Ok(Self { addr, prefix })
    }

    /// Creates a network without validating the prefix length.
    ///
    /// # Safety
    ///
    /// `prefix` must be less than or equal to `IPV4_BITS`.
    pub const unsafe fn new_unchecked(addr: Ipv4Addr, prefix: u8) -> Self {
        debug_assert!(prefix <= IPV4_BITS);

        Self { addr, prefix }
    }

    /// Returns the stored IP address.
    pub const fn ip(self) -> Ipv4Addr {
        self.addr
    }

    /// Returns the prefix length.
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    // Checks if the given `Ipv4Net` is a subnet of the other.
    pub fn is_subnet_of(self, other: Ipv4Net) -> bool {
        other.ip() <= self.ip() && other.broadcast() >= self.broadcast()
    }

    /// Checks if the given `Ipv4Net` is a supernet of the other.
    pub fn is_supernet_of(self, other: Ipv4Net) -> bool {
        other.is_subnet_of(self)
    }

    /// Checks if the given `Ipv4Net` is partly contained in other.
    pub fn overlaps(self, other: Ipv4Net) -> bool {
        other.contains(self.ip())
            || other.contains(self.broadcast())
            || self.contains(other.ip())
            || self.contains(other.broadcast())
    }

    /// Returns the mask for this `Ipv4Net`.
    /// That means the `prefix` most significant bits will be 1 and the rest 0
    pub fn mask(&self) -> Ipv4Addr {
        debug_assert!(self.prefix <= 32);
        if self.prefix == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }

        let mask = u32::MAX << (IPV4_BITS - self.prefix);
        Ipv4Addr::from(mask)
    }

    /// Returns the address of the network denoted by this `Ipv4Net`.
    /// This means the lowest possible IPv4 address inside of the network.
    pub fn network(&self) -> Ipv4Addr {
        let mask = u32::from(self.mask());
        let ip = u32::from(self.addr) & mask;
        Ipv4Addr::from(ip)
    }

    /// Returns the broadcasting address of this `Ipv4Net`.
    /// This means the highest possible IPv4 address inside of the network.
    pub fn broadcast(&self) -> Ipv4Addr {
        let mask = u32::from(self.mask());
        let broadcast = u32::from(self.addr) | !mask;
        Ipv4Addr::from(broadcast)
    }

    /// Checks if a given `Ipv4Addr` is in this `Ipv4Net`
    #[inline]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        debug_assert!(self.prefix <= IPV4_BITS);

        let mask = !(0xffff_ffff_u64 >> self.prefix) as u32;
        let net = u32::from(self.addr) & mask;
        (u32::from(ip) & mask) == net
    }
}

impl FromStr for Ipv4Net {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (v4, prefix) = cidr_parts::<Ipv4Addr>(s)?;
        let prefix = prefix.unwrap_or(32);
        if prefix > 32 {
            return Err(CidrParseError::InvalidPrefixLength { prefix, max: 32 });
        }

        Ok(Ipv4Net { addr: v4, prefix })
    }
}

impl TryFrom<&str> for Ipv4Net {
    type Error = CidrParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

const IPV6_BITS: u8 = 128;

/// Represents a network range where the IP addresses are of v6
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv6Net {
    addr: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Net {
    /// Creates a network after validating the prefix length.
    pub const fn new(addr: Ipv6Addr, prefix: u8) -> Result<Self, CidrParseError> {
        if prefix > IPV6_BITS {
            return Err(CidrParseError::InvalidPrefixLength { prefix, max: IPV6_BITS });
        }

        Ok(Self { addr, prefix })
    }

    /// Creates a network without validating the prefix length.
    ///
    /// # Safety
    ///
    /// `prefix` must be less than or equal to `IPV6_BITS`.
    pub const unsafe fn new_unchecked(addr: Ipv6Addr, prefix: u8) -> Self {
        debug_assert!(prefix <= IPV6_BITS);

        Self { addr, prefix }
    }

    /// Returns the stored IP address.
    pub const fn ip(self) -> Ipv6Addr {
        self.addr
    }

    /// Returns the prefix length.
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    /// Checks if the given `Ipv6Net` is a subnet of the other.
    pub fn is_subnet_of(self, other: Ipv6Net) -> bool {
        other.ip() <= self.ip() && other.broadcast() >= self.broadcast()
    }

    /// Checks if the given `Ipv6Net` is a supernet of the other.
    pub fn is_supernet_of(self, other: Ipv6Net) -> bool {
        other.is_subnet_of(self)
    }

    /// Checks if the given `Ipv6Net` is partly contained in other.
    pub fn overlaps(self, other: Ipv6Net) -> bool {
        other.contains(self.ip())
            || other.contains(self.broadcast())
            || self.contains(other.ip())
            || self.contains(other.broadcast())
    }

    /// Returns the mask for this `Ipv6Net`.
    /// That means the `prefix` most significant bits will be 1 and the rest 0
    pub fn mask(&self) -> Ipv6Addr {
        debug_assert!(self.prefix <= IPV6_BITS);

        if self.prefix == 0 {
            return Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        }
        let mask = u128::MAX << (IPV6_BITS - self.prefix);
        Ipv6Addr::from(mask)
    }

    /// Returns the address of the network denoted by this `Ipv6Net`.
    /// This means the lowest possible IPv6 address inside of the network.
    pub fn network(&self) -> Ipv6Addr {
        let mask = u128::from(self.mask());
        let network = u128::from(self.addr) & mask;
        Ipv6Addr::from(network)
    }

    /// Returns the broadcast address of this `Ipv6Net`.
    /// This means the highest possible IPv4 address inside of the network.
    pub fn broadcast(&self) -> Ipv6Addr {
        let mask = u128::from(self.mask());
        let broadcast = u128::from(self.addr) | !mask;
        Ipv6Addr::from(broadcast)
    }

    /// Checks if a given `Ipv6Addr` is in this `Ipv6Net`
    #[inline]
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let ip = u128::from(ip);
        let net = u128::from(self.network());
        let mask = u128::from(self.mask());
        (ip & mask) == net
    }
}

impl FromStr for Ipv6Net {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (v6, prefix) = cidr_parts::<Ipv6Addr>(s)?;
        let prefix = prefix.unwrap_or(128);
        if prefix > 128 {
            return Err(CidrParseError::InvalidPrefixLength { prefix, max: 128 });
        }

        Ok(Ipv6Net { addr: v6, prefix })
    }
}

impl TryFrom<&str> for Ipv6Net {
    type Error = CidrParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpNet {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl IpNet {
    pub fn new_v4(addr: Ipv4Addr, prefix: u8) -> Result<Self, CidrParseError> {
        let net = Ipv4Net::new(addr, prefix)?;
        Ok(Self::V4(net))
    }

    pub fn new_v6(addr: Ipv6Addr, prefix: u8) -> Result<Self, CidrParseError> {
        let net = Ipv6Net::new(addr, prefix)?;
        Ok(Self::V6(net))
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            IpNet::V4(net) => IpAddr::V4(net.ip()),
            IpNet::V6(net) => IpAddr::V6(net.ip()),
        }
    }

    pub fn prefix(&self) -> u8 {
        match self {
            IpNet::V4(net) => net.prefix(),
            IpNet::V6(net) => net.prefix(),
        }
    }

    /// Returns the address of the network denoted by this `IpNet`.
    /// This means the lowest possible IP address inside of the network.
    pub fn network(&self) -> IpAddr {
        match *self {
            IpNet::V4(ref a) => IpAddr::V4(a.network()),
            IpNet::V6(ref a) => IpAddr::V6(a.network()),
        }
    }

    /// Returns the broadcasting address of this `IpNet`.
    /// This means the highest possible IP address inside of the network.
    pub fn broadcast(&self) -> IpAddr {
        match *self {
            IpNet::V4(ref a) => IpAddr::V4(a.broadcast()),
            IpNet::V6(ref a) => IpAddr::V6(a.broadcast()),
        }
    }

    /// Returns the mask for this `IpNet`.
    /// That means the `prefix` most significant bits will be 1 and the rest 0
    pub fn mask(&self) -> IpAddr {
        match *self {
            IpNet::V4(ref a) => IpAddr::V4(a.mask()),
            IpNet::V6(ref a) => IpAddr::V6(a.mask()),
        }
    }

    /// Returns true if the IP in this `IpNet` is a valid IPv4 address,
    /// false if it's a valid IPv6 address.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpNet::V4(_))
    }

    /// Returns true if the IP in this `IpNet` is a valid IPv6 address,
    /// false if it's a valid IPv4 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpNet::V6(_))
    }

    /// Checks if a given `IpAddr` is in this `IpNet`
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpNet::V4(net), IpAddr::V4(ip)) => net.contains(ip),
            (IpNet::V6(net), IpAddr::V6(ip)) => net.contains(ip),
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = cidr_parts(s)?;
        match ip {
            IpAddr::V4(v4) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return Err(CidrParseError::InvalidPrefixLength { prefix, max: 32 });
                }
                Ok(IpNet::V4(Ipv4Net { addr: v4, prefix }))
            },
            IpAddr::V6(v6) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 {
                    return Err(CidrParseError::InvalidPrefixLength { prefix, max: 128 });
                }
                Ok(IpNet::V6(Ipv6Net { addr: v6, prefix }))
            },
        }
    }
}

impl TryFrom<&str> for IpNet {
    type Error = CidrParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpNet::V4(net) => write!(f, "{}/{}", net.ip(), net.prefix()),
            IpNet::V6(net) => write!(f, "{}/{}", net.ip(), net.prefix()),
        }
    }
}

impl From<Ipv4Net> for IpNet {
    fn from(net: Ipv4Net) -> Self {
        IpNet::V4(net)
    }
}

impl From<Ipv6Net> for IpNet {
    fn from(net: Ipv6Net) -> Self {
        IpNet::V6(net)
    }
}

#[cfg(test)]
mod happy_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_ipv4_cidr() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        assert_eq!(net.ip(), Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(net.prefix(), 24);
    }

    #[test]
    fn parse_ipv4_without_prefix_defaults_to_32() {
        let net: Ipv4Net = "10.0.0.5".parse().unwrap();
        assert_eq!(net.prefix(), 32);
        assert_eq!(net.ip(), Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let net: Ipv6Net = "2001:db8::/32".parse().unwrap();
        assert_eq!(net.prefix(), 32);
        assert_eq!(net.ip(), "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn parse_ipv6_without_prefix_defaults_to_128() {
        let net: Ipv6Net = "::1".parse().unwrap();
        assert_eq!(net.prefix(), 128);
        assert_eq!(net.ip(), Ipv6Addr::LOCALHOST);
    }

    #[test]
    fn new_validates_and_constructs() {
        let v4 = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(v4.prefix(), 24);

        let v6 = Ipv6Net::new(Ipv6Addr::LOCALHOST, 128).unwrap();
        assert_eq!(v6.prefix(), 128);
    }

    #[test]
    fn mask_network_broadcast_v4() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        assert_eq!(net.mask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(net.network(), Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(net.broadcast(), Ipv4Addr::new(192, 168, 0, 255));
    }

    #[test]
    fn contains_v4() {
        let net: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        assert!(net.contains(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(net.contains(Ipv4Addr::new(192, 168, 0, 255)));
        assert!(!net.contains(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn contains_v6() {
        let net: Ipv6Net = "2001:db8::/32".parse().unwrap();
        assert!(net.contains("2001:db8::1".parse().unwrap()));
        assert!(net.contains("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!net.contains("2001:db9::".parse().unwrap()));
    }

    #[test]
    fn subnet_supernet_overlap() {
        let parent: Ipv4Net = "192.168.0.0/16".parse().unwrap();
        let child: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert!(child.is_subnet_of(parent));
        assert!(parent.is_supernet_of(child));
        assert!(parent.overlaps(child));
    }

    #[test]
    fn ipnet_enum_methods() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(net.is_ipv4());
        assert!(!net.is_ipv6());
        assert_eq!(net.prefix(), 8);
        assert_eq!(net.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(net.network(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(net.broadcast(), IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)));
        assert_eq!(net.mask(), IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)));
        assert!(net.contains("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn new_v4_new_v6_helpers() {
        let v4 = IpNet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let v6 = IpNet::new_v6(Ipv6Addr::LOCALHOST, 128).unwrap();
        assert!(v4.is_ipv4());
        assert!(v6.is_ipv6());
    }

    #[test]
    fn display_roundtrip() {
        let v4: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        assert_eq!(v4.to_string(), "192.168.0.0/24");

        let v6: Ipv6Net = "2001:db8::/32".parse().unwrap();
        assert_eq!(v6.to_string(), "2001:db8::/32");
    }

    #[test]
    fn try_from_str() {
        let net = Ipv4Net::try_from("10.0.0.0/8").unwrap();
        assert_eq!(net.prefix(), 8);

        let net = IpNet::try_from("::/0").unwrap();
        assert!(net.is_ipv6());
    }

    #[test]
    fn conversion_from_v4_v6_into_ipnet() {
        let v4: Ipv4Net = "1.2.3.4/32".parse().unwrap();
        let ipnet: IpNet = v4.into();
        assert!(ipnet.is_ipv4());
    }
}

#[cfg(test)]
mod fail_cases {
    use super::*;

    #[test]
    fn invalid_ip_is_rejected() {
        assert!(matches!("not-an-ip".parse::<Ipv4Net>(), Err(CidrParseError::InvalidIp(_)),));
    }

    #[test]
    fn empty_string_is_rejected() {
        assert!(matches!("".parse::<Ipv4Net>(), Err(CidrParseError::InvalidIp(_)),));
    }

    #[test]
    fn empty_prefix_is_rejected() {
        assert!(matches!(
            "192.168.1.1/".parse::<Ipv4Net>(),
            Err(CidrParseError::InvalidPrefix(_)),
        ));
    }

    #[test]
    fn non_numeric_prefix_is_rejected() {
        assert!(matches!(
            "192.168.1.1/xx".parse::<Ipv4Net>(),
            Err(CidrParseError::InvalidPrefix(_)),
        ));
    }

    #[test]
    fn ipv4_prefix_over_32_is_rejected() {
        assert!(matches!(
            "192.168.1.1/33".parse::<Ipv4Net>(),
            Err(CidrParseError::InvalidPrefixLength { prefix: 33, max: 32 }),
        ));
    }

    #[test]
    fn ipv6_prefix_over_128_is_rejected() {
        assert!(matches!(
            "2001:db8::/129".parse::<Ipv6Net>(),
            Err(CidrParseError::InvalidPrefixLength { prefix: 129, max: 128 }),
        ));
    }

    #[test]
    fn multiple_slashes_are_rejected() {
        assert!(matches!(
            "192.168.1.1/24/8".parse::<Ipv4Net>(),
            Err(CidrParseError::MultipleSlashes),
        ));
    }

    #[test]
    fn new_rejects_bad_prefix() {
        assert!(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 33).is_err());
        assert!(Ipv6Net::new(Ipv6Addr::LOCALHOST, 129).is_err());
        assert!(IpNet::new_v4(Ipv4Addr::new(10, 0, 0, 0), 40).is_err());
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn prefix_zero_covers_everything_v4() {
        let net: Ipv4Net = "192.168.1.1/0".parse().unwrap();
        assert_eq!(net.mask(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(net.network(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(net.broadcast(), Ipv4Addr::new(255, 255, 255, 255));
        assert!(net.contains(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(net.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn prefix_zero_covers_everything_v6() {
        let net: IpNet = "::/0".parse().unwrap();
        assert_eq!(net.network(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(
            net.broadcast(),
            IpAddr::V6(Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF))
        );
        assert!(net.contains("::".parse().unwrap()));
        assert!(net.contains("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn prefix_32_single_host_v4() {
        let net: Ipv4Net = "10.1.2.3/32".parse().unwrap();
        assert_eq!(net.network(), Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(net.broadcast(), Ipv4Addr::new(10, 1, 2, 3));
        assert!(net.contains(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!net.contains(Ipv4Addr::new(10, 1, 2, 4)));
    }

    #[test]
    fn non_aligned_address_is_normalized() {
        let net: Ipv4Net = "192.168.1.5/24".parse().unwrap();
        assert_eq!(net.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(net.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert!(net.contains(Ipv4Addr::new(192, 168, 1, 5)));
    }

    #[test]
    fn max_ipv4_net() {
        let net: Ipv4Net = "255.255.255.255/32".parse().unwrap();
        assert_eq!(net.network(), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn prefix_one_v4_mask() {
        let net: Ipv4Net = "128.0.0.0/1".parse().unwrap();
        assert_eq!(net.mask(), Ipv4Addr::new(128, 0, 0, 0));
        assert!(net.contains(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!net.contains(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn link_local_v6_network() {
        let net: Ipv6Net = "fe80::1/10".parse().unwrap();
        assert_eq!(net.mask(), Ipv6Addr::new(0xFFC0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(net.network(), Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 0));
        assert!(net.contains("fe80::2".parse().unwrap()));
        assert!(!net.contains("fec0::".parse().unwrap()));
    }

    #[test]
    fn equal_nets_are_sub_and_supernet() {
        let a: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let b: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        assert!(a.is_subnet_of(b));
        assert!(a.is_supernet_of(b));
        assert!(a.overlaps(b));
    }

    #[test]
    fn adjacent_nets_do_not_overlap() {
        let a: Ipv4Net = "192.168.0.0/24".parse().unwrap();
        let b: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert!(!a.overlaps(b));
    }

    #[test]
    fn ipv4_address_is_never_in_ipv6_net() {
        let net: IpNet = "::/0".parse().unwrap();
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn fully_contained_overlap() {
        let outer: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let inner: Ipv4Net = "10.1.0.0/16".parse().unwrap();
        assert!(outer.overlaps(inner));
        assert!(inner.is_subnet_of(outer));
    }
}
