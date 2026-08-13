use network_types::eth::EthernetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The packet ended before the required header or field was available.
    Truncated,

    /// The Ethernet header is unknow
    InvalidEtherType(u16),

    /// The VLAN header is malformed or otherwise invalid.
    InvalidVlanHeader,

    /// The IPv4 header is malformed or otherwise invalid.
    InvalidIpv4Header,

    /// The IPv4 Internet Header Length (IHL) is smaller than the minimum
    /// valid IPv4 header size.
    InvalidIpv4Ihl,

    /// The IPv4 total length is invalid or exceeds the available packet data.
    InvalidIpv4TotalLength,

    /// The IPv6 header is malformed or otherwise invalid.
    InvalidIpv6Header,

    /// The IPv6 payload length is invalid or exceeds the available packet data.
    InvalidIpv6PayloadLength,

    /// The IPv6 extension header is malformed or otherwise invalid.
    InvalidIpv6ExtensionHeader,

    /// The number of IPv6 extension headers exceeds the parser limit.
    Ipv6ExtensionLimitExceeded,

    /// The IPv6 Fragment header is malformed or otherwise invalid.
    InvalidIpv6FragmentHeader,

    /// The TCP header is malformed or otherwise invalid.
    InvalidTcpHeader,

    /// The TCP data offset is invalid or smaller than the minimum TCP header size.
    InvalidTcpDataOffset,

    /// The UDP header is malformed or otherwise invalid.
    InvalidUdpHeader,

    /// The UDP length field is invalid or exceeds the available packet data.
    InvalidUdpLength,
}

impl ErrorKind {
    /// Returns a stable machine-readable identifier for this error.
    ///
    /// These identifiers can be used as metric labels, log fields, or
    /// externally visible error codes. They should not be changed casually.
    #[inline(always)]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::InvalidEtherType(_) => "invalid_ethernet_header",
            Self::InvalidVlanHeader => "invalid_vlan_header",
            Self::InvalidIpv4Header => "invalid_ipv4_header",
            Self::InvalidIpv4Ihl => "invalid_ipv4_ihl",
            Self::InvalidIpv4TotalLength => "invalid_ipv4_total_length",
            Self::InvalidIpv6Header => "invalid_ipv6_header",
            Self::InvalidIpv6PayloadLength => "invalid_ipv6_payload_length",
            Self::InvalidIpv6ExtensionHeader => "invalid_ipv6_extension_header",
            Self::Ipv6ExtensionLimitExceeded => "ipv6_extension_limit_exceeded",
            Self::InvalidIpv6FragmentHeader => "invalid_ipv6_fragment_header",
            Self::InvalidTcpHeader => "invalid_tcp_header",
            Self::InvalidTcpDataOffset => "invalid_tcp_data_offset",
            Self::InvalidUdpHeader => "invalid_udp_header",
            Self::InvalidUdpLength => "invalid_udp_length",
        }
    }

    /// Returns a human-readable description of this error.
    #[inline(always)]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Truncated => "the packet ended before the required data was available",
            Self::InvalidEtherType(_) => "the Ethernet header is malformed or invalid",
            Self::InvalidVlanHeader => "the VLAN header is malformed or invalid",
            Self::InvalidIpv4Header => "the IPv4 header is malformed or invalid",
            Self::InvalidIpv4Ihl => "the IPv4 IHL is smaller than the minimum header size",
            Self::InvalidIpv4TotalLength => "the IPv4 total length is invalid or exceeds the available packet data",
            Self::InvalidIpv6Header => "the IPv6 header is malformed or invalid",
            Self::InvalidIpv6PayloadLength => "the IPv6 payload length is invalid or exceeds the available packet data",
            Self::InvalidIpv6ExtensionHeader => "the IPv6 extension header is malformed or invalid",
            Self::Ipv6ExtensionLimitExceeded => "the IPv6 extension-header parsing limit was exceeded",
            Self::InvalidIpv6FragmentHeader => "the IPv6 Fragment header is malformed or invalid",
            Self::InvalidTcpHeader => "the TCP header is malformed or invalid",
            Self::InvalidTcpDataOffset => "the TCP data offset is smaller than the minimum TCP header size",
            Self::InvalidUdpHeader => "the UDP header is malformed or invalid",
            Self::InvalidUdpLength => "the UDP length is invalid or exceeds the available packet data",
        }
    }
}

impl From<EthernetError> for ErrorKind {
    #[inline(always)]
    fn from(error: EthernetError) -> Self {
        match error {
            EthernetError::InvalidEtherType(ether_type) => Self::InvalidEtherType(ether_type),
        }
    }
}
