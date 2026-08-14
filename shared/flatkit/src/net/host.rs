use bytes::Bytes;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::{fmt, vec};

/// see https://datatracker.ietf.org/doc/html/rfc1035#section-3.3
const MAX_DNS_HOST_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    #[inline]
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    pub fn parse_prefix(s: &str) -> (Self, &str) {
        if let Some(remainder) = s.strip_prefix("https://") {
            (Self::Https, remainder)
        } else if let Some(remainder) = s.strip_prefix("http://") {
            (Self::Http, remainder)
        } else {
            (Self::Http, s)
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Http => "http",
            Self::Https => "https",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAddrError {
    EmptyInput,
    InvalidPort,
    HostTooLong,
}

impl std::error::Error for HostAddrError {}

impl fmt::Display for HostAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::EmptyInput => "host address cannot be empty",
            Self::InvalidPort => "invalid port number after ':'",
            Self::HostTooLong => "host name exceeds the RFC limit of 256 characters",
        };
        f.write_str(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostAddr {
    pub scheme: Scheme,
    pub host: Bytes,
    pub port: u16,
}

impl HostAddr {
    #[inline]
    pub fn host(&self) -> &str {
        unsafe {
            std::str::from_utf8_unchecked(&self.host) // Safety: previus checked
        }
    }

    #[inline]
    pub fn into_parts(&self) -> (&str, u16) {
        (self.host(), self.port)
    }

    #[inline]
    pub fn sni_name(&self) -> &str {
        self.host()
    }

    #[inline]
    pub fn is_https(&self) -> bool {
        matches!(self.scheme, Scheme::Https)
    }

    #[inline]
    pub fn is_http(&self) -> bool {
        matches!(self.scheme, Scheme::Http)
    }
}

impl TryFrom<Bytes> for HostAddr {
    type Error = HostAddrError;

    fn try_from(buffer: Bytes) -> Result<Self, Self::Error> {
        let raw_str = std::str::from_utf8(&buffer).map_err(|_| HostAddrError::EmptyInput)?.trim();

        if raw_str.is_empty() {
            return Err(HostAddrError::EmptyInput);
        }

        let (scheme, remainder) = Scheme::parse_prefix(raw_str);

        let (host_str, port) = if let Some(colon_idx) = remainder.rfind(':') {
            let h = &remainder[..colon_idx];
            let p_str = &remainder[colon_idx + 1..];

            let p = u16::from_str(p_str).map_err(|_| HostAddrError::InvalidPort)?;
            (h, p)
        } else {
            (remainder, scheme.default_port())
        };

        if host_str.is_empty() {
            return Err(HostAddrError::EmptyInput);
        }

        if host_str.len() > MAX_DNS_HOST_LEN {
            return Err(HostAddrError::HostTooLong);
        }

        let start_offset = host_str.as_ptr() as usize - buffer.as_ptr() as usize;
        let end_offset = start_offset + host_str.len();
        let host_bytes = buffer.slice(start_offset..end_offset);

        Ok(Self { scheme, host: host_bytes, port })
    }
}

impl TryFrom<&str> for HostAddr {
    type Error = HostAddrError;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let buf = Bytes::copy_from_slice(s.as_bytes());
        Self::try_from(buf)
    }
}

impl<'a> From<(&'a str, u16)> for HostAddr {
    fn from((host, port): (&'a str, u16)) -> Self {
        Self {
            scheme: Scheme::Http,
            host: Bytes::copy_from_slice(host.as_bytes()),
            port,
        }
    }
}

impl<'a> From<&'a HostAddr> for (&'a str, u16) {
    #[inline]
    fn from(addr: &'a HostAddr) -> Self {
        (addr.host(), addr.port)
    }
}

impl FromStr for HostAddr {
    type Err = HostAddrError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let buf = Bytes::copy_from_slice(s.as_bytes());
        Self::try_from(buf)
    }
}

impl ToSocketAddrs for HostAddr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let host_slice = self.host();

        (host_slice, self.port).to_socket_addrs()
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host(), self.port)
    }
}

#[cfg(test)]
mod happy_cases {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn parse_plain_host_uses_http_default_port() {
        let addr = HostAddr::try_from(Bytes::from_static(b"example.com")).unwrap();
        assert_eq!(addr.scheme, Scheme::Http);
        assert_eq!(addr.port, 80);
        assert_eq!(addr.host(), "example.com");
    }

    #[test]
    fn parse_https_scheme() {
        let addr = HostAddr::from_str("https://example.com").unwrap();
        assert_eq!(addr.scheme, Scheme::Https);
        assert_eq!(addr.port, 443);
    }

    #[test]
    fn parse_host_with_explicit_port() {
        let addr = HostAddr::from_str("example.com:8080").unwrap();
        assert_eq!(addr.host(), "example.com");
        assert_eq!(addr.port, 8080);
        assert_eq!(addr.scheme, Scheme::Http);
    }

    #[test]
    fn parse_scheme_with_explicit_port() {
        let addr = HostAddr::from_str("http://example.com:8080").unwrap();
        assert_eq!(addr.scheme, Scheme::Http);
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn parse_prefix_detects_scheme_and_rest() {
        assert_eq!(Scheme::parse_prefix("https://x"), (Scheme::Https, "x"));
        assert_eq!(Scheme::parse_prefix("http://x"), (Scheme::Http, "x"));
        assert_eq!(Scheme::parse_prefix("x"), (Scheme::Http, "x"));
    }

    #[test]
    fn default_ports() {
        assert_eq!(Scheme::Http.default_port(), 80);
        assert_eq!(Scheme::Https.default_port(), 443);
    }

    #[test]
    fn accessors() {
        let addr = HostAddr::from_str("https://example.com:443").unwrap();
        assert!(addr.is_https());
        assert!(!addr.is_http());
        assert_eq!(addr.into_parts(), ("example.com", 443));
        assert_eq!(addr.sni_name(), "example.com");
    }

    #[test]
    fn scheme_display() {
        assert_eq!(Scheme::Http.to_string(), "http");
        assert_eq!(Scheme::Https.to_string(), "https");
    }

    #[test]
    fn from_tuple_and_back() {
        let addr = HostAddr::from(("example.com", 8080u16));
        assert_eq!(addr.host(), "example.com");
        assert_eq!(addr.port, 8080);

        let parts: (&str, u16) = (&addr).into();
        assert_eq!(parts, ("example.com", 8080));
    }

    #[test]
    fn display_includes_scheme_host_port() {
        let addr = HostAddr::from_str("http://example.com:8080").unwrap();
        assert_eq!(addr.to_string(), "http://example.com:8080");
    }

    #[test]
    fn trim_surrounding_whitespace() {
        let addr = HostAddr::from_str("  example.com  ").unwrap();
        assert_eq!(addr.host(), "example.com");
    }
}

#[cfg(test)]
mod fail_cases {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(HostAddr::try_from(Bytes::from_static(b"")), Err(HostAddrError::EmptyInput),);
    }

    #[test]
    fn whitespace_only_is_rejected() {
        assert_eq!(HostAddr::try_from(Bytes::from_static(b"   ")), Err(HostAddrError::EmptyInput),);
    }

    #[test]
    fn invalid_port_is_rejected() {
        assert_eq!(HostAddr::from_str("example.com:abc"), Err(HostAddrError::InvalidPort),);
    }

    #[test]
    fn port_out_of_range_is_rejected() {
        assert_eq!(HostAddr::from_str("example.com:70000"), Err(HostAddrError::InvalidPort),);
    }

    #[test]
    fn negative_port_is_rejected() {
        assert_eq!(HostAddr::from_str("example.com:-1"), Err(HostAddrError::InvalidPort),);
    }

    #[test]
    fn trailing_colon_is_rejected() {
        assert_eq!(HostAddr::from_str("example.com:"), Err(HostAddrError::InvalidPort),);
    }

    #[test]
    fn scheme_without_host_is_rejected() {
        assert_eq!(HostAddr::from_str("https://"), Err(HostAddrError::EmptyInput),);
    }

    #[test]
    fn non_utf8_bytes_are_rejected() {
        assert_eq!(
            HostAddr::try_from(Bytes::from_static(&[0xFF, 0xFE, 0x00])),
            Err(HostAddrError::EmptyInput),
        );
    }

    #[test]
    fn host_over_256_chars_is_rejected() {
        let long = format!("{}.example.com", "a".repeat(260));
        assert_eq!(HostAddr::from_str(&long), Err(HostAddrError::HostTooLong),);
    }

    #[test]
    fn non_numeric_port_fragment_is_rejected() {
        assert_eq!(HostAddr::from_str("exa:mple.com"), Err(HostAddrError::InvalidPort),);
    }

    #[test]
    fn only_last_colon_is_treated_as_port_separator() {
        let addr = HostAddr::from_str("example.com:80:90").unwrap();
        assert_eq!(addr.host(), "example.com:80");
        assert_eq!(addr.port, 90);
    }

    #[test]
    fn uppercase_scheme_colons_are_parsed_as_port() {
        assert_eq!(HostAddr::from_str("HTTP://example.com"), Err(HostAddrError::InvalidPort),);
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn host_at_exactly_256_chars_is_accepted() {
        let host = format!("{}.example.com", "a".repeat(244));
        assert_eq!(host.len(), 256);
        let addr = HostAddr::from_str(&host).unwrap();
        assert_eq!(addr.host(), host);
    }

    #[test]
    fn host_at_255_chars_is_accepted() {
        let host = format!("{}.com", "a".repeat(251));
        assert_eq!(host.len(), 255);
        assert!(HostAddr::from_str(&host).is_ok());
    }

    #[test]
    fn single_character_host() {
        let addr = HostAddr::from_str("a").unwrap();
        assert_eq!(addr.host(), "a");
    }

    #[test]
    fn port_zero_is_accepted() {
        let addr = HostAddr::from_str("example.com:0").unwrap();
        assert_eq!(addr.port, 0);
    }

    #[test]
    fn port_max_u16_is_accepted() {
        let addr = HostAddr::from_str("example.com:65535").unwrap();
        assert_eq!(addr.port, 65535);
    }

    #[test]
    fn ipv6_bracketed_literal_host() {
        let addr = HostAddr::from_str("[::1]:8080").unwrap();
        assert_eq!(addr.host(), "[::1]");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn non_numeric_port_fragment_is_rejected() {
        assert_eq!(HostAddr::from_str("exa:mple.com"), Err(HostAddrError::InvalidPort),);
    }
}
