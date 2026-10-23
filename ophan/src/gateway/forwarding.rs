use http::HeaderValue;
use ophan_net::http::header;
use pingora::http::RequestHeader;
use std::net::{IpAddr, Ipv4Addr};

/// `X-Forwarded-*` and `X-Real-IP` headers sent to the upstream.
///
/// Only `X-Forwarded-For` keeps what a trusted proxy sent (the chain of hops); every other
/// header is always rewritten, so the upstream never sees client-forged values.
pub struct Forwarding<'a> {
    /// Socket address of the peer; `None` on Unix socket listeners.
    pub peer: Option<IpAddr>,
    pub peer_trusted: bool,
    pub client: IpAddr,
    pub scheme: &'static str,
    /// `Host` received from the client.
    pub host: Option<&'a HeaderValue>,
}

impl Forwarding<'_> {
    pub fn apply(&self, request: &mut RequestHeader) -> pingora::Result<()> {
        let client = Self::ip_value(self.client);

        match (request.headers.get(header::X_FORWARDED_FOR), self.peer) {
            (Some(chain), Some(peer)) if self.peer_trusted => {
                let mut value = Vec::with_capacity(chain.len() + 41);
                value.extend_from_slice(chain.as_bytes());
                value.extend_from_slice(b", ");

                let mut addr = [0u8; 45];
                let len = write_ip(&mut addr, peer);
                value.extend_from_slice(&addr[..len]);

                let value = HeaderValue::from_maybe_shared(bytes::Bytes::from(value))
                    .map_err(|e| pingora::Error::because(pingora::ErrorType::InternalError, "invalid X-Forwarded-For", e))?;
                request.insert_header(header::wire::X_FORWARDED_FOR, value)?;
            },
            (Some(_), None) if self.peer_trusted => {},
            (_, Some(peer)) if peer != self.client => {
                request.insert_header(header::wire::X_FORWARDED_FOR, Self::ip_value(peer))?
            },
            _ => request.insert_header(header::wire::X_FORWARDED_FOR, client.clone())?,
        }

        request.insert_header(header::wire::X_REAL_IP, client)?;
        request.insert_header(header::wire::X_FORWARDED_PROTO, HeaderValue::from_static(self.scheme))?;

        match self.host {
            Some(host) => request.insert_header(header::wire::X_FORWARDED_HOST, host.clone())?,
            None => {
                request.remove_header(&header::X_FORWARDED_HOST);
            },
        }

        Ok(())
    }

    fn ip_value(ip: IpAddr) -> HeaderValue {
        let mut buf = [0u8; 45];
        let len = write_ip(&mut buf, ip);

        let mut bytes = bytes::Bytes::from_owner(buf);
        bytes.truncate(len);

        HeaderValue::from_maybe_shared(bytes).unwrap_or_else(|_| HeaderValue::from_static(""))
    }
}

/// Writes `ip` in its textual form into `buf`.
///
/// Manual writers avoid the `Display`/`Write` formatting machinery on the request
/// path. Output is byte-identical to `std::net::IpAddr` `Display` (RFC 5952 for IPv6).
fn write_ip(buf: &mut [u8; 45], ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => write_ipv4(buf, v4),
        IpAddr::V6(v6) => write_ipv6(buf, v6),
    }
}

fn write_ipv4(buf: &mut [u8], v4: Ipv4Addr) -> usize {
    let mut len = 0;
    for (i, octet) in v4.octets().into_iter().enumerate() {
        if i > 0 {
            buf[len] = b'.';
            len += 1;
        }
        if octet >= 100 {
            buf[len] = b'0' + octet / 100;
            len += 1;
        }
        if octet >= 10 {
            buf[len] = b'0' + octet / 10 % 10;
            len += 1;
        }
        buf[len] = b'0' + octet % 10;
        len += 1;
    }
    len
}

/// Minimal lowercase hex digit table for nibble encoding.
const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Writes one 16-bit group without leading zeros, returning its length.
#[inline]
fn write_ipv6_segment(buf: &mut [u8], offset: usize, segment: u16) -> usize {
    if segment == 0 {
        buf[offset] = b'0';
        return 1;
    }

    // Least significant nibble first, written downwards from `digits - 1`, so the
    // group comes out in order and without leading zeros.
    let bits = 16 - segment.leading_zeros();
    let digits = bits.div_ceil(4) as usize;
    let mut pos = digits;
    let mut v = segment;

    loop {
        pos -= 1;
        buf[offset + pos] = HEX_DIGITS[(v & 0xf) as usize];
        v >>= 4;
        if pos == 0 {
            break;
        }
    }

    digits
}

/// Writes `segments` colon-separated. Empty slices produce nothing.
fn write_ipv6_groups(buf: &mut [u8], offset: usize, segments: &[u16]) -> usize {
    let mut len = 0;
    for (i, segment) in segments.iter().enumerate() {
        if i > 0 {
            buf[offset + len] = b':';
            len += 1;
        }
        len += write_ipv6_segment(buf, offset + len, *segment);
    }
    len
}

/// Writes `v6` following RFC 5952: lowercase hex, no leading zeros and the
/// leftmost longest run of at least two zero groups compressed to `::`.
fn write_ipv6(buf: &mut [u8; 45], v6: std::net::Ipv6Addr) -> usize {
    let segments = v6.segments();

    // RFC 5952 §5: IPv4-mapped addresses end in dotted decimal (`std` does the same).
    if let Some(mapped) = v6.to_ipv4_mapped() {
        let len = b"::ffff:".len();
        buf[..len].copy_from_slice(b"::ffff:");
        return len + write_ipv4(&mut buf[len..], mapped);
    }

    // Longest zero run, leftmost on ties (`>` keeps the first one).
    let (mut start, mut longest) = (0usize, 0usize);
    let mut current = 0usize;
    for (i, segment) in segments.iter().enumerate() {
        if *segment == 0 {
            current += 1;
            if current > longest {
                longest = current;
                start = i + 1 - current;
            }
        } else {
            current = 0;
        }
    }

    if longest <= 1 {
        write_ipv6_groups(buf, 0, &segments)
    } else {
        let mut len = write_ipv6_groups(buf, 0, &segments[..start]);
        buf[len] = b':';
        buf[len + 1] = b':';
        len += 2;
        len + write_ipv6_groups(buf, len, &segments[start + longest..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&'static str, &'static str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            req.insert_header(*name, *value).unwrap();
        }
        req
    }

    fn header_of(req: &RequestHeader, name: &str) -> Option<String> {
        req.headers.get(name).map(|v| v.to_str().unwrap().to_string())
    }

    #[test]
    fn formats_addresses() {
        for ip in ["0.0.0.0", "9.10.99.100", "255.255.255.255", "203.0.113.9", "2001:db8::1", "::ffff:10.0.0.1"] {
            assert_eq!(Forwarding::ip_value(ip.parse().unwrap()).to_str().unwrap(), ip);
        }
    }

    /// The manual IPv6 writer must stay byte-identical to `std` `Display` (RFC 5952).
    #[test]
    fn ipv6_matches_std_formatting() {
        for (input, expected) in [
            ("0000:0000:0000:0000:0000:0000:0000:0000", "::"),
            ("0::1", "::1"),
            ("1:0:0:2:3:4:5:6", "1::2:3:4:5:6"),
            ("0:0:1:0:0:0:3:4", "0:0:1::3:4"),
            ("0:0:0:1:0:0:0:2", "::1:0:0:0:2"),
            ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
            ("a:b:c:d:e:f:0:0", "a:b:c:d:e:f::"),
            (
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
            ("0:0:0:0:0:0:0:ffff", "::ffff"),
        ] {
            let v6 = input.parse().unwrap();
            assert_eq!(Forwarding::ip_value(v6).to_str().unwrap(), expected, "input {input}");
            assert_eq!(
                Forwarding::ip_value(v6).to_str().unwrap(),
                v6.to_string(),
                "std mismatch for {input}"
            );
        }
    }

    #[test]
    fn trusted_chain_is_extended_with_manual_ip_writer() {
        let mut req = request(&[("x-forwarded-for", "2001:db8:0:0:1:0:0:1, 2001:db8::9")]);
        let host = HeaderValue::from_static("api.example.com");

        Forwarding {
            peer: Some("0:0:0:0:0:0:1:0".parse().unwrap()),
            peer_trusted: true,
            client: "2001:db8::1".parse().unwrap(),
            scheme: "https",
            host: Some(&host),
        }
        .apply(&mut req)
        .unwrap();

        assert_eq!(
            header_of(&req, "x-forwarded-for").as_deref(),
            Some("2001:db8:0:0:1:0:0:1, 2001:db8::9, ::1:0")
        );
    }

    #[test]
    fn untrusted_peer_values_are_replaced() {
        let mut req =
            request(&[("x-forwarded-for", "6.6.6.6"), ("x-forwarded-proto", "https"), ("x-forwarded-host", "evil.example")]);
        let host = HeaderValue::from_static("api.example.com");

        Forwarding {
            peer: Some("203.0.113.9".parse().unwrap()),
            peer_trusted: false,
            client: "203.0.113.9".parse().unwrap(),
            scheme: "http",
            host: Some(&host),
        }
        .apply(&mut req)
        .unwrap();

        assert_eq!(header_of(&req, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(header_of(&req, "x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(header_of(&req, "x-forwarded-host").as_deref(), Some("api.example.com"));
        assert_eq!(header_of(&req, "x-real-ip").as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn trusted_proxy_chain_is_extended_but_host_is_rewritten() {
        let mut req = request(&[("x-forwarded-for", "198.51.100.7"), ("x-forwarded-host", "evil.example")]);
        let host = HeaderValue::from_static("api.example.com");

        Forwarding {
            peer: Some("173.245.48.10".parse().unwrap()),
            peer_trusted: true,
            client: "198.51.100.7".parse().unwrap(),
            scheme: "https",
            host: Some(&host),
        }
        .apply(&mut req)
        .unwrap();

        assert_eq!(
            header_of(&req, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 173.245.48.10")
        );
        assert_eq!(header_of(&req, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(header_of(&req, "x-forwarded-host").as_deref(), Some("api.example.com"));
    }
}
