use flatkit::net::{IpNet, IpSet};
use http::{HeaderMap, HeaderName};
use ophan_net::http::header;
use std::net::IpAddr;

/// What happens to a connection that does not come from a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnUntrusted {
    /// The peer is a direct client: its socket address is the client address.
    #[default]
    Degrade,
    /// Only trusted proxies may connect; anyone else is rejected.
    Reject,
}

impl TryFrom<&str> for OnUntrusted {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "degrade" => Ok(Self::Degrade),
            "reject" => Ok(Self::Reject),
            _ => Err(format!("invalid on_untrusted '{value}', expected 'degrade' or 'reject'")),
        }
    }
}

/// Outcome of resolving the original client address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAddress {
    Resolved(IpAddr),
    /// A Unix socket listener received a request without a usable `real_ip_header`.
    MissingHeader,
}

/// Original client address behind edge proxies (Cloudflare, a load balancer, cloudflared).
///
/// `real_ip_header` is only read from peers in `allowed_ips`. On a Unix socket there is no
/// peer address, so the header is the only source and is always trusted.
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    allowed_ips: Option<IpSet>,
    real_ip_header: Option<HeaderName>,
    on_untrusted: OnUntrusted,
}

impl TrustedProxies {
    pub fn new(allowed_ips: &[IpNet], real_ip_header: Option<HeaderName>, on_untrusted: OnUntrusted) -> Self {
        let allowed_ips = (!allowed_ips.is_empty()).then(|| {
            let mut builder = IpSet::builder();
            for net in allowed_ips {
                builder.insert_network(net);
            }
            builder.build()
        });

        Self { allowed_ips, real_ip_header, on_untrusted }
    }

    pub fn real_ip_header(&self) -> Option<&HeaderName> {
        self.real_ip_header.as_ref()
    }

    pub fn on_untrusted(&self) -> OnUntrusted {
        self.on_untrusted
    }

    #[inline]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.allowed_ips.as_ref().is_some_and(|set| set.contains(ip))
    }

    /// Connection-level check: with `on_untrusted = reject` only trusted proxies get in.
    #[inline]
    pub fn admits(&self, peer: IpAddr) -> bool {
        self.on_untrusted == OnUntrusted::Degrade || self.is_trusted(peer)
    }

    /// Whether `peer` may supply forwarding headers. `None` is a Unix socket peer, which
    /// is always trusted: the header is the only source of the client address.
    #[inline]
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        peer.is_none_or(|ip| self.is_trusted(ip.to_canonical()))
    }

    /// Scheme the client used according to `X-Forwarded-Proto`, read only from a trusted peer.
    ///
    /// The last value is the one the closest proxy wrote; anything other than exactly `http`
    /// or `https` is ignored.
    pub fn forwarded_scheme(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<&'static str> {
        if !self.trusts(peer) {
            return None;
        }

        let values = headers.get_all(header::X_FORWARDED_PROTO);
        let last = values.iter().next_back()?.to_str().ok()?.rsplit(',').next()?.trim();

        if last.eq_ignore_ascii_case("https") {
            Some("https")
        } else if last.eq_ignore_ascii_case("http") {
            Some("http")
        } else {
            None
        }
    }

    /// Resolves the client address of a connection that passed [`Self::admits`].
    /// `peer` is `None` on Unix socket listeners.
    pub fn resolve(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> ClientAddress {
        let Some(peer) = peer.map(|ip| ip.to_canonical()) else {
            return match self.header_ip(headers) {
                Some(ip) => ClientAddress::Resolved(ip),
                None => ClientAddress::MissingHeader,
            };
        };

        if !self.is_trusted(peer) {
            return ClientAddress::Resolved(peer);
        }

        ClientAddress::Resolved(self.header_ip(headers).unwrap_or(peer))
    }

    /// Reads the client address from `real_ip_header`.
    ///
    /// Multi-hop headers (`X-Forwarded-For`, `Forwarded`) are walked from the right, skipping
    /// trusted proxies: the first untrusted hop is the client. Entries left of it are
    /// client-controlled and ignored.
    fn header_ip(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let name = self.real_ip_header.as_ref()?;

        let parse_hop: fn(&str) -> Option<IpAddr> = if *name == header::FORWARDED {
            Self::forwarded_for
        } else if *name == header::X_FORWARDED_FOR {
            |hop| hop.trim().parse::<IpAddr>().ok()
        } else {
            let value = headers.get(name)?.to_str().ok()?;
            return value.trim().parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
        };

        let mut values = headers.get_all(name).iter();
        let first = values.next()?.to_str().ok()?;

        match values.next() {
            None => self.rightmost_untrusted(first.rsplit(',').map(parse_hop)),
            Some(_) => {
                let joined = headers.get_all(name).iter().map(|v| v.to_str().ok()).collect::<Option<Vec<_>>>()?.join(",");
                self.rightmost_untrusted(joined.rsplit(',').map(parse_hop))
            },
        }
    }

    /// `hops` iterates from the closest hop to the farthest one.
    fn rightmost_untrusted(&self, hops: impl Iterator<Item = Option<IpAddr>>) -> Option<IpAddr> {
        let mut last = None;

        for hop in hops {
            // An unparsable hop breaks the chain of trust.
            let ip = hop?.to_canonical();

            if !self.is_trusted(ip) {
                return Some(ip);
            }

            last = Some(ip);
        }

        last
    }

    /// Extracts the `for=` address of one `Forwarded` element: `for=192.0.2.60;proto=http`
    /// or `for="[2001:db8:cafe::17]:4711"`.
    fn forwarded_for(element: &str) -> Option<IpAddr> {
        for directive in element.split(';') {
            let Some((key, val)) = directive.split_once('=') else {
                continue;
            };

            if !key.trim().eq_ignore_ascii_case("for") {
                continue;
            }

            let val = val.trim();
            let mut cleaned = val.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(val);

            if let Some(rest) = cleaned.strip_prefix('[') {
                cleaned = rest.split(']').next()?;
            } else if cleaned.matches(':').count() == 1 {
                cleaned = cleaned.split(':').next()?;
            }

            return cleaned.parse::<IpAddr>().ok();
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn nets(ranges: &[&str]) -> Vec<IpNet> {
        ranges.iter().map(|r| r.parse().unwrap()).collect()
    }

    fn headers(name: &HeaderName, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name.clone(), HeaderValue::from_str(value).unwrap());
        map
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cloudflare(mode: OnUntrusted) -> TrustedProxies {
        TrustedProxies::new(
            &nets(&["173.245.48.0/20"]),
            Some(HeaderName::from_static("cf-connecting-ip")),
            mode,
        )
    }

    #[test]
    fn untrusted_peer_degrades_to_socket_address() {
        let tp = cloudflare(OnUntrusted::Degrade);
        let h = headers(&HeaderName::from_static("cf-connecting-ip"), "1.2.3.4");

        assert_eq!(
            tp.resolve(Some(ip("203.0.113.9")), &h),
            ClientAddress::Resolved(ip("203.0.113.9"))
        );
        assert!(tp.admits(ip("203.0.113.9")));
    }

    #[test]
    fn reject_mode_only_admits_trusted_peers() {
        let tp = cloudflare(OnUntrusted::Reject);

        assert!(!tp.admits(ip("203.0.113.9")));
        assert!(tp.admits(ip("173.245.48.10")));
    }

    #[test]
    fn forwarded_scheme_takes_last_trusted_value() {
        let tp = cloudflare(OnUntrusted::Degrade);
        let cf = Some(ip("173.245.48.10"));

        assert_eq!(
            tp.forwarded_scheme(cf, &headers(&header::X_FORWARDED_PROTO, "https, http")),
            Some("http")
        );
        assert_eq!(
            tp.forwarded_scheme(cf, &headers(&header::X_FORWARDED_PROTO, "HTTPS")),
            Some("https")
        );
        assert_eq!(tp.forwarded_scheme(cf, &headers(&header::X_FORWARDED_PROTO, "gopher")), None);
        assert_eq!(
            tp.forwarded_scheme(Some(ip("203.0.113.9")), &headers(&header::X_FORWARDED_PROTO, "https")),
            None
        );
    }

    #[test]
    fn trusted_peer_uses_header_or_falls_back_to_socket() {
        let tp = cloudflare(OnUntrusted::Reject);
        let h = headers(&HeaderName::from_static("cf-connecting-ip"), "198.51.100.7");

        assert_eq!(
            tp.resolve(Some(ip("173.245.48.10")), &h),
            ClientAddress::Resolved(ip("198.51.100.7"))
        );
        assert_eq!(
            tp.resolve(Some(ip("173.245.48.10")), &HeaderMap::new()),
            ClientAddress::Resolved(ip("173.245.48.10"))
        );
    }

    #[test]
    fn xff_uses_rightmost_untrusted_hop() {
        let tp = TrustedProxies::new(&nets(&["10.0.0.0/8"]), Some(header::X_FORWARDED_FOR), OnUntrusted::Degrade);
        // Client spoofs 6.6.6.6; the trusted proxy appended the real address.
        let h = headers(&header::X_FORWARDED_FOR, "6.6.6.6, 198.51.100.7, 10.0.0.2");

        assert_eq!(
            tp.resolve(Some(ip("10.0.0.1")), &h),
            ClientAddress::Resolved(ip("198.51.100.7"))
        );
    }

    #[test]
    fn forwarded_skips_bad_directives() {
        let tp = TrustedProxies::new(&nets(&["10.0.0.0/8"]), Some(header::FORWARDED), OnUntrusted::Degrade);
        let h = headers(
            &header::FORWARDED,
            r#"for=6.6.6.6, proto=https;;for="[2001:db8::17]:4711", for=10.0.0.5"#,
        );

        assert_eq!(
            tp.resolve(Some(ip("10.0.0.1")), &h),
            ClientAddress::Resolved(ip("2001:db8::17"))
        );
    }

    #[test]
    fn mapped_addresses_are_canonical() {
        let tp = TrustedProxies::new(&nets(&["10.0.0.0/8"]), Some(header::X_FORWARDED_FOR), OnUntrusted::Degrade);
        let h = headers(&header::X_FORWARDED_FOR, "::ffff:198.51.100.7");

        assert_eq!(
            tp.resolve(Some(ip("::ffff:10.0.0.1")), &h),
            ClientAddress::Resolved(ip("198.51.100.7"))
        );
    }

    #[test]
    fn unix_socket_requires_the_header() {
        let tp = TrustedProxies::new(&[], Some(HeaderName::from_static("cf-connecting-ip")), OnUntrusted::Degrade);
        let h = headers(&HeaderName::from_static("cf-connecting-ip"), "198.51.100.7");

        assert_eq!(tp.resolve(None, &h), ClientAddress::Resolved(ip("198.51.100.7")));
        assert_eq!(tp.resolve(None, &HeaderMap::new()), ClientAddress::MissingHeader);
        assert_eq!(
            tp.resolve(None, &headers(&HeaderName::from_static("cf-connecting-ip"), "not-an-ip")),
            ClientAddress::MissingHeader
        );
    }

    #[test]
    fn unix_socket_takes_rightmost_xff_hop() {
        let tp = TrustedProxies::new(&[], Some(header::X_FORWARDED_FOR), OnUntrusted::Degrade);
        let h = headers(&header::X_FORWARDED_FOR, "6.6.6.6, 198.51.100.7");

        assert_eq!(tp.resolve(None, &h), ClientAddress::Resolved(ip("198.51.100.7")));
    }
}
