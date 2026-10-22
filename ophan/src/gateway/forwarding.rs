use http::HeaderValue;
use ophan_net::http::header;
use pingora::http::RequestHeader;
use std::net::IpAddr;

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
        let received = request.headers.get(header::X_FORWARDED_FOR).and_then(|v| v.to_str().ok());

        let forwarded_for = match (received, self.peer) {
            (Some(chain), Some(peer)) if self.peer_trusted => format!("{chain}, {peer}"),
            (Some(chain), None) if self.peer_trusted => chain.to_string(),
            (_, Some(peer)) => peer.to_string(),
            (_, None) => self.client.to_string(),
        };

        request.insert_header(header::X_FORWARDED_FOR, forwarded_for)?;
        request.insert_header(header::X_REAL_IP, self.client.to_string())?;
        request.insert_header(header::X_FORWARDED_PROTO, HeaderValue::from_static(self.scheme))?;

        match self.host {
            Some(host) => request.insert_header(header::X_FORWARDED_HOST, host.clone())?,
            None => {
                request.remove_header(&header::X_FORWARDED_HOST);
            },
        }

        Ok(())
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
