use http::{request::Parts, uri::Scheme};

use crate::http::header;

#[inline(always)]
pub fn client_host(req: &Parts, from_proxy: bool) -> Option<&str> {
    if from_proxy {
        if let Some(forwarded) = req.headers.get(&header::X_FORWARDED_HOST).and_then(|h| h.to_str().ok()) {
            return forwarded.split(',').next().map(|s| s.trim());
        }
    }

    if let Some(host) = req.uri.host() {
        return Some(host);
    }

    req.headers.get(http::header::HOST).and_then(|value| value.to_str().ok()).map(|host_str| {
        if let Some(pos) = host_str.find(':') {
            &host_str[..pos]
        } else {
            host_str
        }
    })
}

pub fn is_request_https(session: &pingora::proxy::Session, from_proxy: bool) -> bool {
    if from_proxy {
        if let Some(proto) = session.req_header().headers.get(&header::X_FORWARDED_PROTO) {
            if let Ok(proto_str) = proto.to_str() {
                return proto_str.eq_ignore_ascii_case("https");
            }
        }
    }

    if session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some() {
        return true;
    }

    if session.req_header().uri.scheme().is_some_and(|s| *s == Scheme::HTTPS) {
        return true;
    }

    false
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for [u8] {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl AsBytes for str {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsBytes for http::HeaderValue {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[inline]
pub fn contains_bytes<T, P>(haystack: &T, needle: &P) -> bool
where
    T: AsBytes + ?Sized,
    P: AsBytes + ?Sized,
{
    memchr::memmem::find(haystack.as_bytes(), needle.as_bytes()).is_some()
}
