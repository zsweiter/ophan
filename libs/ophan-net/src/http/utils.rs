use http::{request::Parts, uri::Scheme};

use crate::http::header;

#[inline(always)]
pub fn client_host(req: &Parts, from_proxy: bool) -> Option<&str> {
    #[allow(clippy::collapsible_if)]
    if from_proxy {
        if let Some(forwarded) = req.headers.get(&header::X_FORWARDED_HOST).and_then(|h| h.to_str().ok()) {
            return forwarded.split(',').next().map(|s| strip_port(s.trim()));
        }
    }

    if let Some(host) = req.uri.host() {
        return Some(strip_port(host));
    }

    req.headers.get(http::header::HOST).and_then(|value| value.to_str().ok()).map(strip_port)
}

/// Removes the port from an authority host (`example.com:8080`, `[::1]:8080`) and the
/// brackets of an IPv6 literal (`[::1]` → `::1`).
#[inline]
pub fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split_once(']').map_or(host, |(ip, _)| ip);
    }

    match host.split_once(':') {
        // A bare IPv6 address has more than one colon and no port.
        Some((name, port)) if !port.contains(':') => name,
        _ => host,
    }
}

/// Normalizes a request path the way an origin server resolves it: percent-encoded
/// unreserved characters are decoded, `.`/`..` segments are removed and repeated
/// slashes are merged. Returns `None` when the path is already normal.
pub fn normalize_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();

    let suspicious =
        memchr::memchr2_iter(b'%', b'/', bytes).any(|i| bytes[i] == b'%' || matches!(bytes.get(i + 1), Some(b'/' | b'.')));

    if !suspicious {
        return None;
    }

    let decoded = decode_unreserved(path);
    let mut segments: Vec<&str> = Vec::new();

    for segment in decoded.split('/') {
        match segment {
            "" | "." => {},
            ".." => {
                segments.pop();
            },
            other => segments.push(other),
        }
    }

    let mut out = String::with_capacity(decoded.len());
    for segment in &segments {
        out.push('/');
        out.push_str(segment);
    }

    let ends_with_dir = decoded.ends_with('/') || decoded.ends_with("/.") || decoded.ends_with("/..");
    if out.is_empty() || (ends_with_dir && !segments.is_empty()) {
        out.push('/');
    }

    (out != path).then_some(out)
}

/// Decodes `%XX` only when it encodes an unreserved character (RFC 3986 §2.3);
/// other escapes, like `%2F`, keep their meaning and are left untouched.
///
/// Works on raw bytes so multi-byte UTF-8 characters survive unchanged; the
/// input is a valid `str`, escapes only produce ASCII, and non-escape runs
/// always end at an ASCII boundary, so the output stays valid UTF-8.
fn decode_unreserved(path: &str) -> std::borrow::Cow<'_, str> {
    if memchr::memchr(b'%', path.as_bytes()).is_none() {
        return std::borrow::Cow::Borrowed(path);
    }

    let bytes = path.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            let c = hi << 4 | lo;
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
                out.push(c);
            } else {
                // Non-unreserved escapes are canonically uppercased.
                out.push(b'%');
                out.push(bytes[i + 1].to_ascii_uppercase());
                out.push(bytes[i + 2].to_ascii_uppercase());
            }
            i += 3;
            continue;
        }

        let run_end = memchr::memchr(b'%', &bytes[i + 1..]).map_or(bytes.len(), |rel| i + 1 + rel);
        out.extend_from_slice(&bytes[i..run_end]);
        i = run_end;
    }

    match String::from_utf8(out) {
        Ok(decoded) => std::borrow::Cow::Owned(decoded),
        Err(_) => std::borrow::Cow::Borrowed(path),
    }
}

#[inline]
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn is_request_https(session: &pingora::proxy::Session, from_proxy: bool) -> bool {
    #[allow(clippy::collapsible_if)]
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

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn strip_port_handles_names_and_ipv6() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("::1"), "::1");
    }

    #[test]
    fn normal_paths_are_untouched() {
        assert_eq!(normalize_path("/api/users/42"), None);
        assert_eq!(normalize_path("/"), None);
        assert_eq!(normalize_path("/files/report.v2.pdf"), None);
        assert_eq!(normalize_path("/a%2Fb"), None);
    }

    #[test]
    fn dot_segments_are_resolved() {
        assert_eq!(normalize_path("/public/../admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/public/%2e%2e/admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/a/./b/").as_deref(), Some("/a/b/"));
        assert_eq!(normalize_path("/../../etc/passwd").as_deref(), Some("/etc/passwd"));
        assert_eq!(normalize_path("/a/..").as_deref(), Some("/"));
    }

    #[test]
    fn slashes_are_merged_and_unreserved_decoded() {
        assert_eq!(normalize_path("//api///users").as_deref(), Some("/api/users"));
        assert_eq!(normalize_path("/%61pi/%7euser").as_deref(), Some("/api/~user"));
        assert_eq!(normalize_path("/a%2fb/%20x").as_deref(), Some("/a%2Fb/%20x"));
    }

    #[test]
    fn multi_byte_utf8_survives_decoding() {
        assert_eq!(decode_unreserved("/café%20x"), "/café%20x");
        assert_eq!(decode_unreserved("/café%61"), "/caféa");
        assert_eq!(decode_unreserved("/ñ/foo%2Fbar"), "/ñ/foo%2Fbar");
        assert_eq!(decode_unreserved("/日本語?a=%41"), "/日本語?a=A");
        assert_eq!(decode_unreserved("/中国%7e"), "/中国~");
    }

    #[test]
    fn normalize_respects_multi_byte_paths() {
        assert_eq!(normalize_path("/café%20x"), None);
        assert_eq!(normalize_path("/ñ/foo%2Fbar"), None);
        assert_eq!(normalize_path("/日本語?a=%41").as_deref(), Some("/日本語?a=A"));
        assert_eq!(normalize_path("/café/%7euser").as_deref(), Some("/café/~user"));
    }

    #[test]
    fn pure_ascii_paths_are_unchanged() {
        assert_eq!(decode_unreserved("/api/users/42?q=1&r=2"), "/api/users/42?q=1&r=2");
        assert_eq!(decode_unreserved("/%61pi/%7euser"), "/api/~user");
    }

    #[test]
    fn invalid_escapes_stay_literal() {
        assert_eq!(decode_unreserved("/a%zz"), "/a%zz");
        assert_eq!(decode_unreserved("/ab%"), "/ab%");
        assert_eq!(decode_unreserved("/a%4x"), "/a%4x");
        assert_eq!(decode_unreserved("/a%20%zz"), "/a%20%zz");
        assert_eq!(decode_unreserved("/日本%G1"), "/日本%G1");
    }
}
