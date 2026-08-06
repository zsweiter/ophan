use bytes::Bytes;
use http::{HeaderMap, Method, Uri, Version};

use crate::http::protocol::error::Result;

const SPACE: u8 = b' ';

const HOST_HEADER: &[u8] = b"Host: ";
const CONTENT_LENGTH_HEADER: &[u8] = b"Content-Length: ";

pub const CRLF: &[u8; 2] = b"\r\n";
pub const HEADER_KV_DELIMITER: &[u8; 2] = b": ";

/// Serializes an HTTP request into its wire-format representation.
///
/// RFC 7230 3.1.1 (Request-Line), RFC 7230 3.2 (Header Fields),
/// RFC 7230 3.3 (Message Body).
///
/// Request-Line: `<METHOD> SP <request-target> SP <HTTP-version> CRLF`
///
/// The `Host` header is generated from the URI authority.
/// `Content-Length` is generated when a body is supplied.
///
/// Bodies are omitted for GET, HEAD, DELETE, CONNECT, OPTIONS.
///
/// The resulting byte sequence is intended to be written directly
/// to a TCP/TLS stream without any transformation.
pub struct Encoder<'a> {
    method: Method,
    uri: Uri,
    version: Version,
    headers: &'a HeaderMap,
    body: Option<Bytes>,
}

impl<'a> Encoder<'a> {
    #[inline]
    pub fn new(method: Method, uri: Uri, headers: &'a HeaderMap) -> Self {
        Self {
            method,
            uri,
            version: Version::default(),
            headers,
            body: None,
        }
    }

    #[inline]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    #[inline]
    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }

    #[inline]
    pub fn finalize(self) -> Result<Vec<u8>> {
        let path_and_query = self.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let host = self.uri.host().unwrap_or("");
        let version = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        };

        let body = if method_supports_body(&self.method) { self.body } else { None };

        let body_len = body.as_ref().map_or(0, Bytes::len);

        let mut content_length_buf = itoa::Buffer::new();
        let content_length = if body_len > 0 {
            Some(content_length_buf.format(body_len))
        } else {
            None
        };

        let mut total_size = self.method.as_str().len() + 1 + path_and_query.len() + 1 + version.len() + CRLF.len();

        if !host.is_empty() {
            total_size += HOST_HEADER.len() + host.len() + CRLF.len();
        }

        for (name, value) in self.headers.iter() {
            total_size += name.as_str().len() + 2 + value.as_bytes().len() + CRLF.len();
        }

        if let Some(content_length) = content_length {
            total_size += CONTENT_LENGTH_HEADER.len() + content_length.len() + CRLF.len();
        }

        total_size += CRLF.len();
        total_size += body_len;

        let mut buf = Vec::with_capacity(total_size);

        buf.extend_from_slice(self.method.as_str().as_bytes());
        buf.push(SPACE);
        buf.extend_from_slice(path_and_query.as_bytes());
        buf.push(SPACE);
        buf.extend_from_slice(version.as_bytes());
        buf.extend_from_slice(CRLF);

        if !host.is_empty() {
            buf.extend_from_slice(HOST_HEADER);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(CRLF);
        }

        if let Some(content_length) = content_length {
            buf.extend_from_slice(CONTENT_LENGTH_HEADER);
            buf.extend_from_slice(content_length.as_bytes());
            buf.extend_from_slice(CRLF);
        }

        for (name, value) in self.headers.iter() {
            buf.extend_from_slice(name.as_str().as_bytes());
            buf.extend_from_slice(HEADER_KV_DELIMITER);
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(CRLF);
        }

        buf.extend_from_slice(CRLF);

        if let Some(body) = body {
            buf.extend_from_slice(&body);
        }

        debug_assert_eq!(buf.len(), total_size, "precomputed capacity mismatch");

        Ok(buf)
    }
}

#[inline(always)]
fn method_supports_body(method: &Method) -> bool {
    !matches!(
        method,
        &Method::GET | &Method::HEAD | &Method::DELETE | &Method::CONNECT | &Method::OPTIONS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use http::header::USER_AGENT;

    #[test]
    fn serialize_get_request() {
        let headers = HeaderMap::new();
        let req = Encoder::new(Method::GET, "http://example.com/test".parse().unwrap(), &headers);
        let bytes = req.finalize().unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            concat!("GET /test HTTP/1.1\r\n", "Host: example.com\r\n", "\r\n")
        );
    }

    #[test]
    fn serialize_post_request_with_body() {
        let headers = HeaderMap::new();
        let req = Encoder::new(Method::POST, "http://example.com/upload".parse().unwrap(), &headers)
            .with_body(Bytes::from_static(b"hello"));
        let bytes = req.finalize().unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            concat!(
                "POST /upload HTTP/1.1\r\n",
                "Host: example.com\r\n",
                "Content-Length: 5\r\n",
                "\r\n",
                "hello"
            )
        );
    }

    #[test]
    fn head_request_does_not_emit_body() {
        let headers = HeaderMap::new();
        let req =
            Encoder::new(Method::HEAD, "http://example.com".parse().unwrap(), &headers).with_body(Bytes::from_static(b"ignored"));
        let bytes = req.finalize().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("Content-Length"));
        assert!(!text.contains("ignored"));
    }

    #[test]
    fn serialize_custom_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "my-client".parse().unwrap());
        let req = Encoder::new(Method::GET, "http://example.com".parse().unwrap(), &headers);
        let bytes = req.finalize().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(&format!("{USER_AGENT}: my-client")));
    }

    #[test]
    fn content_length_matches_body_size() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"123456789");
        let req = Encoder::new(Method::POST, "http://example.com".parse().unwrap(), &headers).with_body(body);
        let bytes = req.finalize().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Content-Length: 9"));
    }

    #[test]
    fn serialize_http_10() {
        let headers = HeaderMap::new();
        let req = Encoder::new(Method::GET, "http://example.com".parse().unwrap(), &headers).with_version(Version::HTTP_10);
        let bytes = req.finalize().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("GET / HTTP/1.0\r\n"));
    }

    #[test]
    fn uri_without_host_does_not_emit_host_header() {
        let headers = HeaderMap::new();
        let req = Encoder::new(Method::GET, "/local/path".parse().unwrap(), &headers);
        let bytes = req.finalize().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("Host:"));
    }
}
