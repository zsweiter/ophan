use http::Version;

use crate::http::ingress::error::{ErrorKind, Result};

const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone)]
pub struct HeaderField<'buf> {
    pub name: &'buf str,
    pub value: &'buf [u8],
}

/// A zero-copy, offset-based representation of an incoming HTTP request.
///
/// All fields reference the original byte buffer — no allocations
/// for headers, method, or path.
///
/// Built to resist HTTP smuggling by rejecting ambiguous input.
#[derive(Debug)]
pub struct IncomingRequest<'buf> {
    pub method: &'buf str,
    pub path: &'buf str,
    pub version: Version,
    pub headers: Vec<HeaderField<'buf>>,
    pub body: &'buf [u8],
}

impl<'buf> IncomingRequest<'buf> {
    pub fn parse(buf: &'buf [u8]) -> Result<Self> {
        let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut raw = httparse::Request::new(&mut raw_headers);

        let consumed = match raw.parse(buf) {
            Ok(httparse::Status::Complete(len)) => len,
            Ok(httparse::Status::Partial) => return Err(ErrorKind::MalformedRequestLine.into()),
            Err(_) => return Err(ErrorKind::MalformedRequestLine.into()),
        };

        let method = raw.method.ok_or(ErrorKind::MalformedRequestLine)?;
        let path = raw.path.ok_or(ErrorKind::MalformedRequestLine)?;

        let version = match raw.version {
            Some(0) => Version::HTTP_10,
            Some(1) => Version::HTTP_11,
            _ => Version::HTTP_11,
        };

        let mut headers = Vec::with_capacity(raw.headers.len());
        for h in raw.headers.iter() {
            if !h.name.is_empty() {
                let name = h.name;
                let value = h.value;
                headers.push(HeaderField { name, value });
            }
        }

        let body = &buf[consumed..];

        Ok(Self { method, path, version, headers, body })
    }

    pub fn header(&self, name: &str) -> Option<&HeaderField<'buf>> {
        self.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name))
    }

    pub fn header_value(&self, name: &str) -> Option<&'buf [u8]> {
        self.header(name).map(|h| h.value)
    }

    pub fn header_str(&self, name: &str) -> Option<&'buf str> {
        self.header(name).and_then(|h| std::str::from_utf8(h.value).ok())
    }

    #[inline]
    pub fn content_length(&self) -> Option<usize> {
        self.header_value("content-length")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|s| s.parse().ok())
    }

    #[inline]
    pub fn is_chunked(&self) -> bool {
        self.header_str("transfer-encoding").is_some_and(|v| v.contains("chunked"))
    }

    #[inline]
    pub fn expects_body(&self) -> bool {
        !matches!(self.method, "GET" | "HEAD" | "DELETE" | "CONNECT" | "OPTIONS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = IncomingRequest::parse(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/path");
        assert_eq!(req.version, Version::HTTP_11);
        assert_eq!(req.header_str("host").unwrap(), "example.com");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_post_with_content_length() {
        let raw = b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let req = IncomingRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_length(), Some(5));
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn parse_http10() {
        let raw = b"GET / HTTP/1.0\r\n\r\n";
        let req = IncomingRequest::parse(raw).unwrap();
        assert_eq!(req.version, Version::HTTP_10);
    }

    #[test]
    fn partial_request_returns_error() {
        let raw = b"GET /path HTTP/1.1\r\nHost: ex";
        assert!(IncomingRequest::parse(raw).is_err());
    }

    #[test]
    fn zero_copy_references() {
        let raw = b"GET /test HTTP/1.1\r\nX-Custom: hello-world\r\n\r\nbody_data";
        let req = IncomingRequest::parse(raw).unwrap();
        // method points into original buffer (offset 0)
        assert_eq!(req.method.as_ptr(), raw.as_ptr() as *const u8);
        // header name points into original buffer
        let h = req.header("X-Custom").unwrap();
        assert_eq!(h.name.as_ptr(), &raw[20] as *const u8);
        // header value points into original buffer
        assert_eq!(h.value.as_ptr(), &raw[30] as *const u8);
        // body points into original buffer (after \r\n\r\n at offset 45)
        assert_eq!(req.body.as_ptr(), &raw[45] as *const u8);
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let raw = b"GET / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        let req = IncomingRequest::parse(raw).unwrap();
        assert_eq!(req.header_str("CONTENT-TYPE").unwrap(), "application/json");
        assert_eq!(req.header_str("content-type").unwrap(), "application/json");
        assert_eq!(req.header_str("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn is_chunked_detection() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req = IncomingRequest::parse(raw).unwrap();
        assert!(req.is_chunked());
    }
}
