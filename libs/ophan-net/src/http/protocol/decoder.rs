use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::http::protocol::error::{ErrorKind, Result};

const MAX_HEADERS: usize = 64;
const HEADER_BUF_SIZE: usize = 8192;
const READ_BUF_SIZE: usize = 4096;

// pub(super) const MAX_HEADERS: usize = 256;

// pub(super) const INIT_HEADER_BUF_SIZE: usize = 4096;
// pub(super) const MAX_HEADER_SIZE: usize = 1048575;

// pub(crate) const BODY_BUF_LIMIT: usize = 1024 * 64;

/// A parsed HTTP response: status line, headers, and body.
pub struct ParsedResponse {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Decodes an HTTP response from an async byte stream using httparse.
///
/// Supports Content-Length, chunked Transfer-Encoding, and
/// read-until-close body strategies.
///
/// Zero-copy for headers (httparse borrows from the read buffer).
pub struct Decoder {
    pub max_header_size: usize,
    pub max_body_size: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self { max_header_size: 65536, max_body_size: 10 * 1024 * 1024 }
    }
}

impl Decoder {
    pub fn new(max_header_size: usize, max_body_size: usize) -> Self {
        Self { max_header_size, max_body_size }
    }

    pub async fn parse<S: AsyncRead + Unpin>(&self, stream: &mut S, is_head: bool) -> Result<ParsedResponse> {
        let mut buf = Vec::with_capacity(HEADER_BUF_SIZE);
        let header_end = self.read_headers(stream, &mut buf).await?;

        let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut raw = httparse::Response::new(&mut raw_headers);

        match raw.parse(&buf)? {
            httparse::Status::Complete(_) => {},
            httparse::Status::Partial => return Err(ErrorKind::Incomplete.into()),
        };

        let status =
            StatusCode::from_u16(raw.code.ok_or(ErrorKind::InvalidStatusCode)?).map_err(|_| ErrorKind::InvalidStatusCode)?;

        let version = match raw.version {
            Some(0) => Version::HTTP_10,
            Some(1) => Version::HTTP_11,
            _ => Version::HTTP_11,
        };

        let mut headers = HeaderMap::with_capacity(raw.headers.len());
        for h in raw.headers.iter() {
            if !h.name.is_empty() {
                let name = HeaderName::from_bytes(h.name.as_bytes())?;
                let value = HeaderValue::from_bytes(h.value)?;
                headers.append(name, value);
            }
        }

        let body = if is_head || no_body_status(&status) {
            Bytes::new()
        } else {
            let partial = if header_end < buf.len() {
                Bytes::copy_from_slice(&buf[header_end..])
            } else {
                Bytes::new()
            };
            self.read_body(stream, &headers, partial).await?
        };

        Ok(ParsedResponse { status, version, headers, body })
    }

    pub async fn parse_status_only<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<u16> {
        let mut buf = Vec::with_capacity(1024);
        let mut temp = [0u8; READ_BUF_SIZE];

        loop {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(ErrorKind::ConnectionClosed.into());
            }
            buf.extend_from_slice(&temp[..n]);

            if find_header_end(&buf).is_some() {
                let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut raw = httparse::Response::new(&mut raw_headers);
                if let httparse::Status::Complete(_) = raw.parse(&buf)? {
                    return raw.code.ok_or_else(|| ErrorKind::InvalidStatusCode.into());
                }
                return Err(ErrorKind::InvalidStatusCode.into());
            }

            if buf.len() > self.max_header_size {
                return Err(ErrorKind::HeadersTooLarge.into());
            }
        }
    }

    async fn read_headers<S: AsyncRead + Unpin>(&self, stream: &mut S, buf: &mut Vec<u8>) -> Result<usize> {
        let mut temp = [0u8; READ_BUF_SIZE];

        loop {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(ErrorKind::ConnectionClosed.into());
            }
            buf.extend_from_slice(&temp[..n]);

            if let Some(pos) = find_header_end(buf) {
                return Ok(pos);
            }

            if buf.len() > self.max_header_size {
                return Err(ErrorKind::HeadersTooLarge.into());
            }
        }
    }

    async fn read_body<S: AsyncRead + Unpin>(&self, stream: &mut S, headers: &HeaderMap, partial: Bytes) -> Result<Bytes> {
        if is_chunked(headers) {
            return self.read_chunked(stream, partial).await;
        }

        if let Some(len) = content_length(headers) {
            if len > self.max_body_size {
                return Err(ErrorKind::BodyTooLarge.into());
            }
            return self.read_fixed(stream, partial, len).await;
        }

        self.read_until_close(stream, partial).await
    }

    async fn read_fixed<S: AsyncRead + Unpin>(&self, stream: &mut S, partial: Bytes, len: usize) -> Result<Bytes> {
        if partial.len() >= len {
            return Ok(partial.slice(..len));
        }

        let mut body = Vec::with_capacity(len);
        body.extend_from_slice(&partial);

        let mut temp = [0u8; READ_BUF_SIZE];
        while body.len() < len {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&temp[..n]);
        }

        Ok(Bytes::from(body))
    }

    async fn read_until_close<S: AsyncRead + Unpin>(&self, stream: &mut S, partial: Bytes) -> Result<Bytes> {
        let mut body = Vec::new();
        body.extend_from_slice(&partial);

        let mut temp = [0u8; READ_BUF_SIZE];
        loop {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&temp[..n]);
            if body.len() > self.max_body_size {
                return Err(ErrorKind::BodyTooLarge.into());
            }
        }

        Ok(Bytes::from(body))
    }

    async fn read_chunked<S: AsyncRead + Unpin>(&self, stream: &mut S, partial: Bytes) -> Result<Bytes> {
        let mut body = Vec::new();
        let mut buf: Vec<u8> = partial.to_vec();
        let mut temp = [0u8; READ_BUF_SIZE];

        loop {
            if let Some(end) = find_crlf(&buf) {
                let line = std::str::from_utf8(&buf[..end]).map_err(|_| ErrorKind::InvalidChunkEncoding)?;
                let size_str = line.split(';').next().unwrap_or("0");
                let chunk_size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| ErrorKind::InvalidChunkEncoding)?;

                if chunk_size == 0 {
                    break;
                }

                let start = end + 2;
                let chunk_end = start + chunk_size;

                if buf.len() < chunk_end + 2 {
                    let n = stream.read(&mut temp).await?;
                    if n == 0 {
                        return Err(ErrorKind::ConnectionClosed.into());
                    }
                    buf.extend_from_slice(&temp[..n]);
                    continue;
                }

                body.extend_from_slice(&buf[start..chunk_end]);
                if body.len() > self.max_body_size {
                    return Err(ErrorKind::BodyTooLarge.into());
                }

                buf = buf[chunk_end + 2..].to_vec();
            } else {
                let n = stream.read(&mut temp).await?;
                if n == 0 {
                    return Err(ErrorKind::ConnectionClosed.into());
                }
                buf.extend_from_slice(&temp[..n]);
            }
        }

        Ok(Bytes::from(body))
    }
}

#[inline]
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[inline]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[inline]
fn no_body_status(status: &StatusCode) -> bool {
    let code = status.as_u16();
    code == 204 || code == 304 || (100..200).contains(&code)
}

#[inline]
fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers.get(http::header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

#[inline]
fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("chunked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_header_end(buf), Some(buf.len()));
    }

    #[test]
    fn test_no_body_status() {
        assert!(no_body_status(&StatusCode::NO_CONTENT));
        assert!(no_body_status(&StatusCode::NOT_MODIFIED));
        assert!(no_body_status(&StatusCode::CONTINUE));
        assert!(!no_body_status(&StatusCode::OK));
    }

    #[tokio::test]
    async fn parse_simple_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let parser = Decoder::default();
        let resp = parser.parse(&mut cursor, false).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.version, Version::HTTP_11);
        assert_eq!(resp.body, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn parse_head_response_no_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let parser = Decoder::default();
        let resp = parser.parse(&mut cursor, true).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn parse_204_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let parser = Decoder::default();
        let resp = parser.parse(&mut cursor, false).await.unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let parser = Decoder::default();
        let resp = parser.parse(&mut cursor, false).await.unwrap();
        assert_eq!(resp.body, Bytes::from_static(b"hello world"));
    }

    #[tokio::test]
    async fn parse_read_until_close() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nbody until close";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let parser = Decoder::default();
        let resp = parser.parse(&mut cursor, false).await.unwrap();
        assert_eq!(resp.body, Bytes::from_static(b"body until close"));
    }
}
