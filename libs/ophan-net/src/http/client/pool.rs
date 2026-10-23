use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use http::{StatusCode, Version};
use tokio::io::{AsyncRead, ReadBuf};

use crate::http::protocol::decoder::ParsedResponse;
use crate::transport::RawStream;

const MAX_IDLE_PER_KEY: usize = 8;
const IDLE_TTL: Duration = Duration::from_secs(10);

struct PoolEntry {
    stream: RawStream,
    parked_at: Instant,
}

/// Idle-connection pool keyed by `(scheme, host, port)`.
///
/// Streams are parked only after a fully read, keep-alive viable exchange
/// (see `response_reusable`); `pop` returns the most recently parked one.
///
/// SO_KEEPALIVE is not set on parked sockets: tokio only exposes it at socket
/// creation time (`TcpSocket`), and neither `socket2` nor `libc` is available
/// as a workspace dependency. The idle TTL bounds the window in which dead
/// sockets are reused, and `pop` drops streams the peer already closed.
pub(super) struct Pool {
    idle: parking_lot::Mutex<HashMap<String, Vec<PoolEntry>>>,
}

impl Pool {
    pub(super) fn new() -> Self {
        Self { idle: parking_lot::Mutex::new(HashMap::new()) }
    }

    /// Take the most recently parked idle stream that is still open, if any.
    /// Expired entries (idle TTL) and streams the peer closed are dropped.
    pub(super) fn pop(&self, key: &str) -> Option<RawStream> {
        let mut idle = self.idle.lock();

        let entries = idle.get_mut(key)?;
        let now = Instant::now();
        entries.retain(|entry| now.saturating_duration_since(entry.parked_at) <= IDLE_TTL);

        let mut found = None;
        while let Some(mut entry) = entries.pop() {
            if Self::is_open(&mut entry.stream) {
                found = Some(entry.stream);
                break;
            }
        }

        if entries.is_empty() {
            idle.remove(key);
        }

        found
    }

    /// An idle stream is usable only while reading it would block: end of stream means
    /// the peer closed it, and bytes the peer sent unprompted leave it out of sync.
    fn is_open(stream: &mut RawStream) -> bool {
        let mut byte = [0u8; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let mut cx = Context::from_waker(Waker::noop());

        matches!(Pin::new(stream).poll_read(&mut cx, &mut buf), Poll::Pending)
    }

    /// Park a stream for reuse; when the key is at capacity, the stream is
    /// dropped (closing the socket).
    pub(super) fn put(&self, key: &str, stream: RawStream) {
        let mut idle = self.idle.lock();
        if idle.get(key).is_some_and(|entries| entries.len() >= MAX_IDLE_PER_KEY) {
            return;
        }

        idle.entry(key.to_owned()).or_default().push(PoolEntry { stream, parked_at: Instant::now() });
    }
}

/// Pool key of the request origin; `None` for unpoolable origins (unix
/// sockets, unknown schemes).
pub(super) fn key(uri: &http::Uri) -> Option<String> {
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;

    let port = authority.port_u16().unwrap_or(match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    });

    Some(format!("{scheme}://{}:{port}", authority.host().to_ascii_lowercase()))
}

/// Explicit `Connection: close` on the outgoing request prevents recycling.
pub(super) fn request_reusable(headers: &http::HeaderMap) -> bool {
    !connection_close(headers)
}

/// A stream is only parkable when it sits exactly at a message boundary after
/// a fully read response: HTTP/1.1, no `Connection: close`, and a delimited
/// body — framed (Content-Length / chunked), HEAD, or an inherently bodiless
/// status.
pub(super) fn response_reusable(parsed: &ParsedResponse, is_head: bool) -> bool {
    parsed.status != StatusCode::SWITCHING_PROTOCOLS
        && parsed.version == Version::HTTP_11
        && !connection_close(&parsed.headers)
        && (is_head
            || no_body_status(parsed.status)
            || parsed.headers.get(http::header::CONTENT_LENGTH).is_some()
            || parsed
                .headers
                .get(http::header::TRANSFER_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("chunked")))
}

#[inline]
fn connection_close(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("close"))
}

// Mirrors `http::protocol::decoder::no_body_status` (private there).
#[inline]
fn no_body_status(status: StatusCode) -> bool {
    let code = status.as_u16();
    code == 204 || code == 304
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};

    fn parsed(response_version: Version, headers: http::HeaderMap, is_head: bool) -> bool {
        response_reusable(
            &ParsedResponse {
                status: StatusCode::OK,
                version: response_version,
                headers,
                body: Bytes::new(),
            },
            is_head,
        )
    }

    fn with_content_length() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_LENGTH, "5".parse().unwrap());
        headers
    }

    #[test]
    fn heads_and_framed_bodies_are_reusable() {
        assert!(parsed(Version::HTTP_11, with_content_length(), true));
        assert!(parsed(Version::HTTP_11, with_content_length(), false));

        let mut chunked = http::HeaderMap::new();
        chunked.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        assert!(parsed(Version::HTTP_11, chunked, false));
    }

    #[test]
    fn close_or_unframeable_responses_are_not_reusable() {
        let mut close = with_content_length();
        close.insert(CONNECTION, "Close".parse().unwrap());
        assert!(!parsed(Version::HTTP_11, close, false));

        assert!(!parsed(Version::HTTP_10, with_content_length(), false));

        // Unframed 200 means read-until-close: not parkable.
        assert!(!parsed(Version::HTTP_11, http::HeaderMap::new(), false));

        let mut identity = http::HeaderMap::new();
        identity.insert(TRANSFER_ENCODING, "identity".parse().unwrap());
        assert!(!parsed(Version::HTTP_11, identity, false));
    }

    #[test]
    fn status_has_no_body_means_reusable() {
        for status in [StatusCode::NO_CONTENT, StatusCode::NOT_MODIFIED] {
            let parsed = ParsedResponse {
                status,
                version: Version::HTTP_11,
                headers: http::HeaderMap::new(),
                body: Bytes::new(),
            };
            assert!(response_reusable(&parsed, false), "{status} is inherently bodiless");
        }
    }

    #[test]
    fn switching_protocols_is_not_reusable() {
        let parsed = ParsedResponse {
            status: StatusCode::SWITCHING_PROTOCOLS,
            version: Version::HTTP_11,
            headers: http::HeaderMap::new(),
            body: Bytes::new(),
        };
        assert!(!response_reusable(&parsed, false));
    }

    #[test]
    fn request_with_connection_close_is_not_reusable() {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONNECTION, "close".parse().unwrap());
        assert!(!request_reusable(&headers));
        assert!(request_reusable(&http::HeaderMap::new()));
    }

    #[test]
    fn key_derives_scheme_host_port() {
        let key_of = |s: &str| key(&s.parse::<http::Uri>().unwrap());
        assert_eq!(key_of("http://Example.com"), Some("http://example.com:80".into()));
        assert_eq!(key_of("https://Example.com:8443"), Some("https://example.com:8443".into()));
        assert_eq!(key_of("ftp://example.com:21"), None);
    }

    async fn connected_pair() -> (RawStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(tokio::net::TcpStream::connect(addr), async {
            let (socket, _) = listener.accept().await.unwrap();
            socket
        });
        (RawStream::Tcp(client.unwrap()), server)
    }

    #[tokio::test]
    async fn roundtrip_and_capacity() {
        let pool = Pool::new();
        let (stream, _server) = connected_pair().await;
        pool.put("http://a:80", stream);
        assert!(pool.pop("http://a:80").is_some());
        assert!(pool.pop("http://a:80").is_none());

        let mut servers = Vec::new();
        for _ in 0..MAX_IDLE_PER_KEY + 1 {
            let (stream, server) = connected_pair().await;
            servers.push(server);
            pool.put("http://a:80", stream);
        }

        let mut popped = 0;
        while pool.pop("http://a:80").is_some() {
            popped += 1;
        }
        assert_eq!(popped, MAX_IDLE_PER_KEY);
    }

    #[tokio::test]
    async fn streams_closed_by_the_peer_are_skipped() {
        let pool = Pool::new();

        let (alive, _server) = connected_pair().await;
        pool.put("http://a:80", alive);

        let (closed, server) = connected_pair().await;
        pool.put("http://a:80", closed);
        drop(server);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(pool.pop("http://a:80").is_some(), "the open stream is returned");
        assert!(pool.pop("http://a:80").is_none(), "the closed stream was dropped");
    }
}
