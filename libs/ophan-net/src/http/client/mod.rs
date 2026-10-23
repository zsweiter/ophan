pub mod common;
pub mod error;
pub mod form;
mod pool;
mod request;
pub mod response;
pub mod url;

use std::sync::Arc;
use std::time::Duration;

use http::Method;

pub use request::RequestBuilder;
pub use response::Response;

use crate::http::Error;
use crate::http::client::error::Result;
use crate::http::client::request::Request;
use crate::http::client::url::IntoUrl;
use crate::http::protocol::{Decoder, v1};

const DEFAULT_MAX_HEADER_SIZE: usize = 64 * 1024;
const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

struct ClientRef {
    decoder: Decoder,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    tls_connector: Option<crate::tls::connector::TlsConnector>,
    pool: pool::Pool,
}

impl Client {
    /// Create a new `Client` with default settings.
    ///
    /// Requests time out after 10 seconds (5 seconds for the connection
    /// phase) unless a per-request timeout is set.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ClientRef {
                decoder: Decoder::default(),
                timeout: Some(DEFAULT_TIMEOUT),
                connect_timeout: Some(DEFAULT_CONNECT_TIMEOUT),
                tls_connector: None,
                pool: pool::Pool::new(),
            }),
        }
    }

    /// Return a builder for configuring a custom `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Start a GET request.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Start a POST request.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Start a PUT request.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Start a PATCH request.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Start a DELETE request.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Start a HEAD request.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Start an OPTIONS request.
    pub fn options<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::OPTIONS, url)
    }

    /// Start a TRACE request.
    pub fn trace<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::TRACE, url)
    }

    /// Start a CONNECT request.
    pub fn connect<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::CONNECT, url)
    }

    /// Internal helper: create a `RequestBuilder` for the given method and URL.
    fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        let req = url.into_url().map(move |url| Request::new(method, url));
        RequestBuilder::new(self.clone(), req)
    }

    /// Send a fully-built `Request` over the wire and return the response.
    ///
    /// The per-request timeout takes precedence over the client default and
    /// bounds the whole exchange, connection phase included.
    ///
    /// A connection previously parked for the same origin is tried first. When the
    /// exchange on it fails, the request is sent again over a fresh connection only
    /// if it was not fully written or its method is idempotent, so a request the
    /// server may already have processed is never repeated. A stream that ends the
    /// exchange at a keep-alive viable boundary is parked again.
    pub(super) async fn execute(&self, req: request::Request) -> Result<Response> {
        let (parts, body, timeout) = req.into_parts()?;

        let is_head = parts.method == Method::HEAD;
        let poolable = pool::request_reusable(&parts.headers);
        let header_bytes =
            v1::http_req_header_to_wire(&parts).map_err(|a| Error::new(error::ErrorKind::Encode(a.to_string())))?;

        let exchange = async {
            let pool = &self.inner.pool;
            let pool_key = pool::key(&parts.uri);

            if let Some(key) = pool_key.as_deref()
                && poolable
                && let Some(stream) = pool.pop(key)
            {
                let (result, stream, sent) =
                    request::drive(&self.inner.decoder, stream, &header_bytes, body.as_ref(), is_head).await;

                match result {
                    Ok(parsed) => {
                        if pool::response_reusable(&parsed, is_head) {
                            pool.put(key, stream);
                        }
                        return Ok(response(parsed));
                    },
                    Err(e) if sent && !parts.method.is_idempotent() => return Err(e),
                    Err(_) => drop(stream),
                }
            }

            let tls = self.inner.tls_connector.as_ref();
            let connect = request::connect_transport(&parts.uri, tls);
            let stream = match self.inner.connect_timeout {
                Some(dur) => tokio::time::timeout(dur, connect).await.map_err(|_| Error::new(error::ErrorKind::Timeout))??,
                None => connect.await?,
            };

            let (result, stream, _) = request::drive(&self.inner.decoder, stream, &header_bytes, body.as_ref(), is_head).await;

            let parsed = result?;
            if let Some(key) = pool_key.as_deref()
                && poolable
                && pool::response_reusable(&parsed, is_head)
            {
                pool.put(key, stream);
            }

            Ok(response(parsed))
        };

        match timeout.or(self.inner.timeout) {
            Some(dur) => tokio::time::timeout(dur, exchange).await.map_err(|_| Error::new(error::ErrorKind::Timeout))?,
            None => exchange.await,
        }
    }
}

#[inline]
fn response(parsed: crate::http::protocol::decoder::ParsedResponse) -> Response {
    Response::new(parsed.status, parsed.version, parsed.headers, parsed.body)
}

pub struct ClientBuilder {
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    max_header_size: usize,
    max_body_size: usize,
    tls: bool,
}

impl ClientBuilder {
    fn new() -> Self {
        Self {
            timeout: Some(DEFAULT_TIMEOUT),
            connect_timeout: Some(DEFAULT_CONNECT_TIMEOUT),
            max_header_size: DEFAULT_MAX_HEADER_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            tls: false,
        }
    }

    /// Set the default timeout for all requests made by this client
    /// (default: 10 seconds). A per-request timeout takes precedence.
    pub fn timeout(mut self, dur: Duration) -> Self {
        self.timeout = Some(dur);
        self
    }

    /// Set the timeout for the connection phase (TCP connect / Unix socket connect,
    /// default: 5 seconds).
    pub fn connect_timeout(mut self, dur: Duration) -> Self {
        self.connect_timeout = Some(dur);
        self
    }

    /// Set the maximum header size in bytes (default: 64 KiB).
    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    /// Set the maximum body size in bytes (default: 10 MiB).
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Enable TLS support for HTTPS requests.
    pub fn tls(mut self) -> Self {
        self.tls = true;
        self
    }

    /// Build the `Client` with the configured settings.
    pub fn build(self) -> Client {
        let tls_connector = if self.tls {
            Some(crate::tls::connector::TlsConnector::new().expect("failed to create TLS connector"))
        } else {
            None
        };

        Client {
            inner: Arc::new(ClientRef {
                decoder: Decoder::new(self.max_header_size, self.max_body_size),
                timeout: self.timeout,
                connect_timeout: self.connect_timeout,
                tls_connector,
                pool: pool::Pool::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn builder_defaults() {
        let client = Client::builder().build();
        let inner = &client.inner;
        assert_eq!(inner.decoder.max_header_size, DEFAULT_MAX_HEADER_SIZE);
        assert_eq!(inner.decoder.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert_eq!(inner.timeout, Some(DEFAULT_TIMEOUT));
        assert_eq!(inner.connect_timeout, Some(DEFAULT_CONNECT_TIMEOUT));
        assert!(inner.tls_connector.is_none());
    }

    #[test]
    fn new_has_default_timeouts() {
        let client = Client::new();
        assert_eq!(client.inner.timeout, Some(DEFAULT_TIMEOUT));
        assert_eq!(client.inner.connect_timeout, Some(DEFAULT_CONNECT_TIMEOUT));
    }

    #[tokio::test]
    async fn per_request_timeout_overrides_client_default() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = Client::builder().timeout(Duration::from_secs(30)).build();
        let started = std::time::Instant::now();
        let result = client.get(format!("http://{addr}/")).timeout(Duration::from_millis(100)).send().await;

        assert!(matches!(result, Err(ref e) if matches!(e.kind, error::ErrorKind::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(2));
        server.abort();
    }

    #[test]
    fn builder_custom() {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .max_header_size(4096)
            .max_body_size(8192)
            .build();
        let inner = &client.inner;
        assert_eq!(inner.timeout, Some(Duration::from_secs(5)));
        assert_eq!(inner.connect_timeout, Some(Duration::from_secs(2)));
        assert_eq!(inner.decoder.max_header_size, 4096);
        assert_eq!(inner.decoder.max_body_size, 8192);
        assert!(inner.tls_connector.is_none());
    }

    #[test]
    fn builder_with_tls() {
        let client = Client::builder().tls().build();
        let inner = &client.inner;
        assert!(inner.tls_connector.is_some());
    }

    #[test]
    fn method_shortcuts() {
        let client = Client::new();
        assert!(client.get("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::GET));
        assert!(client.post("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::POST));
        assert!(client.put("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::PUT));
        assert!(client.patch("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::PATCH));
        assert!(
            client
                .delete("http://a.com")
                .request
                .as_ref()
                .map(|r| &r.method)
                .is_ok_and(|m| *m == Method::DELETE)
        );
        assert!(client.head("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::HEAD));
        assert!(
            client
                .options("http://a.com")
                .request
                .as_ref()
                .map(|r| &r.method)
                .is_ok_and(|m| *m == Method::OPTIONS)
        );
        assert!(client.trace("http://a.com").request.as_ref().map(|r| &r.method).is_ok_and(|m| *m == Method::TRACE));
        assert!(
            client
                .connect("http://a.com")
                .request
                .as_ref()
                .map(|r| &r.method)
                .is_ok_and(|m| *m == Method::CONNECT)
        );
    }

    /// Answers every request, except that the first connection reads its second
    /// request and closes without answering. Returns the address and the number of
    /// accepted connections.
    async fn server_dropping_second_request() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let first = counter.fetch_add(1, Ordering::SeqCst) == 0;

                tokio::spawn(async move {
                    let mut answered = 0;
                    let mut buf = [0u8; 1024];
                    loop {
                        let mut request = Vec::new();
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match socket.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => request.extend_from_slice(&buf[..n]),
                            }
                        }
                        if first && answered == 1 {
                            return;
                        }
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
                        answered += 1;
                    }
                });
            }
        });

        (addr, accepted)
    }

    #[tokio::test]
    async fn idempotent_request_is_retried_after_a_failed_recycle() {
        let (addr, accepted) = server_dropping_second_request().await;
        let client = Client::builder().timeout(Duration::from_secs(5)).build();

        for _ in 0..2 {
            let body = client.get(format!("http://{addr}/")).send().await.unwrap().text().unwrap();
            assert_eq!(body, "ok");
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn non_idempotent_request_is_not_repeated() {
        let (addr, accepted) = server_dropping_second_request().await;
        let client = Client::builder().timeout(Duration::from_secs(5)).build();

        assert!(client.post(format!("http://{addr}/token")).send().await.is_ok());
        assert!(client.post(format!("http://{addr}/token")).send().await.is_err());
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pooled_connection_is_reused_between_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            for _ in 0..2 {
                let mut buf = [0u8; 1024];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            }

            drop(socket);
        });

        let client = Client::builder().timeout(Duration::from_secs(5)).build();

        for expected in ["ok", "ok"] {
            let body = client.get(format!("http://{addr}/")).send().await.unwrap().text().unwrap();
            assert_eq!(body, expected);
        }

        server.await.unwrap();
    }
}
