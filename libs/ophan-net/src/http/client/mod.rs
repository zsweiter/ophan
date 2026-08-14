pub mod common;
pub mod error;
pub mod form;
mod request;
pub mod response;
pub mod url;

use std::sync::Arc;
use std::time::Duration;

use http::Method;
use tokio::io::AsyncWriteExt;

pub use request::RequestBuilder;
pub use response::Response;

use crate::http::Error;
use crate::http::client::error::Result;
use crate::http::client::request::Request;
use crate::http::client::url::IntoUrl;
use crate::http::protocol::{Decoder, v1};

const DEFAULT_MAX_HEADER_SIZE: usize = 64 * 1024;
const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

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
}

impl Client {
    /// Create a new `Client` with default settings.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ClientRef {
                decoder: Decoder::default(),
                timeout: None,
                connect_timeout: None,
                tls_connector: None,
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
    pub(super) async fn execute(&self, req: request::Request) -> Result<Response> {
        let (parts, body, timeout) = req.into_parts()?;

        let tls = self.inner.tls_connector.as_ref();
        let connect = request::connect_transport(&parts.uri, tls);
        let mut stream = match self.inner.connect_timeout {
            Some(dur) => tokio::time::timeout(dur, connect).await.map_err(|_| Error::new(error::ErrorKind::Timeout))??,
            None => connect.await?,
        };

        let header_bytes =
            v1::http_req_header_to_wire(&parts).map_err(|a| Error::new(error::ErrorKind::Encode(a.to_string())))?;

        let send_fut = async {
            stream.write_all(&header_bytes).await?;
            if let Some(body_bytes) = body {
                stream.write_all(&body_bytes).await?;
            }

            stream.flush().await?;

            let is_head = parts.method == Method::HEAD;
            let parsed = self.inner.decoder.parse(&mut stream, is_head).await?;

            Ok::<_, Error>(Response::new(parsed.status, parsed.version, parsed.headers, parsed.body))
        };

        match self.inner.timeout.or(timeout) {
            Some(dur) => tokio::time::timeout(dur, send_fut).await.map_err(|_| Error::new(error::ErrorKind::Timeout))?,
            None => send_fut.await,
        }
    }
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
            timeout: None,
            connect_timeout: None,
            max_header_size: DEFAULT_MAX_HEADER_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            tls: false,
        }
    }

    /// Set the default timeout for all requests made by this client.
    pub fn timeout(mut self, dur: Duration) -> Self {
        self.timeout = Some(dur);
        self
    }

    /// Set the timeout for the connection phase (TCP connect / Unix socket connect).
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
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let client = Client::builder().build();
        let inner = &client.inner;
        assert_eq!(inner.decoder.max_header_size, DEFAULT_MAX_HEADER_SIZE);
        assert_eq!(inner.decoder.max_body_size, DEFAULT_MAX_BODY_SIZE);
        assert!(inner.timeout.is_none());
        assert!(inner.connect_timeout.is_none());
        assert!(inner.tls_connector.is_none());
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
}
