mod builder;
pub mod error;
pub mod form;
pub mod response;

use std::sync::Arc;

use http::header::HeaderName;
use http::{Method, Uri};
use tokio::io::AsyncWriteExt;

pub use builder::RequestBuilder;
pub use response::Response;

use crate::http::client::error::Result;
use crate::http::wire::{Decoder, Encoder};

/// An HTTP client for making outbound requests to upstream services.
///
/// Lightweight, designed for internal system calls (JWK fetching,
/// health checks, etc.).  Each `Client` holds a shared response
/// decoder and a connection pool.
///
/// # Example
///
/// ```no_run
/// use ophan_net::Client;
///
/// # async fn run() {
/// let client = Client::new();
/// let resp = client.get("http://example.com").send().await.unwrap();
/// println!("status: {}", resp.status());
/// # }
/// ```
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
}

impl Client {
    pub fn new() -> Self {
        Self { inner: Arc::new(ClientRef { decoder: Decoder::default() }) }
    }

    pub fn head(&self, url: &str) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: &str) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url)
    }

    pub(super) async fn execute(&self, req: RequestBuilder) -> Result<Response> {
        let (parsed_url, mut transport) = builder::connect_transport(&req.url).await?;

        let uri: Uri = req.url.parse()?;

        let header_refs: Vec<(&HeaderName, &[u8])> = req.headers.iter().map(|(n, v)| (n, v.as_slice())).collect();

        let mut encoder = Encoder::new(req.method.clone(), uri).with_version(req.version).with_headers(&header_refs);

        if let Some(body) = req.body {
            encoder = encoder.with_body(body);
        }

        let wire_bytes = encoder.finalize()?;

        transport.write_all(&wire_bytes).await?;
        transport.flush().await?;

        let is_head = req.method == Method::HEAD;
        let parsed = self.inner.decoder.parse(&mut transport, is_head).await?;

        Ok(Response::new(
            parsed.status,
            parsed.version,
            parsed.headers,
            parsed.body,
            parsed_url,
        ))
    }
}
