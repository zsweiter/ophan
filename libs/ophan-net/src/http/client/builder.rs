use bytes::Bytes;
use http::header::HeaderName;
use http::{Method, Version};
use serde::Serialize;
use url::Url;

use crate::http::client::Client;
use crate::http::client::error::{Error, ErrorKind, Result};
use crate::http::client::form::MultipartBuilder;
use crate::http::client::response::Response;
use crate::transport;

/// Builds an HTTP request that can be sent with `.send()`.
///
/// ```no_run
/// # use ophan_net::Client;
/// # async fn run() {
/// let resp = Client::new()
///     .post("http://api.example.com/data")
///     .header("Authorization", "Bearer token")
///     .body("hello")
///     .send()
///     .await
///     .unwrap();
/// # }
/// ```
pub struct RequestBuilder {
    pub(super) client: Client,
    pub(super) method: Method,
    pub(super) url: String,
    pub(super) version: Version,
    pub(super) headers: Vec<(HeaderName, Vec<u8>)>,
    pub(super) body: Option<Bytes>,
}

impl RequestBuilder {
    pub fn new(client: Client, method: Method, url: &str) -> Self {
        Self {
            client,
            method,
            url: url.to_owned(),
            version: Version::HTTP_11,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let Ok(n) = HeaderName::try_from(name) {
            self.headers.push((n, value.as_bytes().to_vec()));
        }
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn form<T: Serialize + ?Sized>(mut self, data: &T) -> Self {
        if let Ok(value) = serde_urlencoded::to_string(data) {
            self.body = Some(Bytes::from(value));
        }
        self.set_content_type("application/x-www-form-urlencoded");
        self
    }

    pub fn multipart(mut self, form: MultipartBuilder) -> Self {
        let (body, ct) = form.finish();
        self.body = Some(body);
        self.set_content_type(&ct);
        self
    }

    fn set_content_type(&mut self, value: &str) {
        self.headers.retain(|(n, _)| *n != http::header::CONTENT_TYPE);
        self.headers.insert(0, (http::header::CONTENT_TYPE.clone(), value.as_bytes().to_vec()));
    }

    pub async fn send(self) -> Result<Response> {
        let client = self.client.clone();
        client.execute(self).await
    }
}

pub(super) async fn connect_transport(url: &str) -> Result<(Url, crate::transport::Transport)> {
    let parsed = Url::parse(url)?;
    let scheme = parsed.scheme();

    let transport = match scheme {
        "http" => {
            let host = parsed.host_str().ok_or_else(|| Error::new(ErrorKind::InvalidUrl("missing host".into())))?;
            let port = parsed.port().unwrap_or(80);
            transport::connect_tcp(host, port).await?
        },
        "https" => {
            let host = parsed.host_str().ok_or_else(|| Error::new(ErrorKind::InvalidUrl("missing host".into())))?;
            let port = parsed.port().unwrap_or(443);
            transport::connect_tcp(host, port).await?
        },
        "unix" => {
            #[cfg(unix)]
            {
                let path = std::path::Path::new(parsed.path());
                transport::connect_unix(path).await?
            }
            #[cfg(not(unix))]
            return Err(Error::new(ErrorKind::ConnectFailed).with_url(url));
        },
        _ => return Err(Error::new(ErrorKind::InvalidUrl(format!("unsupported scheme: {scheme}"))).with_url(url)),
    };

    Ok((parsed, transport))
}
