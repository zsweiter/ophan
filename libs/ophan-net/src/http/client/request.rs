use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use http::request::Parts;
use http::{HeaderMap, Method, Version};
use serde::Serialize;
use url::Url;

use crate::http::client::Client;
use crate::http::client::error::{Error, ErrorKind, Result};
use crate::http::client::form::MultipartBuilder;
use crate::http::client::response::Response;
use crate::{RawStream, transport};

/// A raw HTTP request ready to be sent.
pub struct Request {
    pub(super) method: Method,
    pub(super) url: Url,
    pub(super) version: Version,
    pub(super) headers: HeaderMap,
    pub(super) body: Option<Bytes>,
    pub(super) timeout: Option<Duration>,
}

/// Builds an HTTP request with a reqwest-style lazy error accumulator.
///
/// Builder methods never fail immediately — errors are collected into an
/// internal `Result<Request>` and only surface when `.send()` is called.
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
    pub(super) request: Result<Request>,
}

impl RequestBuilder {
    /// Create a new `RequestBuilder` for the given method and URL.
    pub fn new(client: Client, req: Result<Request>) -> Self {
        Self { client, request: req }
    }

    /// Create a new `RequestBuilder` for the given method and URL.
    pub fn from_parts(client: Client, method: Method, url: impl Into<Url>) -> Self {
        let request = Ok(Request {
            method,
            url: url.into(),
            version: Version::default(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
        });
        Self { client, request }
    }

    /// Set the HTTP version (defaults to HTTP/1.1).
    pub fn version(mut self, version: Version) -> Self {
        self.request = self.request.map(|mut req| {
            req.version = version;
            req
        });
        self
    }

    /// Set a header. If the name or value is invalid, the error is deferred to `.send()`.
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.request = self.request.and_then(|mut req| {
            let name = HeaderName::try_from(key).map_err(|_| Error::new(ErrorKind::Encode("failed parse header".into())))?;
            let value = HeaderValue::try_from(value).map_err(|_| Error::new(ErrorKind::Encode("failed parse header".into())))?;

            req.headers_mut().append(name, value);
            Ok(req)
        });
        self
    }

    /// Set the raw request body. Removes any previously set Content-Type.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.request = self.request.map(|mut req| {
            req.body = Some(body.into());
            req.headers.remove(http::header::CONTENT_TYPE);
            req
        });
        self
    }

    /// Serialize `data` as `application/x-www-form-urlencoded`.
    /// If serialization fails, the error is deferred to `.send()`.
    pub fn form<T: Serialize + ?Sized>(mut self, data: &T) -> Self {
        self.request = self.request.and_then(|mut req| {
            let value = serde_urlencoded::to_string(data).map_err(|e| Error::new(ErrorKind::Encode(e.to_string())))?;
            req.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));

            req.body = Some(Bytes::from(value));
            Ok(req)
        });
        self
    }

    /// Serialize `data` as `application/json`.
    /// If serialization fails, the error is deferred to `.send()`.
    pub fn json<T: Serialize + ?Sized>(mut self, data: &T) -> Self {
        self.request = self.request.and_then(|mut req| {
            let value = serde_json::to_vec(data).map_err(|e| Error::new(ErrorKind::Encode(e.to_string())))?;
            req.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            req.body = Some(Bytes::from(value));
            Ok(req)
        });
        self
    }

    /// Attach a multipart form body.
    pub fn multipart(mut self, form: MultipartBuilder) -> Self {
        self.request = self.request.and_then(|mut req| {
            let (body, ct) = form.finish();
            let header_value =
                HeaderValue::from_str(&ct).map_err(|e| Error::new(ErrorKind::Encode(format!("invalid content-type: {e}"))))?;
            req.headers_mut().insert(CONTENT_TYPE, header_value);

            req.body = Some(body);
            Ok(req)
        });
        self
    }

    /// Append query parameters to the URL.
    pub fn query(mut self, params: &[(&str, &str)]) -> Self {
        self.request = self.request.map(|mut req| {
            for (k, v) in params {
                req.url.query_pairs_mut().append_pair(k, v);
            }

            req
        });
        self
    }

    /// Set `Authorization: Bearer <token>`.
    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.request = self.request.and_then(|mut req| {
            let value = HeaderValue::try_from(format!("Bearer {token}"))
                .map_err(|e| Error::new(ErrorKind::Encode(format!("invalid bearer token: {e}"))))?;
            req.headers.insert(http::header::AUTHORIZATION, value);
            Ok(req)
        });
        self
    }

    /// Set a per-request timeout. Overrides the client-level timeout if set.
    pub fn timeout(mut self, dur: Duration) -> Self {
        self.request = self.request.map(|mut req| {
            req.timeout = Some(dur);
            req
        });
        self
    }

    /// Execute the request and return the response.
    /// Errors from deferred builder operations surface here.
    pub async fn send(self) -> Result<Response> {
        let req = self.request?;
        self.client.execute(req).await
    }
}

impl Request {
    pub fn new(method: Method, url: impl Into<Url>) -> Self {
        Self {
            method,
            url: url.into(),
            version: Version::default(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }

    pub fn body_mut(&mut self) -> &mut Option<Bytes> {
        &mut self.body
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Converts this custom `Request` into a standard `http::request::Parts`
    /// from the `http` crate along with the remaining fields (body and timeout).
    ///
    /// # Errors
    /// Returns an error if the internal `Url` cannot be parsed into a valid `http::Uri`.
    pub fn into_parts(self) -> Result<(Parts, Option<Bytes>, Option<Duration>)> {
        let uri: http::Uri = self.url.as_str().parse()?;

        let (mut parts, _) = http::Request::builder()
            .method(self.method)
            .uri(uri)
            .version(self.version)
            .body(())
            .map_err(|e| Error::new(ErrorKind::Encode(e.to_string())))?
            .into_parts();

        parts.headers = self.headers;

        if let Some(timeout) = self.timeout {
            parts.extensions.insert(timeout);
        }

        Ok((parts, self.body, self.timeout))
    }
}

/// Parse a URL and connect to its transport (http, https, or unix).
pub(super) async fn connect_transport(
    uri: &http::Uri,
    tls_connector: Option<&crate::tls::connector::TlsConnector>,
) -> Result<RawStream> {
    let transport = match uri.scheme_str() {
        Some("http") => {
            let host = uri.host().ok_or_else(|| Error::new(ErrorKind::InvalidUrl(url::ParseError::EmptyHost)))?;
            let port = uri.port_u16().unwrap_or(80);
            let tcp = transport::connect_tcp(host, port).await?;
            RawStream::Tcp(tcp)
        },
        Some("https") => {
            let host = uri.host().ok_or_else(|| Error::new(ErrorKind::InvalidUrl(url::ParseError::EmptyHost)))?;
            let port = uri.port_u16().unwrap_or(443);
            let connector = tls_connector.ok_or_else(|| Error::new(ErrorKind::Tls("TLS support not enabled".into())))?;
            let tcp = transport::connect_tcp(host, port).await?;
            let tls_stream = connector.connect(host, tcp).await?;
            RawStream::Tls(tls_stream)
        },
        Some("unix") => {
            #[cfg(unix)]
            {
                let path = std::path::Path::new(uri.path());
                transport::connect_unix(path).await?
            }
            #[cfg(not(unix))]
            {
                return Err(Error::new(ErrorKind::Encode(
                    "Unix domain sockets are not supported on this platform".into(),
                )));
            }
        },
        Some(scheme) => {
            return Err(Error::new(ErrorKind::Encode(format!("unsupported URI scheme: {scheme}"))));
        },
        None => {
            return Err(Error::new(ErrorKind::InvalidUrl(url::ParseError::EmptyHost)));
        },
    };

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;

    fn dummy_client() -> Client {
        Client::new()
    }

    #[test]
    fn header_invalid_name_deferred() {
        let rb = dummy_client().get("http://example.com").header("invalid header name\r\n", "value");
        assert!(rb.request.is_err());
    }

    #[test]
    fn invalid_url_stored_as_error() {
        let rb = dummy_client().get("not a url");
        assert!(rb.request.is_err());
    }

    #[test]
    fn query_appends_params() {
        let rb = dummy_client().get("http://example.com/path").query(&[("key", "value"), ("foo", "bar")]);
        let req = rb.request.unwrap();
        assert_eq!(req.url.as_str(), "http://example.com/path?key=value&foo=bar");
    }

    #[test]
    fn query_on_existing_params() {
        let rb = dummy_client().get("http://example.com/path?existing=1").query(&[("new", "2")]);
        let req = rb.request.unwrap();
        assert!(req.url.as_str().contains("existing=1"));
        assert!(req.url.as_str().contains("new=2"));
    }

    #[test]
    fn bearer_auth_sets_header() {
        let rb = dummy_client().get("http://example.com").bearer_auth("mytoken");
        let req = rb.request.unwrap();
        let val = req.headers.get(http::header::AUTHORIZATION);
        assert_eq!(val, Some(&"Bearer mytoken".parse().unwrap()));
    }

    #[test]
    fn timeout_stored_in_request() {
        let rb = dummy_client().get("http://example.com").timeout(Duration::from_secs(3));
        let req = rb.request.unwrap();
        assert_eq!(req.timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn body_overrides_content_type() {
        let rb = dummy_client().post("http://example.com").form(&serde_json::json!({"a": 1}));
        let rb2 = rb.body("raw");
        let req = rb2.request.unwrap();
        assert!(req.headers.get(http::header::CONTENT_TYPE).is_none());
    }

    #[test]
    fn version_defaults_to_http11() {
        let rb = dummy_client().get("http://example.com");
        let req = rb.request.unwrap();
        assert_eq!(req.version, Version::HTTP_11);
    }

    #[test]
    fn version_override() {
        let rb = dummy_client().get("http://example.com").version(Version::HTTP_10);
        let req = rb.request.unwrap();
        assert_eq!(req.version, Version::HTTP_10);
    }

    #[test]
    fn json_error_deferred() {
        let rb = dummy_client().post("http://example.com").json(&serde_json::json!({"key": "value"}));
        let req = rb.request.unwrap();
        assert_eq!(req.body.as_ref().map(|b| b.as_ref()), Some(&b"{\"key\":\"value\"}"[..]));
    }
}
