use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version};
use serde::de::DeserializeOwned;
use url::Url;

use crate::http::client::error::{Error, ErrorKind, Result};

/// A Response to a submitted `Request`.
pub struct Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    url: Box<Url>,
    body_consumed: bool,
}

impl Response {
    pub(super) fn new(status: StatusCode, version: Version, headers: HeaderMap, body: Bytes, url: Url) -> Self {
        Self {
            status,
            version,
            headers,
            body,
            url: Box::new(url),
            body_consumed: false,
        }
    }

    #[inline]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[inline]
    pub fn version(&self) -> Version {
        self.version
    }

    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn text(self) -> Result<String> {
        String::from_utf8(self.body.to_vec()).map_err(|_| Error::new(ErrorKind::Decode("invalid utf-8".into())))
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::new(ErrorKind::Decode(e.to_string())))
    }

    pub fn bytes(self) -> Bytes {
        self.body
    }

    pub fn chunk(&mut self) -> Option<Bytes> {
        if self.body_consumed {
            return None;
        }
        self.body_consumed = true;
        Some(self.body.clone())
    }

    pub fn error_for_status(self) -> Result<Self> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(Error::new(ErrorKind::StatusCode(status.as_u16())).with_status(status))
        } else {
            Ok(self)
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Response")
            .field("url", &self.url.as_str())
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish()
    }
}
