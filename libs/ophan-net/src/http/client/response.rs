use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version};
use serde::de::DeserializeOwned;

use crate::http::client::error::{Error, ErrorKind, Result};

/// An HTTP response with a fully-buffered body.
pub struct Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    body_consumed: bool,
}

impl Response {
    /// Create a new `Response` (internal).
    pub(super) fn new(status: StatusCode, version: Version, headers: HeaderMap, body: Bytes) -> Self {
        Self { status, version, headers, body, body_consumed: false }
    }

    /// Return the HTTP status code.
    #[inline]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Return the HTTP version.
    #[inline]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Return a reference to the response headers.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consume the response and return the body as a UTF-8 string.
    pub fn text(self) -> Result<String> {
        std::str::from_utf8(&self.body)
            .map(|s| s.to_owned())
            .map_err(|_| Error::new(ErrorKind::Decode("invalid utf-8".into())))
    }

    /// Consume the response and return the body as a String, replacing invalid
    /// UTF-8 sequences with the replacement character (U+FFFD).
    pub fn text_lossy(self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Deserialize the body as JSON.
    pub fn json<T: DeserializeOwned>(self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::new(ErrorKind::Decode(e.to_string())))
    }

    /// Consume the response and return the body as raw bytes.
    pub fn bytes(self) -> Bytes {
        self.body
    }

    /// Take one chunk of the body. Returns `None` if already consumed.
    pub fn chunk(&mut self) -> Option<Bytes> {
        if self.body_consumed {
            return None;
        }
        self.body_consumed = true;
        Some(std::mem::take(&mut self.body))
    }

    /// Consume `self` and return `Err` if the status is 4xx or 5xx.
    pub fn error_for_status(self) -> Result<Self> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(Error::new(ErrorKind::StatusCode(self.status.as_u16())).with_status(self.status))
        } else {
            Ok(self)
        }
    }

    /// Borrow-checker-friendly version: returns `Err` if status is 4xx or 5xx,
    /// without consuming `self`.
    pub fn error_for_status_ref(&self) -> Result<()> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(Error::new(ErrorKind::StatusCode(self.status.as_u16())).with_status(self.status))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Response").field("status", &self.status).field("headers", &self.headers).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn ok_response() -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        Response::new(StatusCode::OK, Version::HTTP_11, headers, Bytes::from_static(b"hello"))
    }

    fn not_found_response() -> Response {
        Response::new(
            StatusCode::NOT_FOUND,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"not found"),
        )
    }

    #[test]
    fn status_ok() {
        assert_eq!(ok_response().status(), StatusCode::OK);
    }

    #[test]
    fn text_ok() {
        assert_eq!(ok_response().text().unwrap(), "hello");
    }

    #[test]
    fn text_lossy_valid() {
        assert_eq!(ok_response().text_lossy(), "hello");
    }

    #[test]
    fn text_lossy_invalid_utf8() {
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"\xff\xfe"),
        );
        let s = resp.text_lossy();
        // Should contain replacement characters
        assert_eq!(s, "\u{fffd}\u{fffd}");
    }

    #[test]
    fn json_deserialize() {
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"{\"key\":\"value\"}"),
        );
        let val: serde_json::Value = resp.json().unwrap();
        assert_eq!(val["key"], "value");
    }

    #[test]
    fn json_invalid() {
        let resp = Response::new(
            StatusCode::OK,
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::from_static(b"not json"),
        );
        assert!(resp.json::<serde_json::Value>().is_err());
    }

    #[test]
    fn bytes_consumes() {
        let resp = ok_response();
        assert_eq!(resp.bytes(), Bytes::from_static(b"hello"));
    }

    #[test]
    fn chunk_once() {
        let mut resp = ok_response();
        assert_eq!(resp.chunk(), Some(Bytes::from_static(b"hello")));
        assert_eq!(resp.chunk(), None);
    }

    #[test]
    fn error_for_status_ok() {
        let resp = ok_response();
        assert!(resp.error_for_status().is_ok());
    }

    #[test]
    fn error_for_status_4xx() {
        let resp = not_found_response();
        let err = resp.error_for_status().unwrap_err();
        assert_eq!(err.status, Some(StatusCode::NOT_FOUND));
    }

    #[test]
    fn error_for_status_ref_ok() {
        let resp = ok_response();
        assert!(resp.error_for_status_ref().is_ok());
    }

    #[test]
    fn error_for_status_ref_4xx() {
        let resp = not_found_response();
        assert!(resp.error_for_status_ref().is_err());
        // resp is still usable after ref check
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
