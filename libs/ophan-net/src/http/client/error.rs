use std::fmt;

use http::StatusCode;

/// An HTTP client error.
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub status: Option<StatusCode>,
    pub url: Option<String>,
}

/// The kind of client error.
#[derive(Debug)]
pub enum ErrorKind {
    Timeout,
    StatusCode(u16),
    ConnectFailed,
    Tls(String),
    InvalidUrl(url::ParseError),
    InvalidUri(http::uri::InvalidUri),
    Decode(String),
    Encode(String),
    Io(std::io::Error),
}

impl Error {
    /// Create a new `Error` with the given kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, status: None, url: None }
    }

    /// Attach an HTTP status code to the error.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Attach the request URL to the error.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ref url) = self.url {
            write!(f, " (url: {url})")?;
        }
        if let Some(ref status) = self.status {
            write!(f, " (http {status})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Timeout => write!(f, "request timeout"),
            ErrorKind::StatusCode(code) => write!(f, "status code: {code}"),
            ErrorKind::ConnectFailed => write!(f, "connection failed"),
            ErrorKind::Tls(msg) => write!(f, "tls: {msg}"),
            ErrorKind::InvalidUrl(msg) => write!(f, "invalid url: {msg}"),
            ErrorKind::Decode(msg) => write!(f, "decode: {msg}"),
            ErrorKind::Encode(msg) => write!(f, "encode: {msg}"),
            ErrorKind::Io(e) => write!(f, "io: {e}"),
            ErrorKind::InvalidUri(e) => write!(f, "invalid uri: {e}"),
        }
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io(e))
    }
}

impl From<crate::http::protocol::Error> for Error {
    fn from(e: crate::http::protocol::Error) -> Self {
        Self::new(ErrorKind::Decode(e.to_string()))
    }
}

impl From<crate::transport::Error> for Error {
    fn from(e: crate::transport::Error) -> Self {
        Self::new(ErrorKind::ConnectFailed).with_url(e.peer.unwrap_or_default())
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Self::new(ErrorKind::InvalidUrl(e))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(e: http::uri::InvalidUri) -> Self {
        Self::new(ErrorKind::InvalidUri(e))
    }
}

impl From<crate::tls::error::Error> for Error {
    fn from(e: crate::tls::error::Error) -> Self {
        Self::new(ErrorKind::Tls(e.to_string()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
