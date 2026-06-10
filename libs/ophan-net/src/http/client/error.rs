use std::fmt;

use http::StatusCode;

/// A client-level error with optional HTTP status and URL context.
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub status: Option<StatusCode>,
    pub url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("request timeout")]
    Timeout,
    #[error("status code: {0}")]
    StatusCode(u16),
    #[error("connection failed")]
    ConnectFailed,
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, status: None, url: None }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
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

impl From<crate::http::wire::Error> for Error {
    fn from(e: crate::http::wire::Error) -> Self {
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
        Self::new(ErrorKind::InvalidUrl(e.to_string()))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(_: http::uri::InvalidUri) -> Self {
        Self::new(ErrorKind::InvalidUrl("invalid uri".into()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
