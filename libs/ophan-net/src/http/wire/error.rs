use std::fmt;

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub pos: Option<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("invalid header")]
    InvalidHeader,
    #[error("incomplete message")]
    Incomplete,
    #[error("decode error: {0}")]
    Decode(String),
    #[error("encoding error: {0}")]
    Encode(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("headers too large")]
    HeadersTooLarge,
    #[error("body too large")]
    BodyTooLarge,
    #[error("invalid chunk encoding")]
    InvalidChunkEncoding,
    #[error("invalid status code")]
    InvalidStatusCode,
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(String),
    #[error("invalid uri: {0}")]
    InvalidUri(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, pos: None }
    }

    pub fn at(mut self, pos: usize) -> Self {
        self.pos = Some(pos);
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

impl From<httparse::Error> for Error {
    fn from(e: httparse::Error) -> Self {
        Self::new(ErrorKind::Decode(e.to_string()))
    }
}

impl From<http::header::InvalidHeaderName> for Error {
    fn from(e: http::header::InvalidHeaderName) -> Self {
        Self::new(ErrorKind::InvalidHeaderName(e.to_string()))
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(e: http::header::InvalidHeaderValue) -> Self {
        Self::new(ErrorKind::InvalidHeaderValue(e.to_string()))
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(e: http::uri::InvalidUri) -> Self {
        Self::new(ErrorKind::InvalidUri(e.to_string()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
