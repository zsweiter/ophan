use std::fmt;

/// A wire-level HTTP error (parsing or encoding).
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub pos: Option<usize>,
}

/// The kind of wire error.
#[derive(Debug)]
pub enum ErrorKind {
    InvalidHeader,
    Incomplete,
    Decode(String),
    Encode(String),
    ConnectionClosed,
    HeadersTooLarge,
    BodyTooLarge,
    InvalidChunkEncoding,
    InvalidStatusCode,
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidUri(String),
    Io(std::io::Error),
}

impl Error {
    /// Create a new wire error with the given kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, pos: None }
    }

    /// Record the byte position where the error occurred.
    pub fn at(mut self, pos: usize) -> Self {
        self.pos = Some(pos);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pos) = self.pos {
            write!(f, "{} (at byte {pos})", self.kind)
        } else {
            write!(f, "{}", self.kind)
        }
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
            ErrorKind::InvalidHeader => write!(f, "invalid header"),
            ErrorKind::Incomplete => write!(f, "incomplete message"),
            ErrorKind::Decode(msg) => write!(f, "decode error: {msg}"),
            ErrorKind::Encode(msg) => write!(f, "encoding error: {msg}"),
            ErrorKind::ConnectionClosed => write!(f, "connection closed"),
            ErrorKind::HeadersTooLarge => write!(f, "headers too large"),
            ErrorKind::BodyTooLarge => write!(f, "body too large"),
            ErrorKind::InvalidChunkEncoding => write!(f, "invalid chunk encoding"),
            ErrorKind::InvalidStatusCode => write!(f, "invalid status code"),
            ErrorKind::InvalidHeaderName(msg) => write!(f, "invalid header name: {msg}"),
            ErrorKind::InvalidHeaderValue(msg) => write!(f, "invalid header value: {msg}"),
            ErrorKind::InvalidUri(msg) => write!(f, "invalid uri: {msg}"),
            ErrorKind::Io(e) => write!(f, "io: {e}"),
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
