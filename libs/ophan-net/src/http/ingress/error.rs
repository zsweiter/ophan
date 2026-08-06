use std::fmt;
use std::net::SocketAddr;

/// An ingress (incoming request) error.
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub peer: Option<SocketAddr>,
}

/// The kind of ingress error.
#[derive(Debug)]
pub enum ErrorKind {
    MalformedRequestLine,
    SmugglingDetected,
    HeadersTooLarge(usize),
    InvalidMethod,
    InvalidUri(String),
    InvalidHeader(String),
    Io(std::io::Error),
}

impl Error {
    /// Create a new ingress error with the given kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, peer: None }
    }

    /// Attach the peer socket address to the error.
    pub fn with_peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref peer) = self.peer {
            write!(f, "{} (peer: {})", self.kind, peer)
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
            ErrorKind::MalformedRequestLine => write!(f, "malformed request line"),
            ErrorKind::SmugglingDetected => write!(f, "http smuggling detected"),
            ErrorKind::HeadersTooLarge(size) => write!(f, "headers too large: {size}"),
            ErrorKind::InvalidMethod => write!(f, "invalid method"),
            ErrorKind::InvalidUri(msg) => write!(f, "invalid uri: {msg}"),
            ErrorKind::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
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

pub type Result<T> = std::result::Result<T, Error>;
