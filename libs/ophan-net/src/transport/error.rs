use std::fmt;

/// A transport-level error (TCP or Unix socket).
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub peer: Option<String>,
}

/// The kind of transport error.
#[derive(Debug)]
pub enum ErrorKind {
    Io(std::io::Error),
    Unsupported,
    DnsFailed(String),
}

impl Error {
    /// Create a new transport error with the given kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, peer: None }
    }

    /// Attach the peer identifier to the error.
    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
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
            ErrorKind::Io(e) => write!(f, "io: {e}"),
            ErrorKind::Unsupported => write!(f, "unsupported protocol"),
            ErrorKind::DnsFailed(msg) => write!(f, "dns resolution failed: {msg}"),
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
