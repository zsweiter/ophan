use std::fmt;

/// A TLS error with an optional peer address.
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub peer: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("certificate error: {0}")]
    CertError(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, peer: None }
    }

    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
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

pub type Result<T> = std::result::Result<T, Error>;
