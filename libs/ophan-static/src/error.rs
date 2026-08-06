use http::StatusCode;
use std::error::Error as StdError;
use std::fmt;
use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error type for static file serving operations.
///
/// Every request — success or failure — terminates with this type,
/// ensuring consistent error handling across the crate.
#[derive(Debug)]
pub struct Error {
    /// The HTTP status code to return to the client.
    pub status: StatusCode,
    /// The request path that caused the error.
    pub path: Box<str>,
    /// The underlying I/O error, if any.
    pub source: Option<io::Error>,
}

impl Error {
    #[inline]
    pub fn new(status: StatusCode, path: impl Into<Box<str>>) -> Self {
        Self { status, path: path.into(), source: None }
    }

    #[inline]
    pub fn from_io(err: io::Error, path: &str) -> Self {
        let status = map_io_kind(err.kind());

        Self { status, path: path.into(), source: Some(err) }
    }

    #[inline]
    pub fn forbidden(path: impl Into<Box<str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, path)
    }

    #[inline]
    pub fn not_found(path: impl Into<Box<str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, path)
    }

    #[inline]
    pub fn range_not_satisfiable(path: impl Into<Box<str>>) -> Self {
        Self::new(StatusCode::RANGE_NOT_SATISFIABLE, path)
    }

    pub fn message(&self) -> String {
        match &self.source {
            Some(io) => format!("{} ({}): {}", self.status, self.path, io),
            None => format!("{} ({})", self.status, self.path),
        }
    }
}

impl From<Error> for StatusCode {
    #[inline]
    fn from(e: Error) -> Self {
        e.status
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(err) => write!(f, "{} ({}): {}", self.status, self.path, err),
            None => write!(f, "{} ({})", self.status, self.path),
        }
    }
}

impl StdError for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn StdError + 'static))
    }
}

#[inline]
pub fn map_io_kind(kind: io::ErrorKind) -> StatusCode {
    match kind {
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        io::ErrorKind::AlreadyExists => StatusCode::CONFLICT,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => StatusCode::BAD_REQUEST,
        io::ErrorKind::TimedOut => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
