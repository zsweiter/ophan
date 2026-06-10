#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtErrorKind {
    Expired,
    InvalidSignature,
    InvalidToken,
    Other,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("jwt validation error ({kind:?}): {message}")]
    JwtValidation { kind: JwtErrorKind, message: String },

    #[error("http transport error: {message}")]
    HttpTransport { status: Option<u16>, message: String },

    #[error("http transport error")]
    Http(#[from] ophan_net::http::Error),

    #[error("missing kid")]
    MissingKid,

    #[error("key not found")]
    KeyNotFound,

    #[error("unsupported jwk")]
    UnsupportedJwk,

    #[error("invalid jwks")]
    InvalidJwks,

    #[error("invalid refresh token")]
    InvalidRefreshToken,

    #[error("invalid endpoint")]
    InvalidEndpoint,

    #[error("invalid access token")]
    InvalidAccessToken,
}
