use std::fmt;

#[derive(Debug)]
pub enum Error {
    Transport(ophan_net::http::Error),
    Serialization(serde_json::Error),
    InvalidToken(jsonwebtoken::errors::Error),

    KeyNotFound(String),
    InvalidJwkComponents(String),

    MissingToken,
    UnsupportedAlgorithm(jsonwebtoken::Algorithm),

    ClientNotConfigured,
    RefreshFlowDisabled,
    ProviderStatus(String),

    Dpop(DpopError),
}

#[derive(Debug)]
pub enum DpopError {
    InvalidFormat,
    InvalidType,
    ThumbprintMismatch,
    AthMismatch,
    HtmMismatch,
    HtuMismatch,
    NonceMismatch,
    Required,
    ProofRequired,
    Disabled,
    BindingMissing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "Network or HTTP transport error: {e}"),
            Self::Serialization(e) => write!(f, "Serialization or parsing failed: {e}"),
            Self::InvalidToken(e) => write!(f, "Cryptographic token processing or signature verification failed: {e}"),
            Self::KeyNotFound(kid) => write!(f, "The requested key ID (kid) '{kid}' was not found in the Provider's JWKS"),
            Self::InvalidJwkComponents(kid) => write!(f, "Failed to parse JWK components for key ID: {kid}"),
            Self::MissingToken => write!(
                f,
                "No token could be extracted from the request using the defined TokenSources"
            ),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "The signature algorithm '{alg:?}' is not supported or mismatch detected")
            },
            Self::ClientNotConfigured => write!(
                f,
                "The multi-tenant OAuth/OIDC client configuration is missing for this route"
            ),
            Self::RefreshFlowDisabled => write!(f, "Token refresh flow is disabled by configuration for this client"),
            Self::ProviderStatus(s) => write!(f, "The Identity Provider did not return a valid HTTP success status: {s}"),
            Self::Dpop(e) => write!(f, "{e}"),
        }
    }
}

impl fmt::Display for DpopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "DPoP proof has invalid format or missing required header"),
            Self::InvalidType => write!(f, "DPoP proof type must be 'dpop+jwt'"),
            Self::ThumbprintMismatch => write!(f, "DPoP proof jkt thumbprint does not match token cnf claim"),
            Self::AthMismatch => write!(f, "DPoP proof ath (access token hash) does not match"),
            Self::HtmMismatch => write!(f, "DPoP proof htm (HTTP method) does not match request method"),
            Self::HtuMismatch => write!(f, "DPoP proof htu (HTTP URI) does not match request URI"),
            Self::NonceMismatch => write!(f, "DPoP proof nonce does not match server-provided nonce"),
            Self::Required => write!(f, "DPoP is required but the token used a non-DPoP scheme"),
            Self::ProofRequired => write!(f, "DPoP token presented but no proof was provided"),
            Self::Disabled => write!(f, "DPoP is disabled but a DPoP token was presented"),
            Self::BindingMissing => write!(f, "Token lacks cnf claim required for DPoP binding"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::InvalidToken(e) => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for DpopError {}

impl From<ophan_net::http::Error> for Error {
    fn from(e: ophan_net::http::Error) -> Self {
        Self::Transport(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::InvalidToken(e)
    }
}

impl Error {
    pub fn is_refreshable(&self) -> bool {
        match self {
            Self::InvalidToken(err) => {
                use jsonwebtoken::errors::ErrorKind;
                matches!(err.kind(), ErrorKind::ExpiredSignature | ErrorKind::InvalidSignature)
            },
            Self::MissingToken => true,
            Self::Dpop(DpopError::Required) => true,
            _ => false,
        }
    }

    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidToken(_) | Self::MissingToken | Self::KeyNotFound(_) => 401,
            Self::Dpop(_) => 401,
            Self::ClientNotConfigured => 404,
            Self::RefreshFlowDisabled => 403,
            Self::ProviderStatus(_) => 502,
            _ => 500,
        }
    }

    /// RFC 6750 §3: Return the appropriate WWW-Authenticate challenge for 401 responses.
    pub fn www_authenticate(&self) -> &'static str {
        match self {
            Self::Dpop(_) => "DPoP",
            _ => "Bearer",
        }
    }

    pub fn log_and_explain(&self) -> &'static str {
        match self {
            Self::MissingToken => {
                tracing::info!("{}", self);
                "missing authentication token"
            },

            Self::InvalidToken(err) => {
                use jsonwebtoken::errors::ErrorKind;
                if matches!(err.kind(), ErrorKind::ExpiredSignature) {
                    tracing::info!("Token expired: {}", self);
                    "expired authentication token"
                } else {
                    tracing::warn!("Invalid credential attempt: {}", self);
                    "invalid authentication token"
                }
            },
            Self::Dpop(DpopError::Required) => {
                tracing::warn!("DPoP required but not provided: {}", self);
                "DPoP proof is required"
            },
            Self::Dpop(DpopError::ThumbprintMismatch) | Self::Dpop(DpopError::AthMismatch) => {
                tracing::warn!("DPoP proof binding mismatch: {}", self);
                "DPoP proof does not match token"
            },
            Self::Dpop(DpopError::HtmMismatch) | Self::Dpop(DpopError::HtuMismatch) => {
                tracing::warn!("DPoP proof request mismatch: {}", self);
                "DPoP proof does not match request"
            },
            Self::Dpop(DpopError::NonceMismatch) => {
                tracing::warn!("DPoP nonce mismatch: {}", self);
                "DPoP nonce mismatch — possible replay attack"
            },
            Self::Dpop(DpopError::InvalidFormat) | Self::Dpop(DpopError::InvalidType) => {
                tracing::warn!("Invalid DPoP proof format: {}", self);
                "invalid DPoP proof format"
            },
            Self::KeyNotFound(kid) => {
                tracing::warn!("Key not found for kid '{}': {}", kid, self);
                "signing key not found"
            },
            Self::RefreshFlowDisabled => {
                tracing::warn!("{}", self);
                "token refresh is not allowed for this client"
            },

            _ => {
                tracing::error!("Internal authentication panic/failure: {}", self);
                "internal security processing failure"
            },
        }
    }
}

// -- InvalidDpopPolicyError -----------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidDpopPolicyError(pub String);

impl fmt::Display for InvalidDpopPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid DPoP Policy token: '{}'. Supported choices are: 'auto', 'required', 'disabled'",
            self.0
        )
    }
}

impl std::error::Error for InvalidDpopPolicyError {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::errors::ErrorKind as JwtErrorKind;

    fn make_jwt_error(kind: JwtErrorKind) -> jsonwebtoken::errors::Error {
        jsonwebtoken::errors::Error::from(kind)
    }

    fn make_transport_error() -> ophan_net::http::Error {
        ophan_net::http::Error::new(ophan_net::http::client::error::ErrorKind::ConnectFailed)
    }

    // -- is_refreshable ---------------------------------------------------

    #[test]
    fn test_is_refreshable_expired_signature() {
        assert!(Error::InvalidToken(make_jwt_error(JwtErrorKind::ExpiredSignature)).is_refreshable());
    }

    #[test]
    fn test_is_refreshable_invalid_signature() {
        assert!(Error::InvalidToken(make_jwt_error(JwtErrorKind::InvalidSignature)).is_refreshable());
    }

    #[test]
    fn test_is_refreshable_missing_token() {
        assert!(Error::MissingToken.is_refreshable());
    }

    #[test]
    fn test_is_refreshable_dpop_required() {
        assert!(Error::Dpop(DpopError::Required).is_refreshable());
    }

    #[test]
    fn test_is_refreshable_malformed_token_not_refreshable() {
        assert!(!Error::InvalidToken(make_jwt_error(JwtErrorKind::InvalidToken)).is_refreshable());
    }

    #[test]
    fn test_is_refreshable_other_errors_not_refreshable() {
        assert!(!Error::Transport(make_transport_error()).is_refreshable());
        assert!(!Error::KeyNotFound("kid".into()).is_refreshable());
        assert!(!Error::ClientNotConfigured.is_refreshable());
        assert!(!Error::RefreshFlowDisabled.is_refreshable());
        assert!(!Error::Dpop(DpopError::Disabled).is_refreshable());
        assert!(!Error::Dpop(DpopError::HtmMismatch).is_refreshable());
    }

    // -- status_code ------------------------------------------------------

    #[test]
    fn test_status_code_invalid_token_returns_401() {
        assert_eq!(
            Error::InvalidToken(make_jwt_error(JwtErrorKind::ExpiredSignature)).status_code(),
            401
        );
    }

    #[test]
    fn test_status_code_missing_token_returns_401() {
        assert_eq!(Error::MissingToken.status_code(), 401);
    }

    #[test]
    fn test_status_code_key_not_found_returns_401() {
        assert_eq!(Error::KeyNotFound("kid".into()).status_code(), 401);
    }

    #[test]
    fn test_status_code_dpop_errors_return_401() {
        assert_eq!(Error::Dpop(DpopError::Required).status_code(), 401);
        assert_eq!(Error::Dpop(DpopError::ThumbprintMismatch).status_code(), 401);
        assert_eq!(Error::Dpop(DpopError::NonceMismatch).status_code(), 401);
    }

    #[test]
    fn test_status_code_client_not_configured_returns_404() {
        assert_eq!(Error::ClientNotConfigured.status_code(), 404);
    }

    #[test]
    fn test_status_code_refresh_disabled_returns_403() {
        assert_eq!(Error::RefreshFlowDisabled.status_code(), 403);
    }

    #[test]
    fn test_status_code_provider_status_returns_502() {
        assert_eq!(Error::ProviderStatus("503".into()).status_code(), 502);
    }

    #[test]
    fn test_status_code_transport_returns_500() {
        assert_eq!(Error::Transport(make_transport_error()).status_code(), 500);
    }
}
