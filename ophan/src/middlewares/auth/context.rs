use http::HeaderValue;
use ophan_auth::Claims;
use std::{sync::OnceLock, time::Duration};

/// Authentication state stored during the lifetime of a request.
///
/// This context only exists after successful authentication.
#[derive(Debug)]
pub struct AuthContext {
    /// Authenticated user claims.
    pub claims: Claims,

    /// Newly issued tokens, if the access token was refreshed.
    pub refresh: Option<RefreshedTokens>,

    /// Encoded `x-user-claims` value, built on first use.
    claims_header: OnceLock<Option<HeaderValue>>,
}

impl AuthContext {
    pub fn new(claims: Claims, refresh: Option<RefreshedTokens>) -> Self {
        Self { claims, refresh, claims_header: OnceLock::new() }
    }

    /// The `x-user-claims` upstream header value: the claims encoded with
    /// [`Claims::encode_bytes`].
    ///
    /// The value is encoded once per request and shared by every upstream
    /// attempt (e.g. retries). Returns `None` if the claims cannot be encoded.
    pub fn claims_header(&self) -> Option<&HeaderValue> {
        self.claims_header
            .get_or_init(|| {
                let encoded = self
                    .claims
                    .encode_bytes()
                    .inspect_err(|err| tracing::error!(err = %err, "failed to encode user claims"))
                    .ok()?;

                HeaderValue::from_maybe_shared(encoded)
                    .inspect_err(|err| tracing::error!(err = %err, "failed to create claims header"))
                    .ok()
            })
            .as_ref()
    }
}

/// Tokens issued after a successful refresh operation.
#[derive(Debug, Clone)]
pub struct RefreshedTokens {
    /// Newly issued access token.
    pub access_token: String,

    /// Newly issued refresh token.
    ///
    /// Some providers rotate refresh tokens while others keep the
    /// existing one, so this value is optional.
    pub refresh_token: Option<String>,

    /// Lifetime of the access token, if reported by the provider.
    pub expires_in: Option<Duration>,

    /// Lifetime of the refresh token, if reported by the provider
    /// (`refresh_expires_in`).
    pub refresh_expires_in: Option<Duration>,
}
