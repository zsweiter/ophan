use ophan_auth::Claims;
use std::time::Duration;

/// Authentication state stored during the lifetime of a request.
///
/// This context only exists after successful authentication.
#[derive(Debug)]
pub struct AuthContext {
    /// Authenticated user claims.
    pub claims: Claims,

    /// Newly issued tokens, if the access token was refreshed.
    pub refresh: Option<RefreshedTokens>,
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

    /// Lifetime of the access token.
    pub expires_in: Duration,
}
