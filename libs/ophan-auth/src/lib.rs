mod errors;
mod jwk;
mod jwt;
mod oauth;

#[cfg(test)]
mod auth_test;

use std::sync::Arc;

use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey, decode_header};

pub use errors::{AuthError, JwtErrorKind};
pub use jwk::JwksManager;
pub use jwt::{Claims, JwtConfig, JwtValidator};
pub use oauth::{OAuth2Client, OAuth2Config};

pub type Algorithm = JwtAlgorithm;

/// Mutable auth context.
///
/// This object represents per-request authentication state.
///
/// The service itself is stateless.
/// Any token mutation/refresh operation happens through this context.
///
/// This allows:
///
/// - concurrent request isolation
/// - no shared mutable auth state
/// - easier testing
/// - deterministic auth flows
///
pub struct AuthContext {
    pub access_token: String,
    pub refresh_token: Option<String>,

    /// Indicates whether the auth context was mutated
    /// during the authentication flow.
    ///
    /// Example:
    ///
    /// - token refresh occurred
    /// - access token rotated
    /// - refresh token rotated
    ///
    pub is_mutated: bool,
}

pub struct AuthConfig {
    /// Explicit allowed algorithm.
    ///
    /// IMPORTANT:
    /// Never trust the JWT header algorithm.
    ///
    /// The token algorithm must match this configured algorithm.
    ///
    pub algorithm: Algorithm,

    pub issuer: Option<String>,
    pub audience: Option<String>,

    /// Static HMAC secret.
    ///
    /// Only used for:
    ///
    /// - HS256
    /// - HS384
    /// - HS512
    ///
    pub static_secret: Option<String>,

    /// Remote JWKS endpoint.
    ///
    /// Required for:
    ///
    /// - RS256
    /// - ES256
    /// - EdDSA
    ///
    pub jwk_uri: Option<String>,

    /// JWKS cache ttl.
    #[allow(unused)]
    pub jwk_ttl: Option<usize>,

    /// Optional OAuth2 refresh configuration.
    pub refresh_oauth: Option<OAuth2Config>,
}

pub struct AuthService {
    validator: JwtValidator,
    oauth_client: OAuth2Client,
    jwk_store: JwksManager,
}

impl AuthService {
    pub fn new(validator: JwtValidator, oauth: OAuth2Client, jwk_store: JwksManager) -> Self {
        Self { validator, oauth_client: oauth, jwk_store }
    }

    /// Authenticate request context.
    ///
    /// Flow:
    ///
    /// 1. resolve decoding key
    /// 2. validate jwt
    /// 3. optionally refresh expired tokens
    /// 4. revalidate refreshed token
    ///
    pub async fn authenticate(&self, context: &mut AuthContext, config: &AuthConfig) -> Result<Claims, AuthError> {
        match self.try_authenticate(context, config).await {
            Err(AuthError::JwtValidation { kind: JwtErrorKind::Expired, .. }) => self.try_refresh_flow(context, config).await,
            Ok(claims) => Ok(claims),
            Err(err) => {
                tracing::warn!(error = %err, "authentication failed");
                Err(err)
            },
        }
    }

    async fn try_authenticate(&self, context: &AuthContext, config: &AuthConfig) -> Result<Claims, AuthError> {
        if context.access_token.trim().is_empty() {
            return Err(AuthError::InvalidAccessToken);
        }

        let decoding_key = self.get_decoding_key(context, config).await?;
        let claims = self.validator.validate(&context.access_token, &decoding_key, config)?;

        Ok(claims)
    }

    async fn try_refresh_flow(&self, context: &mut AuthContext, config: &AuthConfig) -> Result<Claims, AuthError> {
        let refresh_token = context.refresh_token.as_deref().ok_or(AuthError::InvalidRefreshToken)?;

        let oauth_config = config.refresh_oauth.as_ref().ok_or_else(|| {
            tracing::warn!("refresh oauth not configured");
            AuthError::InvalidRefreshToken
        })?;

        let token_response = self.oauth_client.refresh_token(refresh_token, oauth_config).await?;
        if token_response.access_token.trim().is_empty() {
            return Err(AuthError::InvalidAccessToken);
        }

        context.access_token = token_response.access_token;

        if let Some(refresh_token) = token_response.refresh_token
            && !refresh_token.trim().is_empty()
        {
            context.refresh_token = Some(refresh_token);
        }

        context.is_mutated = true;

        self.try_authenticate(context, config).await
    }

    async fn get_decoding_key(&self, ctx: &AuthContext, config: &AuthConfig) -> Result<Arc<DecodingKey>, AuthError> {
        let header = decode_header(&ctx.access_token).map_err(|e| {
            tracing::warn!(error = %e, "failed to decode jwt header");
            jwt::jwt_error(e)
        })?;

        if header.alg != config.algorithm {
            tracing::warn!(token_alg = ?header.alg, expected_alg = ?config.algorithm, "token algorithm mismatch");
            return Err(AuthError::UnsupportedJwk);
        }

        match config.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let secret = config.static_secret.as_deref().filter(|s| !s.trim().is_empty()).ok_or_else(|| {
                    tracing::warn!("static secret not configured for hmac algorithm");
                    AuthError::KeyNotFound
                })?;

                Ok(Arc::new(DecodingKey::from_secret(secret.as_bytes())))
            },

            _ => {
                let kid = header.kid.as_deref().filter(|k| !k.trim().is_empty()).ok_or(AuthError::MissingKid)?;
                let url = config.jwk_uri.as_deref().filter(|u| !u.trim().is_empty()).ok_or(AuthError::InvalidJwks)?;

                self.jwk_store.get_key(url, kid).await
            },
        }
    }
}
