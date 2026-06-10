use http::{HeaderMap, Uri, request::Parts as RequestParts};
use ophan_auth::Algorithm;
use std::sync::Arc;

use crate::config::{OAuthConfig, TokenSource};
use crate::gateway::{GatewayError, OphanCtx};
use crate::middlewares::RequestOutcome;
use ophan_auth::{AuthConfig, AuthContext, AuthError, AuthService, Claims, JwtErrorKind, OAuth2Config};

pub struct AuthMiddleware {
    auth_service: Arc<AuthService>,
}

pub struct AuthClaims {
    pub claims: Option<Claims>,
    pub refresh_token: Option<String>,
}

impl AuthMiddleware {
    pub fn new(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }

    pub(crate) fn make_auth_config(oauth_cfg: &OAuthConfig) -> AuthConfig {
        let refresh_oauth = oauth_cfg.refresh_token.as_ref().filter(|r| r.enabled).map(|rt| OAuth2Config {
            endpoint: rt.token_endpoint.clone(),
            client_id: oauth_cfg.client_id.clone(),
            client_secret: oauth_cfg.client_secret.clone().unwrap_or_default(),
        });

        AuthConfig {
            algorithm: Algorithm::EdDSA,
            issuer: Some(oauth_cfg.issuer.clone()),
            audience: None,
            static_secret: None,
            jwk_uri: Some(oauth_cfg.jwk_uri.clone()),
            jwk_ttl: Some(2400),
            refresh_oauth,
        }
    }

    fn map_auth_error(err: AuthError) -> GatewayError {
        match err {
            AuthError::JwtValidation { kind: JwtErrorKind::Expired, .. }
            | AuthError::InvalidAccessToken
            | AuthError::InvalidRefreshToken => GatewayError::Unauthorized("invalid or expired authentication token".into()),
            AuthError::JwtValidation { .. } => {
                tracing::warn!(error = %err, "jwt validation rejected");
                GatewayError::Unauthorized("invalid or expired authentication token".into())
            },
            AuthError::HttpTransport { .. } => GatewayError::BadGateway("authentication provider unavailable".into()),
            AuthError::InvalidJwks | AuthError::UnsupportedJwk | AuthError::InvalidEndpoint => {
                GatewayError::InternalServerError("invalid authentication configuration".into())
            },
            AuthError::KeyNotFound | AuthError::MissingKid => {
                GatewayError::Unauthorized("authentication provider unavailable".into())
            },
            AuthError::Http(_) => GatewayError::InternalServerError("invalid authentication configuration".into()),
        }
    }

    pub async fn authenticate_request(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        oauth_cfg: &OAuthConfig,
        auth_config: &AuthConfig,
    ) -> Result<AuthClaims, GatewayError> {
        let tokens = Self::get_access_tokens(headers, uri, oauth_cfg);

        let Some(access_token) = tokens.acces_token else {
            let Some(refresh_token) = tokens.refresh_token else {
                return Err(GatewayError::Unauthorized("access token is not provided".into()));
            };
            return self.refresh_and_authenticate(refresh_token, auth_config).await;
        };

        let mut auth_ctx = AuthContext {
            access_token,
            refresh_token: tokens.refresh_token,
            is_mutated: false,
        };

        let claims = self.auth_service.authenticate(&mut auth_ctx, auth_config).await.map_err(Self::map_auth_error)?;
        Ok(AuthClaims { claims: Some(claims), refresh_token: auth_ctx.refresh_token })
    }

    async fn refresh_and_authenticate(
        &self,
        refresh_token: String,
        auth_config: &AuthConfig,
    ) -> Result<AuthClaims, GatewayError> {
        let mut auth_ctx = AuthContext {
            access_token: String::new(),
            refresh_token: Some(refresh_token),
            is_mutated: false,
        };

        match self.auth_service.authenticate(&mut auth_ctx, auth_config).await {
            Ok(claims) => Ok(AuthClaims { claims: Some(claims), refresh_token: auth_ctx.refresh_token }),
            Err(err) => {
                tracing::warn!(error = %err, "refresh and authenticate failed");
                Err(Self::map_auth_error(err))
            },
        }
    }

    pub fn get_access_tokens(headers: &HeaderMap, uri: &Uri, oauth_cfg: &OAuthConfig) -> PartialTokens {
        let acces_token: Option<String> = Self::extract_token_from(headers, uri, &oauth_cfg.sources);
        let mut refresh_token: Option<String> = None;

        if let Some(ref_cfg) = oauth_cfg.refresh_token.as_ref()
            && ref_cfg.enabled
        {
            refresh_token = Self::extract_token_from(headers, uri, std::slice::from_ref(&ref_cfg.source))
        }

        PartialTokens { acces_token, refresh_token }
    }

    fn strip_prefix<'a>(value: &'a str, prefix: &Option<String>) -> Option<&'a str> {
        match prefix {
            Some(p) => value.strip_prefix(p.as_str()),
            None => Some(value),
        }
    }

    fn extract_token_from(headers: &HeaderMap, uri: &Uri, sources: &[TokenSource]) -> Option<String> {
        for source in sources {
            let token: Option<&str> = match source {
                TokenSource::Header { name, prefix } => {
                    headers.get(name).and_then(|v| v.to_str().ok()).and_then(|v| Self::strip_prefix(v, prefix))
                },
                TokenSource::QueryParam { name, prefix } => uri.query().and_then(|query| {
                    query.split('&').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        (k == name).then(|| Self::strip_prefix(v, prefix)).flatten()
                    })
                }),
                TokenSource::Cookie { name, prefix } => headers.get("cookie").and_then(|v| v.to_str().ok()).and_then(|cookies| {
                    cookies.split(';').find_map(|cookie| {
                        let (k, v) = cookie.trim().split_once('=')?;
                        (k == name).then(|| Self::strip_prefix(v, prefix)).flatten()
                    })
                }),
            };

            if let Some(token) = token {
                return Some(token.to_owned());
            }
        }

        None
    }

    pub async fn on_request(&self, request: &RequestParts, ctx: &mut OphanCtx) -> Result<RequestOutcome, pingora::BError> {
        let Some(auth_cfg) = ctx.matched_route.as_ref().and_then(|r| r.auth_policy.as_deref()) else {
            return Ok(RequestOutcome::Continue);
        };
        let Some(auth_config) = ctx.matched_route.as_ref().and_then(|r| r.auth_config.as_deref()) else {
            return Ok(RequestOutcome::Continue);
        };

        if let Some(ref matched) = ctx.matched_route
            && matched.auth_excludes.contains(request.uri.path())
        {
            return Ok(RequestOutcome::Continue);
        }

        match self.authenticate_request(&request.headers, &request.uri, auth_cfg, auth_config).await {
            Ok(claims) => {
                ctx.jwt_claims = claims.claims;
                ctx.refreshed_token = claims.refresh_token;
                Ok(RequestOutcome::Continue)
            },
            Err(err) => {
                tracing::warn!(error = ?err, "authentication rejected");
                Ok(RequestOutcome::Reject(err))
            },
        }
    }
}

pub struct PartialTokens {
    pub acces_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use http::{HeaderMap, Uri};

    use crate::{
        config::{OAuthConfig, RefreshTokenConfig, TokenSource},
        middlewares::auth::AuthMiddleware,
    };

    #[test]
    fn test_extract_token_from_header_with_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer my-access-token".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-access-token".into()));
    }

    #[test]
    fn test_extract_token_from_header_without_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Api-Key", "my-api-key".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "X-Api-Key".into(), prefix: None }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-api-key".into()));
    }

    #[test]
    fn test_extract_token_from_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc; access_token=my-token; other=val".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Cookie { name: "access_token".into(), prefix: None }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-token".into()));
    }

    #[test]
    fn test_extract_token_from_cookie_with_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "token=Bearer%20my-token".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Cookie { name: "token".into(), prefix: Some("Bearer%20".into()) }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-token".into()));
    }

    #[test]
    fn test_extract_token_from_query_param() {
        let headers = HeaderMap::new();
        let uri = Uri::from_static("/api/resource?access_token=my-token&other=val");

        let sources = vec![TokenSource::QueryParam { name: "access_token".into(), prefix: None }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-token".into()));
    }

    #[test]
    fn test_extract_token_from_query_param_with_prefix() {
        let headers = HeaderMap::new();
        let uri = Uri::from_static("/api/resource?token=Bearer%20my-token");

        let sources = vec![TokenSource::QueryParam { name: "token".into(), prefix: Some("Bearer%20".into()) }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("my-token".into()));
    }

    #[test]
    fn test_extract_token_returns_first_match() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer first-token".parse().unwrap());
        headers.insert("X-Api-Key", "second-key".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![
            TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) },
            TokenSource::Header { name: "X-Api-Key".into(), prefix: None },
        ];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, Some("first-token".into()));
    }

    #[test]
    fn test_extract_token_missing_returns_none() {
        let headers = HeaderMap::new();
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, None);
    }

    #[test]
    fn test_extract_token_wrong_prefix_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic dGVzdDp0ZXN0".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }];

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_config(&sources));
        assert_eq!(tokens.acces_token, None);
    }

    #[test]
    fn test_extract_refresh_token() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer access-token-123".parse().unwrap());
        headers.insert("X-Refresh-Token", "refresh-token-456".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }];
        let refresh_source = TokenSource::Header { name: "X-Refresh-Token".into(), prefix: None };

        let oauth_cfg = OAuthConfig {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            client_secret: Some("secret".into()),
            scopes: vec![],
            jwk_uri: "https://auth.example.com/jwks".into(),
            sources,
            refresh_token: Some(RefreshTokenConfig {
                enabled: true,
                token_endpoint: "https://auth.example.com/token".into(),
                source: refresh_source,
                auto_rotate_response: false,
            }),
            excludes: vec![],
        };

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_cfg);
        assert_eq!(tokens.acces_token, Some("access-token-123".into()));
        assert_eq!(tokens.refresh_token, Some("refresh-token-456".into()));
    }

    #[test]
    fn test_extract_refresh_token_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer access-token-123".parse().unwrap());
        headers.insert("X-Refresh-Token", "refresh-token-456".parse().unwrap());
        let uri = Uri::from_static("/api/resource");

        let sources = vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }];
        let refresh_source = TokenSource::Header { name: "X-Refresh-Token".into(), prefix: None };

        let oauth_cfg = OAuthConfig {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            client_secret: Some("secret".into()),
            scopes: vec![],
            jwk_uri: "https://auth.example.com/jwks".into(),
            sources,
            refresh_token: Some(RefreshTokenConfig {
                enabled: false,
                token_endpoint: "https://auth.example.com/token".into(),
                source: refresh_source,
                auto_rotate_response: false,
            }),
            excludes: vec![],
        };

        let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, &oauth_cfg);
        assert_eq!(tokens.acces_token, Some("access-token-123".into()));
        assert_eq!(tokens.refresh_token, None);
    }

    fn oauth_config(sources: &[TokenSource]) -> OAuthConfig {
        OAuthConfig {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            client_secret: Some("secret".into()),
            scopes: vec![],
            jwk_uri: "https://auth.example.com/jwks".into(),
            sources: sources.to_vec(),
            refresh_token: None,
            excludes: vec![],
        }
    }
}
