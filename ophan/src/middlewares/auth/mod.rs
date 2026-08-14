mod context;

use std::time::Duration;

use flatkit::matchers::PathMatcherSet;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use ophan_auth::{
    AuthConfig as InnerAuthConfig, AuthService, Claims, DPoPRequestContext, JwtConfig, JwtValidator, OAuthClient, RawToken,
};
use ophan_net::{
    http::{
        client,
        cookies::{self, Cookie},
    },
    proxy::{RequestParts, ResponseParts},
};

use crate::{
    gateway::{GatewayError, OphanCtx},
    middlewares::FilterAction,
};

pub use context::{AuthContext, RefreshedTokens};

/// Defines where a token should be extracted from.
#[derive(Debug, Clone)]
pub enum TokenSource {
    Header { name: String, prefix: Option<String> },
    Cookie { name: String, prefix: Option<String> },
    QueryParam { name: String, prefix: Option<String> },
}

impl TokenSource {
    /// Standard Authorization: Bearer <token>.
    pub fn bearer() -> Self {
        Self::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }
    }

    /// DPoP proof header.
    pub fn dpop() -> Self {
        Self::Header { name: "DPoP".into(), prefix: None }
    }

    /// Default refresh token cookie.
    pub fn refresh() -> Self {
        Self::Cookie { name: "refresh_token".into(), prefix: None }
    }
}

impl Default for TokenSource {
    fn default() -> Self {
        Self::bearer()
    }
}

/// Defines where refreshed tokens should be injected.
#[derive(Debug, Clone)]
pub enum TokenDestination {
    Header { name: HeaderName },
    Cookie { name: String, path: String },
}

/// Successful authentication result.
#[derive(Debug, Clone)]
pub struct Authentication {
    /// Authenticated user claims.
    pub claims: Claims,

    /// Newly issued tokens, if the session was refreshed.
    pub refresh: Option<RefreshedTokens>,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub client: InnerAuthConfig,

    /// Locations used to search for access tokens.
    pub sources: Box<[TokenSource]>,

    /// Optional refresh token source.
    pub refresh_sources: Option<TokenSource>,

    /// Optional DPoP proof source.
    pub dpop_source: Option<TokenSource>,

    /// Where to inject a refreshed access token.
    pub inject_access_token_into: Box<[TokenDestination]>,

    /// Where to inject a refreshed refresh token.
    pub inject_refresh_token_into: Box<[TokenDestination]>,

    /// Optional token lifetime override.
    pub token_ttl: Option<Duration>,

    pub skip_patterns: Option<PathMatcherSet>,
}

pub struct AuthMiddleware {
    auth_service: AuthService,
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self {
            auth_service: AuthService::new(
                OAuthClient::new(client::Client::new()),
                JwtValidator::new(JwtConfig::default()),
            ),
        }
    }

    pub async fn on_request(&self, request: &RequestParts, config: &AuthConfig, ctx: &mut OphanCtx) -> FilterAction {
        if let Some(skip_pattern) = config.skip_patterns.as_ref()
            && skip_pattern.is_match(request.uri.path().as_bytes())
        {
            return FilterAction::Continue;
        }

        match self.authenticate_request(request, config).await {
            Ok(auth) => {
                ctx.policies.auth = Some(AuthContext { claims: auth.claims, refresh: auth.refresh });

                FilterAction::Continue
            },

            Err(err) => {
                ctx.policies.auth = None;

                tracing::warn!(error = ?err, "authentication rejected");

                FilterAction::Reject(err.kind.into())
            },
        }
    }

    pub fn prepare_response(&self, res: &mut ResponseParts, config: &AuthConfig, auth: &AuthContext) {
        let Some(ref refreshed) = auth.refresh else {
            return;
        };

        for target in config.inject_access_token_into.iter() {
            inject_token(res, target, &refreshed.access_token, Some(refreshed.expires_in));
        }

        if let Some(refresh_token) = refreshed.refresh_token.as_deref() {
            for target in config.inject_refresh_token_into.iter() {
                inject_token(res, target, refresh_token, Some(refreshed.expires_in));
            }
        }
    }

    async fn authenticate_request(&self, request: &RequestParts, config: &AuthConfig) -> Result<Authentication, GatewayError> {
        let tokens = Self::extract_request_tokens(&request.headers, &request.uri, config);

        let Some(access_token) = tokens.access_token else {
            return match tokens.refresh_token {
                Some(refresh) => self.refresh_session(&config.client, refresh, tokens.dpop_proof).await,
                None => Err(GatewayError::from(StatusCode::UNAUTHORIZED)),
            };
        };

        let raw_token = RawToken { token: access_token, ttype: tokens.access_token_type };

        let dpop_proof = DPoPRequestContext {
            dpop_proof: tokens.dpop_proof,
            method: request.method.as_str(),
            uri: request.uri.path_and_query().map(|a| a.as_str()).unwrap_or_default(),
            nonce: None,
        };

        match self.auth_service.authenticate(&config.client, raw_token, dpop_proof).await {
            Ok(claims) => Ok(Authentication { claims, refresh: None }),

            Err(err) if err.is_refreshable() => match tokens.refresh_token {
                Some(refresh) => self.refresh_session(&config.client, refresh, tokens.dpop_proof).await,
                None => Err(auth_error_to_gateway(err)),
            },

            Err(err) => Err(auth_error_to_gateway(err)),
        }
    }

    async fn refresh_session(
        &self,
        config: &InnerAuthConfig,
        refresh_token: &str,
        dpop_proof: Option<&str>,
    ) -> Result<Authentication, GatewayError> {
        let refreshed = self.auth_service.refresh_session(config, refresh_token, dpop_proof).await;
        // !TODO describe errors and log
        let refreshed = refreshed.map_err(|_| GatewayError::from(StatusCode::UNAUTHORIZED))?;

        Ok(Authentication {
            claims: refreshed.claims,
            refresh: Some(RefreshedTokens {
                access_token: refreshed.response.access_token.into_owned(),
                refresh_token: refreshed.response.refresh_token.map(|a| a.into_owned()),
                expires_in: Duration::from_secs(refreshed.response.expires_in),
            }),
        })
    }

    fn extract_request_tokens<'a>(headers: &'a HeaderMap, uri: &'a Uri, config: &AuthConfig) -> RequestTokens<'a> {
        let (access_token, access_token_type) = Self::match_source_with_type(headers, uri, &config.sources);

        let mut refresh_token = None;
        if config.client.oauth_client.as_ref().is_some_and(|c| c.refresh_flow_enabled)
            && let Some(sources) = &config.refresh_sources
        {
            refresh_token = Self::match_source(headers, uri, std::slice::from_ref(sources));
        }

        let mut dpop_proof = None;
        if let Some(source) = &config.dpop_source {
            dpop_proof = Self::match_source(headers, uri, std::slice::from_ref(source));
        }

        RequestTokens { access_token, access_token_type, refresh_token, dpop_proof }
    }

    fn match_source<'a>(headers: &'a HeaderMap, uri: &'a Uri, sources: &[TokenSource]) -> Option<&'a str> {
        Self::match_source_with_type(headers, uri, sources).0
    }

    /// Match a token source and also detect the token type from the Authorization header prefix.
    /// RFC 6750 §2.1: "Bearer" / RFC 9449 §4.1: "DPoP"
    fn match_source_with_type<'a>(
        headers: &'a HeaderMap,
        uri: &'a Uri,
        sources: &[TokenSource],
    ) -> (Option<&'a str>, ophan_auth::TokenType) {
        for source in sources {
            let (token, token_type) = match source {
                TokenSource::Header { name, prefix } => {
                    let val = headers.get(name).and_then(|v| v.to_str().ok());
                    match (val, prefix.as_deref()) {
                        (Some(v), Some("Bearer ")) => (v.strip_prefix("Bearer "), ophan_auth::TokenType::Bearer),
                        (Some(v), Some("DPoP ")) => (v.strip_prefix("DPoP "), ophan_auth::TokenType::DPoP),
                        (Some(v), Some(p)) => (v.strip_prefix(p), ophan_auth::TokenType::Bearer),
                        (Some(v), None) => (Some(v), ophan_auth::TokenType::Bearer),
                        (None, _) => (None, ophan_auth::TokenType::Bearer),
                    }
                },

                TokenSource::QueryParam { name, prefix } => {
                    let tok = uri.query().and_then(|query| {
                        query.split('&').find_map(|pair| {
                            let (k, v) = pair.split_once('=')?;
                            (k == name).then(|| strip_prefix(v, prefix.as_ref())).flatten()
                        })
                    });
                    (tok, ophan_auth::TokenType::Bearer)
                },

                TokenSource::Cookie { name, prefix } => {
                    let tok = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).and_then(|cookies| {
                        cookies.split(';').find_map(|cookie| {
                            let (k, v) = cookie.trim().split_once('=')?;
                            (k == name).then(|| strip_prefix(v, prefix.as_ref())).flatten()
                        })
                    });
                    (tok, ophan_auth::TokenType::Bearer)
                },
            };

            if token.is_some() {
                return (token, token_type);
            }
        }

        (None, ophan_auth::TokenType::Bearer)
    }
}

/// Tokens extracted from the incoming request.
pub struct RequestTokens<'a> {
    pub access_token: Option<&'a str>,
    pub access_token_type: ophan_auth::TokenType,
    pub refresh_token: Option<&'a str>,
    pub dpop_proof: Option<&'a str>,
}

#[inline]
fn strip_prefix<'a>(value: &'a str, prefix: Option<&String>) -> Option<&'a str> {
    match prefix {
        Some(prefix) => value.strip_prefix(prefix),
        None => Some(value),
    }
}

/// Convert an authentication error into a GatewayError with appropriate status code
/// and explanation message. Used to deduplicate error handling in authenticate_request.
#[inline]
fn auth_error_to_gateway(err: ophan_auth::Error) -> GatewayError {
    let explanation = err.log_and_explain();
    GatewayError::explain(StatusCode::from_u16(err.status_code()).unwrap().into(), explanation)
}

fn inject_token(res: &mut ResponseParts, target: &TokenDestination, token: &str, _expires_in: Option<Duration>) {
    match target {
        TokenDestination::Header { name } => {
            if let Ok(value) = HeaderValue::from_str(token) {
                let _ = res.insert_header(name, value);
            }
        },

        TokenDestination::Cookie { name, path } => {
            let mut cookie = Cookie::new(name.as_str(), token);
            cookie.set_path(path);
            cookie.set_secure(true);
            cookie.set_http_only(true);
            cookie.set_same_site(cookies::SameSite::Strict);

            let _ = res.append_header(header::SET_COOKIE, cookie);
        },
    }
}
