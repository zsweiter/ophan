mod context;

use std::time::Duration;

use flatkit::matchers::PathMatcherSet;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header, header::InvalidHeaderName};
use ophan_auth::{
    AuthConfig as InnerAuthConfig, AuthService, Claims, DPoPRequestContext, DpopPolicy, JwtValidator, OAuthClient, RawToken,
    TokenType,
};
use ophan_net::{
    http::{
        client,
        cookies::{self, Cookie},
    },
    proxy::{RequestParts, ResponseParts},
};

use crate::{
    gateway::{ErrorKind, GatewayError, OphanCtx},
    middlewares::FilterAction,
};

pub use context::{AuthContext, RefreshedTokens};

/// RFC 9449 §4.1: header carrying the DPoP proof.
const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");

/// Total timeout for requests to identity providers.
const IDP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Connection timeout for requests to identity providers.
const IDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Defines where a token should be extracted from.
///
/// For header sources, `prefix` is an authentication scheme (RFC 7235):
/// it is matched case-insensitively and any amount of whitespace may
/// separate it from the credentials.
#[derive(Debug, Clone)]
pub enum TokenSource {
    Header { name: HeaderName, prefix: Option<String> },
    Cookie { name: String, prefix: Option<String> },
    QueryParam { name: String, prefix: Option<String> },
}

impl TokenSource {
    /// Standard Authorization: Bearer <token>.
    pub fn bearer() -> Self {
        Self::Header { name: header::AUTHORIZATION, prefix: Some("Bearer ".into()) }
    }

    /// DPoP proof header.
    pub fn dpop() -> Self {
        Self::Header { name: DPOP_HEADER, prefix: None }
    }

    /// Default refresh token cookie.
    pub fn refresh() -> Self {
        Self::Cookie { name: "refresh_token".into(), prefix: None }
    }

    /// Header source for a configured header name.
    pub fn header(name: &str, prefix: Option<&str>) -> Result<Self, InvalidHeaderName> {
        Ok(Self::Header {
            name: HeaderName::from_bytes(name.as_bytes())?,
            prefix: prefix.map(str::to_owned),
        })
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

    /// DPoP proof source. When `None`, the `DPoP` header is used unless the
    /// DPoP policy is disabled.
    pub dpop_source: Option<TokenSource>,

    /// Where to inject a refreshed access token.
    pub inject_access_token_into: Box<[TokenDestination]>,

    /// Where to inject a refreshed refresh token.
    pub inject_refresh_token_into: Box<[TokenDestination]>,

    /// Optional access token cookie lifetime override.
    pub token_ttl: Option<Duration>,

    /// Refresh token cookie lifetime used when the provider does not report
    /// `refresh_expires_in`. When `None`, a session cookie is issued.
    pub refresh_token_ttl: Option<Duration>,

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
        let http_client = client::Client::builder()
            .tls()
            .timeout(IDP_REQUEST_TIMEOUT)
            .connect_timeout(IDP_CONNECT_TIMEOUT)
            .build();

        Self {
            auth_service: AuthService::new(OAuthClient::new(http_client), JwtValidator::new()),
        }
    }

    /// Authenticates `request`, assuming the client used the scheme of the
    /// request URI, or `https` when the URI carries none.
    ///
    /// Prefer [`Self::on_request_with_scheme`] when the scheme is known.
    pub async fn on_request(&self, request: &RequestParts, config: &AuthConfig, ctx: &mut OphanCtx) -> FilterAction {
        let scheme = request.uri.scheme_str().unwrap_or("https");
        self.on_request_with_scheme(request, scheme, config, ctx).await
    }

    /// Authenticates `request`. `scheme` is the scheme the client used to
    /// reach the gateway (e.g. `https` for TLS connections), which DPoP
    /// proofs are bound to.
    pub async fn on_request_with_scheme(
        &self,
        request: &RequestParts,
        scheme: &str,
        config: &AuthConfig,
        ctx: &mut OphanCtx,
    ) -> FilterAction {
        if let Some(skip_pattern) = config.skip_patterns.as_ref()
            && skip_pattern.is_match(request.uri.path().as_bytes())
        {
            return FilterAction::Continue;
        }

        match self.authenticate_request(request, scheme, config).await {
            Ok(auth) => {
                ctx.policies.auth = Some(AuthContext::new(auth.claims, auth.refresh));

                FilterAction::Continue
            },

            Err(err) => {
                ctx.policies.auth = None;

                FilterAction::Reject(err.kind.into())
            },
        }
    }

    pub fn prepare_response(&self, res: &mut ResponseParts, config: &AuthConfig, auth: &AuthContext) {
        let Some(ref refreshed) = auth.refresh else {
            return;
        };

        let access_token_ttl = config.token_ttl.or(refreshed.expires_in);
        for target in config.inject_access_token_into.iter() {
            inject_token(res, target, &refreshed.access_token, access_token_ttl);
        }

        if let Some(refresh_token) = refreshed.refresh_token.as_deref() {
            let refresh_token_ttl = refreshed.refresh_expires_in.or(config.refresh_token_ttl);
            for target in config.inject_refresh_token_into.iter() {
                inject_token(res, target, refresh_token, refresh_token_ttl);
            }
        }
    }

    async fn authenticate_request(
        &self,
        request: &RequestParts,
        scheme: &str,
        config: &AuthConfig,
    ) -> Result<Authentication, GatewayError> {
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
            scheme,
            authority: Self::request_authority(request),
            path: request.uri.path(),
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
        let refreshed = refreshed.map_err(|err| match err.resolve() {
            ophan_auth::Error::Transport(_) | ophan_auth::Error::ProviderStatus(_) => GatewayError::from(StatusCode::BAD_GATEWAY),
            ophan_auth::Error::Serialization(_) | ophan_auth::Error::InvalidDiscovery(_) => {
                GatewayError::explain(ErrorKind::BadGateway, "invalid response from identity provider")
            },
            ophan_auth::Error::RefreshBusy => {
                GatewayError::explain(ErrorKind::ServiceUnavailable, "token refresh temporarily unavailable")
            },
            _ => GatewayError::from(StatusCode::UNAUTHORIZED),
        })?;

        let lifetime = |seconds: u64| (seconds > 0).then(|| Duration::from_secs(seconds));

        Ok(Authentication {
            claims: refreshed.claims,
            refresh: Some(RefreshedTokens {
                access_token: refreshed.response.access_token.into_owned(),
                refresh_token: refreshed.response.refresh_token.map(|a| a.into_owned()),
                expires_in: lifetime(refreshed.response.expires_in),
                refresh_expires_in: refreshed.response.refresh_expires_in.and_then(lifetime),
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

        let dpop_proof = match &config.dpop_source {
            Some(source) => Self::match_source(headers, uri, std::slice::from_ref(source)),
            None if config.client.dpop_policy == DpopPolicy::Disabled => None,
            None => Self::single_header_value(headers, &DPOP_HEADER),
        };

        RequestTokens { access_token, access_token_type, refresh_token, dpop_proof }
    }

    fn match_source<'a>(headers: &'a HeaderMap, uri: &'a Uri, sources: &[TokenSource]) -> Option<&'a str> {
        Self::match_source_with_type(headers, uri, sources).0
    }

    /// Match a token source and also detect the token type from the Authorization header scheme.
    /// RFC 6750 §2.1: "Bearer" / RFC 9449 §4.1: "DPoP"
    fn match_source_with_type<'a>(headers: &'a HeaderMap, uri: &'a Uri, sources: &[TokenSource]) -> (Option<&'a str>, TokenType) {
        for source in sources {
            let (token, token_type) = match source {
                TokenSource::Header { name, prefix } => match headers.get(name).and_then(|v| v.to_str().ok()) {
                    Some(value) => Self::match_header_value(name, value, prefix.as_deref()),
                    None => (None, TokenType::Bearer),
                },

                TokenSource::QueryParam { name, prefix } => {
                    let tok = uri.query().and_then(|query| {
                        query.split('&').find_map(|pair| {
                            let (k, v) = pair.split_once('=')?;
                            (k == name).then(|| strip_prefix(v, prefix.as_deref())).flatten()
                        })
                    });
                    (tok, TokenType::Bearer)
                },

                TokenSource::Cookie { name, prefix } => (
                    Self::find_cookie(headers, name).and_then(|v| strip_prefix(v, prefix.as_deref())),
                    TokenType::Bearer,
                ),
            };

            if let Some(token) = token.filter(|token| !token.is_empty()) {
                return (Some(token), token_type);
            }
        }

        (None, TokenType::Bearer)
    }
}

/// Tokens extracted from the incoming request.
pub struct RequestTokens<'a> {
    pub access_token: Option<&'a str>,
    pub access_token_type: TokenType,
    pub refresh_token: Option<&'a str>,
    pub dpop_proof: Option<&'a str>,
}

impl AuthMiddleware {
    #[inline]
    fn is_auth_whitespace(c: char) -> bool {
        c == ' ' || c == '\t'
    }

    /// Splits an `Authorization`-style value into scheme and credentials.
    fn split_auth_scheme(value: &str) -> Option<(&str, &str)> {
        let (scheme, credentials) = value.trim_matches(Self::is_auth_whitespace).split_once(Self::is_auth_whitespace)?;
        let credentials = credentials.trim_matches(Self::is_auth_whitespace);

        (!credentials.is_empty()).then_some((scheme, credentials))
    }

    #[inline]
    fn token_type_for_scheme(scheme: &str) -> TokenType {
        if scheme.eq_ignore_ascii_case("DPoP") {
            TokenType::DPoP
        } else {
            TokenType::Bearer
        }
    }

    fn match_header_value<'a>(name: &HeaderName, value: &'a str, prefix: Option<&str>) -> (Option<&'a str>, TokenType) {
        match prefix.map(|p| p.trim_matches(Self::is_auth_whitespace)).filter(|p| !p.is_empty()) {
            Some(expected) => match Self::split_auth_scheme(value) {
                Some((scheme, credentials)) if scheme.eq_ignore_ascii_case(expected) => {
                    (Some(credentials), Self::token_type_for_scheme(expected))
                },
                _ => (None, TokenType::Bearer),
            },

            None if name == header::AUTHORIZATION => match Self::split_auth_scheme(value) {
                Some((scheme, credentials)) if scheme.eq_ignore_ascii_case("DPoP") => (Some(credentials), TokenType::DPoP),
                Some((scheme, credentials)) if scheme.eq_ignore_ascii_case("Bearer") => (Some(credentials), TokenType::Bearer),
                Some(_) => (None, TokenType::Bearer),
                None => (Some(value.trim_matches(Self::is_auth_whitespace)), TokenType::Bearer),
            },

            None => (Some(value.trim_matches(Self::is_auth_whitespace)), TokenType::Bearer),
        }
    }

    /// Finds cookie `name` across all `Cookie` header fields (HTTP/2 may send
    /// one field per cookie), removing optional surrounding double quotes.
    fn find_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key.trim() == name).then(|| Self::unquote(value.trim()))
            })
    }

    #[inline]
    fn unquote(value: &str) -> &str {
        value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value)
    }

    /// Returns the value of `name` when the header is present exactly once.
    fn single_header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        value.to_str().ok()
    }

    /// The authority the client addressed: `:authority` for HTTP/2, else `Host`.
    fn request_authority(request: &RequestParts) -> &str {
        request
            .uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| request.headers.get(header::HOST).and_then(|v| v.to_str().ok()))
            .unwrap_or_default()
    }
}

#[inline]
fn strip_prefix<'a>(value: &'a str, prefix: Option<&str>) -> Option<&'a str> {
    match prefix {
        Some(prefix) => value.strip_prefix(prefix),
        None => Some(value),
    }
}

/// Convert an authentication error into a GatewayError with appropriate status code
/// and explanation message. Used to deduplicate error handling in authenticate_request.
#[inline]
fn auth_error_to_gateway(err: ophan_auth::Error) -> GatewayError {
    let explanation: &'static str = err.log_and_explain();
    GatewayError::explain(StatusCode::from_u16(err.status_code()).unwrap().into(), explanation)
}

fn inject_token(res: &mut ResponseParts, target: &TokenDestination, token: &str, expires_in: Option<Duration>) {
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

            if let Some(ttl) = expires_in {
                cookie.set_max_age(ttl);
            }

            if let Ok(value) = cookie.to_header_value() {
                let _ = res.append_header(header::SET_COOKIE, value);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use ophan_auth::{AuthMode, JwtValidatorConfig, OAuthClientConfig, crypto::HmacAlg};

    fn uri(value: &str) -> Uri {
        value.parse().unwrap()
    }

    fn authorization(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        headers
    }

    fn auth_config() -> AuthConfig {
        let client = InnerAuthConfig::new(
            JwtValidatorConfig::new("https://issuer.example.com"),
            AuthMode::new_static(b"secret", HmacAlg::HS256),
        )
        .with_oauth_client(OAuthClientConfig::new("client").enable_refresh_flow());

        AuthConfig {
            client,
            sources: Box::new([TokenSource::bearer()]),
            refresh_sources: Some(TokenSource::refresh()),
            dpop_source: None,
            inject_access_token_into: Box::new([TokenDestination::Cookie { name: "access".into(), path: "/".into() }]),
            inject_refresh_token_into: Box::new([TokenDestination::Cookie { name: "refresh".into(), path: "/".into() }]),
            token_ttl: None,
            refresh_token_ttl: None,
            skip_patterns: None,
        }
    }

    fn claims() -> Claims {
        serde_json::from_value(serde_json::json!({ "sub": "user-1", "exp": 999, "iat": 100 })).unwrap()
    }

    fn set_cookies(response: &ResponseParts) -> Vec<String> {
        response
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn extracts_bearer_and_dpop_schemes_without_confusion() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer bearer-token"));
        let request_uri = uri("/");
        let (token, kind) = AuthMiddleware::match_source_with_type(&headers, &request_uri, &[TokenSource::bearer()]);
        assert_eq!(token, Some("bearer-token"));
        assert_eq!(kind, TokenType::Bearer);

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("DPoP dpop-token"));
        let (token, kind) = AuthMiddleware::match_source_with_type(
            &headers,
            &request_uri,
            &[TokenSource::Header { name: header::AUTHORIZATION, prefix: None }],
        );
        assert_eq!(token, Some("dpop-token"));
        assert_eq!(kind, TokenType::DPoP);
    }

    #[test]
    fn configured_bearer_source_rejects_dpop_scheme() {
        let headers = authorization("DPoP dpop-token");
        let request_uri = uri("/");
        let (token, _) = AuthMiddleware::match_source_with_type(&headers, &request_uri, &[TokenSource::bearer()]);
        assert_eq!(token, None);
    }

    #[test]
    fn authorization_scheme_is_case_insensitive_and_whitespace_tolerant() {
        let request_uri = uri("/");
        let any_scheme = [TokenSource::Header { name: header::AUTHORIZATION, prefix: None }];

        for value in ["bearer tok", "BEARER tok", "Bearer    tok", "  Bearer\ttok  "] {
            let headers = authorization(value);
            let bearer = AuthMiddleware::match_source_with_type(&headers, &request_uri, &[TokenSource::bearer()]);
            assert_eq!(bearer, (Some("tok"), TokenType::Bearer), "value: {value:?}");

            let detected = AuthMiddleware::match_source_with_type(&headers, &request_uri, &any_scheme);
            assert_eq!(detected, (Some("tok"), TokenType::Bearer), "value: {value:?}");
        }

        for value in ["dpop tok", "DPOP  tok"] {
            let headers = authorization(value);
            let detected = AuthMiddleware::match_source_with_type(&headers, &request_uri, &any_scheme);
            assert_eq!(detected, (Some("tok"), TokenType::DPoP), "value: {value:?}");
        }

        let dpop_source = [TokenSource::Header { name: header::AUTHORIZATION, prefix: Some("DPoP ".into()) }];
        let headers = authorization("dpop tok");
        let detected = AuthMiddleware::match_source_with_type(&headers, &request_uri, &dpop_source);
        assert_eq!(detected, (Some("tok"), TokenType::DPoP));

        for value in ["Bearer", "Bearer   ", "Basic dXNlcjpwYXNz"] {
            let headers = authorization(value);
            let (token, _) = AuthMiddleware::match_source_with_type(&headers, &request_uri, &[TokenSource::bearer()]);
            assert_eq!(token, None, "value: {value:?}");
        }
    }

    #[test]
    fn extracts_cookie_and_query_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("other=x; session=abc"));
        let cookie_uri = uri("/resource?unused=x");
        let cookie = AuthMiddleware::match_source_with_type(
            &headers,
            &cookie_uri,
            &[TokenSource::Cookie { name: "session".into(), prefix: None }],
        );
        assert_eq!(cookie.0, Some("abc"));

        let empty_headers = HeaderMap::new();
        let query_uri = uri("/resource?unused=x&token=xyz");
        let query = AuthMiddleware::match_source_with_type(
            &empty_headers,
            &query_uri,
            &[TokenSource::QueryParam { name: "token".into(), prefix: None }],
        );
        assert_eq!(query.0, Some("xyz"));
    }

    #[test]
    fn cookie_lookup_spans_multiple_cookie_headers_and_unquotes() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
        headers.append(header::COOKIE, HeaderValue::from_static("lang=en"));
        headers.append(header::COOKIE, HeaderValue::from_static("session=\"abc.def\"; other=1"));

        let root = uri("/");
        let source = [TokenSource::Cookie { name: "session".into(), prefix: None }];
        let (token, _) = AuthMiddleware::match_source_with_type(&headers, &root, &source);
        assert_eq!(token, Some("abc.def"));

        let missing = [TokenSource::Cookie { name: "absent".into(), prefix: None }];
        assert_eq!(AuthMiddleware::match_source_with_type(&headers, &root, &missing).0, None);
    }

    #[test]
    fn dpop_proof_defaults_to_dpop_header() {
        let root = uri("/");
        let mut config = auth_config();
        let mut headers = authorization("DPoP access");
        headers.insert(DPOP_HEADER, HeaderValue::from_static("proof"));

        let tokens = AuthMiddleware::extract_request_tokens(&headers, &root, &config);
        assert_eq!(tokens.dpop_proof, Some("proof"));

        headers.append(DPOP_HEADER, HeaderValue::from_static("second-proof"));
        let tokens = AuthMiddleware::extract_request_tokens(&headers, &root, &config);
        assert_eq!(tokens.dpop_proof, None, "multiple DPoP headers must not yield a proof");

        config.client.dpop_policy = DpopPolicy::Disabled;
        headers.insert(DPOP_HEADER, HeaderValue::from_static("proof"));
        let tokens = AuthMiddleware::extract_request_tokens(&headers, &root, &config);
        assert_eq!(tokens.dpop_proof, None);
    }

    #[test]
    fn header_source_requires_valid_name() {
        assert!(TokenSource::header("X-Api-Token", None).is_ok());
        assert!(TokenSource::header("bad header", None).is_err());
    }

    #[test]
    fn request_authority_prefers_uri_authority_over_host() {
        let mut request = RequestParts::build("GET", b"/resource", None).unwrap();
        request.insert_header(header::HOST, "api.example.com:8443").unwrap();
        assert_eq!(AuthMiddleware::request_authority(&request), "api.example.com:8443");

        request.set_uri(uri("https://h2.example.com/resource"));
        assert_eq!(AuthMiddleware::request_authority(&request), "h2.example.com");
    }

    #[test]
    fn cookie_injection_sets_security_attributes_and_ttl() {
        let mut response = ResponseParts::build(StatusCode::OK, None).unwrap();
        inject_token(
            &mut response,
            &TokenDestination::Cookie { name: "access".into(), path: "/".into() },
            "token",
            Some(Duration::from_secs(900)),
        );

        let cookie = response.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("access=token"));
        assert!(cookie.contains("Max-Age=900"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn refresh_cookie_uses_refresh_lifetime_not_access_lifetime() {
        let middleware_config = auth_config();
        let refreshed = |refresh_expires_in| RefreshedTokens {
            access_token: "new-access".into(),
            refresh_token: Some("new-refresh".into()),
            expires_in: Some(Duration::from_secs(300)),
            refresh_expires_in,
        };
        let middleware = AuthMiddleware::new();

        let mut response = ResponseParts::build(StatusCode::OK, None).unwrap();
        let context = AuthContext::new(claims(), Some(refreshed(Some(Duration::from_secs(86_400)))));
        middleware.prepare_response(&mut response, &middleware_config, &context);
        let cookies = set_cookies(&response);
        assert!(cookies.iter().any(|c| c.contains("access=new-access") && c.contains("Max-Age=300")));
        assert!(cookies.iter().any(|c| c.contains("refresh=new-refresh") && c.contains("Max-Age=86400")));

        let mut response = ResponseParts::build(StatusCode::OK, None).unwrap();
        let context = AuthContext::new(claims(), Some(refreshed(None)));
        middleware.prepare_response(&mut response, &middleware_config, &context);
        let refresh_cookie = set_cookies(&response).into_iter().find(|c| c.contains("refresh=new-refresh")).unwrap();
        assert!(
            !refresh_cookie.contains("Max-Age"),
            "refresh cookie must be a session cookie: {refresh_cookie}"
        );

        let mut configured = auth_config();
        configured.refresh_token_ttl = Some(Duration::from_secs(7 * 86_400));
        let mut response = ResponseParts::build(StatusCode::OK, None).unwrap();
        middleware.prepare_response(&mut response, &configured, &context);
        assert!(
            set_cookies(&response)
                .iter()
                .any(|c| c.contains("refresh=new-refresh") && c.contains("Max-Age=604800"))
        );
    }

    #[test]
    fn claims_header_is_encoded_once() {
        let context = AuthContext::new(claims(), None);
        let first = context.claims_header().expect("claims must encode");
        let second = context.claims_header().unwrap();

        assert!(std::ptr::eq(first, second));
        assert_eq!(first.as_bytes(), context.claims.encode_bytes().unwrap().as_slice());
    }

    #[test]
    fn custom_prefix_is_stripped() {
        assert_eq!(strip_prefix("Token abc", Some("Token ")), Some("abc"));
        assert_eq!(strip_prefix("Bearer abc", Some("Token ")), None);
        assert_eq!(strip_prefix("abc", None), Some("abc"));
    }
}
