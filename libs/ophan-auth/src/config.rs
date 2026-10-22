use std::{str::FromStr, sync::Arc, time::Duration};

use flatkit::str::ImmerStr;
use jsonwebtoken::{AlgorithmFamily, Validation};

use crate::{
    crypto::{Algorithm, HmacAlg},
    error::InvalidDpopPolicyError,
};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum DpopPolicy {
    /// Accept Bearer and DPoP authorization schemes.
    ///
    /// A DPoP proof is required when the authorization scheme is DPoP.
    /// Bearer authentication remains valid without a DPoP proof.
    #[default]
    Auto,

    /// Require DPoP authentication.
    ///
    /// Bearer authorization is rejected and a valid DPoP proof is required.
    Required,

    /// Disable DPoP authentication.
    ///
    /// DPoP authorization is rejected and only non-DPoP authentication
    /// schemes are accepted.
    Disabled,
}

impl DpopPolicy {
    pub const fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }

    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl FromStr for DpopPolicy {
    type Err = InvalidDpopPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "auto" | "optional" => Ok(DpopPolicy::Auto),
            "required" | "strict" => Ok(DpopPolicy::Required),
            "disabled" => Ok(DpopPolicy::Disabled),
            _ => Err(InvalidDpopPolicyError(value.to_string())),
        }
    }
}

impl<'a> TryFrom<&'a str> for DpopPolicy {
    type Error = InvalidDpopPolicyError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for DpopPolicy {
    type Error = InvalidDpopPolicyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DpopPolicy::try_from(value.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Pre-configured key (HMAC or asymmetric).
    /// No external HTTP calls. The algorithm is fixed to prevent
    /// algorithm confusion attacks.
    Static { key: Arc<jsonwebtoken::DecodingKey>, algorithm: HmacAlg },
    /// Direct JWKS endpoint per OAuth2.0 spec.
    /// Only `expected_algorithms` are accepted during validation.
    Jwks { uri: String, expected_algorithms: Box<[Algorithm]> },
    /// Full OIDC Discovery
    Oidc { discovery_url: String },
}

impl AuthMode {
    pub fn new_static(secret: &[u8], algorithm: HmacAlg) -> Self {
        AuthMode::Static {
            key: Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)),
            algorithm,
        }
    }

    pub fn new_jwks(uri: String, expected_algorithms: Box<[Algorithm]>) -> Self {
        AuthMode::Jwks { uri, expected_algorithms }
    }

    pub fn new_oidc(discovery_url: String) -> Self {
        AuthMode::Oidc { discovery_url }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub validator: JwtValidatorConfig,
    pub oauth_client: Option<OAuthClientConfig>,
    pub auth_mode: AuthMode,
    pub dpop_policy: DpopPolicy,
    /// How long fetched signing keys and OIDC discovery documents are
    /// cached. Overrides the provider's `Cache-Control` when set; always
    /// clamped to a sane range.
    pub key_cache_ttl: Option<Duration>,
}

impl AuthConfig {
    pub fn new(validator: JwtValidatorConfig, auth_mode: AuthMode) -> Self {
        Self {
            validator,
            oauth_client: None,
            auth_mode,
            dpop_policy: DpopPolicy::default(),
            key_cache_ttl: None,
        }
    }

    pub fn with_key_cache_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.key_cache_ttl = ttl;
        self
    }

    pub fn with_oauth_client(mut self, oauth_client: OAuthClientConfig) -> Self {
        self.oauth_client = Some(oauth_client);
        self
    }

    pub fn with_dpop_policy(mut self, dpop_policy: DpopPolicy) -> Self {
        self.dpop_policy = dpop_policy;
        self
    }

    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            validator: JwtValidatorConfig::new("https://example.com"),
            oauth_client: Some(OAuthClientConfig {
                client_id: "mock-client-id".to_string(),
                client_secret: Some("mock-client-secret".to_string()),
                token_endpoint: Some("https://example.com".to_string()),
                refresh_flow_enabled: true,
            }),
            auth_mode: AuthMode::Oidc { discovery_url: "https://example.com".to_string() },
            dpop_policy: DpopPolicy::default(),
            key_cache_ttl: None,
        }
    }
}

/// Default clock skew leeway applied to `exp` and `nbf`.
const DEFAULT_LEEWAY_SECS: u64 = 60;

/// Default maximum distance of `iat` into the future.
const DEFAULT_MAX_IAT_FUTURE_SKEW_SECS: u64 = 300;

/// Claim validation rules for access tokens.
///
/// The `jsonwebtoken` validation rules are compiled once on construction
/// and on every change, so validating a token never rebuilds them.
///
/// `exp` is always required. `iss` and `aud` are required, and must match
/// one of the configured values, whenever at least one is configured; a
/// token carrying `aud` is rejected when no audience is configured.
#[derive(Debug, Clone)]
pub struct JwtValidatorConfig {
    issuer: Box<[ImmerStr]>,
    audience: Box<[ImmerStr]>,
    leeway_seconds: u64,
    validate_nbf: bool,
    max_iat_future_skew_secs: Option<u64>,
    compiled: Arc<CompiledValidation>,
}

/// One [`Validation`] per algorithm family, since `jsonwebtoken` requires
/// every allowed algorithm of a validation to share the key's family. The
/// exact algorithm allowlist is enforced before decoding.
#[derive(Debug)]
struct CompiledValidation {
    hmac: Validation,
    rsa: Validation,
    ec: Validation,
    ed: Validation,
}

impl CompiledValidation {
    fn new(issuer: &[ImmerStr], audience: &[ImmerStr], leeway_seconds: u64, validate_nbf: bool) -> Self {
        let issuers = issuer.iter().map(ImmerStr::as_str).collect::<Vec<_>>();
        let audiences = audience.iter().map(ImmerStr::as_str).collect::<Vec<_>>();

        let mut required = vec!["exp"];
        if !issuers.is_empty() {
            required.push("iss");
        }
        if !audiences.is_empty() {
            required.push("aud");
        }

        let for_family = |family: AlgorithmFamily| {
            let mut validation = Validation::new_for_family(family);
            validation.leeway = leeway_seconds;
            validation.validate_exp = true;
            validation.validate_nbf = validate_nbf;
            validation.validate_aud = true;
            validation.set_required_spec_claims(&required);
            if !issuers.is_empty() {
                validation.set_issuer(&issuers);
            }
            if !audiences.is_empty() {
                validation.set_audience(&audiences);
            }
            validation
        };

        Self {
            hmac: for_family(AlgorithmFamily::Hmac),
            rsa: for_family(AlgorithmFamily::Rsa),
            ec: for_family(AlgorithmFamily::Ec),
            ed: for_family(AlgorithmFamily::Ed),
        }
    }
}

impl JwtValidatorConfig {
    pub fn new(issuer: impl Into<ImmerStr>) -> Self {
        Self::build(
            Box::new([issuer.into()]),
            Box::new([]),
            DEFAULT_LEEWAY_SECS,
            true,
            Some(DEFAULT_MAX_IAT_FUTURE_SKEW_SECS),
        )
    }

    fn build(
        issuer: Box<[ImmerStr]>,
        audience: Box<[ImmerStr]>,
        leeway_seconds: u64,
        validate_nbf: bool,
        max_iat_future_skew_secs: Option<u64>,
    ) -> Self {
        let compiled = Arc::new(CompiledValidation::new(&issuer, &audience, leeway_seconds, validate_nbf));
        Self {
            issuer,
            audience,
            leeway_seconds,
            validate_nbf,
            max_iat_future_skew_secs,
            compiled,
        }
    }

    fn compile(&mut self) {
        self.compiled = Arc::new(CompiledValidation::new(
            &self.issuer,
            &self.audience,
            self.leeway_seconds,
            self.validate_nbf,
        ));
    }

    /// Sets the allowed token issuers.
    /// Accepts any type that can be converted into `Box<[ImmerStr]>`.
    pub fn with_issuers<I>(mut self, issuers: I) -> Self
    where
        I: Into<Box<[ImmerStr]>>,
    {
        self.set_issuers(issuers);
        self
    }

    /// Sets the allowed token audiences.
    /// Accepts any type that can be converted into `Box<[ImmerStr]>`.
    pub fn with_audiences<A>(mut self, audiences: A) -> Self
    where
        A: Into<Box<[ImmerStr]>>,
    {
        self.set_audiences(audiences);
        self
    }

    /// Replaces the allowed token issuers.
    pub fn set_issuers<I>(&mut self, issuers: I)
    where
        I: Into<Box<[ImmerStr]>>,
    {
        self.issuer = issuers.into();
        self.compile();
    }

    /// Replaces the allowed token audiences.
    pub fn set_audiences<A>(&mut self, audiences: A)
    where
        A: Into<Box<[ImmerStr]>>,
    {
        self.audience = audiences.into();
        self.compile();
    }

    /// Configures the clock skew leeway in seconds applied to `exp` and `nbf`.
    pub fn with_leeway(mut self, leeway_seconds: u64) -> Self {
        self.leeway_seconds = leeway_seconds;
        self.compile();
        self
    }

    /// Enables or disables `nbf` validation (enabled by default).
    pub fn with_nbf_validation(mut self, enabled: bool) -> Self {
        self.validate_nbf = enabled;
        self.compile();
        self
    }

    /// Rejects tokens whose `iat` lies more than `max_skew_secs` seconds in
    /// the future (default: 300). `None` disables the check.
    pub fn with_max_iat_future_skew(mut self, max_skew_secs: Option<u64>) -> Self {
        self.max_iat_future_skew_secs = max_skew_secs;
        self
    }

    /// The allowed token issuers.
    pub fn issuers(&self) -> &[ImmerStr] {
        &self.issuer
    }

    /// The allowed token audiences.
    pub fn audiences(&self) -> &[ImmerStr] {
        &self.audience
    }

    /// The clock skew leeway in seconds.
    pub const fn leeway_seconds(&self) -> u64 {
        self.leeway_seconds
    }

    /// The maximum distance of `iat` into the future, if checked.
    pub const fn max_iat_future_skew_secs(&self) -> Option<u64> {
        self.max_iat_future_skew_secs
    }

    /// The compiled validation rules for tokens signed with `algorithm`.
    pub(crate) fn validation(&self, algorithm: jsonwebtoken::Algorithm) -> &Validation {
        match algorithm.family() {
            AlgorithmFamily::Hmac => &self.compiled.hmac,
            AlgorithmFamily::Rsa => &self.compiled.rsa,
            AlgorithmFamily::Ec => &self.compiled.ec,
            AlgorithmFamily::Ed => &self.compiled.ed,
        }
    }

    /// Checks whether the provided issuer is allowed by this configuration.
    pub fn is_valid_issuer(&self, iss: &str) -> bool {
        self.issuer.iter().any(|allowed| allowed.as_ref() == iss)
    }

    /// Checks whether the provided audience is allowed by this configuration.
    pub fn is_valid_audience(&self, aud: &str) -> bool {
        self.audience.iter().any(|allowed| allowed.as_ref() == aud)
    }
}

#[derive(Debug, Clone)]
pub struct OAuthClientConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint: Option<String>,
    pub refresh_flow_enabled: bool,
}

impl OAuthClientConfig {
    /// Creates a basic configuration with the mandatory client ID.
    /// Accepts any type implementing `Into<String>` (e.g., `&str` or `String`).
    /// Disables the refresh flow and leaves optional fields as `None` by default.
    pub fn new<S: Into<String>>(client_id: S) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            token_endpoint: None,
            refresh_flow_enabled: false,
        }
    }

    /// Sets the client secret credentials.
    pub fn with_secret<S: Into<String>>(mut self, secret: S) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Sets the remote token endpoint URL.
    pub fn with_token_endpoint<S: Into<String>>(mut self, endpoint: S) -> Self {
        self.token_endpoint = Some(endpoint.into());
        self
    }

    /// Explicitly activates the OAuth2 refresh token lifecycle flow.
    pub const fn enable_refresh_flow(mut self) -> Self {
        self.refresh_flow_enabled = true;
        self
    }

    /// Checks if the client acts as a public client (no secret configured).
    pub const fn is_public_client(&self) -> bool {
        self.client_secret.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_policy_parsing() {
        assert_eq!(DpopPolicy::try_from("auto"), Ok(DpopPolicy::Auto));
        assert_eq!(DpopPolicy::try_from("optional"), Ok(DpopPolicy::Auto));
        assert_eq!(DpopPolicy::try_from("required"), Ok(DpopPolicy::Required));
        assert_eq!(DpopPolicy::try_from("strict"), Ok(DpopPolicy::Required));
        assert_eq!(DpopPolicy::try_from("disabled"), Ok(DpopPolicy::Disabled));
    }

    #[test]
    fn test_invalid_policy_parsing() {
        let err = DpopPolicy::try_from("unknow");
        assert!(err.is_err());
    }

    #[test]
    fn test_policy_is_required() {
        assert!(!DpopPolicy::Auto.is_required());
        assert!(DpopPolicy::Required.is_required());
        assert!(!DpopPolicy::Disabled.is_required());
    }

    #[test]
    fn test_policy_is_disabled() {
        assert!(!DpopPolicy::Auto.is_disabled());
        assert!(!DpopPolicy::Required.is_disabled());
        assert!(DpopPolicy::Disabled.is_disabled());
    }

    #[test]
    fn test_policy_default() {
        assert_eq!(DpopPolicy::default(), DpopPolicy::Auto);
    }

    #[test]
    fn test_auth_config_builder() {
        let validator = JwtValidatorConfig::new("https://issuer.example.com");
        let mode = AuthMode::new_static(b"secret", HmacAlg::HS256);

        let config = AuthConfig::new(validator, mode).with_dpop_policy(DpopPolicy::Required);

        assert_eq!(config.dpop_policy, DpopPolicy::Required);
        assert!(config.oauth_client.is_none());
    }

    #[test]
    fn test_auth_config_with_oauth_client() {
        let validator = JwtValidatorConfig::new("https://issuer.example.com");
        let mode = AuthMode::new_static(b"secret", HmacAlg::HS256);
        let oauth = OAuthClientConfig::new("client-id")
            .with_secret("client-secret")
            .with_token_endpoint("https://token.example.com")
            .enable_refresh_flow();

        let config = AuthConfig::new(validator, mode).with_oauth_client(oauth);

        let client = config.oauth_client.unwrap();
        assert_eq!(client.client_id, "client-id");
        assert_eq!(client.client_secret.as_deref(), Some("client-secret"));
        assert!(client.refresh_flow_enabled);
    }

    #[test]
    fn test_jwt_validator_config_builder() {
        let config = JwtValidatorConfig::new("https://issuer.example.com")
            .with_audiences(vec![ImmerStr::from("https://aud.example.com")])
            .with_leeway(30);

        assert!(config.is_valid_issuer("https://issuer.example.com"));
        assert!(!config.is_valid_issuer("https://other.com"));
        assert!(config.is_valid_audience("https://aud.example.com"));
        assert!(!config.is_valid_audience("https://other.com"));
        assert_eq!(config.leeway_seconds(), 30);
    }

    #[test]
    fn test_jwt_validator_config_multiple_issuers() {
        let config = JwtValidatorConfig::new("https://issuer1.com").with_issuers(vec![
            ImmerStr::from("https://issuer1.com"),
            ImmerStr::from("https://issuer2.com"),
        ]);

        assert!(config.is_valid_issuer("https://issuer1.com"));
        assert!(config.is_valid_issuer("https://issuer2.com"));
        assert!(!config.is_valid_issuer("https://issuer3.com"));
    }

    #[test]
    fn test_oauth_client_config_builder() {
        let config = OAuthClientConfig::new("my-client")
            .with_secret("my-secret")
            .with_token_endpoint("https://token.example.com")
            .enable_refresh_flow();

        assert_eq!(config.client_id, "my-client");
        assert_eq!(config.client_secret.as_deref(), Some("my-secret"));
        assert_eq!(config.token_endpoint.as_deref(), Some("https://token.example.com"));
        assert!(config.refresh_flow_enabled);
        assert!(!config.is_public_client());
    }

    #[test]
    fn test_oauth_client_public() {
        let config = OAuthClientConfig::new("public-client");
        assert!(config.is_public_client());
        assert!(!config.refresh_flow_enabled);
    }

    #[test]
    fn test_config_mock() {
        let config = AuthConfig::mock();
        assert!(config.oauth_client.is_some());
        assert_eq!(config.dpop_policy, DpopPolicy::default());
    }
}
