mod auth;
mod config;
pub mod crypto;
mod error;
mod serialization;

use jsonwebtoken::{AlgorithmFamily, DecodingKey, decode_header};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

use cache::MemoryCache;
use flatkit::str::ImmerStr;

pub use auth::oauth::{GrantType, KEY_REFETCH_COOLDOWN, OAuthClient};
pub use auth::validator::JwtValidator;
pub use auth::{
    CnfClaim, DPoPRequestContext, OidcConfiguration, RawToken, Refreshed, TokenRequest, TokenResponse, TokenType, claims::Claims,
    generate_dpop_nonce,
};
pub use config::{AuthConfig, AuthMode, DpopPolicy, JwtValidatorConfig, OAuthClientConfig};
pub use error::{DpopError, Error, Result};

use crate::auth::validator::DpopValidator;

/// How long the outcome of a token refresh is shared with later requests
/// presenting the same refresh token. This also absorbs bursts of parallel
/// requests that would otherwise replay a rotated refresh token.
const REFRESH_SHARE_TTL: Duration = Duration::from_secs(5);

/// Maximum number of refresh requests in flight to identity providers.
const MAX_CONCURRENT_REFRESHES: usize = 32;

/// Maximum number of refresh outcomes kept for sharing.
const REFRESH_CACHE_CAPACITY: usize = 4096;

type RefreshKey = [u8; 32];

pub struct AuthService {
    oauth_client: Arc<OAuthClient>,
    jwt_validator: JwtValidator,
    dpop_validator: DpopValidator,
    refreshes: MemoryCache<RefreshKey, Arc<TokenResponse<'static>>>,
    refresh_permits: Arc<Semaphore>,
}

impl AuthService {
    pub fn new(oauth_client: OAuthClient, jwt_validator: JwtValidator) -> Self {
        Self {
            oauth_client: Arc::new(oauth_client),
            jwt_validator,
            dpop_validator: DpopValidator::new(),
            refreshes: MemoryCache::new(REFRESH_CACHE_CAPACITY).with_negative_ttl(REFRESH_SHARE_TTL),
            refresh_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REFRESHES)),
        }
    }

    pub async fn authenticate(
        &self,
        config: &AuthConfig,
        raw_token: RawToken<'_>,
        dpop: DPoPRequestContext<'_>,
    ) -> Result<Claims> {
        match config.dpop_policy {
            DpopPolicy::Auto => {
                if raw_token.ttype == TokenType::DPoP && dpop.dpop_proof.is_none() {
                    return Err(Error::Dpop(DpopError::ProofRequired));
                }
            },
            DpopPolicy::Required => {
                if raw_token.ttype != TokenType::DPoP {
                    return Err(Error::Dpop(DpopError::Required));
                }

                if dpop.dpop_proof.is_none() {
                    return Err(Error::Dpop(DpopError::ProofRequired));
                }
            },
            DpopPolicy::Disabled => {
                if raw_token.ttype == TokenType::DPoP {
                    return Err(Error::Dpop(DpopError::Disabled));
                }
            },
        }

        let claims = self.validate_token(config, raw_token.token, &config.validator).await?;

        match raw_token.ttype {
            TokenType::DPoP => {
                let proof = dpop.dpop_proof.ok_or(Error::Dpop(DpopError::ProofRequired))?;
                let cnf = claims.cnf.as_ref().ok_or(Error::Dpop(DpopError::BindingMissing))?;

                self.dpop_validator.validate(proof, raw_token.token, cnf, dpop)?;
            },
            // RFC 9449 §7.1: a DPoP-bound token must not be accepted as a bearer token.
            TokenType::Bearer if claims.cnf.is_some() => {
                return Err(Error::Dpop(DpopError::BoundTokenAsBearer));
            },
            TokenType::Bearer => {},
        }

        Ok(claims)
    }

    /// Verifies the signature and claims of `token` against the key source of
    /// `config` and the claim rules of `validator`.
    async fn validate_token(&self, config: &AuthConfig, token: &str, validator: &JwtValidatorConfig) -> Result<Claims> {
        let header = decode_header(token)?;
        let key = self.resolve_key(config, header.alg, header.kid.as_deref()).await?;

        Ok(self.jwt_validator.validate(token, &key, header.alg, validator)?)
    }

    /// Resolves the key for a token signed with `alg`, enforcing the
    /// algorithm allowlist of the configured key source:
    ///
    /// - static: exactly the configured algorithm;
    /// - JWKS: the configured algorithms, restricted to those of the JWK;
    /// - OIDC: asymmetric algorithms of the JWK only. The discovery
    ///   document's `issuer` must be one of the configured issuers.
    async fn resolve_key(
        &self,
        config: &AuthConfig,
        alg: jsonwebtoken::Algorithm,
        kid: Option<&str>,
    ) -> Result<Arc<DecodingKey>> {
        let missing_kid = || {
            Error::InvalidToken(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))
        };

        match &config.auth_mode {
            AuthMode::Static { algorithm, key } => {
                if alg != **algorithm {
                    return Err(Error::UnsupportedAlgorithm(alg));
                }

                Ok(Arc::clone(key))
            },
            AuthMode::Jwks { expected_algorithms, uri } => {
                if !expected_algorithms.iter().any(|algorithm| **algorithm == alg) {
                    return Err(Error::UnsupportedAlgorithm(alg));
                }

                let kid = kid.ok_or_else(missing_kid)?;
                let key = self.oauth_client.get_verification_key(uri, kid, config.key_cache_ttl).await?;
                if !key.allows(alg) {
                    return Err(Error::UnsupportedAlgorithm(alg));
                }

                Ok(Arc::clone(&key.key))
            },
            AuthMode::Oidc { discovery_url } => {
                if matches!(alg.family(), AlgorithmFamily::Hmac) {
                    return Err(Error::UnsupportedAlgorithm(alg));
                }

                let kid = kid.ok_or_else(missing_kid)?;
                let discovery = self.oauth_client.discover(discovery_url, config.key_cache_ttl).await?;

                let issuers = config.validator.issuers();
                if !issuers.is_empty() && !config.validator.is_valid_issuer(&discovery.issuer) {
                    return Err(Error::InvalidDiscovery(format!(
                        "issuer '{}' does not match the configured issuer",
                        discovery.issuer
                    )));
                }

                let key = self.oauth_client.get_verification_key(&discovery.jwks_uri, kid, config.key_cache_ttl).await?;
                if !key.allows(alg) {
                    return Err(Error::UnsupportedAlgorithm(alg));
                }

                Ok(Arc::clone(&key.key))
            },
        }
    }

    fn refresh_key(client_id: &str, refresh_token: &str) -> RefreshKey {
        Sha256::new()
            .chain_update(client_id)
            .chain_update([0])
            .chain_update(refresh_token)
            .finalize()
            .into()
    }

    /// Exchanges `refresh_token` for new tokens and validates the result.
    ///
    /// Concurrent refreshes with the same refresh token send a single request
    /// to the identity provider and share its outcome, which stays shared
    /// for a few seconds. At most a fixed number of refreshes are in flight
    /// at once; beyond that, [`Error::RefreshBusy`] is returned.
    ///
    /// The new access token is validated like any presented token
    /// (signature, `iss`, `aud`). If it is opaque (not a JWT), the claims are
    /// taken from the `id_token` of the response instead, validated with the
    /// client ID as audience; without a valid `id_token` the refresh fails.
    pub async fn refresh_session(
        &self,
        config: &AuthConfig,
        refresh_token: &str,
        dpop_proof: Option<&str>,
    ) -> Result<Refreshed<'static, Claims>> {
        let oauth_config = config.oauth_client.as_ref().ok_or(Error::ClientNotConfigured)?;

        if !oauth_config.refresh_flow_enabled {
            return Err(Error::RefreshFlowDisabled);
        }

        let key = Self::refresh_key(&oauth_config.client_id, refresh_token);
        let response = match self.refreshes.get_value(&key) {
            Some(response) => response,
            None => {
                let oauth_client = Arc::clone(&self.oauth_client);
                let permits = Arc::clone(&self.refresh_permits);
                let config = config.clone();
                let refresh_token = refresh_token.to_owned();
                let dpop_proof = dpop_proof.map(str::to_owned);

                self.refreshes
                    .get_or_fetch(key, Some(REFRESH_SHARE_TTL), move || async move {
                        let _permit = permits.try_acquire_owned().map_err(|_| Error::RefreshBusy)?;
                        let oauth_config = config.oauth_client.as_ref().ok_or(Error::ClientNotConfigured)?;

                        let token_request = TokenRequest {
                            grant_type: GrantType::RefreshToken,
                            client_id: &oauth_config.client_id,
                            client_secret: oauth_config.client_secret.as_deref(),
                            code: None,
                            refresh_token: Some(&refresh_token),
                            token_type_hint: Some("refresh_token"),
                            code_verifier: None,
                        };

                        let response = oauth_client.request_token(&config, token_request, dpop_proof.as_deref()).await?;

                        Ok::<_, Error>(Arc::new(response))
                    })
                    .await
                    .map_err(Error::Shared)?
            },
        };

        let claims = self.validate_refreshed(config, &oauth_config.client_id, &response).await?;

        Ok(Refreshed { claims, response: TokenResponse::clone(&response) })
    }

    async fn validate_refreshed(&self, config: &AuthConfig, client_id: &str, response: &TokenResponse<'_>) -> Result<Claims> {
        let access_token = response.access_token.as_ref();
        if decode_header(access_token).is_ok() {
            return self.validate_token(config, access_token, &config.validator).await;
        }

        let id_token = response.id_token.as_deref().ok_or_else(|| {
            Error::InvalidToken(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))
        })?;

        let id_token_validator = config.validator.clone().with_audiences(vec![ImmerStr::from(client_id)]);
        self.validate_token(config, id_token, &id_token_validator).await
    }
}
