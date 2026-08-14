//! OAuth 2.0 / OIDC client.
//!
//! Provides token exchange (`request_token`) and JWT signing-key resolution
//! (`get_validation_key`) for two supported key-discovery strategies:
//!
//! - **OIDC Discovery**: fetches `/.well-known/openid-configuration`, then the
//!   provider's JWKS endpoint referenced by it. Both the metadata and the keys
//!   are cached together under the discovery URL.
//! - **Direct JWKS**: fetches a JWKS document directly and caches the keys
//!   under the JWKS URI.
//!
//! Both strategies share a single [`MemoryCache`] keyed by URL, since a
//! [`KeyVaultCache`] entry only needs to know whether OIDC metadata is present
//! (`config: Some(..)`) or not (`config: None`).

use ahash::AHashMap;
use cache::MemoryCache;
use jsonwebtoken::{DecodingKey, jwk::JwkSet};
use ophan_net::http::{CachePolicy, Client};
use serde::Serialize;
use std::borrow::Cow;
use std::{sync::Arc, time::Duration};

use super::{OidcConfiguration, TokenRequest, TokenResponse};
use crate::config::{AuthConfig, AuthMode};
use crate::error::{Error, Result};

/// Fallback TTL applied to a cached key set when the upstream response does
/// not include a `Cache-Control: max-age` directive.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

/// Maximum number of distinct providers (discovery URLs / JWKS URIs) kept in
/// the in-memory cache at once.
const DEFAULT_CACHE_CAPACITY: usize = 5;

/// OAuth 2.0 grant type sent as part of a token request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Authorization Code grant (`authorization_code`).
    AuthorizationCode,
    /// Refresh Token grant (`refresh_token`).
    RefreshToken,
    /// Client Credentials grant (`client_credentials`).
    #[serde(rename = "client_credentials")]
    Credentials,
}

/// A cached set of JWT signing keys, optionally paired with the OIDC
/// metadata it was discovered from.
///
/// - `config: Some(..)` — populated via OIDC Discovery; both provider
///   metadata and keys are available.
/// - `config: None` — populated via direct JWKS resolution; only keys are
///   available.
struct KeyVaultCache {
    config: Option<OidcConfiguration>,
    keys: AHashMap<String, Arc<DecodingKey>>,
}

/// Strategy used to resolve a JWT signing key, identified by its `kid`.
pub enum KeyResolver<'a> {
    /// Resolve directly against a JWKS document URI.
    Jwks(&'a str),
    /// Resolve via an OIDC discovery document URL.
    Oidc(&'a str),
}

/// OAuth 2.0 / OIDC client handling token exchange and signing-key
/// resolution, with in-memory caching of discovery metadata and JWKS keys.
pub struct OAuthClient {
    http_client: Client,
    /// TTL used when an upstream response omits cache-control headers.
    cache_ttl: Duration,
    /// Cache of resolved key vaults, keyed by discovery URL or JWKS URI.
    registry: MemoryCache<String, Arc<KeyVaultCache>>,
}

impl OAuthClient {
    /// Creates a new client backed by `http_client`, using the default cache
    /// TTL and capacity.
    pub fn new(http_client: Client) -> Self {
        Self {
            http_client,
            cache_ttl: DEFAULT_CACHE_TTL,
            registry: MemoryCache::new(DEFAULT_CACHE_CAPACITY),
        }
    }

    /// Fetches and parses a JWKS document into a key map.
    ///
    /// Keys without a `kid` are skipped, since they cannot be looked up by
    /// [`KeyResolver`]. Keys that fail to parse are logged and skipped rather
    /// than failing the whole request, so a single malformed key does not
    /// take down validation for the rest of the provider's key set.
    ///
    /// Returns the parsed keys together with the TTL to cache them under,
    /// derived from the response's `Cache-Control` header (falling back to
    /// [`Self::cache_ttl`]).
    async fn fetch_and_parse_jwks(&self, jwks_uri: &str) -> Result<(AHashMap<String, Arc<DecodingKey>>, Duration)> {
        let response = self.http_client.get(jwks_uri).send().await?.error_for_status()?;
        let ttl = CachePolicy::from_headers(response.headers()).max_age.unwrap_or(self.cache_ttl);
        let jwks: JwkSet = response.json()?;

        let mut keys = AHashMap::with_capacity(jwks.keys.len());
        for jwk in jwks.keys {
            let Some(key_id) = jwk.common.key_id.clone() else {
                continue;
            };

            let decoding_key = match DecodingKey::from_jwk(&jwk) {
                Ok(key) => key,
                Err(err) => {
                    tracing::error!(err = %err, key_id = %key_id, "failed to parse JWK, skipping");
                    continue;
                },
            };

            keys.insert(key_id, Arc::new(decoding_key));
        }

        Ok((keys, ttl))
    }

    /// Wraps `config`/`keys` into a cached [`KeyVaultCache`], stores it in the
    /// registry under `cache_key` with the given `ttl`, and returns it.
    ///
    /// Centralizes the "wrap + cache" step shared by [`Self::resolve_oidc`]
    /// and [`Self::resolve_jwks`] so both paths stay in sync.
    fn cache_vault(
        &self,
        cache_key: &str,
        config: Option<OidcConfiguration>,
        keys: AHashMap<String, Arc<DecodingKey>>,
        ttl: Duration,
    ) -> Arc<KeyVaultCache> {
        let vault = Arc::new(KeyVaultCache { config, keys });
        self.registry.put(cache_key, Arc::clone(&vault), Some(ttl));
        vault
    }

    /// Resolves a full OIDC provider: fetches discovery metadata, then the
    /// JWKS keys it references. The result is cached under `discovery_url`.
    async fn resolve_oidc(&self, discovery_url: &str) -> Result<Arc<KeyVaultCache>> {
        if let Some(cached) = self.registry.get_value(discovery_url) {
            return Ok(cached);
        }

        let oidc_resp = self.http_client.get(discovery_url).send().await?.error_for_status()?;
        let ttl = CachePolicy::from_headers(oidc_resp.headers()).max_age.unwrap_or(self.cache_ttl);
        let oidc_config: OidcConfiguration = oidc_resp.json()?;

        let (keys, _jwks_ttl) = self.fetch_and_parse_jwks(&oidc_config.jwks_uri).await?;

        Ok(self.cache_vault(discovery_url, Some(oidc_config), keys, ttl))
    }

    /// Resolves a signing key directly from a JWKS URI.
    async fn resolve_jwks(&self, jwks_uri: &str, kid: &str) -> Result<Arc<DecodingKey>> {
        if let Some(cached) = self.registry.get_value(jwks_uri)
            && let Some(key) = cached.keys.get(kid)
        {
            return Ok(Arc::clone(key));
        }

        let (keys, ttl) = self.fetch_and_parse_jwks(jwks_uri).await?;
        let key = keys.get(kid).cloned().ok_or_else(|| Error::KeyNotFound(kid.to_string()))?;

        self.cache_vault(jwks_uri, None, keys, ttl);

        Ok(key)
    }

    /// Resolves the JWT signing key identified by `kid`, using the strategy
    /// described by `resolver`.
    pub async fn get_validation_key(&self, resolver: KeyResolver<'_>, kid: &str) -> Result<Arc<DecodingKey>> {
        match resolver {
            KeyResolver::Jwks(uri) => self.resolve_jwks(uri, kid).await,
            KeyResolver::Oidc(discovery_url) => {
                let store = self.resolve_oidc(discovery_url).await?;
                store.keys.get(kid).cloned().ok_or_else(|| Error::KeyNotFound(kid.to_string()))
            },
        }
    }

    /// Exchanges `body` for a token at the endpoint configured by `config`.
    ///
    /// For [`AuthMode::Oidc`], the token endpoint is taken from
    /// `config.oauth_client` if explicitly set, otherwise from the endpoint
    /// discovered via the provider's OIDC metadata. For all other auth
    /// modes, the endpoint must be explicitly configured.
    pub async fn request_token<'a>(
        &self,
        config: &AuthConfig,
        body: TokenRequest<'a>,
        dpop_proof: Option<&str>,
    ) -> Result<TokenResponse<'a>> {
        let endpoint = self.resolve_token_endpoint(config).await?;

        let mut request = self.http_client.post(endpoint.as_ref()).form(&body);
        if let Some(proof) = dpop_proof {
            request = request.header("DPoP", proof);
        }

        let response = request.send().await?.error_for_status()?;

        Ok(response.json()?)
    }

    /// Determines the token endpoint to use for `config`, per the resolution
    /// order documented on [`Self::request_token`].
    async fn resolve_token_endpoint<'a>(&'a self, config: &'a AuthConfig) -> Result<Cow<'a, str>> {
        if let Some(endpoint) = config.oauth_client.as_ref().and_then(|c| c.token_endpoint.as_deref()) {
            return Ok(Cow::Borrowed(endpoint));
        }

        match &config.auth_mode {
            AuthMode::Oidc { discovery_url } => {
                let store = self.resolve_oidc(discovery_url).await?;

                store
                    .config
                    .as_ref()
                    .map(|c| Cow::Owned(c.token_endpoint.to_owned()))
                    .ok_or(Error::ClientNotConfigured)
            },

            _ => Err(Error::ClientNotConfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_type_serialization() {
        let ac = serde_json::to_value(GrantType::AuthorizationCode).unwrap();
        assert_eq!(ac, "authorization_code");

        let rt = serde_json::to_value(GrantType::RefreshToken).unwrap();
        assert_eq!(rt, "refresh_token");

        let cc = serde_json::to_value(GrantType::Credentials).unwrap();
        assert_eq!(cc, "client_credentials");
    }
}
