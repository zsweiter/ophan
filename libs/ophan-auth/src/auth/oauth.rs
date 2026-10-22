//! OAuth 2.0 / OIDC client.
//!
//! Provides token exchange (`request_token`) and JWT signing-key resolution
//! for two supported key-discovery strategies:
//!
//! - **OIDC Discovery**: fetches `/.well-known/openid-configuration`, then the
//!   provider's JWKS endpoint referenced by it.
//! - **Direct JWKS**: fetches a JWKS document directly.
//!
//! Discovery documents and key sets are cached separately, keyed by URL, so
//! both strategies share the same key-set cache and rotation handling.
//! Concurrent misses for the same URL are coalesced into a single fetch,
//! failed fetches are remembered briefly, and every fetch is bounded by a
//! timeout.
//!
//! A token signed with an unknown `kid` triggers at most one refetch of its
//! key set per refetch cooldown (default [`KEY_REFETCH_COOLDOWN`]), so key rotation is picked up without
//! waiting for the cache TTL while random `kid`s cannot be used to force a
//! fetch per request.

use ahash::AHashMap;
use cache::MemoryCache;
use dashmap::{DashMap, mapref::entry::Entry};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse},
};
use ophan_net::http::{CacheControl, Client};
use serde::Serialize;
use std::borrow::Cow;
use std::str::FromStr;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::{OidcConfiguration, TokenRequest, TokenResponse};
use crate::config::{AuthConfig, AuthMode};
use crate::error::{Error, Result};

/// Fallback TTL applied to a cached key set or discovery document when the
/// upstream response does not include a `Cache-Control: max-age` directive.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

/// Lower bound for any key-set / discovery cache TTL, so `max-age=0` or a
/// tiny TTL cannot turn every request into a fetch.
const MIN_CACHE_TTL: Duration = Duration::from_secs(60);

/// Upper bound for any key-set / discovery cache TTL.
const MAX_CACHE_TTL: Duration = Duration::from_secs(24 * 3600);

/// How long a failed discovery / key-set fetch is remembered.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);

/// Minimum interval between refetches of a key set triggered by an unknown `kid`.
pub const KEY_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// Timeout for every request sent to the identity provider.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of distinct providers (discovery URLs / JWKS URIs) kept in
/// the in-memory cache at once.
const DEFAULT_CACHE_CAPACITY: usize = 64;

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

/// A JWT verification key together with the algorithms it may be used with.
#[derive(Debug)]
pub struct VerificationKey {
    pub key: Arc<DecodingKey>,
    /// Taken from the JWK's `alg` when present, otherwise derived from its
    /// key type and curve.
    pub algorithms: Box<[Algorithm]>,
}

impl VerificationKey {
    pub fn allows(&self, algorithm: Algorithm) -> bool {
        self.algorithms.contains(&algorithm)
    }

    fn from_jwk(jwk: &Jwk) -> Option<Result<Self>> {
        if matches!(
            jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        ) {
            return None;
        }

        let family_algorithms: &[Algorithm] = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => AlgorithmFamily::Rsa.algorithms(),
            AlgorithmParameters::EllipticCurve(params) => match params.curve {
                EllipticCurve::P256 => &[Algorithm::ES256],
                EllipticCurve::P384 => &[Algorithm::ES384],
                _ => &[],
            },
            AlgorithmParameters::OctetKeyPair(params) => match params.curve {
                EllipticCurve::Ed25519 => &[Algorithm::EdDSA],
                _ => &[],
            },
            AlgorithmParameters::OctetKey(_) => AlgorithmFamily::Hmac.algorithms(),
            _ => &[],
        };

        let algorithms: Box<[Algorithm]> = match jwk.common.key_algorithm {
            Some(declared) => {
                let declared = Algorithm::from_str(&declared.to_string()).ok()?;
                if !family_algorithms.contains(&declared) {
                    return None;
                }
                Box::new([declared])
            },
            None => family_algorithms.into(),
        };

        if algorithms.is_empty() {
            return None;
        }

        Some(DecodingKey::from_jwk(jwk).map(|key| Self { key: Arc::new(key), algorithms }).map_err(Error::from))
    }
}

/// A cached set of JWT verification keys fetched from a JWKS document.
#[derive(Debug)]
pub struct KeySet {
    keys: AHashMap<String, Arc<VerificationKey>>,
    fetched_at: Instant,
}

impl KeySet {
    pub fn get(&self, kid: &str) -> Option<&Arc<VerificationKey>> {
        self.keys.get(kid)
    }
}

/// OAuth 2.0 / OIDC client handling token exchange and signing-key
/// resolution, with in-memory caching of discovery metadata and JWKS keys.
pub struct OAuthClient {
    http_client: Client,
    /// TTL used when an upstream response omits cache-control headers.
    cache_ttl: Duration,
    /// Cached OIDC discovery documents, keyed by discovery URL.
    discovery: MemoryCache<String, Arc<OidcConfiguration>>,
    /// Cached key sets, keyed by JWKS URI.
    key_sets: MemoryCache<String, Arc<KeySet>>,
    /// Time of the last unknown-`kid` refetch, per JWKS URI.
    refetches: DashMap<String, Instant>,
    /// Minimum interval between unknown-`kid` refetches of a key set.
    refetch_cooldown: Duration,
}

impl OAuthClient {
    /// Creates a new client backed by `http_client`, using the default cache
    /// TTL and capacity.
    pub fn new(http_client: Client) -> Self {
        Self {
            http_client,
            cache_ttl: DEFAULT_CACHE_TTL,
            discovery: MemoryCache::new(DEFAULT_CACHE_CAPACITY).with_negative_ttl(NEGATIVE_CACHE_TTL),
            key_sets: MemoryCache::new(DEFAULT_CACHE_CAPACITY).with_negative_ttl(NEGATIVE_CACHE_TTL),
            refetches: DashMap::new(),
            refetch_cooldown: KEY_REFETCH_COOLDOWN,
        }
    }

    /// Sets the minimum interval between refetches of a key set triggered
    /// by an unknown `kid` (default: [`KEY_REFETCH_COOLDOWN`]).
    pub fn with_key_refetch_cooldown(mut self, cooldown: Duration) -> Self {
        self.refetch_cooldown = cooldown;
        self
    }

    /// Picks the TTL to cache a response under: the configured override,
    /// else the response's `Cache-Control`, else the default, clamped to
    /// [`MIN_CACHE_TTL`]..=[`MAX_CACHE_TTL`].
    fn cache_ttl(configured: Option<Duration>, response: Option<Duration>, default: Duration) -> Duration {
        configured.or(response).unwrap_or(default).clamp(MIN_CACHE_TTL, MAX_CACHE_TTL)
    }

    /// Fetches and parses a JWKS document into a key set.
    ///
    /// Keys without a `kid` are skipped, since they cannot be looked up.
    /// Encryption keys and keys whose algorithm cannot be determined are
    /// skipped too. Keys that fail to parse are logged and skipped rather
    /// than failing the whole request, so a single malformed key does not
    /// take down validation for the rest of the provider's key set.
    async fn fetch_key_set(
        http_client: Client,
        jwks_uri: String,
        configured_ttl: Option<Duration>,
        default_ttl: Duration,
    ) -> Result<(Arc<KeySet>, Option<Duration>)> {
        let response = http_client.get(jwks_uri.as_str()).timeout(FETCH_TIMEOUT).send().await?.error_for_status()?;
        let ttl = Self::cache_ttl(configured_ttl, CacheControl::from(response.headers()).ttl(), default_ttl);
        let jwks: JwkSet = response.json()?;

        let mut keys = AHashMap::with_capacity(jwks.keys.len());
        for jwk in &jwks.keys {
            let Some(key_id) = jwk.common.key_id.as_ref() else {
                continue;
            };

            match VerificationKey::from_jwk(jwk) {
                Some(Ok(key)) => {
                    keys.insert(key_id.clone(), Arc::new(key));
                },
                Some(Err(err)) => {
                    tracing::error!(err = %err, key_id = %key_id, "failed to parse JWK, skipping");
                },
                None => {
                    tracing::debug!(key_id = %key_id, "JWK is not usable for signature verification, skipping");
                },
            }
        }

        Ok((Arc::new(KeySet { keys, fetched_at: Instant::now() }), Some(ttl)))
    }

    async fn fetch_discovery(
        http_client: Client,
        discovery_url: String,
        configured_ttl: Option<Duration>,
        default_ttl: Duration,
    ) -> Result<(Arc<OidcConfiguration>, Option<Duration>)> {
        let response = http_client.get(discovery_url.as_str()).timeout(FETCH_TIMEOUT).send().await?.error_for_status()?;
        let ttl = Self::cache_ttl(configured_ttl, CacheControl::from(response.headers()).ttl(), default_ttl);
        let config: OidcConfiguration = response.json()?;

        Ok((Arc::new(config), Some(ttl)))
    }

    /// Returns the OIDC discovery document at `discovery_url`, from the
    /// cache when possible.
    pub async fn discover(&self, discovery_url: &str, ttl: Option<Duration>) -> Result<Arc<OidcConfiguration>> {
        if let Some(cached) = self.discovery.get_value(discovery_url) {
            return Ok(cached);
        }

        let http_client = self.http_client.clone();
        let url = discovery_url.to_owned();
        let default_ttl = self.cache_ttl;

        self.discovery
            .get_or_fetch_with_ttl(discovery_url.to_owned(), move || {
                Self::fetch_discovery(http_client, url, ttl, default_ttl)
            })
            .await
            .map_err(Error::Shared)
    }

    async fn key_set(&self, jwks_uri: &str, ttl: Option<Duration>) -> Result<Arc<KeySet>> {
        if let Some(cached) = self.key_sets.get_value(jwks_uri) {
            return Ok(cached);
        }

        let http_client = self.http_client.clone();
        let uri = jwks_uri.to_owned();
        let default_ttl = self.cache_ttl;

        self.key_sets
            .get_or_fetch_with_ttl(jwks_uri.to_owned(), move || {
                Self::fetch_key_set(http_client, uri, ttl, default_ttl)
            })
            .await
            .map_err(Error::Shared)
    }

    /// Claims the right to refetch `jwks_uri` for an unknown `kid`; granted
    /// at most once per refetch cooldown.
    fn claim_refetch(&self, jwks_uri: &str) -> bool {
        let now = Instant::now();
        match self.refetches.entry(jwks_uri.to_owned()) {
            Entry::Occupied(mut last) => {
                if now.duration_since(*last.get()) < self.refetch_cooldown {
                    return false;
                }
                last.insert(now);
                true
            },
            Entry::Vacant(slot) => {
                slot.insert(now);
                true
            },
        }
    }

    /// Resolves the key identified by `kid` from the JWKS document at
    /// `jwks_uri`.
    ///
    /// An unknown `kid` refetches the key set (coalesced with concurrent
    /// callers) if it is older than the refetch cooldown and no other
    /// refetch happened within that window; otherwise it fails immediately
    /// with [`Error::KeyNotFound`].
    pub async fn get_verification_key(&self, jwks_uri: &str, kid: &str, ttl: Option<Duration>) -> Result<Arc<VerificationKey>> {
        let key_set = self.key_set(jwks_uri, ttl).await?;
        if let Some(key) = key_set.get(kid) {
            return Ok(Arc::clone(key));
        }

        if key_set.fetched_at.elapsed() < self.refetch_cooldown || !self.claim_refetch(jwks_uri) {
            return Err(Error::KeyNotFound(kid.to_string()));
        }

        tracing::debug!(jwks_uri = %jwks_uri, kid = %kid, "unknown kid, refetching key set");
        self.key_sets.remove(jwks_uri);

        let key_set = self.key_set(jwks_uri, ttl).await?;
        key_set.get(kid).cloned().ok_or_else(|| Error::KeyNotFound(kid.to_string()))
    }

    /// Exchanges `body` for a token at the endpoint configured by `config`.
    ///
    /// For [`AuthMode::Oidc`], the token endpoint is taken from
    /// `config.oauth_client` if explicitly set, otherwise from the endpoint
    /// discovered via the provider's OIDC metadata. For all other auth
    /// modes, the endpoint must be explicitly configured.
    pub async fn request_token(
        &self,
        config: &AuthConfig,
        body: TokenRequest<'_>,
        dpop_proof: Option<&str>,
    ) -> Result<TokenResponse<'static>> {
        let endpoint = self.resolve_token_endpoint(config).await?;

        let mut request = self.http_client.post(endpoint.as_ref()).timeout(FETCH_TIMEOUT).form(&body);
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
                let discovery = self.discover(discovery_url, config.key_cache_ttl).await?;

                Ok(Cow::Owned(discovery.token_endpoint.to_owned()))
            },

            _ => Err(Error::ClientNotConfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_grant_type_serialization() {
        let ac = serde_json::to_value(GrantType::AuthorizationCode).unwrap();
        assert_eq!(ac, "authorization_code");

        let rt = serde_json::to_value(GrantType::RefreshToken).unwrap();
        assert_eq!(rt, "refresh_token");

        let cc = serde_json::to_value(GrantType::Credentials).unwrap();
        assert_eq!(cc, "client_credentials");
    }

    #[test]
    fn cache_ttl_is_clamped() {
        let default = DEFAULT_CACHE_TTL;
        assert_eq!(OAuthClient::cache_ttl(None, Some(Duration::ZERO), default), MIN_CACHE_TTL);
        assert_eq!(
            OAuthClient::cache_ttl(None, Some(Duration::from_secs(7 * 86_400)), default),
            MAX_CACHE_TTL
        );
        assert_eq!(
            OAuthClient::cache_ttl(None, Some(Duration::from_secs(600)), default),
            Duration::from_secs(600)
        );
        assert_eq!(OAuthClient::cache_ttl(None, None, default), DEFAULT_CACHE_TTL);
        assert_eq!(
            OAuthClient::cache_ttl(Some(Duration::from_secs(300)), Some(Duration::from_secs(600)), default),
            Duration::from_secs(300)
        );
    }

    fn jwk(value: serde_json::Value) -> Jwk {
        serde_json::from_value(value).unwrap()
    }

    const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    #[test]
    fn verification_key_algorithms_follow_jwk() {
        let derived = VerificationKey::from_jwk(&jwk(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y })))
            .unwrap()
            .unwrap();
        assert_eq!(&*derived.algorithms, &[Algorithm::ES256]);

        let declared = VerificationKey::from_jwk(&jwk(
            json!({ "kty": "EC", "crv": "P-256", "alg": "ES256", "x": EC_X, "y": EC_Y }),
        ))
        .unwrap()
        .unwrap();
        assert!(declared.allows(Algorithm::ES256));
        assert!(!declared.allows(Algorithm::HS256));
    }

    #[test]
    fn verification_key_rejects_inconsistent_or_encryption_keys() {
        let mismatched = jwk(json!({ "kty": "EC", "crv": "P-256", "alg": "HS256", "x": EC_X, "y": EC_Y }));
        assert!(VerificationKey::from_jwk(&mismatched).is_none());

        let encryption = jwk(json!({ "kty": "EC", "crv": "P-256", "use": "enc", "x": EC_X, "y": EC_Y }));
        assert!(VerificationKey::from_jwk(&encryption).is_none());
    }

    #[test]
    fn refetch_is_claimed_once_per_cooldown() {
        let client = OAuthClient::new(Client::new());
        assert!(client.claim_refetch("https://idp/jwks"));
        assert!(!client.claim_refetch("https://idp/jwks"));
        assert!(client.claim_refetch("https://other/jwks"));
    }
}
