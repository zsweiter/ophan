use std::sync::Arc;

use dashmap::DashMap;
use jsonwebtoken::{
    DecodingKey,
    jwk::{AlgorithmParameters, JwkSet},
};
use ophan_net::Client;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::errors::AuthError;

pub struct JwksCache {
    pub fetched_at: Instant,
    pub keys: HashMap<String, Arc<DecodingKey>>,
}

#[derive(Default)]
pub struct JwksManager {
    client: Client,
    cache_ttl: Duration,
    cache: DashMap<String, JwksCache>,
}

impl JwksManager {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            cache_ttl: Duration::from_hours(12),
            cache: DashMap::new(),
        }
    }

    async fn fetch_jwks(&self, jwks_url: &str) -> Result<JwksCache, AuthError> {
        let response = self.client.get(jwks_url).send().await?.error_for_status()?;

        let jwks: JwkSet = response.json()?;

        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in jwks.keys {
            let kid = match jwk.common.key_id {
                Some(k) => k,
                None => continue,
            };

            let decoding_key = match jwk.algorithm {
                AlgorithmParameters::RSA(ref rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e).map_err(|e| {
                    tracing::warn!(%kid, error = %e, "failed to parse RSA JWK key components");
                    AuthError::InvalidJwks
                })?,
                AlgorithmParameters::EllipticCurve(ref ec) => DecodingKey::from_ec_components(&ec.x, &ec.y).map_err(|e| {
                    tracing::warn!(%kid, error = %e, "failed to parse EC JWK key components");
                    AuthError::InvalidJwks
                })?,
                AlgorithmParameters::OctetKeyPair(ref okp) => DecodingKey::from_ed_components(&okp.x).map_err(|e| {
                    tracing::warn!(%kid, error = %e, "failed to parse Ed25519 JWK key components");
                    AuthError::InvalidJwks
                })?,
                AlgorithmParameters::OctetKey(ref oct) => DecodingKey::from_base64_secret(&oct.value).map_err(|e| {
                    tracing::warn!(%kid, error = %e, "failed to parse symmetric JWK key");
                    AuthError::InvalidJwks
                })?,
            };

            keys.insert(kid, Arc::new(decoding_key));
        }

        Ok(JwksCache { fetched_at: Instant::now(), keys })
    }

    pub async fn get_key(&self, jwks_url: &str, kid: &str) -> Result<Arc<DecodingKey>, AuthError> {
        if let Some(cached) = self.cache.get(jwks_url)
            && cached.fetched_at.elapsed() < self.cache_ttl
            && let Some(key) = cached.keys.get(kid)
        {
            return Ok(Arc::clone(key));
        }

        let new_cache = self.fetch_jwks(jwks_url).await?;
        let target_key = match new_cache.keys.get(kid) {
            Some(k) => Arc::clone(k),
            None => {
                tracing::warn!(jwks_url, kid, "key not found in jwks");
                return Err(AuthError::KeyNotFound);
            },
        };

        self.cache.insert(jwks_url.to_string(), new_cache);
        Ok(target_key)
    }
}
