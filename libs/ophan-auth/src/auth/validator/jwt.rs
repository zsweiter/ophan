use jsonwebtoken::{Algorithm, DecodingKey, Validation, dangerous, decode, errors::Error as JwtError};
use serde::de::DeserializeOwned;

use crate::config::JwtValidatorConfig;

pub struct JwtConfig {
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub validate_aud: bool,
    pub validate_iat: bool,
    pub leeway_seconds: u64,
    /// Maximum allowed clock skew in the future for iat validation.
    /// Tokens with iat more than this many seconds in the future are rejected.
    pub max_iat_future_skew_secs: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            validate_aud: true,
            validate_iat: true,
            leeway_seconds: 5,
            // Allow 5 minutes of future skew for iat to account for clock drift
            // between the authorization server and resource server.
            max_iat_future_skew_secs: 300,
        }
    }
}

pub struct JwtValidator {
    config: JwtConfig,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    fn build_validation(&self, leeway: u64, algo: Algorithm) -> Validation {
        let mut validation = Validation::new(algo);

        validation.validate_exp = self.config.validate_exp;
        validation.validate_nbf = self.config.validate_nbf;
        validation.validate_aud = self.config.validate_aud;
        validation.leeway = leeway;

        validation
    }

    pub fn validate<T: DeserializeOwned + serde::Serialize>(
        &self,
        token: &str,
        key: &DecodingKey,
        algo: Algorithm,
        config: &JwtValidatorConfig,
    ) -> Result<T, JwtError> {
        let mut validation = self.build_validation(config.leeway_seconds, algo);

        let issuers = config.issuer.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
        validation.set_issuer(&issuers);

        let audiences = config.audience.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
        validation.set_audience(&audiences);

        let decoded = decode::<T>(token, key, &validation)?;

        Ok(decoded.claims)
    }
}

pub fn insecure_decode<T: DeserializeOwned>(token: &str) -> Result<T, JwtError> {
    let data = dangerous::insecure_decode::<T>(token)?;

    Ok(data.claims)
}
