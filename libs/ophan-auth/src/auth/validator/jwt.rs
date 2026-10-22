use jsonwebtoken::{
    Algorithm, DecodingKey, decode,
    errors::{Error as JwtError, ErrorKind},
};

use crate::{auth::claims::Claims, config::JwtValidatorConfig, serialization::get_current_timestamp};

/// Validates access tokens against a [`JwtValidatorConfig`].
///
/// Signature, `exp`, `nbf`, `iss` and `aud` are checked with the rules
/// compiled into the configuration; `iat` is additionally rejected when it
/// lies further in the future than the configured skew.
#[derive(Debug, Default)]
pub struct JwtValidator;

impl JwtValidator {
    pub fn new() -> Self {
        Self
    }

    /// Verifies `token`, signed with `algorithm` (taken from its already
    /// decoded header), using `key`.
    ///
    /// The caller is responsible for checking `algorithm` against the
    /// allowlist of its key source.
    pub fn validate(
        &self,
        token: &str,
        key: &DecodingKey,
        algorithm: Algorithm,
        config: &JwtValidatorConfig,
    ) -> Result<Claims, JwtError> {
        let decoded = decode::<Claims>(token, key, config.validation(algorithm))?;
        let claims = decoded.claims;

        if let Some(max_skew) = config.max_iat_future_skew_secs() {
            let now = get_current_timestamp().as_secs();
            let issued_at = u64::try_from(claims.iat).unwrap_or(u64::MAX);
            if issued_at > now.saturating_add(max_skew) {
                return Err(ErrorKind::ImmatureSignature.into());
            }
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flatkit::str::ImmerStr;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    const SECRET: &[u8] = b"jwt-validator-test-secret-0123456789";
    const ISS: &str = "https://issuer.example.com";
    const AUD: &str = "https://api.example.com";

    fn config() -> JwtValidatorConfig {
        JwtValidatorConfig::new(ISS).with_audiences(vec![ImmerStr::from(AUD)])
    }

    fn sign(payload: Value) -> String {
        encode(&Header::new(Algorithm::HS256), &payload, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    fn validate(token: &str, config: &JwtValidatorConfig) -> Result<Claims, JwtError> {
        JwtValidator::new().validate(token, &DecodingKey::from_secret(SECRET), Algorithm::HS256, config)
    }

    fn now() -> u64 {
        get_current_timestamp().as_secs()
    }

    #[test]
    fn accepts_token_with_expected_iss_and_aud() {
        let token = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "iss": ISS, "aud": AUD }));
        assert_eq!(validate(&token, &config()).unwrap().sub, "u");
    }

    #[test]
    fn rejects_token_without_aud_when_audience_configured() {
        let token = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "iss": ISS }));
        let err = validate(&token, &config()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "aud"));
    }

    #[test]
    fn rejects_token_without_iss_when_issuer_configured() {
        let token = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "aud": AUD }));
        let err = validate(&token, &config()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::MissingRequiredClaim(claim) if claim == "iss"));
    }

    #[test]
    fn rejects_unexpected_iss_and_aud() {
        let wrong_iss = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "iss": "https://evil", "aud": AUD }));
        assert!(matches!(
            validate(&wrong_iss, &config()).unwrap_err().kind(),
            ErrorKind::InvalidIssuer
        ));

        let wrong_aud = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "iss": ISS, "aud": "other" }));
        assert!(matches!(
            validate(&wrong_aud, &config()).unwrap_err().kind(),
            ErrorKind::InvalidAudience
        ));
    }

    #[test]
    fn issuer_change_recompiles_validation() {
        let token = sign(json!({ "sub": "u", "iat": now(), "exp": now() + 600, "iss": "https://other", "aud": AUD }));
        let mut config = config();
        assert!(validate(&token, &config).is_err());

        config.set_issuers(vec![ImmerStr::from("https://other")]);
        assert!(validate(&token, &config).is_ok());
    }

    #[test]
    fn rejects_iat_too_far_in_future() {
        let token = sign(json!({ "sub": "u", "iat": now() + 3_600, "exp": now() + 7_200, "iss": ISS, "aud": AUD }));
        let err = validate(&token, &config()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::ImmatureSignature));

        let relaxed = config().with_max_iat_future_skew(None);
        assert!(validate(&token, &relaxed).is_ok());
    }

    #[test]
    fn applies_configured_leeway_to_exp() {
        let token = sign(json!({ "sub": "u", "iat": now() - 100, "exp": now() - 30, "iss": ISS, "aud": AUD }));
        assert!(validate(&token, &config()).is_ok());

        let strict = config().with_leeway(0);
        let err = validate(&token, &strict).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::ExpiredSignature));
    }

    #[test]
    fn rejects_immature_nbf() {
        let token = sign(json!({ "sub": "u", "iat": now(), "nbf": now() + 600, "exp": now() + 1_200, "iss": ISS, "aud": AUD }));
        assert!(matches!(
            validate(&token, &config()).unwrap_err().kind(),
            ErrorKind::ImmatureSignature
        ));
    }
}
