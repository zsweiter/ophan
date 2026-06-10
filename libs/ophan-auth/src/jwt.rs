use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    AuthConfig,
    errors::{AuthError, JwtErrorKind},
};

pub struct JwtConfig {
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub validate_aud: bool,
    pub leeway_seconds: u64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            validate_aud: true,
            leeway_seconds: 5,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,

    pub exp: usize,
    pub iat: usize,

    pub nbf: Option<usize>,
    pub iss: Option<String>,
    pub aud: Option<String>,

    pub jti: Option<String>,
    pub scope: Option<String>,

    #[serde(flatten)]
    pub extra_data: Map<String, Value>,
}

impl Claims {
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let mut user_context = self.extra_data.clone();

        user_context.insert("user_id".to_string(), Value::String(self.sub.clone()));

        if let Some(ref scope) = self.scope {
            user_context.insert("scope".to_string(), Value::String(scope.clone()));
        }

        let json_string = serde_json::to_string(&user_context)?;

        Ok(STANDARD.encode(json_string))
    }
}

pub struct JwtValidator {
    config: JwtConfig,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    fn build_validation(&self, issuer: Option<String>, audience: Option<String>, algo: Algorithm) -> Validation {
        let mut validation = Validation::new(algo);

        validation.validate_exp = self.config.validate_exp;
        validation.validate_nbf = self.config.validate_nbf;
        validation.validate_aud = self.config.validate_aud;
        validation.leeway = self.config.leeway_seconds;

        if let Some(iss) = &issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(aud) = &audience {
            validation.set_audience(&[aud]);
        }

        validation
    }

    fn jwt_error(err: jsonwebtoken::errors::Error) -> AuthError {
        let kind = match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtErrorKind::Expired,
            jsonwebtoken::errors::ErrorKind::InvalidSignature => JwtErrorKind::InvalidSignature,
            jsonwebtoken::errors::ErrorKind::InvalidToken => JwtErrorKind::InvalidToken,
            _ => JwtErrorKind::Other,
        };
        AuthError::JwtValidation { kind, message: err.to_string() }
    }

    pub fn validate(&self, token: &str, key: &DecodingKey, config: &AuthConfig) -> Result<Claims, AuthError> {
        let validation = self.build_validation(config.issuer.clone(), config.audience.clone(), config.algorithm);

        match decode::<Claims>(token, key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => Err(Self::jwt_error(e)),
        }
    }
}

pub(crate) fn jwt_error(err: jsonwebtoken::errors::Error) -> AuthError {
    JwtValidator::jwt_error(err)
}
