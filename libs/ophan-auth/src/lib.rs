mod auth;
mod config;
pub mod crypto;
mod error;
mod serialization;

use jsonwebtoken::decode_header;
use std::sync::Arc;

pub use auth::oauth::{GrantType, OAuthClient};
pub use auth::validator::{JwtConfig, JwtValidator};
pub use auth::{
    DPoPRequestContext, OidcConfiguration, RawToken, Refreshed, TokenRequest, TokenResponse, TokenType, claims::Claims,
    generate_dpop_nonce,
};
pub use config::{AuthConfig, AuthMode, DpopPolicy, JwtValidatorConfig, OAuthClientConfig};
pub use error::{DpopError, Error, Result};

use crate::auth::oauth::KeyResolver;
use crate::auth::validator::DpopValidator;

pub struct AuthService {
    oauth_client: OAuthClient,
    jwt_validator: JwtValidator,
    dpop_validator: DpopValidator,
}

impl AuthService {
    pub fn new(oauth_client: OAuthClient, jwt_validator: JwtValidator) -> Self {
        Self {
            oauth_client,
            jwt_validator,
            dpop_validator: DpopValidator::new(),
        }
    }

    pub async fn authenticate(
        &self,
        config: &AuthConfig,
        raw_token: RawToken<'_>,
        dpop: DPoPRequestContext<'_>,
    ) -> Result<Claims> {
        match config.dpop_policy {
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
            DpopPolicy::Auto => {
                if raw_token.ttype == TokenType::DPoP && dpop.dpop_proof.is_none() {
                    return Err(Error::Dpop(DpopError::ProofRequired));
                }
            },
        }

        let header = decode_header(raw_token.token)?;

        let decoding_key = match &config.auth_mode {
            AuthMode::Static { algorithm, key } => {
                if header.alg != **algorithm {
                    return Err(Error::UnsupportedAlgorithm(header.alg));
                }

                Arc::clone(key)
            },
            AuthMode::Jwks { expected_algorithms, uri } => {
                if !expected_algorithms.iter().any(|algorithm| **algorithm == header.alg) {
                    return Err(Error::UnsupportedAlgorithm(header.alg));
                }

                let kid = header.kid.ok_or_else(|| {
                    Error::InvalidToken(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken,
                    ))
                })?;

                self.oauth_client.get_validation_key(KeyResolver::Jwks(uri), &kid).await?
            },
            AuthMode::Oidc { discovery_url } => {
                let kid = header.kid.ok_or_else(|| {
                    Error::InvalidToken(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken,
                    ))
                })?;

                self.oauth_client.get_validation_key(KeyResolver::Oidc(discovery_url), &kid).await?
            },
        };

        let claims: Claims = self.jwt_validator.validate(raw_token.token, &decoding_key, header.alg, &config.validator)?;

        if raw_token.ttype == TokenType::DPoP {
            let proof = dpop.dpop_proof.ok_or(Error::Dpop(DpopError::ProofRequired))?;
            let cnf = claims.cnf.as_ref().ok_or(Error::Dpop(DpopError::BindingMissing))?;

            self.dpop_validator.validate(proof, raw_token.token, cnf, dpop)?;
        }

        Ok(claims)
    }

    pub async fn refresh_session<'a>(
        &self,
        config: &'a AuthConfig,
        refresh_token: &'a str,
        dpop_proof: Option<&'a str>,
    ) -> Result<Refreshed<'a, Claims>> {
        let oauth_config = config.oauth_client.as_ref().ok_or(Error::ClientNotConfigured)?;

        if !oauth_config.refresh_flow_enabled {
            return Err(Error::RefreshFlowDisabled);
        }

        let token_request = TokenRequest {
            grant_type: GrantType::RefreshToken,
            client_id: &oauth_config.client_id,
            client_secret: oauth_config.client_secret.as_deref(),
            code: None,
            refresh_token: Some(refresh_token),
            token_type_hint: Some("refresh_token"),
            code_verifier: None,
        };

        let response = self.oauth_client.request_token(config, token_request, dpop_proof).await?;

        // NOTE: We intentionally use insecure_decode here. The access token returned by the
        // authorization server's token endpoint has already been validated and signed by the
        // provider.
        let claims = auth::validator::insecure_decode(&response.access_token)?;

        Ok(Refreshed { claims, response })
    }
}
