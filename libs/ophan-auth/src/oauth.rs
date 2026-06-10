use ophan_net::Client;
use serde::{Deserialize, Serialize};

use super::errors::AuthError;
pub struct OAuth2Config {
    pub endpoint: String,

    pub client_id: String,
    pub client_secret: String,
}

#[derive(Serialize)]
pub struct RefreshTokenRequest<'a> {
    pub grant_type: &'a str,
    pub refresh_token: &'a str,

    pub client_id: &'a str,
    pub client_secret: &'a str,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Default)]
pub struct OAuth2Client {
    http_client: Client,
}

impl OAuth2Client {
    pub fn new() -> Self {
        Self { http_client: Client::new() }
    }

    pub async fn refresh_token(&self, refresh_token: &str, config: &OAuth2Config) -> Result<TokenResponse, AuthError> {
        if refresh_token.trim().is_empty() {
            return Err(AuthError::InvalidRefreshToken);
        }

        if config.endpoint.trim().is_empty() {
            return Err(AuthError::InvalidEndpoint);
        }

        let body = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token,
            client_id: &config.client_id,
            client_secret: &config.client_secret,
        };

        let response = self.http_client.post(&config.endpoint).form(&body).send().await?.error_for_status()?;
        // {
        //     Ok(resp) => resp,
        //     Err(e) => {
        //         tracing::warn!(endpoint = %config.endpoint, error = %e, "oauth token refresh http request failed");
        //         return Err(e);
        //     },
        // };

        // let response = match response.error_for_status() {
        //     Ok(resp) => resp,
        //     Err(e) => {
        //         tracing::warn!(endpoint = %config.endpoint, error = %e, "oauth endpoint returned error status");
        //         return Err(http_error(e));
        //     },
        // };

        let token_response: TokenResponse = response.json()?;
        // {
        //     Ok(t) => t,
        //     Err(e) => {
        //         tracing::warn!(endpoint = %config.endpoint, error = %e, "failed to parse oauth token response");
        //         return Err(http_error(e));
        //     },
        // };

        if token_response.access_token.trim().is_empty() {
            // tracing::warn!(endpoint = %config.endpoint, "oauth response contains empty access token");
            return Err(AuthError::InvalidAccessToken);
        }

        Ok(token_response)
    }
}
