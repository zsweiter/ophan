use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::auth::oauth::GrantType;

#[derive(Debug, Clone, Serialize)]
pub struct TokenRequest<'a> {
    pub grant_type: GrantType,
    pub client_id: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<&'a str>,

    /// OAuth 2.0: Hint about the token type being refreshed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<&'a str>,

    /// RFC 7636: PKCE code verifier for authorization code exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse<'a> {
    pub access_token: Cow<'a, str>,
    pub token_type: TokenType,
    pub expires_in: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Cow<'a, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<Cow<'a, str>>,
}

#[derive(Debug, Clone)]
pub struct Refreshed<'a, T> {
    pub claims: T,
    pub response: TokenResponse<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum TokenType {
    Bearer,
    DPoP,
}

pub struct RawToken<'a> {
    pub ttype: TokenType,
    pub token: &'a str,
}
