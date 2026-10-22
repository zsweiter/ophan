use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
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

    /// Lifetime of the access token in seconds; `0` when not provided.
    #[serde(default)]
    pub expires_in: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Cow<'a, str>>,

    /// Lifetime of the refresh token in seconds, as reported by providers
    /// such as Keycloak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<Cow<'a, str>>,
}

#[derive(Debug, Clone)]
pub struct Refreshed<'a, T> {
    pub claims: T,
    pub response: TokenResponse<'a>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum TokenType {
    Bearer,
    DPoP,
}

/// RFC 6749 §5.1: the `token_type` value is case-insensitive.
impl<'de> Deserialize<'de> for TokenType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Cow::<'de, str>::deserialize(deserializer)?;
        if value.eq_ignore_ascii_case("bearer") {
            Ok(Self::Bearer)
        } else if value.eq_ignore_ascii_case("dpop") {
            Ok(Self::DPoP)
        } else {
            Err(D::Error::unknown_variant(&value, &["Bearer", "DPoP"]))
        }
    }
}

pub struct RawToken<'a> {
    pub ttype: TokenType,
    pub token: &'a str,
}
