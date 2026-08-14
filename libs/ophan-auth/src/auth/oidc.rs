use serde::Deserialize;

use crate::crypto::SignatureAlg;

#[derive(Deserialize, Debug, Clone)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,

    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<SignatureAlg>,

    #[serde(default)]
    pub authorization_endpoint: Option<String>,

    /// RFC 9449: Demonstration of Proof-of-Possession (DPoP)
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Option<Vec<SignatureAlg>>,

    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,

    #[serde(default)]
    pub grant_types_supported: Option<Vec<String>>,

    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}
