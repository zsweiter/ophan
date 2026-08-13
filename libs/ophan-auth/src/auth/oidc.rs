use serde::Deserialize;

use crate::crypto::SignatureAlg;

#[derive(Deserialize, Debug)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<SignatureAlg>,
    pub dpop_signing_alg_values_supported: Vec<SignatureAlg>,
}
