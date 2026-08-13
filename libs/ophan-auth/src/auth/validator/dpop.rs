use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::ThumbprintHash};
use sha2::{Digest, Sha256};

use crate::{
    auth::{CnfClaim, DPoPRequestContext, DpopProofClaims},
    error::{DpopError, Error},
    serialization::b64_encode,
};

/// The DPoP Validator
/// RFC 9449
pub struct DpopValidator;

impl DpopValidator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn validate(&self, dpop_proof: &str, access_token: &str, cnf: &CnfClaim, ctx: DPoPRequestContext) -> Result<bool, Error> {
        let header = decode_header(dpop_proof)?;

        // DPoP proof typ must be "dpop+jwt".
        if header.typ.as_deref() != Some("dpop+jwt") {
            return Err(Error::Dpop(DpopError::InvalidType));
        }

        let jwk = header.jwk.as_ref().ok_or(Error::Dpop(DpopError::InvalidFormat))?;

        let client_public_key = DecodingKey::from_jwk(jwk)?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.required_spec_claims = vec!["jti".into(), "htm".into(), "htu".into(), "iat".into()].into_iter().collect();

        let decoded = decode::<DpopProofClaims>(dpop_proof, &client_public_key, &validation)?;
        let proof_claims = decoded.claims;

        // Validate JWK Thumbprint matches the token's cnf.jkt.
        let actual_jkt = jwk.thumbprint(ThumbprintHash::SHA256)?;
        if *cnf.jkt != actual_jkt {
            return Err(Error::Dpop(DpopError::ThumbprintMismatch));
        }

        // htm (HTTP Method) comparison must be case-sensitive.
        if proof_claims.htm != ctx.method {
            return Err(Error::Dpop(DpopError::HtmMismatch));
        }

        // htu (HTTP URI) must match exactly.
        if proof_claims.htu != ctx.uri {
            return Err(Error::Dpop(DpopError::HtuMismatch));
        }

        // If the server provided a DPoP-Nonce, the proof must include it.
        if let Some(expected_nonce) = ctx.nonce {
            match &proof_claims.nonce {
                Some(proof_nonce) if proof_nonce == expected_nonce => {},
                _ => return Err(Error::Dpop(DpopError::NonceMismatch)),
            }
        }

        // ath must be present and match the SHA-256 hash of the access token.
        let actual_ath = b64_encode(Sha256::digest(access_token.as_bytes()));
        if proof_claims.ath != actual_ath {
            return Err(Error::Dpop(DpopError::AthMismatch));
        }

        Ok(true)
    }
}
