use jsonwebtoken::{AlgorithmFamily, DecodingKey, Validation, decode, decode_header, jwk::ThumbprintHash};
use sha2::{Digest, Sha256};

use crate::{
    auth::{CnfClaim, DPoPRequestContext, DpopProofClaims},
    error::{DpopError, Error},
    serialization::{b64_encode, get_current_timestamp},
};

const MAX_PROOF_AGE_SECS: u64 = 300;

#[inline]
fn is_fresh(iat: usize, now: u64) -> bool {
    let issued_at = u64::try_from(iat).unwrap_or(u64::MAX);
    issued_at <= now.saturating_add(MAX_PROOF_AGE_SECS) && now.saturating_sub(issued_at) <= MAX_PROOF_AGE_SECS
}

#[inline]
fn constant_time_eq(left: &str, right: &str) -> bool {
    let mut difference = left.len() ^ right.len();
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

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

        // DPoP requires an asymmetric signature verified against the public JWK
        match header.alg.family() {
            AlgorithmFamily::Ec | AlgorithmFamily::Rsa | AlgorithmFamily::Ed => {},
            _ => return Err(Error::Dpop(DpopError::InvalidFormat)),
        }

        let jwk = header.jwk.as_ref().ok_or(Error::Dpop(DpopError::InvalidFormat))?;

        let client_public_key = DecodingKey::from_jwk(jwk)?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;

        // These claims are required by the DPoP proof format and are validated
        // against the current HTTP request below.
        validation.required_spec_claims = vec!["jti".into(), "htm".into(), "htu".into(), "iat".into()].into_iter().collect();

        let decoded = decode::<DpopProofClaims>(dpop_proof, &client_public_key, &validation)?;
        let proof_claims = decoded.claims;

        let now = get_current_timestamp().as_secs();

        // DPoP proofs are short-lived to limit the window in which a stolen proof
        // can be replayed. Clock skew is tolerated within the same window.
        if !is_fresh(proof_claims.iat, now) {
            return Err(Error::Dpop(DpopError::InvalidFormat));
        }

        // Validate JWK Thumbprint matches the token's cnf.jkt.
        let actual_jkt = jwk.thumbprint(ThumbprintHash::SHA256)?;
        if !constant_time_eq(&cnf.jkt, &actual_jkt) {
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
        if !constant_time_eq(&proof_claims.ath, &actual_ath) {
            return Err(Error::Dpop(DpopError::AthMismatch));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_iat_accepts_clock_skew_window() {
        assert!(is_fresh(1_000, 1_000));
        assert!(is_fresh(700, 1_000));
        assert!(is_fresh(1_300, 1_000));
    }

    #[test]
    fn proof_iat_rejects_stale_and_future_proofs() {
        assert!(!is_fresh(699, 1_000));
        assert!(!is_fresh(1_301, 1_000));
    }
}
