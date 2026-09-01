use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

#[must_use]
pub fn get_current_timestamp() -> Duration {
    let start = std::time::SystemTime::now();
    start.duration_since(std::time::UNIX_EPOCH).expect("Time went backwards")
}

#[inline]
pub(crate) fn b64_encode<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

#[allow(unused)]
/// RFC 7636 §4.1: Generate a PKCE code verifier (43-128 characters, unreserved chars).
pub fn generate_code_verifier() -> String {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    b64_encode(entropy)
}

#[allow(unused)]
/// RFC 7636 §4.2: Compute S256 code challenge from a code verifier.
/// code_challenge = BASE64URL(SHA256(code_verifier))
pub fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    b64_encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_verifier_is_rfc7636_sized_and_random() {
        let first = generate_code_verifier();
        let second = generate_code_verifier();

        assert!((43..=128).contains(&first.len()));
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)));
    }

    #[test]
    fn code_challenge_matches_rfc7636_s256_example() {
        assert_eq!(
            compute_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
