use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
    let hash = Sha256::digest(get_current_timestamp().as_nanos().to_be_bytes());
    // Take first 32 bytes, encode to base64url → 43 chars (within 43-128 range)
    b64_encode(&hash[..32])
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
    fn test_b64_encode_no_padding() {
        let encoded = b64_encode(b"hello world");
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_b64_encode_empty() {
        let encoded = b64_encode(b"");
        assert_eq!(encoded, "");
    }
}
