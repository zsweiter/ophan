use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::serialization::{b64_encode, get_current_timestamp};

/// DPoP request context.
///
/// Contains the values that must match the proof.
pub struct DPoPRequestContext<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub nonce: Option<&'a str>,

    pub dpop_proof: Option<&'a str>, // The DPoP proof token
}

/// RFC 9449 §4.3: Generate a DPoP nonce value.
/// The server should include this in the DPoP-Nonce response header.
pub fn generate_dpop_nonce() -> String {
    let ts = get_current_timestamp().as_nanos();

    b64_encode(Sha256::digest(ts.to_be_bytes()))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DpopProofClaims {
    /// Unique proof identifier (prevents replay).
    pub jti: String,
    /// HTTP method (e.g. "POST", "GET").
    pub htm: String,
    /// HTTP URI (e.g. "https://server.example.com/token").
    pub htu: String,
    /// Issued-at timestamp.
    pub iat: usize,
    /// Hash of the associated access token (base64url-encoded).
    /// RFC 9449 §4.2: Required when the DPoP proof is bound to an access token.
    pub ath: String,
    /// RFC 9449 §4.3: Nonce provided by the server in the DPoP-Nonce response header.
    /// When present, the server MUST validate it matches the expected nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CnfClaim {
    /// JWK SHA-256 Thumbprint (base64url-encoded).
    pub jkt: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dpop_nonce_format() {
        let nonce = generate_dpop_nonce();
        assert!(!nonce.is_empty());
        assert!(!nonce.contains('+'));
        assert!(!nonce.contains('/'));
        assert!(!nonce.contains('='));
    }

    #[test]
    fn test_generate_dpop_nonce_uniqueness() {
        let n1 = generate_dpop_nonce();
        let n2 = generate_dpop_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_dpop_proof_claims_serialize_deserialize() {
        let claims = DpopProofClaims {
            jti: "jti-1".into(),
            htm: "GET".into(),
            htu: "https://example.com/resource".into(),
            iat: 1234567890,
            ath: "abc123".into(),
            nonce: Some("server-nonce".into()),
        };

        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["jti"], "jti-1");
        assert_eq!(json["htm"], "GET");
        assert_eq!(json["nonce"], "server-nonce");

        let deserialized: DpopProofClaims = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.htm, "GET");
        assert_eq!(deserialized.nonce, Some("server-nonce".into()));
    }

    #[test]
    fn test_dpop_proof_claims_nonce_optional() {
        let claims = DpopProofClaims {
            jti: "jti-1".into(),
            htm: "POST".into(),
            htu: "https://example.com/token".into(),
            iat: 1234567890,
            ath: "def456".into(),
            nonce: None,
        };

        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("nonce").is_none());

        let deserialized: DpopProofClaims = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.nonce, None);
    }

    #[test]
    fn test_cnf_claim_serialize_deserialize() {
        let cnf = CnfClaim { jkt: "thumbprint-xyz".into() };
        let json = serde_json::to_value(&cnf).unwrap();
        let deserialized: CnfClaim = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.jkt, "thumbprint-xyz");
    }
}
