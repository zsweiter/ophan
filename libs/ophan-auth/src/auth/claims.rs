use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::write::EncoderWriter;
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use serde_json::{Map, Value};
use std::io::Write;

use crate::auth::CnfClaim;

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audiences {
        Single(String),
        Multiple(Vec<String>),
    }

    let opt = Option::<Audiences>::deserialize(deserializer)?;
    Ok(match opt {
        Some(Audiences::Single(s)) => Some(vec![s]),
        Some(Audiences::Multiple(v)) => Some(v),
        None => None,
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: String,

    pub exp: usize,
    pub iat: usize,

    pub nbf: Option<usize>,
    pub iss: Option<String>,
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Option<Vec<String>>,

    pub jti: Option<String>,
    pub scope: Option<String>,

    /// DPoP confirmation claim (RFC 9449).
    /// Links the token to a client's public key via JWK Thumbprint.
    pub cnf: Option<CnfClaim>,

    #[serde(flatten)]
    pub extra_data: Map<String, Value>,
}

impl Claims {
    /// Encodes the claims directly into unpadded URL-Safe Base64 bytes.
    ///
    /// # Errors
    /// Returns an error if JSON serialization or Base64 encoding fails.
    pub fn encode_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct ClaimsRefEncoder<'a> {
            user_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            scope: Option<&'a str>,
            #[serde(flatten)]
            extra: &'a Map<String, Value>,
        }

        let encoder = ClaimsRefEncoder {
            user_id: &self.sub,
            scope: self.scope.as_deref(),
            extra: &self.extra_data,
        };

        let mut b64_output_buf = Vec::with_capacity(256);
        {
            let mut base64_writer = EncoderWriter::new(&mut b64_output_buf, &URL_SAFE_NO_PAD);

            // Serialize JSON directly into the Base64 stream.
            serde_json::to_writer(&mut base64_writer, &encoder)?;

            base64_writer.flush().map_err(serde_json::Error::custom)?;
        }

        Ok(b64_output_buf)
    }

    /// Evaluates dot-notation paths (e.g., `"user.role"` or `"items.0.id"`)
    /// to extract nested claim values without full JSON tree traversal.
    ///
    /// # Arguments
    /// * `path` - A dot-separated string representing the target property path.
    ///
    /// # Returns
    /// An `Option<&str>` referencing the internal string value if found and valid.
    #[inline]
    pub fn get_by_dot(&self, path: &str) -> Option<&str> {
        match path {
            "sub" => return Some(&self.sub),
            "iss" => return self.iss.as_deref(),
            "scope" => return self.scope.as_deref(),
            _ => {},
        }

        let mut parts = path.split('.');
        let first_key = parts.next()?;

        let mut current = self.extra_data.get(first_key)?;

        // Traverses nested JSON Objects and Arrays sequentially
        for key in parts {
            if key.is_empty() {
                return None;
            }

            match current {
                Value::Object(map) => {
                    current = map.get(key)?;
                },
                Value::Array(arr) => {
                    let idx = key.parse::<usize>().ok()?;
                    current = arr.get(idx)?;
                },
                _ => return None,
            }
        }

        current.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CnfClaim;

    fn make_claims() -> Claims {
        Claims {
            sub: "user-1".into(),
            exp: 999,
            iat: 100,
            nbf: Some(100),
            iss: Some("https://issuer.example.com".into()),
            aud: Some(vec!["https://aud.example.com".into()]),
            jti: Some("jti-1".into()),
            scope: Some("openid profile".into()),
            cnf: None,
            extra_data: Map::new(),
        }
    }

    #[test]
    fn test_claims_get_by_dot_standard_fields() {
        let claims = make_claims();
        assert_eq!(claims.get_by_dot("sub"), Some("user-1"));
        assert_eq!(claims.get_by_dot("iss"), Some("https://issuer.example.com"));
        assert_eq!(claims.get_by_dot("scope"), Some("openid profile"));
        assert_eq!(claims.get_by_dot("nonexistent"), None);
    }

    #[test]
    fn test_claims_get_by_dot_extra_data() {
        let mut claims = make_claims();
        claims.extra_data.insert("role".into(), Value::String("admin".into()));
        claims.extra_data.insert("org".into(), serde_json::json!({ "name": "acme", "id": "123" }));

        assert_eq!(claims.get_by_dot("role"), Some("admin"));
        assert_eq!(claims.get_by_dot("org.name"), Some("acme"));
        assert_eq!(claims.get_by_dot("org.id"), Some("123"));
        assert_eq!(claims.get_by_dot("org.missing"), None);
    }

    #[test]
    fn test_claims_get_by_dot_nested_empty_key() {
        let mut claims = make_claims();
        claims.extra_data.insert("obj".into(), serde_json::json!({"a": "1"}));

        assert_eq!(claims.get_by_dot("obj."), None);
    }

    #[test]
    fn test_claims_get_by_dot_array() {
        let mut claims = make_claims();
        claims.extra_data.insert("arr".into(), serde_json::json!(["x", "y", "z"]));

        assert_eq!(claims.get_by_dot("arr.0"), Some("x"));
        assert_eq!(claims.get_by_dot("arr.2"), Some("z"));
        assert_eq!(claims.get_by_dot("arr.5"), None);
    }

    #[test]
    fn test_claims_get_by_dot_non_string_value() {
        let mut claims = make_claims();
        claims.extra_data.insert("num".into(), Value::Number(42.into()));

        assert_eq!(claims.get_by_dot("num"), None);
    }

    #[test]
    fn test_claims_encode() {
        let mut claims = make_claims();
        claims.extra_data.insert("custom".into(), Value::String("val".into()));

        let encoded = claims.encode_bytes().unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_claims_deserialize_single_audience() {
        let json = serde_json::json!({
            "sub": "user-1",
            "exp": 999,
            "iat": 100,
            "aud": "single-aud"
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert_eq!(claims.aud, Some(vec!["single-aud".into()]));
    }

    #[test]
    fn test_claims_deserialize_multiple_audiences() {
        let json = serde_json::json!({
            "sub": "user-1",
            "exp": 999,
            "iat": 100,
            "aud": ["aud-1", "aud-2"]
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert_eq!(claims.aud, Some(vec!["aud-1".into(), "aud-2".into()]));
    }

    #[test]
    fn test_claims_deserialize_no_audience() {
        let json = serde_json::json!({
            "sub": "user-1",
            "exp": 999,
            "iat": 100
        });
        let claims: Claims = serde_json::from_value(json).unwrap();
        assert_eq!(claims.aud, None);
    }

    #[test]
    fn test_claims_with_cnf() {
        let mut claims = make_claims();
        claims.cnf = Some(CnfClaim { jkt: "thumbprint-123".into() });

        let json = serde_json::to_value(&claims).unwrap();
        let deserialized: Claims = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.cnf.unwrap().jkt, "thumbprint-123");
    }

    #[test]
    fn test_claims_serialize_deserialize_roundtrip() {
        let mut claims = make_claims();
        claims.extra_data.insert("org".into(), serde_json::json!({"name": "acme"}));

        let json = serde_json::to_value(&claims).unwrap();
        let deserialized: Claims = serde_json::from_value(json).unwrap();

        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.exp, claims.exp);
        assert_eq!(deserialized.iss, claims.iss);
        assert_eq!(deserialized.aud, claims.aud);
        assert_eq!(deserialized.scope, claims.scope);
        assert_eq!(deserialized.extra_data.get("org").unwrap()["name"], "acme");
    }

    #[test]
    fn test_claims_encode_produces_valid_base64url() {
        let claims = make_claims();
        let encoded = claims.encode_bytes().unwrap();

        use base64::Engine;
        let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded_bytes).unwrap();

        assert_eq!(json["user_id"], "user-1");
        assert_eq!(json["scope"], "openid profile");
    }
}
