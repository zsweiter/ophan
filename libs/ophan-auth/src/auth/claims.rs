use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::{auth::CnfClaim, serialization::b64_encode};

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
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let mut data = self.extra_data.clone();

        data.insert("user_id".to_string(), Value::String(self.sub.clone()));
        if let Some(scope) = self.scope.as_ref() {
            data.insert("scope".to_string(), Value::String(scope.clone()));
        }

        Ok(b64_encode(serde_json::to_vec(&data)?))
    }

    pub fn get_by_dot<'a>(&'a self, path: &str) -> Option<&'a str> {
        match path {
            "sub" => Some(&self.sub),
            "iss" => self.iss.as_deref(),
            "scope" => self.scope.as_deref(),
            _ => {
                let mut parts = path.split('.');
                let first_key = parts.next()?;

                if parts.clone().next().is_none() {
                    if let Some(val) = self.extra_data.get(first_key) {
                        return val.as_str();
                    }
                }

                let mut current = self.extra_data.get(first_key)?;

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
            },
        }
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

        let encoded = claims.encode().unwrap();
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
        let encoded = claims.encode().unwrap();

        use base64::Engine;
        let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded_bytes).unwrap();

        assert_eq!(json["user_id"], "user-1");
        assert_eq!(json["scope"], "openid profile");
    }
}
