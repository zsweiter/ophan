use std::sync::Arc;

use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use ophan_auth::{
    AuthConfig, AuthMode, AuthService, Claims, DPoPRequestContext, DpopError, DpopPolicy, Error, JwtConfig, JwtValidator,
    JwtValidatorConfig, OAuthClient, OAuthClientConfig, RawToken, TokenType,
    crypto::{Algorithm, HmacAlg},
};
use ophan_net::http::Client;
use serde_json::Map;

const TEST_SECRET: &[u8] = b"test-integration-secret-0123456789abcdef";
const TEST_KID: &str = "integration-key-id";
const TEST_ISS: &str = "https://issuer.example.com";
const TEST_AUD: &str = "https://audience.example.com";

fn make_claims() -> Claims {
    Claims {
        sub: "user-42".into(),
        exp: 9_999_999_999,
        iat: 1_000_000_000,
        nbf: Some(1_000_000_000),
        iss: Some(TEST_ISS.into()),
        aud: Some(vec![TEST_AUD.into()]),
        jti: Some("jti-unique-1".into()),
        scope: Some("openid profile".into()),
        cnf: None,
        extra_data: Map::new(),
    }
}

fn sign_hs256(claims: &Claims, secret: &[u8], kid: &str) -> String {
    let header = Header { kid: Some(kid.into()), ..Header::new(HmacAlg::HS256.into()) };
    encode(&header, claims, &EncodingKey::from_secret(secret)).unwrap()
}

fn make_validator_config() -> JwtValidatorConfig {
    JwtValidatorConfig {
        issuer: vec![TEST_ISS.into()].into(),
        audience: vec![TEST_AUD.into()].into(),
        leeway_seconds: 300,
    }
}

fn make_service() -> AuthService {
    let client = Client::new();
    let oauth = OAuthClient::new(client);
    let validator = JwtValidator::new(JwtConfig::default());
    AuthService::new(oauth, validator)
}

fn make_static_auth_config() -> AuthConfig {
    AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(TEST_SECRET)),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    }
}

fn no_dpop_context() -> DPoPRequestContext<'static> {
    DPoPRequestContext {
        method: "GET",
        uri: "https://server.example.com/resource",
        nonce: None,
        dpop_proof: None,
    }
}

// -----------------------------------------------------------------------
// Static key authentication
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_authenticate_static_key_success() {
    let config = make_static_auth_config();
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    let claims = result.expect("static key authentication should succeed");
    assert_eq!(claims.sub, "user-42");
    assert_eq!(claims.iss.as_deref(), Some(TEST_ISS));
    assert_eq!(claims.aud, Some(vec![TEST_AUD.to_string()]));
}

#[tokio::test]
async fn test_authenticate_static_key_wrong_secret_fails() {
    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(b"different-secret-not-matching")),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_err(), "wrong secret should cause validation failure");
}

#[tokio::test]
async fn test_authenticate_malformed_token_fails() {
    let config = make_static_auth_config();
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: "definitely.not.a.jwt" },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// DPoP policy enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_dpop_required_rejects_bearer_token() {
    let mut config = make_static_auth_config();
    config.dpop_policy = DpopPolicy::Required;

    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(result, Err(Error::Dpop(DpopError::Required))));
}

#[tokio::test]
async fn test_dpop_required_missing_proof_fails() {
    let mut config = make_static_auth_config();
    config.dpop_policy = DpopPolicy::Required;

    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::DPoP, token: &token },
            DPoPRequestContext {
                method: "GET",
                uri: "https://server.example.com/resource",
                nonce: None,
                dpop_proof: None,
            },
        )
        .await;

    assert!(matches!(result, Err(Error::Dpop(DpopError::ProofRequired))));
}

#[tokio::test]
async fn test_dpop_disabled_rejects_dpop_token() {
    let mut config = make_static_auth_config();
    config.dpop_policy = DpopPolicy::Disabled;

    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(&config, RawToken { ttype: TokenType::DPoP, token: &token }, no_dpop_context())
        .await;
    assert!(matches!(result, Err(Error::Dpop(DpopError::Disabled))));
}

#[tokio::test]
async fn test_dpop_auto_allows_bearer_without_proof() {
    let config = make_static_auth_config();
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dpop_auto_requires_proof_for_dpop_token() {
    let config = make_static_auth_config();
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let service = make_service();

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::DPoP, token: &token },
            DPoPRequestContext {
                method: "GET",
                uri: "https://server.example.com/resource",
                nonce: None,
                dpop_proof: None,
            },
        )
        .await;
    assert!(matches!(result, Err(Error::Dpop(DpopError::ProofRequired))));
}

// -----------------------------------------------------------------------
// Refresh session (config-level)
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_refresh_session_no_client_config() {
    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(TEST_SECRET)),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service.refresh_session(&config, "some-token", None).await;
    assert!(matches!(result, Err(Error::ClientNotConfigured)));
}

#[tokio::test]
async fn test_refresh_session_disabled() {
    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: Some(OAuthClientConfig {
            client_id: "test-client".into(),
            client_secret: None,
            token_endpoint: None,
            refresh_flow_enabled: false,
        }),
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(TEST_SECRET)),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service.refresh_session(&config, "some-token", None).await;
    assert!(matches!(result, Err(Error::RefreshFlowDisabled)));
}

// -----------------------------------------------------------------------
// JWKS direct authentication (httpmock)
// -----------------------------------------------------------------------

fn sign_es256(claims: &Claims, kid: &str) -> (String, serde_json::Value) {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand::thread_rng;

    let signing_key = SigningKey::random(&mut thread_rng());
    let verifying_key = signing_key.verifying_key();

    let public_bytes = verifying_key.to_encoded_point(false);
    let x = public_bytes.x().unwrap();
    let y = public_bytes.y().unwrap();

    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);

    let pkcs8_der = signing_key.to_pkcs8_der().unwrap();
    let encoding_key = EncodingKey::from_ec_der(pkcs8_der.as_bytes());

    let header = Header {
        kid: Some(kid.into()),
        ..Header::new(Algorithm::ES256.into())
    };
    let token = encode(&header, claims, &encoding_key).unwrap();

    let public_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "x": x_b64,
        "y": y_b64,
    });

    (token, public_jwk)
}

#[tokio::test]
async fn test_jwks_direct_success() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token, public_jwk) = sign_es256(&make_claims(), TEST_KID);
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    let claims = result.expect("JWKS direct auth should succeed");
    assert_eq!(claims.sub, "user-42");
}

#[tokio::test]
async fn test_jwks_direct_wrong_kid_fails() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token, public_jwk) = sign_es256(&make_claims(), TEST_KID);
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_ok());

    // Create a token with a different kid not in the JWKS
    let (token2, _) = sign_es256(&make_claims(), "wrong-kid");
    let result2 = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token2 },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(result2, Err(Error::KeyNotFound(_))));
}

#[tokio::test]
async fn test_jwks_direct_unexpected_algorithm_fails() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token, public_jwk) = sign_es256(&make_claims(), TEST_KID);
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    // Configure to only accept RS256 but token uses ES256
    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::RS256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(
        result,
        Err(Error::UnsupportedAlgorithm(jsonwebtoken::Algorithm::ES256))
    ));
}

#[tokio::test]
async fn test_jwks_direct_no_kid_in_token_fails() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let public_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": TEST_KID,
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    // Create token without kid
    let claims = make_claims();
    let header = Header::new(Algorithm::ES256.into());
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand::thread_rng;
    let signing_key = SigningKey::random(&mut thread_rng());
    let pkcs8_der = signing_key.to_pkcs8_der().unwrap();
    let encoding_key = EncodingKey::from_ec_der(pkcs8_der.as_bytes());
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// JWKS endpoint errors
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_jwks_server_error_fails() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(500);
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImludGVncmF0aW9uLWV5ZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjEwMDAwMDAwMDB9.fake";
    let result = service.authenticate(&config, RawToken { ttype: TokenType::Bearer, token }, no_dpop_context()).await;
    assert!(matches!(result, Err(Error::Transport(_))));
}

#[tokio::test]
async fn test_jwks_invalid_json_fails() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).header("Content-Type", "application/json").body("not valid json {{{");
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url,
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImludGVncmF0aW9uLWV5ZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjEwMDAwMDAwMDB9.fake";
    let result = service.authenticate(&config, RawToken { ttype: TokenType::Bearer, token }, no_dpop_context()).await;
    assert!(matches!(result, Err(Error::Transport(_))));
}

// -----------------------------------------------------------------------
// OIDC Discovery authentication
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_oidc_success() {
    let server = httpmock::MockServer::start();
    let oidc_url = server.url("/.well-known/openid-configuration");
    let jwks_url = server.url("/.well-known/jwks.json");
    let token_endpoint = server.url("/token");

    let mock_origin = format!("http://127.0.0.1:{}", server.port());
    let mut claims = make_claims();
    claims.iss = Some(mock_origin.clone());
    let (token, public_jwk) = sign_es256(&claims, TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(200).header("Content-Type", "application/json").json_body(serde_json::json!({
            "issuer": &mock_origin,
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": token_endpoint,
            "jwks_uri": jwks_url,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"]
        }));
    });

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    let config = AuthConfig {
        validator: JwtValidatorConfig {
            issuer: vec![mock_origin.into()].into(),
            audience: vec![TEST_AUD.into()].into(),
            leeway_seconds: 300,
        },
        oauth_client: None,
        auth_mode: AuthMode::Oidc { discovery_url: oidc_url },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    let claims = result.expect("OIDC auth should succeed");
    assert_eq!(claims.sub, "user-42");
}

#[tokio::test]
async fn test_oidc_wrong_issuer_fails() {
    let server = httpmock::MockServer::start();
    let oidc_url = server.url("/.well-known/openid-configuration");
    let jwks_url = server.url("/.well-known/jwks.json");

    let mock_origin = format!("http://127.0.0.1:{}", server.port());
    let claims = make_claims(); // iss = "https://issuer.example.com" (different from mock)
    let (token, public_jwk) = sign_es256(&claims, TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(200).header("Content-Type", "application/json").json_body(serde_json::json!({
            "issuer": &mock_origin,
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": "https://token.example.com",
            "jwks_uri": jwks_url,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"]
        }));
    });

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    let config = AuthConfig {
        validator: JwtValidatorConfig {
            issuer: vec![mock_origin.into()].into(),
            audience: vec![TEST_AUD.into()].into(),
            leeway_seconds: 300,
        },
        oauth_client: None,
        auth_mode: AuthMode::Oidc { discovery_url: oidc_url },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(
        matches!(result, Err(Error::InvalidToken(_))),
        "OIDC auth should fail with wrong issuer, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_oidc_discovery_server_error_fails() {
    let server = httpmock::MockServer::start();
    let oidc_url = server.url("/.well-known/openid-configuration");

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(503);
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Oidc { discovery_url: oidc_url },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(result, Err(Error::Transport(_))));
}

// -----------------------------------------------------------------------
// JWKS Caching: second call uses cache
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_jwks_caching_second_call_uses_cache() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token, public_jwk) = sign_es256(&make_claims(), TEST_KID);

    // JWKS endpoint should only be called once
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({ "keys": [public_jwk] }));
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: None,
        auth_mode: AuthMode::Jwks {
            uri: jwks_url.clone(),
            expected_algorithms: Box::new([Algorithm::ES256]),
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();

    // First call fetches from JWKS
    let result1 = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result1.is_ok());
    mock.assert_calls(1);

    // Second call should use cache
    let result2 = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(result2.is_ok());
    mock.assert_calls(1); // Still 1 call — cached
}

// -----------------------------------------------------------------------
// Token refresh with httpmock
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_refresh_session_success() {
    let server = httpmock::MockServer::start();
    let token_endpoint = server.url("/token");

    let new_access_token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(200).header("Content-Type", "application/json").json_body(serde_json::json!({
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        }));
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: Some(OAuthClientConfig {
            client_id: "test-client".into(),
            client_secret: Some("test-secret".into()),
            token_endpoint: Some(token_endpoint),
            refresh_flow_enabled: true,
        }),
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(TEST_SECRET)),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service.refresh_session(&config, "old-refresh-token", None).await;
    let refreshed = result.expect("refresh should succeed");
    assert_eq!(refreshed.claims.sub, "user-42");
    assert_eq!(refreshed.response.access_token, new_access_token);
    assert_eq!(refreshed.response.expires_in, 3600);
    assert_eq!(refreshed.response.refresh_token.as_deref(), Some("new-refresh-token"));
}

#[tokio::test]
async fn test_refresh_session_provider_error() {
    let server = httpmock::MockServer::start();
    let token_endpoint = server.url("/token");

    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(401).body("invalid_grant");
    });

    let config = AuthConfig {
        validator: make_validator_config(),
        oauth_client: Some(OAuthClientConfig {
            client_id: "test-client".into(),
            client_secret: Some("test-secret".into()),
            token_endpoint: Some(token_endpoint),
            refresh_flow_enabled: true,
        }),
        auth_mode: AuthMode::Static {
            key: Arc::new(DecodingKey::from_secret(TEST_SECRET)),
            algorithm: HmacAlg::HS256,
        },
        dpop_policy: DpopPolicy::Auto,
    };

    let service = make_service();
    let result = service.refresh_session(&config, "expired-refresh-token", None).await;
    assert!(matches!(result, Err(Error::Transport(_))));
}
