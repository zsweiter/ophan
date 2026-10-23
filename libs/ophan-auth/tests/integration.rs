use std::sync::Arc;

use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use ophan_auth::{
    AuthConfig, AuthMode, AuthService, Claims, DPoPRequestContext, DpopError, DpopPolicy, Error, JwtValidator,
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
    JwtValidatorConfig::new(TEST_ISS).with_audiences(vec![TEST_AUD.into()]).with_leeway(300)
}

fn make_service() -> AuthService {
    let client = Client::new();
    let oauth = OAuthClient::new(client);
    let validator = JwtValidator::new();
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
        key_cache_ttl: None,
    }
}

fn no_dpop_context() -> DPoPRequestContext<'static> {
    DPoPRequestContext {
        method: "GET",
        scheme: "https",
        authority: "server.example.com",
        path: "/resource",
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
        key_cache_ttl: None,
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
                scheme: "https",
                authority: "server.example.com",
                path: "/resource",
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
                scheme: "https",
                authority: "server.example.com",
                path: "/resource",
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
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
    assert!(matches!(resolved(&result2), Some(Error::KeyNotFound(_))));
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
        key_cache_ttl: None,
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
        resolved(&result),
        Some(Error::UnsupportedAlgorithm(jsonwebtoken::Algorithm::ES256))
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
    };

    let service = make_service();
    let token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImludGVncmF0aW9uLWV5ZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjEwMDAwMDAwMDB9.fake";
    let result = service.authenticate(&config, RawToken { ttype: TokenType::Bearer, token }, no_dpop_context()).await;
    assert!(matches!(result.as_ref().map_err(Error::resolve), Err(Error::Transport(_))));
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
        key_cache_ttl: None,
    };

    let service = make_service();
    let token = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImludGVncmF0aW9uLWV5ZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjEwMDAwMDAwMDB9.fake";
    let result = service.authenticate(&config, RawToken { ttype: TokenType::Bearer, token }, no_dpop_context()).await;
    assert!(matches!(result.as_ref().map_err(Error::resolve), Err(Error::Transport(_))));
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
        validator: JwtValidatorConfig::new(mock_origin.as_str()).with_audiences(vec![TEST_AUD.into()]).with_leeway(300),
        oauth_client: None,
        auth_mode: AuthMode::Oidc { discovery_url: oidc_url },
        dpop_policy: DpopPolicy::Auto,
        key_cache_ttl: None,
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
        validator: JwtValidatorConfig::new(mock_origin.as_str()).with_audiences(vec![TEST_AUD.into()]).with_leeway(300),
        oauth_client: None,
        auth_mode: AuthMode::Oidc { discovery_url: oidc_url },
        dpop_policy: DpopPolicy::Auto,
        key_cache_ttl: None,
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
        matches!(resolved(&result), Some(Error::InvalidToken(_))),
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
        key_cache_ttl: None,
    };

    let service = make_service();
    let (token, _) = sign_es256(&make_claims(), TEST_KID);
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(result.as_ref().map_err(Error::resolve), Err(Error::Transport(_))));
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
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
        key_cache_ttl: None,
    };

    let service = make_service();
    let result = service.refresh_session(&config, "expired-refresh-token", None).await;
    assert!(matches!(result.as_ref().map_err(Error::resolve), Err(Error::Transport(_))));
}

// -----------------------------------------------------------------------
// Claim requirements
// -----------------------------------------------------------------------

fn sign_hs256_json(payload: serde_json::Value) -> String {
    let header = Header {
        kid: Some(TEST_KID.into()),
        ..Header::new(HmacAlg::HS256.into())
    };
    encode(&header, &payload, &EncodingKey::from_secret(TEST_SECRET)).unwrap()
}

#[tokio::test]
async fn test_token_without_aud_or_iss_is_rejected() {
    let config = make_static_auth_config();
    let service = make_service();

    for payload in [
        serde_json::json!({ "sub": "u", "iat": 1_000_000_000u64, "exp": 9_999_999_999u64, "iss": TEST_ISS }),
        serde_json::json!({ "sub": "u", "iat": 1_000_000_000u64, "exp": 9_999_999_999u64, "aud": TEST_AUD }),
    ] {
        let token = sign_hs256_json(payload);
        let result = service
            .authenticate(
                &config,
                RawToken { ttype: TokenType::Bearer, token: &token },
                no_dpop_context(),
            )
            .await;
        assert!(
            matches!(resolved(&result), Some(Error::InvalidToken(e)) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_))),
            "token lacking a configured claim must be rejected, got: {result:?}"
        );
    }
}

#[tokio::test]
async fn test_dpop_bound_token_with_bearer_scheme_is_rejected() {
    let config = make_static_auth_config();
    let service = make_service();

    let mut claims = make_claims();
    claims.cnf = Some(ophan_auth_cnf("thumbprint"));
    let token = sign_hs256(&claims, TEST_SECRET, TEST_KID);

    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(result, Err(Error::Dpop(DpopError::BoundTokenAsBearer))));
    assert!(!result.unwrap_err().is_refreshable());
}

fn ophan_auth_cnf(jkt: &str) -> ophan_auth::CnfClaim {
    serde_json::from_value(serde_json::json!({ "jkt": jkt })).unwrap()
}

// -----------------------------------------------------------------------
// Unknown kid handling
// -----------------------------------------------------------------------

fn jwks_config(uri: String) -> AuthConfig {
    AuthConfig::new(make_validator_config(), AuthMode::new_jwks(uri, Box::new([Algorithm::ES256])))
}

#[tokio::test]
async fn test_unknown_kid_refetches_at_most_once_per_cooldown() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token_a, jwk_a) = sign_es256(&make_claims(), "kid-a");
    let (token_b, jwk_b) = sign_es256(&make_claims(), "kid-b");

    let mut initial = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).json_body(serde_json::json!({ "keys": [jwk_a] }));
    });

    let cooldown = std::time::Duration::from_millis(300);
    let service = AuthService::new(
        OAuthClient::new(Client::new()).with_key_refetch_cooldown(cooldown),
        JwtValidator::new(),
    );
    let config = jwks_config(jwks_url);
    let authenticate = |token: &str| {
        let token = token.to_owned();
        let service = &service;
        let config = &config;
        async move {
            service
                .authenticate(
                    config,
                    RawToken { ttype: TokenType::Bearer, token: &token },
                    no_dpop_context(),
                )
                .await
        }
    };

    assert!(authenticate(&token_a).await.is_ok());
    initial.assert_calls(1);

    // The key set was just fetched: random kids fail fast without a fetch.
    for kid in ["random-1", "random-2", "random-3"] {
        let (token, _) = sign_es256(&make_claims(), kid);
        assert!(matches!(resolved(&authenticate(&token).await), Some(Error::KeyNotFound(_))));
    }
    initial.assert_calls(1);

    // Rotation: the provider now serves kid-b.
    initial.delete();
    let rotated = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).json_body(serde_json::json!({ "keys": [jwk_a, jwk_b] }));
    });

    tokio::time::sleep(cooldown + std::time::Duration::from_millis(50)).await;
    assert!(
        authenticate(&token_b).await.is_ok(),
        "unknown kid must refetch after the cooldown"
    );
    rotated.assert_calls(1);

    tokio::time::sleep(cooldown + std::time::Duration::from_millis(50)).await;
    let (unknown_1, _) = sign_es256(&make_claims(), "random-4");
    let (unknown_2, _) = sign_es256(&make_claims(), "random-5");
    assert!(matches!(
        resolved(&authenticate(&unknown_1).await),
        Some(Error::KeyNotFound(_))
    ));
    assert!(matches!(
        resolved(&authenticate(&unknown_2).await),
        Some(Error::KeyNotFound(_))
    ));
    rotated.assert_calls(2);
}

#[tokio::test]
async fn test_concurrent_unknown_kids_share_one_refetch() {
    let server = httpmock::MockServer::start();
    let jwks_url = server.url("/.well-known/jwks.json");

    let (token_a, jwk_a) = sign_es256(&make_claims(), "kid-a");
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .delay(std::time::Duration::from_millis(100))
            .json_body(serde_json::json!({ "keys": [jwk_a] }));
    });

    let cooldown = std::time::Duration::from_millis(100);
    let service = Arc::new(AuthService::new(
        OAuthClient::new(Client::new()).with_key_refetch_cooldown(cooldown),
        JwtValidator::new(),
    ));
    let config = Arc::new(jwks_config(jwks_url));

    let initial = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token_a },
            no_dpop_context(),
        )
        .await;
    assert!(initial.is_ok());
    tokio::time::sleep(cooldown + std::time::Duration::from_millis(20)).await;

    let tasks = (0..16)
        .map(|i| {
            let service = Arc::clone(&service);
            let config = Arc::clone(&config);
            let (token, _) = sign_es256(&make_claims(), &format!("random-{i}"));
            tokio::spawn(async move {
                service
                    .authenticate(
                        &config,
                        RawToken { ttype: TokenType::Bearer, token: &token },
                        no_dpop_context(),
                    )
                    .await
            })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        assert!(matches!(resolved(&task.await.unwrap()), Some(Error::KeyNotFound(_))));
    }
    mock.assert_calls(2);
}

// -----------------------------------------------------------------------
// OIDC hardening
// -----------------------------------------------------------------------

fn oidc_discovery(server: &httpmock::MockServer, issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": server.url("/token"),
        "jwks_uri": server.url("/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
    })
}

fn oidc_config(server: &httpmock::MockServer, issuer: &str) -> AuthConfig {
    AuthConfig::new(
        JwtValidatorConfig::new(issuer).with_audiences(vec![TEST_AUD.into()]),
        AuthMode::new_oidc(server.url("/.well-known/openid-configuration")),
    )
}

#[tokio::test]
async fn test_oidc_discovery_issuer_must_match_configuration() {
    let server = httpmock::MockServer::start();
    let (token, jwk) = sign_es256(&make_claims(), TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(200).json_body(oidc_discovery(&server, "https://attacker.example.com"));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).json_body(serde_json::json!({ "keys": [jwk] }));
    });

    let config = oidc_config(&server, TEST_ISS);
    let result = make_service()
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(
        matches!(resolved(&result), Some(Error::InvalidDiscovery(_))),
        "got: {result:?}"
    );
}

#[tokio::test]
async fn test_oidc_rejects_symmetric_algorithms() {
    let server = httpmock::MockServer::start();
    let jwk = serde_json::json!({
        "kty": "oct",
        "kid": TEST_KID,
        "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TEST_SECRET),
    });

    let discovery = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(200).json_body(oidc_discovery(&server, TEST_ISS));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).json_body(serde_json::json!({ "keys": [jwk] }));
    });

    let config = oidc_config(&server, TEST_ISS);
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let result = make_service()
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    assert!(matches!(
        resolved(&result),
        Some(Error::UnsupportedAlgorithm(jsonwebtoken::Algorithm::HS256))
    ));
    discovery.assert_calls(0);
}

#[tokio::test]
async fn test_oidc_picks_up_rotated_key_without_waiting_for_ttl() {
    let server = httpmock::MockServer::start();
    let (token_a, jwk_a) = sign_es256(&make_claims(), "kid-a");
    let (token_b, jwk_b) = sign_es256(&make_claims(), "kid-b");

    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/openid-configuration");
        then.status(200).json_body(oidc_discovery(&server, TEST_ISS));
    });
    let mut initial = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200)
            .header("Cache-Control", "max-age=86400")
            .json_body(serde_json::json!({ "keys": [jwk_a] }));
    });

    let cooldown = std::time::Duration::from_millis(200);
    let service = AuthService::new(
        OAuthClient::new(Client::new()).with_key_refetch_cooldown(cooldown),
        JwtValidator::new(),
    );
    let config = oidc_config(&server, TEST_ISS);

    assert!(
        service
            .authenticate(
                &config,
                RawToken { ttype: TokenType::Bearer, token: &token_a },
                no_dpop_context()
            )
            .await
            .is_ok()
    );

    initial.delete();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).json_body(serde_json::json!({ "keys": [jwk_b] }));
    });

    tokio::time::sleep(cooldown + std::time::Duration::from_millis(50)).await;
    let result = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token_b },
            no_dpop_context(),
        )
        .await;
    assert!(result.is_ok(), "rotated key must be fetched, got: {result:?}");
}

// -----------------------------------------------------------------------
// Refresh coalescing and validation
// -----------------------------------------------------------------------

fn refresh_config(token_endpoint: String) -> AuthConfig {
    AuthConfig::new(make_validator_config(), AuthMode::new_static(TEST_SECRET, HmacAlg::HS256)).with_oauth_client(
        OAuthClientConfig::new("test-client")
            .with_secret("test-secret")
            .with_token_endpoint(token_endpoint)
            .enable_refresh_flow(),
    )
}

#[tokio::test]
async fn test_concurrent_refreshes_are_coalesced() {
    let server = httpmock::MockServer::start();
    let new_access_token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);

    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/token")
            .body_includes("refresh_token=shared-refresh-token");
        then.status(200).delay(std::time::Duration::from_millis(150)).json_body(serde_json::json!({
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 300,
            "refresh_token": "rotated-refresh-token",
            "refresh_expires_in": 1800
        }));
    });

    let service = Arc::new(make_service());
    let config = Arc::new(refresh_config(server.url("/token")));

    let tasks = (0..12)
        .map(|_| {
            let service = Arc::clone(&service);
            let config = Arc::clone(&config);
            tokio::spawn(async move { service.refresh_session(&config, "shared-refresh-token", None).await })
        })
        .collect::<Vec<_>>();

    for task in tasks {
        let refreshed = task.await.unwrap().expect("every coalesced refresh must succeed");
        assert_eq!(refreshed.claims.sub, "user-42");
        assert_eq!(refreshed.response.refresh_token.as_deref(), Some("rotated-refresh-token"));
        assert_eq!(refreshed.response.refresh_expires_in, Some(1800));
    }
    mock.assert_calls(1);

    let late = service.refresh_session(&config, "shared-refresh-token", None).await;
    assert!(late.is_ok());
    mock.assert_calls(1);
}

#[tokio::test]
async fn test_failed_refresh_is_not_retried_immediately() {
    let server = httpmock::MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(400).body("invalid_grant");
    });

    let service = make_service();
    let config = refresh_config(server.url("/token"));

    for _ in 0..5 {
        let result = service.refresh_session(&config, "bad-refresh-token", None).await;
        assert!(matches!(result.as_ref().map_err(Error::resolve), Err(Error::Transport(_))));
    }
    mock.assert_calls(1);
}

#[tokio::test]
async fn test_refreshed_access_token_is_validated() {
    let server = httpmock::MockServer::start();
    let mut claims = make_claims();
    claims.aud = Some(vec!["https://other-api.example.com".into()]);
    let foreign_token = sign_hs256(&claims, TEST_SECRET, TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(200).json_body(serde_json::json!({
            "access_token": foreign_token,
            "token_type": "Bearer",
            "expires_in": 300
        }));
    });

    let result = make_service().refresh_session(&refresh_config(server.url("/token")), "refresh", None).await;
    assert!(matches!(resolved(&result), Some(Error::InvalidToken(_))), "got: {result:?}");
}

#[tokio::test]
async fn test_opaque_refreshed_access_token_uses_id_token_claims() {
    let server = httpmock::MockServer::start();
    let mut id_claims = make_claims();
    id_claims.aud = Some(vec!["test-client".into()]);
    let id_token = sign_hs256(&id_claims, TEST_SECRET, TEST_KID);

    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token").body_includes("refresh_token=with-id-token");
        then.status(200).json_body(serde_json::json!({
            "access_token": "opaque-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token
        }));
    });
    server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token").body_includes("refresh_token=without-id-token");
        then.status(200).json_body(serde_json::json!({
            "access_token": "opaque-access-token",
            "token_type": "Bearer",
            "expires_in": 300
        }));
    });

    let service = make_service();
    let config = refresh_config(server.url("/token"));

    let refreshed = service.refresh_session(&config, "with-id-token", None).await.expect("id_token claims must be used");
    assert_eq!(refreshed.claims.sub, "user-42");
    assert_eq!(refreshed.response.access_token, "opaque-access-token");

    let result = service.refresh_session(&config, "without-id-token", None).await;
    assert!(matches!(result, Err(Error::InvalidToken(_))));
}

// ─── Validation cache ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_validation_cache_hits_without_revalidation() {
    let service = make_service();
    let config = AuthConfig {
        validator: make_validator_config(),
        ..make_static_auth_config()
    };
    let token = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);

    let first = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;
    let second = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token },
            no_dpop_context(),
        )
        .await;

    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(first.unwrap().sub, second.unwrap().sub);
}

#[tokio::test]
async fn test_validation_cache_distinguishes_tokens() {
    let service = make_service();
    let config = AuthConfig {
        validator: make_validator_config(),
        ..make_static_auth_config()
    };

    let mut other = make_claims();
    other.sub = "user-43".into();

    let token_a = sign_hs256(&make_claims(), TEST_SECRET, TEST_KID);
    let token_b = sign_hs256(&other, TEST_SECRET, TEST_KID);

    let a = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token_a },
            no_dpop_context(),
        )
        .await
        .unwrap();
    let b = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &token_b },
            no_dpop_context(),
        )
        .await
        .unwrap();

    assert_ne!(a.sub, b.sub);
}

#[tokio::test]
async fn test_validation_cache_invalid_token_is_not_served() {
    let service = make_service();
    let config = AuthConfig {
        validator: make_validator_config(),
        ..make_static_auth_config()
    };

    let forged = sign_hs256(&make_claims(), b"totally-different-secret", TEST_KID);
    let first = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &forged },
            no_dpop_context(),
        )
        .await;
    let second = service
        .authenticate(
            &config,
            RawToken { ttype: TokenType::Bearer, token: &forged },
            no_dpop_context(),
        )
        .await;

    assert!(first.is_err());
    assert!(second.is_err());
}

/// The underlying error of a shared single-flight fetch result
/// (`Error::Shared` wraps the original `Error`).
fn resolved<T>(result: &Result<T, Error>) -> Option<&Error> {
    result.as_ref().err().map(Error::resolve)
}
