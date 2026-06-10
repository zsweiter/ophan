use super::{
    AuthConfig, AuthContext, AuthService, JwksManager, JwtConfig, JwtValidator, OAuth2Client, OAuth2Config, errors::AuthError,
};

// ---------------------------------------------------------------------------
// JwksManager tests
// ---------------------------------------------------------------------------

const RSA_JWKS_JSON: &str = r#"{
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key-1",
            "n": "u1SU1LfVLPHCYZMtCpuH6aGpFyo3aYKnB3-JhBqMgs3lOLp3yFGqFNYo5MNPqT6pua14HgLJj9KWJxYlJRLOp3oDqC36g2FqX4CpmS6P2RlMxVY4KaBPz6hG8BAoB5Kp6lB-sFKL4tWrCvTqSHN0E0mLoQ5v-_pO_IlR1gZqD5J3OnRXdD2GEoMTOAxY_-nS3Ona8hbGJjGlCFdYfHDAGd6jP9JXw4BisJvS1MobZ5KxJfqF4J1QfQmT-X7tCbYWYr3zYIq4JQQZcFYjFGj7WjXaPJuXnR5BqBtkoxXGlFZ0g8lK9mGFyRoCXjNnG2Zwyg5U6FZ4Xx70",
            "e": "AQAB"
        }
    ]
}"#;

const RSA_JWKS_OTHER_KEY: &str = r#"{
    "keys": [
        {
            "kty": "RSA",
            "kid": "other-key",
            "n": "u1SU1LfVLPHCYZMtCpuH6aGpFyo3aYKnB3-JhBqMgs3lOLp3yFGqFNYo5MNPqT6pua14HgLJj9KWJxYlJRLOp3oDqC36g2FqX4CpmS6P2RlMxVY4KaBPz6hG8BAoB5Kp6lB-sFKL4tWrCvTqSHN0E0mLoQ5v-_pO_IlR1gZqD5J3OnRXdD2GEoMTOAxY_-nS3Ona8hbGJjGlCFdYfHDAGd6jP9JXw4BisJvS1MobZ5KxJfqF4J1QfQmT-X7tCbYWYr3zYIq4JQQZcFYjFGj7WjXaPJuXnR5BqBtkoxXGlFZ0g8lK9mGFyRoCXjNnG2Zwyg5U6FZ4Xx70",
            "e": "AQAB"
        }
    ]
}"#;

#[tokio::test]
async fn test_jwks_fetch_success() {
    let mock_server = httpmock::MockServer::start();
    let jwks_url = mock_server.url("/.well-known/jwks.json");

    let jwks_mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).header("Content-Type", "application/json").body(RSA_JWKS_JSON);
    });

    let manager = JwksManager::new();
    let key = manager.get_key(&jwks_url, "test-key-1").await;

    assert!(key.is_ok(), "expected OK, got: {:?}", key.err());
    jwks_mock.assert();
}

#[tokio::test]
async fn test_jwks_fetch_http_error() {
    let mock_server = httpmock::MockServer::start();
    let jwks_url = mock_server.url("/.well-known/jwks.json");

    let _mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(500).body("Internal Server Error");
    });

    let manager = JwksManager::new();
    let result = manager.get_key(&jwks_url, "test-key-1").await;

    assert!(matches!(result, Err(AuthError::Http { .. })));
}

#[tokio::test]
async fn test_jwks_key_not_found() {
    let mock_server = httpmock::MockServer::start();
    let jwks_url = mock_server.url("/.well-known/jwks.json");

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).header("Content-Type", "application/json").body(RSA_JWKS_OTHER_KEY);
    });

    let manager = JwksManager::new();
    let result = manager.get_key(&jwks_url, "missing-key").await;

    assert!(matches!(result, Err(AuthError::KeyNotFound)));
}

#[tokio::test]
async fn test_jwks_cache_hit() {
    let mock_server = httpmock::MockServer::start();
    let jwks_url = mock_server.url("/.well-known/jwks.json");

    let jwks_mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).header("Content-Type", "application/json").body(RSA_JWKS_JSON);
    });

    let manager = JwksManager::new();

    // First call fetches from server
    let key1 = manager.get_key(&jwks_url, "test-key-1").await;
    assert!(key1.is_ok());
    jwks_mock.assert();
    assert_eq!(jwks_mock.calls(), 1);

    // Second call should use cache
    let key2 = manager.get_key(&jwks_url, "test-key-1").await;
    assert!(key2.is_ok());
    assert_eq!(jwks_mock.calls(), 1);
}

const INVALID_RSA_JWKS_JSON: &str = r#"{
    "keys": [
        {
            "kty": "RSA",
            "kid": "bad-key",
            "n": "!!!not-valid-base64!!!",
            "e": "AQAB"
        }
    ]
}"#;

#[tokio::test]
async fn test_jwks_invalid_key_components() {
    let mock_server = httpmock::MockServer::start();
    let jwks_url = mock_server.url("/.well-known/jwks.json");

    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/.well-known/jwks.json");
        then.status(200).header("Content-Type", "application/json").body(INVALID_RSA_JWKS_JSON);
    });

    let manager = JwksManager::new();
    let result = manager.get_key(&jwks_url, "bad-key").await;

    assert!(matches!(result, Err(AuthError::InvalidJwks)));
}

// ---------------------------------------------------------------------------
// OAuth2Client tests
// ---------------------------------------------------------------------------

fn make_oauth_config(endpoint: &str) -> OAuth2Config {
    OAuth2Config {
        endpoint: endpoint.to_string(),
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
    }
}

#[tokio::test]
async fn test_oauth_refresh_success() {
    let mock_server = httpmock::MockServer::start();
    let endpoint = mock_server.url("/token");

    let response_json = r#"{"access_token":"new-access-token","refresh_token":"new-refresh-token"}"#;

    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(200).header("Content-Type", "application/json").body(response_json);
    });

    let client = OAuth2Client::new();
    let config = make_oauth_config(&endpoint);

    let result = client.refresh_token("old-refresh-token", &config).await;

    assert!(result.is_ok(), "expected OK, got: {:?}", result.err());
    let token = result.unwrap();
    assert_eq!(token.access_token, "new-access-token");
    assert_eq!(token.refresh_token, Some("new-refresh-token".into()));
    mock.assert();
}

#[tokio::test]
async fn test_oauth_refresh_http_error() {
    let mock_server = httpmock::MockServer::start();
    let endpoint = mock_server.url("/token");

    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(401).body("Unauthorized");
    });

    let client = OAuth2Client::new();
    let config = make_oauth_config(&endpoint);

    let result = client.refresh_token("old-refresh-token", &config).await;

    assert!(matches!(result, Err(AuthError::Http { .. })));
    mock.assert();
}

#[tokio::test]
async fn test_oauth_refresh_empty_access_token() {
    let mock_server = httpmock::MockServer::start();
    let endpoint = mock_server.url("/token");

    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::POST).path("/token");
        then.status(200).header("Content-Type", "application/json").body(r#"{"access_token":""}"#);
    });

    let client = OAuth2Client::new();
    let config = make_oauth_config(&endpoint);

    let result = client.refresh_token("old-refresh-token", &config).await;

    assert!(matches!(result, Err(AuthError::InvalidAccessToken)));
    mock.assert();
}

#[tokio::test]
async fn test_oauth_refresh_invalid_refresh_token() {
    let client = OAuth2Client::new();
    let config = make_oauth_config("https://example.com/token");

    let result = client.refresh_token("", &config).await;
    assert!(matches!(result, Err(AuthError::InvalidRefreshToken)));
}

#[tokio::test]
async fn test_oauth_refresh_invalid_endpoint() {
    let client = OAuth2Client::new();
    let config = make_oauth_config("");

    let result = client.refresh_token("some-token", &config).await;
    assert!(matches!(result, Err(AuthError::InvalidEndpoint)));
}

// ---------------------------------------------------------------------------
// AuthService tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authenticate_invalid_access_token() {
    let validator = JwtValidator::new(JwtConfig::default());
    let oauth = OAuth2Client::new();
    let jwk_store = JwksManager::new();

    let service = AuthService::new(validator, oauth, jwk_store);

    let mut ctx = AuthContext {
        access_token: String::new(),
        refresh_token: None,
        is_mutated: false,
    };

    let config = AuthConfig {
        algorithm: jsonwebtoken::Algorithm::EdDSA,
        issuer: Some("https://auth.example.com".into()),
        audience: None,
        static_secret: None,
        jwk_uri: Some("https://auth.example.com/jwks".into()),
        jwk_ttl: Some(2400),
        refresh_oauth: None,
    };

    let result = service.authenticate(&mut ctx, &config).await;
    assert!(matches!(result, Err(AuthError::InvalidAccessToken)));
}
