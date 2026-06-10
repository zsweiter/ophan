# ophan-auth — Authentication & Authorization

> ⚠️ **Active Development** — API may change without notice.

JWT validation, OAuth2 token refresh, and JWKS key management for the Ophan gateway.

## Public API

### AuthService

Main authentication orchestrator.

```rust
pub struct AuthService;

impl AuthService {
    pub fn new(validator: JwtValidator, oauth: OAuth2Client, jwk_store: JwksManager) -> Self;

    /// Authenticate a request context against the given config.
    /// Returns Ok(Claims) on success, Err(AuthError) on failure.
    pub async fn authenticate(
        &self,
        context: &mut AuthContext,
        config: &AuthConfig,
    ) -> Result<Claims, AuthError>;
}
```

### AuthConfig

Configuration for a single authentication attempt.

```rust
pub struct AuthConfig {
    pub algorithm: Algorithm,           // Required JWT algorithm (e.g. EdDSA, RS256)
    pub issuer: Option<String>,        // Expected `iss` claim
    pub audience: Option<Vec<String>>, // Expected `aud` claim(s)
    pub static_secret: Option<String>, // Symmetric key (HMAC) — no JWKS fetch
    pub jwk_uri: Option<String>,       // JWKS endpoint URL
    pub jwk_ttl: Option<u64>,          // JWKS cache TTL in seconds
    pub refresh_oauth: Option<OAuth2Config>, // OAuth2 refresh token config
}
```

### AuthContext

Mutable per-request state carried through the authentication lifecycle.

```rust
pub struct AuthContext {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub is_mutated: bool,
}
```

### AuthError

Authentication failure reasons.

```rust
pub enum AuthError {
    JwtValidation { kind: JwtErrorKind, detail: String },
    HttpTransport { url: String, status: u16, body: String },
    Http(hyper::StatusCode),
    MissingKid,
    KeyNotFound,
    UnsupportedJwk,
    InvalidJwks(String),
    InvalidRefreshToken,
    InvalidEndpoint(String),
    InvalidAccessToken,
}

pub enum JwtErrorKind {
    Expired,
    InvalidSignature,
    InvalidToken,
    Other(String),
}
```

### Claims

Decoded JWT payload.

```rust
pub struct Claims {
    pub sub: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub nbf: Option<u64>,
    pub iss: Option<String>,
    pub aud: Option<Vec<String>>,
    pub jti: Option<String>,
    pub scope: Option<String>,
    pub extra_data: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Re-encode claims as a JWT string (for upstream propagation).
    pub fn encode(&self) -> Result<String, AuthError>;
}
```

### JwtValidator

Validates JWT tokens against a key.

```rust
pub struct JwtValidator;

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self;
    pub fn validate(&self, token: &str, key: &[u8], config: &AuthConfig) -> Result<Claims, AuthError>;
}

pub struct JwtConfig {
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub validate_aud: bool,
    pub leeway_seconds: u64,
}
```

### JwksManager

Fetches and caches JSON Web Key Sets.

```rust
pub struct JwksManager;

impl JwksManager {
    pub fn new() -> Self;
    pub async fn get_key(&self, config: &AuthConfig) -> Result<Vec<u8>, AuthError>;
}
```

### OAuth2Client

OAuth2 refresh token flow.

```rust
pub struct OAuth2Client;

impl OAuth2Client {
    pub fn new() -> Self;
    pub async fn refresh_token(&self, config: &OAuth2Config, refresh_token: &str) -> Result<TokenResponse, AuthError>;
}

pub struct OAuth2Config {
    pub endpoint: String,
    pub client_id: String,
    pub client_secret: String,
}

pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}
```

### Algorithm

Re-exported JWT signing algorithm.

```rust
pub type Algorithm = jsonwebtoken::Algorithm;
```
