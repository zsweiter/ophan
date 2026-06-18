#![allow(dead_code)]
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};

pub const MAX_CONFIG_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2MB
pub const MAX_ROUTES: usize = 5000;
pub const MAX_LISTENERS: usize = 100;
pub const MAX_UPSTREAMS: usize = 500;
pub const MAX_POLICIES: usize = 500;

//
// ============================================================
// NETWORK
// ============================================================
//

#[derive(Debug, Clone)]
pub enum SecurityConfig {
    Plaintext,
    Tls {
        certs: SSLConfig,
        alpn_protocols: Vec<String>,
        min_version: TlsVersion,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum TlsVersion {
    Tls12,
    #[default]
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkTransport {
    Tcp(SocketAddr),
    Uds(String),
}

impl Default for NetworkTransport {
    fn default() -> Self {
        Self::Tcp(SocketAddr::from(([127, 0, 0, 1], 80)))
    }
}

impl NetworkTransport {
    pub fn tcp(host: [u8; 4], port: u16) -> Self {
        Self::Tcp(SocketAddr::from((host, port)))
    }

    pub fn unix(socket: &str) -> Self {
        Self::Uds(socket.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkProtocol {
    Http1 { allow_websocket_upgrade: bool },
    Http2 { mode: Http2Mode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Http2Mode {
    #[default]
    Standard,
    Grpc,
}

//
// ============================================================
// SSL
// ============================================================
//

#[derive(Debug, Clone)]
pub struct SSLConfig {
    pub cert: String,
    pub key: String,
    pub client_ca: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamSSLConfig {
    pub insecure_skip_verify: bool,
    pub hosts: Option<Vec<String>>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

//
// ============================================================
// LISTENERS
// ============================================================
//

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub name: String,
    pub listen: Vec<String>,
    pub transport: NetworkTransport,
    pub security: SecurityConfig,
    pub protocols: Vec<NetworkProtocol>,
}

impl ListenerConfig {
    pub fn http(name: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            listen: vec![addr.to_string()],
            transport: NetworkTransport::Tcp(addr),
            security: SecurityConfig::Plaintext,
            protocols: vec![NetworkProtocol::Http1 { allow_websocket_upgrade: false }],
        }
    }

    pub fn https(name: impl Into<String>, addr: SocketAddr, cert: SSLConfig) -> Self {
        Self {
            name: name.into(),
            listen: vec![addr.to_string()],
            transport: NetworkTransport::Tcp(addr),
            security: SecurityConfig::Tls {
                certs: cert,
                alpn_protocols: vec!["h2".into(), "http/1.1".into()],
                min_version: TlsVersion::Tls13,
            },
            protocols: vec![
                NetworkProtocol::Http1 { allow_websocket_upgrade: false }, // For HTTPS, we disable WebSocket Upgrade for security (Prevents WebSocket hijacking attacks over TLS)
                NetworkProtocol::Http2 { mode: Http2Mode::Standard },
            ],
        }
    }
}

//
// ============================================================
// UPSTREAMS
// ============================================================
//

#[derive(Debug, Clone, Default)]
pub enum BalanceStrategy {
    RoundRobin,
    #[default]
    LeastConnections,
    IpHash,
    Random,
}

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub protocol: NetworkProtocol,
    pub address: String,
    pub transport: NetworkTransport,
    pub ssl: Option<UpstreamSSLConfig>,
    pub weight: u32,
    pub is_healthy: bool,
}

impl UpstreamServer {
    pub fn http(address: impl Into<String>) -> Self {
        Self {
            protocol: NetworkProtocol::Http1 { allow_websocket_upgrade: false },
            address: address.into(),
            transport: NetworkTransport::default(),
            ssl: None,
            weight: 1,
            is_healthy: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub path: String,
    pub interval: u64,
    pub timeout: u64,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub balance_strategy: BalanceStrategy,
    pub health_check: Option<HealthCheckConfig>,
}

impl UpstreamConfig {
    pub fn single(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            servers: vec![UpstreamServer::http(address)],
            balance_strategy: BalanceStrategy::RoundRobin,
            health_check: None,
        }
    }
}

//
// ============================================================
// STATIC
// ============================================================
//

#[derive(Debug, Clone)]
pub enum StaticUpstream {
    Local {
        path: String,
        permissions: Option<String>,
        listing: bool,
        dotfiles: bool,
        blacklist: Vec<String>,
    },
    // (standby for now)
    Cdn {
        url: String,
        bucket: String,
        region: Option<String>,
        access_key: String,
        secret_key: String,
    },
}

impl Default for StaticUpstream {
    fn default() -> Self {
        Self::Local {
            path: "/".into(),
            permissions: None,
            listing: false,
            dotfiles: false,
            blacklist: vec![],
        }
    }
}

//
// ============================================================
// BACKEND TARGET (STATIC, UPSTREAM)
// ============================================================
//

#[derive(Debug, Clone)]
pub enum BackendTarget {
    Static(Arc<StaticUpstream>),
    Upstream(String),
}

//
// ============================================================
// REWRITES
// ============================================================
//

#[derive(Debug, Clone)]
pub struct RouteRewrites {
    pub rules: Option<HashMap<String, String>>,
    pub append_headers: HashMap<String, String>,
    pub prepend_headers: Vec<String>,
}

//
// ============================================================
// AUTH
// ============================================================
//

#[derive(Debug, Clone)]
pub struct RefreshTokenConfig {
    pub enabled: bool,
    pub source: TokenSource,
    pub token_endpoint: String,
    pub auto_rotate_response: bool,
}

#[derive(Debug, Clone)]
pub enum TokenSource {
    Header { name: String, prefix: Option<String> },
    Cookie { name: String, prefix: Option<String> },
    QueryParam { name: String, prefix: Option<String> },
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub issuer: String,
    // pub audience: Vec<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub sources: Vec<TokenSource>,
    pub jwk_uri: String, // !TODO need optional jwk_uri and jwk_ttl
    pub refresh_token: Option<RefreshTokenConfig>,
    pub excludes: Vec<String>,
}

impl OAuthConfig {
    pub fn merge(&mut self, other: OAuthConfig) {
        if !other.issuer.is_empty() {
            self.issuer = other.issuer;
        }
        if !other.client_id.is_empty() {
            self.client_id = other.client_id;
        }
        if other.client_secret.is_some() {
            self.client_secret = other.client_secret;
        }
        if !other.scopes.is_empty() {
            self.scopes = other.scopes;
        }
        if !other.sources.is_empty() {
            self.sources = other.sources;
        }
        if !other.jwk_uri.is_empty() {
            self.jwk_uri = other.jwk_uri;
        }
        if other.refresh_token.is_some() {
            self.refresh_token = other.refresh_token;
        }
        if !other.excludes.is_empty() {
            self.excludes = other.excludes;
        }
    }
}

//
// ============================================================
// RATE LIMITER
// ============================================================
//

#[derive(Default, Debug, Clone)]
pub enum RateLimitAlgorithm {
    #[default]
    SlidingWindow,
    TokenBucket,
}

#[derive(Default, Debug, Clone)]
pub enum LimiterIdentifier {
    #[default]
    Ip,
    Header(String),
    Token(String),
}

#[derive(Debug, Clone)]
pub struct LimiterRate {
    pub requests: u64,
    pub per_seconds: u64,
}

impl Default for LimiterRate {
    fn default() -> Self {
        Self { requests: 60, per_seconds: 60 }
    }
}

#[derive(Debug, Clone)]
pub struct LimiterConfig {
    pub rate: LimiterRate,
    pub burst: u64,
    pub algorithm: RateLimitAlgorithm,
    pub identifier: LimiterIdentifier,
    pub excludes: Vec<String>,
}

impl LimiterConfig {
    pub fn merge(&mut self, other: LimiterConfig) {
        self.rate.requests = other.rate.requests;
        self.rate.per_seconds = other.rate.per_seconds;
        self.burst = other.burst;
        self.algorithm = other.algorithm;
        self.identifier = other.identifier;
        if !other.excludes.is_empty() {
            self.excludes = other.excludes;
        }
    }
}

impl Default for LimiterConfig {
    fn default() -> Self {
        Self {
            rate: LimiterRate::default(),
            burst: 15,
            algorithm: RateLimitAlgorithm::default(),
            identifier: LimiterIdentifier::default(),
            excludes: vec![],
        }
    }
}

//
// ============================================================
// CORS
// ============================================================
//

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<u64>,
    pub excludes: Vec<String>,
}

impl CorsConfig {
    pub fn merge(&mut self, other: CorsConfig) {
        if !other.allow_origins.is_empty() {
            self.allow_origins = other.allow_origins;
        }
        if !other.allow_methods.is_empty() {
            self.allow_methods = other.allow_methods;
        }
        if !other.allow_headers.is_empty() {
            self.allow_headers = other.allow_headers;
        }
        if !other.expose_headers.is_empty() {
            self.expose_headers = other.expose_headers;
        }
        self.allow_credentials = other.allow_credentials;
        if other.max_age.is_some() {
            self.max_age = other.max_age;
        }
        if !other.excludes.is_empty() {
            self.excludes = other.excludes;
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origins: vec![],
            allow_methods: vec!["GET".into(), "HEAD".into()],
            allow_headers: vec![],
            expose_headers: vec![],
            allow_credentials: false,
            max_age: Some(600),
            excludes: vec![],
        }
    }
}

//
// ============================================================
// POLICIES
// ============================================================
//

#[derive(Debug, Clone, Default)]
pub struct PolicyConfig {
    pub auth: Option<HashMap<String, OAuthConfig>>,
    pub cors: Option<HashMap<String, CorsConfig>>,
    pub waf: Option<HashMap<String, WafConfig>>,
    pub limiter: Option<HashMap<String, LimiterConfig>>,
}

impl PolicyConfig {
    pub fn resolve_waf(&self, policy: &RouteWafPolicy) -> Option<Arc<WafConfig>> {
        match policy {
            RouteWafPolicy::Reference(name) => self.waf.as_ref()?.get(name).map(|c| Arc::new(c.clone())),
            RouteWafPolicy::Local(cfg) => Some(Arc::new(cfg.clone())),
            RouteWafPolicy::Override { base, config } => {
                let mut base_cfg = self.waf.as_ref()?.get(base)?.clone();
                base_cfg.merge(config.clone());
                Some(Arc::new(base_cfg))
            },
        }
    }

    pub fn resolve_auth(&self, policy: &RouteAuthPolicy) -> Option<Arc<OAuthConfig>> {
        match policy {
            RouteAuthPolicy::Reference(name) => self.auth.as_ref()?.get(name).map(|c| Arc::new(c.clone())),
            RouteAuthPolicy::Local(cfg) => Some(Arc::new(cfg.clone())),
            RouteAuthPolicy::Override { base, config } => {
                let mut base_cfg = self.auth.as_ref()?.get(base)?.clone();
                base_cfg.merge(config.clone());
                Some(Arc::new(base_cfg))
            },
        }
    }

    pub fn resolve_cors(&self, policy: &RouteCorsPolicy) -> Option<Arc<CorsConfig>> {
        match policy {
            RouteCorsPolicy::Reference(name) => self.cors.as_ref()?.get(name).map(|c| Arc::new(c.clone())),
            RouteCorsPolicy::Local(cfg) => Some(Arc::new(cfg.clone())),
            RouteCorsPolicy::Override { base, config } => {
                let mut base_cfg = self.cors.as_ref()?.get(base)?.clone();
                base_cfg.merge(config.clone());
                Some(Arc::new(base_cfg))
            },
        }
    }

    pub fn resolve_limiter(&self, policy: &RouteLimiterPolicy) -> Option<Arc<LimiterConfig>> {
        match policy {
            RouteLimiterPolicy::Reference(name) => self.limiter.as_ref()?.get(name).map(|c| Arc::new(c.clone())),
            RouteLimiterPolicy::Local(cfg) => Some(Arc::new(cfg.clone())),
            RouteLimiterPolicy::Override { base, config } => {
                let mut base_cfg = self.limiter.as_ref()?.get(base)?.clone();
                base_cfg.merge(config.clone());
                Some(Arc::new(base_cfg))
            },
        }
    }

    pub fn merge_all(&mut self, other: PolicyConfig) {
        if let Some(ref auth_map) = other.auth {
            self.auth.get_or_insert_with(HashMap::new).extend(auth_map.clone());
        }
        if let Some(ref cors_map) = other.cors {
            self.cors.get_or_insert_with(HashMap::new).extend(cors_map.clone());
        }
        if let Some(ref waf_map) = other.waf {
            self.waf.get_or_insert_with(HashMap::new).extend(waf_map.clone());
        }
        if let Some(ref limiter_map) = other.limiter {
            self.limiter.get_or_insert_with(HashMap::new).extend(limiter_map.clone());
        }
    }
}

// ============================================================
// ROUTE-LEVEL POLICY ENUMS
// ============================================================

#[derive(Debug, Clone)]
pub enum RouteAuthPolicy {
    Reference(String),
    Override { base: String, config: OAuthConfig },
    Local(OAuthConfig),
}

#[derive(Debug, Clone)]
pub enum RouteWafPolicy {
    Reference(String),
    Override { base: String, config: WafConfig },
    Local(WafConfig),
}

#[derive(Debug, Clone)]
pub enum RouteCorsPolicy {
    Reference(String),
    Override { base: String, config: CorsConfig },
    Local(CorsConfig),
}

#[derive(Debug, Clone)]
pub enum RouteLimiterPolicy {
    Reference(String),
    Override { base: String, config: LimiterConfig },
    Local(LimiterConfig),
}

//
// ============================================================
// ROUTE TIMEOUTS
// ============================================================
//

#[derive(Debug, Clone)]
pub struct RouteTimeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub send: Option<Duration>,
}

//
// ============================================================
// ROUTE STREAMING
// ============================================================
//

#[derive(Debug, Clone)]
pub struct RouteStreaming {
    pub buffering: bool,
    pub chunked: bool,
}

impl Default for RouteStreaming {
    fn default() -> Self {
        Self { buffering: true, chunked: true }
    }
}

//
// ============================================================
// ROUTES
// ============================================================
//

#[derive(Debug, Clone)]
pub struct RoutesConfig {
    pub path: String,
    pub hosts: Vec<String>,
    pub methods: HttpMethodSet,
    pub backend: BackendTarget,
    pub auth_policy: Option<RouteAuthPolicy>,
    pub waf_policy: Option<RouteWafPolicy>,
    pub cors_policy: Option<RouteCorsPolicy>,
    pub limiter_policy: Option<RouteLimiterPolicy>,
    pub priority: u32,
    pub rewrite: Option<RouteRewrites>,
    pub timeouts: Option<RouteTimeouts>,
    pub streaming: Option<RouteStreaming>,
}

impl RoutesConfig {
    pub fn static_stream(path: impl Into<String>, upstream: impl Into<StaticUpstream>) -> Self {
        Self {
            path: path.into(),
            hosts: vec![],
            methods: HttpMethodSet::new(HttpMethod::GET),
            backend: BackendTarget::Static(Arc::new(upstream.into())),
            auth_policy: None,
            waf_policy: None,
            cors_policy: None,
            limiter_policy: None,
            priority: 1,
            rewrite: None,
            timeouts: None,
            streaming: None,
        }
    }

    pub fn upstream(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            hosts: vec![],
            methods: HttpMethodSet::all(),
            backend: BackendTarget::Upstream(name.into()),
            auth_policy: None,
            waf_policy: None,
            cors_policy: None,
            limiter_policy: None,
            priority: 1,
            rewrite: None,
            timeouts: None,
            streaming: None,
        }
    }
}

//
// ============================================================
// GATEWAY
// ============================================================
//

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub name: String,
    pub listeners: Vec<ListenerConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    pub routes: Vec<RoutesConfig>,
    pub policies: PolicyConfig,
}

impl GatewayConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            listeners: Vec::new(),
            upstreams: Vec::new(),
            routes: Vec::new(),
            policies: PolicyConfig::default(),
        }
    }
}

// ======================= FMT ==============================
use std::fmt;

use ophan_net::http::{HttpMethod, HttpMethodSet};
use ophan_waf::config::WafConfig;

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Tls12 => write!(f, "TLS1.2"),
            TlsVersion::Tls13 => write!(f, "TLS1.3"),
        }
    }
}

impl fmt::Display for NetworkTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkTransport::Tcp(addr) => write!(f, "tcp://{addr}"),
            NetworkTransport::Uds(path) => write!(f, "unix://{path}"),
        }
    }
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkProtocol::Http1 { allow_websocket_upgrade } => {
                write!(f, "HTTP/1.1 (websocket_upgrade={allow_websocket_upgrade})")
            },

            NetworkProtocol::Http2 { mode } => {
                write!(f, "HTTP/2 ({mode:?})")
            },
        }
    }
}

impl fmt::Display for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityConfig::Plaintext => write!(f, "plaintext"),

            SecurityConfig::Tls { certs, alpn_protocols, min_version } => {
                write!(
                    f,
                    "tls(cert={}, key={}, alpn={:?}, min={})",
                    certs.cert, certs.key, alpn_protocols, min_version
                )
            },
        }
    }
}

impl fmt::Display for ListenerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Listener: {}", self.name)?;
        writeln!(f, "  transport: {}", self.transport)?;
        writeln!(f, "  security : {}", self.security)?;

        writeln!(f, "  protocols:")?;

        for protocol in &self.protocols {
            writeln!(f, "    - {protocol}")?;
        }

        Ok(())
    }
}

impl fmt::Display for UpstreamServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] weight={} healthy={}",
            self.address, self.protocol, self.weight, self.is_healthy
        )
    }
}

impl fmt::Display for UpstreamConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Upstream: {}", self.name)?;
        writeln!(f, "  strategy: {:?}", self.balance_strategy)?;

        for server in &self.servers {
            writeln!(f, "    - {server}")?;
        }

        Ok(())
    }
}

impl fmt::Display for BackendTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendTarget::Static(_) => write!(f, "static"),
            BackendTarget::Upstream(name) => write!(f, "upstream({name})"),
        }
    }
}

impl fmt::Display for RoutesConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Route: {}", self.path)?;
        writeln!(f, "  backend : {}", self.backend)?;
        writeln!(f, "  priority: {}", self.priority)?;

        // if !self.methods.is_empty() {
        //     writeln!(f, "  methods : {:?}", self.methods)?;
        // }

        if !self.hosts.is_empty() {
            writeln!(f, "  hosts   : {:?}", self.hosts)?;
        }

        Ok(())
    }
}

impl fmt::Display for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Gateway: {}", self.name)?;
        writeln!(f)?;

        writeln!(f, "Listeners:")?;
        for listener in &self.listeners {
            writeln!(f, "{listener}")?;
        }

        writeln!(f, "Upstreams:")?;
        for upstream in &self.upstreams {
            writeln!(f, "{upstream}")?;
        }

        writeln!(f, "Routes:")?;
        for route in &self.routes {
            writeln!(f, "{route}")?;
        }

        Ok(())
    }
}
