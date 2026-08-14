use std::{borrow::Cow, time::Duration};

use flatkit::sizes::ByteSize;

#[derive(Debug, Clone)]
pub struct EnvVar<'a>(pub Cow<'a, str>);

impl<'a> EnvVar<'a> {
    #[inline]
    pub fn get_value(&self) -> Option<String> {
        std::env::var(self.0.as_ref()).ok()
    }
}

#[derive(Debug, Clone)]
pub enum RawSecretKey<'a> {
    Env(EnvVar<'a>),
    Base64(&'a str),
}

#[derive(Debug, Clone)]
pub struct RawConfig<'a> {
    pub master: RawMaster<'a>,
    pub gateways: Vec<(&'a str, RawGateway<'a>)>,
}

// ============================================================================
// MASTER
// ============================================================================

#[derive(Debug, Clone)]
pub struct RawMaster<'a> {
    pub name: &'a str,
    pub user: &'a str,
    pub workers: RawWorkers,
    pub pid: &'a str,
    pub error_log: &'a str,
    pub includes: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub enum RawWorkers {
    Auto,
    Count(usize),
}

// ============================================================================
// GATEWAY
// ============================================================================

#[derive(Debug, Clone)]
pub struct RawGateway<'a> {
    pub name: &'a str,
    pub listeners: Vec<RawListener<'a>>,
    pub upstreams: Vec<RawUpstream<'a>>,
    pub routes: Vec<RawRoute<'a>>,
    pub policies: Vec<RawPolicy<'a>>,
}

// ============================================================================
// LISTENERS & NETWORKING
// ============================================================================

#[derive(Debug, Clone)]
pub struct RawListener<'a> {
    pub name: &'a str,
    pub address: &'a str,
    pub protocols: Vec<&'a str>,
    pub tls: Option<RawTls<'a>>,
    pub network_policy: Option<RawNetworkPolicy<'a>>,
    pub limits: Option<RawListenerLimits>,
    pub timeouts: Option<RawListenerTimeouts>,
}

#[derive(Debug, Clone)]
pub struct RawTls<'a> {
    pub cert: &'a str,
    pub key: &'a str,
    pub versions: Vec<&'a str>,
    pub client_auth: Option<&'a str>,
    pub client_ca: Option<&'a str>,
    pub ciphers: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawNetworkPolicy<'a> {
    pub allowed_ip_ranges: Vec<&'a str>,
    pub blocked_ip_ranges: Vec<&'a str>,
    pub real_ip_header: Option<&'a str>,
    pub proxy_allowed_ips: Option<Vec<&'a str>>,
}

#[derive(Debug, Clone)]
pub struct RawListenerLimits {
    pub connections: Option<u64>,
    pub request_size: Option<ByteSize>,
}

#[derive(Debug, Clone)]
pub struct RawListenerTimeouts {
    pub idle: Option<Duration>,
    pub keepalive: Option<Duration>,
}

// ============================================================================
// UPSTREAMS
// ============================================================================

#[derive(Debug, Clone)]
pub struct RawUpstream<'a> {
    pub name: &'a str,
    pub balance_strategy: Option<&'a str>,
    pub static_servers: Vec<RawUpstreamServer<'a>>,
    pub security: Option<RawUpstreamSecurity<'a>>,
    pub health_check: Option<RawHealthCheck<'a>>,
    // planed
    pub circuit_breaker: Option<RawCircuitBreaker>,
    pub discovery: Option<RawDiscovery<'a>>,
    pub registry: Option<RawRegistry<'a>>,
}

#[derive(Debug, Clone)]
pub struct RawUpstreamServer<'a> {
    pub endpoint: &'a str,
    pub weight: u16, // always 1 if not provided
    pub protocol: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawUpstreamSecurity<'a> {
    pub insecure_skip_verify: Option<bool>,
    pub hosts: Option<Vec<&'a str>>,
    pub cert: Option<&'a str>,
    pub key: Option<&'a str>,
    pub client_ca: Option<&'a str>,
    pub client_auth: Option<&'a str>,
    pub versions: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawHealthCheck<'a> {
    pub path: Option<&'a str>,
    pub interval: Option<Duration>,
    pub timeout: Option<Duration>,
    pub healthy_threshold: Option<u32>,
    pub unhealthy_threshold: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RawCircuitBreaker {
    pub consecutive_failures: Option<u32>,
    pub ejection_time: Option<Duration>,
    pub max_ejection_percent: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RawDiscovery<'a> {
    pub driver: &'a str,
    pub dns: Option<&'a str>,
    pub refresh_interval: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct RawRegistry<'a> {
    pub driver: &'a str,
    pub security: Option<RawRegistrySecurity<'a>>,
}

#[derive(Debug, Clone)]
pub enum RawRegistrySecurity<'a> {
    Mtls { cert: &'a str, key: &'a str, client_ca: &'a str },
    ApiKey { key: &'a str, algo: &'a str },
}

// ============================================================================
// ROUTES & GROUPS
// ============================================================================

#[derive(Debug, Clone)]
pub enum RawRoute<'a> {
    Path(RawPathRoute<'a>),
    // planed
    Group(RawGroupRoute<'a>),
}

#[derive(Debug, Clone)]
pub struct RawPathRoute<'a> {
    pub path: &'a str,
    pub hosts: Vec<&'a str>,
    pub methods: Vec<&'a str>,
    pub protocols: Vec<&'a str>,
    pub backend: RawBackend<'a>,
    pub timeouts: Option<RawRouteTimeouts>,
    pub streaming: Option<RawStreaming>,
    pub policies: Option<RawRoutePolicies<'a>>,
    pub rewrite: Option<RawUriRewrite<'a>>,
    pub inbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersOps<'a>>>,
    pub outbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersRemove<'a>>>,
}

#[derive(Debug, Clone)]
pub struct RawGroupRoute<'a> {
    pub name: &'a str,
    pub hosts: Vec<&'a str>,
    pub methods: Vec<&'a str>,
    pub backend: Option<RawBackend<'a>>,
    pub policies: Option<RawRoutePolicies<'a>>,
    pub inbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersOps<'a>>>,
    pub outbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersRemove<'a>>>,
    pub matches: Vec<RawRouteMatch<'a>>,
}

#[derive(Debug, Clone)]
pub struct RawRouteMatch<'a> {
    pub pattern: &'a str, // e.g. "GET /*"
    pub backend: RawBackend<'a>,
}

#[derive(Debug, Clone)]
pub enum RawBackend<'a> {
    Upstream(&'a str),
    Static(RawStaticBackend<'a>),
}

#[derive(Debug, Clone)]
pub struct RawStaticBackend<'a> {
    pub root: &'a str,
    pub flags: RawStaticFlags,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawStaticFlags {
    pub listing: Option<bool>,
    pub dotfiles: Option<bool>,
    pub index: Option<bool>,
    pub symlinks: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RawRouteTimeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub send: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct RawStreaming {
    pub buffering: Option<bool>,
    pub chunked: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RawUriRewrite<'a> {
    pub strip_prefix: Option<&'a str>,
    pub strip_suffix: Option<&'a str>,
    pub replaces: Vec<(&'a str, &'a str)>,
    pub trailing_slash: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawHeadersOps<'a> {
    pub set: Vec<(&'a str, &'a str)>,
    pub remove: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawHeadersRemove<'a> {
    pub remove: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawRouteHeadersOpts<'a, D> {
    pub opts: RawHeadersOps<'a>,
    pub upstream: D,
}

// ============================================================================
// ROUTE POLICY INVOCATIONS / OVERRIDES
// ============================================================================

#[derive(Debug, Clone)]
pub struct RawRoutePolicies<'a> {
    pub auth: Option<RawRouteAction<'a, RawAuthConfig<'a>>>,
    pub cors: Option<RawRouteAction<'a, RawCorsConfig<'a>>>,
    pub waf: Option<RawRouteAction<'a, RawWafConfig<'a>>>,
    pub limiter: Option<RawRouteAction<'a, RawLimiterConfig<'a>>>,
    pub helmet: Option<RawRouteAction<'a, RawHelmetConfig<'a>>>,
}

#[derive(Debug, Clone)]
pub enum RawRouteAction<'a, T> {
    Ref(&'a str),
    Extends { base: &'a str, overrides: T },
    Inline(T),
}

// ============================================================================
// GLOBAL POLICIES
// ============================================================================

#[derive(Debug, Clone)]
pub enum RawPolicy<'a> {
    Auth { name: &'a str, config: RawAuthConfig<'a> },
    Limiter { name: &'a str, config: RawLimiterConfig<'a> },
    Cors { name: &'a str, config: RawCorsConfig<'a> },
    Helmet { name: &'a str, config: RawHelmetConfig<'a> },
    Waf { name: &'a str, config: RawWafConfig<'a> },
}

impl<'a> RawPolicy<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            RawPolicy::Auth { name, .. } => name,
            RawPolicy::Limiter { name, .. } => name,
            RawPolicy::Cors { name, .. } => name,
            RawPolicy::Helmet { name, .. } => name,
            RawPolicy::Waf { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RawAuthConfig<'a> {
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub mode: Option<RawAuthMode<'a>>,
    pub dpop_proof: Option<&'a str>,
    pub sources: Option<Vec<RawTokenSource<'a>>>,
    pub refresh: Option<RawRefreshConfig<'a>>,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub enum RawAuthMode<'a> {
    Jwks {
        uri: Option<&'a str>,
        ttl: Option<Duration>,
        algorithms: Vec<&'a str>,
    },
    Oidc {
        discovery_url: Option<&'a str>,
        ttl: Option<Duration>,
    },
    Static {
        secret_key: RawSecretKey<'a>,
        alg: &'a str,
    },
}

#[derive(Debug, Clone)]
pub enum RawTokenSource<'a> {
    Header { name: &'a str, prefix: Option<&'a str> },
    Cookie { name: &'a str, prefix: Option<&'a str> },
    QueryParam { name: &'a str, prefix: Option<&'a str> },
}

#[derive(Debug, Clone)]
pub struct RawRefreshConfig<'a> {
    pub enabled: Option<bool>,
    pub endpoint: Option<&'a str>,
    pub sources: Option<RawTokenSource<'a>>,
    pub inject: Option<RawInjectConfig<'a>>,
}

#[derive(Debug, Clone)]
pub struct RawInjectConfig<'a> {
    pub access_token: Vec<RawInjectTarget<'a>>,
    pub refresh_token: Vec<RawInjectTarget<'a>>,
}

#[derive(Debug, Clone)]
pub enum RawInjectTarget<'a> {
    Header { name: &'a str },
    Cookie(RawCookieConfig<'a>),
}

#[derive(Debug, Clone)]
pub struct RawCookieConfig<'a> {
    pub name: &'a str,
    pub path: Option<&'a str>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub same_site: Option<&'a str>,
}

// --- LIMITER ---

#[derive(Debug, Clone, Default)]
pub struct RawLimiterConfig<'a> {
    pub rate: Option<(u64, Duration)>, // request/per
    pub burst: Option<u64>,
    pub identifier: Option<&'a str>,
    pub strategy: Option<&'a str>,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct RawCorsConfig<'a> {
    pub allow_origins: Vec<&'a str>,
    pub allow_methods: Vec<&'a str>,
    pub allow_headers: Vec<&'a str>,
    pub expose_headers: Vec<&'a str>,
    pub allow_credentials: Option<bool>,
    pub max_age: Option<Duration>,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct RawHelmetConfig<'a> {
    pub target: Option<&'a str>,
    pub level: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct RawWafConfig<'a> {
    pub mode: Option<&'a str>,
    pub ruleset: Option<&'a str>,
    pub max_body_size: Option<ByteSize>,
    pub anomaly_threshold: Option<u32>,
    pub rules: Vec<RawWafRule<'a>>,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RawWafRule<'a> {
    pub name: &'a str,
    pub phase: &'a str,
    pub action: &'a str,
    pub score: Option<u32>,
    pub when: &'a str, // Logical condition string parsed during evaluation
    pub message: Option<&'a str>,
}
