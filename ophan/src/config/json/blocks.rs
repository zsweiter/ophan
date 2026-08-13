use std::time::Duration;
use serde::{Deserialize, Serialize};
use flatkit::sizes::ByteSize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawConfig<'a> {
    pub master: RawMaster<'a>,
    #[serde(borrow)]
    pub gateways: Vec<(&'a str, RawGateway<'a>)>,
}

// ============================================================================
// MASTER
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawMaster<'a> {
    pub name: &'a str,
    pub user: &'a str,
    pub workers: RawWorkers,
    pub pid: &'a str,
    pub error_log: &'a str,
    pub includes: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawWorkers {
    Auto,
    Count(usize),
}

// ============================================================================
// GATEWAY
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawListener<'a> {
    pub name: &'a str,
    pub address: &'a str,
    pub protocols: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<RawTls<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<RawNetworkPolicy<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<RawListenerLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<RawListenerTimeouts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawTls<'a> {
    pub cert: &'a str,
    pub key: &'a str,
    pub versions: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<&'a str>,
    pub ciphers: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawNetworkPolicy<'a> {
    pub allowed_ip_ranges: Vec<&'a str>,
    pub blocked_ip_ranges: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub real_ip_header: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_allowed_ips: Option<Vec<&'a str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawListenerLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_size: Option<ByteSize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawListenerTimeouts {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub idle: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub keepalive: Option<Duration>,
}

// ============================================================================
// UPSTREAMS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawUpstream<'a> {
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_strategy: Option<&'a str>,
    pub static_servers: Vec<RawUpstreamServer<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<RawUpstreamSecurity<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<RawHealthCheck<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<RawCircuitBreaker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<RawDiscovery<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RawRegistry<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawUpstreamServer<'a> {
    pub endpoint: &'a str,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'a str>,
}

fn default_weight() -> u16 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawUpstreamSecurity<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_skip_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<&'a str>,
    pub versions: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawHealthCheck<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub interval: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub timeout: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthy_threshold: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unhealthy_threshold: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawCircuitBreaker {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consecutive_failures: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub ejection_time: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ejection_percent: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawDiscovery<'a> {
    pub driver: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<&'a str>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub refresh_interval: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRegistry<'a> {
    pub driver: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<RawRegistrySecurity<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawRegistrySecurity<'a> {
    Mtls { cert: &'a str, key: &'a str, client_ca: &'a str },
    ApiKey { key: &'a str, algo: &'a str },
}

// ============================================================================
// ROUTES & GROUPS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawRoute<'a> {
    Path(RawPathRoute<'a>),
    Group(RawGroupRoute<'a>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawPathRoute<'a> {
    pub path: &'a str,
    pub hosts: Vec<&'a str>,
    pub methods: Vec<&'a str>,
    pub protocols: Vec<&'a str>,
    pub backend: RawBackend<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<RawRouteTimeouts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<RawStreaming>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<RawRoutePolicies<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<RawUriRewrite<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersOps<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersRemove<'a>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawGroupRoute<'a> {
    pub name: &'a str,
    pub hosts: Vec<&'a str>,
    pub methods: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<RawBackend<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<RawRoutePolicies<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersOps<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersRemove<'a>>>,
    pub matches: Vec<RawRouteMatch<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRouteMatch<'a> {
    pub pattern: &'a str,
    pub backend: RawBackend<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawBackend<'a> {
    Upstream { name: &'a str },
    Static(RawStaticBackend<'a>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawStaticBackend<'a> {
    pub root: &'a str,
    pub flags: RawStaticFlags,
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawStaticFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotfiles: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlinks: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRouteTimeouts {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub connect: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub read: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub send: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawStreaming {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffering: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawUriRewrite<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strip_prefix: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strip_suffix: Option<&'a str>,
    pub replaces: Vec<(&'a str, &'a str)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing_slash: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawHeadersOps<'a> {
    pub set: Vec<(&'a str, &'a str)>,
    pub remove: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawHeadersRemove<'a> {
    pub remove: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRouteHeadersOpts<'a, D> {
    pub opts: RawHeadersOps<'a>,
    pub upstream: D,
}

// ============================================================================
// ROUTE POLICY INVOCATIONS / OVERRIDES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRoutePolicies<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RawRouteAction<'a, RawAuthConfig<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cors: Option<RawRouteAction<'a, RawCorsConfig<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf: Option<RawRouteAction<'a, RawWafConfig<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limiter: Option<RawRouteAction<'a, RawLimiterConfig<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helmet: Option<RawRouteAction<'a, RawHelmetConfig<'a>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawRouteAction<'a, T> {
    Ref { name: &'a str },
    Extends { base: &'a str, overrides: T },
    Inline(T),
}

// ============================================================================
// GLOBAL POLICIES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawAuthConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<RawAuthMode<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_proof: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<RawTokenSource<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RawRefreshConfig<'a>>,
    #[serde(default)]
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawAuthMode<'a> {
    Jwks {
        #[serde(skip_serializing_if = "Option::is_none")]
        uri: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
        ttl: Option<Duration>,
        algorithms: Vec<&'a str>,
    },
    Oidc {
        #[serde(skip_serializing_if = "Option::is_none")]
        discovery_url: Option<&'a str>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
        ttl: Option<Duration>,
    },
    Static {
        key: &'a str,
        alg: &'a str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawTokenSource<'a> {
    Header { name: &'a str, #[serde(skip_serializing_if = "Option::is_none")] prefix: Option<&'a str> },
    Cookie { name: &'a str, #[serde(skip_serializing_if = "Option::is_none")] prefix: Option<&'a str> },
    QueryParam { name: &'a str, #[serde(skip_serializing_if = "Option::is_none")] prefix: Option<&'a str> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawRefreshConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<RawTokenSource<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject: Option<RawInjectConfig<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawInjectConfig<'a> {
    pub access_token: Vec<RawInjectTarget<'a>>,
    pub refresh_token: Vec<RawInjectTarget<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawInjectTarget<'a> {
    Header { name: &'a str },
    Cookie(RawCookieConfig<'a>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawCookieConfig<'a> {
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<&'a str>,
}

// --- LIMITER ---

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawLimiterConfig<'a> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<(u64, Duration)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<&'a str>,
    #[serde(default)]
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawCorsConfig<'a> {
    pub allow_origins: Vec<&'a str>,
    pub allow_methods: Vec<&'a str>,
    pub allow_headers: Vec<&'a str>,
    pub expose_headers: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde::option")]
    pub max_age: Option<Duration>,
    #[serde(default)]
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawHelmetConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<&'a str>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawWafConfig<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_body_size: Option<ByteSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_threshold: Option<u32>,
    pub rules: Vec<RawWafRule<'a>>,
    #[serde(default)]
    pub exclude_paths: Vec<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RawWafRule<'a> {
    pub name: &'a str,
    pub phase: &'a str,
    pub action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    pub when: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'a str>,
}