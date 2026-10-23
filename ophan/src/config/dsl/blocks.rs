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

/// A secret given either inline or as an `env("NAME")` reference.
#[derive(Debug, Clone)]
pub enum RawSecretValue<'a> {
    Env(EnvVar<'a>),
    Literal(&'a str),
}

impl RawSecretValue<'_> {
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::Literal(value) => Ok((*value).to_owned()),
            Self::Env(env) => env.get_value().ok_or_else(|| format!("environment variable '{}' is not set", env.0)),
        }
    }
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
    pub metrics: Option<RawMetrics<'a>>,
}

#[derive(Debug, Clone)]
pub struct RawMetrics<'a> {
    pub listen: Option<&'a str>,
    pub path: Option<&'a str>,
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
    pub permissions: Option<&'a str>,
    pub firewall: Option<RawFirewall<'a>>,
    pub trusted_proxies: Option<RawTrustedProxies<'a>>,
    /// Deprecated: superseded by `firewall` and `trusted_proxies`.
    pub network_policy: Option<RawNetworkPolicy<'a>>,
    pub limits: Option<RawListenerLimits>,
    pub timeouts: Option<RawListenerTimeouts>,
}

#[derive(Debug, Clone, Default)]
pub struct RawFirewall<'a> {
    pub allow: Vec<&'a str>,
    pub deny: Vec<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub struct RawTrustedProxies<'a> {
    pub allowed_ips: Vec<&'a str>,
    pub real_ip_header: Option<&'a str>,
    pub on_untrusted: Option<&'a str>,
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
    pub policy: Option<&'a str>,
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
    Host(RawHostRoute<'a>),
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

/// Route settings as written in a `route`, `host` or `match` block; `None` means unset.
#[derive(Debug, Clone, Default)]
pub struct RawRouteFields<'a> {
    pub hosts: Option<Vec<&'a str>>,
    pub methods: Option<Vec<&'a str>>,
    pub protocols: Option<Vec<&'a str>>,
    pub backend: Option<RawBackend<'a>>,
    pub static_config: Option<(RawStaticFlags, Vec<&'a str>)>,
    pub timeouts: Option<RawRouteTimeouts>,
    pub streaming: Option<RawStreaming>,
    pub policies: Option<RawRoutePolicies<'a>>,
    pub rewrite: Option<RawUriRewrite<'a>>,
    pub inbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersOps<'a>>>,
    pub outbound_headers: Option<RawRouteHeadersOpts<'a, RawHeadersRemove<'a>>>,
}

impl<'a> RawRouteFields<'a> {
    /// The route for `path`, with `static_config` folded into a static backend.
    pub fn into_path_route(self, path: &'a str) -> Result<RawPathRoute<'a>, String> {
        let mut backend = self.backend.unwrap_or(RawBackend::Upstream(""));

        if let Some((flags, exclude_paths)) = self.static_config {
            let RawBackend::Static(ref mut sb) = backend else {
                return Err(format!("static_config requires a static backend in route '{path}'"));
            };

            sb.flags.listing = flags.listing.or(sb.flags.listing);
            sb.flags.dotfiles = flags.dotfiles.or(sb.flags.dotfiles);
            sb.flags.index = flags.index.or(sb.flags.index);
            sb.flags.symlinks = flags.symlinks.or(sb.flags.symlinks);
            sb.exclude_paths.extend(exclude_paths);
        }

        Ok(RawPathRoute {
            path,
            hosts: self.hosts.unwrap_or_default(),
            methods: self.methods.unwrap_or_default(),
            protocols: self.protocols.unwrap_or_default(),
            backend,
            timeouts: self.timeouts,
            streaming: self.streaming,
            policies: self.policies,
            rewrite: self.rewrite,
            inbound_headers: self.inbound_headers,
            outbound_headers: self.outbound_headers,
        })
    }

    /// These settings over the inherited `parent`.
    ///
    /// The backend (with its `static_config`), protocols, timeouts, streaming and rewrite
    /// are replaced as a whole. Policies are merged per kind and headers per name.
    fn over(self, parent: &Self) -> Self {
        let static_config = match self.backend {
            Some(_) => self.static_config,
            None => self.static_config.or_else(|| parent.static_config.clone()),
        };

        Self {
            hosts: self.hosts.or_else(|| parent.hosts.clone()),
            methods: self.methods.or_else(|| parent.methods.clone()),
            protocols: self.protocols.or_else(|| parent.protocols.clone()),
            backend: self.backend.or_else(|| parent.backend.clone()),
            static_config,
            timeouts: self.timeouts.or_else(|| parent.timeouts.clone()),
            streaming: self.streaming.or_else(|| parent.streaming.clone()),
            policies: RawRoutePolicies::merged(self.policies, parent.policies.as_ref()),
            rewrite: self.rewrite.or_else(|| parent.rewrite.clone()),
            inbound_headers: RawRouteHeadersOpts::merged(self.inbound_headers, parent.inbound_headers.as_ref()),
            outbound_headers: RawRouteHeadersOpts::merged(self.outbound_headers, parent.outbound_headers.as_ref()),
        }
    }
}

/// `host [..] { ... match "<methods> <path>" { ... } }`: routes of some hosts sharing settings.
#[derive(Debug, Clone)]
pub struct RawHostRoute<'a> {
    pub hosts: Vec<&'a str>,
    pub defaults: RawRouteFields<'a>,
    pub matches: Vec<RawMatchRoute<'a>>,
}

/// `match "GET|POST /path" { ... }`; without methods the path accepts every method.
#[derive(Debug, Clone)]
pub struct RawMatchRoute<'a> {
    pub pattern: &'a str,
    pub fields: RawRouteFields<'a>,
}

impl<'a> RawMatchRoute<'a> {
    /// Splits the pattern into its methods (empty for every method) and its path.
    pub fn methods_and_path(&self) -> Result<(Vec<&'a str>, &'a str), String> {
        let pattern = self.pattern.trim();

        let (methods, path) = match pattern.split_once(char::is_whitespace) {
            Some((methods, path)) => (methods.split('|').map(str::trim).collect::<Vec<_>>(), path.trim()),
            None => (Vec::new(), pattern),
        };

        if !path.starts_with('/') {
            return Err(format!(
                "match '{}': expected \"<METHOD|METHOD> /path\" or \"/path\"",
                self.pattern
            ));
        }

        if let Some(method) = methods.iter().find(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase())) {
            return Err(format!("match '{}': invalid method '{method}'", self.pattern));
        }

        Ok((methods, path))
    }
}

impl<'a> RawHostRoute<'a> {
    /// The path routes this block declares: one per `match`, or a `/*` route when the
    /// block has none. Every route inherits the block settings.
    pub fn expand(&self) -> Result<Vec<RawPathRoute<'a>>, String> {
        let mut defaults = self.defaults.clone();
        defaults.hosts = Some(self.hosts.clone());

        if self.matches.is_empty() {
            return defaults.into_path_route("/*").map(|route| vec![route]);
        }

        self.matches
            .iter()
            .map(|m| {
                let (methods, path) = m.methods_and_path()?;
                let mut fields = m.fields.clone().over(&defaults);
                if !methods.is_empty() {
                    fields.methods = Some(methods);
                }
                fields.into_path_route(path)
            })
            .collect()
    }
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

/// Header rules declared at a nested level over the ones it inherits.
pub trait InheritHeaders: Clone {
    fn over(self, parent: &Self) -> Self;
}

impl InheritHeaders for RawHeadersOps<'_> {
    /// The parent's `set` entries for headers this level sets or removes are dropped, and
    /// the parent's removals of headers this level sets.
    fn over(mut self, parent: &Self) -> Self {
        let named = |list: &[&str], name: &str| list.iter().any(|n| n.eq_ignore_ascii_case(name));
        let own_set: Vec<&str> = self.set.iter().map(|(name, _)| *name).collect();

        let inherited_set = parent
            .set
            .iter()
            .filter(|(name, _)| !named(&own_set, name) && !named(&self.remove, name))
            .cloned()
            .collect::<Vec<_>>();
        let inherited_remove = parent
            .remove
            .iter()
            .filter(|name| !named(&own_set, name) && !named(&self.remove, name))
            .copied()
            .collect::<Vec<_>>();

        self.set.splice(0..0, inherited_set);
        self.remove.splice(0..0, inherited_remove);
        self
    }
}

impl InheritHeaders for RawHeadersRemove<'_> {
    fn over(mut self, parent: &Self) -> Self {
        let inherited = parent
            .remove
            .iter()
            .filter(|name| !self.remove.iter().any(|own| own.eq_ignore_ascii_case(name)))
            .copied()
            .collect::<Vec<_>>();

        self.remove.splice(0..0, inherited);
        self
    }
}

impl<D: InheritHeaders> RawRouteHeadersOpts<'_, D> {
    fn merged(own: Option<Self>, parent: Option<&Self>) -> Option<Self> {
        match (own, parent) {
            (own, None) => own,
            (None, Some(parent)) => Some(parent.clone()),
            (Some(own), Some(parent)) => Some(Self {
                opts: own.opts.over(&parent.opts),
                upstream: own.upstream.over(&parent.upstream),
            }),
        }
    }
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

impl RawRoutePolicies<'_> {
    /// `own` over `parent`, kind by kind: a kind `own` sets, `off` included, replaces the parent's.
    fn merged(own: Option<Self>, parent: Option<&Self>) -> Option<Self> {
        match (own, parent) {
            (own, None) => own,
            (None, Some(parent)) => Some(parent.clone()),
            (Some(own), Some(parent)) => Some(Self {
                auth: own.auth.or_else(|| parent.auth.clone()),
                cors: own.cors.or_else(|| parent.cors.clone()),
                waf: own.waf.or_else(|| parent.waf.clone()),
                limiter: own.limiter.or_else(|| parent.limiter.clone()),
                helmet: own.helmet.or_else(|| parent.helmet.clone()),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RawRouteAction<'a, T> {
    Ref(&'a str),
    Extends {
        base: &'a str,
        overrides: T,
    },
    Inline(T),
    /// `<policy> = off`: no policy of this kind, overriding an inherited one.
    Off,
}

impl<T> RawRouteAction<'_, T> {
    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }
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
    pub client_secret: Option<RawSecretValue<'a>>,
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
