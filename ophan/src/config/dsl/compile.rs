use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ahash::AHashMap;
use ahash::HashMapExt;
use ahash::HashSetExt;
use ahash::{HashMap, HashSet};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flatkit::matchers::{GlobPattern, PathMatcherSet};
use flatkit::net::IpNet;
use flatkit::str::ImmerStr;
use http::HeaderName;
use http::HeaderValue;
use http::header;
use ophan_auth::crypto::{Algorithm, HmacAlg};
use ophan_auth::{AuthConfig as InnerAuthConfig, AuthMode, JwtValidatorConfig, OAuthClientConfig};
use ophan_net::http::HttpMethodSet;
use ophan_net::tls::{ALPN, TlsVersion};
use ophan_sec::l7::CompiledWafRules;
use ophan_sec::l7::WafConfig;
use ophan_sec::l7::WafMode;
// use ophan_sec::config::{WafAction, WafCondition, WafConfig, WafMode, WafPhase, WafRule};
use ophan_sec::l4::ListenerFirewall;
use ophan_sec::{OnUntrusted, TrustedProxies};
use ophan_static::FsFlags;

use crate::balancer::BalanceStrategy;
use crate::config::get_max_thread_size;

use crate::middlewares::auth::AuthConfig;
use crate::middlewares::auth::TokenSource;
use crate::middlewares::cors::{AllowedOrigins, CorsConfig};
use crate::middlewares::helmet::{HelmetConfig, HelmetLevel, HelmetTarget};
use crate::middlewares::limiter::LimiterConfig;
use crate::middlewares::limiter::LimiterIdentifier;
use crate::middlewares::limiter::LimiterRate;
use crate::middlewares::limiter::RateLimitAlgorithm;

use super::blocks::*;
use super::parser::parse_raw_master;
use crate::config::domain::*;

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    /// Warnings are reported but do not reject the configuration.
    pub warning: bool,
}

impl CompileError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into(), warning: false }
    }

    pub fn warning(msg: impl Into<String>) -> Self {
        Self { message: msg.into(), warning: true }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

type CResult<T> = Result<T, Vec<CompileError>>;

// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age
pub const CORS_MAX_AGE_LIMIT_SEC: u32 = 86400;

pub fn compile(raw: &RawConfig) -> CResult<OphanConfig> {
    let mut errors: Vec<CompileError> = Vec::new();
    let master = compile_master(&raw.master, &mut errors);
    let mut gateways = AHashMap::with_capacity(raw.gateways.len());

    let mut listeners = Vec::with_capacity(raw.gateways.iter().map(|(_, g)| g.listeners.len()).sum());
    let mut upstreams = Vec::with_capacity(raw.gateways.iter().map(|(_, g)| g.upstreams.len()).sum());

    for (name, gateway) in &raw.gateways {
        if let Some(compiled_gateway) = compile_gateway(gateway, &mut errors) {
            listeners.extend(compiled_gateway.listeners.iter().cloned());
            upstreams.extend(compiled_gateway.upstreams.iter().cloned());

            gateways.insert(ImmerStr::from(*name), compiled_gateway);
        }
    }

    let (warnings, errors): (Vec<_>, Vec<_>) = errors.into_iter().partition(|e| e.warning);

    for warning in &warnings {
        eprintln!("warning: {warning}");
        tracing::warn!("config: {warning}");
    }

    if errors.is_empty() {
        Ok(OphanConfig {
            master,
            gateways,
            listeners: listeners.into_boxed_slice(),
            upstreams: upstreams.into_boxed_slice(),
            master_tracker: None,
            gateway_trackers: AHashMap::new(),
        })
    } else {
        Err(errors)
    }
}

pub fn get_config_pid(config_path: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(config_path).ok()?;
    let raw = parse_raw_master(&content).ok()?;
    let pid = raw.pid.trim();
    if pid.is_empty() { None } else { Some(PathBuf::from(pid)) }
}

fn compile_master(raw: &RawMaster, errors: &mut Vec<CompileError>) -> MasterConfig {
    let name = raw.name.to_string();
    let user = raw.user.to_string();
    let pid = raw.pid.to_string();
    let error_log = raw.error_log.to_string();
    let includes: Vec<String> = raw.includes.iter().map(|s| s.to_string()).collect();

    let max_threads_size = get_max_thread_size().max(1);
    let workers = match &raw.workers {
        RawWorkers::Auto => max_threads_size,
        RawWorkers::Count(n) => {
            let n = *n;
            if n > max_threads_size * 4 {
                errors.push(CompileError::new(format!(
                    "workers count {} exceeds reasonable limit ({}), using {}",
                    n,
                    max_threads_size * 4,
                    max_threads_size
                )));

                max_threads_size
            } else if n == 0 {
                errors.push(CompileError::new("workers count must be at least 1".to_string()));
                1
            } else {
                n
            }
        },
    };

    let metrics = raw.metrics.as_ref().and_then(|m| compile_metrics(m, errors));

    MasterConfig {
        name: name.into(),
        user,
        workers,
        pid,
        error_log,
        includes: includes.into_boxed_slice(),
        metrics,
    }
}

fn compile_metrics(raw: &RawMetrics, errors: &mut Vec<CompileError>) -> Option<MetricsConfig> {
    let Some(listen) = raw.listen else {
        errors.push(CompileError::new("metrics: 'listen' is required".to_string()));
        return None;
    };

    let listen = match ListenerAddress::from_str(listen) {
        Ok(addr) => addr,
        Err(e) => {
            errors.push(CompileError::new(format!("metrics: invalid listen address '{listen}': {e}")));
            return None;
        },
    };

    let path = raw.path.unwrap_or("/metrics");
    if !path.starts_with('/') {
        errors.push(CompileError::new(format!("metrics: path '{path}' must start with '/'")));
        return None;
    }

    Some(MetricsConfig { listen, path: path.to_string() })
}

struct GatewayScope<'a> {
    auth: &'a HashMap<String, Arc<AuthConfig>>,
    waf: &'a HashMap<String, Arc<WafConfig>>,
    cors: &'a HashMap<String, Arc<CorsConfig>>,
    limiter: &'a HashMap<String, Arc<LimiterConfig>>,
    helmet: &'a HashMap<String, HelmetConfig>,
    upstreams: &'a HashMap<ImmerStr, Arc<UpstreamConfig>>,
}

// ============================================================================
// COMPILE GATEWAY
// ============================================================================

fn compile_gateway(raw: &RawGateway, errors: &mut Vec<CompileError>) -> Option<GatewayConfig> {
    let name = raw.name.to_string();

    let auth_map = build_auth_map(raw, errors);
    let waf_map = build_waf_map(raw, errors);
    let cors_map = build_cors_map(raw, errors);
    let limiter_map = build_limiter_map(raw, errors);
    let helmet_map = build_helmet_map(raw, errors);

    let upstreams: Vec<Arc<UpstreamConfig>> = raw
        .upstreams
        .iter()
        .enumerate()
        .filter_map(|(index, ru)| compile_upstream(index, ru, errors))
        .collect();
    let upstreams = upstreams.into_boxed_slice();

    let upstream_map = upstreams.iter().map(|u| (u.name.clone(), u.clone())).collect();

    validate_upstream_names(&upstreams, errors);

    let listeners: Vec<Arc<ListenerConfig>> = raw.listeners.iter().filter_map(|rl| compile_listener(rl, errors)).collect();
    let listeners = listeners.into_boxed_slice();

    validate_listeners(&listeners, errors);

    let scope = GatewayScope {
        auth: &auth_map,
        waf: &waf_map,
        cors: &cors_map,
        limiter: &limiter_map,
        helmet: &helmet_map,
        upstreams: &upstream_map,
    };

    let path_routes = expand_routes(&raw.routes, errors);
    let routes: Vec<Arc<RoutesConfig>> = path_routes.iter().filter_map(|route| compile_route(route, &scope, errors)).collect();

    Some(GatewayConfig {
        name: name.into(),
        listeners,
        upstreams,
        routes: routes.into_boxed_slice(),
    })
}

// ============================================================================
// POLICY MAP BUILDERS
// ============================================================================

fn build_auth_map(raw: &RawGateway, errors: &mut Vec<CompileError>) -> HashMap<String, Arc<AuthConfig>> {
    let mut map = HashMap::new();
    for rp in &raw.policies {
        if let RawPolicy::Auth { name, config } = rp {
            match build_auth_from_raw(config) {
                Ok(cfg) => {
                    map.insert(name.to_string(), Arc::new(cfg));
                },
                Err(e) => errors.push(CompileError::new(format!("policy auth '{}': {}", name, e))),
            }
        }
    }
    map
}

fn build_waf_map(raw: &RawGateway, errors: &mut Vec<CompileError>) -> HashMap<String, Arc<WafConfig>> {
    let mut map = HashMap::new();
    for rp in &raw.policies {
        if let RawPolicy::Waf { name, config } = rp {
            match build_waf_from_raw(config) {
                Ok(cfg) => {
                    map.insert(name.to_string(), Arc::new(cfg));
                },
                Err(e) => errors.push(CompileError::new(format!("policy waf '{}': {}", name, e))),
            }
        }
    }
    map
}

fn build_cors_map(raw: &RawGateway, errors: &mut Vec<CompileError>) -> HashMap<String, Arc<CorsConfig>> {
    let mut map = HashMap::new();
    for rp in &raw.policies {
        if let RawPolicy::Cors { name, config } = rp {
            match build_cors_from_raw(config) {
                Ok(cfg) => {
                    map.insert(name.to_string(), Arc::new(cfg));
                },
                Err(e) => errors.push(CompileError::new(format!("policy cors '{}': {}", name, e))),
            }
        }
    }
    map
}

fn build_limiter_map(raw: &RawGateway, errors: &mut Vec<CompileError>) -> HashMap<String, Arc<LimiterConfig>> {
    let mut map = HashMap::new();
    for rp in &raw.policies {
        if let RawPolicy::Limiter { name, config } = rp {
            match build_limiter_from_raw(config) {
                Ok(mut cfg) => {
                    cfg.scope = limiter_scope(&format!("policy:{name}"), &cfg);
                    map.insert(name.to_string(), Arc::new(cfg));
                },
                Err(e) => errors.push(CompileError::new(format!("policy limiter '{}': {}", name, e))),
            }
        }
    }
    map
}

// ============================================================================
// LISTENER
// ============================================================================

fn compile_listener(raw: &RawListener, errors: &mut Vec<CompileError>) -> Option<Arc<ListenerConfig>> {
    let name = raw.name.to_string();

    let address = match ListenerAddress::try_from(raw.address) {
        Ok(t) => t,
        Err(e) => {
            errors.push(CompileError::new(format!("listener '{}': {}", name, e)));
            return None;
        },
    };

    let mut protocols = Vec::with_capacity(raw.protocols.len());
    for p in &raw.protocols {
        match NetworkProtocol::try_from(*p) {
            Ok(proto) => protocols.push(proto),
            Err(e) => errors.push(CompileError::new(format!("listener '{}': {}", name, e))),
        }
    }

    let security = match &raw.tls {
        Some(ssl) => {
            if !Path::new(ssl.cert).exists() {
                errors.push(CompileError::new(format!(
                    "listener '{}': ssl cert '{}' not found",
                    name, ssl.cert
                )));
            }
            if !Path::new(ssl.key).exists() {
                errors.push(CompileError::new(format!(
                    "listener '{}': ssl key '{}' not found",
                    name, ssl.key
                )));
            }

            let min_version = if ssl.versions.is_empty() {
                TlsVersion::default()
            } else {
                TlsVersion::try_from(ssl.versions.as_slice())
                    .map_err(|e| {
                        errors.push(CompileError::new(format!("listener '{}': ssl version '{}' ", name, e)));
                    })
                    .ok()?
            };

            let client_ca = match ssl.client_ca {
                None => None,
                Some(path) => match std::fs::read(path) {
                    Ok(pem) => Some(pem),
                    Err(e) => {
                        errors.push(CompileError::new(format!(
                            "listener '{}': ssl client_ca '{}': {}",
                            name, path, e
                        )));
                        None
                    },
                },
            };

            let client_auth_required = match ssl.client_auth {
                None => client_ca.is_some(),
                Some("required") => true,
                Some("none") => false,
                Some("optional") => {
                    errors.push(CompileError::warning(format!(
                        "listener '{}': ssl client_auth = \"optional\" is not supported by the TLS backend, client certificates are not requested",
                        name
                    )));
                    false
                },
                Some(other) => {
                    errors.push(CompileError::new(format!(
                        "listener '{}': ssl client_auth '{}' is not supported, expected 'required', 'optional' or 'none'",
                        name, other
                    )));
                    false
                },
            };

            if client_auth_required && client_ca.is_none() {
                errors.push(CompileError::new(format!(
                    "listener '{}': ssl client_auth = \"required\" needs client_ca",
                    name
                )));
            }

            if !ssl.ciphers.is_empty() {
                errors.push(CompileError::warning(format!(
                    "listener '{}': ssl ciphers are ignored, the cipher suite follows the TLS versions policy",
                    name
                )));
            }

            let http2 = protocols.iter().any(NetworkProtocol::is_http2);

            SecurityConfig::Tls {
                certs: TlsCerts {
                    cert: ssl.cert.to_string(),
                    key: ssl.key.to_string(),
                    client_ca,
                    client_auth_required,
                },
                alpn_protocols: http2.then_some(ALPN::H2H1),
                min_version,
            }
        },
        None => SecurityConfig::default(),
    };

    let mut listener = ListenerConfig::new(name, address);
    listener.protocols = protocols.into_boxed_slice();
    listener.security = security;

    // Compile limits
    if let Some(ref limits) = raw.limits {
        if let Some(connections) = limits.connections {
            listener.connection.max_connections = Some(connections as u32);
            errors.push(CompileError::warning(format!(
                "listener '{}': limits.connections is not enforced yet",
                listener.name
            )));
        }
        if let Some(ref request_size) = limits.request_size {
            listener.connection.max_request_size = Some(*request_size);
        }
    }

    // Compile timeouts
    if let Some(ref timeouts) = raw.timeouts {
        listener.connection.idle_timeout = timeouts.idle;
        listener.connection.keepalive_timeout = timeouts.keepalive;
    }

    let (firewall, trusted_proxies) = compile_listener_access(raw, &listener.address, errors);
    listener.firewall = firewall;
    listener.trusted_proxies = trusted_proxies;
    listener.permissions = compile_permissions(raw.name, raw.permissions, &listener.address, errors);

    Some(Arc::new(listener))
}

// ============================================================================
// UPSTREAM
// ============================================================================

fn compile_upstream(index: usize, raw: &RawUpstream, errors: &mut Vec<CompileError>) -> Option<Arc<UpstreamConfig>> {
    let name = ImmerStr::new(raw.name);

    let balance_strategy = match raw.balance_strategy {
        Some(s) => match BalanceStrategy::from_str(s) {
            Ok(b) => b,
            Err(e) => {
                errors.push(CompileError::new(format!("upstream '{}': {}", name, e)));
                BalanceStrategy::default()
            },
        },
        None => BalanceStrategy::default(),
    };

    let servers = compile_servers(&name, &raw.static_servers, errors);
    let health_check = match &raw.health_check {
        Some(hc) => match compile_health_check(hc) {
            Ok(h) => Some(h),
            Err(e) => {
                errors.push(CompileError::new(format!("upstream '{}': {}", name, e)));
                None
            },
        },
        None => None,
    };

    Some(Arc::new(UpstreamConfig {
        id: UpstreamId(index),
        name,
        servers: servers.into_boxed_slice(),
        tls: None, // !TODO: implement TLS config for upstreams
        balance_strategy,
        health_check,
        circuit_breaker: None,
        discovery: None,
    }))
}

fn compile_servers(upstream_name: &str, servers: &[RawUpstreamServer], errors: &mut Vec<CompileError>) -> Vec<UpstreamServer> {
    servers
        .iter()
        .filter_map(|s| match parse_detailed_server(s) {
            Ok(s) => Some(s),
            Err(e) => {
                errors.push(CompileError::new(format!("upstream '{}': {}", upstream_name, e)));
                None
            },
        })
        .collect()
}

fn parse_detailed_server(raw: &RawUpstreamServer) -> Result<UpstreamServer, String> {
    let address = UpstreamAddress::try_from(raw.endpoint)?;
    let protocol = match raw.protocol {
        Some(s) => NetworkProtocol::try_from(s)?,
        None => NetworkProtocol::default(),
    };

    let mut server = UpstreamServer::new(address);

    server.weight = raw.weight as u32;
    server.protocol = protocol;

    Ok(server)
}

fn compile_health_check(raw: &RawHealthCheck) -> Result<HealthCheckConfig, String> {
    let path = match raw.path {
        Some(p) if !p.starts_with('/') => return Err(format!("health_check: path '{p}' must start with '/'")),
        Some(p) if p.bytes().any(|b| b.is_ascii_control() || b == b' ') => {
            return Err(format!("health_check: path '{p}' contains invalid characters"));
        },
        p => p.map(str::to_string),
    };
    let interval = raw.interval.unwrap_or(Duration::from_secs(10));
    let timeout = raw.timeout.unwrap_or(Duration::from_secs(5));
    let unhealthy_threshold = raw.unhealthy_threshold.unwrap_or(3);
    let healthy_threshold = raw.healthy_threshold.unwrap_or(2);

    Ok(HealthCheckConfig {
        path,
        interval,
        timeout,
        unhealthy_threshold,
        healthy_threshold,
    })
}

// ============================================================================
// ROUTE
// ============================================================================

/// Flattens `route` and `host` blocks into path routes, rejecting two routes of the same
/// host and path that share a method, or that are declared by both a `route` and a `host`
/// block.
fn expand_routes<'a>(raw: &[RawRoute<'a>], errors: &mut Vec<CompileError>) -> Vec<RawPathRoute<'a>> {
    let mut routes: Vec<(RawPathRoute<'a>, bool)> = Vec::with_capacity(raw.len());

    for route in raw {
        match route {
            RawRoute::Path(path) => routes.push((path.clone(), false)),
            RawRoute::Host(host) => match host.expand() {
                Ok(expanded) => routes.extend(expanded.into_iter().map(|route| (route, true))),
                Err(e) => errors.push(CompileError::new(format!("host {:?}: {e}", host.hosts))),
            },
        }
    }

    for (i, (a, a_from_host)) in routes.iter().enumerate() {
        for (b, b_from_host) in &routes[i + 1..] {
            if a.path.trim_end_matches('/') != b.path.trim_end_matches('/') {
                continue;
            }

            let Some(host) = shared_host(&a.hosts, &b.hosts) else {
                continue;
            };

            if a_from_host != b_from_host {
                errors.push(CompileError::new(format!(
                    "path '{}' on host '{host}' is declared by both a route block and a host block",
                    a.path
                )));
            } else if route_methods(a).intersects(&route_methods(b)) {
                errors.push(CompileError::new(format!(
                    "path '{}' on host '{host}' is declared twice with a common method",
                    a.path
                )));
            }
        }
    }

    routes.into_iter().map(|(route, _)| route).collect()
}

/// A host both lists serve; routes without hosts belong to the default host.
fn shared_host<'a>(a: &[&'a str], b: &[&str]) -> Option<&'a str> {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Some("*"),
        (false, false) => a.iter().copied().find(|h| b.iter().any(|o| o.eq_ignore_ascii_case(h))),
        _ => None,
    }
}

/// Methods a route accepts; none listed means all of them.
fn route_methods(route: &RawPathRoute) -> HttpMethodSet {
    match route.methods.is_empty() {
        true => HttpMethodSet::all(),
        false => HttpMethodSet::from_str_iter(&route.methods),
    }
}

fn compile_route(route: &RawPathRoute, scope: &GatewayScope, errors: &mut Vec<CompileError>) -> Option<Arc<RoutesConfig>> {
    let path = route.path.to_string();
    let hosts: Vec<String> = route.hosts.iter().map(|s| s.to_string()).collect();
    let methods = HttpMethodSet::from_str_iter(&route.methods);
    let backend = compile_route_backend(route, scope, errors)?;

    let mut protocols = Vec::with_capacity(route.protocols.len());
    for p in &route.protocols {
        match NetworkProtocol::try_from(*p) {
            Ok(proto) => protocols.push(proto),
            Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
        }
    }

    if !protocols.is_empty() {
        errors.push(CompileError::warning(format!(
            "route '{}': protocols is ignored, the upstream server protocol decides",
            path
        )));
    }

    let mut auth: Option<Arc<AuthConfig>> = None;
    let mut waf: Option<Arc<WafConfig>> = None;
    let mut cors: Option<Arc<CorsConfig>> = None;
    let mut limiter: Option<Arc<LimiterConfig>> = None;
    let mut helmet: Option<HelmetConfig> = None;

    if let Some(ref policies) = route.policies {
        if let Some(action) = policies.auth.as_ref().filter(|a| !a.is_off()) {
            match resolve_auth(action, scope) {
                Ok(cfg) => auth = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(action) = policies.waf.as_ref().filter(|a| !a.is_off()) {
            match resolve_waf(action, scope) {
                Ok(cfg) => waf = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
            errors.push(CompileError::warning(format!(
                "route '{}': the WAF engine is disabled in this build, the waf policy has no effect",
                path
            )));
        }
        if let Some(action) = policies.cors.as_ref().filter(|a| !a.is_off()) {
            match resolve_cors(action, scope) {
                Ok(cfg) => cors = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(action) = policies.helmet.as_ref() {
            match resolve_helmet(action, scope) {
                Ok(cfg) => helmet = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(action) = policies.limiter.as_ref().filter(|a| !a.is_off()) {
            let identity = match (route.hosts.is_empty(), route.methods.is_empty()) {
                (true, true) => path.clone(),
                _ => format!("{}|{}|{}", route.hosts.join(","), route.methods.join("|"), path),
            };
            match resolve_limiter(action, scope, &identity) {
                Ok(cfg) => limiter = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
    }

    let rewrite = route.rewrite.as_ref().map(compile_rewrite);
    let timeouts = route.timeouts.as_ref().map(|rt| RouteTimeouts {
        connect: rt.connect,
        read: rt.read,
        send: rt.send,
        ..Default::default()
    });
    let streaming = route.streaming.as_ref().map(|rs| RouteStreaming {
        buffering: rs.buffering.unwrap_or(true),
        chunked: rs.chunked.unwrap_or(true),
    });
    if route.streaming.as_ref().is_some_and(|rs| rs.chunked.is_some()) {
        errors.push(CompileError::warning(format!(
            "route '{}': streaming.chunked is ignored, framing follows the upstream response",
            path
        )));
    }
    let headers = compile_headers(&path, &route.inbound_headers, &route.outbound_headers, errors);

    Some(Arc::new(RoutesConfig {
        path,
        hosts: hosts.into_boxed_slice(),
        methods,
        protocols: protocols.into_boxed_slice(),
        backend,
        auth,
        waf,
        cors,
        limiter,
        helmet,
        rewrite,
        headers,
        timeouts,
        streaming,
    }))
}

fn compile_route_backend(route: &RawPathRoute, scope: &GatewayScope, errors: &mut Vec<CompileError>) -> Option<BackendTarget> {
    match &route.backend {
        RawBackend::Upstream(name) => match scope.upstreams.get(*name) {
            Some(arc) => Some(BackendTarget::Upstream(Arc::clone(arc))),
            None => {
                errors.push(CompileError::new(format!(
                    "route '{}': unknown upstream '{}'",
                    route.path, name
                )));
                None
            },
        },
        RawBackend::Static(sb) => {
            let root = sb.root.to_string();
            let flags = {
                let mut f = FsFlags::secure();
                if let Some(listing) = sb.flags.listing {
                    f.set(FsFlags::DIRECTORY_LIST, listing);
                }
                if let Some(dotfiles) = sb.flags.dotfiles {
                    f.set(FsFlags::DOTFILES, dotfiles);
                }
                if let Some(index) = sb.flags.index {
                    f.set(FsFlags::INDEX_FILES, index);
                }
                if let Some(symlinks) = sb.flags.symlinks {
                    f.set(FsFlags::FOLLOW_SYMLINKS, symlinks);
                }
                f
            };

            let blacklist = match compile_exclude_patterns(&sb.exclude_paths, "static backend") {
                Ok(set) => Some(set),
                Err(e) => {
                    errors.push(CompileError::new(format!("route '{}': {}", route.path, e)));
                    None
                },
            };
            let static_config = ophan_static::ServeConfig {
                root: PathBuf::from(root),
                skip_patterns: blacklist,
                flags,
                security_headers: ophan_static::SecurityHeaders::default(),
                cache_ttl: None,
                indexes: None,
            };

            Some(BackendTarget::Static(Arc::new(StaticUpstream::Local(static_config))))
        },
    }
}

fn compile_rewrite(raw: &RawUriRewrite) -> RouteRewrites {
    RouteRewrites {
        replaces: raw.replaces.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        strip_prefix: raw.strip_prefix.map(|p| p.to_owned()),
        strip_suffix: raw.strip_suffix.map(|p| p.to_owned()),
        trailing_slash: raw.trailing_slash.and_then(|a| a.parse().ok()),
    }
}

fn compile_headers(
    route: &str,
    inbound: &Option<RawRouteHeadersOpts<'_, RawHeadersOps<'_>>>,
    outbound: &Option<RawRouteHeadersOpts<'_, RawHeadersRemove<'_>>>,
    errors: &mut Vec<CompileError>,
) -> Option<HeaderMutations> {
    let mut header_set = |pairs: &[(&str, &str)]| -> AHashMap<HeaderName, HeaderValue> {
        pairs
            .iter()
            .filter_map(
                |(k, v)| match (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                    (Ok(name), Ok(value)) => Some((name, value)),
                    _ => {
                        errors.push(CompileError::new(format!("route '{route}': invalid header '{k}: {v}'")));
                        None
                    },
                },
            )
            .collect()
    };

    let inbound_set = inbound.as_ref().map(|h| (header_set(&h.opts.set), header_set(&h.upstream.set)));
    let outbound_set = outbound.as_ref().map(|h| header_set(&h.opts.set));

    let mut header_names = |names: &[&str]| -> Box<[HeaderName]> {
        names
            .iter()
            .filter_map(|k| match HeaderName::from_bytes(k.as_bytes()) {
                Ok(name) => Some(name),
                Err(_) => {
                    errors.push(CompileError::new(format!("route '{route}': invalid header name '{k}'")));
                    None
                },
            })
            .collect()
    };

    let inbound = inbound.as_ref().zip(inbound_set).map(|(h, (client_set, to_upstream_set))| InboundHeaderMutations {
        client_set,
        client_remove: header_names(&h.opts.remove),
        to_upstream_set,
        to_upstream_remove: header_names(&h.upstream.remove),
    });

    let outbound = outbound.as_ref().zip(outbound_set).map(|(h, client_set)| OutboundHeaderMutations {
        from_upstream_set: AHashMap::new(),
        from_upstream_remove: header_names(&h.upstream.remove),
        client_set,
        client_remove: header_names(&h.opts.remove),
    });

    let mutations = HeaderMutations {
        inbound: inbound.unwrap_or_default(),
        outbound: outbound.unwrap_or_default(),
    };

    (!mutations.is_empty()).then_some(mutations)
}

fn build_helmet_map(raw: &RawGateway, errors: &mut Vec<CompileError>) -> HashMap<String, HelmetConfig> {
    let mut map = HashMap::new();
    for rp in &raw.policies {
        if let RawPolicy::Helmet { name, config } = rp {
            match HelmetConfig::default().with_overrides(config.target, config.level) {
                Ok(cfg) => {
                    map.insert(name.to_string(), cfg);
                },
                Err(e) => errors.push(CompileError::new(format!("policy helmet '{}': {}", name, e))),
            }
        }
    }
    map
}

// ============================================================================
// POLICY RESOLUTION
// ============================================================================

fn resolve_auth(action: &RawRouteAction<RawAuthConfig>, scope: &GatewayScope) -> Result<Arc<AuthConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => scope.auth.get(*name).cloned().ok_or_else(|| format!("auth policy '{}' not found", name)),
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.auth.get(*base).ok_or_else(|| format!("auth policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_auth_override(&mut cfg, overrides)?;
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_auth_from_raw(config)?)),
        RawRouteAction::Off => Err("auth is off".into()),
    }
}

/// `off` keeps only the headers sent on every response (`X-Content-Type-Options`).
fn resolve_helmet(action: &RawRouteAction<RawHelmetConfig>, scope: &GatewayScope) -> Result<HelmetConfig, String> {
    match action {
        RawRouteAction::Ref(name) => {
            scope.helmet.get(*name).copied().ok_or_else(|| format!("helmet policy '{}' not found", name))
        },
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.helmet.get(*base).ok_or_else(|| format!("helmet policy '{}' not found", base))?;
            base.with_overrides(overrides.target, overrides.level)
        },
        RawRouteAction::Inline(config) => HelmetConfig::default().with_overrides(config.target, config.level),
        RawRouteAction::Off => Ok(HelmetConfig::new(HelmetTarget::default(), HelmetLevel::Disabled)),
    }
}

fn resolve_waf(action: &RawRouteAction<RawWafConfig>, scope: &GatewayScope) -> Result<Arc<WafConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => scope.waf.get(*name).cloned().ok_or_else(|| format!("waf policy '{}' not found", name)),
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.waf.get(*base).ok_or_else(|| format!("waf policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_waf_override(&mut cfg, overrides)?;
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_waf_from_raw(config)?)),
        RawRouteAction::Off => Err("waf is off".into()),
    }
}

fn resolve_cors(action: &RawRouteAction<RawCorsConfig>, scope: &GatewayScope) -> Result<Arc<CorsConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => scope.cors.get(*name).cloned().ok_or_else(|| format!("cors policy '{}' not found", name)),
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.cors.get(*base).ok_or_else(|| format!("cors policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_cors_override(&mut cfg, overrides);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_cors_from_raw(config)?)),
        RawRouteAction::Off => Err("cors is off".into()),
    }
}

/// Stable identity of a limiter policy instance. It only changes when the policy itself
/// changes, so a reload keeps the counters of untouched policies.
fn limiter_scope(origin: &str, cfg: &LimiterConfig) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::hash::DefaultHasher::new();
    origin.hash(&mut hasher);
    format!("{:?}|{}|{:?}|{:?}", cfg.rate, cfg.burst, cfg.algorithm, cfg.identifier).hash(&mut hasher);
    hasher.finish()
}

fn resolve_limiter(
    action: &RawRouteAction<RawLimiterConfig>,
    scope: &GatewayScope,
    route: &str,
) -> Result<Arc<LimiterConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => {
            scope.limiter.get(*name).cloned().ok_or_else(|| format!("limiter policy '{}' not found", name))
        },
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.limiter.get(*base).ok_or_else(|| format!("limiter policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_limiter_override(&mut cfg, overrides)?;
            cfg.scope = limiter_scope(&format!("route:{route}:extends"), &cfg);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => {
            let mut cfg = build_limiter_from_raw(config)?;
            cfg.scope = limiter_scope(&format!("route:{route}"), &cfg);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Off => Err("limiter is off".into()),
    }
}

// ============================================================================
// POLICY BUILDERS (from RawPolicy fields)
// ============================================================================

/// Compiles `exclude_paths` glob patterns, naming the offending pattern on error.
fn compile_exclude_patterns(patterns: &[&str], context: &str) -> Result<PathMatcherSet, String> {
    let compiled = patterns
        .iter()
        .map(|p| GlobPattern::compile(*p).map_err(|e| format!("{context}: invalid exclude_paths pattern '{p}': {e}")))
        .collect::<Result<Box<[GlobPattern]>, String>>()?;

    Ok(PathMatcherSet::from_patterns(&compiled))
}

fn build_auth_from_raw(raw: &RawAuthConfig) -> Result<AuthConfig, String> {
    let issuer = raw.issuer.ok_or_else(|| "auth: issuer is required".to_string())?;
    let audience = raw.audience.ok_or_else(|| "auth: audience is required".to_string())?;

    let validator = JwtValidatorConfig::new(issuer).with_audiences(vec![ImmerStr::from(audience)]);

    let dpop_policy = raw.dpop_proof.and_then(|dpop| dpop.parse().ok()).unwrap_or_default();

    let (auth_mode, key_cache_ttl) = match raw.mode.as_ref() {
        Some(RawAuthMode::Jwks { uri, algorithms, ttl }) => {
            let algs = algorithms.iter().filter_map(|a| Algorithm::from_str(a).ok()).collect::<Vec<_>>();
            let uri = uri.as_deref().map(str::to_owned).unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer));

            (AuthMode::new_jwks(uri, algs.into_boxed_slice()), *ttl)
        },
        Some(RawAuthMode::Oidc { discovery_url, ttl }) => {
            let url = discovery_url
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{}/.well-known/openid-configuration", issuer));

            (AuthMode::new_oidc(url), *ttl)
        },
        Some(RawAuthMode::Static { secret_key, alg }) => {
            let key_bytes = match secret_key {
                RawSecretKey::Env(env) => {
                    let value = env.get_value().ok_or_else(|| format!("environment variable '{}' is not set", env.0))?;

                    URL_SAFE_NO_PAD
                        .decode(value)
                        .map_err(|e| format!("invalid base64 in environment variable '{}': {e}", env.0))?
                },

                RawSecretKey::Base64(value) => {
                    URL_SAFE_NO_PAD.decode(value).map_err(|e| format!("invalid base64 secret key: {e}"))?
                },
            };

            let alg = HmacAlg::from_str(alg).map_err(|_| format!("unsupported HMAC algorithm: {alg}"))?;

            (AuthMode::new_static(&key_bytes, alg), None)
        },
        None => {
            let discovery_url = format!("{}/.well-known/openid-configuration", issuer);
            (AuthMode::new_oidc(discovery_url), None)
        },
    };

    let mut inner_config = InnerAuthConfig::new(validator, auth_mode)
        .with_dpop_policy(dpop_policy)
        .with_key_cache_ttl(key_cache_ttl);

    let refresh_enabled = raw.refresh.as_ref().is_some_and(|r| r.enabled.unwrap_or(true));
    if let Some(client_id) = raw.client_id {
        let mut oauth_client = OAuthClientConfig::new(client_id);
        if let Some(secret) = raw.client_secret.as_ref() {
            oauth_client = oauth_client.with_secret(secret.resolve().map_err(|e| format!("auth: client_secret: {e}"))?);
        }
        if let Some(endpoint) = raw.refresh.as_ref().and_then(|r| r.endpoint) {
            oauth_client = oauth_client.with_token_endpoint(endpoint);
        }
        if refresh_enabled {
            oauth_client = oauth_client.enable_refresh_flow();
        }
        inner_config = inner_config.with_oauth_client(oauth_client);
    } else if refresh_enabled {
        return Err("auth: refresh requires client_id".to_string());
    }

    // Compile inject → TokenDestination
    let inject_access_token_into: Box<[crate::middlewares::auth::TokenDestination]> = raw
        .refresh
        .as_ref()
        .and_then(|r| r.inject.as_ref())
        .map(|i| i.access_token.iter().map(compile_inject_target).collect())
        .unwrap_or_default();
    let inject_refresh_token_into: Box<[crate::middlewares::auth::TokenDestination]> = raw
        .refresh
        .as_ref()
        .and_then(|r| r.inject.as_ref())
        .map(|i| i.refresh_token.iter().map(compile_inject_target).collect())
        .unwrap_or_default();

    // Compile refresh sources
    let refresh_sources = raw.refresh.as_ref().and_then(|r| r.sources.as_ref().map(compile_token_source)).transpose()?;

    // Compile skip_patterns from exclude_paths
    let skip_patterns = if raw.exclude_paths.is_empty() {
        None
    } else {
        Some(compile_exclude_patterns(&raw.exclude_paths, "auth")?)
    };

    let sources = match raw.sources.as_ref() {
        Some(sources) => sources.iter().map(compile_token_source).collect::<Result<_, _>>()?,
        None => Box::new([TokenSource::bearer()]) as Box<[TokenSource]>,
    };
    let dpop_source = (!inner_config.dpop_policy.is_disabled()).then(TokenSource::dpop);

    Ok(AuthConfig {
        client: inner_config,
        sources,
        refresh_sources,
        dpop_source,
        inject_access_token_into,
        inject_refresh_token_into,
        token_ttl: None,
        refresh_token_ttl: None,
        skip_patterns,
    })
}

fn build_waf_from_raw(raw: &RawWafConfig) -> Result<WafConfig, String> {
    let mut cfg = WafConfig::default();
    if let Some(mode) = raw.mode {
        cfg.mode = WafMode::from_str(mode).map_err(|_| {
            format!(
                "invalid waf mode '{}', expected one of: detection_only, block, blocking",
                mode
            )
        })?
    }
    if let Some(size) = raw.max_body_size {
        cfg.max_body_size = size;
    }
    if let Some(threshold) = raw.anomaly_threshold {
        cfg.anomaly_threshold = threshold;
    }
    if !raw.exclude_paths.is_empty() {
        cfg.skip_patterns = Some(compile_exclude_patterns(&raw.exclude_paths, "waf")?);
    }

    cfg.compiled = compile_waf_rules(&raw.rules);
    // cfg.compiled = Arc::new(WafPhasesTable::compile(&cfg.rules));
    Ok(cfg)
}

fn build_cors_from_raw(raw: &RawCorsConfig) -> Result<CorsConfig, String> {
    let allow_origins = AllowedOrigins::try_from(raw.allow_origins.clone()).map_err(|e| e.to_string())?;
    let allow_credentials = raw.allow_credentials.unwrap_or(false);
    let max_age = raw.max_age;

    let allow_methods = if raw.allow_methods.is_empty() {
        None
    } else {
        Some(
            raw.allow_methods
                .join(", ")
                .parse::<HeaderValue>()
                .map_err(|_| "invalid allow_methods header value".to_string())?,
        )
    };

    let allow_headers = if raw.allow_headers.is_empty() {
        None
    } else {
        Some(
            raw.allow_headers
                .join(", ")
                .parse::<HeaderValue>()
                .map_err(|_| "invalid allow_headers header value".to_string())?,
        )
    };

    let allow_expose_headers = if raw.expose_headers.is_empty() {
        None
    } else {
        Some(
            raw.expose_headers
                .join(", ")
                .parse::<HeaderValue>()
                .map_err(|_| "invalid expose_headers header value".to_string())?,
        )
    };

    let allow_max_age = max_age.map(|secs| HeaderValue::from(secs.as_secs()));

    Ok(CorsConfig {
        allow_origins,
        allow_credentials,
        max_age,
        allow_methods,
        allow_headers,
        allow_expose_headers,
        allow_max_age,
    })
}

fn build_limiter_from_raw(raw: &RawLimiterConfig) -> Result<LimiterConfig, String> {
    let mut cfg = LimiterConfig::default();
    if let Some(rate) = raw.rate {
        cfg.rate = LimiterRate::from(rate);
    }
    if let Some(burst) = raw.burst {
        cfg.burst = burst;
    }
    if let Some(algo) = raw.strategy {
        cfg.algorithm = RateLimitAlgorithm::from_str(algo).map_err(|a| a.to_string())?;
    }
    if let Some(id) = raw.identifier {
        cfg.identifier = LimiterIdentifier::from_str(id).map_err(|a| a.to_string())?;
    }
    if !raw.exclude_paths.is_empty() {
        cfg.skip_patterns = Some(compile_exclude_patterns(&raw.exclude_paths, "limiter")?);
    }

    Ok(cfg)
}

// ============================================================================
// AUTH merge (route-level overrides)
// ============================================================================

fn merge_auth_override(cfg: &mut AuthConfig, overrides: &RawAuthConfig) -> Result<(), String> {
    if let Some(issuer) = overrides.issuer {
        cfg.client.validator.set_issuers(vec![ImmerStr::from(issuer)]);
    }
    if let Some(audience) = overrides.audience {
        cfg.client.validator.set_audiences(vec![ImmerStr::from(audience)]);
    }
    if let Some(ref mode) = overrides.mode {
        cfg.client.auth_mode = match mode {
            RawAuthMode::Jwks { uri, algorithms, ttl } => {
                let algs = algorithms.iter().filter_map(|a| Algorithm::from_str(a).ok()).collect::<Vec<_>>();
                let uri_str = uri.as_deref().unwrap_or("");
                cfg.client.key_cache_ttl = *ttl;
                AuthMode::new_jwks(uri_str.to_string(), algs.into_boxed_slice())
            },
            RawAuthMode::Oidc { discovery_url, ttl } => {
                let url = discovery_url.as_deref().unwrap_or("");
                cfg.client.key_cache_ttl = *ttl;
                AuthMode::new_oidc(url.to_owned())
            },
            RawAuthMode::Static { secret_key, alg } => {
                let key_bytes = match secret_key {
                    RawSecretKey::Env(env) => {
                        let value = env.get_value().unwrap();

                        URL_SAFE_NO_PAD.decode(value).unwrap()
                    },

                    RawSecretKey::Base64(value) => URL_SAFE_NO_PAD.decode(value).unwrap(),
                };

                let alg = HmacAlg::from_str(alg).unwrap_or_default();

                AuthMode::new_static(&key_bytes, alg)
            },
        };
    }
    if let Some(ref sources) = overrides.sources {
        cfg.sources = sources.iter().map(compile_token_source).collect::<Result<_, _>>()?;
    }
    if let Some(ref refresh) = overrides.refresh {
        cfg.refresh_sources = refresh.sources.as_ref().map(compile_token_source).transpose()?;
        if let Some(ref inject) = refresh.inject {
            cfg.inject_access_token_into = inject.access_token.iter().map(compile_inject_target).collect();
            cfg.inject_refresh_token_into = inject.refresh_token.iter().map(compile_inject_target).collect();
        }
    }
    if !overrides.exclude_paths.is_empty() {
        cfg.skip_patterns = Some(compile_exclude_patterns(&overrides.exclude_paths, "auth override")?);
    }

    Ok(())
}

fn compile_token_source(raw: &RawTokenSource) -> Result<TokenSource, String> {
    Ok(match raw {
        RawTokenSource::Header { name, prefix } => {
            TokenSource::header(name, *prefix).map_err(|e| format!("auth: invalid header name '{name}': {e}"))?
        },
        RawTokenSource::Cookie { name, prefix } => TokenSource::Cookie {
            name: name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        },
        RawTokenSource::QueryParam { name, prefix } => TokenSource::QueryParam {
            name: name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        },
    })
}

fn compile_inject_target(raw: &RawInjectTarget) -> crate::middlewares::auth::TokenDestination {
    match raw {
        RawInjectTarget::Header { name } => crate::middlewares::auth::TokenDestination::Header {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap_or(header::AUTHORIZATION),
        },
        RawInjectTarget::Cookie(cookie) => crate::middlewares::auth::TokenDestination::Cookie {
            name: cookie.name.to_string(),
            path: cookie.path.unwrap_or("/").to_string(),
        },
    }
}

fn compile_waf_rules(_raw: &[RawWafRule]) -> Arc<CompiledWafRules> {
    // raw.iter()
    //     .map(|r| WafRule {
    //         id: r.name.to_string(),
    //         phase: match r.phase {
    //             "request_headers" => WafPhase::RequestHeaders,
    //             "request_body" => WafPhase::RequestBody,
    //             "response_headers" => WafPhase::ResponseHeaders,
    //             "response_body" => WafPhase::ResponseBody,
    //             _ => WafPhase::RequestBody,
    //         },
    //         condition: if r.when.is_empty() {
    //             WafCondition::BodyContains(vec![])
    //         } else {
    //             WafCondition::BodyContains(vec![r.when.to_string()])
    //         },
    //         action: match r.action {
    //             "log" => WafAction::Log,
    //             "block" => WafAction::Block,
    //             "allow" => WafAction::Allow,
    //             _ => WafAction::Block,
    //         },
    //         score: r.score.unwrap_or(0),
    //     })
    //     .collect()

    Arc::new(CompiledWafRules::default())
}

// ============================================================================
// WAF merge (route-level overrides)
// ============================================================================

fn merge_waf_override(cfg: &mut WafConfig, overrides: &RawWafConfig) -> Result<(), String> {
    if let Some(v) = overrides.mode {
        cfg.mode = match v {
            "detection_only" => WafMode::DetectionOnly,
            "block" | "blocking" => WafMode::Blocking,
            _ => cfg.mode, // keep existing mode for invalid values
        };
    }
    if let Some(size) = overrides.max_body_size {
        cfg.max_body_size = size;
    }
    if let Some(v) = overrides.anomaly_threshold {
        cfg.anomaly_threshold = v;
    }
    if !overrides.exclude_paths.is_empty() {
        cfg.skip_patterns = Some(compile_exclude_patterns(&overrides.exclude_paths, "waf override")?);
    }
    if !overrides.rules.is_empty() {
        cfg.compiled = compile_waf_rules(&overrides.rules);
    }

    Ok(())
}

// ============================================================================
// CORS merge (route-level overrides)
// ============================================================================

fn merge_cors_override(cfg: &mut CorsConfig, overrides: &RawCorsConfig) {
    if !overrides.allow_origins.is_empty() {
        cfg.allow_origins = AllowedOrigins::try_from(overrides.allow_origins.clone()).expect("invalid cors origin");
    }
    if let Some(v) = overrides.allow_credentials {
        cfg.allow_credentials = v;
    }
    if let Some(max_age) = overrides.max_age {
        // validate if max_age is safe limit
        // see https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age
        if max_age.as_secs() <= CORS_MAX_AGE_LIMIT_SEC as u64 {
            let max_age_value = max_age.as_secs();
            cfg.allow_max_age = Some(HeaderValue::from(max_age_value));

            cfg.max_age = Some(max_age);
        }
    }
    if !overrides.allow_methods.is_empty() {
        cfg.allow_methods = Some(overrides.allow_methods.join(", ").parse::<HeaderValue>().expect("valid header value"));
    }
    if !overrides.allow_headers.is_empty() {
        cfg.allow_headers = Some(overrides.allow_headers.join(", ").parse::<HeaderValue>().expect("valid header value"));
    }
    if !overrides.expose_headers.is_empty() {
        cfg.allow_expose_headers = Some(overrides.expose_headers.join(", ").parse::<HeaderValue>().expect("valid header value"));
    }
}

// ============================================================================
// LIMITER merge (route-level overrides)
// ============================================================================

fn merge_limiter_override(cfg: &mut LimiterConfig, overrides: &RawLimiterConfig) -> Result<(), String> {
    if let Some(rate) = overrides.rate {
        cfg.rate = LimiterRate::from(rate);
    }
    if let Some(v) = overrides.burst {
        cfg.burst = v;
    }
    if let Some(v) = overrides.strategy {
        cfg.algorithm = RateLimitAlgorithm::try_from(v).unwrap_or_default();
    }
    if let Some(v) = overrides.identifier {
        cfg.identifier = match v {
            "ip" => LimiterIdentifier::Ip,
            other => LimiterIdentifier::Header(other.to_string()),
        };
    }
    if !overrides.exclude_paths.is_empty() {
        cfg.skip_patterns = Some(compile_exclude_patterns(&overrides.exclude_paths, "limiter override")?);
    }

    Ok(())
}

// ============================================================================
// LISTENER ACCESS (firewall + trusted proxies)
// ============================================================================

type ListenerAccess = (Option<Arc<ListenerFirewall>>, Option<Arc<TrustedProxies>>);

fn compile_listener_access(raw: &RawListener, address: &ListenerAddress, errors: &mut Vec<CompileError>) -> ListenerAccess {
    let name = raw.name;
    let legacy = raw.network_policy.as_ref();

    if legacy.is_some() && (raw.firewall.is_some() || raw.trusted_proxies.is_some()) {
        errors.push(CompileError::new(format!(
            "listener '{name}': network_policy cannot be combined with firewall or trusted_proxies"
        )));
        return (None, None);
    }

    let (firewall, trusted) = match legacy {
        None => (raw.firewall.clone(), raw.trusted_proxies.clone()),
        Some(policy) => {
            errors.push(CompileError::warning(format!(
                "listener '{name}': network_policy is deprecated, use `firewall` and `trusted_proxies`"
            )));
            legacy_listener_access(policy)
        },
    };

    let is_unix = !matches!(address, ListenerAddress::Tcp(_));

    let firewall = firewall.and_then(|fw| {
        if is_unix {
            errors.push(CompileError::new(format!(
                "listener '{name}': firewall does not apply to unix sockets, restrict access with `permissions`"
            )));
            return None;
        }

        let allow = parse_ip_ranges(name, "firewall.allow", &fw.allow, errors);
        let deny = parse_ip_ranges(name, "firewall.deny", &fw.deny, errors);

        Some(Arc::new(ListenerFirewall::new(&allow, &deny)))
    });

    let trusted = match trusted {
        Some(tp) => compile_trusted_proxies(name, &tp, is_unix, errors),
        None if is_unix => {
            errors.push(CompileError::new(format!(
                "listener '{name}': unix sockets have no client address, `trusted_proxies.real_ip_header` is required"
            )));
            None
        },
        None => None,
    };

    (firewall, trusted)
}

fn compile_trusted_proxies(
    name: &str,
    raw: &RawTrustedProxies,
    is_unix: bool,
    errors: &mut Vec<CompileError>,
) -> Option<Arc<TrustedProxies>> {
    let allowed_ips = parse_ip_ranges(name, "trusted_proxies.allowed_ips", &raw.allowed_ips, errors);

    if allowed_ips.iter().any(|net| net.prefix() == 0) {
        errors.push(CompileError::new(format!(
            "listener '{name}': trusted_proxies.allowed_ips cannot contain 0.0.0.0/0 or ::/0, anyone could forge the client address"
        )));
    }

    let real_ip_header = match raw.real_ip_header.map(HeaderName::from_str) {
        None => None,
        Some(Ok(header)) => Some(header),
        Some(Err(_)) => {
            errors.push(CompileError::new(format!(
                "listener '{name}': invalid trusted_proxies.real_ip_header '{}'",
                raw.real_ip_header.unwrap_or_default()
            )));
            None
        },
    };

    let on_untrusted = match raw.on_untrusted.map(OnUntrusted::try_from) {
        None => OnUntrusted::default(),
        Some(Ok(mode)) => mode,
        Some(Err(e)) => {
            errors.push(CompileError::new(format!("listener '{name}': {e}")));
            OnUntrusted::default()
        },
    };

    if is_unix {
        if !allowed_ips.is_empty() || raw.on_untrusted.is_some() {
            errors.push(CompileError::new(format!(
                "listener '{name}': unix sockets have no peer address, only `real_ip_header` applies"
            )));
        }
        if raw.real_ip_header.is_none() {
            errors.push(CompileError::new(format!(
                "listener '{name}': unix sockets have no client address, `trusted_proxies.real_ip_header` is required"
            )));
        }
    } else {
        if allowed_ips.is_empty() && raw.real_ip_header.is_some() {
            errors.push(CompileError::new(format!(
                "listener '{name}': trusted_proxies.real_ip_header needs allowed_ips, the header is only read from those proxies"
            )));
        }
        if allowed_ips.is_empty() && on_untrusted == OnUntrusted::Reject {
            errors.push(CompileError::new(format!(
                "listener '{name}': on_untrusted = \"reject\" needs allowed_ips, otherwise every connection is rejected"
            )));
        }
    }

    Some(Arc::new(TrustedProxies::new(&allowed_ips, real_ip_header, on_untrusted)))
}

/// Maps the deprecated `network_policy` block onto `firewall` and `trusted_proxies`.
fn legacy_listener_access<'a>(policy: &RawNetworkPolicy<'a>) -> (Option<RawFirewall<'a>>, Option<RawTrustedProxies<'a>>) {
    let firewall = (!policy.allowed_ip_ranges.is_empty() || !policy.blocked_ip_ranges.is_empty()).then(|| RawFirewall {
        allow: policy.allowed_ip_ranges.clone(),
        deny: policy.blocked_ip_ranges.clone(),
    });

    let trusted = policy.proxy_allowed_ips.as_ref().map(|proxies| RawTrustedProxies {
        allowed_ips: proxies.clone(),
        real_ip_header: Some(policy.real_ip_header.unwrap_or("X-Forwarded-For")),
        on_untrusted: policy.policy.map(|mode| if mode.eq_ignore_ascii_case("deny") { "reject" } else { mode }),
    });

    (firewall, trusted)
}

fn parse_ip_ranges(name: &str, field: &str, ranges: &[&str], errors: &mut Vec<CompileError>) -> Vec<IpNet> {
    ranges
        .iter()
        .filter_map(|range| match range.parse::<IpNet>() {
            Ok(net) => Some(net),
            Err(e) => {
                errors.push(CompileError::new(format!("listener '{name}': {field} '{range}': {e}")));
                None
            },
        })
        .collect()
}

fn compile_permissions(name: &str, raw: Option<&str>, address: &ListenerAddress, errors: &mut Vec<CompileError>) -> Option<u32> {
    let raw = raw?;

    if matches!(address, ListenerAddress::Tcp(_)) {
        errors.push(CompileError::new(format!(
            "listener '{name}': permissions only apply to unix sockets"
        )));
        return None;
    }

    match u32::from_str_radix(raw.trim_start_matches("0o"), 8) {
        Ok(mode) if mode <= 0o777 => Some(mode),
        _ => {
            errors.push(CompileError::new(format!(
                "listener '{name}': invalid permissions '{raw}', expected an octal mode like \"0660\""
            )));
            None
        },
    }
}

// ============================================================================
// VALIDATION
// ============================================================================

fn validate_listeners(listeners: &[Arc<ListenerConfig>], errors: &mut Vec<CompileError>) {
    let mut seen: HashSet<String> = HashSet::with_capacity(listeners.len());
    for l in listeners {
        let addr = format!("{:?}", l.address);
        if !seen.insert(addr.clone()) {
            errors.push(CompileError::new(format!("listener '{}': {} already bound", l.name, addr)));
        }
    }
}

fn validate_upstream_names(upstreams: &[Arc<UpstreamConfig>], errors: &mut Vec<CompileError>) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(upstreams.len());
    for u in upstreams {
        if !seen.insert(&u.name) {
            errors.push(CompileError::new(format!("upstream '{}' defined multiple times", u.name)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener_from(dsl: &str) -> (Option<Arc<ListenerConfig>>, Vec<CompileError>) {
        let source = format!("listeners {{ {dsl} }}");
        let raw = crate::config::dsl::parser::parse_raw_gateway(&source).expect("valid syntax");
        let mut errors = Vec::new();
        let listener = compile_listener(&raw.listeners[0], &mut errors);
        (listener, errors)
    }

    fn fatal(errors: &[CompileError]) -> Vec<&str> {
        errors.iter().filter(|e| !e.warning).map(|e| e.message.as_str()).collect()
    }

    fn gateway_from(routes: &str) -> (Option<GatewayConfig>, Vec<CompileError>) {
        let source = format!(
            r#"name = "gw"
            listeners {{ listener "http" {{ address = "127.0.0.1:8080" }} }}
            upstreams {{
                upstream "api" {{ static_servers = ["127.0.0.1:3000"] }}
                upstream "users" {{ static_servers = ["127.0.0.1:3001"] }}
            }}
            routes {{ {routes} }}
            policy limiter "default" {{ rate = 10/s identifier = "ip" }}
            policy cors "web" {{ allow_origins = ["app.example.com"] }}"#
        );
        let raw = crate::config::dsl::parser::parse_raw_gateway(&source).expect("valid syntax");
        let mut errors = Vec::new();
        let gateway = compile_gateway(&raw, &mut errors);
        (gateway, errors)
    }

    fn upstream_of(route: &RoutesConfig) -> &str {
        match &route.backend {
            BackendTarget::Upstream(upstream) => &upstream.name,
            BackendTarget::Static(_) => "static",
        }
    }

    fn route<'a>(gateway: &'a GatewayConfig, path: &str) -> &'a RoutesConfig {
        gateway.routes.iter().find(|r| r.path == path).unwrap_or_else(|| panic!("no route for {path}"))
    }

    fn helmet_gateway(routes: &str) -> (Option<GatewayConfig>, Vec<CompileError>) {
        let source = format!(
            r#"name = "gw"
            listeners {{ listener "http" {{ address = "127.0.0.1:8080" }} }}
            upstreams {{ upstream "api" {{ static_servers = ["127.0.0.1:3000"] }} }}
            routes {{ {routes} }}
            policy helmet "api-strict" {{ target = "api" level = "strict" }}"#
        );
        let raw = crate::config::dsl::parser::parse_raw_gateway(&source).expect("valid syntax");
        let mut errors = Vec::new();
        let gateway = compile_gateway(&raw, &mut errors);
        (gateway, errors)
    }

    #[test]
    fn route_helmet_policies_are_compiled() {
        let (gateway, errors) = helmet_gateway(
            r#"route "/ref" { backend = upstream("api") policies { helmet = "api-strict" } }
            route "/extends" { backend = upstream("api") policies { helmet extends "api-strict" { level = "standard" } } }
            route "/inline" { backend = upstream("api") policies { helmet { target = "api" } } }
            route "/off" { backend = upstream("api") policies { helmet = off } }
            route "/default" { backend = upstream("api") }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        let gateway = gateway.unwrap();

        assert_eq!(
            route(&gateway, "/ref").helmet,
            Some(HelmetConfig::new(HelmetTarget::Api, HelmetLevel::Strict))
        );
        assert_eq!(
            route(&gateway, "/extends").helmet,
            Some(HelmetConfig::new(HelmetTarget::Api, HelmetLevel::Standard))
        );
        assert_eq!(
            route(&gateway, "/inline").helmet,
            Some(HelmetConfig::new(HelmetTarget::Api, HelmetLevel::Standard))
        );
        assert_eq!(route(&gateway, "/off").helmet.map(|h| h.level), Some(HelmetLevel::Disabled));
        assert_eq!(route(&gateway, "/default").helmet, None);
    }

    #[test]
    fn helmet_off_overrides_the_host_policy() {
        let (gateway, errors) = helmet_gateway(
            r#"host "example.com" {
                backend = upstream("api")
                policies { helmet = "api-strict" }
                match "/app/*" { }
                match "/raw/*" { policies { helmet = off } }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        let gateway = gateway.unwrap();

        assert_eq!(route(&gateway, "/app/*").helmet.map(|h| h.level), Some(HelmetLevel::Strict));
        assert_eq!(route(&gateway, "/raw/*").helmet.map(|h| h.level), Some(HelmetLevel::Disabled));
    }

    #[test]
    fn invalid_helmet_values_are_rejected() {
        let (_, errors) = helmet_gateway(r#"route "/x" { backend = upstream("api") policies { helmet { level = "max" } } }"#);
        assert!(
            fatal(&errors).iter().any(|e| e.contains("unknown helmet level 'max'")),
            "{:?}",
            fatal(&errors)
        );

        let (_, errors) = helmet_gateway(r#"route "/x" { backend = upstream("api") policies { helmet = "missing" } }"#);
        assert!(
            fatal(&errors).iter().any(|e| e.contains("helmet policy 'missing' not found")),
            "{:?}",
            fatal(&errors)
        );
    }

    #[test]
    fn routes_use_their_compiled_helmet() {
        let (gateway, errors) = helmet_gateway(r#"route "/x" { backend = upstream("api") policies { helmet = "api-strict" } }"#);
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));

        let context = crate::state::AppContext::build(&gateway.unwrap(), None).unwrap();
        let matched = context.router.match_route(None, &http::Method::GET, "/x").unwrap();
        assert_eq!(
            matched.value.helmet_policy,
            Some(HelmetConfig::new(HelmetTarget::Api, HelmetLevel::Strict))
        );
    }

    #[test]
    fn host_accepts_a_string_or_an_array() {
        let (gateway, errors) = gateway_from(r#"host "example.com" { backend = upstream("api") }"#);
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        assert_eq!(&*route(&gateway.unwrap(), "/*").hosts, ["example.com".to_string()]);

        for source in [r#"routes { host "" { } }"#, r#"routes { host [] { } }"#, r#"routes { host ["a.com", " "] { } }"#] {
            assert!(crate::config::dsl::parser::parse_raw_gateway(source).is_err(), "{source}");
        }
    }

    #[test]
    fn host_without_matches_serves_every_path() {
        let (gateway, errors) = gateway_from(r#"host ["example.com", "www.example.com"] { backend = upstream("api") }"#);
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));

        let gateway = gateway.unwrap();
        assert_eq!(gateway.routes.len(), 1);
        let route = route(&gateway, "/*");
        assert_eq!(&*route.hosts, ["example.com".to_string(), "www.example.com".to_string()]);
        assert!(route.methods.is_empty(), "every method");
        assert_eq!(upstream_of(route), "api");
    }

    #[test]
    fn matches_inherit_and_override_the_host_settings() {
        let (gateway, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                policies { limiter = "default" cors = "web" }

                match "GET|POST /users" { backend = upstream("users") }
                match "/health" { policies { limiter = off } }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        let gateway = gateway.unwrap();

        let users = route(&gateway, "/users");
        assert_eq!(upstream_of(users), "users");
        assert!(users.methods.contains_str("GET") && users.methods.contains_str("POST"));
        assert!(!users.methods.contains_str("DELETE"));
        assert!(users.limiter.is_some() && users.cors.is_some(), "policies are inherited");
        assert_eq!(&*users.hosts, ["example.com".to_string()]);

        let health = route(&gateway, "/health");
        assert_eq!(upstream_of(health), "api", "backend is inherited");
        assert!(health.methods.is_empty(), "no methods means every method");
        assert!(health.limiter.is_none(), "off removes the inherited limiter");
        assert!(health.cors.is_some(), "other policies are still inherited");
    }

    #[test]
    fn same_path_with_other_methods_is_allowed() {
        let (gateway, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                match "GET /users" { }
                match "POST|PUT /users" { backend = upstream("users") }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        assert_eq!(gateway.unwrap().routes.len(), 2);
    }

    #[test]
    fn same_path_with_a_common_method_is_rejected() {
        let (_, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                match "GET|POST /users" { }
                match "POST /users" { }
            }"#,
        );
        assert!(
            fatal(&errors).iter().any(|e| e.contains("declared twice with a common method")),
            "{:?}",
            fatal(&errors)
        );

        let (_, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                match "/users" { }
                match "DELETE /users" { }
            }"#,
        );
        assert!(
            fatal(&errors).iter().any(|e| e.contains("common method")),
            "a match without methods takes them all"
        );
    }

    #[test]
    fn route_and_host_blocks_cannot_declare_the_same_path() {
        let (_, errors) = gateway_from(
            r#"route "/users" { hosts = ["example.com"] methods = ["GET"] backend = upstream("api") }
            host ["EXAMPLE.com"] { backend = upstream("api") match "POST /users" { } }"#,
        );
        assert!(
            fatal(&errors).iter().any(|e| e.contains("both a route block and a host block")),
            "{:?}",
            fatal(&errors)
        );

        let (_, errors) = gateway_from(
            r#"route "/users" { hosts = ["other.com"] backend = upstream("api") }
            host ["example.com"] { backend = upstream("api") match "/users" { } }"#,
        );
        assert!(fatal(&errors).is_empty(), "other hosts do not conflict: {:?}", fatal(&errors));
    }

    #[test]
    fn invalid_match_patterns_are_rejected() {
        for pattern in ["users", "get /users", "GET|/users", "GET users"] {
            let (_, errors) = gateway_from(&format!(
                r#"host ["example.com"] {{ backend = upstream("api") match "{pattern}" {{ }} }}"#
            ));
            assert!(
                fatal(&errors).iter().any(|e| e.contains("match")),
                "{pattern}: {:?}",
                fatal(&errors)
            );
        }
    }

    #[test]
    fn headers_are_merged_by_name() {
        let source = r#"routes { host ["example.com"] {
            inbound_headers { set = { X-A = "host", X-B = "host" } remove = ["X-C", "X-D"] }
            match "/users" { inbound_headers { set = { x-b = "match", X-C = "match" } } }
        } }"#;
        let raw = crate::config::dsl::parser::parse_raw_gateway(source).unwrap();
        let RawRoute::Host(host) = &raw.routes[0] else {
            panic!("expected a host block");
        };

        let routes = host.expand().unwrap();
        let headers = &routes[0].inbound_headers.as_ref().unwrap().opts;
        assert_eq!(headers.set, vec![("X-A", "host"), ("x-b", "match"), ("X-C", "match")]);
        assert_eq!(headers.remove, vec!["X-D"], "a header the match sets is not removed");
    }

    #[test]
    fn match_cannot_set_methods_or_hosts() {
        let source = r#"routes { host ["example.com"] { match "/users" { methods = ["GET"] } } }"#;
        assert!(crate::config::dsl::parser::parse_raw_gateway(source).is_err());

        let source = r#"routes { host ["example.com"] { hosts = ["other.com"] } }"#;
        assert!(crate::config::dsl::parser::parse_raw_gateway(source).is_err());
    }

    #[test]
    fn static_config_follows_the_inherited_backend() {
        let (gateway, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = static("/var/www")
                static_config { listing = true }

                match "/files/*" { }
                match "/api/*" { backend = upstream("api") }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        let gateway = gateway.unwrap();

        assert_eq!(upstream_of(route(&gateway, "/files/*")), "static");
        assert_eq!(
            upstream_of(route(&gateway, "/api/*")),
            "api",
            "an own backend drops the host static_config"
        );
    }

    #[test]
    fn catch_all_match_keeps_serving_its_base_path() {
        let (gateway, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                policies { cors = "web" }
                match "GET /users/*" { }
                match "POST|PUT /users" { backend = upstream("users") }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));

        let context = crate::state::AppContext::build(&gateway.unwrap(), None).unwrap();
        let get = context.router.match_route(Some("example.com"), &http::Method::GET, "/users").unwrap();
        let post = context.router.match_route(Some("example.com"), &http::Method::POST, "/users").unwrap();

        assert!(matches!(&get.value.backend, BackendTarget::Upstream(u) if &*u.name == "api"));
        assert!(matches!(&post.value.backend, BackendTarget::Upstream(u) if &*u.name == "users"));
    }

    #[test]
    fn routes_of_one_path_are_chosen_by_method_at_runtime() {
        let (gateway, errors) = gateway_from(
            r#"host ["example.com"] {
                backend = upstream("api")
                policies { cors = "web" }
                match "GET /users" { }
                match "POST /users" { backend = upstream("users") }
            }"#,
        );
        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));

        let context = crate::state::AppContext::build(&gateway.unwrap(), None).expect("both routes register");
        let router = &context.router;

        let get = router.match_route(Some("example.com"), &http::Method::GET, "/users").unwrap();
        let post = router.match_route(Some("example.com"), &http::Method::POST, "/users").unwrap();
        let preflight = router.match_route(Some("example.com"), &http::Method::OPTIONS, "/users");

        assert!(matches!(&get.value.backend, BackendTarget::Upstream(u) if &*u.name == "api"));
        assert!(matches!(&post.value.backend, BackendTarget::Upstream(u) if &*u.name == "users"));
        assert!(preflight.is_ok(), "one of the CORS routes answers preflights");
        assert!(router.match_route(Some("example.com"), &http::Method::DELETE, "/users").is_err());
    }

    #[test]
    fn listener_firewall_and_trusted_proxies() {
        let (listener, errors) = listener_from(
            r#"listener "public" {
                address = "0.0.0.0:8443"
                firewall { allow = [] deny = ["203.0.113.0/24"] }
                trusted_proxies {
                    allowed_ips = ["173.245.48.0/20"]
                    real_ip_header = "CF-Connecting-IP"
                    on_untrusted = "reject"
                }
            }"#,
        );

        assert!(errors.is_empty(), "{:?}", fatal(&errors));
        let listener = listener.unwrap();
        let firewall = listener.firewall.as_ref().unwrap();
        let trusted = listener.trusted_proxies.as_ref().unwrap();

        assert!(!firewall.admits("203.0.113.7".parse().unwrap()));
        assert!(trusted.is_trusted("173.245.48.9".parse().unwrap()));
        assert_eq!(trusted.on_untrusted(), OnUntrusted::Reject);
        assert_eq!(trusted.real_ip_header().unwrap(), "cf-connecting-ip");
    }

    #[test]
    fn header_without_allowed_ips_is_rejected() {
        let (_, errors) =
            listener_from(r#"listener "l" { address = "0.0.0.0:8080" trusted_proxies { real_ip_header = "X-Forwarded-For" } }"#);
        assert!(fatal(&errors).iter().any(|e| e.contains("needs allowed_ips")));
    }

    #[test]
    fn reject_without_allowed_ips_is_rejected() {
        let (_, errors) =
            listener_from(r#"listener "l" { address = "0.0.0.0:8080" trusted_proxies { on_untrusted = "reject" } }"#);
        assert!(fatal(&errors).iter().any(|e| e.contains("every connection is rejected")));
    }

    #[test]
    fn open_ranges_cannot_be_trusted() {
        let (_, errors) = listener_from(
            r#"listener "l" { address = "0.0.0.0:8080" trusted_proxies { allowed_ips = ["0.0.0.0/0"] real_ip_header = "X-Real-IP" } }"#,
        );
        assert!(fatal(&errors).iter().any(|e| e.contains("0.0.0.0/0")));
    }

    #[test]
    fn invalid_on_untrusted_is_rejected() {
        let (_, errors) = listener_from(
            r#"listener "l" { address = "0.0.0.0:8080" trusted_proxies { allowed_ips = ["10.0.0.0/8"] on_untrusted = "deny" } }"#,
        );
        assert!(fatal(&errors).iter().any(|e| e.contains("on_untrusted")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_requires_real_ip_header() {
        let (_, errors) = listener_from(r#"listener "uds" { address = "unix:/run/ophan.sock" }"#);
        assert!(fatal(&errors).iter().any(|e| e.contains("real_ip_header` is required")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_rejects_firewall_and_allowed_ips() {
        let (_, errors) = listener_from(
            r#"listener "uds" {
                address = "unix:/run/ophan.sock"
                firewall { deny = ["203.0.113.0/24"] }
                trusted_proxies { allowed_ips = ["10.0.0.0/8"] real_ip_header = "CF-Connecting-IP" }
            }"#,
        );
        let errors = fatal(&errors);
        assert!(errors.iter().any(|e| e.contains("firewall does not apply")));
        assert!(errors.iter().any(|e| e.contains("only `real_ip_header` applies")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_with_header_and_permissions() {
        let (listener, errors) = listener_from(
            r#"listener "uds" {
                address = "unix:/run/ophan.sock"
                permissions = "0660"
                trusted_proxies { real_ip_header = "CF-Connecting-IP" }
            }"#,
        );
        assert!(errors.is_empty(), "{:?}", fatal(&errors));
        assert_eq!(listener.unwrap().permissions, Some(0o660));
    }

    #[test]
    fn permissions_only_apply_to_unix_sockets() {
        let (_, errors) = listener_from(r#"listener "l" { address = "0.0.0.0:8080" permissions = "0660" }"#);
        assert!(fatal(&errors).iter().any(|e| e.contains("only apply to unix sockets")));
    }

    #[test]
    fn legacy_network_policy_is_mapped_with_a_warning() {
        let (listener, errors) = listener_from(
            r#"listener "l" {
                address = "0.0.0.0:8080"
                network_policy {
                    allowed_ip_ranges = ["10.0.0.0/8"]
                    blocked_ip_ranges = ["10.0.0.66/32"]
                    proxy_allowed_ips = ["10.1.0.0/16"]
                    policy = "deny"
                }
            }"#,
        );

        assert!(fatal(&errors).is_empty(), "{:?}", fatal(&errors));
        assert!(errors.iter().any(|e| e.warning && e.message.contains("deprecated")));

        let listener = listener.unwrap();
        let firewall = listener.firewall.as_ref().unwrap();
        let trusted = listener.trusted_proxies.as_ref().unwrap();

        assert!(!firewall.admits("10.0.0.66".parse().unwrap()));
        assert!(firewall.admits("10.2.0.1".parse().unwrap()));
        assert_eq!(trusted.on_untrusted(), OnUntrusted::Reject);
        assert_eq!(trusted.real_ip_header().unwrap(), "x-forwarded-for");
    }

    #[test]
    fn legacy_and_new_blocks_cannot_be_mixed() {
        let (_, errors) = listener_from(
            r#"listener "l" {
                address = "0.0.0.0:8080"
                network_policy { allowed_ip_ranges = ["10.0.0.0/8"] }
                firewall { deny = ["203.0.113.0/24"] }
            }"#,
        );
        assert!(fatal(&errors).iter().any(|e| e.contains("cannot be combined")));
    }

    #[test]
    fn metrics_defaults_path_and_accepts_tcp() {
        let mut errors = Vec::new();
        let raw = RawMetrics { listen: Some("127.0.0.1:9100"), path: None };

        let cfg = compile_metrics(&raw, &mut errors).unwrap();

        assert!(errors.is_empty());
        assert_eq!(cfg.listen, ListenerAddress::Tcp("127.0.0.1:9100".parse().unwrap()));
        assert_eq!(cfg.path, "/metrics");
    }

    #[cfg(unix)]
    #[test]
    fn metrics_accepts_unix_socket() {
        let mut errors = Vec::new();
        let raw = RawMetrics {
            listen: Some("unix:/run/ophan/metrics.sock"),
            path: Some("/m"),
        };

        let cfg = compile_metrics(&raw, &mut errors).unwrap();

        assert_eq!(cfg.listen, ListenerAddress::Uds("/run/ophan/metrics.sock".into()));
        assert_eq!(cfg.path, "/m");
    }

    #[test]
    fn metrics_rejects_missing_listen_and_bad_path() {
        let mut errors = Vec::new();

        assert!(compile_metrics(&RawMetrics { listen: None, path: None }, &mut errors).is_none());
        assert!(
            compile_metrics(
                &RawMetrics { listen: Some("127.0.0.1:9100"), path: Some("metrics") },
                &mut errors
            )
            .is_none()
        );
        assert!(compile_metrics(&RawMetrics { listen: Some("example.com:9100"), path: None }, &mut errors).is_none());
        assert_eq!(errors.len(), 3);
    }

    fn raw_auth<'a>() -> RawAuthConfig<'a> {
        RawAuthConfig {
            issuer: Some("https://auth.example.com"),
            audience: Some("api"),
            ..Default::default()
        }
    }

    fn raw_refresh<'a>(enabled: Option<bool>, endpoint: Option<&'a str>) -> RawRefreshConfig<'a> {
        RawRefreshConfig { enabled, endpoint, sources: None, inject: None }
    }

    #[test]
    fn auth_refresh_configures_oauth_client() {
        let raw = RawAuthConfig {
            client_id: Some("edge"),
            client_secret: Some(RawSecretValue::Literal("s3cret")),
            refresh: Some(raw_refresh(Some(true), Some("https://auth.example.com/oauth/token"))),
            ..raw_auth()
        };

        let cfg = build_auth_from_raw(&raw).unwrap();
        let client = cfg.client.oauth_client.expect("oauth client must be configured");

        assert_eq!(client.client_id, "edge");
        assert_eq!(client.client_secret.as_deref(), Some("s3cret"));
        assert_eq!(client.token_endpoint.as_deref(), Some("https://auth.example.com/oauth/token"));
        assert!(client.refresh_flow_enabled);
    }

    #[test]
    fn auth_refresh_block_defaults_to_enabled() {
        let raw = RawAuthConfig {
            client_id: Some("edge"),
            refresh: Some(raw_refresh(None, None)),
            ..raw_auth()
        };

        let cfg = build_auth_from_raw(&raw).unwrap();
        assert!(cfg.client.oauth_client.unwrap().refresh_flow_enabled);
    }

    #[test]
    fn auth_refresh_disabled_keeps_client_without_refresh() {
        let raw = RawAuthConfig {
            client_id: Some("edge"),
            refresh: Some(raw_refresh(Some(false), None)),
            ..raw_auth()
        };

        let cfg = build_auth_from_raw(&raw).unwrap();
        assert!(!cfg.client.oauth_client.unwrap().refresh_flow_enabled);
    }

    #[test]
    fn auth_refresh_without_client_id_is_rejected() {
        let raw = RawAuthConfig { refresh: Some(raw_refresh(Some(true), None)), ..raw_auth() };

        let err = build_auth_from_raw(&raw).unwrap_err();
        assert!(err.contains("client_id"), "{err}");
    }

    #[test]
    fn auth_client_secret_from_missing_env_is_rejected() {
        let raw = RawAuthConfig {
            client_id: Some("edge"),
            client_secret: Some(RawSecretValue::Env(EnvVar("OPHAN_TEST_UNSET_CLIENT_SECRET".into()))),
            ..raw_auth()
        };

        let err = build_auth_from_raw(&raw).unwrap_err();
        assert!(err.contains("OPHAN_TEST_UNSET_CLIENT_SECRET"), "{err}");
    }

    #[test]
    fn invalid_exclude_pattern_is_a_clean_error() {
        let raw = RawWafConfig { exclude_paths: vec!["/safe/*", "{a"], ..Default::default() };

        let err = build_waf_from_raw(&raw).unwrap_err();
        assert!(err.contains("{a"), "{err}");
        assert!(err.contains("exclude_paths"), "{err}");
    }

    #[test]
    fn merged_overrides_propagate_invalid_patterns() {
        let waf_overrides = RawWafConfig { exclude_paths: vec!["/ok/**", "[z-a]"], ..Default::default() };
        let mut waf = WafConfig::default();

        let err = merge_waf_override(&mut waf, &waf_overrides).unwrap_err();
        assert!(err.contains("[z-a]"), "{err}");

        let limiter_overrides = RawLimiterConfig { exclude_paths: vec!["{a,{b}"], ..Default::default() };
        let mut limiter = LimiterConfig::default();

        let err = merge_limiter_override(&mut limiter, &limiter_overrides).unwrap_err();
        assert!(err.contains("{a,{b}"), "{err}");

        let auth_overrides = RawAuthConfig {
            exclude_paths: vec!["**/**/**/**/**/**/**"],
            ..Default::default()
        };
        let mut auth = build_auth_from_raw(&raw_auth()).unwrap();

        let err = merge_auth_override(&mut auth, &auth_overrides).unwrap_err();
        assert!(err.contains("wildcards") || err.contains("**"), "{err}");
    }
}
