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
use flatkit::matchers::PathMatcherSet;
use flatkit::net::IpNet;
use flatkit::str::ImmerStr;
use http::HeaderName;
use http::HeaderValue;
use http::header;
use ophan_auth::crypto::{Algorithm, HmacAlg};
use ophan_auth::{AuthConfig as InnerAuthConfig, AuthMode, JwtValidatorConfig};
use ophan_net::http::HttpMethodSet;
use ophan_net::tls::TlsVersion;
use ophan_sec::l7::CompiledWafRules;
use ophan_sec::l7::WafConfig;
use ophan_sec::l7::WafMode;
// use ophan_sec::config::{WafAction, WafCondition, WafConfig, WafMode, WafPhase, WafRule};
use ophan_sec::{NetPolicy, PolicyMode};
use ophan_static::FsFlags;

use crate::balancer::BalanceStrategy;
use crate::config::get_max_thread_size;

use crate::middlewares::auth::AuthConfig;
use crate::middlewares::auth::TokenSource;
use crate::middlewares::cors::{AllowedOrigins, CorsConfig};
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
}

impl CompileError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
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

    MasterConfig {
        name: name.into(),
        user,
        workers,
        pid,
        error_log,
        includes: includes.into_boxed_slice(),
    }
}

struct GatewayScope<'a> {
    auth: &'a HashMap<String, Arc<AuthConfig>>,
    waf: &'a HashMap<String, Arc<WafConfig>>,
    cors: &'a HashMap<String, Arc<CorsConfig>>,
    limiter: &'a HashMap<String, Arc<LimiterConfig>>,
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
        upstreams: &upstream_map,
    };

    let routes: Vec<Arc<RoutesConfig>> = raw.routes.iter().filter_map(|rr| compile_route(rr, &scope, errors)).collect();

    Some(GatewayConfig {
        name: name.into(),
        listeners,
        upstreams,
        routes: routes.into_boxed_slice(),
        net_policy: None,
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
                Ok(cfg) => {
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

            SecurityConfig::Tls {
                certs: TlsCerts {
                    cert: ssl.cert.to_string(),
                    key: ssl.key.to_string(),
                    client_ca: ssl.client_ca.map(|s| s.to_string().as_bytes().to_owned()), // TODO read ca bytes
                },
                alpn_protocols: None,
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

    if let Some(ref raw_policy) = raw.network_policy {
        match compile_net_policy(raw_policy) {
            Ok(policy) => listener.policy = Some(Arc::new(policy)),
            Err(e) => errors.push(CompileError::new(format!("listener '{}': net_policy: {}", listener.name, e))),
        }
    }

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
    let path = raw.path.unwrap_or("/").to_string();
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

fn compile_route(raw: &RawRoute, scope: &GatewayScope, errors: &mut Vec<CompileError>) -> Option<Arc<RoutesConfig>> {
    let route = match raw {
        RawRoute::Path(p) => p,
        RawRoute::Group(_g) => {
            // !TODO: implement group routes
            return None;
        },
    };

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

    let mut auth: Option<Arc<AuthConfig>> = None;
    let mut waf: Option<Arc<WafConfig>> = None;
    let mut cors: Option<Arc<CorsConfig>> = None;
    let mut limiter: Option<Arc<LimiterConfig>> = None;

    if let Some(ref policies) = route.policies {
        if let Some(ref action) = policies.auth {
            match resolve_auth(action, scope) {
                Ok(cfg) => auth = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(ref action) = policies.waf {
            match resolve_waf(action, scope) {
                Ok(cfg) => waf = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(ref action) = policies.cors {
            match resolve_cors(action, scope) {
                Ok(cfg) => cors = Some(cfg),
                Err(e) => errors.push(CompileError::new(format!("route '{}': {}", path, e))),
            }
        }
        if let Some(ref action) = policies.limiter {
            match resolve_limiter(action, scope) {
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
    let headers = compile_headers(&route.inbound_headers, &route.outbound_headers);

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

            let blacklist = PathMatcherSet::try_from(sb.exclude_paths.to_owned()).ok();
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
    inbound: &Option<RawRouteHeadersOpts<'_, RawHeadersOps<'_>>>,
    outbound: &Option<RawRouteHeadersOpts<'_, RawHeadersRemove<'_>>>,
) -> Option<HeaderMutations> {
    let has_inbound = inbound.as_ref().is_some_and(|h| {
        !h.opts.set.is_empty() || !h.opts.remove.is_empty() || !h.upstream.set.is_empty() || !h.upstream.remove.is_empty()
    });
    let has_outbound = outbound
        .as_ref()
        .is_some_and(|h| !h.opts.set.is_empty() || !h.opts.remove.is_empty() || !h.upstream.remove.is_empty());

    if !has_inbound && !has_outbound {
        return None;
    }

    let inbound_mutations = inbound
        .as_ref()
        .map(|h| {
            let client_set: AHashMap<HeaderName, HeaderValue> = h
                .opts
                .set
                .iter()
                .filter_map(|(k, v)| {
                    let name = HeaderName::from_bytes(k.as_bytes()).ok()?;
                    let value = HeaderValue::from_str(v).ok()?;
                    Some((name, value))
                })
                .collect();
            let client_remove: Box<[HeaderName]> =
                h.opts.remove.iter().filter_map(|k| HeaderName::from_bytes(k.as_bytes()).ok()).collect();
            let to_upstream_set: AHashMap<HeaderName, HeaderValue> = h
                .upstream
                .set
                .iter()
                .filter_map(|(k, v)| {
                    let name = HeaderName::from_bytes(k.as_bytes()).ok()?;
                    let value = HeaderValue::from_str(v).ok()?;
                    Some((name, value))
                })
                .collect();
            let to_upstream_remove: Box<[HeaderName]> =
                h.upstream.remove.iter().filter_map(|k| HeaderName::from_bytes(k.as_bytes()).ok()).collect();

            InboundHeaderMutations {
                client_set,
                client_remove,
                to_upstream_set,
                to_upstream_remove,
            }
        })
        .unwrap_or_default();

    let outbound_mutations = outbound
        .as_ref()
        .map(|h| {
            let from_upstream_set: AHashMap<HeaderName, HeaderValue> = h
                .opts
                .set
                .iter()
                .filter_map(|(k, v)| {
                    let name = HeaderName::from_bytes(k.as_bytes()).ok()?;
                    let value = HeaderValue::from_str(v).ok()?;
                    Some((name, value))
                })
                .collect();
            let from_upstream_remove: Box<[HeaderName]> =
                h.opts.remove.iter().filter_map(|k| HeaderName::from_bytes(k.as_bytes()).ok()).collect();
            let client_set: AHashMap<HeaderName, HeaderValue> = AHashMap::new();
            let client_remove: Box<[HeaderName]> =
                h.upstream.remove.iter().filter_map(|k| HeaderName::from_bytes(k.as_bytes()).ok()).collect();

            OutboundHeaderMutations {
                from_upstream_set,
                from_upstream_remove,
                client_set,
                client_remove,
            }
        })
        .unwrap_or_default();

    Some(HeaderMutations { inbound: inbound_mutations, outbound: outbound_mutations })
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
            merge_auth_override(&mut cfg, overrides);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_auth_from_raw(config)?)),
    }
}

fn resolve_waf(action: &RawRouteAction<RawWafConfig>, scope: &GatewayScope) -> Result<Arc<WafConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => scope.waf.get(*name).cloned().ok_or_else(|| format!("waf policy '{}' not found", name)),
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.waf.get(*base).ok_or_else(|| format!("waf policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_waf_override(&mut cfg, overrides);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_waf_from_raw(config)?)),
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
    }
}

fn resolve_limiter(action: &RawRouteAction<RawLimiterConfig>, scope: &GatewayScope) -> Result<Arc<LimiterConfig>, String> {
    match action {
        RawRouteAction::Ref(name) => {
            scope.limiter.get(*name).cloned().ok_or_else(|| format!("limiter policy '{}' not found", name))
        },
        RawRouteAction::Extends { base, overrides } => {
            let base = scope.limiter.get(*base).ok_or_else(|| format!("limiter policy '{}' not found", base))?;
            let mut cfg = base.as_ref().clone();
            merge_limiter_override(&mut cfg, overrides);
            Ok(Arc::new(cfg))
        },
        RawRouteAction::Inline(config) => Ok(Arc::new(build_limiter_from_raw(config)?)),
    }
}

// ============================================================================
// POLICY BUILDERS (from RawPolicy fields)
// ============================================================================

fn build_auth_from_raw(raw: &RawAuthConfig) -> Result<AuthConfig, String> {
    let issuer = raw.issuer.ok_or_else(|| "auth: issuer is required".to_string())?;
    let audience = raw.audience.ok_or_else(|| "auth: audience is required".to_string())?;

    let mut validator = JwtValidatorConfig::new(issuer);
    validator.audience = vec![ImmerStr::from(audience)].into_boxed_slice();

    let dpop_policy = raw.dpop_proof.and_then(|dpop| dpop.parse().ok()).unwrap_or_default();

    let (auth_mode, token_ttl) = match raw.mode.as_ref() {
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

    let mut inner_config = InnerAuthConfig::new(validator, auth_mode);
    inner_config.dpop_policy = dpop_policy;

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
    let refresh_sources = raw.refresh.as_ref().and_then(|r| r.sources.as_ref().map(compile_token_source));

    // Compile skip_patterns from exclude_paths
    let skip_patterns = if raw.exclude_paths.is_empty() {
        None
    } else {
        Some(PathMatcherSet::try_from(raw.exclude_paths.to_owned()).map_err(|e| e.to_string())?)
    };

    let sources = raw.sources.as_ref().map(|s| s.iter().map(compile_token_source).collect()).unwrap_or_default();

    Ok(AuthConfig {
        client: inner_config,
        sources,
        refresh_sources,
        dpop_source: None,
        inject_access_token_into,
        inject_refresh_token_into,
        token_ttl,
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
        cfg.skip_patterns = Some(PathMatcherSet::try_from(raw.exclude_paths.as_slice()).map_err(|a| a.to_string())?);
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
        cfg.skip_patterns = Some(PathMatcherSet::try_from(raw.exclude_paths.clone()).map_err(|a| a.to_string())?);
    }

    Ok(cfg)
}

// ============================================================================
// AUTH merge (route-level overrides)
// ============================================================================

fn merge_auth_override(cfg: &mut AuthConfig, overrides: &RawAuthConfig) {
    if let Some(issuer) = overrides.issuer {
        cfg.client.validator.issuer = Box::new([ImmerStr::from(issuer)]);
    }
    if let Some(audience) = overrides.audience {
        cfg.client.validator.audience = Box::new([ImmerStr::from(audience)]);
    }
    if let Some(ref mode) = overrides.mode {
        cfg.client.auth_mode = match mode {
            RawAuthMode::Jwks { uri, algorithms, .. } => {
                let algs = algorithms.iter().filter_map(|a| Algorithm::from_str(a).ok()).collect::<Vec<_>>();
                let uri_str = uri.as_deref().unwrap_or("");
                AuthMode::new_jwks(uri_str.to_string(), algs.into_boxed_slice())
            },
            RawAuthMode::Oidc { discovery_url, .. } => {
                let url = discovery_url.as_deref().unwrap_or("");
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
        cfg.sources = sources.iter().map(compile_token_source).collect();
    }
    if let Some(ref refresh) = overrides.refresh {
        cfg.refresh_sources = refresh.sources.as_ref().map(compile_token_source);
        if let Some(ref inject) = refresh.inject {
            cfg.inject_access_token_into = inject.access_token.iter().map(compile_inject_target).collect();
            cfg.inject_refresh_token_into = inject.refresh_token.iter().map(compile_inject_target).collect();
        }
    }
    if !overrides.exclude_paths.is_empty() {
        cfg.skip_patterns = PathMatcherSet::try_from(overrides.exclude_paths.to_owned()).ok();
    }
}

fn compile_token_source(raw: &RawTokenSource) -> TokenSource {
    match raw {
        RawTokenSource::Header { name, prefix } => TokenSource::Header {
            name: name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        },
        RawTokenSource::Cookie { name, prefix } => TokenSource::Cookie {
            name: name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        },
        RawTokenSource::QueryParam { name, prefix } => TokenSource::QueryParam {
            name: name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        },
    }
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

fn merge_waf_override(cfg: &mut WafConfig, overrides: &RawWafConfig) {
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
        cfg.skip_patterns = PathMatcherSet::try_from(overrides.exclude_paths.as_slice()).ok();
    }
    if !overrides.rules.is_empty() {
        cfg.compiled = compile_waf_rules(&overrides.rules);
    }
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

fn merge_limiter_override(cfg: &mut LimiterConfig, overrides: &RawLimiterConfig) {
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
        cfg.skip_patterns = Some(PathMatcherSet::try_from(overrides.exclude_paths.to_owned()).unwrap());
    }
}

// ============================================================================
// TRUSTED PROXIES
// ============================================================================

fn compile_net_policy(raw: &RawNetworkPolicy) -> Result<NetPolicy, String> {
    let real_ip_header = raw
        .real_ip_header
        .unwrap_or("X-Forwarded-For")
        .parse::<HeaderName>()
        .map_err(|_| format!("invalid real_ip_header '{}'", raw.real_ip_header.unwrap_or("X-Forwarded-For")))?;

    let mut all_ranges: Vec<&str> = Vec::new();
    all_ranges.extend(raw.allowed_ip_ranges.iter().copied());
    if let Some(ref proxy_ips) = raw.proxy_allowed_ips {
        all_ranges.extend(proxy_ips.iter().copied());
    }

    let allowed_ip_ranges: Vec<IpNet> = all_ranges
        .into_iter()
        .map(|ip| ip.parse::<IpNet>().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;

    let policy = raw.proxy_allowed_ips.as_ref().map(|_| PolicyMode::Degrade).unwrap_or(PolicyMode::Deny);

    Ok(NetPolicy::builder(real_ip_header, allowed_ip_ranges).with_policy_mode(policy).build())
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
