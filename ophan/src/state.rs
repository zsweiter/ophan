use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;
use ophan_net::http::{HttpMethod, HttpMethodSet};
use ophan_router::Router;
use ophan_sec::l7::WafConfig;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use crate::balancer::{Backend, BackendAddr, LoadBalancer, Upstream};
use crate::gateway::listener::ListenerTable;
use crate::metrics::{CONFIG_RELOADS, RouteMetrics};

use crate::config::{
    BackendTarget, GatewayConfig, HeaderMutations, ListenerConfig, OphanConfig, RouteStreaming, RouteTimeouts, RoutesConfig,
    UpstreamAddress, load_config,
};

use crate::middlewares::auth::AuthConfig;
use crate::middlewares::cors::CorsConfig;
use crate::middlewares::helmet::HelmetConfig;
use crate::middlewares::limiter::LimiterConfig;
use crate::middlewares::rewrites::RewriteEngine;

/// Result of a config reload attempt.
pub enum ReloadOutcome {
    /// No files changed, nothing to do.
    NoChange,
    /// Non-listener config was hot-swapped; new requests use the updated config.
    Swapped,
    /// Listeners changed — requires a full graceful upgrade via pingora.
    NeedsUpgrade,
}

pub struct HttpRoute {
    pub backend: BackendTarget,
    pub methods: HttpMethodSet,
    pub rewrite: Option<RewriteEngine>,

    pub auth_policy: Option<Arc<AuthConfig>>,
    pub waf_policy: Option<Arc<WafConfig>>,
    pub cors_policy: Option<Arc<CorsConfig>>,
    pub limiter_policy: Option<Arc<LimiterConfig>>,
    pub helmet_policy: Option<HelmetConfig>,

    pub timeouts: Option<RouteTimeouts>,
    pub streaming: Option<RouteStreaming>,
    pub headers: Option<HeaderMutations>,

    pub metrics: RouteMetrics,
}

pub struct AppContext {
    pub router: Router<Arc<HttpRoute>>,
    /// Rebuilt with the rest of the context, so upstream ids always match the routes.
    pub load_balancer: LoadBalancer,
    pub listeners: ListenerTable,
}

impl AppContext {
    /// `previous` is the context being replaced on a reload; unchanged backends are
    /// carried over so their health and in-flight counters survive.
    pub fn build(config: &GatewayConfig, previous: Option<&AppContext>) -> Result<Self, String> {
        let mut router = Router::with_capacity(config.routes.len());

        // Paths whose OPTIONS requests already go to a route: one listing OPTIONS, or the first
        // route with CORS. Routes of one path that differ by method share a single preflight route.
        let mut options_routed: AHashSet<(String, String)> = config
            .routes
            .iter()
            .filter(|route| route.methods.contains_http(HttpMethod::OPTIONS))
            .flat_map(Self::route_keys)
            .collect();

        for route in &config.routes {
            let rewrite_rules = route.rewrite.as_ref().map(|rules| {
                RewriteEngine::new(
                    rules.replaces.clone(),
                    rules.strip_prefix.as_deref(),
                    rules.strip_suffix.as_deref(),
                    rules.trailing_slash.unwrap_or_default(),
                )
                .map_err(|e| format!("{:?}", e))
            });

            let rewrite_rules = rewrite_rules.transpose()?;

            let compiled = Arc::new(HttpRoute {
                backend: match &route.backend {
                    BackendTarget::Static(s) => BackendTarget::Static(Arc::clone(s)),
                    BackendTarget::Upstream(u) => BackendTarget::Upstream(Arc::clone(u)),
                },
                methods: route.methods.clone(),
                rewrite: rewrite_rules,
                auth_policy: route.auth.clone(),
                waf_policy: route.waf.clone(),
                cors_policy: route.cors.clone(),
                limiter_policy: route.limiter.clone(),
                helmet_policy: Some(HelmetConfig::default()),
                timeouts: route.timeouts.clone(),
                streaming: route.streaming,
                headers: route.headers.clone(),
                metrics: RouteMetrics::new(&config.name, &route.path),
            });

            let hosts = route.hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>();

            // CORS preflights use OPTIONS; the CORS policy answers them and rejects other OPTIONS.
            let mut methods = route.methods.clone();
            if route.cors.is_some() && !methods.is_empty() {
                let keys = Self::route_keys(route);
                if keys.iter().all(|key| !options_routed.contains(key)) {
                    methods.add_standard(HttpMethod::OPTIONS);
                    options_routed.extend(keys);
                }
            }

            router.add_route(&route.path, methods, hosts, compiled).map_err(|e| e.to_string())?;
        }

        Ok(Self {
            router,
            load_balancer: Self::build_load_balancer(config, previous.map(|p| &p.load_balancer)),
            listeners: ListenerTable::from_config(&config.listeners),
        })
    }

    /// `(host, path)` pairs a route serves; routes without hosts serve the default host.
    fn route_keys(route: &Arc<RoutesConfig>) -> Vec<(String, String)> {
        let path = route.path.trim_end_matches('/').to_string();

        if route.hosts.is_empty() {
            return vec![(String::new(), path)];
        }

        route.hosts.iter().map(|host| (host.to_ascii_lowercase(), path.clone())).collect()
    }

    /// Builds the balancer of a gateway. `previous` is the balancer being replaced on a reload;
    /// unchanged backends are carried over so their health and in-flight counters survive.
    fn build_load_balancer(config: &GatewayConfig, previous: Option<&LoadBalancer>) -> LoadBalancer {
        let previous = previous.map(|lb| lb.upstreams());

        let upstreams = config
            .upstreams
            .iter()
            .map(|up| {
                let old_backends = previous
                    .as_ref()
                    .and_then(|ups| ups.iter().find(|old| old.name == up.name))
                    .map(|old| old.servers.load_full());

                let backends = up
                    .servers
                    .iter()
                    .map(|server| {
                        let addr = BackendAddr::from(&server.address);

                        let reused = old_backends
                            .as_ref()
                            .and_then(|olds| olds.iter().find(|b| b.addr == addr && b.protocol == server.protocol));

                        if let Some(backend) = reused {
                            backend.set_weight(server.weight);
                            return Arc::clone(backend);
                        }

                        let mut backend = match server.address {
                            UpstreamAddress::Tcp(addr) => Backend::from_tcp(addr, server.weight),
                            UpstreamAddress::Host(ref addr) => Backend::from_host(addr, server.weight),

                            #[cfg(unix)]
                            UpstreamAddress::Uds(ref addr) => Backend::from_uds(PathBuf::from(addr), server.weight),
                        };

                        backend.set_protocol(server.protocol.clone());

                        Arc::new(backend)
                    })
                    .collect::<Vec<Arc<Backend>>>();

                let mut upstream = Upstream::new(up.id.0, up.name.clone(), backends, up.balance_strategy);
                upstream.update_health_config(up.health_check.clone());
                upstream
            })
            .collect::<Vec<Upstream>>();

        LoadBalancer::new(upstreams)
    }
}

/// Shared application state holding the current config and derived context.
///
/// Both fields are atomic-swappable so readers see a consistent snapshot without locking.
pub struct AppState {
    pub config: ArcSwap<OphanConfig>,
    pub gateways: AHashMap<ImmerStr, Arc<ArcSwap<AppContext>>>,
}

impl AppState {
    pub fn new(config: OphanConfig, gateways: AHashMap<ImmerStr, Arc<ArcSwap<AppContext>>>) -> Self {
        Self { config: ArcSwap::from_pointee(config), gateways }
    }

    /// Re-parse config files and apply changes if safe.
    ///
    /// If parsing or validation fails the running config is left untouched.
    /// When only non-listener fields (routes, upstreams, policies) changed,
    /// the new config is swapped in atomically. Listener changes require
    /// a full upgrade because pingora does not support hot-removing listeners.
    pub fn reload(&self) -> ReloadOutcome {
        let outcome = self.reload_inner();

        let label = match outcome {
            ReloadOutcome::NoChange => "unchanged",
            ReloadOutcome::Swapped => "swapped",
            ReloadOutcome::NeedsUpgrade => "upgrade",
        };
        CONFIG_RELOADS.with_label_values(&[label]).inc();

        outcome
    }

    fn reload_inner(&self) -> ReloadOutcome {
        let current = self.config.load();

        if !self.any_file_changed(&current) {
            return ReloadOutcome::NoChange;
        }

        let new_config = match load_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("config reload failed to parse: {:#}", e);
                tracing::error!("config reload failed to parse: {:#}", e);

                return ReloadOutcome::NoChange;
            },
        };

        // Gateways added or removed require a full upgrade (pingora cannot hot-add services)
        if current.gateways.len() != new_config.gateways.len()
            || !current.gateways.keys().all(|k| new_config.gateways.contains_key(k))
        {
            return ReloadOutcome::NeedsUpgrade;
        }

        if self.listeners_changed(&current.listeners, &new_config.listeners) {
            return ReloadOutcome::NeedsUpgrade;
        }

        if current.master.metrics != new_config.master.metrics {
            return ReloadOutcome::NeedsUpgrade;
        }

        // Build all new contexts first (all-or-nothing: if any fails, swap nothing)
        let mut new_contexts = AHashMap::with_capacity(new_config.gateways.len());
        for (name, gw_config) in &new_config.gateways {
            let previous = self.gateways.get(name).map(|swap| swap.load_full());
            match AppContext::build(gw_config, previous.as_deref()) {
                Ok(ctx) => {
                    new_contexts.insert(name.clone(), Arc::new(ctx));
                },
                Err(e) => {
                    tracing::error!("config reload validation error for gateway '{}': {}", name, e);
                    eprintln!("config reload validation error for gateway '{}': {}", name, e);

                    return ReloadOutcome::NoChange;
                },
            }
        }

        // Atomic swap: update config, then each gateway context
        self.config.store(Arc::new(new_config));

        for (name, ctx) in new_contexts {
            if let Some(swap) = self.gateways.get(&name) {
                swap.store(ctx);
            }
        }

        ReloadOutcome::Swapped
    }

    fn any_file_changed(&self, config: &OphanConfig) -> bool {
        if config.master_tracker.as_ref().is_none_or(|t| t.has_changed().unwrap_or(false)) {
            return true;
        }

        config.gateway_trackers.values().any(|t| t.has_changed().unwrap_or(false))
    }

    /// Checks if listeners differ significantly.
    ///
    /// Compares network-level options (address, TLS, transport) to determine if
    /// listener updates require a socket reload, while ignoring metadata like names.
    fn listeners_changed(&self, a: &[Arc<ListenerConfig>], b: &[Arc<ListenerConfig>]) -> bool {
        // Fail-fast detect remove or add new listeners
        if a.len() != b.len() {
            return true;
        }

        a.iter().zip(b.iter()).any(|(a, b)| a.address != b.address || a.security != b.security)
    }
}
