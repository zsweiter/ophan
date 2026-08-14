use ahash::AHashMap;
use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;
use ophan_net::http::HttpMethodSet;
use ophan_router::Router;
use ophan_sec::NetPolicy;
use ophan_sec::l4::{IngressFilter, PacketAction};
use ophan_sec::l7::WafConfig;
use pingora::listeners::ConnectionFilter;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{
    BackendTarget, GatewayConfig, ListenerAddress, ListenerConfig, OphanConfig, RouteStreaming, RouteTimeouts, load_config,
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
}

#[derive(Debug)]
pub struct ConnectionFilters {
    ingress_filter: IngressFilter,
    port: Option<u16>,
}

impl ConnectionFilters {
    pub fn filter(&self, ip: std::net::IpAddr, port: Option<u16>) -> PacketAction {
        self.ingress_filter.filter(ip, port)
    }

    pub fn has_rules(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl ConnectionFilter for ConnectionFilters {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        let Some(socket) = addr else {
            return true;
        };

        match self.ingress_filter.filter(socket.ip(), self.port) {
            PacketAction::DROP => false,
            PacketAction::PASS => true,
        }
    }
}

pub trait Reloadable {
    fn hot_reload(&self) -> impl Future<Output = ()> + Send + Sync;
}

pub struct AppContext {
    pub router: Router<Arc<HttpRoute>>,
    pub net_policy: Option<Arc<NetPolicy>>,
    pub net_policies: AHashMap<u16, Arc<NetPolicy>>,
    pub net_filter: Option<Arc<ConnectionFilters>>,
}

impl AppContext {
    pub fn build(config: &GatewayConfig) -> Result<Self, String> {
        let mut router = Router::with_capacity(config.routes.len());

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
            });

            let hosts = route.hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>();

            router.add_route(&route.path, route.methods.clone(), hosts, compiled).map_err(|e| e.to_string())?;
        }

        let mut net_policies = AHashMap::new();
        let mut ingress_builder = IngressFilter::builder();
        let mut has_ingress_rules = false;

        for listener in config.listeners.iter() {
            if let Some(policy) = listener.policy.as_ref() {
                if let ListenerAddress::Tcp(addr) = &listener.address {
                    net_policies.insert(addr.port(), Arc::clone(policy));

                    ingress_builder = ingress_builder.port(addr.port());
                    has_ingress_rules = true;
                }

                for ip_net in policy.allowed_ip_ranges.iter() {
                    ingress_builder = ingress_builder.allow(ip_net.to_owned());
                }
            }
        }

        let net_filter = if has_ingress_rules {
            Some(Arc::new(ConnectionFilters {
                ingress_filter: ingress_builder.build()?,
                port: None,
            }))
        } else {
            None
        };

        Ok(Self {
            router,
            net_policy: config.net_policy.clone(),
            net_policies,
            net_filter,
        })
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

        // Build all new contexts first (all-or-nothing: if any fails, swap nothing)
        let mut new_contexts = AHashMap::with_capacity(new_config.gateways.len());
        for (name, gw_config) in &new_config.gateways {
            match AppContext::build(gw_config) {
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
