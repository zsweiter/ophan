use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use ophan_router::Router;
use ophan_waf::config::WafConfig;

use ophan_auth::AuthConfig;
use ophan_net::http::{HttpMethod, HttpMethodSet};

use crate::config::validate::{ConfigError, validate_config};
use crate::config::{
    BackendTarget, CorsConfig, LimiterConfig, OAuthConfig, OphanConfig, RouteStreaming, RouteTimeouts, UpstreamConfig,
};
use crate::gateway::rewrite::RewriteEngine;
use crate::middlewares::exclude::ExcludesEngine;

/// Top-level application state, atomically swapped on hot-reload.
///
/// Every request clones an `Arc<AppContext>` at the start of `request_filter`
/// and drops it when the response completes. This guarantees that in-flight
/// requests keep using the config they started with, even if a reload happens.
pub struct AppContext {
    pub router: Router<Arc<CompiledRoute>>,
    pub upstreams: HashMap<String, Arc<UpstreamConfig>>,
}

/// Fully compiled route data stored as the router value.
///
/// Everything is pre-resolved at insertion time so the hot path
/// (request_filter) never needs to touch `PolicyConfig` or config files.
pub struct CompiledRoute {
    pub backend: BackendTarget,
    pub methods: HttpMethodSet,
    pub rewrite: Option<RewriteEngine>,
    pub prepend_headers: Vec<String>,
    pub auth_policy: Option<Arc<OAuthConfig>>,
    pub auth_config: Option<Arc<AuthConfig>>,
    pub waf_policy: Option<Arc<WafConfig>>,
    pub cors_policy: Option<Arc<CorsConfig>>,
    pub limiter_policy: Option<Arc<LimiterConfig>>,
    pub timeouts: Option<Arc<RouteTimeouts>>,
    pub streaming: Option<Arc<RouteStreaming>>,
    pub waf_excludes: ExcludesEngine,
    pub cors_excludes: ExcludesEngine,
    pub auth_excludes: ExcludesEngine,
    pub limiter_excludes: ExcludesEngine,
}

impl CompiledRoute {
    pub fn apply_rewrite<'a>(&self, request_path: &'a str) -> Cow<'a, str> {
        if let Some(ref rewrite) = self.rewrite {
            return rewrite.execute(request_path);
        }
        Cow::Borrowed(request_path)
    }

    pub fn can_rewrite(&self) -> bool {
        self.rewrite.is_some()
    }
}

/// Builds an `AppContext` from a parsed config.
///
/// 1. Validates the config (upstream refs, policy refs, SSL files, etc.)
/// 2. Resolves all policy references into concrete configs
/// 3. Constructs the radix tree router with `Arc<CompiledRoute>` values
/// 4. Builds the upstreams map
pub fn build_app_context(config: &OphanConfig) -> Result<AppContext, Vec<ConfigError>> {
    let errors = validate_config(config);
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut router = Router::new();
    let mut upstreams = HashMap::new();

    for upstream in &config.upstreams {
        upstreams.insert(upstream.name.clone(), upstream.clone());
    }

    for route_cfg in &config.routes {
        let rewrite_engine = route_cfg
            .rewrite
            .as_ref()
            .and_then(|rw| rw.rules.as_ref().map(|rules| RewriteEngine::new(rules, Some(false))));

        let resolved_auth = route_cfg.auth_policy.as_ref().and_then(|p| config.policies.resolve_auth(p));
        let auth_config = resolved_auth
            .as_ref()
            .map(|cfg| Arc::new(crate::middlewares::auth::AuthMiddleware::make_auth_config(cfg)));
        let resolved_waf = route_cfg.waf_policy.as_ref().and_then(|p| config.policies.resolve_waf(p));
        let resolved_cors = route_cfg.cors_policy.as_ref().and_then(|p| config.policies.resolve_cors(p));
        let resolved_limiter = route_cfg.limiter_policy.as_ref().and_then(|p| config.policies.resolve_limiter(p));

        let route_methods = route_cfg.methods.clone();
        // If no methods were specified, default to ALL
        let methods = if route_methods.standard() == HttpMethod::NONE {
            HttpMethodSet::all()
        } else {
            route_methods
        };
        let compiled = Arc::new(CompiledRoute {
            backend: route_cfg.backend.clone(),
            methods,
            rewrite: rewrite_engine,
            prepend_headers: route_cfg.rewrite.as_ref().map_or(vec![], |rw| rw.prepend_headers.clone()),
            auth_policy: resolved_auth.clone(),
            auth_config: auth_config.clone(),
            waf_policy: resolved_waf.clone(),
            cors_policy: resolved_cors.clone(),
            limiter_policy: resolved_limiter.clone(),
            timeouts: route_cfg.timeouts.as_ref().map(|t| Arc::new(t.clone())),
            streaming: route_cfg.streaming.as_ref().map(|s| Arc::new(s.clone())),
            waf_excludes: ExcludesEngine::compile(&resolved_waf.as_ref().map_or(vec![], |c| c.excludes.clone())),
            cors_excludes: ExcludesEngine::compile(&resolved_cors.as_ref().map_or(vec![], |c| c.excludes.clone())),
            auth_excludes: ExcludesEngine::compile(&resolved_auth.as_ref().map_or(vec![], |c| c.excludes.clone())),
            limiter_excludes: ExcludesEngine::compile(&resolved_limiter.as_ref().map_or(vec![], |c| c.excludes.clone())),
        });

        if route_cfg.hosts.is_empty() {
            router.add_route(None, &route_cfg.path, route_cfg.methods.clone(), compiled).unwrap_or_else(|e| {
                tracing::error!("failed to add route '{}': {}", route_cfg.path, e);
            });
        } else {
            for host in &route_cfg.hosts {
                router
                    .add_route(Some(host), &route_cfg.path, route_cfg.methods.clone(), compiled.clone())
                    .unwrap_or_else(|e| {
                        tracing::error!("failed to add route '{}' on host '{}': {}", route_cfg.path, host, e);
                    });
            }
        }
    }

    Ok(AppContext { router, upstreams })
}
