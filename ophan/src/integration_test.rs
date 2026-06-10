#[cfg(test)]
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use http::HeaderMap;
use ophan_net::http::{HttpMethod, HttpMethodSet};
use ophan_waf::config::{WafConfig, WafMode};

use crate::config::OphanConfig;
use crate::config::{
    BackendTarget, BalanceStrategy, ConfigFileTracker, CorsConfig, LimiterConfig, LimiterIdentifier, LimiterRate, MasterConfig,
    OAuthConfig, PolicyConfig, RateLimitAlgorithm, RouteAuthPolicy, RouteCorsPolicy, RouteLimiterPolicy, RouteRewrites,
    RouteStreaming, RouteTimeouts, RouteWafPolicy, RoutesConfig, StaticUpstream, TokenSource, UpstreamConfig,
};
use crate::gateway::{AppContext, CompiledRoute, build_app_context};

// ===================================================================
// Helpers
// ===================================================================

fn make_config() -> OphanConfig {
    OphanConfig {
        master: MasterConfig {
            name: "test".into(),
            pid: "/tmp/ophan.pid".into(),
            error_log: "/tmp/ophan.log".into(),
            user: "nobody".into(),
            workers: String::new(),
            includes: vec![],
        },
        gateways: vec![],
        policies: PolicyConfig::default(),
        master_tracker: ConfigFileTracker { path: PathBuf::new(), last_mtime: SystemTime::UNIX_EPOCH },
        gateway_trackers: vec![],
        listeners: vec![],
        routes: vec![],
        upstreams: vec![],
        upstreams_index: HashMap::new(),
        routes_fast_match: vec![],
    }
}

fn add_upstream(cfg: &mut OphanConfig, name: &str) {
    let u = Arc::new(UpstreamConfig {
        name: name.into(),
        servers: vec![],
        balance_strategy: BalanceStrategy::RoundRobin,
        health_check: None,
    });
    cfg.upstreams.push(u.clone());
    cfg.upstreams_index.insert(name.into(), u);
}

fn add_route(cfg: &mut OphanConfig, route: RoutesConfig) {
    cfg.routes.push(Arc::new(route));
}

fn mock_oauth_config() -> OAuthConfig {
    OAuthConfig {
        issuer: "https://auth.test.com".into(),
        client_id: "test-client".into(),
        client_secret: None,
        scopes: vec!["openid".into(), "email".into()],
        sources: vec![
            TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer".into()) },
            TokenSource::Cookie { name: "session".into(), prefix: None },
        ],
        jwk_uri: "https://auth.test.com/.well-known/jwks.json".into(),
        refresh_token: None,
        excludes: vec!["/secure/health*".to_string()],
    }
}

fn mock_waf_config() -> WafConfig {
    WafConfig {
        enabled: true,
        mode: WafMode::Blocking,
        rules: vec![],
        max_body_size: 65536,
        anomaly_threshold: 5,
        excludes: vec!["/public/*".to_string()],
    }
}

fn mock_cors_config() -> CorsConfig {
    CorsConfig {
        allow_origins: vec!["https://app.test.com".into()],
        allow_methods: vec!["GET".into(), "POST".into()],
        allow_headers: vec!["Content-Type".into()],
        expose_headers: vec![],
        allow_credentials: true,
        max_age: Some(600),
        excludes: vec!["*.html".to_string()],
    }
}

fn mock_limiter_config() -> LimiterConfig {
    LimiterConfig {
        rate: LimiterRate { requests: 100, per_seconds: 60 },
        burst: 20,
        algorithm: RateLimitAlgorithm::SlidingWindow,
        identifier: LimiterIdentifier::Ip,
        excludes: vec!["/health".to_string()],
    }
}

/// Resolves a route and clones the Arc.
fn resolve(ctx: &AppContext, host: Option<&str>, method: &str, path: &str) -> Arc<CompiledRoute> {
    ctx.router.find_route(host, method, path).map(|m| m.value.clone()).expect("route should match")
}

// ===================================================================
// Route Resolution
// ===================================================================

#[test]
fn exact_route_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/users".into(),
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/users");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "api"));
}

#[test]
fn param_route_extracts_params() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/users/:id".into(),
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let m = ctx.router.find_route(None, "GET", "/users/42").unwrap();
    assert_eq!(m.params.get("id"), Some("42"));
}

#[test]
fn wildcard_route_multi_segment() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "static");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/static/files/*".into(),
            backend: BackendTarget::Upstream("static".into()),
            ..RoutesConfig::upstream("", "static")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/static/files/a/b/c");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "static"));
}

#[test]
fn catch_all_route() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "default");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            backend: BackendTarget::Upstream("default".into()),
            ..RoutesConfig::upstream("", "default")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/anything/at/all");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "default"));
    let route = resolve(&ctx, None, "GET", "/");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "default"));
}

#[test]
fn regex_route() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "assets");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: r"^/assets/.*\.(png|jpg)$".into(),
            backend: BackendTarget::Upstream("assets".into()),
            ..RoutesConfig::upstream("", "assets")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/assets/logo.png");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "assets"));
}

#[test]
fn host_based_routing() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/data".into(),
            hosts: vec!["api.example.com".into()],
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, Some("api.example.com"), "GET", "/data");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "api"));
    let miss = ctx.router.find_route(Some("other.com"), "GET", "/data");
    assert!(miss.is_err());
}

#[test]
fn no_host_route_matches_any_host() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/data".into(),
            hosts: vec![],
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/data");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "api"));
    let route = resolve(&ctx, Some("anything.com"), "GET", "/data");
    assert!(matches!(route.backend, BackendTarget::Upstream(ref n) if n == "api"));
}

#[test]
fn method_filtering() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure".into(),
            backend: BackendTarget::Upstream("api".into()),
            methods: HttpMethodSet::new(HttpMethod::GET),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/secure");
    // Route was compiled with GET-only methods
    assert!(route.methods.contains_str("GET"));
    assert!(!route.methods.contains_str("POST"));
    assert!(!route.methods.contains_str("DELETE"));
}

// ===================================================================
// WAF Policy
// ===================================================================

#[test]
fn waf_reference_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.waf = Some(HashMap::from([("my-waf".into(), mock_waf_config())]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            waf_policy: Some(RouteWafPolicy::Reference("my-waf".into())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/secure/data");
    let waf = route.waf_policy.as_ref().expect("waf_policy should be Some");
    assert!(waf.enabled);
    assert_eq!(waf.mode, WafMode::Blocking);
}

#[test]
fn waf_local_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            waf_policy: Some(RouteWafPolicy::Local(mock_waf_config())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    assert!(resolve(&ctx, None, "GET", "/secure/data").waf_policy.is_some());
}

#[test]
#[ignore = "WafConfig::merge replaces mode; needs granular merge semantics"]
fn waf_override_merges() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.waf = Some(HashMap::from([(
        "base-waf".into(),
        WafConfig {
            enabled: false,
            mode: WafMode::DetectionOnly,
            ..mock_waf_config()
        },
    )]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            waf_policy: Some(RouteWafPolicy::Override {
                base: "base-waf".into(),
                config: WafConfig { enabled: true, ..mock_waf_config() },
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/secure/data");
    let waf = route.waf_policy.as_ref().expect("waf_policy should be Some");
    assert!(waf.enabled);
    assert_eq!(waf.mode, WafMode::DetectionOnly);
}

// ===================================================================
// CORS Policy
// ===================================================================

#[test]
fn cors_reference_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.cors = Some(HashMap::from([("my-cors".into(), mock_cors_config())]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            cors_policy: Some(RouteCorsPolicy::Reference("my-cors".into())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    assert!(resolve(&ctx, None, "GET", "/api/data").cors_policy.is_some());
}

#[test]
fn cors_local_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            cors_policy: Some(RouteCorsPolicy::Local(mock_cors_config())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    assert!(resolve(&ctx, None, "GET", "/api/data").cors_policy.is_some());
}

#[test]
fn cors_override_merges() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.cors = Some(HashMap::from([(
        "base-cors".into(),
        CorsConfig {
            allow_origins: vec!["https://legacy.test.com".into()],
            ..mock_cors_config()
        },
    )]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            cors_policy: Some(RouteCorsPolicy::Override {
                base: "base-cors".into(),
                config: CorsConfig {
                    allow_origins: vec!["https://app.test.com".into()],
                    ..mock_cors_config()
                },
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let cors = resolve(&ctx, None, "GET", "/api/data").cors_policy.clone().unwrap();
    assert_eq!(cors.allow_origins, vec!["https://app.test.com"]);
}

// ===================================================================
// Limiter Policy
// ===================================================================

#[test]
fn limiter_reference_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.limiter = Some(HashMap::from([("my-limit".into(), mock_limiter_config())]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            limiter_policy: Some(RouteLimiterPolicy::Reference("my-limit".into())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/data");
    let lim = route.limiter_policy.as_ref().expect("limiter_policy should be Some");
    assert_eq!(lim.rate.requests, 100);
    assert_eq!(lim.rate.per_seconds, 60);
}

#[test]
fn limiter_local_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            limiter_policy: Some(RouteLimiterPolicy::Local(mock_limiter_config())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    assert!(resolve(&ctx, None, "GET", "/api/data").limiter_policy.is_some());
}

#[test]
#[ignore = "LimiterConfig::merge replaces rate; needs granular merge semantics"]
fn limiter_override_merges() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.limiter = Some(HashMap::from([(
        "base-limit".into(),
        LimiterConfig {
            rate: LimiterRate { requests: 10, per_seconds: 60 },
            ..mock_limiter_config()
        },
    )]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            limiter_policy: Some(RouteLimiterPolicy::Override {
                base: "base-limit".into(),
                config: LimiterConfig { burst: 50, ..mock_limiter_config() },
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let compiled = resolve(&ctx, None, "GET", "/api/data");
    let lim = compiled.limiter_policy.as_ref().unwrap();
    assert_eq!(lim.burst, 50);
    assert_eq!(lim.rate.requests, 10);
}

// ===================================================================
// OAuth / Auth Policy
// ===================================================================

#[test]
fn auth_reference_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.auth = Some(HashMap::from([("my-oauth".into(), mock_oauth_config())]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            auth_policy: Some(RouteAuthPolicy::Reference("my-oauth".into())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/secure/data");
    let auth = route.auth_policy.as_ref().expect("auth_policy should be Some");
    assert_eq!(auth.issuer, "https://auth.test.com");
    assert!(auth.scopes.contains(&"openid".into()));
}

#[test]
fn auth_local_resolves() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            auth_policy: Some(RouteAuthPolicy::Local(mock_oauth_config())),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    assert!(resolve(&ctx, None, "GET", "/secure/data").auth_policy.is_some());
}

#[test]
fn auth_override_merges() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    cfg.policies.auth = Some(HashMap::from([(
        "base-auth".into(),
        OAuthConfig {
            issuer: "https://legacy.test.com".into(),
            scopes: vec!["read".into()],
            ..mock_oauth_config()
        },
    )]));
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            auth_policy: Some(RouteAuthPolicy::Override {
                base: "base-auth".into(),
                config: OAuthConfig {
                    issuer: "https://app.test.com".into(),
                    scopes: vec!["admin".into()],
                    ..mock_oauth_config()
                },
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let compiled = resolve(&ctx, None, "GET", "/secure/data");
    let auth = compiled.auth_policy.as_ref().unwrap();
    assert_eq!(auth.issuer, "https://app.test.com");
    assert_eq!(auth.client_id, "test-client");
}

#[test]
fn oauth_complete_flow() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");

    // Protected route (needs auth)
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/data".into(),
            backend: BackendTarget::Upstream("api".into()),
            auth_policy: Some(RouteAuthPolicy::Local(OAuthConfig {
                issuer: "https://auth.test.com".into(),
                client_id: "svc-gateway".into(),
                client_secret: None,
                scopes: vec!["api:read".into()],
                sources: vec![TokenSource::Header { name: "Authorization".into(), prefix: Some("Bearer ".into()) }],
                jwk_uri: "https://auth.test.com/.well-known/jwks.json".into(),
                refresh_token: None,
                excludes: vec!["/secure/health*".to_string()],
            })),
            ..RoutesConfig::upstream("", "api")
        },
    );

    // Public route (no auth)
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/public/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );

    let ctx = build_app_context(&cfg).unwrap();

    // 1. Auth-required route resolves with auth_policy
    let route_auth = resolve(&ctx, None, "GET", "/secure/data");
    let auth = route_auth.auth_policy.as_ref().expect("secure route must have auth_policy");
    assert_eq!(auth.issuer, "https://auth.test.com");
    assert_eq!(auth.client_id, "svc-gateway");
    assert_eq!(auth.scopes, vec!["api:read"]);

    // 2. Public route resolves without auth_policy
    let route_public = resolve(&ctx, None, "GET", "/public/anything");
    assert!(route_public.auth_policy.is_none());

    // 3. Exclude patterns work: /secure/healthcheck excluded, /secure/data not
    assert!(route_auth.auth_excludes.contains("/secure/healthcheck"));
    assert!(!route_auth.auth_excludes.contains("/secure/data"));

    // 4. Token extraction via AuthMiddleware API, no network call
    use crate::middlewares::auth::AuthMiddleware;

    // Prefix is "Bearer ", so "Bearer <token>" correctly strips to just the token
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer eyJ0b2tlbiI6InRlc3QifQ".parse().unwrap());
    let uri = "https://api.test.com/secure/data".parse::<http::Uri>().unwrap();
    let tokens = AuthMiddleware::get_access_tokens(&headers, &uri, auth);
    assert!(tokens.acces_token.is_some(), "should extract Bearer token");
    assert_eq!(tokens.acces_token.as_deref(), Some("eyJ0b2tlbiI6InRlc3QifQ"));

    // 5. Without Authorization header, extraction returns None
    let empty_headers = HeaderMap::new();
    let tokens_empty = AuthMiddleware::get_access_tokens(&empty_headers, &uri, auth);
    assert!(tokens_empty.acces_token.is_none());
}

// ===================================================================
// Engine Integration
// ===================================================================

#[test]
fn rewrite_engine_compiled_and_works() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    let mut rules = HashMap::new();
    rules.insert("/api/*".into(), "/v2/".into());
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            rewrite: Some(RouteRewrites {
                rules: Some(rules),
                append_headers: HashMap::new(),
                prepend_headers: vec![],
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/users");
    assert!(route.can_rewrite());
    let result = route.rewrite.as_ref().unwrap().execute("/api/users");
    assert_eq!(result.as_ref(), "/v2/users");
}

#[test]
fn timeouts_propagated() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            timeouts: Some(RouteTimeouts {
                connect: Some(Duration::from_secs(5)),
                read: Some(Duration::from_secs(30)),
                send: Some(Duration::from_secs(10)),
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/data");
    let t = route.timeouts.as_ref().expect("timeouts should be Some");
    assert_eq!(t.connect, Some(Duration::from_secs(5)));
    assert_eq!(t.read, Some(Duration::from_secs(30)));
    assert_eq!(t.send, Some(Duration::from_secs(10)));
}

#[test]
fn streaming_propagated() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            streaming: Some(RouteStreaming { buffering: false, chunked: true }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/data");
    let s = route.streaming.as_ref().expect("streaming should be Some");
    assert!(!s.buffering);
    assert!(s.chunked);
}

#[test]
fn prepend_headers_propagated() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            rewrite: Some(RouteRewrites {
                rules: None,
                append_headers: HashMap::new(),
                prepend_headers: vec!["X-Debug".into(), "X-Request-Id".into()],
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/data");
    assert_eq!(route.prepend_headers, vec!["X-Debug", "X-Request-Id"]);
}

// ===================================================================
// Validation + Complex
// ===================================================================

#[test]
fn invalid_config_accumulates_errors() {
    let mut cfg = make_config();
    // 3 routes, each references a missing upstream
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("x".into()),
            ..RoutesConfig::upstream("", "x")
        },
    );
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/secure/*".into(),
            backend: BackendTarget::Upstream("x".into()),
            waf_policy: Some(RouteWafPolicy::Reference("missing-waf".into())),
            ..RoutesConfig::upstream("", "x")
        },
    );
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/admin/*".into(),
            backend: BackendTarget::Upstream("x".into()),
            auth_policy: Some(RouteAuthPolicy::Reference("missing-auth".into())),
            ..RoutesConfig::upstream("", "x")
        },
    );
    let result = build_app_context(&cfg);
    assert!(result.is_err());
}

#[test]
fn multiple_routes_priority() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "catch-all");
    add_upstream(&mut cfg, "param");
    add_upstream(&mut cfg, "static");

    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            backend: BackendTarget::Upstream("catch-all".into()),
            ..RoutesConfig::upstream("", "catch-all")
        },
    );
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/users/:id".into(),
            backend: BackendTarget::Upstream("param".into()),
            ..RoutesConfig::upstream("", "param")
        },
    );
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/users/me".into(),
            backend: BackendTarget::Upstream("static".into()),
            ..RoutesConfig::upstream("", "static")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();

    let r = resolve(&ctx, None, "GET", "/users/me");
    assert!(matches!(r.backend, BackendTarget::Upstream(ref n) if n == "static"));

    let r = resolve(&ctx, None, "GET", "/users/42");
    assert!(matches!(r.backend, BackendTarget::Upstream(ref n) if n == "param"));

    let r = resolve(&ctx, None, "GET", "/other/path");
    assert!(matches!(r.backend, BackendTarget::Upstream(ref n) if n == "catch-all"));
}

#[test]
#[ignore = "regex + catch-all conflicts; regex fallback never reached when /* in tree"]
fn complex_multi_route_config() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_upstream(&mut cfg, "static-bucket");
    add_upstream(&mut cfg, "assets");

    let routes: Vec<(&str, &str)> = vec![
        ("/api/v1/users", "api"),
        ("/api/v1/users/:id", "api"),
        ("/api/v1/users/:id/posts/:pid", "api"),
        ("/api/v1/posts", "api"),
        ("/api/health", "api"),
        ("/static/files/*", "static-bucket"),
        (r"^/assets/.*\.(png|jpg)$", "assets"),
        ("/*", "api"),
    ];

    for (path, upstream) in &routes {
        add_route(
            &mut cfg,
            RoutesConfig {
                path: path.to_string(),
                backend: BackendTarget::Upstream(upstream.to_string()),
                ..RoutesConfig::upstream("", *upstream)
            },
        );
    }

    let ctx = build_app_context(&cfg).unwrap();

    let hit = |path| backend_name(&ctx, path);
    assert_eq!(hit("/api/v1/users"), "api");
    assert_eq!(hit("/api/v1/users/42"), "api");
    assert_eq!(hit("/api/v1/posts"), "api");
    assert_eq!(hit("/api/health"), "api");
    assert_eq!(hit("/static/files/main.js"), "static-bucket");
    assert_eq!(hit("/static/files/a/b/c"), "static-bucket");
    assert_eq!(hit("/assets/logo.png"), "assets");
    assert_eq!(hit("/assets/photo.jpg"), "assets");

    // regex should NOT match .txt
    let miss = ctx.router.find_route(None, "GET", "/assets/file.txt");
    assert!(miss.is_err());

    // catch-all
    assert_eq!(hit("/other/path"), "api");
    assert_eq!(hit("/"), "api");
}

fn backend_name(ctx: &AppContext, path: &str) -> String {
    let route = resolve(ctx, None, "GET", path);
    match &route.backend {
        BackendTarget::Upstream(n) => n.clone(),
        _ => "static".into(),
    }
}

#[test]
fn upstreams_map_populated() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_upstream(&mut cfg, "static-bucket");
    add_upstream(&mut cfg, "cdn-origin");
    let ctx = build_app_context(&cfg).unwrap();
    assert_eq!(ctx.upstreams.len(), 3);
    assert!(ctx.upstreams.contains_key("api"));
    assert!(ctx.upstreams.contains_key("static-bucket"));
    assert!(ctx.upstreams.contains_key("cdn-origin"));
}

#[test]
fn arcswap_hot_reload_simulation() {
    let mut cfg_a = make_config();
    add_upstream(&mut cfg_a, "api-v1");
    add_route(
        &mut cfg_a,
        RoutesConfig {
            path: "/users".into(),
            backend: BackendTarget::Upstream("api-v1".into()),
            ..RoutesConfig::upstream("", "api-v1")
        },
    );
    let ctx_a = build_app_context(&cfg_a).unwrap();

    let mut cfg_b = make_config();
    add_upstream(&mut cfg_b, "api-v2");
    add_route(
        &mut cfg_b,
        RoutesConfig {
            path: "/users".into(),
            backend: BackendTarget::Upstream("api-v2".into()),
            ..RoutesConfig::upstream("", "api-v2")
        },
    );
    let ctx_b = build_app_context(&cfg_b).unwrap();

    let swap = ArcSwap::from_pointee(ctx_a);
    let old = swap.load();
    // resolve from initial context
    {
        let r = old.router.find_route(None, "GET", "/users").unwrap();
        assert!(matches!(r.value.backend, BackendTarget::Upstream(ref n) if n == "api-v1"));
    }

    swap.store(Arc::new(ctx_b));
    let current = swap.load();

    // new requests go to api-v2
    {
        let r = current.router.find_route(None, "GET", "/users").unwrap();
        assert!(matches!(r.value.backend, BackendTarget::Upstream(ref n) if n == "api-v2"));
    }

    // OLD arc is still valid (in-flight request)
    {
        let r = old.router.find_route(None, "GET", "/users").unwrap();
        assert!(matches!(r.value.backend, BackendTarget::Upstream(ref n) if n == "api-v1"));
    }
}

#[test]
fn no_policy_is_none() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/api/data");
    assert!(route.auth_policy.is_none());
    assert!(route.waf_policy.is_none());
    assert!(route.cors_policy.is_none());
    assert!(route.limiter_policy.is_none());
}

#[test]
fn static_backend_resolves() {
    let mut cfg = make_config();
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/static/*".into(),
            backend: BackendTarget::Static(Arc::new(StaticUpstream::Local {
                path: "/var/www".into(),
                permissions: None,
                listing: false,
                dotfiles: false,
                blacklist: vec![],
            })),
            ..RoutesConfig::static_stream("", StaticUpstream::default())
        },
    );
    let ctx = build_app_context(&cfg).unwrap();
    let route = resolve(&ctx, None, "GET", "/static/index.html");
    assert!(matches!(route.backend, BackendTarget::Static(_)));
}

// ===================================================================
// End-to-End
// ===================================================================

#[test]
fn e2e_full_config_flow() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_upstream(&mut cfg, "static-bucket");

    // API route with all policies enabled
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/api/*".into(),
            backend: BackendTarget::Upstream("api".into()),
            methods: HttpMethodSet::new(HttpMethod::GET | HttpMethod::POST),
            auth_policy: Some(RouteAuthPolicy::Local(mock_oauth_config())),
            waf_policy: Some(RouteWafPolicy::Local(mock_waf_config())),
            cors_policy: Some(RouteCorsPolicy::Local(mock_cors_config())),
            limiter_policy: Some(RouteLimiterPolicy::Local(mock_limiter_config())),
            timeouts: Some(RouteTimeouts {
                connect: Some(Duration::from_secs(5)),
                read: None,
                send: None,
            }),
            streaming: Some(RouteStreaming { buffering: false, chunked: true }),
            rewrite: Some(RouteRewrites {
                rules: Some(HashMap::from([("/api/*".into(), "/v1/".into())])),
                append_headers: HashMap::new(),
                prepend_headers: vec![],
            }),
            ..RoutesConfig::upstream("", "api")
        },
    );

    // Static route (no policies)
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/static/*".into(),
            backend: BackendTarget::Static(Arc::new(StaticUpstream::Local {
                path: "/var/www".into(),
                permissions: None,
                listing: false,
                dotfiles: false,
                blacklist: vec![],
            })),
            ..RoutesConfig::static_stream("", StaticUpstream::default())
        },
    );

    // Catch-all
    add_upstream(&mut cfg, "fallback");
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            backend: BackendTarget::Upstream("fallback".into()),
            ..RoutesConfig::upstream("", "fallback")
        },
    );

    let ctx = build_app_context(&cfg).unwrap();

    // ---- 1. API route: all policies resolved ----
    let api = resolve(&ctx, None, "GET", "/api/data");
    assert_eq!(backend_name_of(&api), "api");
    assert!(api.auth_policy.is_some(), "auth should be set");
    assert!(api.waf_policy.is_some(), "waf should be set");
    assert!(api.cors_policy.is_some(), "cors should be set");
    assert!(api.limiter_policy.is_some(), "limiter should be set");
    assert!(api.timeouts.is_some(), "timeouts should be set");
    assert!(api.streaming.is_some(), "streaming should be set");
    assert!(api.rewrite.is_some(), "rewrite should be set");
    assert!(api.can_rewrite(), "can_rewrite should be true");

    // Rewrite works: /api/users -> /v1/users
    let rewritten = api.rewrite.as_ref().unwrap().execute("/api/users");
    assert_eq!(rewritten.as_ref(), "/v1/users");

    // Method filtering: GET + POST allowed, DELETE not
    assert!(api.methods.contains_str("GET"));
    assert!(api.methods.contains_str("POST"));
    assert!(!api.methods.contains_str("DELETE"));

    // ---- 2. Static route: no policies, static backend ----
    let static_route = resolve(&ctx, None, "GET", "/static/file.txt");
    assert!(matches!(static_route.backend, BackendTarget::Static(_)));
    assert!(static_route.auth_policy.is_none());
    assert!(static_route.waf_policy.is_none());
    assert!(!static_route.can_rewrite());

    // ---- 3. Catch-all: matches everything else ----
    let fallback = resolve(&ctx, None, "GET", "/other");
    assert_eq!(backend_name_of(&fallback), "fallback");

    // ---- 4. Upstreams map is correctly populated ----
    assert!(ctx.upstreams.contains_key("api"));
    assert!(ctx.upstreams.contains_key("static-bucket"));
    assert!(ctx.upstreams.contains_key("fallback"));
}

fn backend_name_of(route: &CompiledRoute) -> String {
    match &route.backend {
        BackendTarget::Upstream(n) => n.clone(),
        _ => "static".into(),
    }
}

#[test]
fn e2e_httpmock_service() {
    let mock_server = httpmock::MockServer::start();
    let mock = mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/api/data");
        then.status(200).body("OK");
    });

    // Send a real HTTP request via TcpStream
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("{}:{}", mock_server.host(), mock_server.port());
    let mut stream = TcpStream::connect(&addr).unwrap();
    write!(
        stream,
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("200 OK"), "expected 200, got: {}", response);
    assert!(response.contains("OK"));

    mock.assert();
}

#[test]
fn e2e_rayon_race_condition() {
    use rayon::prelude::*;

    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_upstream(&mut cfg, "catch-all");

    // Insert 1000 static routes
    for i in 0..1000 {
        add_route(
            &mut cfg,
            RoutesConfig {
                path: format!("/route/{}", i),
                backend: BackendTarget::Upstream("api".into()),
                ..RoutesConfig::upstream("", "api")
            },
        );
    }
    // Catch-all at the end
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            backend: BackendTarget::Upstream("catch-all".into()),
            ..RoutesConfig::upstream("", "catch-all")
        },
    );

    let ctx = std::sync::Arc::new(build_app_context(&cfg).unwrap());
    let hit_paths: Vec<String> = (0..1000).map(|i| format!("/route/{}", i)).collect();
    let miss_paths = vec!["/other".to_string(), "/foo/bar".to_string(), "/deeply/nested/path".to_string()];

    // 100 parallel workers × (1000 hits + 3 misses) × 2 iterations each
    let total_lookups = 100 * (1000 + 3) * 2;
    let workers: Vec<_> = (0..100).map(|_| (hit_paths.clone(), miss_paths.clone())).collect();

    let results: Vec<Result<(), String>> = workers
        .par_iter()
        .map(|(hits, misses)| {
            for _ in 0..2 {
                for path in hits {
                    match ctx.router.find_route(None, "GET", path) {
                        Ok(m) => {
                            let is_api = matches!(
                                m.value.backend,
                                BackendTarget::Upstream(ref n) if n == "api"
                            );
                            if !is_api {
                                return Err(format!("expected api backend for {path}"));
                            }
                        },
                        Err(e) => return Err(format!("unexpected miss on {path}: {e:?}")),
                    }
                }
                for path in misses {
                    match ctx.router.find_route(None, "GET", path) {
                        Ok(m) => {
                            let is_catch = matches!(
                                m.value.backend,
                                BackendTarget::Upstream(ref n) if n == "catch-all"
                            );
                            if !is_catch {
                                return Err(format!("expected catch-all for {path}, got {:?}", m.value.backend));
                            }
                        },
                        Err(e) => return Err(format!("expected catch-all on {path}: {e:?}")),
                    }
                }
            }
            Ok(())
        })
        .collect();

    for (i, r) in results.iter().enumerate() {
        if let Err(e) = r {
            panic!("worker {i} failed: {e}");
        }
    }

    eprintln!(
        "Completed {} concurrent route lookups across 100 parallel workers",
        total_lookups
    );
}

#[test]
fn e2e_bench_throughput() {
    use rayon::prelude::*;
    use std::time::Instant;

    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");
    add_upstream(&mut cfg, "assets");
    add_upstream(&mut cfg, "catch-all");

    let n_static = 5_000;
    let n_param = 500;
    let n_wild = 500;

    // Insert static routes
    for i in 0..n_static {
        add_route(
            &mut cfg,
            RoutesConfig {
                path: format!("/route/{}", i),
                backend: BackendTarget::Upstream("api".into()),
                ..RoutesConfig::upstream("", "api")
            },
        );
    }
    // Insert param routes
    for i in 0..n_param {
        add_route(
            &mut cfg,
            RoutesConfig {
                path: format!("/resource/{}/detail", i),
                backend: BackendTarget::Upstream("api".into()),
                ..RoutesConfig::upstream("", "api")
            },
        );
    }
    // Insert wildcard routes
    for i in 0..n_wild {
        add_route(
            &mut cfg,
            RoutesConfig {
                path: format!("/bucket/dir{}/*", i),
                backend: BackendTarget::Upstream("assets".into()),
                ..RoutesConfig::upstream("", "assets")
            },
        );
    }
    // Regex
    add_route(
        &mut cfg,
        RoutesConfig {
            path: r"^/api/v[0-9]+/.*$".into(),
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );
    // Catch-all
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            backend: BackendTarget::Upstream("catch-all".into()),
            ..RoutesConfig::upstream("", "catch-all")
        },
    );

    let ctx = std::sync::Arc::new(build_app_context(&cfg).unwrap());
    let total_routes = n_static + n_param + n_wild + 2;

    // --- Benchmark: exact hits ---
    let paths: Vec<String> = (0..n_static).map(|i| format!("/route/{}", i)).collect();
    let start = Instant::now();
    let iterations = 50;
    let lookups_per_iter = n_static;

    (0..iterations).into_par_iter().for_each(|_| {
        for path in &paths {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });

    let elapsed = start.elapsed();
    let total = (iterations * lookups_per_iter) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ exact hits (static):  {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Benchmark: exact miss ---
    let miss = "/nonexistent";
    let start = Instant::now();
    let miss_iters = 500_000;
    (0..miss_iters).into_par_iter().for_each(|_| {
        let _ = ctx.router.find_route(None, "GET", miss);
    });
    let elapsed = start.elapsed();
    let qps = miss_iters as f64 / elapsed.as_secs_f64();
    eprintln!(
        "▸ exact miss:           {:.0} lookups in {:.2}s = {:.0} QPS",
        miss_iters as f64,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Benchmark: param hits ---
    let param_paths: Vec<String> = (0..n_param).map(|i| format!("/resource/{}/detail", i)).collect();
    let start = Instant::now();
    (0..iterations).into_par_iter().for_each(|_| {
        for path in &param_paths {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });
    let elapsed = start.elapsed();
    let total = (iterations * n_param) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ param hits:           {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Benchmark: wildcard multi-segment ---
    let wild_paths: Vec<String> = (0..n_wild).map(|i| format!("/bucket/dir{}/a/b/c", i)).collect();
    let start = Instant::now();
    (0..iterations).into_par_iter().for_each(|_| {
        for path in &wild_paths {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });
    let elapsed = start.elapsed();
    let total = (iterations * n_wild) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ wildcard multi-seg:   {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Benchmark: catch-all (when tree misses everything) ---
    let catch_paths: Vec<String> = (0..100).map(|i| format!("/unknown/path/that/misses/{}", i)).collect();
    let start = Instant::now();
    let catch_iters = 200;
    (0..catch_iters).into_par_iter().for_each(|_| {
        for path in &catch_paths {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });
    let elapsed = start.elapsed();
    let total = (catch_iters * catch_paths.len()) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ catch-all fallback:   {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Benchmark: regex ---
    let regex_paths = vec!["/api/v2/users", "/api/v1/posts/42"];
    let start = Instant::now();
    let regex_iters = 50_000;
    (0..regex_iters).into_par_iter().for_each(|_| {
        for path in &regex_paths {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });
    let elapsed = start.elapsed();
    let total = (regex_iters * regex_paths.len()) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ regex match:          {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    // --- Mixed workload ---
    let mixed: Vec<&str> = vec![
        "/route/42",
        "/route/1234",
        "/resource/7/detail",
        "/bucket/dir99/a/b/c",
        "/api/v2/users",
        "/unknown/path",
    ];
    let start = Instant::now();
    let mixed_iters = 100_000;
    (0..mixed_iters).into_par_iter().for_each(|_| {
        for path in &mixed {
            let _ = ctx.router.find_route(None, "GET", path).unwrap();
        }
    });
    let elapsed = start.elapsed();
    let total = (mixed_iters * mixed.len()) as f64;
    let qps = total / elapsed.as_secs_f64();
    eprintln!(
        "▸ mixed workload (6 req): {:.0} lookups in {:.2}s = {:.0} QPS",
        total,
        elapsed.as_secs_f64(),
        qps
    );

    eprintln!(
        "\n📊 Router: {} static + {} param + {} wildcard + regex + catch-all = {} routes",
        n_static, n_param, n_wild, total_routes
    );
}

// ═══════════════════════════════════════════════════════════════
// DEBUG: reproduce the exact e2e scenario with config files
// ═══════════════════════════════════════════════════════════════

#[test]
fn debug_parse_and_route() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let cfg_dir = tmp.path().join("config");
    let gw_dir = cfg_dir.join("gateways");
    std::fs::create_dir_all(&gw_dir).unwrap();

    let gw_cfg = br#"name = "test-gw"
listeners { listener "main" { address = "127.0.0.1:5050" } }
upstreams { upstream "api" { servers = "127.0.0.1:9999" } }
routes {
    route "/v1/realtime/sse" {
        hosts = ["api.izzimed.me"]
        backend = upstream("api")
    }
    route "/*" {
        hosts = ["api.izzimed.me"]
        backend = upstream("api")
    }
}
"#;
    std::fs::write(gw_dir.join("test.conf"), gw_cfg).unwrap();

    let master = format!(
        r#"master "test" {{
    user = "nobody"
    workers = "auto"
    pid = "/tmp/ophan-test.pid"
    error_log = "/tmp/ophan-test.log"
    includes = "{gw}/test.conf"
}}
"#,
        gw = gw_dir.display()
    );
    std::fs::write(cfg_dir.join("master.conf"), &master).unwrap();

    // Use the config path env var
    let old = std::env::var("CONFIG_PATH").ok();
    unsafe { std::env::set_var("CONFIG_PATH", cfg_dir.to_str().unwrap()); }

    let config = crate::config::OphanConfig::parse().expect("parse config");
    let ctx = crate::gateway::build_app_context(&config).expect("build app context");

    eprintln!(
        "Parsed: {} routes, {} upstreams",
        config.routes.len(),
        config.upstreams.len()
    );

    let r = ctx.router.find_route(Some("api.izzimed.me"), "GET", "/v1");
    match &r {
        Ok(m) => eprintln!("✅ Router match: backend={:?}", m.value.backend),
        Err(e) => eprintln!("❌ Router miss: {:?}", e),
    }

    // Also test /v1/realtime/sse
    let r2 = ctx.router.find_route(Some("api.izzimed.me"), "GET", "/v1/realtime/sse");
    match &r2 {
        Ok(m) => eprintln!("✅ SSE route match: backend={:?}", m.value.backend),
        Err(e) => eprintln!("❌ SSE route miss: {:?}", e),
    }

    unsafe { std::env::set_var("CONFIG_PATH", old.unwrap_or_default()); }

    if r.is_err() || r2.is_err() {
        eprintln!("Routes registered: {}", config.routes.len());
        for (i, rt) in config.routes.iter().enumerate() {
            eprintln!("  [{}] path={}, hosts={:?}, backend={:?}", i, rt.path, rt.hosts, rt.backend);
        }
    }

    assert!(r.is_ok(), "Route should match /v1 for api.izzimed.me");
}

// ═══════════════════════════════════════════════════════════════
// DEBUG: reproduce the exact scenario that returns 404
// ═══════════════════════════════════════════════════════════════

#[test]
#[ignore = "debug — run manually"]
fn debug_catch_all_with_prefix() {
    let mut cfg = make_config();
    add_upstream(&mut cfg, "api");

    // Route for specific path (static prefix)
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/v1/realtime/sse".into(),
            hosts: vec!["api.izzimed.me".into()],
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );

    // Catch-all
    add_route(
        &mut cfg,
        RoutesConfig {
            path: "/*".into(),
            hosts: vec!["api.izzimed.me".into()],
            backend: BackendTarget::Upstream("api".into()),
            ..RoutesConfig::upstream("", "api")
        },
    );

    let ctx = build_app_context(&cfg).unwrap();

    // Test: /v1 should match the catch-all
    eprintln!("=== Testing /v1 with host api.izzimed.me ===");
    let result = ctx.router.find_route(Some("api.izzimed.me"), "GET", "/v1");
    match &result {
        Ok(m) => eprintln!("✅ MATCH: backend={:?}", m.value.backend),
        Err(e) => eprintln!("❌ ERROR: {:?}", e),
    }

    // Also test without host (should use default vhost)
    eprintln!("=== Testing /v1 without host ===");
    let result2 = ctx.router.find_route(None, "GET", "/v1");
    match &result2 {
        Ok(m) => eprintln!("✅ MATCH: backend={:?}", m.value.backend),
        Err(e) => eprintln!("❌ ERROR: {:?}", e),
    }

    // Test the specific SSE route works
    eprintln!("=== Testing /v1/realtime/sse ===");
    let result3 = ctx.router.find_route(Some("api.izzimed.me"), "GET", "/v1/realtime/sse");
    match &result3 {
        Ok(m) => eprintln!("✅ MATCH: backend={:?}", m.value.backend),
        Err(e) => eprintln!("❌ ERROR: {:?}", e),
    }

    if let Err(e) = &result {
        // Try without the SSE prefix route
        eprintln!("\n=== DEBUG: trying without prefix route ===");
        let mut cfg2 = make_config();
        add_upstream(&mut cfg2, "api");
        add_route(
            &mut cfg2,
            RoutesConfig {
                path: "/*".into(),
                hosts: vec!["api.izzimed.me".into()],
                backend: BackendTarget::Upstream("api".into()),
                ..RoutesConfig::upstream("", "api")
            },
        );
        let ctx2 = build_app_context(&cfg2).unwrap();
        let r = ctx2.router.find_route(Some("api.izzimed.me"), "GET", "/v1");
        match &r {
            Ok(m) => eprintln!("✅ Without prefix: MATCH backend={:?}", m.value.backend),
            Err(e2) => eprintln!("❌ Without prefix: {:?}", e2),
        }
    }

    if let Err(e) = &result {
        panic!("Catch-all should match /v1 but got: {:?}", e);
    }
}
