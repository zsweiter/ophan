use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::config::parts::{
    BackendTarget, ListenerConfig, RouteAuthPolicy, RouteCorsPolicy, RouteLimiterPolicy, RouteWafPolicy, RoutesConfig,
    SecurityConfig,
};
use crate::config::{OphanConfig, UpstreamConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    E001, // Upstream references
    E002, // Policy references
    E003, // SSL certificate / key file existence
    E004, // Port conflicts
    E005, // Duplicate upstreams
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::E001 => "E001",
            ErrorCode::E002 => "E002",
            ErrorCode::E003 => "E003",
            ErrorCode::E004 => "E004",
            ErrorCode::E005 => "E005",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single configuration validation error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub code: ErrorCode,
    pub message: String,
}

impl ConfigError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}]: {}", self.code, self.message)
    }
}

/// Validates a fully parsed `OphanConfig` for semantic errors.
///
/// Checks cross-references (upstream names, policy names), file existence
/// (SSL certs), port conflicts, and duplicate names. Accumulates ALL errors
/// in a single pass so the user gets complete feedback.
pub fn validate_config(config: &OphanConfig) -> Vec<ConfigError> {
    let mut errors = Vec::with_capacity(2);

    validate_upstream_refs(&mut errors, &config.routes, &config.upstreams_index);
    validate_policy_refs(&mut errors, &config.routes, config);
    validate_ssl_files(&mut errors, &config.listeners);
    validate_port_conflicts(&mut errors, &config.listeners);
    validate_duplicate_upstreams(&mut errors, &config.upstreams);

    errors
}

// ---------------------------------------------------------------------------
// E001: Upstream references
// ---------------------------------------------------------------------------

fn validate_upstream_refs(
    errors: &mut Vec<ConfigError>,
    routes: &[Arc<RoutesConfig>],
    upstreams_index: &HashMap<String, Arc<UpstreamConfig>>,
) {
    for route in routes {
        if let BackendTarget::Upstream(name) = &route.backend
            && !upstreams_index.contains_key(name.as_str())
        {
            errors.push(ConfigError::new(
                ErrorCode::E001,
                format!("route '{}' references upstream '{}' which is not defined", route.path, name,),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// E002: Policy references
// ---------------------------------------------------------------------------

fn validate_policy_refs(errors: &mut Vec<ConfigError>, routes: &[Arc<RoutesConfig>], config: &OphanConfig) {
    for route in routes {
        check_waf_ref(errors, route, config);
        check_auth_ref(errors, route, config);
        check_cors_ref(errors, route, config);
        check_limiter_ref(errors, route, config);
    }
}

fn check_waf_ref(errors: &mut Vec<ConfigError>, route: &RoutesConfig, config: &OphanConfig) {
    match &route.waf_policy {
        Some(RouteWafPolicy::Reference(name)) => {
            let found = config.policies.waf.as_ref().and_then(|m| m.get(name)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!("route '{}' references waf policy '{}' which is not defined", route.path, name,),
                ));
            }
        },
        Some(RouteWafPolicy::Override { base, .. }) => {
            let found = config.policies.waf.as_ref().and_then(|m| m.get(base)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!("route '{}' extends waf policy '{}' which is not defined", route.path, base,),
                ));
            }
        },
        Some(RouteWafPolicy::Local(_)) | None => {}, // inline config, always valid
    }
}

fn check_auth_ref(errors: &mut Vec<ConfigError>, route: &RoutesConfig, config: &OphanConfig) {
    match &route.auth_policy {
        Some(RouteAuthPolicy::Reference(name)) => {
            let found = config.policies.auth.as_ref().and_then(|m| m.get(name)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!(
                        "route '{}' references auth policy '{}' which is not defined",
                        route.path, name,
                    ),
                ));
            }
        },
        Some(RouteAuthPolicy::Override { base, .. }) => {
            let found = config.policies.auth.as_ref().and_then(|m| m.get(base)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!("route '{}' extends auth policy '{}' which is not defined", route.path, base,),
                ));
            }
        },
        Some(RouteAuthPolicy::Local(_)) | None => {},
    }
}

fn check_cors_ref(errors: &mut Vec<ConfigError>, route: &RoutesConfig, config: &OphanConfig) {
    match &route.cors_policy {
        Some(RouteCorsPolicy::Reference(name)) => {
            let found = config.policies.cors.as_ref().and_then(|m| m.get(name)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!(
                        "route '{}' references cors policy '{}' which is not defined",
                        route.path, name,
                    ),
                ));
            }
        },
        Some(RouteCorsPolicy::Override { base, .. }) => {
            let found = config.policies.cors.as_ref().and_then(|m| m.get(base)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!("route '{}' extends cors policy '{}' which is not defined", route.path, base,),
                ));
            }
        },
        Some(RouteCorsPolicy::Local(_)) | None => {},
    }
}

fn check_limiter_ref(errors: &mut Vec<ConfigError>, route: &RoutesConfig, config: &OphanConfig) {
    match &route.limiter_policy {
        Some(RouteLimiterPolicy::Reference(name)) => {
            let found = config.policies.limiter.as_ref().and_then(|m| m.get(name)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!(
                        "route '{}' references limiter policy '{}' which is not defined",
                        route.path, name,
                    ),
                ));
            }
        },
        Some(RouteLimiterPolicy::Override { base, .. }) => {
            let found = config.policies.limiter.as_ref().and_then(|m| m.get(base)).is_some();
            if !found {
                errors.push(ConfigError::new(
                    ErrorCode::E002,
                    format!(
                        "route '{}' extends limiter policy '{}' which is not defined",
                        route.path, base,
                    ),
                ));
            }
        },
        Some(RouteLimiterPolicy::Local(_)) | None => {},
    }
}

// ---------------------------------------------------------------------------
// E003: SSL certificate / key file existence
// ---------------------------------------------------------------------------

fn validate_ssl_files(errors: &mut Vec<ConfigError>, listeners: &[Arc<ListenerConfig>]) {
    for listener in listeners {
        if let SecurityConfig::Tls { certs, .. } = &listener.security {
            if !Path::new(&certs.cert).exists() {
                errors.push(ConfigError::new(
                    ErrorCode::E003,
                    format!(
                        "listener '{}' references SSL cert '{}' which does not exist",
                        listener.name, certs.cert,
                    ),
                ));
            }
            if !Path::new(&certs.key).exists() {
                errors.push(ConfigError::new(
                    ErrorCode::E003,
                    format!(
                        "listener '{}' references SSL key '{}' which does not exist",
                        listener.name, certs.key,
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E004: Port conflicts
// ---------------------------------------------------------------------------
fn validate_port_conflicts(errors: &mut Vec<ConfigError>, listeners: &[Arc<ListenerConfig>]) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(listeners.len());

    for listener in listeners {
        for addr in &listener.listen {
            if !seen.insert(addr) {
                errors.push(ConfigError::new(
                    ErrorCode::E004,
                    format!("port '{}' is already bound by listener '{}'", addr, listener.name,),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E005: Duplicate upstream names
// ---------------------------------------------------------------------------
fn validate_duplicate_upstreams(errors: &mut Vec<ConfigError>, upstreams: &[Arc<UpstreamConfig>]) {
    let mut seen: HashSet<&str> = HashSet::with_capacity(upstreams.len());

    for upstream in upstreams {
        if !seen.insert(&upstream.name) {
            errors.push(ConfigError::new(
                ErrorCode::E005,
                format!("upstream '{}' is defined multiple times", upstream.name,),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;

    use super::*;
    use crate::config::dsl_parser::MasterConfig;
    use crate::config::parse::ConfigFileTracker;
    use crate::config::parts::{ListenerConfig, PolicyConfig, SecurityConfig, UpstreamConfig};
    use ophan_net::http::{HttpMethod, HttpMethodSet};

    fn make_valid_config() -> OphanConfig {
        OphanConfig {
            master: MasterConfig {
                name: "test".into(),
                pid: "/tmp/ophan.pid".into(),
                error_log: "/tmp/ophan.log".into(),
                user: "nobody".into(),
                workers: 1,
                includes: vec![],
            },
            gateways: vec![],
            policies: PolicyConfig::default(),
            master_tracker: ConfigFileTracker { path: PathBuf::new(), last_mtime: SystemTime::UNIX_EPOCH },
            gateway_trackers: vec![],
            listeners: vec![],
            routes: vec![],
            upstreams: vec![],
            upstreams_index: std::collections::HashMap::new(),
            routes_fast_match: vec![],
        }
    }

    #[test]
    fn no_errors_for_empty_config() {
        let cfg = make_valid_config();
        assert!(validate_config(&cfg).is_empty());
    }

    #[test]
    fn detects_missing_upstream() {
        let mut cfg = make_valid_config();
        let route = RoutesConfig {
            path: "/api/*".into(),
            hosts: vec![],
            methods: HttpMethodSet::new(HttpMethod::GET),
            backend: BackendTarget::Upstream("missing-upstream".into()),
            auth_policy: None,
            waf_policy: None,
            cors_policy: None,
            limiter_policy: None,
            priority: 1,
            rewrite: None,
            timeouts: None,
            streaming: None,
        };
        cfg.routes.push(Arc::new(route));
        let errors = validate_config(&cfg);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, ErrorCode::E001);
        assert!(errors[0].message.contains("missing-upstream"));
    }

    #[test]
    fn detects_missing_waf_policy() {
        let mut cfg = make_valid_config();
        // Add the referenced upstream so E001 doesn't fire
        let upstream = Arc::new(UpstreamConfig {
            name: "api".into(),
            servers: vec![],
            balance_strategy: crate::config::parts::BalanceStrategy::RoundRobin,
            health_check: None,
        });
        cfg.upstreams.push(Arc::clone(&upstream));
        cfg.upstreams_index.insert("api".into(), upstream);
        let route = RoutesConfig {
            path: "/secure/*".into(),
            hosts: vec![],
            methods: HttpMethodSet::new(HttpMethod::GET),
            backend: BackendTarget::Upstream("api".into()),
            auth_policy: None,
            waf_policy: Some(RouteWafPolicy::Reference("nonexistent-waf".into())),
            cors_policy: None,
            limiter_policy: None,
            priority: 1,
            rewrite: None,
            timeouts: None,
            streaming: None,
        };
        cfg.routes.push(Arc::new(route));
        let errors = validate_config(&cfg);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, ErrorCode::E002);
        assert!(errors[0].message.contains("waf"));
        assert!(errors[0].message.contains("nonexistent-waf"));
    }

    #[test]
    fn detects_ssl_cert_missing() {
        let mut cfg = make_valid_config();
        let listener = ListenerConfig {
            name: "https-gw".into(),
            listen: vec!["0.0.0.0:443".into()],
            transport: crate::config::parts::NetworkTransport::Tcp("0.0.0.0:443".parse().unwrap()),
            security: SecurityConfig::Tls {
                certs: crate::config::parts::SSLConfig {
                    cert: "/tmp/nonexistent-cert.pem".into(),
                    key: "/tmp/nonexistent-key.pem".into(),
                    client_ca: None,
                },
                alpn_protocols: vec![],
                min_version: crate::config::parts::TlsVersion::Tls13,
            },
            protocols: vec![],
        };
        cfg.listeners.push(Arc::new(listener));
        let errors = validate_config(&cfg);
        assert!(errors.iter().any(|e| e.code == ErrorCode::E003));
    }
}
