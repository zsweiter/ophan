use arc_swap::ArcSwap;
use std::sync::Arc;

use crate::config::{ConfigError, ListenerConfig, OphanConfig, SecurityConfig};
use crate::gateway::{AppContext, build_app_context};

/// Result of a config reload attempt.
pub enum ReloadOutcome {
    /// No files changed, nothing to do.
    NoChange,
    /// Non-listener config was hot-swapped; new requests use the updated config.
    Swapped,
    /// Listeners changed — requires a full graceful upgrade via pingora.
    NeedsUpgrade,
}

/// Shared application state holding the current config and derived context.
///
/// Both fields are atomic-swappable so readers see a consistent snapshot without locking.
pub struct AppState {
    pub context: ArcSwap<AppContext>,
    pub config: ArcSwap<OphanConfig>,
}

impl AppState {
    pub fn new(config: OphanConfig) -> Result<Self, Vec<ConfigError>> {
        let ctx = build_app_context(&config)?;
        Ok(Self {
            context: ArcSwap::from_pointee(ctx),
            config: ArcSwap::from_pointee(config),
        })
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

        let new_config = match OphanConfig::parse() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("config reload failed to parse: {:#}", e);
                return ReloadOutcome::NoChange;
            },
        };

        if self.listeners_differ(&current.listeners, &new_config.listeners) {
            return ReloadOutcome::NeedsUpgrade;
        }

        let new_ctx = match build_app_context(&new_config) {
            Ok(ctx) => ctx,
            Err(errors) => {
                for e in &errors {
                    tracing::error!("config reload validation error: {}", e);
                }

                return ReloadOutcome::NoChange;
            },
        };

        self.config.store(Arc::new(new_config));
        self.context.store(Arc::new(new_ctx));
        ReloadOutcome::Swapped
    }

    fn any_file_changed(&self, config: &OphanConfig) -> bool {
        if config.master_tracker.has_changed().unwrap_or(false) {
            return true;
        }

        config.gateway_trackers.iter().any(|t| t.has_changed().unwrap_or(false))
    }

    /// Checks if listeners differ significantly.
    ///
    /// Compares network-level options (address, TLS, transport) to determine if
    /// listener updates require a socket reload, while ignoring metadata like names.
    fn listeners_differ(&self, a: &[Arc<ListenerConfig>], b: &[Arc<ListenerConfig>]) -> bool {
        // Fail-fast detect remove or add new listeners
        if a.len() != b.len() {
            return true;
        }

        a.iter()
            .zip(b.iter())
            .any(|(a, b)| a.listen != b.listen || a.transport != b.transport || !self.security_equal(&a.security, &b.security))
    }

    fn security_equal(&self, a: &SecurityConfig, b: &SecurityConfig) -> bool {
        match (a, b) {
            (SecurityConfig::Plaintext, SecurityConfig::Plaintext) => true,
            (
                SecurityConfig::Tls { certs: ac, alpn_protocols: aa, min_version: am },
                SecurityConfig::Tls { certs: bc, alpn_protocols: ba, min_version: bm },
            ) => ac.cert == bc.cert && ac.key == bc.key && ac.client_ca == bc.client_ca && aa == ba && am == bm,
            _ => false,
        }
    }
}
