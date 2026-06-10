use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::signal::unix::{SignalKind, signal};

use crate::config::OphanConfig;
use crate::gateway::{AppContext, build_app_context};

/// Sets up SIGHUP / SIGUSR1 handlers for hot-reload.
///
/// On SIGHUP  (gentle): re-reads config files only if mtime changed.
/// On SIGUSR1 (force):  re-reads config files unconditionally.
///
/// If the new config fails validation, the old config keeps running
/// and errors are logged — the server is never killed.
pub async fn setup_signal_handlers(
    config_swap: &ArcSwap<OphanConfig>,
    app_swap: &ArcSwap<AppContext>,
) {
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to setup SIGHUP handler: {}", e);
            return;
        },
    };
    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to setup SIGUSR1 handler: {}", e);
            return;
        },
    };

    loop {
        tokio::select! {
            _ = sighup.recv() => {
                tracing::info!("Received SIGHUP, reloading config...");
                reload_config(config_swap, app_swap, false).await;
            }
            _ = sigusr1.recv() => {
                tracing::info!("Received SIGUSR1, force reloading config...");
                reload_config(config_swap, app_swap, true).await;
            }
        }
    }
}

async fn reload_config(
    config_swap: &ArcSwap<OphanConfig>,
    app_swap: &ArcSwap<AppContext>,
    force: bool,
) {
    let snapshot = config_swap.load();
    let mut current = OphanConfig::clone(&snapshot);
    drop(snapshot);

    match current.reload_if_changed(force) {
        Ok(true) => {
            match build_app_context(&current) {
                Ok(new_ctx) => {
                    config_swap.store(Arc::new(current));
                    app_swap.store(Arc::new(new_ctx));
                    tracing::info!("Config reloaded successfully");
                },
                Err(errors) => {
                    for e in &errors {
                        tracing::error!("Reload rejected: {}", e);
                    }
                    tracing::error!(
                        "Config has {} error(s) — keeping old config running",
                        errors.len()
                    );
                },
            }
        },
        Ok(false) => {
            tracing::info!("No config changes detected");
        },
        Err(e) => {
            tracing::error!("Failed to reload config: {}", e);
        },
    }
}
