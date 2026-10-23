use pingora::server::{ShutdownSignal, ShutdownSignalWatch};
use std::sync::Arc;
use tokio::signal::unix;

use crate::state::AppState;
use crate::state::ReloadOutcome;
use crate::sys::systemd::Systemd;
use crate::sys::upgrade::Upgrade;

/// A Unix shutdown watcher that awaits for Unix signals.
///
/// - `SIGHUP`: reload. When the binary on disk was replaced or the listeners changed, a new
///   process takes over the listeners (zero-downtime upgrade); otherwise the configuration
///   is swapped in place.
/// - `SIGTERM`, `SIGINT`: graceful terminate
/// - `SIGQUIT`: hand the listeners over to a process already started in upgrade mode
pub struct UnixShutdownSignalWatch {
    pub state: Arc<AppState>,
}

impl UnixShutdownSignalWatch {
    /// Why a reload must hand over to a new process, or `None` once it reloaded in place.
    fn upgrade_reason(&self) -> Option<&'static str> {
        if Upgrade::binary_replaced() {
            return Some("the binary was replaced");
        }

        match self.state.reload() {
            ReloadOutcome::NeedsUpgrade => Some("listeners changed"),
            ReloadOutcome::Swapped => {
                tracing::info!("config reloaded");
                None
            },
            ReloadOutcome::NoChange => None,
        }
    }
}

#[async_trait::async_trait]
impl ShutdownSignalWatch for UnixShutdownSignalWatch {
    async fn recv(&self) -> ShutdownSignal {
        let mut sigquit = unix::signal(unix::SignalKind::quit()).unwrap();
        let mut sighup = unix::signal(unix::SignalKind::hangup()).unwrap();
        let mut sigterm = unix::signal(unix::SignalKind::terminate()).unwrap();
        let mut sigint = unix::signal(unix::SignalKind::interrupt()).unwrap();

        loop {
            tokio::select! {
                _ = sigquit.recv() => {
                    return ShutdownSignal::GracefulUpgrade
                },
                _ = sighup.recv() => {
                    Systemd::reloading();

                    if let Some(reason) = self.upgrade_reason() {
                        let config = crate::config::get_config_path();
                        let started = tokio::task::spawn_blocking(move || Upgrade::respawn_self(config))
                            .await
                            .map_err(|e| e.to_string())
                            .and_then(|result| result);

                        match started {
                            Ok(()) => {
                                tracing::warn!("{reason}, handing over to a new process");
                                return ShutdownSignal::GracefulUpgrade;
                            },
                            Err(e) => {
                                tracing::error!("{reason} but the new process could not start, keeping the current one: {e}");
                            },
                        }
                    }

                    Systemd::ready();
                },
                _ = sigterm.recv() => {
                    Systemd::stopping();
                    return ShutdownSignal::GracefulTerminate
                },
                _ = sigint.recv() => {
                    Systemd::stopping();
                    return ShutdownSignal::GracefulTerminate
                },
            }
        }
    }
}
