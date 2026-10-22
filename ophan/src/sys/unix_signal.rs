use pingora::server::{ShutdownSignal, ShutdownSignalWatch};
use std::sync::Arc;
use tokio::signal::unix;

use crate::state::AppState;
use crate::state::ReloadOutcome;

/// A Unix shutdown watcher that awaits for Unix signals.
///
/// - `SIGQUIT`: graceful upgrade
/// - `SIGTERM`, `SIGINT`: graceful terminate
/// - `SIGHUP`: graceful config reload (hot-swap if possible, upgrade if listeners changed)
pub struct UnixShutdownSignalWatch {
    pub state: Arc<AppState>,
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
                    match self.state.reload() {
                        ReloadOutcome::NeedsUpgrade => match crate::sys::upgrade::Upgrade::respawn_self() {
                            Ok(pid) => {
                                tracing::warn!("listeners changed, handing over to new process {pid}");
                                return ShutdownSignal::GracefulUpgrade;
                            },
                            Err(e) => {
                                tracing::error!("listeners changed but the new process could not start, keeping the current one: {e}");
                            },
                        },
                        ReloadOutcome::Swapped => {
                            tracing::info!("config reloaded");
                        },
                        ReloadOutcome::NoChange => {},
                    }
                },
                _ = sigterm.recv() => {
                    return ShutdownSignal::GracefulTerminate
                },
                _ = sigint.recv() => {
                    return ShutdownSignal::GracefulTerminate
                },
            }
        }
    }
}
