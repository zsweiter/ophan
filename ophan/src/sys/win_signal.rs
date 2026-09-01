//! Windows shutdown signal watcher.
//!
//! On Unix, Ophan reacts to POSIX signals. On Windows there are no POSIX
//! signals, but the console control handler can deliver `Ctrl+C` and
//! `Ctrl+Break`. This watcher implements Pingora's `ShutdownSignalWatch` using
//! those events:
//!
//! | Windows event | `ShutdownSignal`        | Unix equivalent   |
//! |--------------|-------------------------|-------------------|
//! | `Ctrl+C`     | `FastShutdown`          | `SIGINT`          |
//! | `Ctrl+Break` | `GracefulTerminate`     | `SIGTERM`         |
//!
//! ## Known limitations on Windows (NT)
//!
//! * **No `SIGHUP` / live reload.** There is no standard Windows console event
//!   that maps to "reload configuration". A `reload` would require an explicit
//!   control channel (e.g. a named pipe / RPC) which is intentionally out of
//!   scope here.
//! * **No graceful restart / upgrade.** The Unix `SIGQUIT` upgrade path spawns a
//!   second process that inherits the listening sockets. Windows has no
//!   `fork()`/socket passing equivalent, so `GracefulUpgrade` cannot be
//!   implemented without a secondary helper process. We do not implement it.
//! * **Service Control Manager (SCM).** When Ophan runs as a Windows *Service*
//!   (session 0, no console), `tokio::signal::windows` does **not** receive the
//!   `SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN` codes. The SCM talks to
//!   a registered service control handler, not the console control handler.
//!   Capturing those would require `RegisterServiceCtrlHandlerExW` plus a full
//!   service main loop, which Pingora's Windows `RunArgs` does not currently
//!   expose as an injectable `ShutdownSignalWatch`. When run as a plain console
//!   process (the common case for local dev / foreground), `Ctrl+C` works as
//!   expected. This limitation is documented here rather than worked around
//!   because it needs changes outside this crate's control.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::server::{ShutdownSignal, ShutdownSignalWatch};
use tokio::signal::windows;

use crate::state::AppState;

#[cfg(windows)]
pub struct WindowsShutdownSignalWatch {
    pub state: Arc<AppState>,
}

#[cfg(windows)]
#[async_trait]
impl ShutdownSignalWatch for WindowsShutdownSignalWatch {
    async fn recv(&self) -> ShutdownSignal {
        let ctrl_c = windows::ctrl_c().expect("failed to install Ctrl+C handler");
        let ctrl_break = windows::ctrl_break().expect("failed to install Ctrl+Break handler");

        tokio::select! {
            // Fast shutdown: drop in-flight work immediately.
            _ = ctrl_c => ShutdownSignal::FastShutdown,
            // Graceful terminate: drain existing connections.
            _ = ctrl_break => ShutdownSignal::GracefulTerminate,
        }
    }
}
