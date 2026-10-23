//! Service manager notifications (`sd_notify`), so systemd follows a zero-downtime upgrade.
//!
//! The unit runs with `Type=notify` and `NotifyAccess=all`: the gateway reports `READY=1`
//! once it serves, and a process that takes over the listeners reports itself as the new
//! main process before the previous one exits. Outside systemd every call is a no-op.

use std::io;
use std::os::unix::net::UnixDatagram;

pub struct Systemd;

impl Systemd {
    const ENV: &str = "NOTIFY_SOCKET";

    /// Whether a service manager waits for notifications from this process.
    pub fn is_managed() -> bool {
        std::env::var_os(Self::ENV).is_some()
    }

    /// The gateway serves requests.
    pub fn ready() {
        Self::send("READY=1");
    }

    /// The process sending this owns the listeners now and serves requests.
    pub fn took_over() {
        Self::send(&format!("MAINPID={}\nREADY=1", std::process::id()));
    }

    /// A reload started; [`Self::ready`] or [`Self::took_over`] ends it.
    pub fn reloading() {
        Self::send("RELOADING=1");
    }

    pub fn stopping() {
        Self::send("STOPPING=1");
    }

    fn send(state: &str) {
        if let Err(e) = Self::notify(state) {
            tracing::warn!("failed to notify the service manager ({state}): {e}");
        }
    }

    fn notify(state: &str) -> io::Result<()> {
        let Some(path) = std::env::var_os(Self::ENV) else {
            return Ok(());
        };

        let socket = UnixDatagram::unbound()?;

        match path.as_encoded_bytes().strip_prefix(b"@") {
            #[cfg(target_os = "linux")]
            Some(name) => {
                use std::os::linux::net::SocketAddrExt;
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                socket.send_to_addr(state.as_bytes(), &addr)?;
            },
            #[cfg(not(target_os = "linux"))]
            Some(_) => return Err(io::Error::new(io::ErrorKind::Unsupported, "abstract notify socket")),
            None => {
                socket.send_to(state.as_bytes(), &path)?;
            },
        }

        Ok(())
    }
}
