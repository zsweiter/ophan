//! Zero-downtime binary/listener upgrade.
//!
//! A new process is started with [`Upgrade::ENV`] set. It boots in pingora upgrade mode and
//! waits on the upgrade socket for the listening sockets of the running process, which hands
//! them over when it receives `SIGQUIT` (pingora `GracefulUpgrade`) and then drains.
//!
//! `SIGHUP` starts an upgrade when the binary on disk was replaced (by the package manager or
//! `ophan --upgrade`) or when the listeners changed; the new binary must first accept the
//! current configuration, otherwise the running process keeps serving.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::SystemTime;

pub struct Upgrade;

/// File identity of the binary a process started from.
#[derive(Debug, PartialEq)]
struct BinaryIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    modified: Option<SystemTime>,
    len: u64,
}

impl BinaryIdentity {
    fn of(path: PathBuf) -> Option<Self> {
        let metadata = std::fs::metadata(&path).ok()?;

        #[cfg(unix)]
        let (device, inode) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(unix))]
        let (device, inode) = (0, 0);

        Some(Self {
            device,
            inode,
            modified: metadata.modified().ok(),
            len: metadata.len(),
            path,
        })
    }
}

static RUNNING_BINARY: OnceLock<Option<BinaryIdentity>> = OnceLock::new();

impl Upgrade {
    /// Marks a process started to take over the listeners of a running one.
    pub const ENV: &str = "OPHAN_UPGRADE";

    /// Longest upgrade socket path kept next to the PID file; `sun_path` holds 108 bytes.
    const MAX_SOCKET_PATH: usize = 100;

    pub fn is_child() -> bool {
        std::env::var_os(Self::ENV).is_some_and(|v| v == "1")
    }

    /// Records the binary this process runs, before anything can replace it.
    pub fn record_binary() {
        RUNNING_BINARY.get_or_init(|| std::env::current_exe().ok().and_then(BinaryIdentity::of));
    }

    /// Whether the binary file this process started from was replaced since it started.
    pub fn binary_replaced() -> bool {
        let Some(Some(running)) = RUNNING_BINARY.get() else {
            return false;
        };

        BinaryIdentity::of(running.path.clone()).is_some_and(|on_disk| on_disk != *running)
    }

    /// Starts `program` with `args` in upgrade mode.
    ///
    /// Under systemd the new process is started through an intermediate process that exits at
    /// once, so it is reparented to the service manager before it reports itself as the main
    /// process: systemd only waits for the graceful stop of a main process that is its child.
    pub fn spawn(program: &Path, args: impl IntoIterator<Item = OsString>) -> std::io::Result<()> {
        let mut cmd = Command::new(program);
        cmd.args(args).env(Self::ENV, "1").stdin(Stdio::null());

        #[cfg(unix)]
        let detach = crate::sys::systemd::Systemd::is_managed();

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);

            if detach {
                // SAFETY: only fork and _exit run between fork and exec, both async-signal-safe.
                unsafe {
                    cmd.pre_exec(|| match nix::unistd::fork() {
                        Ok(nix::unistd::ForkResult::Parent { .. }) => nix::libc::_exit(0),
                        Ok(nix::unistd::ForkResult::Child) => Ok(()),
                        Err(errno) => Err(errno.into()),
                    });
                }
            }
        }

        let mut child = cmd.spawn()?;

        #[cfg(unix)]
        if detach {
            child.wait()?;
        }

        Ok(())
    }

    /// Restarts the current invocation (same arguments) in upgrade mode, from the binary now
    /// at the path this process started from, once that binary accepts `config`.
    pub fn respawn_self(config: &Path) -> Result<(), String> {
        let program = match RUNNING_BINARY.get() {
            Some(Some(running)) => running.path.clone(),
            _ => std::env::current_exe().map_err(|e| format!("cannot locate the ophan binary: {e}"))?,
        };

        Self::validate(&program, config)?;
        Self::spawn(&program, std::env::args_os().skip(1)).map_err(|e| format!("cannot start {}: {e}", program.display()))
    }

    /// Runs `program -t -c config`: the binary must start and accept the configuration.
    fn validate(program: &Path, config: &Path) -> Result<(), String> {
        let output = Command::new(program)
            .arg("-t")
            .arg("-c")
            .arg(config)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", program.display()))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{} rejects {}: {}",
            program.display(),
            config.display(),
            stderr.trim()
        ))
    }

    /// `ophan_upgrade.sock` next to the PID file, or a stable path in the temp dir when that
    /// path does not fit in a Unix socket address. Old and new processes derive the same path.
    pub fn socket_path(run_dir: PathBuf) -> PathBuf {
        let path = run_dir.join("ophan_upgrade.sock");

        if path.as_os_str().len() < Self::MAX_SOCKET_PATH {
            return path;
        }

        use std::hash::{Hash, Hasher};
        let mut hasher = std::hash::DefaultHasher::new();
        run_dir.hash(&mut hasher);

        std::env::temp_dir().join(format!("ophan-upgrade-{:016x}.sock", hasher.finish()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_file_has_another_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ophan");
        std::fs::write(&path, b"v1").unwrap();
        let before = BinaryIdentity::of(path.clone()).unwrap();

        assert_eq!(BinaryIdentity::of(path.clone()).unwrap(), before);

        let staged = dir.path().join(".ophan.new");
        std::fs::write(&staged, b"v2").unwrap();
        std::fs::rename(&staged, &path).unwrap();

        assert_ne!(BinaryIdentity::of(path).unwrap(), before);
    }
}
