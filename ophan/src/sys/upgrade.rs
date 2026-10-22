//! Zero-downtime binary/listener upgrade.
//!
//! A new process is started with [`Upgrade::ENV`] set. It boots in pingora upgrade mode and
//! waits on the upgrade socket for the listening sockets of the running process, which hands
//! them over when it receives `SIGQUIT` (pingora `GracefulUpgrade`) and then drains.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Upgrade;

impl Upgrade {
    /// Marks a process started to take over the listeners of a running one.
    pub const ENV: &str = "OPHAN_UPGRADE";

    /// Longest upgrade socket path kept next to the PID file; `sun_path` holds 108 bytes.
    const MAX_SOCKET_PATH: usize = 100;

    pub fn is_child() -> bool {
        std::env::var_os(Self::ENV).is_some_and(|v| v == "1")
    }

    /// Starts `program` with `args` in upgrade mode and returns its PID.
    pub fn spawn(program: &Path, args: impl IntoIterator<Item = OsString>) -> std::io::Result<u32> {
        let mut cmd = Command::new(program);
        cmd.args(args).env(Self::ENV, "1").stdin(Stdio::null());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        cmd.spawn().map(|child| child.id())
    }

    /// Restarts the current invocation (same program and arguments) in upgrade mode.
    pub fn respawn_self() -> std::io::Result<u32> {
        let mut args = std::env::args_os();
        let program = args.next().ok_or_else(|| std::io::Error::other("missing argv[0]"))?;

        Self::spawn(Path::new(&program), args)
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
