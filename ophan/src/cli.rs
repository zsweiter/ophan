use cli::{Parser, Subcommand};

use crate::sys::Signal;
#[cfg(unix)]
use crate::sys::release::ReleaseTarget;

#[derive(Subcommand, Debug, PartialEq)]
pub enum Command {
    #[arg(short = "t", flag = "--test", help = "Validate configuration syntax")]
    Test,

    #[arg(short = "v", flag = "--version", help = "Print version and exit")]
    Version,

    #[cfg(unix)]
    #[arg(flag = "--doctor", help = "Run diagnostics and system health checks")]
    Doctor,

    #[cfg(unix)]
    #[arg(
        flag = "--upgrade",
        help = "Install a release ([latest] or X.Y.Z) and hand the running instance over to it"
    )]
    Upgrade(Option<ReleaseTarget>),

    #[cfg(unix)]
    #[arg(short = "s", flag = "--signal", help = "Send control signal to running instance")]
    Signal(Signal),

    #[cfg(target_os = "linux")]
    #[arg(flag = "--systemd-setup", help = "Install systemd unit files (Linux only)")]
    SystemdSetup,
}

#[derive(Parser, Debug)]
pub struct CliApp {
    #[arg(short = "c", flag = "--config", help = "Path to the configuration file")]
    pub config: Option<String>,

    #[arg(short = "P", flag = "--pid-file", help = "Override default PID file path")]
    pub pid_file: Option<String>,

    #[arg(subcommand)]
    pub cmd: Option<Command>,
}

impl CliApp {
    pub fn validate(&self) -> Result<(), String> {
        if matches!(self.cmd, Some(Command::Test)) && self.config.is_none() {
            return Err("The '--test' flag requires a configuration file via '-c' or '--config'.".into());
        }
        Ok(())
    }
}
