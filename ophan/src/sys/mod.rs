pub mod error;
pub mod pid;

#[cfg(unix)]
pub mod unix_signal;

#[cfg(windows)]
pub mod win_signal;

#[cfg(unix)]
pub type ShutdownWatch = unix_signal::UnixShutdownSignalWatch;

#[cfg(windows)]
pub type ShutdownWatch = win_signal::WindowsShutdownSignalWatch;

#[cfg(unix)]
pub type OsSignal = nix::sys::signal::Signal;

#[cfg(windows)]
pub type OsSignal = u32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Signal {
    Stop,
    Quit,
    Reload,
    Reopen,
}

impl std::str::FromStr for Signal {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stop" => Ok(Signal::Stop),
            "quit" => Ok(Signal::Quit),
            "reload" => Ok(Signal::Reload),
            "reopen" => Ok(Signal::Reopen),
            _ => Err("Invalid signal string"),
        }
    }
}

#[cfg(unix)]
impl From<Signal> for OsSignal {
    fn from(value: Signal) -> Self {
        match value {
            Signal::Stop => Self::SIGTERM,
            Signal::Quit => Self::SIGQUIT,
            Signal::Reload => Self::SIGHUP,
            Signal::Reopen => Self::SIGUSR1,
        }
    }
}

#[cfg(windows)]
impl From<Signal> for OsSignal {
    fn from(value: Signal) -> Self {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

        match value {
            Signal::Stop => CTRL_BREAK_EVENT,
            Signal::Quit => CTRL_C_EVENT,

            Signal::Reload => CTRL_BREAK_EVENT,
            Signal::Reopen => CTRL_BREAK_EVENT,
        }
    }
}
