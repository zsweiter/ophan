use core::fmt;
use std::{
    error::Error,
    io,
    process::{self, ExitStatus, Termination},
};

/// `ExitCode` is a type that represents the system exit code constants as
/// defined by [`<sysexits.h>`].
///
/// [`<sysexits.h>`]: https://man.openbsd.org/sysexits
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExitCode {
    /// The successful exit.
    #[default]
    Ok,

    /// The command was used incorrectly, e.g., with the wrong number of
    /// arguments, a bad flag, bad syntax in a parameter, or whatever.
    Usage = 64,

    /// The input data was incorrect in some way. This should only be used for
    /// user's data and not system files.
    DataErr,

    /// An input file (not a system file) did not exist or was not readable.
    /// This could also include errors like "No message" to a mailer (if it
    /// cared to catch it).
    NoInput,

    /// The user specified did not exist. This might be used for mail addresses
    /// or remote logins.
    NoUser,

    /// The host specified did not exist. This is used in mail addresses or
    /// network requests.
    NoHost,

    /// A service is unavailable. This can occur if a support program or file
    /// does not exist. This can also be used as a catch-all message when
    /// something you wanted to do doesn't work, but you don't know why.
    Unavailable,

    /// An internal software error has been detected. This should be limited to
    /// non-operating system related errors if possible.
    Software,

    /// An operating system error has been detected. This is intended to be used
    /// for such things as "cannot fork", or "cannot create pipe". It includes
    /// things like [`getuid(2)`] returning a user that does not exist in the
    /// passwd file.
    OsErr,

    /// Some system file (e.g., `/etc/passwd`, `/var/run/utmp`) does not exist,
    /// cannot be opened, or has some sort of error (e.g., syntax error).
    OsFile,

    /// A (user specified) output file cannot be created.
    CantCreat,

    /// An error occurred while doing I/O on some file.
    IoErr,

    /// Temporary failure, indicating something that is not really an error. For
    /// example that a mailer could not create a connection, and the request
    /// should be reattempted later.
    TempFail,

    /// The remote system returned something that was "not possible" during a
    /// protocol exchange.
    Protocol,

    /// You did not have sufficient permission to perform the operation. This is
    /// not intended for file system problems, which should use
    /// [`NoInput`](Self::NoInput) or [`CantCreat`](Self::CantCreat), but rather
    /// for higher level permissions.
    NoPerm,

    /// Something was found in an unconfigured or misconfigured state.
    Config,
}

impl ExitCode {
    /// Returns [`true`] if this system exit code represents successful
    /// termination.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns [`true`] if this system exit code represents unsuccessful
    /// termination.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !self.is_success()
    }

    /// Terminates the current process with the exit code defined by `ExitCode`.
    ///
    /// Equivalent to [`process::exit`] with a restricted exit code.
    ///
    pub fn exit(self) -> ! {
        process::exit(u8::from(self).into())
    }
}

impl From<ExitCode> for u8 {
    /// Converts an `ExitCode` into the raw underlying [`u8`] value.
    ///
    /// The resulting value is `0` or `64..=78`.
    ///
    fn from(code: ExitCode) -> Self {
        code as Self
    }
}

impl From<ExitCode> for process::ExitCode {
    /// Converts an `sysexits::ExitCode` into an [`process::ExitCode`].
    fn from(code: ExitCode) -> Self {
        code.report()
    }
}

impl From<io::Error> for ExitCode {
    /// Converts an [`io::Error`] into an `ExitCode`.
    fn from(error: io::Error) -> Self {
        error.kind().into()
    }
}

impl From<io::ErrorKind> for ExitCode {
    /// Converts an [`io::ErrorKind`] into an `ExitCode`.
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::NotFound => Self::NoInput,
            io::ErrorKind::PermissionDenied => Self::NoPerm,
            io::ErrorKind::ConnectionRefused | io::ErrorKind::OutOfMemory => Self::OsErr,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted => Self::TempFail,
            io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => Self::NoHost,
            io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkDown => Self::Unavailable,
            io::ErrorKind::AlreadyExists | io::ErrorKind::ReadOnlyFilesystem => Self::CantCreat,
            io::ErrorKind::WouldBlock | io::ErrorKind::Unsupported => Self::Protocol,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Self::DataErr,
            io::ErrorKind::WriteZero | io::ErrorKind::UnexpectedEof => Self::Software,
            _ => Self::IoErr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TryFromExitStatusError(Option<i32>);

impl TryFromExitStatusError {
    pub(crate) const fn new(code: Option<i32>) -> Self {
        Self(code)
    }

    /// Returns the corresponding exit code for this error.
    ///
    /// Returns [`None`] if the process was terminated by a signal.
    #[must_use]
    pub const fn code(self) -> Option<i32> {
        self.0
    }
}

impl fmt::Display for TryFromExitStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code() {
            write!(f, "invalid exit code `{code}`")
        } else {
            write!(f, "exit code is unknown")
        }
    }
}

impl Error for TryFromExitStatusError {}

impl TryFrom<ExitStatus> for ExitCode {
    type Error = TryFromExitStatusError;

    /// Converts an [`ExitStatus`] into an `ExitCode`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - The exit code is not `0` or `64..=78`.
    /// - The exit code is unknown (e.g., the process was terminated by a
    ///   signal).
    fn try_from(status: ExitStatus) -> Result<Self, Self::Error> {
        match status.code() {
            Some(0) => Ok(Self::Ok),
            Some(64) => Ok(Self::Usage),
            Some(65) => Ok(Self::DataErr),
            Some(66) => Ok(Self::NoInput),
            Some(67) => Ok(Self::NoUser),
            Some(68) => Ok(Self::NoHost),
            Some(69) => Ok(Self::Unavailable),
            Some(70) => Ok(Self::Software),
            Some(71) => Ok(Self::OsErr),
            Some(72) => Ok(Self::OsFile),
            Some(73) => Ok(Self::CantCreat),
            Some(74) => Ok(Self::IoErr),
            Some(75) => Ok(Self::TempFail),
            Some(76) => Ok(Self::Protocol),
            Some(77) => Ok(Self::NoPerm),
            Some(78) => Ok(Self::Config),
            Some(code) => Err(Self::Error::new(Some(code))),
            None => Err(Self::Error::new(None)),
        }
    }
}

impl Error for ExitCode {}

impl fmt::Display for ExitCode {
    /// Shows the integer representation of this `ExitCode`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        u8::from(*self).fmt(f)
    }
}

impl Termination for ExitCode {
    fn report(self) -> process::ExitCode {
        u8::from(self).into()
    }
}
