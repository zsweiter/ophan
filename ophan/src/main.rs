use ophan::cli::{CliApp, Command};
use ophan::config;
use ophan::sys::error::ExitCode;

fn main() -> ExitCode {
    if let Err(code) = main_entry() {
        return code;
    }

    ExitCode::Ok
}

fn main_entry() -> Result<(), ExitCode> {
    let app = CliApp::parse();

    if let Err(e) = app.validate() {
        eprintln!("Error: {e}");
        return Err(ExitCode::Usage);
    }

    match app.cmd {
        None => {
            if let Some(ref cfg) = app.config {
                let _ = config::set_config_path(cfg);
            }
            ophan::bootstrap(app.pid_file.clone())
        },

        Some(Command::Test) => {
            let path = app.config.unwrap_or_default();
            let _ = config::set_config_path(&path);

            match config::load_config() {
                Ok(_) => {
                    println!("✔ Configuration is valid");
                    Ok(())
                },
                Err(e) => {
                    eprintln!("{e}");
                    Err(ExitCode::Config)
                },
            }
        },

        #[cfg(unix)]
        Some(Command::Signal(signal)) => {
            use nix::sys::signal::kill;
            use nix::unistd::Pid;

            use ophan::sys::OsSignal;
            use ophan::sys::pid::read_pid;

            let config_path = app.config.as_ref().map(std::path::PathBuf::from);
            let (pid, _) = read_pid(app.pid_file.as_deref(), config_path.as_ref())?;

            let os_signal: OsSignal = signal.into();
            if let Err(e) = kill(Pid::from_raw(pid), os_signal) {
                eprintln!("Error: failed to send signal to PID {pid}: {e}");
                return Err(ExitCode::OsErr);
            }

            println!("Signal sent to PID {pid} ({os_signal})");
            Ok(())
        },

        #[cfg(unix)]
        Some(Command::Upgrade) => {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            use ophan::sys::pid::read_pid;

            let config_path = app.config.as_ref().map(std::path::PathBuf::from);
            let (pid, _) = read_pid(app.pid_file.as_deref(), config_path.as_ref())?;

            if let Err(e) = kill(Pid::from_raw(pid), Signal::SIGQUIT) {
                eprintln!("Error: failed to send upgrade signal to PID {pid}: {e}");
                return Err(ExitCode::OsErr);
            }

            println!("Upgrade signal sent to PID {pid}");
            Ok(())
        },

        #[cfg(unix)]
        Some(Command::Doctor) => {
            use nix::sys::signal::kill;
            use nix::unistd::Pid;
            use ophan::config::get_config_path;
            use ophan::sys::pid::read_pid;

            let mut all_ok = true;

            if let Some(ref path) = app.config {
                let _ = config::set_config_path(path);
            }

            let (pid, pid_path) = read_pid(app.pid_file.as_deref(), Some(get_config_path()))?;

            match kill(Pid::from_raw(pid), None) {
                Ok(_) => println!("PID file:      ✔ {} running (PID {})", pid_path.display(), pid),
                Err(_) => {
                    println!(
                        "PID file:      ⚠ {} exists but process {} not running",
                        pid_path.display(),
                        pid
                    );
                },
            };

            if let Ok(config) = config::load_config() {
                let log_path = std::path::Path::new(&config.master.error_log);
                if let Some(parent) = log_path.parent() {
                    if parent.exists() {
                        println!("Error log:     ✔ {} writable", parent.display());
                    } else {
                        println!("Error log:     ✘ parent directory '{}' does not exist", parent.display());
                        all_ok = false;
                    }
                }
            }

            if all_ok { Ok(()) } else { Err(ExitCode::Config) }
        },

        #[cfg(target_os = "linux")]
        Some(Command::SystemdSetup) => {
            eprintln!("Error: 'systemd-setup' is not implemented yet");
            Err(ExitCode::Unavailable)
        },
    }
}
