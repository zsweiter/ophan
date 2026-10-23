use ophan::cli::{CliApp, Command};
use ophan::config;
use ophan::sys::error::ExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    if let Err(code) = main_entry() {
        return code;
    }

    ExitCode::Ok
}

fn apply_config_path(path: &str) -> Result<(), ExitCode> {
    config::set_config_path(path).map_err(|_| {
        eprintln!(
            "Error: config path already initialized to '{}', cannot use '{path}'",
            config::get_config_path().display()
        );
        ExitCode::Software
    })
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
                apply_config_path(cfg)?;
            }

            let config_path = config::get_config_path();
            match config::ConfigSeed::apply(config_path) {
                Ok(true) => eprintln!("No configuration at {}, copied the defaults", config_path.display()),
                Ok(false) => {},
                Err(e) => eprintln!(
                    "Warning: cannot copy the default configuration to {}: {e}",
                    config_path.display()
                ),
            }
            ophan::bootstrap(app.pid_file.clone())
        },

        Some(Command::Version) => {
            println!("ophan {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        },

        Some(Command::Test) => {
            let path = app.config.unwrap_or_default();
            apply_config_path(&path)?;

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
        Some(Command::Upgrade(ref target)) => {
            use ophan::sys::release::{Release, ReleaseTarget};

            if let Some(ref path) = app.config {
                apply_config_path(path)?;
            }
            let config_path = config::get_config_path();

            let release = Release::new(target.clone().unwrap_or(ReleaseTarget::Latest)).map_err(|e| {
                eprintln!("Error: {e}");
                ExitCode::OsErr
            })?;

            let installed = release.install(config_path).map_err(|e| {
                eprintln!("Error: {e}");
                ExitCode::Unavailable
            })?;

            let Some(version) = installed else {
                println!("ophan {} is already installed", env!("CARGO_PKG_VERSION"));
                return Ok(());
            };

            println!("Installed ophan {version} at {}", release.exe().display());

            match Release::reload_running(app.pid_file.as_deref(), config_path) {
                Ok(Some(pid)) => println!("PID {pid} is handing its listeners over to ophan {version}"),
                Ok(None) => println!("No running instance found; start ophan to use the new version"),
                Err(e) => {
                    eprintln!("Error: the new binary is installed but the running instance was not reloaded: {e}");
                    return Err(ExitCode::OsErr);
                },
            }

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
                apply_config_path(path)?;
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
