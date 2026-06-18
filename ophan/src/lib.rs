pub mod cli;
pub mod config;
pub mod errors;
pub mod gateway;
pub mod middlewares;
pub mod state;

#[cfg(unix)]
pub mod signals;

use pingora::proxy::HttpProxy;
use pingora::server::{RunArgs, Server, configuration::ServerConf};
use pingora::services::listening::Service;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use crate::cli::{Command, parse_cli};
use crate::config::{OphanConfig, SecurityConfig};
use crate::config::{parse_master_config, set_config_path};
use crate::errors::ExitCode;
use crate::gateway::OphanGateway;
use crate::state::AppState;

pub fn main_entry() -> Result<(), ExitCode> {
    let version = env!("CARGO_PKG_VERSION");
    let (command, args) = parse_cli(version);

    match command {
        None => bootstrap(),

        Some(Command::Version) => {
            println!("Ophan API Gateway v{version}");

            Ok(())
        },

        Some(Command::Config | Command::Test) => {
            let Some(path) = args.config else {
                eprintln!("Error: --config or -c is required for this command");
                return Err(ExitCode::Usage);
            };

            if path.is_empty() {
                eprintln!("Error: --config or -c is required for this command");
                return Err(ExitCode::Usage);
            }

            let _ = set_config_path(&path);

            if let Some(Command::Test) = command {
                match OphanConfig::parse() {
                    Ok(_) => {
                        println!("✔ Configuration is valid");
                        Ok(())
                    },
                    Err(e) => {
                        eprintln!("{e}");
                        Err(ExitCode::Config)
                    },
                }
            } else {
                bootstrap()
            }
        },

        #[cfg(unix)]
        Some(Command::Signal(signal)) => {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let (pid, _) = read_pid(args.config.as_ref())?;

            let unix_signal = match signal {
                cli::Signal::Stop => Signal::SIGTERM,
                cli::Signal::Quit => Signal::SIGQUIT,
                cli::Signal::Reload => Signal::SIGHUP,
                cli::Signal::Reopen => Signal::SIGUSR1,
            };

            if let Err(e) = kill(Pid::from_raw(pid), unix_signal) {
                eprintln!("Error: failed to send signal to PID {pid}: {e}");
                return Err(ExitCode::OsErr);
            }

            println!("Signal sent to PID {pid} ({unix_signal})");
            Ok(())
        },

        #[cfg(unix)]
        Some(Command::Upgrade) => {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let (pid, _) = read_pid(args.config.as_ref())?;

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

            let mut all_ok = true;

            if let Some(ref path) = args.config {
                let _ = set_config_path(path);
            }

            match OphanConfig::parse() {
                Ok(_) => println!("Config:        ✔ valid"),
                Err(e) => {
                    println!("Config:        ✘ {e}");
                    all_ok = false;
                },
            }

            let pid_path = resolve_pid_path(args.config.as_ref());
            match std::fs::read_to_string(&pid_path) {
                Ok(s) => {
                    let trimmed = s.trim();
                    if let Ok(pid) = trimmed.parse::<i32>() {
                        match kill(Pid::from_raw(pid), None) {
                            Ok(_) => println!("PID file:      ✔ {} running (PID {})", pid_path.display(), pid),
                            Err(_) => {
                                println!(
                                    "PID file:      ⚠ {} exists but process {} not running",
                                    pid_path.display(),
                                    pid
                                );
                            },
                        }
                    } else {
                        println!("PID file:      ✘ {} contains invalid PID '{}'", pid_path.display(), trimmed);
                        all_ok = false;
                    }
                },
                Err(_) => {
                    println!("PID file:      ℹ {} not found (server not running)", pid_path.display());
                },
            }

            if let Ok(config) = OphanConfig::parse() {
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
    }
}

fn bootstrap() -> Result<(), ExitCode> {
    LogTracer::init().map_err(|e| {
        eprintln!("failed to initialize log tracer: {e}");
        ExitCode::Software
    })?;

    let config = OphanConfig::parse().map_err(|e| {
        eprintln!("Error parsing config: {e:#}");
        ExitCode::Config
    })?;

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false);

    let file_layer = std::fs::File::create(&config.master.error_log).map_err(|e| {
        eprintln!("failed to create error log file: {e}");
        ExitCode::Config
    })?;

    let file_layer = fmt::layer()
        .with_writer(file_layer)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false);

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(stderr_layer)
        .with(file_layer);

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("failed to initialize tracing subscriber: {e}");
        return Err(ExitCode::Software);
    }

    let app_state = AppState::new(config).map_err(|errors| {
        for e in &errors {
            eprintln!("{e:?}");
        }

        ExitCode::Config
    })?;

    server_run(Arc::new(app_state)).map_err(|e| {
        eprintln!("Error: {e:#}");
        ExitCode::Config
    })
}

fn server_run(app_state: Arc<AppState>) -> Result<(), String> {
    let config = app_state.config.load();

    let mut server = Server::new_with_opt_and_conf(
        None,
        ServerConf {
            version: 1,
            daemon: false,
            pid_file: config.master.pid.clone(),
            error_log: Some(config.master.error_log.clone()),
            user: Some(config.master.user.clone()),
            upgrade_sock: String::from("/tmp/ophan_upgrade.sock"),
            work_stealing: true,
            threads: config.master.workers,
            ..Default::default()
        },
    );

    let _pid_guard = PidGuard::create(std::path::PathBuf::from(&config.master.pid))?;

    server.bootstrap();

    let gateway = OphanGateway::new(Arc::clone(&app_state), &config);

    let mut proxy = HttpProxy::new(gateway, Arc::clone(&server.configuration));
    proxy.handle_init_modules();

    let mut proxy_service = Service::new(String::from("Ophan gateway"), proxy);

    for listener in &config.listeners {
        match &listener.security {
            SecurityConfig::Plaintext => {
                for address in &listener.listen {
                    proxy_service.add_tcp(address);
                }
            },
            SecurityConfig::Tls { certs, .. } => {
                for address in &listener.listen {
                    proxy_service
                        .add_tls(address, &certs.cert, &certs.key)
                        .map_err(|e| format!("failed to add TLS listener: {e:?}"))?;
                }
            },
        }
    }

    server.add_service(proxy_service);

    drop(config);

    server.run(RunArgs {
        #[cfg(unix)] // Shutdown signal only available en unix systems for now
        shutdown_signal: Box::new(crate::signals::UnixShutdownSignalWatch { state: app_state }),
    });

    Ok(())
}

struct PidGuard {
    path: std::path::PathBuf,
}

impl PidGuard {
    fn create(path: std::path::PathBuf) -> Result<Self, String> {
        let current_pid = std::process::id();
        std::fs::write(&path, current_pid.to_string())
            .map_err(|e| format!("Failed to write PID file '{}': {}", path.display(), e))?;

        Ok(Self { path })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn resolve_pid_path(config_arg: Option<&String>) -> PathBuf {
    if let Some(path) = config_arg
        && let Ok(content) = std::fs::read_to_string(path)
        && let Ok(master) = parse_master_config(&content)
    {
        let p = PathBuf::from(&master.pid);
        if p.exists() {
            return p;
        }
    }

    PathBuf::from("/run/ophan.pid")
}

fn read_pid(config_arg: Option<&String>) -> Result<(i32, PathBuf), ExitCode> {
    let pid_path = resolve_pid_path(config_arg);
    let pid_str = std::fs::read_to_string(&pid_path).map_err(|e| {
        eprintln!("Error: cannot read PID file '{}': {}", pid_path.display(), e);
        ExitCode::NoInput
    })?;

    let trimmed = pid_str.trim();
    let pid = trimmed.parse::<i32>().map_err(|e| {
        eprintln!("Error: invalid PID '{}' in '{}': {}", trimmed, pid_path.display(), e);
        ExitCode::DataErr
    })?;

    Ok((pid, pid_path))
}
