mod config;
mod errors;
mod gateway;
mod middlewares;
mod state;

#[cfg(unix)]
mod signals;
use pingora::proxy::HttpProxy;
use pingora::server::{RunArgs, Server, configuration::ServerConf};
use pingora::services::listening::Service;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::sync::Arc;

use crate::config::{OphanConfig, SecurityConfig};
use crate::errors::ExitCode;
use crate::gateway::OphanGateway;

use crate::state::AppState;

macro_rules! must_take {
    ($res:expr, |$err:ident| $else:block) => {
        match $res {
            Ok(value) => value,
            Err($err) => $else,
        }
    };
}

fn main() -> ExitCode {
    if let Err(e) = LogTracer::init() {
        eprintln!("failed to initialize log tracer: {e}");
        return ExitCode::Software;
    }

    let config = must_take!(OphanConfig::parse(), |e| {
        eprintln!("Error parsing config: {:#}", e);
        return ExitCode::Config;
    });

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false);

    let file_layer = must_take!(std::fs::File::create(&config.master.error_log), |e| {
        eprintln!("failed to create error log file: {e}");
        return ExitCode::Config;
    });

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
        return ExitCode::Software;
    }

    let app_state = must_take!(AppState::new(config), |errors| {
        for e in &errors {
            eprintln!("{}", e);
        }
        return ExitCode::Config;
    });

    if let Err(e) = server_run(Arc::new(app_state)) {
        eprintln!("Error: {:#}", e);
        return ExitCode::Config;
    }

    ExitCode::Ok
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

    server.bootstrap();

    let gateway = OphanGateway::new(app_state.clone(), &config);

    let mut proxy = HttpProxy::new(gateway, server.configuration.clone());
    proxy.handle_init_modules();

    let mut proxy_service = Service::new(String::from("Ophan gateway"), proxy);

    for listener in config.listeners.iter() {
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
                        .map_err(|e| format!("failed to add TLS listener: {:?}", e))?;
                }
            },
        }
    }

    server.add_service(proxy_service);

    drop(config);

    server.run(RunArgs {
        #[cfg(unix)] // Shutdown signal only available en unix systems
        shutdown_signal: Box::new(crate::signals::UnixShutdownSignalWatch { state: app_state.clone() }),
    });

    Ok(())
}
