pub mod balancer;
pub mod cli;
pub mod config;
pub mod gateway;
pub mod logging;
pub mod middlewares;
pub mod state;
pub mod sys;

use ahash::AHashMap;
use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;
use pingora::listeners::ConnectionFilter;
use pingora::proxy::HttpProxy;
use pingora::server::{RunArgs, Server, configuration::ServerConf};
use pingora::services::listening::Service;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::fs::OpenOptions;
use std::sync::Arc;

use crate::config::{GatewayConfig, ListenerAddress, OphanConfig, get_config_path, load_config};
use crate::gateway::OphanGateway;
use crate::state::{AppContext, AppState, ConnectionFilters};
use crate::sys::error::ExitCode;
use crate::sys::pid::{PidGuard, effective_pid_path};

pub fn bootstrap(pid_file: Option<String>) -> Result<(), ExitCode> {
    LogTracer::init().map_err(|e| {
        eprintln!("failed to initialize log tracer: {e}");
        ExitCode::Software
    })?;

    let config = load_config().map_err(|e| {
        eprintln!("Error parsing config: {e:#}");
        ExitCode::Config
    })?;

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false);

    if let Some(parent) = std::path::Path::new(&config.master.error_log).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            eprintln!("failed to create error log directory '{}': {e}", parent.display());
            ExitCode::Config
        })?;
    }

    let file_layer = OpenOptions::new().create(true).append(true).open(&config.master.error_log).map_err(|e| {
        eprintln!("failed to create error log file: {e}");
        ExitCode::Config
    })?;

    let file_layer = fmt::layer()
        .with_writer(file_layer)
        .with_ansi(false)
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

    server_run(config, pid_file).map_err(|e| {
        eprintln!("Error: {e:#}");
        ExitCode::Config
    })
}

fn server_run(config: OphanConfig, pid_file: Option<String>) -> Result<(), String> {
    let mut server = Server::new_with_opt_and_conf(
        None,
        ServerConf {
            version: 1,
            daemon: false,
            pid_file: String::with_capacity(0),
            error_log: None,
            user: Some(config.master.user.clone()),
            upgrade_sock: String::from("/tmp/ophan_upgrade.sock"),
            work_stealing: false,
            threads: config.master.workers,
            ..Default::default()
        },
    );

    let pid_path = effective_pid_path(pid_file.as_deref(), Some(get_config_path()));
    if let Some(parent) = pid_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create pid directory '{}': {e}", parent.display()))?;
    }

    let _pig_guard = PidGuard::create(pid_path)?;

    server.bootstrap();

    // Build all gateway contexts and create the shared ArcSwap map
    let mut gateway_ctxs = AHashMap::with_capacity(config.gateways.len());
    for (name, gateway) in &config.gateways {
        let ctx = AppContext::build(gateway)?;
        gateway_ctxs.insert(name.clone(), Arc::new(ArcSwap::from_pointee(ctx)));
    }

    let app_state = Arc::new(AppState::new(config, gateway_ctxs));

    // Create services, each with its own ArcSwap reference
    {
        let config_guard = app_state.config.load();
        for (name, gateway) in &config_guard.gateways {
            let ctx_swap = Arc::clone(app_state.gateways.get(name).unwrap());
            let conf = Arc::clone(&server.configuration);
            let net_filter = ctx_swap.load().net_filter.clone();
            let service = gateway_service(name.clone(), gateway, ctx_swap, conf, net_filter);

            server.add_service(service);
        }
    }

    server.run(RunArgs {
        #[cfg(unix)] // Shutdown signal only available on unix systems
        shutdown_signal: Box::new(sys::ShutdownWatch { state: app_state.clone() }),
    });

    Ok(())
}

type GatewayService = Service<HttpProxy<OphanGateway>>;
type AppCtx = Arc<ArcSwap<AppContext>>;

fn gateway_service(
    name: ImmerStr,
    config: &GatewayConfig,
    ctx: AppCtx,
    conf: Arc<ServerConf>,
    net_filter: Option<Arc<ConnectionFilters>>,
) -> GatewayService {
    let app_gateway = OphanGateway::new(ctx, config);

    let mut proxy = HttpProxy::new(app_gateway, conf);
    proxy.handle_init_modules();

    let mut proxy_service = Service::new(name.to_string(), proxy);

    for listener in &config.listeners {
        let (l4, tls) = match &listener.address {
            ListenerAddress::Tcp(addr) => {
                use pingora::listeners::ServerAddress;
                let address = addr.to_string();

                if cfg!(debug_assertions) {
                    println!("[{}] listen {}", name, address)
                }

                // TODO: missing tcp socket options, like keepalive
                (ServerAddress::Tcp(address, None), listener.security.clone().into())
            },

            // In unix domain sockets not support tls
            #[cfg(unix)]
            ListenerAddress::Uds(addr) => {
                use pingora::listeners::ServerAddress;
                if cfg!(debug_assertions) {
                    println!("[{}] listen {}", name, addr)
                }

                // TODO: missing unix socket fs permissions
                (ServerAddress::Uds(addr.clone(), None), None)
            },
        };

        if let Some(filter) = net_filter.as_ref() {
            proxy_service.set_connection_filter(Arc::clone(filter) as Arc<dyn ConnectionFilter>);
        }

        proxy_service.endpoints().add_endpoint(l4, tls);
    }

    proxy_service
}
