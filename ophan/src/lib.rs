pub mod balancer;
pub mod cli;
pub mod config;
pub mod gateway;
pub mod housekeeping;
pub mod logging;
pub mod metrics;
pub mod middlewares;
pub mod state;
pub mod sys;

use ahash::AHashMap;
use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;
use pingora::proxy::HttpProxy;
use pingora::server::{
    RunArgs, Server,
    configuration::{Opt, ServerConf},
};
use pingora::services::background::background_service;
use pingora::services::listening::Service;
use tracing_log::LogTracer;

use std::sync::Arc;
use std::time::Duration;

use crate::config::{GatewayConfig, ListenerAddress, NetworkProtocol, OphanConfig, SecurityConfig, get_config_path, load_config};
use crate::gateway::OphanGateway;
use crate::gateway::listener::ListenerGuard;
use crate::housekeeping::{Housekeeping, WatchedGateway};
use crate::logging::Logger;
use crate::metrics::{MetricsApp, UpstreamCollector};
use crate::state::{AppContext, AppState};
use crate::sys::error::ExitCode;
use crate::sys::pid::{PidGuard, effective_pid_path};
use crate::sys::upgrade::Upgrade;
use pingora::apps::HttpServerOptions;
use pingora::listeners::TcpSocketOptions;
use pingora::protocols::TcpKeepalive;

pub fn bootstrap(pid_file: Option<String>) -> Result<(), ExitCode> {
    LogTracer::builder().with_max_level(tracing_log::log::LevelFilter::Warn).init().map_err(|e| {
        eprintln!("failed to initialize log tracer: {e}");
        ExitCode::Software
    })?;

    let config = load_config().map_err(|e| {
        eprintln!("Error parsing config: {e:#}");
        ExitCode::Config
    })?;

    let _logger = Logger::init(&config.master.error_log)?;

    server_run(config, pid_file).map_err(|e| {
        eprintln!("Error: {e:#}");
        ExitCode::Config
    })
}

const GRACE_PERIOD_SECS: u64 = 3;
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

const UPSTREAM_KEEPALIVE_POOL_SIZE: usize = 512;
const MAX_UPSTREAM_RETRIES: usize = 3;

/// Requests served on one downstream HTTP/1 connection before it is recycled.
const KEEPALIVE_REQUEST_LIMIT: u32 = 10_000;
const H2_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

fn server_run(config: OphanConfig, pid_file: Option<String>) -> Result<(), String> {
    let pid_path = effective_pid_path(pid_file.as_deref(), Some(get_config_path()));
    let run_dir = pid_path.parent().filter(|p| !p.as_os_str().is_empty()).map(std::path::Path::to_path_buf);
    if let Some(ref dir) = run_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("failed to create pid directory '{}': {e}", dir.display()))?;
    }

    let upgrade_sock = Upgrade::socket_path(run_dir.unwrap_or_else(|| std::path::PathBuf::from(".")));

    let opt = Opt { upgrade: Upgrade::is_child(), ..Default::default() };

    let mut server = Server::new_with_opt_and_conf(
        opt,
        ServerConf {
            version: 1,
            daemon: false,
            pid_file: String::with_capacity(0),
            error_log: None,
            user: Some(config.master.user.clone()),
            upgrade_sock: upgrade_sock.to_string_lossy().into_owned(),
            work_stealing: false,
            threads: config.master.workers,
            grace_period_seconds: Some(GRACE_PERIOD_SECS),
            graceful_shutdown_timeout_seconds: Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECS),
            upstream_keepalive_pool_size: UPSTREAM_KEEPALIVE_POOL_SIZE,
            max_retries: MAX_UPSTREAM_RETRIES,
            ..Default::default()
        },
    );

    // In upgrade mode bootstrap waits for the listening sockets of the running process;
    // the PID file is only taken over once that succeeded.
    server.bootstrap();

    let _pid_guard = PidGuard::create(pid_path)?;

    // Build all gateway contexts and create the shared ArcSwap map
    let mut gateway_ctxs = AHashMap::with_capacity(config.gateways.len());
    for (name, gateway) in &config.gateways {
        let ctx = AppContext::build(gateway, None)?;
        gateway_ctxs.insert(name.clone(), Arc::new(ArcSwap::from_pointee(ctx)));
    }

    let app_state = Arc::new(AppState::new(config, gateway_ctxs));

    // Create services, each with its own ArcSwap reference
    {
        let config_guard = app_state.config.load();
        let mut watched = Vec::with_capacity(config_guard.gateways.len());

        for (name, gateway) in &config_guard.gateways {
            let ctx_swap = Arc::clone(app_state.gateways.get(name).unwrap());
            let conf = Arc::clone(&server.configuration);
            let app_gateway = OphanGateway::new(Arc::clone(&ctx_swap), gateway);
            let guard = Arc::new(ListenerGuard::new(Arc::clone(&ctx_swap)));

            watched.push(WatchedGateway {
                name: name.as_str().into(),
                context: ctx_swap,
                limiter: app_gateway.pipeline.rate_limiter_store(),
            });

            server.add_service(gateway_service(name.clone(), gateway, app_gateway, conf, guard));
        }

        let upstreams = UpstreamCollector::new(watched.iter().map(|g| (g.name.clone(), Arc::clone(&g.context))).collect())
            .and_then(|collector| prometheus::register(Box::new(collector)));
        if let Err(e) = upstreams {
            tracing::error!("failed to register upstream metrics: {e}");
        }

        server.add_service(background_service("housekeeping", Housekeeping::new(watched)));

        if let Some(metrics) = &config_guard.master.metrics {
            server.add_service(MetricsApp::service(metrics));
        }
    }

    server.run(RunArgs {
        #[cfg(unix)] // Shutdown signal only available on unix systems
        shutdown_signal: Box::new(sys::ShutdownWatch { state: app_state.clone() }),
    });

    Ok(())
}

type GatewayService = Service<HttpProxy<OphanGateway>>;

fn gateway_service(
    name: ImmerStr,
    config: &GatewayConfig,
    app_gateway: OphanGateway,
    conf: Arc<ServerConf>,
    guard: Arc<ListenerGuard>,
) -> GatewayService {
    let mut proxy = HttpProxy::new(app_gateway, conf);
    proxy.handle_init_modules();

    let h2c = config
        .listeners
        .iter()
        .any(|l| l.security == SecurityConfig::Plaintext && l.protocols.iter().any(NetworkProtocol::is_http2));

    let mut server_options = HttpServerOptions::default();
    server_options.h2c = h2c;
    server_options.keepalive_request_limit = Some(KEEPALIVE_REQUEST_LIMIT);
    server_options.h2_idle_timeout = Some(H2_IDLE_TIMEOUT);
    proxy.server_options = Some(server_options);

    let mut proxy_service = Service::new(name.to_string(), proxy);

    proxy_service.endpoints().set_pre_tls_callback(guard);

    for listener in &config.listeners {
        let (l4, tls) = match &listener.address {
            ListenerAddress::Tcp(addr) => {
                use pingora::listeners::ServerAddress;
                let address = addr.to_string();

                if cfg!(debug_assertions) {
                    println!("[{}] listen {}", name, address)
                }

                let mut options = TcpSocketOptions::default();
                options.tcp_keepalive = Some(TcpKeepalive {
                    idle: Duration::from_secs(60),
                    interval: Duration::from_secs(10),
                    count: 3,
                    #[cfg(target_os = "linux")]
                    user_timeout: Duration::from_secs(0),
                });

                (ServerAddress::Tcp(address, Some(options)), listener.security.clone().into())
            },

            // In unix domain sockets not support tls
            #[cfg(unix)]
            ListenerAddress::Uds(addr) => {
                use pingora::listeners::ServerAddress;
                if cfg!(debug_assertions) {
                    println!("[{}] listen {}", name, addr)
                }

                use std::os::unix::fs::PermissionsExt;
                let permissions = listener.permissions.map(std::fs::Permissions::from_mode);

                (ServerAddress::Uds(addr.clone(), permissions), None)
            },
        };

        proxy_service.endpoints().add_endpoint(l4, tls);
    }

    proxy_service
}
