mod config;
mod gateway;
mod middlewares;

#[cfg(test)]
mod integration_test;

use std::thread;
use std::time::Instant;

use arc_swap::ArcSwap;
use pingora::prelude::*;
use pingora::proxy::HttpProxy;
use pingora::server::configuration::ServerConf;
use pingora::services::listening::Service;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use crate::config::{OphanConfig, SecurityConfig};
use crate::gateway::{AppContext, OphanGateway, build_app_context};

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_thread_ids(true)
        .with_target(false)
        .with_thread_names(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("failed the setting logger");

    let config = match OphanConfig::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing config: {:#}", e);
            std::process::exit(1);
        },
    };

    // ---------------------------------------------------------------
    // Validate and build the AppContext (fail-fast on startup)
    // ---------------------------------------------------------------
    let app_ctx = match build_app_context(&config) {
        Ok(ctx) => ctx,
        Err(errors) => {
            for e in &errors {
                eprintln!("{}", e);
            }
            std::process::exit(1);
        },
    };

    let config_swap = ArcSwap::from_pointee(config);
    let app_swap = ArcSwap::from_pointee(app_ctx);

    // TODO: activar con SIGHUP
    // setup_reload(&config_swap, &app_swap);

    if let Err(e) = run_gateway_server(config_swap, app_swap) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run_gateway_server(config_swap: ArcSwap<OphanConfig>, app_swap: ArcSwap<AppContext>) -> Result<(), String> {
    let snapshot = config_swap.load();
    let cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    let mut server = Server::new_with_opt_and_conf(
        None,
        ServerConf {
            version: 1,
            daemon: false,
            pid_file: snapshot.master.pid.clone(),
            error_log: Some(snapshot.master.error_log.clone()),
            user: Some(snapshot.master.user.clone()),
            upgrade_sock: String::from("/tmp/ophan_upgrade.sock"),
            work_stealing: true,
            threads: cpus,
            ..Default::default()
        },
    );

    server.bootstrap();

    let gateway = OphanGateway::new(app_swap, &snapshot);

    let mut proxy = HttpProxy::new(gateway, server.configuration.clone());
    proxy.handle_init_modules();

    let mut proxy_service = Service::new(String::from("Ophan gateway"), proxy);

    for listener in &snapshot.listeners {
        match listener.security.clone() {
            SecurityConfig::Plaintext => {
                for address in &listener.listen {
                    proxy_service.add_tcp(address);
                    println!("Listener: {}", address);
                }
            },
            SecurityConfig::Tls { certs, .. } => {
                for address in &listener.listen {
                    proxy_service
                        .add_tls(address, &certs.cert, &certs.key)
                        .map_err(|e| format!("failed to add TLS listener: {:?}", e))?;

                    println!("Listener: {}", address);
                }
            },
        }
    }

    server.add_service(proxy_service);
    println!(
        "[master: {:?}][{}] Ophan API Gateway is running...",
        Instant::now(),
        snapshot.master.name.clone()
    );

    drop(snapshot);

    server.run_forever();
}
