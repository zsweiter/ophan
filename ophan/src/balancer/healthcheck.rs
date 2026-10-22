use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::balancer::Upstream;
use crate::balancer::backend::BackendAddr;
use crate::config::HealthCheckConfig;
use crate::state::AppContext;

const CHECK_CONCURRENCY: usize = 8;

/// Active health checks of upstream backends.
pub struct HealthChecker;

impl HealthChecker {
    /// Starts the checks of every upstream of `context` whose interval elapsed. Upstreams are
    /// read from the context given on each call, so a hot reload is picked up.
    pub fn check_due(context: &Arc<AppContext>, now_ms: u64) {
        for (idx, upstream) in context.load_balancer.upstreams().iter().enumerate() {
            if !upstream.is_due(now_ms) || upstream.checking.swap(true, Ordering::AcqRel) {
                continue;
            }

            upstream.mark_checked(now_ms);

            let context = Arc::clone(context);
            tokio::spawn(async move {
                if let Some(upstream) = context.load_balancer.upstreams().get(idx) {
                    Self::check_upstream(upstream).await;
                    upstream.checking.store(false, Ordering::Release);
                }
            });
        }
    }

    async fn check_upstream(upstream: &Upstream) {
        let Some(health) = upstream.health.as_ref() else {
            return;
        };

        let backends = upstream.servers.load_full();

        stream::iter(backends.iter())
            .for_each_concurrent(CHECK_CONCURRENCY, |backend| async move {
                let ok = Self::check_backend(&backend.addr, health).await;
                backend.report_check(ok, health.healthy_threshold, health.unhealthy_threshold);
            })
            .await;
    }

    async fn check_backend(addr: &BackendAddr, health: &HealthCheckConfig) -> bool {
        let probe = async {
            match addr {
                BackendAddr::Tcp(socket_addr) => {
                    let stream = TcpStream::connect(socket_addr).await?;
                    Self::probe_http(stream, &socket_addr.to_string(), health.path.as_deref()).await
                },

                // TLS backends are checked at the TCP level only.
                BackendAddr::Host(host_addr) => {
                    let stream = TcpStream::connect(host_addr.into_parts()).await?;
                    let path = if host_addr.is_https() { None } else { health.path.as_deref() };
                    Self::probe_http(stream, host_addr.host(), path).await
                },

                #[cfg(unix)]
                BackendAddr::Uds(path) => {
                    let stream = tokio::net::UnixStream::connect(path.as_ref()).await?;
                    Self::probe_http(stream, "localhost", health.path.as_deref()).await
                },
            }
        };

        matches!(tokio::time::timeout(health.timeout, probe).await, Ok(Ok(true)))
    }

    /// Without a path, a successful connect is enough. With a path, sends a
    /// `GET` and accepts any 2xx or 3xx status.
    async fn probe_http<S>(mut stream: S, host: &str, path: Option<&str>) -> std::io::Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some(path) = path else {
            return Ok(true);
        };

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ophan-health-check\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;

        // "HTTP/1.1 200" is all we need.
        let mut status_line = [0u8; 12];
        stream.read_exact(&mut status_line).await?;

        Ok(Self::parse_status(&status_line).is_some_and(|code| (200..400).contains(&code)))
    }

    /// Status code of an HTTP/1.x status line (`HTTP/1.1 200`).
    fn parse_status(line: &[u8; 12]) -> Option<u16> {
        if !line.starts_with(b"HTTP/1.") || line[8] != b' ' {
            return None;
        }

        std::str::from_utf8(&line[9..12]).ok()?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_line() {
        assert_eq!(HealthChecker::parse_status(b"HTTP/1.1 204"), Some(204));
        assert_eq!(HealthChecker::parse_status(b"HTTP/1.0 503"), Some(503));
        assert_eq!(HealthChecker::parse_status(b"SSH-2.0-Open"), None);
    }

    #[tokio::test]
    async fn probe_without_path_only_needs_connect() {
        let (client, _server) = tokio::io::duplex(64);
        assert!(HealthChecker::probe_http(client, "x", None).await.unwrap());
    }

    #[tokio::test]
    async fn probe_with_path_checks_status() {
        let (client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET /health HTTP/1.1\r\n"));
            server.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await.unwrap();
        });

        assert!(!HealthChecker::probe_http(client, "x", Some("/health")).await.unwrap());
        server_task.await.unwrap();
    }
}
