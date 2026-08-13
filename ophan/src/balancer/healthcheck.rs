use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;

use crate::balancer::Backend;
use crate::balancer::Upstream;
use crate::balancer::backend::BackendAddr;

pub struct HealthScheduler {
    queue: DelayQueue<Arc<Upstream>>,
    events: mpsc::Receiver<Arc<Backend>>,
}

#[allow(unused)] // for future use with dynamic routing
#[derive(Debug)]
pub struct Shard {
    pub servers: Vec<Arc<Backend>>,
    pub interval: Duration,
    pub timeout: Duration,
    pub concurrency: usize,
}

impl HealthScheduler {
    pub fn new(upstreams: Vec<Arc<Upstream>>, events: mpsc::Receiver<Arc<Backend>>) -> Self {
        let mut queue = DelayQueue::new();

        for u in upstreams {
            queue.insert(u, Duration::from_secs(0));
        }

        Self { queue, events }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // We receive a backend event, which indicates that a backend has been added or removed.
                Some(_backend) = self.events.recv() => {
                    // let upstream = backend.upstream();
                    // let interval = upstream.health.interval;

                    // Self::check_upstream(&upstream).await;

                    // self.queue.insert(upstream, interval);
                }

                Some(expired) = self.queue.next() => {
                    let upstream = expired.into_inner();
                    let interval = upstream.health.interval;

                    Self::check_upstream(&upstream).await;

                    self.queue.insert(upstream, interval);
                }
            }
        }
    }

    async fn check_upstream(upstream: &Upstream) {
        let timeout = upstream.health.timeout;
        let concurrency = upstream.health.concurrency;

        let backends = upstream.servers.load();

        stream::iter(backends.iter())
            .map(|backend| {
                let backend = Arc::clone(backend);
                async move {
                    let ok = Self::check_backend_status(&backend.addr, timeout).await;
                    backend.set_healthy(ok);
                }
            })
            .buffer_unordered(concurrency)
            .for_each(|_| async {})
            .await;
    }

    async fn check_backend_status(addr: &BackendAddr, timeout: Duration) -> bool {
        match addr {
            BackendAddr::Tcp(socket_addr) => {
                let result = tokio::time::timeout(timeout, TcpStream::connect(socket_addr)).await;

                result.map(|r| r.is_ok()).unwrap_or(false)
            },

            BackendAddr::Host(host_addr) => tokio::time::timeout(timeout, TcpStream::connect(host_addr.into_parts()))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false),

            #[cfg(unix)]
            BackendAddr::Uds(path) => {
                if !path.exists() {
                    return false;
                }

                let result = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path.as_ref())).await;

                result.map(|r| r.is_ok()).unwrap_or(false)
            },
        }
    }
}
