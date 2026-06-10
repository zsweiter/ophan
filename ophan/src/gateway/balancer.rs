use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use dashmap::DashMap;

use crate::config::{BalanceStrategy, NetworkProtocol, NetworkTransport};

pub struct Backend {
    pub addr: String,
    pub transport: NetworkTransport,
    pub protocol: NetworkProtocol,
    pub active_conns: AtomicUsize,
    pub is_healthy: AtomicBool,
}

impl Backend {
    pub fn new(addr: String, transport: NetworkTransport, protocol: NetworkProtocol) -> Self {
        Self {
            addr,
            transport,
            protocol,
            active_conns: AtomicUsize::new(0),
            is_healthy: AtomicBool::new(true),
        }
    }
}

pub struct LoadBalancer {
    upstreams: DashMap<String, Vec<Arc<Backend>>>,
    round_robin_counters: DashMap<String, AtomicUsize>,
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            upstreams: DashMap::new(),
            round_robin_counters: DashMap::new(),
        }
    }

    pub fn add_upstream(&self, name: String, backends: Vec<Arc<Backend>>) {
        self.upstreams.insert(name, backends);
    }

    pub fn select_server(
        &self,
        upstream_name: &str,
        strategy: &BalanceStrategy,
        client_ip: Option<&str>,
    ) -> Option<Arc<Backend>> {
        let bucket = self.upstreams.get(upstream_name)?;
        let count = bucket.len();
        if count == 0 {
            return None;
        }

        let idx = match strategy {
            BalanceStrategy::RoundRobin => {
                let counter = self.round_robin_counters.entry(upstream_name.to_string()).or_insert_with(|| AtomicUsize::new(0));
                counter.fetch_add(1, Ordering::Relaxed) % count
            },
            BalanceStrategy::LeastConnections => bucket
                .iter()
                .enumerate()
                .filter(|(_, b)| b.is_healthy.load(Ordering::Relaxed))
                .min_by_key(|(_, b)| b.active_conns.load(Ordering::Relaxed))
                .map(|(i, _)| i)?,
            BalanceStrategy::IpHash => {
                let ip = client_ip.unwrap_or("127.0.0.1");
                ip.bytes().fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(b as usize)) % count
            },
            BalanceStrategy::Random => {
                let mut entry_key = upstream_name.to_string();
                entry_key.push_str("_rnd");

                let counter = self.round_robin_counters.entry(entry_key).or_insert_with(|| AtomicUsize::new(0));
                counter.fetch_add(1, Ordering::Relaxed) % count
            },
        };

        let server = bucket[idx].clone();
        server.active_conns.fetch_add(1, Ordering::Relaxed);
        Some(server)
    }

    pub fn release_conn(&self, upstream_name: &str, addr: &str) {
        if let Some(bucket) = self.upstreams.get(upstream_name) {
            for backend in bucket.iter() {
                if backend.addr == addr {
                    backend.active_conns.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}
