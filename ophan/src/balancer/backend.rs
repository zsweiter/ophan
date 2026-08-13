use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use flatkit::net::HostAddr;

use crate::config::NetworkProtocol;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendAddr {
    Tcp(SocketAddr),
    Host(HostAddr),
    #[cfg(unix)]
    Uds(Arc<PathBuf>),
}

// Backend reprents a Server Backend, like clusters
#[allow(unused)] // for future use with dinamic routing
#[derive(Debug)]
pub struct Backend {
    pub addr: BackendAddr,
    pub protocol: NetworkProtocol,
    pub host_addr: Option<HostAddr>,

    active_conns: AtomicUsize,
    score: AtomicUsize,
    total_requests: AtomicU64,
    failed_requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    total_latency_ns: AtomicU64,
    latency_samples: AtomicU64,

    weight: AtomicU32,
    healthy: AtomicBool,
}

impl Backend {
    pub fn new(addr: BackendAddr, weight: u32) -> Self {
        Self {
            addr,
            protocol: NetworkProtocol::default(),
            active_conns: AtomicUsize::new(0),
            score: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            weight: AtomicU32::new(weight),
            healthy: AtomicBool::new(true),
            host_addr: None,
        }
    }

    pub fn from_tcp(addr: SocketAddr, weight: u32) -> Self {
        Self::new(BackendAddr::Tcp(addr), weight)
    }

    pub fn from_host(addr: &HostAddr, weight: u32) -> Self {
        let mut backend = Self::new(BackendAddr::Host(addr.to_owned()), weight);
        backend.host_addr = Some(addr.to_owned());
        backend
    }

    #[cfg(unix)]
    pub fn from_uds(path: PathBuf, weight: u32) -> Self {
        Self::new(BackendAddr::Uds(Arc::new(path)), weight)
    }

    pub fn set_protocol(&mut self, protocol: NetworkProtocol) {
        self.protocol = protocol
    }
}

#[allow(unused)] // for future use with dinamic routing
impl Backend {
    pub fn weight(&self) -> u32 {
        self.weight.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, status: bool) {
        let prev = self.healthy.load(Ordering::Relaxed);
        if prev != status {
            self.healthy.store(status, Ordering::Relaxed);
        }
    }

    pub fn active_conns(&self) -> usize {
        self.active_conns.load(Ordering::Relaxed)
    }

    pub fn acquire(&self) {
        self.active_conns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        let old = self.active_conns.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(old > 0);
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_latency_ns(&self, ns: u64) {
        self.total_latency_ns.fetch_add(ns, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn avg_latency_ns(&self) -> Option<u64> {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return None;
        }

        let total = self.total_latency_ns.load(Ordering::Relaxed);
        Some(total / samples)
    }

    pub fn score(&self) -> usize {
        self.score.load(Ordering::Relaxed)
    }

    pub fn update_score(&self) {
        let conns = self.active_conns.load(Ordering::Acquire);
        let failures = self.failed_requests.load(Ordering::Acquire);
        let latency = self.avg_latency_ns().unwrap_or(0);

        let computed = (conns * 10) + (failures as usize * 50) + (latency as usize / 1_000_000);

        self.score.store(computed, Ordering::Release);
    }

    pub fn load_factor(&self) -> usize {
        let conns = self.active_conns.load(Ordering::Acquire);
        let failures = self.failed_requests.load(Ordering::Acquire) as usize;
        let latency = self.avg_latency_ns().unwrap_or(0) as usize;

        conns + failures * 2 + latency / 1_000_000
    }

    pub fn is_overloaded(&self, threshold: usize) -> bool {
        self.load_factor() > threshold
    }
}
