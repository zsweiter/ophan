use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;

use crate::balancer::{Backend, BalanceStrategy};

#[derive(Clone, Debug)]
pub struct HealthConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub concurrency: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(3),
            concurrency: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct UpstreamId(pub usize);

#[derive(Debug)]
pub struct Upstream {
    pub id: UpstreamId,
    pub name: ImmerStr,
    pub health: HealthConfig,
    pub servers: ArcSwap<Vec<Arc<Backend>>>,
    pub balance_strategy: BalanceStrategy,

    last_check_ms: AtomicU64,
    rr_counter: AtomicUsize,
    lc_counter: AtomicUsize,
}

impl Upstream {
    pub fn new(id: usize, name: ImmerStr, backends: Vec<Arc<Backend>>, lb: BalanceStrategy) -> Self {
        Self {
            id: UpstreamId(id),
            name,
            health: HealthConfig::default(),
            last_check_ms: AtomicU64::new(0),
            rr_counter: AtomicUsize::new(0),
            lc_counter: AtomicUsize::new(0),
            servers: ArcSwap::new(Arc::new(backends)),
            balance_strategy: lb,
        }
    }

    pub fn update_balance_strategy(&mut self, strategy: BalanceStrategy) {
        self.balance_strategy = strategy;
    }

    pub fn update_backends(&self, backends: Vec<Arc<Backend>>) {
        self.servers.store(Arc::new(backends));
    }

    pub fn update_health_config(&mut self, health: HealthConfig) {
        self.health = health;
    }

    pub fn is_due(&self, now_ms: u64) -> bool {
        let last = self.last_check_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last) >= self.health.interval.as_millis() as u64
    }

    pub fn mark_checked(&self, now_ms: u64) {
        self.last_check_ms.store(now_ms, Ordering::Relaxed);
    }

    #[inline]
    pub fn next_ticket(&self) -> usize {
        match self.balance_strategy {
            BalanceStrategy::RoundRobin => self.rr_counter.fetch_add(1, Ordering::Relaxed),
            BalanceStrategy::LeastConnections => self.lc_counter.fetch_add(1, Ordering::Relaxed),
            _ => 0, // For other strategies, we can return 0 or handle accordingly
        }
    }
}
