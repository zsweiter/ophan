use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use arc_swap::ArcSwap;
use flatkit::str::ImmerStr;

use crate::balancer::{Backend, BalanceStrategy};
use crate::config::HealthCheckConfig;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct UpstreamId(pub usize);

#[derive(Debug)]
pub struct Upstream {
    pub id: UpstreamId,
    pub name: ImmerStr,
    pub health: Option<HealthCheckConfig>,
    pub servers: ArcSwap<Vec<Arc<Backend>>>,
    pub balance_strategy: BalanceStrategy,

    last_check_ms: AtomicU64,
    pub checking: AtomicBool,
}

thread_local! {
    /// Per-thread selection ticket, each thread starting at its own offset.
    static TICKET: Cell<usize> = Cell::new(NEXT_THREAD_OFFSET.fetch_add(1, Ordering::Relaxed));
}

static NEXT_THREAD_OFFSET: AtomicUsize = AtomicUsize::new(0);

impl Upstream {
    pub fn new(id: usize, name: ImmerStr, backends: Vec<Arc<Backend>>, lb: BalanceStrategy) -> Self {
        Self {
            id: UpstreamId(id),
            name,
            health: None,
            last_check_ms: AtomicU64::new(0),
            checking: AtomicBool::new(false),
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

    pub fn update_health_config(&mut self, health: Option<HealthCheckConfig>) {
        self.health = health;
    }

    pub fn is_due(&self, now_ms: u64) -> bool {
        let Some(health) = &self.health else {
            return false;
        };

        let last = self.last_check_ms.load(Ordering::Relaxed);
        last == 0 || now_ms.saturating_sub(last) >= health.interval.as_millis() as u64
    }

    pub fn mark_checked(&self, now_ms: u64) {
        self.last_check_ms.store(now_ms, Ordering::Relaxed);
    }

    #[inline]
    pub fn next_ticket(&self) -> usize {
        match self.balance_strategy {
            BalanceStrategy::RoundRobin | BalanceStrategy::LeastConnections => TICKET.with(|ticket| {
                let value = ticket.get();
                ticket.set(value.wrapping_add(1));
                value
            }),
            BalanceStrategy::IpHash => 0,
        }
    }
}
