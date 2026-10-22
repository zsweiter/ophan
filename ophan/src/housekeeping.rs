use arc_swap::ArcSwap;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::balancer::HealthChecker;
use crate::metrics::RATE_LIMIT_ENTRIES;
use crate::middlewares::limiter::MemoryRateLimiter;
use crate::state::AppContext;

/// A gateway whose periodic tasks run in [`Housekeeping`].
pub struct WatchedGateway {
    pub name: Box<str>,
    pub context: Arc<ArcSwap<AppContext>>,
    pub limiter: Arc<MemoryRateLimiter>,
}

/// Background service that schedules the periodic tasks of every gateway: upstream health
/// checks every tick and rate limiter eviction every few ticks.
pub struct Housekeeping {
    gateways: Vec<WatchedGateway>,
}

impl Housekeeping {
    const TICK: Duration = Duration::from_secs(1);
    const LIMITER_EVICTION_EVERY: u32 = 10;

    pub fn new(gateways: Vec<WatchedGateway>) -> Self {
        Self { gateways }
    }

    fn tick(&self, now_ms: u64, evict_limiters: bool) {
        for gateway in &self.gateways {
            HealthChecker::check_due(&gateway.context.load_full(), now_ms);

            if evict_limiters {
                let remaining = gateway.limiter.evict_idle();
                RATE_LIMIT_ENTRIES.with_label_values(&[&*gateway.name]).set(remaining as i64);
            }
        }
    }
}

#[async_trait::async_trait]
impl BackgroundService for Housekeeping {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let started = Instant::now();
        let mut interval = tokio::time::interval(Self::TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut ticks: u32 = 0;

        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = interval.tick() => {
                    ticks = ticks.wrapping_add(1);
                    // Offset by one so the first check is never mistaken for "never checked".
                    let now_ms = started.elapsed().as_millis() as u64 + 1;
                    self.tick(now_ms, ticks.is_multiple_of(Self::LIMITER_EVICTION_EVERY));
                }
            }
        }
    }
}
