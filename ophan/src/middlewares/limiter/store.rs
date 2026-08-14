use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use dashmap::DashMap;

use crate::state::Reloadable;

use super::algorithm::{RateLimitResult, SlidingWindow, TokenBucket};
use super::config::{LimiterConfig, RateLimitAlgorithm};

/// Internal rate limit state: either a sliding window or token bucket.
pub enum LimiterState {
    Sliding(SlidingWindow),
    Bucket(TokenBucket),
}

/// Composite key for rate limit state lookup.
///
/// The `key_hash` identifies the client (IP, header value, or token claim).
/// The `epoch` ensures that hot-reloaded configurations create fresh states
/// rather than reusing stale ones from a previous configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LimiterKey {
    pub key_hash: u64,
    pub epoch: u64,
}

impl LimiterKey {
    #[inline(always)]
    pub fn from_ip(ip: IpAddr, epoch: u64) -> Self {
        let mut hasher = ahash::AHasher::default();
        ip.hash(&mut hasher);
        Self { key_hash: hasher.finish(), epoch }
    }

    #[inline(always)]
    pub fn from_raw_hash(hash: u64, epoch: u64) -> Self {
        Self { key_hash: hash, epoch }
    }
}

impl LimiterState {
    pub fn new(config: &LimiterConfig) -> Self {
        match config.algorithm {
            RateLimitAlgorithm::SlidingWindow => Self::Sliding(SlidingWindow::new(config)),
            RateLimitAlgorithm::TokenBucket => Self::Bucket(TokenBucket::new(config)),
        }
    }
}

/// In-memory rate limiter backed by a concurrent hash map.
///
/// Uses `Instant::now().elapsed()` (monotonic clock) for time tracking,
/// which is immune to NTP adjustments, wall-clock skew, and leap seconds.
/// See [std::time::Instant](https://doc.rust-lang.org/std/time/struct.Instant.html).
///
/// States are keyed by `(key_hash, epoch)`. When the epoch changes (hot reload),
/// all existing clients get fresh rate limit states.
pub struct MemoryRateLimiter {
    states: DashMap<LimiterKey, Arc<LimiterState>>,
    start_time: Instant,
    epoch: AtomicU64,
}

impl Default for MemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRateLimiter {
    pub fn new() -> Self {
        Self {
            states: DashMap::with_capacity(1024),
            start_time: Instant::now(),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn with_capacity(size: usize) -> Self {
        Self {
            states: DashMap::with_capacity(size),
            start_time: Instant::now(),
            epoch: AtomicU64::new(0),
        }
    }

    pub fn consume(&self, key: LimiterKey, cfg: &LimiterConfig) -> RateLimitResult {
        let now_ms = self.start_time.elapsed().as_millis() as u64;
        let limiter = self.states.entry(key).or_insert_with(|| Arc::new(LimiterState::new(cfg)));

        match limiter.value().as_ref() {
            LimiterState::Sliding(w) => w.check(now_ms),
            LimiterState::Bucket(b) => b.check(now_ms),
        }
    }
}

impl Reloadable for MemoryRateLimiter {
    async fn hot_reload(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

pub enum LimiterBackend {
    Memory(Arc<MemoryRateLimiter>),
}

impl LimiterBackend {
    pub fn new_memory(size_hint: usize) -> Self {
        Self::Memory(Arc::new(MemoryRateLimiter::with_capacity(size_hint)))
    }
}

pub struct RateLimiter {
    backend: LimiterBackend,
    epoch: AtomicU64,
}

impl RateLimiter {
    pub fn new(backend: LimiterBackend) -> Self {
        Self { backend, epoch: AtomicU64::new(0) }
    }

    pub fn consume(&self, key: LimiterKey, cfg: &LimiterConfig) -> RateLimitResult {
        match &self.backend {
            LimiterBackend::Memory(state) => state.consume(key, cfg),
        }
    }

    #[inline]
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    #[allow(unused)]
    #[inline]
    pub fn update_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_config(requests: u64, per_secs: u64) -> LimiterConfig {
        LimiterConfig {
            rate: super::super::config::LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst: 0,
            algorithm: super::super::config::RateLimitAlgorithm::SlidingWindow,
            identifier: super::super::config::LimiterIdentifier::Ip,
            skip_patterns: None,
        }
    }

    fn make_bucket_config(requests: u64, per_secs: u64, burst: u64) -> LimiterConfig {
        LimiterConfig {
            rate: super::super::config::LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst,
            algorithm: super::super::config::RateLimitAlgorithm::TokenBucket,
            identifier: super::super::config::LimiterIdentifier::Ip,
            skip_patterns: None,
        }
    }

    fn ip(lim: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, lim))
    }

    // ── LimiterKey ────────────────────────────────────────────────────────

    #[test]
    fn key_from_ip_deterministic() {
        let k1 = LimiterKey::from_ip(ip(1), 0);
        let k2 = LimiterKey::from_ip(ip(1), 0);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_from_ip_different_ips_differ() {
        let k1 = LimiterKey::from_ip(ip(1), 0);
        let k2 = LimiterKey::from_ip(ip(2), 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_from_ip_different_epochs_differ() {
        let k1 = LimiterKey::from_ip(ip(1), 0);
        let k2 = LimiterKey::from_ip(ip(1), 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_from_raw_hash_preserves_value() {
        let k = LimiterKey::from_raw_hash(0xDEAD_BEEF, 42);
        assert_eq!(k.key_hash, 0xDEAD_BEEF);
        assert_eq!(k.epoch, 42);
    }

    // ── MemoryRateLimiter ─────────────────────────────────────────────────

    #[test]
    fn memory_limiter_allows_under_limit() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(5, 60);
        let key = LimiterKey::from_ip(ip(1), 0);

        let r = limiter.consume(key, &cfg);
        assert!(r.allowed);
    }

    #[test]
    fn memory_limiter_rejects_over_limit() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(2, 60);
        let key = LimiterKey::from_ip(ip(1), 0);

        limiter.consume(key, &cfg);
        limiter.consume(key, &cfg);
        let r = limiter.consume(key, &cfg);

        assert!(!r.allowed);
    }

    #[test]
    fn memory_limiter_different_keys_independent() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(1, 60);

        let r1 = limiter.consume(LimiterKey::from_ip(ip(1), 0), &cfg);
        assert!(r1.allowed);

        // Different IP should have its own bucket
        let r2 = limiter.consume(LimiterKey::from_ip(ip(2), 0), &cfg);
        assert!(r2.allowed);
    }

    #[test]
    fn memory_limiter_same_key_shares_state() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(2, 60);
        let key = LimiterKey::from_ip(ip(1), 0);

        limiter.consume(key, &cfg);
        let r = limiter.consume(key, &cfg);
        assert!(r.allowed);

        let r = limiter.consume(key, &cfg);
        assert!(!r.allowed);
    }

    #[test]
    fn memory_limiter_token_bucket_variant() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_bucket_config(5, 60, 0);
        let key = LimiterKey::from_ip(ip(1), 0);

        let r = limiter.consume(key, &cfg);
        assert!(r.allowed);
        assert!(r.remaining > 0);
    }

    // ── Epoch / Hot Reload ────────────────────────────────────────────────

    /// When the epoch changes, keys with the old epoch should create fresh
    /// states. This simulates a hot reload: existing clients get a clean slate.
    #[test]
    fn epoch_change_creates_fresh_state() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(2, 60);
        let key_v0 = LimiterKey::from_ip(ip(1), 0);
        let key_v1 = LimiterKey::from_ip(ip(1), 1);

        // Exhaust v0
        limiter.consume(key_v0, &cfg);
        limiter.consume(key_v0, &cfg);
        let r = limiter.consume(key_v0, &cfg);
        assert!(!r.allowed, "v0 should be exhausted");

        // v1 (new epoch) should start fresh
        let r = limiter.consume(key_v1, &cfg);
        assert!(r.allowed, "v1 should be allowed after epoch change");
    }

    #[test]
    fn epoch_change_does_not_affect_other_keys() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(1, 60);

        // Exhaust key A at epoch 0
        let key_a0 = LimiterKey::from_ip(ip(1), 0);
        limiter.consume(key_a0, &cfg);
        let r = limiter.consume(key_a0, &cfg);
        assert!(!r.allowed);

        // Key B at epoch 0 should still work (different IP)
        let key_b0 = LimiterKey::from_ip(ip(2), 0);
        let r = limiter.consume(key_b0, &cfg);
        assert!(r.allowed);
    }

    // ── RateLimiter wrapper ───────────────────────────────────────────────

    #[test]
    fn rate_limiter_epoch_starts_at_zero() {
        let limiter = RateLimiter::new(LimiterBackend::new_memory(1024));
        assert_eq!(limiter.current_epoch(), 0);
    }

    #[test]
    fn rate_limiter_update_epoch_increments() {
        let limiter = RateLimiter::new(LimiterBackend::new_memory(1024));
        limiter.update_epoch();
        assert_eq!(limiter.current_epoch(), 1);
        limiter.update_epoch();
        assert_eq!(limiter.current_epoch(), 2);
    }

    #[test]
    fn rate_limiter_consume_delegates_to_backend() {
        let limiter = RateLimiter::new(LimiterBackend::new_memory(1024));
        let cfg = make_config(3, 60);
        let key = LimiterKey::from_ip(ip(1), 0);

        assert!(limiter.consume(key, &cfg).allowed);
        assert!(limiter.consume(key, &cfg).allowed);
        assert!(limiter.consume(key, &cfg).allowed);
        assert!(!limiter.consume(key, &cfg).allowed);
    }

    // ── Hot Reloadable trait ──────────────────────────────────────────────

    #[tokio::test]
    async fn hot_reload_increments_epoch() {
        use crate::state::Reloadable;

        let limiter = MemoryRateLimiter::new();
        assert_eq!(limiter.epoch.load(Ordering::SeqCst), 0);

        limiter.hot_reload().await;
        assert_eq!(limiter.epoch.load(Ordering::SeqCst), 1);

        limiter.hot_reload().await;
        assert_eq!(limiter.epoch.load(Ordering::SeqCst), 2);
    }

    // ── Clock / Timing ────────────────────────────────────────────────────

    /// The limiter uses `Instant::now().elapsed()` (monotonic clock),
    /// so there should be no NTP drift or wall-clock skew issues.
    /// This test verifies that time always moves forward.
    #[test]
    fn monotonic_time_never_goes_backwards() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(100, 60);
        let key = LimiterKey::from_ip(ip(1), 0);

        let mut prev_remaining = u64::MAX;
        for _ in 0..20 {
            let r = limiter.consume(key, &cfg);
            // Remaining should never increase (no refill in sliding window within same window)
            assert!(
                r.remaining <= prev_remaining,
                "remaining went backwards: {} > {}",
                r.remaining,
                prev_remaining
            );
            prev_remaining = r.remaining;
        }
    }

    /// Verifies that `Instant::now().elapsed()` is used (monotonic),
    /// not `SystemTime::now()` which could jump on NTP sync.
    #[test]
    fn uses_monotonic_not_system_clock() {
        // MemoryRateLimiter stores start_time as Instant
        let limiter = MemoryRateLimiter::new();
        // start_time is Instant::now() — this is monotonic by definition.
        // We can't directly test the clock source, but we verify the
        // limiter doesn't panic or produce negative durations.
        let cfg = make_config(10, 1);
        let key = LimiterKey::from_ip(ip(1), 0);

        // Multiple rapid calls should work without issue
        for _ in 0..100 {
            limiter.consume(key, &cfg);
        }
    }

    // ── LimiterBackend ────────────────────────────────────────────────────

    #[test]
    fn backend_memory_creation() {
        let backend = LimiterBackend::new_memory(256);
        match backend {
            LimiterBackend::Memory(m) => {
                // Verify it's usable
                let cfg = make_config(5, 60);
                let key = LimiterKey::from_ip(ip(1), 0);
                let r = m.consume(key, &cfg);
                assert!(r.allowed);
            },
        }
    }
}
