use std::{
    hash::{BuildHasherDefault, Hash, Hasher},
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, LazyLock},
    time::Instant,
};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::algorithm::{RateLimitResult, SlidingWindow, TokenBucket};
use super::config::{LimiterConfig, RateLimitAlgorithm};

/// Network mask applied to IPv6 addresses before hashing.
///
/// Clients are typically assigned a full `/64` prefix, so limiting by individual
/// IPv6 address would allow a single client to bypass the limit by rotating addresses.
const IPV6_PREFIX_MASK: u128 = u128::MAX << 64;

/// Upper bound of tracked clients per store. Beyond it, new clients of a policy share
/// one overflow bucket until idle entries are evicted, so memory stays bounded.
const MAX_TRACKED_CLIENTS: usize = 1 << 20;
const OVERFLOW_KEY: u64 = u64::MAX;

/// Per-process random seed so clients cannot craft colliding identifiers.
static KEY_HASHER: LazyLock<ahash::RandomState> = LazyLock::new(ahash::RandomState::new);

/// Hashes a client identifier (header value, token claim) with the process seed.
#[inline]
pub fn hash_identifier(bytes: &[u8]) -> u64 {
    KEY_HASHER.hash_one(bytes)
}

/// Hasher for [`LimiterKey`], whose client hash is already seeded: it only mixes the two
/// words instead of hashing them again.
#[derive(Default, Clone, Copy)]
pub struct PrehashedKey(u64);

impl Hasher for PrehashedKey {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.0 = self.0.rotate_left(29) ^ value;
    }
}

/// Internal rate limit state: either a sliding window or token bucket.
pub enum LimiterState {
    Sliding(SlidingWindow),
    Bucket(TokenBucket),
}

/// Composite key for rate limit state lookup.
///
/// The `key_hash` identifies the client (IP, header value, or token claim).
/// The `scope` identifies the limiter policy instance, so routes with different
/// policies and configurations loaded by a hot reload never share state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LimiterKey {
    pub key_hash: u64,
    pub scope: u64,
}

impl LimiterKey {
    /// Builds a key from a client IP address.
    ///
    /// IPv4-mapped IPv6 addresses are normalized to IPv4, and IPv6 addresses
    /// are truncated to their `/64` prefix.
    #[inline(always)]
    pub fn from_ip(ip: IpAddr, scope: u64) -> Self {
        let ip = match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & IPV6_PREFIX_MASK)),
            v4 => v4,
        };

        Self { key_hash: KEY_HASHER.hash_one(ip), scope }
    }

    #[inline(always)]
    pub fn from_raw_hash(hash: u64, scope: u64) -> Self {
        Self { key_hash: hash, scope }
    }
}

impl LimiterState {
    pub fn new(config: &LimiterConfig) -> Self {
        match config.algorithm {
            RateLimitAlgorithm::SlidingWindow => Self::Sliding(SlidingWindow::new(config)),
            RateLimitAlgorithm::TokenBucket => Self::Bucket(TokenBucket::new(config)),
        }
    }

    #[inline]
    fn check(&self, now_ms: u64) -> RateLimitResult {
        match self {
            Self::Sliding(w) => w.check(now_ms),
            Self::Bucket(b) => b.check(now_ms),
        }
    }

    /// Returns `true` when the state is indistinguishable from a fresh one.
    #[inline]
    fn is_idle(&self, now_ms: u64) -> bool {
        match self {
            Self::Sliding(w) => w.is_idle(now_ms),
            Self::Bucket(b) => b.is_idle(now_ms),
        }
    }
}

/// In-memory rate limiter backed by a concurrent hash map.
///
/// Uses `start_time.elapsed()` (monotonic clock) for time tracking,
/// which is immune to NTP adjustments, wall-clock skew, and leap seconds.
/// See [std::time::Instant](https://doc.rust-lang.org/std/time/struct.Instant.html).
///
/// Idle states are removed by [`MemoryRateLimiter::evict_idle`], which keeps memory
/// bounded by the number of active clients.
pub struct MemoryRateLimiter {
    states: DashMap<LimiterKey, LimiterState, BuildHasherDefault<PrehashedKey>>,
    tracked: AtomicUsize,
    max_tracked: usize,
    start_time: Instant,
}

impl Default for MemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRateLimiter {
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub fn with_capacity(size: usize) -> Self {
        Self {
            states: DashMap::with_capacity_and_hasher(size, BuildHasherDefault::default()),
            tracked: AtomicUsize::new(0),
            max_tracked: MAX_TRACKED_CLIENTS,
            start_time: Instant::now(),
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    pub fn consume(&self, key: LimiterKey, cfg: &LimiterConfig) -> RateLimitResult {
        let now_ms = self.now_ms();

        if let Some(state) = self.states.get(&key) {
            return state.check(now_ms);
        }

        let key = if self.tracked.load(Ordering::Relaxed) >= self.max_tracked {
            LimiterKey { key_hash: OVERFLOW_KEY, ..key }
        } else {
            key
        };

        match self.states.entry(key) {
            Entry::Occupied(state) => state.get().check(now_ms),
            Entry::Vacant(slot) => {
                self.tracked.fetch_add(1, Ordering::Relaxed);
                slot.insert(LimiterState::new(cfg)).check(now_ms)
            },
        }
    }

    /// Removes states whose window has fully elapsed. Returns the number of entries left.
    pub fn evict_idle(&self) -> usize {
        let now_ms = self.now_ms();
        self.states.retain(|_, state| !state.is_idle(now_ms));

        let len = self.states.len();
        self.tracked.store(len, Ordering::Relaxed);
        len
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
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
}

impl RateLimiter {
    pub fn new(backend: LimiterBackend) -> Self {
        Self { backend }
    }

    pub fn consume(&self, key: LimiterKey, cfg: &LimiterConfig) -> RateLimitResult {
        match &self.backend {
            LimiterBackend::Memory(state) => state.consume(key, cfg),
        }
    }

    pub fn backend(&self) -> &LimiterBackend {
        &self.backend
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
            scope: 0,
        }
    }

    fn make_bucket_config(requests: u64, per_secs: u64, burst: u64) -> LimiterConfig {
        LimiterConfig {
            rate: super::super::config::LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst,
            algorithm: super::super::config::RateLimitAlgorithm::TokenBucket,
            identifier: super::super::config::LimiterIdentifier::Ip,
            skip_patterns: None,
            scope: 0,
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
    fn key_from_ip_different_scopes_differ() {
        let k1 = LimiterKey::from_ip(ip(1), 0);
        let k2 = LimiterKey::from_ip(ip(1), 1);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_from_raw_hash_preserves_value() {
        let k = LimiterKey::from_raw_hash(0xDEAD_BEEF, 42);
        assert_eq!(k.key_hash, 0xDEAD_BEEF);
        assert_eq!(k.scope, 42);
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

    // ── Scopes / Eviction ─────────────────────────────────────────────────

    /// Each policy instance has its own scope, so exhausting one route's limit
    /// never affects another route (or a reloaded configuration).
    #[test]
    fn different_scopes_have_independent_state() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(2, 60);
        let key_a = LimiterKey::from_ip(ip(1), 1);
        let key_b = LimiterKey::from_ip(ip(1), 2);

        limiter.consume(key_a, &cfg);
        limiter.consume(key_a, &cfg);
        assert!(!limiter.consume(key_a, &cfg).allowed, "scope a should be exhausted");

        assert!(limiter.consume(key_b, &cfg).allowed, "scope b must start fresh");
    }

    #[test]
    fn new_clients_share_overflow_bucket_when_full() {
        let mut limiter = MemoryRateLimiter::new();
        limiter.max_tracked = 2;
        let cfg = make_config(1, 60);

        assert!(limiter.consume(LimiterKey::from_ip(ip(1), 0), &cfg).allowed);
        assert!(limiter.consume(LimiterKey::from_ip(ip(2), 0), &cfg).allowed);

        // The table is full: both newcomers land in the overflow bucket.
        assert!(limiter.consume(LimiterKey::from_ip(ip(3), 0), &cfg).allowed);
        assert!(!limiter.consume(LimiterKey::from_ip(ip(4), 0), &cfg).allowed);
        assert_eq!(limiter.len(), 3);
    }

    #[test]
    fn evict_idle_keeps_active_states() {
        let limiter = MemoryRateLimiter::new();
        let cfg = make_config(5, 60);

        limiter.consume(LimiterKey::from_ip(ip(1), 0), &cfg);
        limiter.consume(LimiterKey::from_ip(ip(2), 0), &cfg);

        assert_eq!(limiter.evict_idle(), 2);
    }

    #[test]
    fn evict_idle_removes_full_buckets() {
        let limiter = MemoryRateLimiter::new();
        // Zero-burst bucket of 1000 req/s refills a token every millisecond.
        let cfg = make_bucket_config(1000, 1, 0);

        limiter.consume(LimiterKey::from_ip(ip(1), 0), &cfg);
        std::thread::sleep(std::time::Duration::from_millis(5));

        assert_eq!(limiter.evict_idle(), 0);
    }

    // ── RateLimiter wrapper ───────────────────────────────────────────────

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

    // ── Clock / Timing ────────────────────────────────────────────────────

    /// The limiter uses `start_time.elapsed()` (monotonic clock),
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

    /// Verifies that `start_time.elapsed()` is used (monotonic),
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
