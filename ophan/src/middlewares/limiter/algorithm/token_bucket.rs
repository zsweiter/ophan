use std::sync::atomic::{AtomicU64, Ordering};

use crate::middlewares::limiter::{LimiterConfig, algorithm::RateLimitResult};

/// Token bucket rate limiter.
///
/// Implements the token bucket algorithm through its equivalent formulation, the
/// Generic Cell Rate Algorithm (GCRA), as defined in ITU-T Recommendation I.371.
///
/// The bucket has a maximum capacity of `limit + burst` tokens and refills at a constant
/// rate of `limit / window`, allowing short bursts above the steady-state rate.
///
/// The state is stored as a single theoretical arrival time (TAT) instead of a token
/// count and a refill timestamp, so it can be updated atomically with a single CAS.
///
/// Uses a CAS loop for lock-free concurrent access.
pub struct TokenBucket {
    /// Time required to refill a single token, in nanoseconds.
    emission_ns: u64,
    /// Time equivalent of a full bucket, in nanoseconds.
    tolerance_ns: u64,
    window_secs: u64,

    /// Theoretical arrival time of the next request, in nanoseconds.
    tat_ns: AtomicU64,
}

const NANOS_PER_MS: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

impl TokenBucket {
    pub fn new(cfg: &LimiterConfig) -> Self {
        let limit = cfg.limit();
        let window_secs = cfg.window();
        assert!(window_secs > 0, "rate limiter window must be greater than 0");

        let window_ns = window_secs.saturating_mul(NANOS_PER_SEC);
        // A zero limit disables refilling; all requests are rejected.
        let emission_ns = if limit == 0 { 0 } else { (window_ns / limit).max(1) };
        let capacity = limit.saturating_add(cfg.burst);
        let tolerance_ns = emission_ns.saturating_mul(capacity);

        Self {
            emission_ns,
            tolerance_ns,
            window_secs,
            tat_ns: AtomicU64::new(0),
        }
    }

    /// The bucket has refilled completely.
    pub fn is_idle(&self, now_ms: u64) -> bool {
        self.tat_ns.load(Ordering::Acquire) <= now_ms.saturating_mul(NANOS_PER_MS)
    }

    pub fn check(&self, now_ms: u64) -> RateLimitResult {
        if self.emission_ns == 0 {
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after: self.window_secs,
                reset_after: self.window_secs,
            };
        }

        let now = now_ms.saturating_mul(NANOS_PER_MS);
        let limit_at = now.saturating_add(self.tolerance_ns);
        let mut tat = self.tat_ns.load(Ordering::Acquire);

        loop {
            // A TAT in the past means the bucket is full.
            let new_tat = tat.max(now).saturating_add(self.emission_ns);

            if new_tat > limit_at {
                let wait_ns = new_tat - limit_at;
                return RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    retry_after: wait_ns.div_ceil(NANOS_PER_SEC),
                    reset_after: (tat.max(now) - now).div_ceil(NANOS_PER_SEC),
                };
            }

            match self.tat_ns.compare_exchange_weak(tat, new_tat, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    return RateLimitResult {
                        allowed: true,
                        remaining: (limit_at - new_tat) / self.emission_ns,
                        retry_after: 0,
                        reset_after: (new_tat - now).div_ceil(NANOS_PER_SEC),
                    };
                },
                // Another thread updated the state, retry
                Err(actual) => tat = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middlewares::limiter::{LimiterConfig, LimiterIdentifier, LimiterRate, RateLimitAlgorithm};
    use std::time::Duration;

    fn bucket_config(requests: u64, per_secs: u64, burst: u64) -> LimiterConfig {
        LimiterConfig {
            rate: LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst,
            algorithm: RateLimitAlgorithm::TokenBucket,
            identifier: LimiterIdentifier::Ip,
            skip_patterns: None,
            scope: 0,
        }
    }

    #[test]
    fn token_bucket_allows_initial_requests() {
        let cfg = bucket_config(5, 60, 0);
        let tb = TokenBucket::new(&cfg);
        let now_ms = 1_000;

        let r = tb.check(now_ms);
        assert!(r.allowed);
        assert!(r.remaining > 0);
    }

    #[test]
    fn token_bucket_rejects_when_exhausted() {
        let cfg = bucket_config(2, 60, 0);
        let tb = TokenBucket::new(&cfg);
        let now_ms = 1_000;

        tb.check(now_ms);
        tb.check(now_ms);
        let r = tb.check(now_ms);

        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
        assert!(r.retry_after > 0);
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let cfg = bucket_config(10, 1, 0);
        let tb = TokenBucket::new(&cfg);

        let r1 = tb.check(0);
        assert!(r1.allowed);

        let r2 = tb.check(1);
        assert!(r2.allowed);

        let r3 = tb.check(2);
        assert!(r3.allowed);

        assert!(r3.remaining <= r1.remaining);
    }

    #[test]
    fn token_bucket_burst_allows_above_limit() {
        let cfg = bucket_config(5, 60, 3); // limit=5, burst=3 → capacity=8
        let tb = TokenBucket::new(&cfg);

        // Should allow 8 requests (5 + 3 burst)
        for i in 0..8 {
            let r = tb.check(0);
            assert!(r.allowed, "request {i} should be allowed with burst");
        }
        // 9th should be rejected
        let r = tb.check(0);
        assert!(!r.allowed);
    }

    #[test]
    fn token_bucket_full_refill_after_window() {
        let cfg = bucket_config(5, 1, 0); // 5 req/sec
        let tb = TokenBucket::new(&cfg);

        // Exhaust all tokens
        for _ in 0..5 {
            tb.check(0);
        }
        let r = tb.check(0);
        assert!(!r.allowed);

        // After full window (1s = 1000ms), tokens should refill
        let r = tb.check(1000);
        assert!(r.allowed);
    }

    #[test]
    fn token_bucket_partial_refill() {
        let cfg = bucket_config(10, 1, 0); // 10 req/sec → 10 tokens per 1000ms
        let tb = TokenBucket::new(&cfg);

        // Exhaust all
        for _ in 0..10 {
            tb.check(0);
        }

        // After 500ms, should have ~5 tokens refilled (10 * 500/1000 = 5)
        let r = tb.check(500);
        assert!(r.allowed);
    }

    #[test]
    fn token_bucket_never_exceeds_capacity() {
        let cfg = bucket_config(5, 60, 0);
        let tb = TokenBucket::new(&cfg);

        // Even after long time, tokens should not exceed capacity
        let r = tb.check(0);
        let initial_remaining = r.remaining;

        let r = tb.check(600_000); // 10 minutes later
        assert!(r.remaining <= initial_remaining);
    }

    #[test]
    fn token_bucket_retry_after_estimates_refill_time() {
        let cfg = bucket_config(10, 1, 0);
        let tb = TokenBucket::new(&cfg);

        // Exhaust
        for _ in 0..10 {
            tb.check(0);
        }

        let r = tb.check(0);
        assert!(!r.allowed);
        // retry_after should be ~1 second (1000ms) since refill_rate = 10 tokens/sec
        assert!(r.retry_after >= 1);
        assert!(r.retry_after <= 2);
    }

    #[test]
    fn token_bucket_concurrent_check() {
        use std::sync::Arc;
        use std::thread;

        // Long window so that no refill occurs during the test
        let cfg = bucket_config(100, 60, 0);
        let tb = Arc::new(TokenBucket::new(&cfg));

        let mut handles = Vec::with_capacity(10);

        for _ in 0..10 {
            let tb = Arc::clone(&tb);

            handles.push(thread::spawn(move || {
                let mut allowed = 0;

                for _ in 0..20 {
                    if tb.check(1000).allowed {
                        allowed += 1;
                    }
                }

                allowed
            }));
        }

        let total_allowed: u64 = handles.into_iter().map(|handle| handle.join().unwrap()).sum();

        assert_eq!(total_allowed, 100, "exactly the initial bucket capacity must be consumed");
    }

    #[test]
    fn token_bucket_first_request_initializes() {
        let cfg = bucket_config(5, 60, 0);
        let tb = TokenBucket::new(&cfg);

        // First request at any time should always be allowed
        let r = tb.check(50000);
        assert!(r.allowed);
        assert_eq!(r.remaining, 4); // 5 - 1
    }

    #[test]
    #[should_panic(expected = "window must be greater than 0")]
    fn token_bucket_rejects_zero_window() {
        let cfg = bucket_config(100, 0, 0);
        let _ = TokenBucket::new(&cfg);
    }
}
