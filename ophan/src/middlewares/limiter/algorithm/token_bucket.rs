use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::middlewares::limiter::{LimiterConfig, algorithm::RateLimitResult};

/// Token bucket rate limiter.
///
/// Implements the classic token bucket algorithm as described in
/// [RFC 2697](https://datatracker.ietf.org/doc/html/rfc2697) (Single Rate Three Color Marker).
///
/// Tokens refill at a constant rate. Each request consumes one token (scaled by `SCALE`).
/// The bucket has a maximum capacity = `(limit + burst) * SCALE`, allowing short bursts
/// above the steady-state rate.
///
/// Uses a CAS loop for lock-free concurrent access.
pub struct TokenBucket {
    capacity: u64,
    refill_rate_per_ms: f64,
    per_seconds: u64,

    tokens: AtomicU64,
    last_refill: AtomicU64,
    initialized: AtomicBool,
}

/// Internal scale factor for sub-token precision. Allows smooth token
/// accumulation at any rate without discrete refill intervals.
const TOKEN_SCALE: u64 = 1_000;

impl TokenBucket {
    pub fn new(cfg: &LimiterConfig) -> Self {
        let limit = cfg.limit();
        let capacity = (limit + cfg.burst) * TOKEN_SCALE;
        let refill_rate_per_ms = (limit * TOKEN_SCALE) as f64 / (cfg.window() * 1000) as f64;

        Self {
            capacity,
            refill_rate_per_ms,
            per_seconds: cfg.window(),
            tokens: AtomicU64::new(capacity),
            last_refill: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn check(&self, now_ms: u64) -> RateLimitResult {
        loop {
            let current_tokens = self.tokens.load(Ordering::Acquire);

            if !self.initialized.load(Ordering::Acquire) {
                if self.initialized.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                    self.last_refill.store(now_ms, Ordering::Release);

                    if current_tokens < TOKEN_SCALE {
                        let missing = TOKEN_SCALE - current_tokens;
                        let retry_after_ms = if self.refill_rate_per_ms > 0.0 {
                            (missing as f64 / self.refill_rate_per_ms).ceil() as u64
                        } else {
                            self.per_seconds * 1000
                        };
                        return RateLimitResult {
                            allowed: false,
                            remaining: 0,
                            retry_after: retry_after_ms.div_ceil(1000),
                        };
                    }

                    let rem_tokens = current_tokens - TOKEN_SCALE;
                    if self
                        .tokens
                        .compare_exchange(current_tokens, rem_tokens, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return RateLimitResult {
                            allowed: true,
                            remaining: rem_tokens / TOKEN_SCALE,
                            retry_after: 0,
                        };
                    }
                    continue;
                }
                // Another thread won the race, retry
                continue;
            }

            let last = self.last_refill.load(Ordering::Acquire);
            let elapsed = now_ms.saturating_sub(last);
            let refill = (elapsed as f64 * self.refill_rate_per_ms) as u64;
            let new_tokens = (current_tokens + refill).min(self.capacity);

            if new_tokens < TOKEN_SCALE {
                let missing = TOKEN_SCALE - new_tokens;
                let retry_after_ms = if self.refill_rate_per_ms > 0.0 {
                    (missing as f64 / self.refill_rate_per_ms).ceil() as u64
                } else {
                    self.per_seconds * 1000
                };

                return RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    retry_after: retry_after_ms.div_ceil(1000),
                };
            }

            let rem_tokens = new_tokens - TOKEN_SCALE;
            let next_refill = last + elapsed;

            if self.last_refill.compare_exchange(last, next_refill, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                self.tokens.store(rem_tokens, Ordering::Release);
                return RateLimitResult {
                    allowed: true,
                    remaining: rem_tokens / TOKEN_SCALE,
                    retry_after: 0,
                };
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

        let cfg = bucket_config(100, 0, 0);
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
}
