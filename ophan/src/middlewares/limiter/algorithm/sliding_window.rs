use std::sync::atomic::{AtomicU64, Ordering};

use crate::middlewares::limiter::{LimiterConfig, algorithm::RateLimitResult};

/// Sliding window rate limiter.
///
/// Uses a weighted combination of the previous and current window counts
/// to provide a smooth approximation of a true sliding window, as described in
/// [Cloudflare's blog on sliding window rate limiting](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/).
///
/// The algorithm:
/// 1. Divide time into fixed windows of `window_secs` seconds.
/// 2. Track request counts for the current and previous windows.
/// 3. Compute effective count = `prev_count * weight + current_count`,
///    where `weight = (window_size - elapsed_in_window) / window_size`.
/// 4. Allow the request if `effective + 1 <= max_requests`.
pub struct SlidingWindow {
    max_requests: u64,
    window_secs: u64,
    current_window: AtomicU64,
    current_count: AtomicU64,
    previous_window: AtomicU64,
    previous_count: AtomicU64,
}

impl SlidingWindow {
    pub fn new(cfg: &LimiterConfig) -> Self {
        Self {
            max_requests: cfg.limit(),
            window_secs: cfg.window(),
            current_window: AtomicU64::new(0),
            current_count: AtomicU64::new(0),
            previous_window: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
        }
    }

    pub fn check(&self, now_ms: u64) -> RateLimitResult {
        let window_size_ms = self.window_secs * 1000;
        let window = now_ms / window_size_ms;
        let current = self.current_window.load(Ordering::Acquire);

        if current != window && self.current_window.compare_exchange(current, window, Ordering::AcqRel, Ordering::Acquire).is_ok()
        {
            let old = self.current_count.swap(0, Ordering::AcqRel);
            self.previous_count.store(old, Ordering::Release);
            self.previous_window.store(current, Ordering::Release);
        }

        let elapsed = now_ms % window_size_ms;
        let weight = (window_size_ms - elapsed) as f64 / window_size_ms as f64;

        let previous_window = self.previous_window.load(Ordering::Acquire);
        let previous_count = if previous_window + 1 == window {
            self.previous_count.load(Ordering::Acquire)
        } else {
            0
        };

        let current_count = self.current_count.load(Ordering::Acquire);
        let effective = (previous_count as f64 * weight) + current_count as f64;

        let allowed = (effective + 1.0) <= self.max_requests as f64;

        if allowed {
            self.current_count.fetch_add(1, Ordering::SeqCst);
            let remaining = self.max_requests.saturating_sub((effective + 1.0) as u64);
            RateLimitResult { allowed: true, remaining, retry_after: 0 }
        } else {
            let retry_after_ms = if previous_count > 0 {
                let needed_weight = (self.max_requests as f64 - current_count as f64) / previous_count as f64;
                if needed_weight < weight {
                    let target_elapsed = window_size_ms as f64 * (1.0 - needed_weight);
                    (target_elapsed - elapsed as f64).max(0.0) as u64
                } else {
                    window_size_ms - elapsed
                }
            } else {
                window_size_ms - elapsed
            };

            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after: retry_after_ms.div_ceil(1000),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middlewares::limiter::{LimiterConfig, LimiterIdentifier, LimiterRate, RateLimitAlgorithm};
    use std::time::Duration;

    fn sliding_config(requests: u64, per_secs: u64) -> LimiterConfig {
        LimiterConfig {
            rate: LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst: 0,
            algorithm: RateLimitAlgorithm::SlidingWindow,
            identifier: LimiterIdentifier::Ip,
            skip_patterns: None,
        }
    }

    #[test]
    fn sliding_window_allows_under_limit() {
        let cfg = sliding_config(5, 60);
        let sw = SlidingWindow::new(&cfg);
        let now_ms = 1_000;

        let r = sw.check(now_ms);
        assert!(r.allowed);
        assert!(r.remaining > 0);
    }

    #[test]
    fn sliding_window_rejects_over_limit() {
        let cfg = sliding_config(2, 60);
        let sw = SlidingWindow::new(&cfg);
        let now_ms = 1_000;

        sw.check(now_ms);
        sw.check(now_ms);
        let r = sw.check(now_ms);

        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
        assert!(r.retry_after > 0);
    }

    #[test]
    fn sliding_window_remaining_decrements() {
        let cfg = sliding_config(10, 60);
        let sw = SlidingWindow::new(&cfg);
        let now_ms = 1_000;

        let r1 = sw.check(now_ms);
        assert_eq!(r1.remaining, 9);

        let r2 = sw.check(now_ms);
        assert_eq!(r2.remaining, 8);
    }

    #[test]
    fn sliding_window_exact_limit_boundary() {
        let cfg = sliding_config(3, 60);
        let sw = SlidingWindow::new(&cfg);
        let now_ms = 1_000;

        assert!(sw.check(now_ms).allowed);
        assert!(sw.check(now_ms).allowed);
        assert!(sw.check(now_ms).allowed);
        // 4th request at exact limit should be rejected
        let r = sw.check(now_ms);
        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
    }

    #[test]
    fn sliding_window_weighted_previous_window() {
        // Window size = 60s = 60_000ms
        // Place 2 requests in window 0 (time 0..59_999)
        let cfg = sliding_config(10, 60);
        let sw = SlidingWindow::new(&cfg);

        sw.check(0);
        sw.check(1000);

        // Move to 50% into the next window (time 60_000 + 30_000 = 90_000)
        // previous_count=2, weight=0.5, effective = 2*0.5 + 0 = 1.0
        // (1.0 + 1.0) <= 10 → allowed
        let r = sw.check(90_000);
        assert!(r.allowed);
        // remaining should account for weighted previous: 10 - (1+1) = 8
        assert_eq!(r.remaining, 8);
    }

    #[test]
    fn sliding_window_previous_window_fully_aged_out() {
        let cfg = sliding_config(5, 1); // 1 second window
        let sw = SlidingWindow::new(&cfg);

        sw.check(0);
        sw.check(100);
        sw.check(200);
        sw.check(300);
        sw.check(400);

        // Move 2 full windows ahead (window 2 vs current window 0)
        // previous_window (0) + 1 != window (2), so previous_count = 0
        let r = sw.check(2500);
        assert!(r.allowed);
        assert_eq!(r.remaining, 4); // 5 - 1 (only current request counted)
    }

    #[test]
    fn sliding_window_retry_after_calculation() {
        let cfg = sliding_config(2, 60);
        let sw = SlidingWindow::new(&cfg);

        sw.check(0);
        sw.check(1000);

        let r = sw.check(2000);
        assert!(!r.allowed);
        // retry_after should be until end of window (60s window, 2s elapsed → ~58s)
        assert!(r.retry_after > 50);
        assert!(r.retry_after <= 60);
    }

    #[test]
    fn sliding_window_concurrent_check() {
        use std::sync::Arc;
        use std::thread;

        let cfg = sliding_config(100, 60);
        let sw = Arc::new(SlidingWindow::new(&cfg));
        let mut handles = vec![];

        for _ in 0..10 {
            let sw = Arc::clone(&sw);
            handles.push(thread::spawn(move || {
                let mut allowed_count = 0;
                for _ in 0..20 {
                    if sw.check(1000).allowed {
                        allowed_count += 1;
                    }
                }
                allowed_count
            }));
        }

        let total_allowed: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // Should not exceed max_requests (100) due to atomic operations
        assert!(total_allowed <= 100, "total_allowed={total_allowed} exceeded limit of 100");
    }

    #[test]
    fn sliding_window_zero_elapsed_time() {
        // At the very start of a window (elapsed=0), weight=1.0
        let cfg = sliding_config(5, 60);
        let sw = SlidingWindow::new(&cfg);

        // Window 0: requests at time 0
        sw.check(0);

        // Still in window 0, elapsed=0, weight should be 1.0
        // previous should not contribute since previous_window (0) == current window
        let r = sw.check(0);
        assert!(r.allowed);
        assert_eq!(r.remaining, 3); // 5 - 2 (two requests in current window)
    }

    #[test]
    fn sliding_window_boundary_crossing() {
        // Window size = 1s = 1000ms, limit = 5
        // Fill window 0 (time 0..999ms)
        let cfg = sliding_config(5, 1);
        let sw = SlidingWindow::new(&cfg);

        for _ in 0..5 {
            sw.check(0);
        }
        assert!(!sw.check(0).allowed);

        // Cross into window 1 at t=1000ms.
        // Weighted previous count = 5 * 1.0 (weight at elapsed=0) = 5.0
        // effective = 5.0 + 0 = 5.0 → (5.0 + 1) > 5 → still blocked
        // This is correct: a full previous window blocks the first request
        // in the new window until enough time elapses for the weight to decay.
        let r = sw.check(1000);
        assert!(!r.allowed);

        // After 20% of the window elapses (t=1200ms), weight = 0.8
        // effective = 5 * 0.8 = 4.0 → (4.0 + 1) <= 5 → allowed
        let r = sw.check(1200);
        assert!(r.allowed);
    }

    #[test]
    fn sliding_window_single_request_limit() {
        let cfg = sliding_config(1, 60);
        let sw = SlidingWindow::new(&cfg);

        assert!(sw.check(0).allowed);
        let r = sw.check(0);
        assert!(!r.allowed);
        assert_eq!(r.remaining, 0);
    }
}
