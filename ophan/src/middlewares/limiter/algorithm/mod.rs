mod sliding_window;
mod token_bucket;

pub use sliding_window::SlidingWindow;
pub use token_bucket::TokenBucket;

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    /// Seconds until the next request would be allowed (`0` when allowed).
    pub retry_after: u64,
    /// Seconds until the client's quota is fully restored.
    pub reset_after: u64,
}
