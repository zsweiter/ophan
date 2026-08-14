mod sliding_window;
mod token_bucket;

pub use sliding_window::SlidingWindow;
pub use token_bucket::TokenBucket;

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after: u64,
}
