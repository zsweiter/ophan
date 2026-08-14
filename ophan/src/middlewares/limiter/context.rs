/// Maximum number of requests allowed in the current window.
///
/// Maps to the `X-Ratelimit-Limit` response header.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RateLimit(pub u64);

/// Number of requests remaining in the current window.
///
/// Maps to the `X-Ratelimit-Remaining` response header.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RemainingRequests(pub u64);

/// Seconds until the current rate limit window resets.
///
/// Maps to the `X-Ratelimit-Reset` response header.
/// A value of `0` indicates that no reset time should be emitted.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ResetAt(pub u64);

/// Per-request state produced by the rate limiter.
///
/// This context contains the values required to emit the standard
/// rate limit response headers per
/// [IETF draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/).
#[derive(Debug)]
pub struct RateLimitContext {
    /// Whether the request exceeded the configured rate limit.
    pub limited: bool,

    /// Maximum number of requests allowed in the current window.
    pub limit: RateLimit,

    /// Number of requests remaining in the current window.
    pub remaining: RemainingRequests,

    /// Unix timestamp when the current rate limit window resets.
    ///
    /// A value of `0` indicates that no reset time should be emitted.
    pub reset_at: ResetAt,
}

impl Default for RateLimitContext {
    fn default() -> Self {
        Self {
            limited: false,
            limit: RateLimit(0),
            remaining: RemainingRequests(0),
            reset_at: ResetAt(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_default_not_limited() {
        let ctx = RateLimitContext::default();
        assert!(!ctx.limited);
        assert_eq!(ctx.limit.0, 0);
        assert_eq!(ctx.remaining.0, 0);
        assert_eq!(ctx.reset_at.0, 0);
    }

    #[test]
    fn context_construction() {
        let ctx = RateLimitContext {
            limited: true,
            limit: RateLimit(100),
            remaining: RemainingRequests(0),
            reset_at: ResetAt(1_700_000_060),
        };
        assert!(ctx.limited);
        assert_eq!(ctx.limit.0, 100);
        assert_eq!(ctx.remaining.0, 0);
        assert_eq!(ctx.reset_at.0, 1_700_000_060);
    }
}
