use std::{str::FromStr, time::Duration};

use flatkit::matchers::PathMatcherSet;

/// Configuration for the rate limiter middleware.
///
/// Controls the rate limit, burst tolerance, algorithm, client identification,
/// and URL exclusion patterns.
#[derive(Debug, Clone)]
pub struct LimiterConfig {
    pub rate: LimiterRate,
    pub burst: u64,
    pub algorithm: RateLimitAlgorithm,
    pub identifier: LimiterIdentifier,
    pub skip_patterns: Option<PathMatcherSet>,
}

impl LimiterConfig {
    #[inline]
    pub fn limit(&self) -> u64 {
        self.rate.requests
    }

    #[inline]
    pub fn window(&self) -> u64 {
        self.rate.per.as_secs()
    }

    #[inline]
    pub fn bucket_capacity(&self) -> u64 {
        self.rate.requests + self.burst
    }
}

impl Default for LimiterConfig {
    fn default() -> Self {
        Self {
            rate: LimiterRate::default(),
            burst: 15,
            algorithm: RateLimitAlgorithm::default(),
            identifier: LimiterIdentifier::default(),
            skip_patterns: None,
        }
    }
}

/// Rate definition: number of requests allowed within a time window.
#[derive(Debug, Clone)]
pub struct LimiterRate {
    pub requests: u64,
    pub per: Duration,
}

// use from (request, seconds)
impl From<LimiterRate> for (u64, u64) {
    fn from(value: LimiterRate) -> Self {
        (value.requests, value.per.as_secs())
    }
}

impl From<(u64, u64)> for LimiterRate {
    fn from(value: (u64, u64)) -> Self {
        Self { requests: value.0, per: Duration::from_secs(value.1) }
    }
}

impl From<(u64, Duration)> for LimiterRate {
    fn from(value: (u64, Duration)) -> Self {
        Self { requests: value.0, per: value.1 }
    }
}

impl Default for LimiterRate {
    fn default() -> Self {
        Self { requests: 60, per: Duration::from_secs(60) }
    }
}

/// Rate limiting algorithm selection.
///
/// - **Sliding window** (default): Weighted average of previous and current window counts.
///   Provides smooth rate limiting without the burst-at-boundary issue of fixed windows.
/// - **Token bucket**: Allows bursts up to `capacity = (limit + burst)` while enforcing
///   a steady-state rate. Refills tokens at a constant rate.
///
/// See [Cloudflare's sliding window approach](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum RateLimitAlgorithm {
    #[default]
    SlidingWindow,
    TokenBucket,
}

impl FromStr for RateLimitAlgorithm {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sliding_window" | "sliding-window" => Ok(Self::SlidingWindow),
            "token_bucket" | "token-bucket" => Ok(Self::TokenBucket),
            _ => Err(format!(
                "invalid rate limit algorithm '{value}', expected one of: sliding_window, token_bucket"
            )),
        }
    }
}

impl TryFrom<&str> for RateLimitAlgorithm {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<RateLimitAlgorithm> for &'static str {
    fn from(value: RateLimitAlgorithm) -> Self {
        match value {
            RateLimitAlgorithm::SlidingWindow => "sliding_window",
            RateLimitAlgorithm::TokenBucket => "token_bucket",
        }
    }
}

/// How the rate limiter identifies a client.
///
/// - **Ip**: Rate limit by client IP address (default).
/// - **Header**: Rate limit by a specific request header value (e.g., `X-Api-Key`).
/// - **Token**: Rate limit by a JWT claim value (e.g., `sub`, `scope`, or a custom claim).
///
/// If the configured identifier is missing (header not present, claim not found),
/// the limiter degrades to IP-based identification as a fallback.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum LimiterIdentifier {
    #[default]
    Ip,
    Header(String), // Stores the header name (e.g., "x-api-key")
    Token(String),  // Stores the JSON path / dotted claim (e.g., "sub", "data.plan")
}

impl FromStr for LimiterIdentifier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed.eq_ignore_ascii_case("ip") {
            return Ok(Self::Ip);
        }

        if trimmed.eq_ignore_ascii_case("header") {
            return Ok(Self::Header("authorization".to_string()));
        } else if let Some(header_name) = trimmed.strip_prefix("header:") {
            let name = header_name.trim();
            if name.is_empty() {
                return Err("Header name cannot be empty after 'header:' prefix".into());
            }
            return Ok(Self::Header(name.to_ascii_lowercase()));
        }

        if trimmed.eq_ignore_ascii_case("token") {
            return Ok(Self::Token("sub".to_string()));
        } else if let Some(token_path) = trimmed.strip_prefix("token:") {
            let path = token_path.trim();
            if path.is_empty() {
                return Err("Token claim path cannot be empty after 'token:' prefix".into());
            }
            return Ok(Self::Token(path.to_string()));
        }

        Err(format!(
            "invalid identifier '{s}', expected 'ip', 'header', 'header:<name>', 'token', or 'token:<claim>'"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_algorithm_default() {
        assert_eq!(RateLimitAlgorithm::default(), RateLimitAlgorithm::SlidingWindow);
    }

    #[test]
    fn test_limiter_identifier_default() {
        assert_eq!(LimiterIdentifier::default(), LimiterIdentifier::Ip);
    }

    // ---------------------------------------------------------------------------
    // RateLimitAlgorithm
    // ---------------------------------------------------------------------------

    #[test]
    fn test_rate_limit_algorithm_sliding_window() {
        for s in &["sliding_window", "sliding-window"] {
            assert_eq!(RateLimitAlgorithm::try_from(*s).unwrap(), RateLimitAlgorithm::SlidingWindow);
        }
    }

    #[test]
    fn test_rate_limit_algorithm_token_bucket() {
        for s in &["token_bucket", "token-bucket"] {
            assert_eq!(RateLimitAlgorithm::try_from(*s).unwrap(), RateLimitAlgorithm::TokenBucket);
        }
    }

    #[test]
    fn test_rate_limit_algorithm_invalid() {
        let err = RateLimitAlgorithm::try_from("fixed_window").unwrap_err();
        assert!(err.contains("invalid rate limit algorithm"));
    }

    #[test]
    fn test_rate_limit_algorithm_into_static_str() {
        assert_eq!(
            <RateLimitAlgorithm as Into<&'static str>>::into(RateLimitAlgorithm::SlidingWindow),
            "sliding_window"
        );
        assert_eq!(
            <RateLimitAlgorithm as Into<&'static str>>::into(RateLimitAlgorithm::TokenBucket),
            "token_bucket"
        );
    }

    // ---------------------------------------------------------------------------
    // LimiterConfig
    // ---------------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let cfg = LimiterConfig::default();
        assert_eq!(cfg.rate.requests, 60);
        assert_eq!(cfg.rate.per, Duration::from_secs(60));
        assert_eq!(cfg.burst, 15);
        assert_eq!(cfg.algorithm, RateLimitAlgorithm::SlidingWindow);
        assert_eq!(cfg.identifier, LimiterIdentifier::Ip);
        assert!(cfg.skip_patterns.is_none());
    }

    #[test]
    fn config_limit_returns_requests() {
        let cfg = LimiterConfig {
            rate: LimiterRate { requests: 42, per: Duration::from_secs(30) },
            ..Default::default()
        };
        assert_eq!(cfg.limit(), 42);
    }

    #[test]
    fn config_window_returns_per_secs() {
        let cfg = LimiterConfig {
            rate: LimiterRate { requests: 10, per: Duration::from_secs(120) },
            ..Default::default()
        };
        assert_eq!(cfg.window(), 120);
    }

    #[test]
    fn config_bucket_capacity_includes_burst() {
        let cfg = LimiterConfig {
            rate: LimiterRate { requests: 10, per: Duration::from_secs(60) },
            burst: 5,
            ..Default::default()
        };
        assert_eq!(cfg.bucket_capacity(), 15);
    }

    #[test]
    fn config_bucket_capacity_zero_burst() {
        let cfg = LimiterConfig {
            rate: LimiterRate { requests: 10, per: Duration::from_secs(60) },
            burst: 0,
            ..Default::default()
        };
        assert_eq!(cfg.bucket_capacity(), 10);
    }

    // ---------------------------------------------------------------------------
    // LimiterRate conversions
    // ---------------------------------------------------------------------------

    #[test]
    fn rate_into_tuple() {
        let rate = LimiterRate { requests: 100, per: Duration::from_secs(30) };
        let (reqs, secs): (u64, u64) = rate.into();
        assert_eq!(reqs, 100);
        assert_eq!(secs, 30);
    }

    #[test]
    fn rate_from_tuple() {
        let rate: LimiterRate = (50, 120).into();
        assert_eq!(rate.requests, 50);
        assert_eq!(rate.per, Duration::from_secs(120));
    }

    #[test]
    fn rate_from_tuple_zero() {
        let rate: LimiterRate = (0, 0).into();
        assert_eq!(rate.requests, 0);
        assert_eq!(rate.per, Duration::from_secs(0));
    }

    // ---------------------------------------------------------------------------
    // RateLimitAlgorithm edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn algorithm_try_from_case_insensitive() {
        assert!(RateLimitAlgorithm::try_from("SLIDING_WINDOW").is_err(),);
        assert!(RateLimitAlgorithm::try_from("Token_Bucket").is_err(),);
    }

    #[test]
    fn algorithm_try_from_with_whitespace() {
        assert!(RateLimitAlgorithm::try_from("  sliding_window  ").is_err(),);
        assert!(RateLimitAlgorithm::try_from("  token-bucket  ").is_err(),);
    }

    #[test]
    fn algorithm_try_from_empty_string() {
        assert!(RateLimitAlgorithm::try_from("").is_err());
    }

    #[test]
    fn algorithm_try_from_completely_invalid() {
        assert!(RateLimitAlgorithm::try_from("random").is_err());
        assert!(RateLimitAlgorithm::try_from("123").is_err());
    }

    // ---------------------------------------------------------------------------
    // LimiterIdentifier
    // ---------------------------------------------------------------------------

    #[test]
    fn identifier_ip_default() {
        assert_eq!(LimiterIdentifier::default(), LimiterIdentifier::Ip);
    }

    #[test]
    fn identifier_header_clone() {
        let id = LimiterIdentifier::Header("X-Api-Key".to_string());
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn identifier_token_clone() {
        let id = LimiterIdentifier::Token("sub".to_string());
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }
}
