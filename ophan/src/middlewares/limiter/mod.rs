mod algorithm;
mod config;
mod context;
mod store;

use std::hash::Hasher;
use std::net::IpAddr;

pub use config::{LimiterConfig, LimiterIdentifier, LimiterRate, RateLimitAlgorithm};
pub use context::RateLimitContext;
use ophan_auth::Claims;
use ophan_net::http::header;
use ophan_net::proxy::{RequestParts, ResponseParts};

use http::{HeaderMap, HeaderValue, StatusCode};

use crate::{
    gateway::OphanCtx,
    middlewares::{
        FilterAction,
        limiter::store::{LimiterBackend, LimiterKey, RateLimiter},
    },
};

pub struct RateLimitMiddleware {
    limiter: RateLimiter,
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitMiddleware {
    pub fn new() -> Self {
        Self { limiter: RateLimiter::new(LimiterBackend::new_memory(1024)) }
    }

    pub fn on_request(&self, request: &RequestParts, config: &LimiterConfig, ctx: &mut OphanCtx) -> FilterAction {
        if config.skip_patterns.as_ref().is_some_and(|p| p.is_match(request.uri.path().as_bytes())) {
            return FilterAction::Continue;
        }

        let claims = ctx.policies.auth.as_ref().map(|a| &a.claims);

        let current_epoch = self.limiter.current_epoch();
        let limiter_key = self.resolve_key(config, ctx.client_addr, claims, &request.headers, current_epoch);

        let result = self.limiter.consume(limiter_key, config);

        ctx.policies.limiter = Some(RateLimitContext {
            limited: !result.allowed,
            limit: context::RateLimit(config.limit()),
            remaining: context::RemainingRequests(result.remaining),
            reset_at: context::ResetAt(result.retry_after),
        });

        if !result.allowed {
            return FilterAction::Reject(StatusCode::TOO_MANY_REQUESTS);
        }

        FilterAction::Continue
    }

    pub fn prepare_response(&self, res: &mut ResponseParts, limiter: &RateLimitContext) {
        let _ = res.insert_header(header::X_RATE_LIMIT_LIMIT, HeaderValue::from(limiter.limit.0));
        let _ = res.insert_header(header::X_RATE_LIMIT_REMAINING, HeaderValue::from(limiter.remaining.0));

        if limiter.reset_at.0 > 0 {
            let _ = res.insert_header(header::X_RATE_LIMIT_RESET, HeaderValue::from(limiter.reset_at.0));
        }
    }

    pub fn resolve_key(
        &self,
        config: &LimiterConfig,
        ip: IpAddr,
        claims: Option<&Claims>,
        headers: &HeaderMap,
        epoch: u64,
    ) -> LimiterKey {
        match &config.identifier {
            LimiterIdentifier::Ip => LimiterKey::from_ip(ip, epoch),

            LimiterIdentifier::Token(path) => {
                let claim_value = claims.and_then(|c| c.get_by_dot(path));

                let Some(sub) = claim_value else {
                    tracing::warn!(
                        path = %path,
                        client_ip = %ip,
                        "Token identifier claim not found; degrading to IP rate limiting"
                    );

                    return LimiterKey::from_ip(ip, epoch);
                };

                let mut hasher = ahash::AHasher::default();
                hasher.write(sub.as_bytes());

                LimiterKey::from_raw_hash(hasher.finish(), epoch)
            },

            LimiterIdentifier::Header(header_name) => {
                let header_bytes = match headers.get(header_name) {
                    Some(val) => val.as_bytes(),
                    None => {
                        tracing::warn!(
                            header = %header_name,
                            client_ip = %ip,
                            "Rate limit header not found; degrading to IP rate limiting"
                        );
                        return LimiterKey::from_ip(ip, epoch);
                    },
                };

                let mut hasher = ahash::AHasher::default();
                hasher.write(header_bytes);

                LimiterKey::from_raw_hash(hasher.finish(), epoch)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::OphanCtx;
    use context::{RateLimit, RemainingRequests, ResetAt};
    use http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn ip(lim: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, lim))
    }

    fn make_config(requests: u64, per_secs: u64, algorithm: RateLimitAlgorithm) -> LimiterConfig {
        LimiterConfig {
            rate: LimiterRate { requests, per: Duration::from_secs(per_secs) },
            burst: 0,
            algorithm,
            identifier: LimiterIdentifier::Ip,
            skip_patterns: None,
        }
    }

    fn make_request(method: &str, path: &str) -> pingora::http::RequestHeader {
        pingora::http::RequestHeader::build(method, path.as_bytes(), None).unwrap()
    }

    fn make_ctx(client_ip: IpAddr) -> OphanCtx {
        let mut ctx = OphanCtx::new();
        ctx.client_addr = client_ip;
        ctx
    }

    fn make_middleware() -> RateLimitMiddleware {
        RateLimitMiddleware::new()
    }

    // ── on_request ────────────────────────────────────────────────────────

    #[test]
    fn on_request_allows_under_limit() {
        let mw = make_middleware();
        let cfg = make_config(5, 60, RateLimitAlgorithm::SlidingWindow);
        let req = make_request("GET", "/api/data");
        let mut ctx = make_ctx(ip(1));

        let action = mw.on_request(&req, &cfg, &mut ctx);
        assert!(matches!(action, FilterAction::Continue));
        assert!(!ctx.policies.limiter.as_ref().unwrap().limited);
    }

    #[test]
    fn on_request_rejects_over_limit() {
        let mw = make_middleware();
        let cfg = make_config(2, 60, RateLimitAlgorithm::SlidingWindow);
        let req = make_request("GET", "/api/data");
        let mut ctx = make_ctx(ip(1));

        mw.on_request(&req, &cfg, &mut ctx);
        mw.on_request(&req, &cfg, &mut ctx);
        let action = mw.on_request(&req, &cfg, &mut ctx);

        assert!(matches!(action, FilterAction::Reject(StatusCode::TOO_MANY_REQUESTS)));
        assert!(ctx.policies.limiter.as_ref().unwrap().limited);
    }

    #[test]
    fn on_request_sets_context_values() {
        let mw = make_middleware();
        let cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        let req = make_request("GET", "/api/data");
        let mut ctx = make_ctx(ip(1));

        mw.on_request(&req, &cfg, &mut ctx);

        let limiter = ctx.policies.limiter.as_ref().unwrap();
        assert_eq!(limiter.limit.0, 10);
        assert_eq!(limiter.remaining.0, 9);
        assert!(!limiter.limited);
    }

    #[test]
    fn on_request_different_ips_independent() {
        let mw = make_middleware();
        let cfg = make_config(1, 60, RateLimitAlgorithm::SlidingWindow);
        let req = make_request("GET", "/");

        let mut ctx1 = make_ctx(ip(1));
        let action1 = mw.on_request(&req, &cfg, &mut ctx1);
        assert!(matches!(action1, FilterAction::Continue));

        // Different IP should have its own limit
        let mut ctx2 = make_ctx(ip(2));
        let action2 = mw.on_request(&req, &cfg, &mut ctx2);
        assert!(matches!(action2, FilterAction::Continue));
    }

    #[test]
    fn on_request_token_bucket_variant() {
        let mw = make_middleware();
        let cfg = make_config(5, 60, RateLimitAlgorithm::TokenBucket);
        let req = make_request("GET", "/");
        let mut ctx = make_ctx(ip(1));

        let action = mw.on_request(&req, &cfg, &mut ctx);
        assert!(matches!(action, FilterAction::Continue));
    }

    // ── prepare_response ──────────────────────────────────────────────────

    #[test]
    fn prepare_response_sets_headers() {
        let mw = make_middleware();
        let mut res = pingora::http::ResponseHeader::build(200, None).unwrap();

        let limiter = RateLimitContext {
            limited: false,
            limit: RateLimit(100),
            remaining: RemainingRequests(75),
            reset_at: ResetAt(1_700_000_060),
        };

        mw.prepare_response(&mut res, &limiter);

        assert_eq!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_LIMIT).unwrap(), "100");
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_REMAINING).unwrap(),
            "75"
        );
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_RESET).unwrap(),
            "1700000060"
        );
    }

    #[test]
    fn prepare_response_omits_reset_when_zero() {
        let mw = make_middleware();
        let mut res = pingora::http::ResponseHeader::build(200, None).unwrap();

        let limiter = RateLimitContext {
            limited: false,
            limit: RateLimit(100),
            remaining: RemainingRequests(100),
            reset_at: ResetAt(0),
        };

        mw.prepare_response(&mut res, &limiter);

        assert_eq!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_LIMIT).unwrap(), "100");
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_REMAINING).unwrap(),
            "100"
        );
        assert!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_RESET).is_none());
    }

    #[test]
    fn prepare_response_limited_state() {
        let mw = make_middleware();
        let mut res = pingora::http::ResponseHeader::build(429, None).unwrap();

        let limiter = RateLimitContext {
            limited: true,
            limit: RateLimit(10),
            remaining: RemainingRequests(0),
            reset_at: ResetAt(1_700_000_000),
        };

        mw.prepare_response(&mut res, &limiter);

        assert_eq!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_LIMIT).unwrap(), "10");
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_REMAINING).unwrap(),
            "0"
        );
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_RESET).unwrap(),
            "1700000000"
        );
    }

    // ── resolve_key ───────────────────────────────────────────────────────

    #[test]
    fn resolve_key_ip_identifier() {
        let mw = make_middleware();
        let cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        let headers = HeaderMap::new();

        let key = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        let key2 = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        assert_eq!(key, key2);
    }

    #[test]
    fn resolve_key_ip_different_ips() {
        let mw = make_middleware();
        let cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        let headers = HeaderMap::new();

        let k1 = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        let k2 = mw.resolve_key(&cfg, ip(2), None, &headers, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn resolve_key_header_identifier_found() {
        use ophan_auth::Claims;

        let mw = make_middleware();
        let mut cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        cfg.identifier = LimiterIdentifier::Header("x-api-key".to_string());

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("my-key-123"));

        let claims = Claims {
            sub: "user1".into(),
            exp: 9999999999,
            iat: 0,
            nbf: None,
            iss: None,
            aud: None,
            jti: None,
            scope: None,
            cnf: None,
            extra_data: serde_json::Map::new(),
        };

        let key = mw.resolve_key(&cfg, ip(1), Some(&claims), &headers, 0);
        // Same header value should produce same key
        let key2 = mw.resolve_key(&cfg, ip(1), Some(&claims), &headers, 0);
        assert_eq!(key, key2);
    }

    #[test]
    fn resolve_key_header_identifier_missing_degrades_to_ip() {
        let mw = make_middleware();
        let mut cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        cfg.identifier = LimiterIdentifier::Header("x-api-key".to_string());

        let headers = HeaderMap::new(); // No header present

        let key = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        let ip_key = LimiterKey::from_ip(ip(1), 0);
        assert_eq!(key, ip_key);
    }

    #[test]
    fn resolve_key_token_identifier_found() {
        use ophan_auth::Claims;

        let mw = make_middleware();
        let mut cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        cfg.identifier = LimiterIdentifier::Token("sub".to_string());

        let claims = Claims {
            sub: "user-abc".into(),
            exp: 9999999999,
            iat: 0,
            nbf: None,
            iss: None,
            aud: None,
            jti: None,
            scope: None,
            cnf: None,
            extra_data: serde_json::Map::new(),
        };

        let headers = HeaderMap::new();
        let key = mw.resolve_key(&cfg, ip(1), Some(&claims), &headers, 0);
        let key2 = mw.resolve_key(&cfg, ip(1), Some(&claims), &headers, 0);
        assert_eq!(key, key2);
    }

    #[test]
    fn resolve_key_token_identifier_missing_degrades_to_ip() {
        let mw = make_middleware();
        let mut cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        cfg.identifier = LimiterIdentifier::Token("sub".to_string());

        let headers = HeaderMap::new();
        // No claims provided → should degrade to IP
        let key = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        let ip_key = LimiterKey::from_ip(ip(1), 0);
        assert_eq!(key, ip_key);
    }

    #[test]
    fn resolve_key_epoch_affects_key() {
        let mw = make_middleware();
        let cfg = make_config(10, 60, RateLimitAlgorithm::SlidingWindow);
        let headers = HeaderMap::new();

        let k0 = mw.resolve_key(&cfg, ip(1), None, &headers, 0);
        let k1 = mw.resolve_key(&cfg, ip(1), None, &headers, 1);
        assert_ne!(k0, k1);
    }

    // ── End-to-end flow ───────────────────────────────────────────────────

    #[test]
    fn e2e_rate_limit_then_reject_then_serve_response() {
        let mw = make_middleware();
        let cfg = make_config(2, 60, RateLimitAlgorithm::SlidingWindow);
        let req = make_request("GET", "/api/data");
        let mut ctx = make_ctx(ip(1));

        // Request 1: allowed
        let action = mw.on_request(&req, &cfg, &mut ctx);
        assert!(matches!(action, FilterAction::Continue));
        let limiter = ctx.policies.limiter.as_ref().unwrap();
        assert_eq!(limiter.remaining.0, 1);

        // Request 2: allowed
        let action = mw.on_request(&req, &cfg, &mut ctx);
        assert!(matches!(action, FilterAction::Continue));
        let limiter = ctx.policies.limiter.as_ref().unwrap();
        assert_eq!(limiter.remaining.0, 0);

        // Request 3: rejected
        let action = mw.on_request(&req, &cfg, &mut ctx);
        assert!(matches!(action, FilterAction::Reject(StatusCode::TOO_MANY_REQUESTS)));
        let limiter = ctx.policies.limiter.as_ref().unwrap();
        assert!(limiter.limited);

        // Prepare response headers
        let mut res = pingora::http::ResponseHeader::build(429, None).unwrap();
        mw.prepare_response(&mut res, limiter);
        assert_eq!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_LIMIT).unwrap(), "2");
        assert_eq!(
            res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_REMAINING).unwrap(),
            "0"
        );
        assert!(res.headers.get(&ophan_net::http::header::X_RATE_LIMIT_RESET).is_some());
    }
}
