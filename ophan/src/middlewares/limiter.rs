use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHasher;
use dashmap::DashMap;
use http::request::Parts;

use crate::{
    config::{LimiterConfig, LimiterIdentifier},
    gateway::{GatewayError, OphanCtx},
    middlewares::RequestOutcome,
};

#[derive(Clone, Copy, Eq)]
pub enum LimiterKey {
    Ip(IpAddr),
    Hash(u64),
}

impl PartialEq for LimiterKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ip(a), Self::Ip(b)) => a == b,
            (Self::Hash(a), Self::Hash(b)) => a == b,
            _ => false,
        }
    }
}

impl Hash for LimiterKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Ip(ip) => ip.hash(state),
            Self::Hash(v) => v.hash(state),
        }
    }
}

#[derive(Debug)]
pub struct GcraState {
    tat: Instant,
}

pub struct RateLimiter {
    states: DashMap<LimiterKey, GcraState>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { states: DashMap::with_capacity(4096) }
    }

    #[inline]
    pub fn check(&self, request: &Parts, cfg: &LimiterConfig) -> bool {
        let key = self.resolve_key(request, cfg);
        let now = Instant::now();

        let mut entry = self.states.entry(key).or_insert_with(|| GcraState { tat: now });

        self.check_gcra(entry.value_mut(), cfg, now)
    }

    /// GCRA algorithm
    ///
    /// Returns:
    /// true  => rate limited
    /// false => allowed
    #[inline]
    fn check_gcra(&self, state: &mut GcraState, cfg: &LimiterConfig, now: Instant) -> bool {
        let emission_interval = Duration::from_secs_f64(cfg.rate.per_seconds as f64 / cfg.rate.requests as f64);

        let burst_offset = emission_interval.mul_f64(cfg.burst as f64);
        let allow_at = state.tat.checked_sub(burst_offset).unwrap_or(now);

        if now < allow_at {
            return true;
        }

        state.tat = std::cmp::max(state.tat, now) + emission_interval;

        false
    }

    #[inline]
    fn resolve_key(&self, request: &Parts, cfg: &LimiterConfig) -> LimiterKey {
        match &cfg.identifier {
            LimiterIdentifier::Ip => LimiterKey::Ip(IpAddr::from([0, 0, 0, 0])),

            LimiterIdentifier::Header(name) | LimiterIdentifier::Token(name) => {
                let value = request.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");

                LimiterKey::Hash(self.hash_pair(name.as_bytes(), value.as_bytes()))
            },
        }
    }

    #[inline]
    fn hash_pair(&self, a: &[u8], b: &[u8]) -> u64 {
        let mut hasher = AHasher::default();

        hasher.write(a);
        hasher.write_u8(b':');
        hasher.write(b);

        hasher.finish()
    }
}

pub struct RateLimitMiddleware {
    limiter: Arc<RateLimiter>,
}

impl RateLimitMiddleware {
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }

    pub fn on_request(&self, request: &Parts, ctx: &mut OphanCtx) -> Result<RequestOutcome, pingora::BError> {
        let limiter_cfg = match ctx.matched_route.as_ref() {
            Some(route) => match route.limiter_policy.as_deref() {
                Some(policy) => policy,
                None => return Ok(RequestOutcome::Continue),
            },

            None => return Ok(RequestOutcome::Continue),
        };

        if let Some(route) = &ctx.matched_route
            && route.limiter_excludes.contains(request.uri.path())
        {
            return Ok(RequestOutcome::Continue);
        }

        if self.limiter.check(request, limiter_cfg) {
            // let resp = Response::builder()
            //     .status(429)
            //     .header("Retry-After", retry_after.to_string())
            //     .header("RateLimit-Limit", limit.to_string())
            //     .header("RateLimit-Remaining", "0")
            //     .body(None)
            //     .unwrap();

            // return Ok(RequestOutcome::Respond(resp));
            return Ok(RequestOutcome::Reject(GatewayError::TooManyRequests));
        }

        Ok(RequestOutcome::Continue)
    }
}
