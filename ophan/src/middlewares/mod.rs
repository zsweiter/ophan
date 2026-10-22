pub mod auth;
pub mod cors;
pub mod helmet;
pub mod limiter;
pub mod rewrites;
pub mod waf;

use crate::{
    gateway::OphanCtx,
    middlewares::{
        auth::{AuthContext, AuthMiddleware},
        cors::{CorsContext, CorsMiddleware},
        helmet::{Helmet, HelmetConfig},
        limiter::{LimiterIdentifier, MemoryRateLimiter, RateLimitContext, RateLimitMiddleware},
        waf::{WafContext, WafEngineMiddleware},
    },
    state::HttpRoute,
};

use bytes::Bytes;
use http::StatusCode;
use ophan_net::http::vary::VarySet;
use ophan_net::proxy::{RequestParts, ResponseParts};

const X_USER_CLAIMS: http::HeaderName = http::HeaderName::from_static("x-user-claims");

#[derive(Debug, Default)]
pub struct PolicyContext {
    pub cors: Option<CorsContext>,         // stage 1
    pub waf: Option<WafContext>,           // stage 2
    pub limiter: Option<RateLimitContext>, // stage 3
    pub auth: Option<AuthContext>,         // stage 4
}

pub enum FilterAction {
    Continue, // Continue flow
    EarlyResponse(StatusCode),
    Reject(StatusCode),
}

macro_rules! run_policy_filter {
    ($middleware:expr, $policy:expr, $req:expr, $ctx:expr) => {
        let action = $middleware.on_request($req, $policy, $ctx);

        if !matches!(action, FilterAction::Continue) {
            return action;
        }
    };
}

pub struct Pipeline {
    cors_middleware: CorsMiddleware,            // stage 1
    waf_middleware: WafEngineMiddleware,        // stage 2
    rate_limit_middleware: RateLimitMiddleware, // stage 3
    auth_middleware: AuthMiddleware,            // stage 4

    // Security
    helmet: Helmet,
}

impl Pipeline {
    pub fn new(auth: AuthMiddleware, rate_limit: RateLimitMiddleware, waf: WafEngineMiddleware, cors: CorsMiddleware) -> Self {
        Self {
            auth_middleware: auth,
            rate_limit_middleware: rate_limit,
            waf_middleware: waf,
            cors_middleware: cors,
            helmet: Helmet::new(),
        }
    }

    pub fn rate_limiter_store(&self) -> std::sync::Arc<MemoryRateLimiter> {
        self.rate_limit_middleware.store()
    }

    /// Pre-request processing pipeline.
    /// This function is called before the request is forwarded to the backend.
    pub async fn on_request(&self, req: &RequestParts, route: &HttpRoute, ctx: &mut OphanCtx) -> FilterAction {
        if let Some(cors) = route.cors_policy.as_ref() {
            // The router admits OPTIONS on CORS routes for preflights only.
            let not_preflight =
                req.method == http::Method::OPTIONS && !req.headers.contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD);
            if not_preflight && !route.methods.is_empty() && !route.methods.contains_method(&req.method) {
                return FilterAction::Reject(StatusCode::METHOD_NOT_ALLOWED);
            }

            run_policy_filter!(self.cors_middleware, cors, req, ctx);
        }

        // For now is omited
        if false && let Some(waf) = route.waf_policy.as_ref() {
            match self.waf_middleware.on_request(req, waf, ctx) {
                FilterAction::Continue => { /* continue */ },
                action => return action,
            }
        }

        let limiter = route.limiter_policy.as_ref();
        let limit_after_auth = limiter.is_some_and(|l| matches!(l.identifier, LimiterIdentifier::Token(_)));

        if !limit_after_auth && let Some(limiter) = limiter {
            run_policy_filter!(self.rate_limit_middleware, limiter, req, ctx);
        }

        if let Some(auth) = route.auth_policy.as_ref() {
            let scheme = ctx.scheme;
            match Box::pin(self.auth_middleware.on_request_with_scheme(req, scheme, auth, ctx)).await {
                FilterAction::Continue => { /* continue */ },
                action => return action,
            }
        }

        if limit_after_auth && let Some(limiter) = limiter {
            run_policy_filter!(self.rate_limit_middleware, limiter, req, ctx);
        }

        FilterAction::Continue
    }

    pub async fn on_request_body(
        &self,
        req: &RequestParts,
        route: &HttpRoute,
        body: &mut Option<Bytes>,
        _body_end: bool,
        ctx: &mut OphanCtx,
    ) -> FilterAction {
        let Some(waf_config) = route.waf_policy.as_ref() else {
            return FilterAction::Continue;
        };

        // If current request no have waf_policies, is disabled or excluded
        let Some(_waf) = ctx.policies.waf.as_ref() else {
            return FilterAction::Continue;
        };

        let Some(bytes) = &body else {
            return FilterAction::Continue;
        };

        match self.waf_middleware.filter_request_body(req, bytes, waf_config, ctx) {
            FilterAction::Continue => { /* continue */ },
            action => return action,
        }

        FilterAction::Continue
    }

    pub async fn on_upstream_request(
        &self,
        upstream_request: &mut RequestParts,
        _route: &HttpRoute,
        ctx: &PolicyContext,
    ) -> Result<(), pingora::BError> {
        upstream_request.remove_header(&X_USER_CLAIMS);

        if let Some(auth) = ctx.auth.as_ref() {
            let header_value = auth
                .claims_header()
                .ok_or_else(|| pingora::Error::explain(pingora::ErrorType::InternalError, "failed to encode user claims"))?;

            upstream_request.insert_header(ophan_net::http::header::wire::X_USER_CLAIMS, header_value.clone())?;
        }

        Ok(())
    }

    pub fn prepare_response(&self, response: &mut ResponseParts, route: Option<&HttpRoute>, ctx: &PolicyContext, vary: VarySet) {
        // Responses that matched no route (our own error pages) use the default policy.
        let helmet_cfg = route.map_or(Some(HelmetConfig::default()), |r| r.helmet_policy);
        if let Some(helmet_cfg) = helmet_cfg {
            self.helmet.prepare_response(helmet_cfg, response);
        }

        if let Some(cors) = ctx.cors.as_ref()
            && let Some(cors_config) = route.and_then(|r| r.cors_policy.as_deref())
        {
            self.cors_middleware.prepare_response(response, cors_config, cors);
        }

        if let Some(limiter) = ctx.limiter.as_ref() {
            self.rate_limit_middleware.prepare_response(response, limiter);
        }

        if let Some(auth) = ctx.auth.as_ref()
            && let Some(auth_config) = route.and_then(|r| r.auth_policy.as_deref())
        {
            self.auth_middleware.prepare_response(response, auth_config, auth);
        }

        vary.merge_into(response);
    }
}
