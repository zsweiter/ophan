pub mod auth;
pub mod cors;
pub mod exclude;
pub mod limiter;
pub mod waf;

use crate::{
    gateway::{GatewayError, OphanCtx},
    middlewares::{auth::AuthMiddleware, cors::CorsMiddleware, limiter::RateLimitMiddleware, waf::WafEngineMiddleware},
};
use bytes::Bytes;
use http::{Response, request::Parts as RequestParts, response::Parts as ResponseParts};

pub enum RequestOutcome {
    Continue,
    Respond(Response<Option<Bytes>>),
    Reject(GatewayError),
}

macro_rules! execute_stage {
    ($expr:expr) => {
        match $expr? {
            RequestOutcome::Continue => { /* continue */ },
            outcome => return Ok(outcome),
        }
    };
}

pub struct Pipeline {
    auth_middleware: AuthMiddleware,            // stage 4
    rate_limit_middleware: RateLimitMiddleware, // stage 3
    waf_middleware: WafEngineMiddleware,        // stage 2
    cors_middleware: CorsMiddleware,            // stage 1
}

impl Pipeline {
    pub fn new(auth: AuthMiddleware, rate_limit: RateLimitMiddleware, waf: WafEngineMiddleware, cors: CorsMiddleware) -> Self {
        Self {
            auth_middleware: auth,             // stage 4
            rate_limit_middleware: rate_limit, // stage 3
            waf_middleware: waf,               // stage 2
            cors_middleware: cors,
        }
    }

    pub async fn pre_request(&self, request: &RequestParts, ctx: &mut OphanCtx) -> Result<RequestOutcome, pingora::BError> {
        execute_stage!(self.cors_middleware.on_request(request, ctx));

        if ctx.enabled_waf {
            execute_stage!(self.waf_middleware.on_request(request, ctx));
        }

        execute_stage!(self.rate_limit_middleware.on_request(request, ctx));

        execute_stage!(self.auth_middleware.on_request(request, ctx).await);

        Ok(RequestOutcome::Continue)
    }

    pub async fn pre_response(
        &self,
        request: &RequestParts,
        response: &mut ResponseParts,
        ctx: &mut OphanCtx,
    ) -> Result<(), pingora::BError> {
        self.cors_middleware.on_response(request, response, ctx).await?;

        // if ctx.enabled_waf {
        //     execute_stage!(self.waf_middleware.on_request(request, ctx));
        // }

        // execute_stage!(self.rate_limit_middleware.on_request(request, ctx));

        // execute_stage!(self.auth_middleware.on_request(request, ctx).await);

        Ok(())
    }
}
