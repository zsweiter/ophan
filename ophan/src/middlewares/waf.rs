use http::request::Parts as RequestParts;

use crate::gateway::GatewayError;
use crate::gateway::OphanCtx;
use crate::middlewares::RequestOutcome;
use ophan_waf::config::{WafConfig, WafPhase};
use ophan_waf::{WafEngine, WafResult};

#[derive(Default)]
pub struct WafEngineMiddleware {
    engine: WafEngine,
}

impl WafEngineMiddleware {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_waf_config(ctx: &OphanCtx) -> Option<&WafConfig> {
        ctx.matched_route.as_ref().and_then(|cfg| cfg.waf_policy.as_deref())
    }

    pub fn on_request(&self, request: &RequestParts, ctx: &mut OphanCtx) -> Result<RequestOutcome, pingora::BError> {
        let Some(waf) = Self::get_waf_config(ctx) else {
            return Ok(RequestOutcome::Continue);
        };

        if !waf.enabled {
            return Ok(RequestOutcome::Continue);
        }

        if let Some(ref matched) = ctx.matched_route
            && matched.waf_excludes.contains(request.uri.path())
        {
            return Ok(RequestOutcome::Continue);
        }

        let result = self.engine.inspect(waf, WafPhase::RequestHeaders, request, &[]);

        if let WafResult::Action(_, reason) = result {
            tracing::warn!("WAF blocked: {}", reason);
            return Ok(RequestOutcome::Reject(GatewayError::Forbidden));
        }

        Ok(RequestOutcome::Continue)
    }
}
