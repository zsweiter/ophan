mod context;

pub use context::WafContext;

use ophan_net::proxy::RequestParts;
use ophan_sec::l7::{WafConfig, WafEngine};

use crate::{gateway::OphanCtx, middlewares::FilterAction};

#[derive(Default)]
pub struct WafEngineMiddleware {
    pub engine: WafEngine,
}

impl WafEngineMiddleware {
    pub fn new() -> Self {
        Self { engine: WafEngine::default() }
    }

    pub fn on_request(&self, _request: &RequestParts, _config: &WafConfig, _ctx: &mut OphanCtx) -> FilterAction {
        FilterAction::Continue
    }

    pub fn filter_request_body(
        &self,
        _request: &RequestParts,
        _body: &[u8],
        _config: &WafConfig,
        _ctx: &mut OphanCtx,
    ) -> FilterAction {
        FilterAction::Continue
    }

    pub fn filter_response_headers(&self, _request: &RequestParts, _config: &WafConfig, _ctx: &mut OphanCtx) -> FilterAction {
        FilterAction::Continue
    }

    pub fn filter_response_body(
        &self,
        _request: &RequestParts,
        _body: &[u8],
        _config: &WafConfig,
        _ctx: &mut OphanCtx,
    ) -> FilterAction {
        FilterAction::Continue
    }
}
