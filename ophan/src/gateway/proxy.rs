use bytes::Bytes;
use pingora::http::RequestHeader;
use pingora::prelude::*;
use pingora::proxy::{FailToProxy, ProxyHttp};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{
    BackendTarget, BalanceStrategy, Http2Mode, NetworkProtocol, NetworkTransport, OphanConfig, StaticUpstream, UpstreamConfig,
};
use crate::gateway::app_ctx::CompiledRoute;
use crate::gateway::balancer::{Backend, LoadBalancer};
use crate::gateway::errors::GatewayError;
use crate::gateway::utils::{StackString, get_real_client_ip};
use crate::middlewares::auth::AuthMiddleware;
use crate::middlewares::cors::CorsMiddleware;
use crate::middlewares::limiter::{RateLimitMiddleware, RateLimiter};
use crate::middlewares::waf::WafEngineMiddleware;
use crate::middlewares::{Pipeline, RequestOutcome};
use crate::state::AppState;

use ophan_auth::{AuthService, Claims, JwksManager, JwtConfig, JwtValidator, OAuth2Client};
use ophan_net::proxy::Session;
use ophan_static::FileServer;

pub enum BackendCandidate {
    Upstream(Arc<UpstreamConfig>),
    Static(Arc<StaticUpstream>),
}

pub struct RequestFlow;

impl RequestFlow {
    pub const TERMINATE: bool = true;
    pub const CONTINUE: bool = false;
}

const EMPTY_HOST: &str = "one.one.one.one";

pub struct OphanCtx {
    pub backend_candidate: Option<BackendCandidate>,
    pub matched_route: Option<Arc<CompiledRoute>>,
    pub jwt_claims: Option<Claims>,
    pub refreshed_token: Option<String>,
    pub selected_backend: Option<(StackString, StackString)>,
    pub enabled_waf: bool,
}

pub struct OphanGateway {
    pub app_state: Arc<AppState>,
    pub load_balancer: LoadBalancer,
    pub pipeline: Pipeline,
    pub file_server: FileServer,
}

#[async_trait::async_trait]
impl ProxyHttp for OphanGateway {
    type CTX = OphanCtx;

    fn new_ctx(&self) -> Self::CTX {
        OphanCtx {
            backend_candidate: None,
            matched_route: None,
            jwt_claims: None,
            refreshed_token: None,
            selected_backend: None,
            enabled_waf: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let request_headers = session.as_downstream().req_header();
        let request_path = request_headers.uri.path();
        let request_host = request_headers.headers.get("Host").and_then(|v| v.to_str().ok());
        let request_method = request_headers.method.as_str();

        let state = self.app_state.context.load();

        let matched = match state.router.find_route(request_host, request_method, request_path) {
            Ok(m) => m,
            Err(_) => return self.reject(session, ctx, GatewayError::NotFound).await,
        };

        let matched = Arc::clone(matched.value);

        if !matched.methods.contains_str(request_method) {
            drop(state);
            return self.reject(session, ctx, GatewayError::MethodNotAllowed).await;
        }

        match &matched.backend {
            BackendTarget::Upstream(name) => {
                let candidate = state.upstreams.get(name).cloned();
                ctx.backend_candidate = candidate.map(BackendCandidate::Upstream);
            },
            BackendTarget::Static(cfg) => {
                ctx.backend_candidate = Some(BackendCandidate::Static(cfg.clone()));
            },
        }

        if ctx.backend_candidate.is_none() {
            return self.reject(session, ctx, GatewayError::BadGateway("no backend configured".into())).await;
        }

        drop(state);

        ctx.matched_route = Some(matched);

        let outcome = {
            let request = session.as_downstream().req_header().as_ref();
            self.pipeline.pre_request(request, ctx).await?
        };

        match outcome {
            RequestOutcome::Respond(resp) => {
                let status = resp.status().as_u16();
                let mut header = pingora::http::ResponseHeader::build(status, None)?;

                for (name, value) in resp.headers().iter() {
                    let _ = header.append_header(name, value);
                }

                session.write_response_header(Box::new(header), true).await?;
                return Ok(RequestFlow::TERMINATE);
            },
            RequestOutcome::Reject(err) => {
                return self.reject(session, ctx, err).await;
            },
            RequestOutcome::Continue => {},
        }

        // Static file handling
        if let Some(BackendCandidate::Static(ref static_cfg)) = ctx.backend_candidate {
            match static_cfg.as_ref() {
                StaticUpstream::Local { path, .. } => {
                    let request = session.as_downstream().req_header().as_ref();
                    let path_buf = PathBuf::from(path);
                    let config = ophan_static::ServeConfig::new(path_buf);

                    match self.file_server.handle_request(request, request_path, config) {
                        Ok(response) => {
                            let mut header = pingora::http::ResponseHeader::build(200, None)?;

                            for (name, value) in response.headers().iter() {
                                let _ = header.append_header(name, value);
                            }

                            let body = response.into_body();

                            session.write_response_header(Box::new(header), body.is_empty()).await?;
                            if body.is_empty() {
                                session.write_response_body(Some(body), true).await?;
                            }

                            return Ok(RequestFlow::TERMINATE);
                        },
                        Err(status) => {
                            return self.reject(session, ctx, GatewayError::from(status)).await;
                        },
                    };
                },
                StaticUpstream::Cdn { .. } => {
                    return self.reject(session, ctx, GatewayError::InternalServerError("CDN not implemented".into())).await;
                },
            }
        }

        Ok(RequestFlow::CONTINUE)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if !ctx.enabled_waf {
            return Ok(());
        }

        Ok(())
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let Some(BackendCandidate::Upstream(upstream)) = ctx.backend_candidate.as_ref() else {
            tracing::error!("no upstream candidate for backend selection");
            return Err(Error::new_str("no upstream candidate"));
        };

        if upstream.servers.is_empty() {
            tracing::error!("upstream '{}' has no servers", upstream.name);
            return Err(Error::new_str("no servers configured"));
        }

        let client_ip = if matches!(upstream.balance_strategy, BalanceStrategy::IpHash) {
            let addr = session.as_downstream().client_addr().and_then(|a| a.as_inet());
            get_real_client_ip(&session.as_downstream().req_header().headers, addr)
        } else {
            None
        };

        let backend = self
            .load_balancer
            .select_server(&upstream.name, &upstream.balance_strategy, client_ip.as_deref())
            .ok_or_else(|| {
                tracing::error!("no healthy server available in upstream '{}'", upstream.name);
                Error::new_str("no healthy servers")
            })?;

        ctx.selected_backend = Some((StackString::new(&upstream.name), StackString::new(&backend.addr)));

        let mut peer = match &backend.transport {
            NetworkTransport::Tcp(addr) => HttpPeer::new(addr, false, EMPTY_HOST.to_string()),
            NetworkTransport::Uds(path) => HttpPeer::new_uds(path.as_str(), false, EMPTY_HOST.to_string())?,
        };

        if let Some(ref route_match) = ctx.matched_route {
            if let Some(ref timeouts) = route_match.timeouts {
                peer.options.connection_timeout = timeouts.connect;
                peer.options.read_timeout = timeouts.read;
                peer.options.write_timeout = timeouts.send;
            }
            if let Some(ref streaming) = route_match.streaming {
                if !streaming.buffering {
                    peer.options.read_timeout = None;
                }
                if !streaming.chunked {}
            }
        }

        // Set ALPN based on upstream protocol
        match &backend.protocol {
            NetworkProtocol::Http2 { mode: Http2Mode::Grpc } => {
                peer.options.alpn = pingora::upstreams::peer::ALPN::H2;
                peer.options.max_h2_streams = 256;
            },
            NetworkProtocol::Http2 { .. } => {
                peer.options.alpn = pingora::upstreams::peer::ALPN::H2;
            },
            NetworkProtocol::Http1 { .. } => {},
        }

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(ref claims) = ctx.jwt_claims {
            upstream_request.append_header(
                "x-user-data",
                claims.encode().map_err(|_| Error::new_str("failed to insert x-content"))?,
            )?;
        }

        if let Some(ref matched) = ctx.matched_route {
            if !matched.can_rewrite() {
                return Ok(());
            }

            let request_path = upstream_request.uri.path();
            let rw_path = matched.apply_rewrite(request_path);

            if rw_path != request_path {
                let uri = rw_path.as_ref().parse::<http::Uri>().map_err(|_| Error::new_str("failed to parse rewritten URI"))?;
                upstream_request.set_uri(uri);
            }
        }

        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if !ctx.enabled_waf {
            return Ok(());
        }

        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if !ctx.enabled_waf {
            return Ok(None);
        }

        Ok(None)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let request = session.as_downstream().req_header().as_ref();
        let response = &mut upstream_response.as_owned_parts();

        self.pipeline.pre_response(request, response, ctx).await?;

        let Some(ref matched) = ctx.matched_route else {
            return Ok(());
        };

        if !matched.prepend_headers.is_empty() {
            matched.prepend_headers.iter().for_each(|name| {
                upstream_response.remove_header(name);
            });
        }

        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some((upstream_name, addr)) = ctx.selected_backend.take() {
            self.load_balancer.release_conn(&upstream_name, &addr);
        }
    }

    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Self::CTX) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        tracing::error!("proxy error: {:?}", e);
        let (code, error) = match e.etype() {
            HTTPStatus(code) => (*code, GatewayError::InternalServerError("".into())),
            _ => match e.esource() {
                ErrorSource::Upstream => (502, GatewayError::BadGateway("".into())),
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => (0, GatewayError::GatewayTimeout),
                    _ => (400, GatewayError::NotFound),
                },
                ErrorSource::Internal | ErrorSource::Unset => (500, GatewayError::InternalServerError("".into())),
            },
        };
        if code > 0 {
            let cors = ctx.matched_route.as_ref().and_then(|r| r.cors_policy.as_ref());
            GatewayError::write_to_session(session, error, cors).await.unwrap_or_else(|e| {
                tracing::error!("failed to send error response to downstream: {e}");
            });
        }

        FailToProxy { error_code: code, can_reuse_downstream: false }
    }
}

impl OphanGateway {
    pub fn new(app_state: Arc<AppState>, config: &OphanConfig) -> Self {
        let load_balancer = LoadBalancer::new();

        for upstream in &config.upstreams {
            let backends: Vec<Arc<Backend>> = upstream
                .servers
                .iter()
                .map(|s| Arc::new(Backend::new(s.address.clone(), s.transport.clone(), s.protocol.clone())))
                .collect();
            load_balancer.add_upstream(upstream.name.clone(), backends);
        }

        let auth_middleware = {
            let validator = JwtValidator::new(JwtConfig::default());
            let svc = Arc::new(AuthService::new(validator, OAuth2Client::new(), JwksManager::new()));
            AuthMiddleware::new(svc)
        };

        let rate_limiter = Arc::new(RateLimiter::new());

        Self {
            app_state,
            load_balancer,
            pipeline: Pipeline::new(
                auth_middleware,
                RateLimitMiddleware::new(rate_limiter),
                WafEngineMiddleware::new(),
                CorsMiddleware::new(),
            ),
            file_server: FileServer::default(),
        }
    }

    async fn reject(&self, session: &mut Session, ctx: &OphanCtx, err: GatewayError) -> Result<bool> {
        let cors = ctx.matched_route.as_ref().and_then(|r| r.cors_policy.as_ref());

        GatewayError::write_to_session(session, err, cors).await?;
        Ok(RequestFlow::TERMINATE)
    }
}
