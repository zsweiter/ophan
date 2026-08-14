use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use ophan_net::http::header;
use ophan_net::http::vary::VarySet;
use ophan_net::proxy::{HttpBody, HttpResponse, Session, SessionExt};
use pingora::prelude::*;
use pingora::protocols::TcpKeepalive;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::balancer::{Backend, BackendAddr, BalancerError, LoadBalancer, Upstream};
use crate::config::{BackendTarget, GatewayConfig, StaticUpstream, UpstreamAddress, UpstreamConfig};
use crate::gateway::error::{self, ErrorKind, GatewayError, build_error_body};
use crate::logging::RequestId;
use crate::middlewares::auth::AuthMiddleware;
use crate::middlewares::cors::CorsMiddleware;
use crate::middlewares::limiter::RateLimitMiddleware;
use crate::middlewares::waf::WafEngineMiddleware;
use crate::middlewares::{FilterAction, Pipeline, PolicyContext};
use crate::state::{AppContext, HttpRoute};

use ophan_sec::NetPolicy;
use ophan_sec::l4::PacketAction;
use ophan_static::StaticService;

/// Constants to control request flow in proxy hooks.
pub struct RequestFlow;

impl RequestFlow {
    /// Signal that the request should be terminated (response already sent).
    pub const TERMINATE: bool = true;
    /// Signal that the proxy should continue to the next lifecycle phase.
    pub const CONTINUE: bool = false;
}

const EMPTY_HOST: &str = "one.one.one.one";

/// Per-request context passed through all proxy lifecycle hooks.
pub struct OphanCtx {
    pub matched_route: Option<Arc<HttpRoute>>,
    pub upstream: Option<Arc<UpstreamConfig>>,
    pub selected_backend: Option<Arc<Backend>>,
    pub client_addr: IpAddr,

    /// Per-listener network policy for real IP resolution behind proxies.
    /// Set in `early_request_filter` based on the listener's port.
    pub net_policy: Option<Arc<NetPolicy>>,

    pub policies: PolicyContext,
    pub vary: VarySet,

    // Logging and tracing
    pub request_id: RequestId,
}

impl Default for OphanCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl OphanCtx {
    pub fn new() -> Self {
        Self {
            upstream: None,
            matched_route: None,
            selected_backend: None,
            client_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            net_policy: None,
            policies: PolicyContext::default(),
            vary: VarySet::default(),

            request_id: RequestId::empty(),
        }
    }

    /// `ctx.matched_route` **must** be `Some`. If missing, it is a bug (the route
    ///   was resolved in `request_filter` and should never be cleared).
    #[inline]
    pub fn route(&self) -> Result<&Arc<HttpRoute>> {
        use crate::bug;

        self.matched_route.as_ref().ok_or_else(|| bug!(error::gateway::MISSING_ROUTE_CONTEXT))
    }
}

pub struct OphanGateway {
    pub app_context: Arc<ArcSwap<AppContext>>,
    pub load_balancer: LoadBalancer,
    pub pipeline: Pipeline,
    pub static_service: StaticService,
}

#[async_trait::async_trait]
impl pingora::proxy::ProxyHttp for OphanGateway {
    type CTX = OphanCtx;

    fn new_ctx(&self) -> Self::CTX {
        OphanCtx::new()
    }

    /// Phase 0a – Early request filtering (before route resolution).
    ///
    /// Runs per-port ACL rules and assigns the listener's `net_policy` to the
    /// context for real IP resolution behind proxies.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let Some(client_addr) = session.as_downstream().client_addr().and_then(|a| a.as_inet()) else {
            return Ok(());
        };
        let Some(listener_addr) = session.as_downstream().server_addr().and_then(|a| a.as_inet()) else {
            return Ok(());
        };

        let listener_port = listener_addr.port();
        let state = self.app_context.load();

        // Fallback until Pingora supports per-listener connection filtering. but in connection filter no have context like listener port
        if let Some(ref filter) = state.net_filter
            && filter.filter(client_addr.ip(), Some(listener_port)) == PacketAction::DROP
        {
            return Err(Error::explain(ErrorType::HTTPStatus(403), "blocked by ingress policy"));
        }

        ctx.net_policy = state.net_policies.get(&listener_port).cloned().or_else(|| state.net_policy.clone());

        Ok(())
    }

    /// Phase 0 – Entry point for every incoming request.
    ///
    /// 1. Resolves the `[HttpRoute]` via the router (host + method + path).
    /// 2. Stores `matched_route`, `backend_candidate`, and `client_addr` in ctx.
    /// 3. Runs the middleware pipeline (`pre_request`):
    ///    - On `Respond` → writes the response directly (e.g. CORS preflight).
    ///    - On `Reject`  → writes an error response via `reject`.
    ///    - On `Continue` → proceeds.
    /// 4. If the resolved backend is **static** → serves the file immediately.
    /// 5. If the resolved backend is **upstream** → returns `Ok(false)` to continue
    ///    to phase 1 (`upstream_peer`).
    ///
    /// # Invariants
    /// - After this hook, `ctx.matched_route` is always `Some`.
    /// - `ctx.client_addr` is updated from the actual downstream socket.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let request = session.as_downstream().req_header();
        let host = ophan_net::http::utils::client_host(request, false);

        ctx.request_id = match session.get_header(&header::X_REQUEST_ID) {
            None => RequestId::new_uuid(),
            Some(header) => RequestId::from(header),
        };

        let state = self.app_context.load();

        let matched = match state.router.match_route(host, &request.method, request.uri.path()) {
            Ok(m) => m,
            Err(err) => {
                let error = GatewayError::from(err.status_code());
                return self.early_reject(session, ctx, error).await;
            },
        };

        let matched_route = Arc::clone(matched.value);
        ctx.matched_route = Some(Arc::clone(&matched_route));

        if let Some(client_addr) = session.as_downstream().client_addr().and_then(|a| a.as_inet()) {
            ctx.client_addr = match ctx.net_policy.as_ref() {
                None => client_addr.ip(),
                Some(policy) => policy.get_real_ip(client_addr.ip(), &request.headers),
            }
        }

        drop(state);

        match self.pipeline.on_request(request, &matched_route, ctx).await {
            FilterAction::Continue => { /* continue */ },
            FilterAction::Reject(status) => {
                return self.early_reject(session, ctx, GatewayError::from(status)).await;
            },
            FilterAction::EarlyResponse(status) => {
                return self.early_response(session, ctx, status).await;
            },
        }

        match &matched_route.backend {
            BackendTarget::Upstream(target) => {
                ctx.upstream = Some(Arc::clone(target));
            },

            BackendTarget::Static(static_cfg) => {
                match static_cfg.as_ref() {
                    StaticUpstream::Local(serve_config) => match self.static_service.serve(serve_config, request).await {
                        Ok(response) => {
                            self.terminate_response(session, ctx, response).await?;
                        },
                        Err(error) => {
                            self.handle_error(session, ctx, GatewayError::from(error.status)).await?;
                        },
                    },
                }

                return Ok(RequestFlow::TERMINATE);
            },
        }

        Ok(RequestFlow::CONTINUE)
    }

    /// Phase 1 – Process request body chunks (upstream flows only).
    ///
    /// Called for every chunk of the request body. Only invoked when the backend
    /// is an upstream (static files are served directly in `request_filter`).
    ///
    /// # Invariants
    /// - `ctx.matched_route` **must** be `Some`. If missing, it is a bug (the route
    ///   was resolved in `request_filter` and should never be cleared).
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let route = Arc::clone(ctx.route()?);
        let request = session.as_downstream().req_header();

        self.pipeline.on_request_body(request, &route, body, end_of_stream, ctx).await;

        Ok(())
    }

    /// Phase 2 – Select upstream backend (only for upstream routes).
    ///
    /// Uses the `LoadBalancer` to pick a healthy backend based on the configured
    /// balance strategy and client IP. Returns an `[HttpPeer]` with:
    /// - The backend address (TCP, TLS, UDP or UDS).
    /// - Route-level timeouts (`connect`, `read`, `write`).
    /// - Stream/buffer configuration from the matched route.
    /// - ALPN negotiation based on the backend protocol (H2 for gRPC/HTTP2).
    ///
    /// # Invariants
    /// - `ctx.backend_candidate` **must** be `BackendTarget::Upstream`.
    /// - `ctx.matched_route` **must** be `Some` (set in `request_filter`).
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // Ensure backend candidate need upstrem
        let Some(upstream) = ctx.upstream.as_ref() else {
            return Err(Error::new_str("no upstream candidate"));
        };

        let route = Arc::clone(ctx.route()?);
        let backend = self.load_balancer.select_backend(upstream.id.0, ctx.client_addr).map_err(|e| match e {
            // !If this error triggers, the configuration has a bug that bypassed the empty upstream validation.
            BalancerError::UpstreamEmpty => Error::explain(ErrorType::Custom("UpstreamEmpty"), e.format(&upstream.name)),
            // !If this error triggers, the configuration has a bug that bypassed the upstream reference validation.
            BalancerError::UpstreamNotFound => Error::explain(ErrorType::Custom("UpstreamNotFound"), e.format(&upstream.name)),
            BalancerError::AllServersUnhealthy => Error::explain(ErrorType::HTTPStatus(503), e.format(&upstream.name)),
        })?;

        ctx.selected_backend = Some(Arc::clone(&backend));

        let mut peer = match &backend.addr {
            BackendAddr::Tcp(addr) => HttpPeer::new(addr, false, EMPTY_HOST.to_string()),
            BackendAddr::Host(addr) => HttpPeer::new(addr, addr.is_https(), addr.sni_name().to_string()),
            #[cfg(unix)]
            BackendAddr::Uds(path) => HttpPeer::new_uds(path.to_str().unwrap(), false, EMPTY_HOST.to_string())?,
        };

        peer.options.connection_timeout = Some(Duration::from_secs(3));
        peer.options.total_connection_timeout = Some(Duration::from_secs(5));
        peer.options.read_timeout = Some(Duration::from_secs(30));
        peer.options.write_timeout = Some(Duration::from_secs(30));
        peer.options.idle_timeout = Some(Duration::from_secs(60));

        peer.options.tcp_fast_open = true;
        peer.options.alpn = pingora::upstreams::peer::ALPN::H1;

        peer.options.tcp_keepalive = Some(TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(10),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(0),
        });

        // peer.options.tcp_recv_buf = Some(65536);

        if let Some(ref timeouts) = route.timeouts {
            if let Some(timeout) = timeouts.connect {
                peer.options.connection_timeout = Some(timeout);
            }
            if let Some(timeout) = timeouts.read {
                peer.options.read_timeout = Some(timeout);
            }
            if let Some(timeout) = timeouts.send {
                peer.options.write_timeout = Some(timeout);
            }
        }

        if let Some(ref streaming) = route.streaming
            && !streaming.buffering
        {
            peer.options.read_timeout = Some(Duration::from_secs(300));
            peer.options.write_timeout = Some(Duration::from_secs(300));
            peer.options.idle_timeout = Some(Duration::from_secs(300));
        }

        // Set ALPN based on upstream protocol
        if backend.protocol.is_http1() {
            peer.options.alpn = pingora::upstreams::peer::ALPN::H1;
        }

        if backend.protocol.is_http2() || backend.protocol.is_grpc() {
            peer.options.alpn = pingora::upstreams::peer::ALPN::H2;
            peer.options.max_h2_streams = 256;
        }

        if backend.protocol.allow_websocket_upgrade() {
            // For WebSocket upgrade, we must use HTTP/1.1 to support the Upgrade header.
            peer.options.alpn = pingora::upstreams::peer::ALPN::H1;

            peer.options.read_timeout = Some(Duration::from_secs(86400)); // 24h
            peer.options.write_timeout = Some(Duration::from_secs(86400));
            peer.options.idle_timeout = Some(Duration::from_secs(86400));
        }

        Ok(Box::new(peer))
    }

    /// Phase 3 – Modify upstream request before sending.
    ///
    /// Mutates the upstream `RequestHeader`:
    /// - Rewrites the `Host` header to the actual backend address.
    /// - Injects `x-user-data` with encoded JWT claims (if authenticated).
    /// - Applies URI rewrite rules from the matched route.
    ///
    /// # Invariants
    /// - `ctx.matched_route` **must** be `Some`.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let route = ctx.route()?;

        self.pipeline.on_upstream_request(upstream_request, route, &ctx.policies).await?;

        if let Some(host_addr) = ctx.selected_backend.as_ref().and_then(|b| b.host_addr.as_ref()) {
            upstream_request.insert_header(header::HOST, host_addr.host()).unwrap();
        }

        // Rewrite uri when have rewrite rules for this route
        if let Some(rewrite) = route.rewrite.as_ref() {
            let request_path = upstream_request.uri.path();

            // If the rewrite engine returns a new path, update the upstream request URI.
            if let Cow::Owned(mut rw_path) = rewrite.apply(request_path) {
                if let Some(query) = upstream_request.uri.query() {
                    rw_path.push('?');
                    rw_path.push_str(query);
                }

                let uri = http::Uri::builder().path_and_query(&rw_path).build();

                debug_assert!(uri.is_err(), "rewritten URI is invalid: {}", rw_path);

                upstream_request.set_uri(uri.unwrap());
            }
        }

        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        Ok(None)
    }

    /// Phase 6 – Modify downstream response after upstream responds.
    ///
    /// Runs the pipeline's `pre_response` (CORS response headers) and
    /// injects accumulated middleware policy headers (`CorsContext`,
    /// `RateLimitContext`, etc.) into the downstream response.
    ///
    /// # Invariants
    /// - `ctx.matched_route` **must** be `Some`.
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let route = ctx.route()?;
        let _request = session.as_downstream().req_header();

        self.pipeline.prepare_response(upstream_response, Some(route), &ctx.policies, ctx.vary);

        Ok(())
    }

    /// Error handler – called when the proxy cannot reach the upstream.
    ///
    /// Maps internal pingora errors to appropriate HTTP status codes and
    /// writes an error response via `handle_error`. Policy context headers
    /// are included in the error response.
    ///
    /// # Status mapping
    /// - `HTTPStatus` codes are propagated as-is.
    /// - `UpstreamNotFound` / `UpstreamEmpty` → 500 (configuration bug).
    /// - `AllServersUnhealthy` → 503.
    /// - Any other upstream error → 502.
    /// - Downstream read/write errors → `GATEWAY_TIMEOUT` or 400.
    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Self::CTX) -> pingora::proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let (code, error) = match e.etype() {
            // Direct HTTP Status propagation from upstream
            HTTPStatus(code) => (
                *code,
                GatewayError::from(StatusCode::from_u16(*code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)),
            ),

            // Handle specific Balancer/Custom errors with precise HTTP codes
            Custom(s) if s.starts_with("UpstreamNotFound") || s.starts_with("UpstreamEmpty") => {
                // Configuration bugs or missing routes are Internal Gateway errors
                (500, GatewayError::explain(ErrorKind::BadGateway, *s))
            },

            // Fallback to structural source matching
            _ => match e.esource() {
                ErrorSource::Upstream => {
                    match e.etype() {
                        // All servers down maps beautifully to a 503 Service Unavailable
                        HTTPStatus(503) => (
                            503,
                            GatewayError::explain(ErrorKind::ServiceUnavailable, "Backends unhealthy"),
                        ),
                        // Any other upstream connection/read/write failure is a 502 Bad Gateway
                        _ => (502, GatewayError::new(ErrorKind::BadGateway)),
                    }
                },
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => (0, GatewayError::from(StatusCode::GATEWAY_TIMEOUT)),
                    _ => (400, GatewayError::from(StatusCode::NOT_FOUND)),
                },
                ErrorSource::Internal | ErrorSource::Unset => (500, GatewayError::from(StatusCode::INTERNAL_SERVER_ERROR)),
            },
        };

        if code > 0 {
            self.handle_error(session, ctx, error).await.unwrap_or_else(|err| {
                tracing::error!("failed to send error response to downstream: {err}");
            });
        }

        pingora::proxy::FailToProxy { error_code: code, can_reuse_downstream: false }
    }

    /// Phase 7 – Final cleanup after response is fully sent or request fails.
    ///
    /// Releases the selected backend connection and records failures for
    /// health checking.
    async fn logging(&self, _session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(ref backend) = ctx.selected_backend {
            backend.release();

            match error {
                None => {},
                Some(err) => {
                    tracing::error!(error =% err);
                    backend.record_failure();
                },
            }
        };
    }
}

impl OphanGateway {
    pub fn new(app_context: Arc<ArcSwap<AppContext>>, config: &GatewayConfig) -> Self {
        let upstreams = config
            .upstreams
            .iter()
            .map(|up| {
                let backends = up.servers.iter().map(|a| {
                    let mut backend = match a.address {
                        UpstreamAddress::Tcp(addr) => Backend::from_tcp(addr, a.weight),
                        UpstreamAddress::Host(ref addr) => Backend::from_host(addr, a.weight),

                        #[cfg(unix)]
                        UpstreamAddress::Uds(ref addr) => Backend::from_uds(PathBuf::from(addr), a.weight),
                    };

                    backend.set_protocol(a.protocol.clone());

                    Arc::new(backend)
                });

                let backends = backends.collect::<Vec<Arc<Backend>>>();

                Upstream::new(up.id.0, up.name.clone(), backends, up.balance_strategy)
            })
            .collect::<Vec<Upstream>>();

        let load_balancer = LoadBalancer::new(upstreams);

        Self {
            app_context,
            load_balancer,
            pipeline: Pipeline::new(
                AuthMiddleware::new(),
                RateLimitMiddleware::new(),
                WafEngineMiddleware::new(),
                CorsMiddleware::new(),
            ),
            static_service: StaticService::new(2048, Duration::from_secs(15)),
        }
    }
}

impl OphanGateway {
    pub async fn handle_error(&self, session: &mut Session, ctx: &OphanCtx, error: GatewayError) -> Result<(), pingora::BError> {
        let accept = session.get_header(header::ACCEPT).map(|a| a.as_bytes());

        let (status, body, content_type) = build_error_body(&error, accept, &ctx.request_id);

        let response = HttpResponse::with_capacity(status, 4)
            .with_header(header::CONTENT_TYPE, content_type)
            .with_header(header::CONTENT_LENGTH, HeaderValue::from(body.len()))
            .with_header(header::X_REQUEST_ID, ctx.request_id.as_header_value())
            .with_body(HttpBody::Bytes(body));

        self.terminate_response(session, ctx, response).await
    }

    #[inline]
    async fn terminate_response(&self, session: &mut Session, ctx: &OphanCtx, response: HttpResponse) -> Result<()> {
        let (mut header, body) = response.into_parts();
        let route = ctx.matched_route.as_deref();

        self.pipeline.prepare_response(&mut header, route, &ctx.policies, ctx.vary);

        session.write_response(header, body).await
    }

    // AUto reject helpers
    /// Writes an error response and terminates the request.
    #[inline(always)]
    async fn early_reject(&self, session: &mut Session, ctx: &OphanCtx, err: GatewayError) -> Result<bool> {
        self.handle_error(session, ctx, err).await?;
        Ok(RequestFlow::TERMINATE)
    }

    // Auto reject helpers
    /// Writes an normal response and terminates the request.
    #[inline(always)]
    async fn early_response(&self, session: &mut Session, ctx: &OphanCtx, status: StatusCode) -> Result<bool> {
        let response = HttpResponse::with_capacity(status, 2)
            .with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"))
            .with_header(header::X_REQUEST_ID, ctx.request_id.as_header_value());

        self.terminate_response(session, ctx, response).await?;

        Ok(RequestFlow::TERMINATE)
    }
}
