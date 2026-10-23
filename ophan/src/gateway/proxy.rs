use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use ophan_net::http::header;
use ophan_net::http::vary::VarySet;
use ophan_net::proxy::{HttpBody, HttpResponse, ResponseParts, Session, SessionExt};
use pingora::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::balancer::{Backend, BalancerError};
use crate::config::{BackendTarget, GatewayConfig, StaticUpstream};
use crate::gateway::error::{self, ErrorKind, GatewayError, build_error_body};
use crate::gateway::forwarding::Forwarding;
use crate::logging::RequestId;
use crate::metrics::GatewayMetrics;
use crate::middlewares::auth::AuthMiddleware;
use crate::middlewares::cors::CorsMiddleware;
use crate::middlewares::limiter::RateLimitMiddleware;
use crate::middlewares::waf::WafEngineMiddleware;
use crate::middlewares::{FilterAction, Pipeline, PolicyContext};
use crate::state::{AppContext, HttpRoute};

use ophan_sec::ClientAddress;
use ophan_static::StaticService;

/// Constants to control request flow in proxy hooks.
pub struct RequestFlow;

impl RequestFlow {
    /// Signal that the request should be terminated (response already sent).
    pub const TERMINATE: bool = true;
    /// Signal that the proxy should continue to the next lifecycle phase.
    pub const CONTINUE: bool = false;
}

/// Downstream keep-alive when the listener does not configure one.
const DEFAULT_KEEPALIVE_SECS: u64 = 60;

/// Per-request context passed through all proxy lifecycle hooks.
pub struct OphanCtx {
    /// Context snapshot taken when the request arrived. Every phase uses it, so a
    /// concurrent hot reload never mixes routes and upstreams from two configs.
    pub app: Option<Arc<AppContext>>,
    pub matched_route: Option<Arc<HttpRoute>>,
    pub selected_backend: Option<Arc<Backend>>,
    /// Original client address (see `trusted_proxies`).
    pub client_addr: IpAddr,
    /// Socket address of the peer; `None` on Unix socket listeners.
    pub peer: Option<IpAddr>,
    /// Whether the peer is a trusted proxy whose forwarding headers are kept.
    pub peer_trusted: bool,

    pub policies: PolicyContext,
    pub vary: VarySet,

    pub request_body_bytes: u64,
    pub max_request_size: Option<u64>,
    /// Scheme the client used: TLS on our listener, or `X-Forwarded-Proto` from a trusted proxy.
    pub scheme: &'static str,

    // Logging and tracing
    pub request_id: RequestId,
    pub started_at: Instant,
}

impl Default for OphanCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl OphanCtx {
    pub fn new() -> Self {
        Self {
            app: None,
            matched_route: None,
            selected_backend: None,
            client_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            peer: None,
            peer_trusted: false,
            policies: PolicyContext::default(),
            vary: VarySet::default(),
            request_body_bytes: 0,
            max_request_size: None,
            scheme: "http",

            request_id: RequestId::empty(),
            started_at: Instant::now(),
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
    pub pipeline: Pipeline,
    pub static_service: StaticService,
    pub metrics: GatewayMetrics,
}

#[async_trait::async_trait]
impl pingora::proxy::ProxyHttp for OphanGateway {
    type CTX = OphanCtx;

    fn new_ctx(&self) -> Self::CTX {
        OphanCtx::new()
    }

    /// Phase 0a – Early request filtering (before route resolution).
    ///
    /// Everything that depends on the connection, once per request: takes the context
    /// snapshot, finds the listener, applies its access rules, resolves the client address
    /// and scheme, applies keep-alive, idle timeout and request size, and normalizes the path.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let app = self.app_context.load_full();
        let listener = app.listeners.lookup(session.as_downstream().server_addr());

        let tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
        let peer = session.as_downstream().client_addr().and_then(|a| a.as_inet()).map(|a| a.ip().to_canonical());

        // Access rules apply to plaintext TCP here: TLS connections were checked before the
        // handshake and Unix sockets have no peer address.
        if !tls
            && let Some(peer) = peer
            && !listener.admits(peer)
        {
            return Err(Error::explain(
                ErrorType::HTTPStatus(403),
                "connection rejected by listener access rules",
            ));
        }

        let headers = &session.req_header().headers;

        ctx.client_addr = match listener.client_address(peer, headers) {
            ClientAddress::Resolved(ip) => ip,
            ClientAddress::MissingHeader => {
                return Err(Error::explain(
                    ErrorType::HTTPStatus(400),
                    "missing or invalid client address header",
                ));
            },
        };
        ctx.scheme = listener.client_scheme(tls, peer, headers);
        ctx.peer_trusted = listener.trusts(peer);
        ctx.peer = peer;

        let keepalive = listener.keepalive.map_or(DEFAULT_KEEPALIVE_SECS, |d| d.as_secs());
        session.set_keepalive(Some(keepalive));

        if let Some(idle) = listener.idle {
            session.as_downstream_mut().set_read_timeout(Some(idle));
            session.as_downstream_mut().set_write_timeout(Some(idle));
        }

        if let Some(limit) = listener.max_request_size {
            let declared = session
                .get_header(header::CONTENT_LENGTH)
                .and_then(|v| std::str::from_utf8(v.as_bytes().trim_ascii()).ok())
                .and_then(|v| v.parse::<u64>().ok());

            if declared.is_some_and(|len| len > limit) {
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    "request body exceeds the listener limit",
                ));
            }
        }

        let header = session.req_header();
        if let Some(path) = ophan_net::http::utils::normalize_path(header.uri.path()) {
            let mut path_and_query = path;
            if let Some(query) = header.uri.query() {
                path_and_query.push('?');
                path_and_query.push_str(query);
            }

            let mut parts = header.uri.clone().into_parts();
            parts.path_and_query = Some(
                http::uri::PathAndQuery::try_from(path_and_query)
                    .map_err(|e| Error::because(ErrorType::HTTPStatus(400), "invalid request path", e))?,
            );

            let uri =
                http::Uri::from_parts(parts).map_err(|e| Error::because(ErrorType::HTTPStatus(400), "invalid request URI", e))?;
            session.req_header_mut().set_uri(uri);
        }

        ctx.max_request_size = listener.max_request_size;
        ctx.app = Some(app);

        Ok(())
    }

    /// Phase 0 – Entry point for every incoming request.
    ///
    /// 1. Resolves the `[HttpRoute]` via the router (host + method + path).
    /// 2. Stores `matched_route` in ctx once the middleware pipeline ran.
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
        ctx.request_id = session
            .get_header(&header::X_REQUEST_ID)
            .and_then(RequestId::from_client)
            .unwrap_or_else(RequestId::new_uuid);

        let Some(app) = ctx.app.as_ref() else {
            return Err(Error::new_str("no application context"));
        };

        let request = session.as_downstream().req_header();
        let host = ophan_net::http::utils::client_host(request, false);

        let route = match app.router.match_route(host, &request.method, request.uri.path()) {
            Ok(matched) => Arc::clone(matched.value),
            Err(err) => {
                let error = GatewayError::from(err.status_code());
                return Box::pin(self.early_reject(session, ctx, error)).await;
            },
        };

        if let Some(headers) = route.headers.as_ref() {
            headers.apply_to_client_request(session.req_header_mut());
        }

        let request = session.as_downstream().req_header();
        let action = self.pipeline.on_request(request, &route, ctx).await;
        ctx.matched_route = Some(route);
        let route = ctx.route()?;

        match action {
            FilterAction::Continue => { /* continue */ },
            FilterAction::Reject(status) => {
                self.count_rejection(ctx, status);
                return Box::pin(self.early_reject(session, ctx, GatewayError::from(status))).await;
            },
            FilterAction::EarlyResponse(status) => {
                return Box::pin(self.early_response(session, ctx, status)).await;
            },
        }

        match &route.backend {
            BackendTarget::Upstream(_) => {},

            BackendTarget::Static(static_cfg) => {
                Box::pin(self.serve_static(session, ctx, static_cfg)).await?;
                return Ok(RequestFlow::TERMINATE);
            },
        }

        Ok(RequestFlow::CONTINUE)
    }

    /// Phase 1 – Process request body chunks (upstream flows only).
    ///
    /// Enforces the listener body size limit and runs the body policies.
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
        if let Some(chunk) = body.as_ref() {
            ctx.request_body_bytes += chunk.len() as u64;

            if ctx.max_request_size.is_some_and(|limit| ctx.request_body_bytes > limit) {
                return Err(Error::explain(HTTPStatus(413), "request body exceeds the listener limit"));
            }
        }

        if ctx.policies.waf.is_none() {
            return Ok(());
        }

        // `Pipeline::on_request_body` takes `&mut OphanCtx` plus `&HttpRoute`, so the
        // route must be cloned out of `ctx` first (only reached when a WAF policy is
        // configured for this route).
        let route = Arc::clone(ctx.route()?);
        let request = session.as_downstream().req_header();

        match self.pipeline.on_request_body(request, &route, body, end_of_stream, ctx).await {
            FilterAction::Continue => Ok(()),
            FilterAction::Reject(status) | FilterAction::EarlyResponse(status) => {
                Err(Error::explain(HTTPStatus(status.as_u16()), "request body rejected by policy"))
            },
        }
    }

    /// Phase 2 – Select upstream backend (only for upstream routes).
    ///
    /// Picks a backend with the configured balance strategy and returns its peer with
    /// the route timeouts applied. On a retry the previous backend is released and
    /// charged with the failure before another one is selected.
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        if let Some(previous) = ctx.selected_backend.take() {
            previous.release();
            previous.record_failure();
        }

        let (Some(route), Some(app)) = (ctx.matched_route.as_deref(), ctx.app.as_deref()) else {
            return Err(Error::new_str("no upstream candidate"));
        };
        let BackendTarget::Upstream(upstream) = &route.backend else {
            return Err(Error::new_str("no upstream candidate"));
        };

        let backend = app.load_balancer.select_backend(upstream.id.0, ctx.client_addr).map_err(|e| match e {
            // !If this error triggers, the configuration has a bug that bypassed the empty upstream validation.
            BalancerError::UpstreamEmpty => Error::explain(ErrorType::Custom("UpstreamEmpty"), e.format(&upstream.name)),
            // !If this error triggers, the configuration has a bug that bypassed the upstream reference validation.
            BalancerError::UpstreamNotFound => Error::explain(ErrorType::Custom("UpstreamNotFound"), e.format(&upstream.name)),
            BalancerError::AllServersUnhealthy => Error::explain(ErrorType::HTTPStatus(503), e.format(&upstream.name)),
        })?;

        ctx.selected_backend = Some(Arc::clone(&backend));

        let mut peer = backend.peer().await?;
        let websocket = backend.protocol.allow_websocket_upgrade();

        if !websocket
            && let Some(ref streaming) = route.streaming
            && !streaming.buffering
        {
            peer.options.read_timeout = Some(Duration::from_secs(300));
            peer.options.write_timeout = Some(Duration::from_secs(300));
        }

        if let Some(ref timeouts) = route.timeouts {
            if let Some(timeout) = timeouts.connect {
                peer.options.connection_timeout = Some(timeout);
                peer.options.total_connection_timeout = peer.options.total_connection_timeout.map(|total| total.max(timeout));
            }

            // WebSocket connections keep their long-lived read and write timeouts.
            if !websocket {
                if let Some(timeout) = timeouts.read {
                    peer.options.read_timeout = Some(timeout);
                }
                if let Some(timeout) = timeouts.send {
                    peer.options.write_timeout = Some(timeout);
                }
            }
        }

        Ok(Box::new(peer))
    }

    /// A failed connect is retried on another backend when the request can be replayed.
    fn fail_to_connect(&self, session: &mut Session, _peer: &HttpPeer, _ctx: &mut Self::CTX, mut e: Box<Error>) -> Box<Error> {
        if session.req_header().method.is_idempotent() {
            e.set_retry(true);
        }

        e
    }

    /// Phase 3 – Modify upstream request before sending.
    ///
    /// Mutates the upstream `RequestHeader`:
    /// - Rewrites the `Host` header to the actual backend address.
    /// - Sets the forwarding headers and the request id.
    /// - Injects `x-user-claims` with encoded JWT claims (if authenticated).
    /// - Applies the route header mutations and URI rewrite rules.
    ///
    /// # Invariants
    /// - `ctx.matched_route` **must** be `Some`.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let route = ctx.route()?;

        self.pipeline.on_upstream_request(upstream_request, route, &ctx.policies).await?;

        Forwarding {
            peer: ctx.peer,
            peer_trusted: ctx.peer_trusted,
            client: ctx.client_addr,
            scheme: ctx.scheme,
            host: session.req_header().headers.get(header::HOST),
        }
        .apply(upstream_request)?;

        if let Some(host) = ctx.selected_backend.as_ref().and_then(|b| b.host_header.as_ref()) {
            upstream_request.insert_header(header::HOST, host.clone())?;
        }

        upstream_request.insert_header(header::wire::X_REQUEST_ID, ctx.request_id.as_header_value().clone())?;

        if let Some(headers) = route.headers.as_ref() {
            headers.apply_to_upstream_request(upstream_request)?;
        }

        // Rewrite uri when have rewrite rules for this route
        if let Some(rewrite) = route.rewrite.as_ref()
            && let Some(uri) = rewrite
                .rewrite_uri(&upstream_request.uri)
                .map_err(|e| Error::because(ErrorType::InternalError, "rewritten URI is invalid", e))?
        {
            upstream_request.set_uri(uri);
        }

        Ok(())
    }

    /// Phase 5 – Applies the route `from_upstream` header rules to the upstream response.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(headers) = ctx.matched_route.as_ref().and_then(|r| r.headers.as_ref()) {
            headers.apply_to_upstream_response(upstream_response)?;
        }

        Ok(())
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
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let route = ctx.route()?;

        self.pipeline.prepare_response(upstream_response, Some(route), &ctx.policies, ctx.vary);
        Self::finish_response(upstream_response, ctx);

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
    /// - Upstream timeouts → 504, any other upstream error → 502.
    /// - Downstream read timeout → 408, a closed connection → nothing is sent,
    ///   any other downstream error → 400.
    ///
    /// Nothing is written when the response has already started.
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

            // Configuration bugs or missing routes are Internal Gateway errors
            Custom(s) if s.starts_with("UpstreamNotFound") || s.starts_with("UpstreamEmpty") => {
                (500, GatewayError::explain(ErrorKind::InternalServerError, *s))
            },

            _ => match e.esource() {
                ErrorSource::Upstream => match e.etype() {
                    ConnectTimedout | ReadTimedout | WriteTimedout => (504, GatewayError::new(ErrorKind::GatewayTimeout)),
                    _ => (502, GatewayError::new(ErrorKind::BadGateway)),
                },
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => (0, GatewayError::new(ErrorKind::BadRequest)),
                    ReadTimedout => (408, GatewayError::from(StatusCode::REQUEST_TIMEOUT)),
                    _ => (400, GatewayError::new(ErrorKind::BadRequest)),
                },
                ErrorSource::Internal | ErrorSource::Unset => (500, GatewayError::new(ErrorKind::InternalServerError)),
            },
        };

        let response_started = session.response_written().is_some();

        let can_reuse = code > 0 && !response_started && session.as_downstream_mut().is_body_done();
        if !can_reuse {
            session.set_keepalive(None);
        }

        if code > 0 && !response_started {
            self.handle_error(session, ctx, error).await.unwrap_or_else(|err| {
                tracing::error!("failed to send error response to downstream: {err}");
            });
        }

        pingora::proxy::FailToProxy { error_code: code, can_reuse_downstream: can_reuse }
    }

    /// Phase 7 – Final cleanup after response is fully sent or request fails.
    ///
    /// Releases the selected backend, charges upstream errors to it for health
    /// accounting and records the request metrics.
    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(ref backend) = ctx.selected_backend {
            backend.release();

            if error.is_some_and(|e| *e.esource() == ErrorSource::Upstream) {
                backend.record_failure();
            }
        };

        let status = session.response_written().map(|r| r.status);
        let route = ctx.matched_route.as_deref().map(|r| &r.metrics);

        self.metrics.observe(route, &session.req_header().method, status, ctx.started_at.elapsed());
    }
}

impl OphanGateway {
    pub fn new(app_context: Arc<ArcSwap<AppContext>>, config: &GatewayConfig) -> Self {
        Self {
            app_context,
            pipeline: Pipeline::new(
                AuthMiddleware::new(),
                RateLimitMiddleware::new(),
                WafEngineMiddleware::new(),
                CorsMiddleware::new(),
            ),
            static_service: StaticService::new(2048, Duration::from_secs(15)),
            metrics: GatewayMetrics::new(&config.name),
        }
    }

    /// Request id and route `outbound_headers` rules, applied to every response we send.
    fn finish_response(response: &mut ResponseParts, ctx: &OphanCtx) {
        let _ = response.insert_header(header::wire::X_REQUEST_ID, ctx.request_id.as_header_value().clone());

        if let Some(headers) = ctx.matched_route.as_ref().and_then(|r| r.headers.as_ref()) {
            headers.apply_to_client_response(response);
        }
    }

    fn count_rejection(&self, ctx: &OphanCtx, status: StatusCode) {
        let counter = if ctx.policies.limiter.as_ref().is_some_and(|l| l.limited) {
            &self.metrics.rejected_rate_limit
        } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            &self.metrics.rejected_auth
        } else {
            &self.metrics.rejected_other
        };

        counter.inc();
    }
}

impl OphanGateway {
    pub async fn handle_error(&self, session: &mut Session, ctx: &OphanCtx, error: GatewayError) -> Result<(), pingora::BError> {
        if session.response_written().is_some() {
            return Ok(());
        }

        let accept = session.get_header(header::ACCEPT).map(|a| a.as_bytes());

        let (status, body, content_type) = build_error_body(&error, accept, &ctx.request_id);

        let mut response = HttpResponse::with_capacity(status, 4)
            .with_header(header::CONTENT_TYPE, content_type)
            .with_header(header::CONTENT_LENGTH, HeaderValue::from(body.len()))
            .with_body(HttpBody::Bytes(body));

        if status == StatusCode::TOO_MANY_REQUESTS
            && let Some(limiter) = ctx.policies.limiter.as_ref()
        {
            response = response.with_header(header::RETRY_AFTER, HeaderValue::from(limiter.reset_at.0.max(1)));
        }

        self.terminate_response(session, ctx, response).await
    }

    async fn terminate_response(&self, session: &mut Session, ctx: &OphanCtx, response: HttpResponse) -> Result<()> {
        let (mut header, body) = response.into_parts();
        let route = ctx.matched_route.as_deref();

        self.pipeline.prepare_response(&mut header, route, &ctx.policies, ctx.vary);
        Self::finish_response(&mut header, ctx);

        session.write_response(header, body).await
    }

    async fn serve_static(&self, session: &mut Session, ctx: &OphanCtx, upstream: &StaticUpstream) -> Result<()> {
        match upstream {
            StaticUpstream::Local(serve_config) => match self.static_service.serve(serve_config, session.req_header()).await {
                Ok(response) => self.terminate_response(session, ctx, response).await,
                Err(error) => self.handle_error(session, ctx, GatewayError::from(error.status)).await,
            },
        }
    }

    /// Writes an error response and terminates the request.
    async fn early_reject(&self, session: &mut Session, ctx: &OphanCtx, err: GatewayError) -> Result<bool> {
        self.handle_error(session, ctx, err).await?;
        Ok(RequestFlow::TERMINATE)
    }

    /// Writes an empty response and terminates the request.
    async fn early_response(&self, session: &mut Session, ctx: &OphanCtx, status: StatusCode) -> Result<bool> {
        let mut response = HttpResponse::with_capacity(status, 2);

        if status != StatusCode::NO_CONTENT && status != StatusCode::NOT_MODIFIED {
            response = response.with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        }

        self.terminate_response(session, ctx, response).await?;

        Ok(RequestFlow::TERMINATE)
    }
}
