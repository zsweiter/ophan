mod config;
mod context;

pub use config::{AllowedOrigins, CorsConfig, OriginPattern};
pub use context::CorsContext;

use crate::gateway::OphanCtx;
use crate::middlewares::FilterAction;

use http::{HeaderValue, Method, StatusCode, header};
use ophan_net::http::vary::VarySet;
use ophan_net::proxy::{RequestParts, ResponseParts};

#[derive(Default)]
pub struct CorsMiddleware;

impl CorsMiddleware {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluates the request against the configured CORS policy.
    ///
    /// Requests outside the scope of the CORS protocol are ignored and continue
    /// through the normal request pipeline.
    ///
    /// For preflight requests, this method populates the CORS context, updates
    /// the required `Vary` headers, and returns an early `204 No Content`
    /// response.
    pub fn on_request(&self, request: &RequestParts, config: &CorsConfig, ctx: &mut OphanCtx) -> FilterAction {
        // If the request does not have Origin header, the request is outside the scope of CORS
        let Some(origin_value) = request.headers.get(header::ORIGIN) else {
            // See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches
            // Unless all origins are allowed, we include the Vary header to cache the response correctly
            if !config.allow_origins.is_allow_all() {
                // To Avoid poisoning the cache, we include the Vary header
                ctx.vary.insert(VarySet::ORIGIN);
            }

            return FilterAction::Continue;
        };

        let is_preflight = request.method == Method::OPTIONS;

        // If it's a preflight request and doesn't have Access-Control-Request-Method header, it's outside the scope of CORS
        if is_preflight && !request.headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
            // To Avoid poisoning the cache, we include the Vary header
            // for non-CORS OPTIONS requests:
            ctx.vary.insert(VarySet::ORIGIN);

            return FilterAction::Continue;
        }

        let mut cors_context = CorsContext { is_preflight, ..Default::default() };

        if config.allow_origins.matches(origin_value.as_bytes()) {
            cors_context.allow_origin = Some(origin_value.clone());

            //  Wildcard origins cannot be combined with credentials.
            // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#preflight_requests_and_credentials
            if config.allow_credentials && !config.allow_origins.is_allow_all() {
                cors_context.allow_credentials = true;
            }
        }

        // Normal request
        if !is_preflight {
            // See https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches
            if !config.allow_origins.is_allow_all() {
                ctx.vary.insert(VarySet::ORIGIN);
            }

            ctx.policies.cors = Some(cors_context);
            return FilterAction::Continue;
        }

        // Pre-flight request

        if let Some(req_hdrs) = request.headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
            cors_context.allow_headers = Some(req_hdrs.clone());
        }

        ctx.policies.cors = Some(cors_context);

        ctx.vary.insert(VarySet::ORIGIN);
        ctx.vary.insert(VarySet::ACCESS_CONTROL_REQUEST_HEADERS);
        ctx.vary.insert(VarySet::ACCESS_CONTROL_REQUEST_METHOD);

        FilterAction::EarlyResponse(StatusCode::NO_CONTENT)
    }

    /// Writes the CORS response headers for a request that matched the policy.
    ///
    /// If the request origin was not allowed, this method leaves the response
    /// unchanged.
    pub fn prepare_response(&self, response: &mut ResponseParts, config: &CorsConfig, cors: &CorsContext) {
        let Some(origin) = cors.allow_origin.as_ref() else {
            return;
        };

        let _ = response.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());

        if cors.allow_credentials {
            let _ = response.insert_header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
        }

        if let Some(ref expose) = config.allow_expose_headers {
            let _ = response.insert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }

        if cors.is_preflight {
            if let Some(ref methods) = config.allow_methods {
                let _ = response.insert_header(header::ACCESS_CONTROL_ALLOW_METHODS, methods.clone());
            }

            if let Some(ref allow_hdrs) = config.allow_headers {
                let _ = response.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_hdrs.clone());
            }

            // else if let Some(req_hdrs) = cors.allow_headers.as_ref() {
            //     let _ = response.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, req_hdrs.clone());
            // }

            if let Some(ref max_age) = config.allow_max_age {
                let _ = response.insert_header(header::ACCESS_CONTROL_MAX_AGE, max_age.clone());
            }
        }
    }
}

#[cfg(test)]
mod cors_tests {
    use super::*;
    use crate::gateway::OphanCtx;
    use http::{HeaderName, HeaderValue, Method, StatusCode, header};
    use ophan_net::proxy::RequestParts;

    fn config_allow_list(origins: &[&str]) -> CorsConfig {
        CorsConfig {
            allow_origins: AllowedOrigins::try_from(origins).unwrap(),
            ..CorsConfig::default()
        }
    }

    fn config_allow_all() -> CorsConfig {
        CorsConfig { allow_origins: AllowedOrigins::All, ..CorsConfig::default() }
    }

    fn build_request(method: Method, headers: &[(&str, &str)]) -> RequestParts {
        let mut req = RequestParts::build(method, b"/", None).unwrap();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            let value = HeaderValue::from_str(value).unwrap();
            req.insert_header(name, value).unwrap();
        }
        req
    }

    // ── on_request: no Origin header ──────────────────────────────────────

    #[test]
    fn on_request_no_origin_returns_continue() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[]);

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.policies.cors.is_none());
    }

    #[test]
    fn on_request_no_origin_adds_vary_when_not_allow_all() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[]);

        let _ = mw.on_request(&req, &config, &mut ctx);

        assert!(ctx.vary.contains(VarySet::ORIGIN));
        assert!(ctx.policies.cors.is_none());
    }

    #[test]
    fn on_request_no_origin_skips_vary_when_allow_all() {
        let mw = CorsMiddleware::new();
        let config = config_allow_all();
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[]);

        let _ = mw.on_request(&req, &config, &mut ctx);

        assert!(!ctx.vary.contains(VarySet::ORIGIN));
    }

    // ── on_request: preflight without ACRM ────────────────────────────────

    #[test]
    fn on_request_preflight_without_acrm_returns_continue() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::OPTIONS, &[("origin", "https://example.com")]);

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.vary.contains(VarySet::ORIGIN));
    }

    // ── on_request: normal requests ───────────────────────────────────────

    #[test]
    fn on_request_normal_matching_origin_sets_context() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["*.example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[("origin", "https://api.example.com")]);

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::Continue));
        let cors = ctx.policies.cors.as_ref().unwrap();
        assert!(!cors.is_preflight);
        assert_eq!(cors.allow_origin.as_ref().unwrap(), "https://api.example.com");
    }

    #[test]
    fn on_request_normal_non_matching_origin_no_allow() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[("origin", "https://evil.com")]);

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::Continue));
        let cors = ctx.policies.cors.as_ref().unwrap();
        assert!(cors.allow_origin.is_none());
    }

    #[test]
    fn on_request_normal_adds_vary_origin_when_not_allow_all() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[("origin", "https://example.com")]);

        let _ = mw.on_request(&req, &config, &mut ctx);

        assert!(ctx.vary.contains(VarySet::ORIGIN));
    }

    // ── on_request: preflight ─────────────────────────────────────────────

    #[test]
    fn on_request_preflight_matching_returns_204() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(
            Method::OPTIONS,
            &[("origin", "https://example.com"), ("access-control-request-method", "POST")],
        );

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::EarlyResponse(StatusCode::NO_CONTENT)));
        let cors = ctx.policies.cors.as_ref().unwrap();
        assert!(cors.is_preflight);
        assert!(ctx.vary.contains(VarySet::ORIGIN));
        assert!(ctx.vary.contains(VarySet::ACCESS_CONTROL_REQUEST_METHOD));
        assert!(ctx.vary.contains(VarySet::ACCESS_CONTROL_REQUEST_HEADERS));
    }

    #[test]
    fn on_request_preflight_captures_acr_headers() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(
            Method::OPTIONS,
            &[
                ("origin", "https://example.com"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "x-custom"),
            ],
        );

        let _ = mw.on_request(&req, &config, &mut ctx);

        let cors = ctx.policies.cors.as_ref().unwrap();
        assert_eq!(cors.allow_headers.as_ref().unwrap(), "x-custom");
    }

    #[test]
    fn on_request_preflight_non_matching_origin_no_allow() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let mut ctx = OphanCtx::new();
        let req = build_request(
            Method::OPTIONS,
            &[("origin", "https://evil.com"), ("access-control-request-method", "POST")],
        );

        let action = mw.on_request(&req, &config, &mut ctx);

        assert!(matches!(action, FilterAction::EarlyResponse(StatusCode::NO_CONTENT)));
        let cors = ctx.policies.cors.as_ref().unwrap();
        println!("{:?}", cors);

        assert!(cors.allow_origin.is_none());
    }

    // ── on_request: credentials ───────────────────────────────────────────

    #[test]
    fn on_request_credentials_set_when_not_wildcard() {
        let mut config = config_allow_list(&["*.example.com"]);
        config.allow_credentials = true;
        let mw = CorsMiddleware::new();
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[("origin", "https://api.example.com")]);

        let _ = mw.on_request(&req, &config, &mut ctx);

        let cors = ctx.policies.cors.as_ref().unwrap();
        assert!(cors.allow_credentials);
    }

    #[test]
    fn on_request_credentials_not_set_for_wildcard() {
        let mut config = config_allow_all();
        config.allow_credentials = true;
        let mw = CorsMiddleware::new();
        let mut ctx = OphanCtx::new();
        let req = build_request(Method::GET, &[("origin", "https://example.com")]);

        let _ = mw.on_request(&req, &config, &mut ctx);

        let cors = ctx.policies.cors.as_ref().unwrap();
        assert!(!cors.allow_credentials);
    }

    // ── prepare_response ──────────────────────────────────────────────────

    #[test]
    fn prepare_response_no_origin_does_nothing() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let cors = CorsContext::default();
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert!(resp.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[test]
    fn prepare_response_sets_allow_origin() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let cors = CorsContext {
            allow_origin: Some(HeaderValue::from_static("https://example.com")),
            ..CorsContext::default()
        };
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert_eq!(
            resp.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn prepare_response_sets_credentials() {
        let mw = CorsMiddleware::new();
        let config = config_allow_list(&["https://example.com"]);
        let cors = CorsContext {
            allow_origin: Some(HeaderValue::from_static("https://example.com")),
            allow_credentials: true,
            ..CorsContext::default()
        };
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert_eq!(resp.headers.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(), "true");
    }

    #[test]
    fn prepare_response_expose_headers() {
        let mut config = config_allow_list(&["https://example.com"]);
        config.allow_expose_headers = Some(HeaderValue::from_static("x-custom"));
        let mw = CorsMiddleware::new();
        let cors = CorsContext {
            allow_origin: Some(HeaderValue::from_static("https://example.com")),
            ..CorsContext::default()
        };
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert_eq!(resp.headers.get(header::ACCESS_CONTROL_EXPOSE_HEADERS).unwrap(), "x-custom");
    }

    #[test]
    fn prepare_response_preflight_sets_methods_headers_max_age() {
        let mut config = config_allow_list(&["https://example.com"]);
        config.allow_methods = Some(HeaderValue::from_static("GET, POST, OPTIONS"));
        config.allow_headers = Some(HeaderValue::from_static("content-type"));
        config.allow_max_age = Some(HeaderValue::from_static("86400"));
        let mw = CorsMiddleware::new();
        let cors = CorsContext {
            allow_origin: Some(HeaderValue::from_static("https://example.com")),
            is_preflight: true,
            ..CorsContext::default()
        };
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert_eq!(
            resp.headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            "GET, POST, OPTIONS"
        );
        assert_eq!(
            resp.headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "content-type"
        );
        assert_eq!(resp.headers.get(header::ACCESS_CONTROL_MAX_AGE).unwrap(), "86400");
    }

    #[test]
    fn prepare_response_non_preflight_omits_preflight_headers() {
        let mut config = config_allow_list(&["https://example.com"]);
        config.allow_methods = Some(HeaderValue::from_static("GET, POST"));
        config.allow_headers = Some(HeaderValue::from_static("content-type"));
        config.allow_max_age = Some(HeaderValue::from_static("86400"));
        let mw = CorsMiddleware::new();
        let cors = CorsContext {
            allow_origin: Some(HeaderValue::from_static("https://example.com")),
            is_preflight: false,
            ..CorsContext::default()
        };
        let mut resp = ResponseParts::build(StatusCode::OK, None).unwrap();

        mw.prepare_response(&mut resp, &config, &cors);

        assert!(resp.headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_none());
        assert!(resp.headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_none());
        assert!(resp.headers.get(header::ACCESS_CONTROL_MAX_AGE).is_none());
    }
}
