use crate::config::CorsConfig;
use crate::gateway::OphanCtx;
use crate::middlewares::RequestOutcome;
use http::{HeaderValue, Method, Response, header, request::Parts as RequestParts, response::Parts as ResponseParts};
use pingora::ErrorType;

#[derive(Default)]
pub struct CorsMiddleware;

impl CorsMiddleware {
    pub fn new() -> Self {
        Self
    }

    pub fn on_request(&self, request: &RequestParts, ctx: &mut OphanCtx) -> Result<RequestOutcome, pingora::BError> {
        let cors = match ctx.matched_route.as_ref() {
            Some(cfg) => match cfg.cors_policy.as_deref() {
                Some(policy) => policy,
                None => return Ok(RequestOutcome::Continue),
            },
            None => return Ok(RequestOutcome::Continue),
        };

        if let Some(ref matched) = ctx.matched_route
            && matched.cors_excludes.contains(request.uri.path())
        {
            return Ok(RequestOutcome::Continue);
        }

        let origin = request.headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());

        let Some(origin) = origin else {
            return Ok(RequestOutcome::Continue);
        };

        if !is_origin_allowed(origin, cors) {
            return Ok(RequestOutcome::Continue);
        }

        let is_preflight =
            request.method == Method::OPTIONS && request.headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

        if is_preflight {
            let allows_any = cors.allow_origins.iter().any(|o| o == "*");
            let allow_origin_value = if allows_any && !cors.allow_credentials { "*" } else { origin };

            let mut builder = Response::builder()
                .status(204)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin_value)
                .header(header::VARY, "Origin");

            if !cors.allow_methods.is_empty() {
                builder = builder.header(header::ACCESS_CONTROL_ALLOW_METHODS, cors.allow_methods.join(", "));
            }
            if !cors.allow_headers.is_empty() {
                builder = builder.header(header::ACCESS_CONTROL_ALLOW_HEADERS, cors.allow_headers.join(", "));
            }
            if cors.allow_credentials {
                builder = builder.header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            }
            if let Some(max_age) = cors.max_age {
                builder = builder.header(header::ACCESS_CONTROL_MAX_AGE, max_age.to_string());
            }
            if !cors.expose_headers.is_empty() {
                builder = builder.header(header::ACCESS_CONTROL_EXPOSE_HEADERS, cors.expose_headers.join(", "));
            }

            let resp = builder
                .body(None)
                .map_err(|e| pingora::Error::because(ErrorType::InternalError, "b failed after a", e))?;

            return Ok(RequestOutcome::Respond(resp));
        }

        Ok(RequestOutcome::Continue)
    }

    pub async fn on_response(
        &self,
        request: &RequestParts,
        response: &mut ResponseParts,
        ctx: &mut OphanCtx,
    ) -> Result<(), pingora::BError> {
        let cors = match ctx.matched_route.as_ref() {
            Some(cfg) => match cfg.cors_policy.as_deref() {
                Some(policy) => policy,
                None => return Ok(()),
            },
            None => return Ok(()),
        };

        if let Some(ref matched) = ctx.matched_route
            && matched.cors_excludes.contains(request.uri.path())
        {
            return Ok(());
        }

        let origin = request.headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());

        let Some(origin) = origin else {
            return Ok(());
        };

        if !is_origin_allowed(origin, cors) {
            return Ok(());
        }

        let allows_any = cors.allow_origins.iter().any(|o| o == "*");
        let allow_origin_value = if allows_any && !cors.allow_credentials { "*" } else { origin };

        let origin_val = HeaderValue::from_str(allow_origin_value)
            .map_err(|e| pingora::Error::because(pingora::ErrorType::HTTPStatus(400), "Invalid Origin header value", e))?;

        response.headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_val);
        response.headers.insert(header::VARY, HeaderValue::from_static(header::ORIGIN.as_str()));

        if cors.allow_credentials && !allows_any {
            response.headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
        }

        if !cors.expose_headers.is_empty() {
            let expose_val = HeaderValue::from_str(&cors.expose_headers.join(", "))
                .map_err(|e| pingora::Error::because(pingora::ErrorType::HTTPStatus(400), "Invalid Expose-Headers value", e))?;
            response.headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose_val);
        }

        Ok(())
    }
}

fn is_origin_allowed(origin: &str, cors: &CorsConfig) -> bool {
    cors.allow_origins.iter().any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(origin))
}
