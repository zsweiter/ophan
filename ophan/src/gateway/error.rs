use std::{borrow::Cow, error::Error as StdError};

use bytes::{Bytes, BytesMut};
use http::{HeaderValue, StatusCode};
use ophan_net::http::header;
use std::fmt::Write as _;

pub type BoxError = Box<dyn StdError + Send + Sync>;

#[derive(Debug)]
pub struct GatewayError {
    pub kind: ErrorKind,
    pub message: Option<Cow<'static, str>>,
    pub source: Option<BoxError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    TooManyRequests,
    PayloadTooLarge,
    UnsupportedMediaType,

    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,

    InternalServerError,
}

impl From<ErrorKind> for StatusCode {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::BadRequest => StatusCode::BAD_REQUEST,
            ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorKind::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,

            ErrorKind::BadGateway => StatusCode::BAD_GATEWAY,
            ErrorKind::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorKind::GatewayTimeout => StatusCode::GATEWAY_TIMEOUT,

            ErrorKind::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<StatusCode> for ErrorKind {
    fn from(value: StatusCode) -> Self {
        match value {
            StatusCode::BAD_REQUEST => ErrorKind::BadRequest,
            StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
            StatusCode::FORBIDDEN => ErrorKind::Forbidden,
            StatusCode::NOT_FOUND => ErrorKind::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => ErrorKind::MethodNotAllowed,
            StatusCode::CONFLICT => ErrorKind::Conflict,
            StatusCode::TOO_MANY_REQUESTS => ErrorKind::TooManyRequests,
            StatusCode::PAYLOAD_TOO_LARGE => ErrorKind::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => ErrorKind::UnsupportedMediaType,

            StatusCode::BAD_GATEWAY => ErrorKind::BadGateway,
            StatusCode::SERVICE_UNAVAILABLE => ErrorKind::ServiceUnavailable,
            StatusCode::GATEWAY_TIMEOUT => ErrorKind::GatewayTimeout,

            StatusCode::INTERNAL_SERVER_ERROR => ErrorKind::InternalServerError,
            _ => ErrorKind::InternalServerError,
        }
    }
}

impl ErrorKind {
    pub const fn default_message(&self) -> &'static str {
        match self {
            Self::BadRequest => "Bad request",
            Self::Unauthorized => "Authentication required",
            Self::Forbidden => "Access denied",
            Self::NotFound => "The requested resource was not found",
            Self::MethodNotAllowed => "HTTP method not allowed",
            Self::Conflict => "Conflict",
            Self::TooManyRequests => "Rate limit exceeded",
            Self::PayloadTooLarge => "Payload too large",
            Self::UnsupportedMediaType => "Unsupported media type",
            Self::BadGateway => "Bad gateway",
            Self::ServiceUnavailable => "Service unavailable",
            Self::GatewayTimeout => "Upstream server timeout",
            Self::InternalServerError => "Internal server error",
        }
    }
}

impl GatewayError {
    #[inline]
    pub fn new(kind: ErrorKind) -> Self {
        Self { kind, message: None, source: None }
    }

    pub fn message(&self) -> Cow<'static, str> {
        self.message.clone().unwrap_or_else(|| Cow::Borrowed(self.kind.default_message()))
    }

    pub fn explain(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(Cow::Owned(message.into())),
            source: None,
        }
    }
}

impl From<StatusCode> for GatewayError {
    fn from(value: StatusCode) -> Self {
        GatewayError::new(value.into())
    }
}

pub fn build_error_body(error: &GatewayError, accept: Option<&[u8]>, request_id: &str) -> (StatusCode, Bytes, HeaderValue) {
    let status: StatusCode = error.kind.into();

    let error_name = status.canonical_reason().unwrap_or("Unknow error");
    let error_message = error.message();

    let wants_json = accept.is_some_and(|accept| memchr::memmem::find(accept, b"application/json").is_some());

    let dynamic_metadata_len = 4 + error_message.len() + error_name.len() + request_id.len();
    let (content_type, body) = match wants_json {
        true => {
            let mut buf = BytesMut::with_capacity(60 + dynamic_metadata_len);

            write!(
                buf,
                r#"{{"status_code":{},"message":"{}","error":"{}","request_id":"{}"}}"#,
                status.as_u16(),
                error_message,
                error_name,
                request_id
            )
            .unwrap();

            (header::CONTENT_TYPE_JSON.clone(), Bytes::from(buf))
        },
        // Otherwise send HTML
        false => {
            let mut buf = BytesMut::with_capacity(1718 + dynamic_metadata_len);
            write!(
                    buf,
                    r#"<!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>{status_code} {error_name}</title>
                        <style>
                            html {{
                                height: 100%;
                                width: 100%;
                                background-image: linear-gradient(324deg, transparent 0%, transparent 45%,rgba(186, 186, 186,0.04) 45%, rgba(186, 186, 186,0.04) 47%,transparent 47%, transparent 100%),linear-gradient(208deg, transparent 0%, transparent 40%,rgba(186, 186, 186,0.04) 40%, rgba(186, 186, 186,0.04) 80%,transparent 80%, transparent 100%),linear-gradient(202deg, transparent 0%, transparent 20%,rgba(186, 186, 186,0.04) 20%, rgba(186, 186, 186,0.04) 40%,transparent 40%, transparent 100%),linear-gradient(338deg, transparent 0%, transparent 10%,rgba(186, 186, 186,0.04) 10%, rgba(186, 186, 186,0.04) 72%,transparent 72%, transparent 100%),linear-gradient(90deg, rgb(0,0,0),rgb(0,0,0));
                            }}

                            body {{
                                font-family: sans-serif;
                                color: #ebeef1;
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                height: 100vh;
                                margin: 0;
                            }}

                            .card {{
                                background: #1a1b1c;
                                padding: 32px;
                                border-radius: 12px;
                                width: 480px;
                            }}

                            h1 {{
                                margin: 0;
                                font-size: 32px;
                            }}

                            p {{
                                color: #9ea9b9;
                            }}

                            code {{
                                color: #38bdf8;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="card">
                            <h1>{status_code} {error_name}</h1>
                            <p>{message}</p>
                            <p>Request ID: <code>{request_id}</code></p>
                        </div>
                    </body>
                    </html>"#,
                    status_code = status.as_u16(),
                    error_name = error_name,
                    message = error_message,
                    request_id = request_id
                )
                .unwrap();

            (header::CONTENT_TYPE_HTML.clone(), Bytes::from(buf))
        },
    };

    (status, body, content_type)
}

#[allow(dead_code)]
pub mod gateway {
    pub const MISSING_ROUTE_CONTEXT: &str = "GW-0001";
    pub const MISSING_BACKEND_CONTEXT: &str = "GW-0002";
    pub const INVALID_REQUEST_STATE: &str = "GW-0003";
    pub const DOUBLE_RESPONSE: &str = "GW-0004";
}

#[allow(dead_code)]
pub mod proxy {
    pub const UPSTREAM_NOT_SELECTED: &str = "PX-0001";
    pub const UPSTREAM_CONNECTION_FAILED: &str = "PX-0002";
    pub const INVALID_REWRITE: &str = "PX-0003";
    pub const INVALID_UPSTREAM_RESPONSE: &str = "PX-0004";
}

#[allow(dead_code)]
pub mod auth {
    pub const MISSING_JWT_CONTEXT: &str = "AU-0001";
    pub const INVALID_AUTH_STATE: &str = "AU-0002";
    pub const JWKS_REFRESH_FAILED: &str = "AU-0003";
}

#[allow(dead_code)]
pub mod cors {
    pub const INVALID_POLICY: &str = "CO-0001";
    pub const INVALID_PREFLIGHT: &str = "CO-0002";
}

#[allow(dead_code)]
pub mod limiter {
    pub const COUNTER_OVERFLOW: &str = "RL-0001";
    pub const STORAGE_FAILURE: &str = "RL-0002";
}

#[allow(dead_code)]
pub mod waf {
    pub const ENGINE_FAILURE: &str = "WF-0001";
    pub const RULESET_CORRUPTED: &str = "WF-0002";
}

#[allow(dead_code)]
pub mod config {
    pub const ROUTER_INCONSISTENT: &str = "CF-0001";
    pub const UPSTREAM_NOT_FOUND: &str = "CF-0002";
    pub const EMPTY_UPSTREAM: &str = "CF-0003";
}

pub fn description(code: &str) -> &'static str {
    match code {
        "GW-0001" => "Matched route missing from request context.",
        "GW-0002" => "Selected backend missing from request context.",
        "GW-0003" => "Gateway request lifecycle invariant violated.",
        "GW-0004" => "Response generated more than once.",
        _ => "Unknown internal error.",
    }
}

#[macro_export]
macro_rules! bug {
    ($code:expr) => {{
        tracing::error!(
            code = $code,
            file = file!(),
            line = line!(),
            module = module_path!(),
            "BUG: {}",
            $crate::gateway::error::description($code)
        );

        ::pingora::Error::explain(
            ::pingora::ErrorType::InternalError,
            format!(
                "BUG[{}] {}",
                $code,
                $crate::gateway::error::description($code)
            ),
        )
    }};

    ($code:expr, $($arg:tt)+) => {{
        tracing::error!(
            code = $code,
            file = file!(),
            line = line!(),
            module = module_path!(),
            "BUG: {}",
            format!($($arg)+)
        );

        ::pingora::Error::explain(
            ::pingora::ErrorType::InternalError,
            format!(
                "BUG[{}] {} ({})",
                $code,
                $crate::gateway::error::description($code),
                format!($($arg)+)
            ),
        )
    }};
}
