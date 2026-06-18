use bytes::Bytes;
use http::{
    StatusCode,
    header::{self, HeaderValue},
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::{borrow::Cow, sync::Arc};
use uuid::Uuid;

use crate::config::CorsConfig;

#[allow(dead_code)]
#[derive(Debug)]
pub enum GatewayError {
    // 4xx
    BadRequest(Cow<'static, str>),
    Unauthorized(Cow<'static, str>),
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict(Cow<'static, str>),
    TooManyRequests,
    PayloadTooLarge,
    UnsupportedMediaType,

    // Gateway / upstream
    BadGateway(Cow<'static, str>),
    ServiceUnavailable(Cow<'static, str>),
    GatewayTimeout,

    // 5xx
    InternalServerError(Cow<'static, str>),
}

impl From<StatusCode> for GatewayError {
    #[inline]
    fn from(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => GatewayError::BadRequest(Cow::Borrowed("Bad Request")),
            StatusCode::UNAUTHORIZED => GatewayError::Unauthorized(Cow::Borrowed("Unauthorized")),
            StatusCode::FORBIDDEN => GatewayError::Forbidden,
            StatusCode::NOT_FOUND => GatewayError::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => GatewayError::MethodNotAllowed,
            StatusCode::CONFLICT => GatewayError::Conflict(Cow::Borrowed("Conflict")),
            StatusCode::TOO_MANY_REQUESTS => GatewayError::TooManyRequests,
            StatusCode::PAYLOAD_TOO_LARGE => GatewayError::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => GatewayError::UnsupportedMediaType,

            StatusCode::BAD_GATEWAY => GatewayError::BadGateway(Cow::Borrowed("Bad Gateway")),
            StatusCode::SERVICE_UNAVAILABLE => GatewayError::ServiceUnavailable(Cow::Borrowed("Service Unavailable")),
            StatusCode::GATEWAY_TIMEOUT => GatewayError::GatewayTimeout,

            _ => GatewayError::InternalServerError(Cow::Borrowed("Internal Server Error")),
        }
    }
}

pub struct ErrorResponse {
    pub status_code: u16,
    pub error: &'static str,
    pub message: String,
    pub request_id: String,
}

const ERROR_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{0} {1}</title>
    <style>
        html {
            height: 100%;
            width: 100%;
            background-image: linear-gradient(324deg, transparent 0%, transparent 45%,rgba(186, 186, 186,0.04) 45%, rgba(186, 186, 186,0.04) 47%,transparent 47%, transparent 100%),linear-gradient(208deg, transparent 0%, transparent 40%,rgba(186, 186, 186,0.04) 40%, rgba(186, 186, 186,0.04) 80%,transparent 80%, transparent 100%),linear-gradient(202deg, transparent 0%, transparent 20%,rgba(186, 186, 186,0.04) 20%, rgba(186, 186, 186,0.04) 40%,transparent 40%, transparent 100%),linear-gradient(338deg, transparent 0%, transparent 10%,rgba(186, 186, 186,0.04) 10%, rgba(186, 186, 186,0.04) 72%,transparent 72%, transparent 100%),linear-gradient(90deg, rgb(0,0,0),rgb(0,0,0));
        }

        body {
            font-family: sans-serif;
            color: #ebeef1;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }

        .card {
            background: #1a1b1c;
            padding: 32px;
            border-radius: 12px;
            width: 480px;
        }

        h1 {
            margin: 0;
            font-size: 32px;
        }

        p {
            color: #9ea9b9;
        }

        code {
            color: #38bdf8;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>{0} {1}</h1>
        <p>{2}</p>
        <p>Request ID: <code>{3}</code></p>
    </div>
</body>
</html>"#;

impl GatewayError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,

            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::GatewayTimeout => StatusCode::GATEWAY_TIMEOUT,

            Self::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_name(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "Bad Request",
            Self::Unauthorized(_) => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::Conflict(_) => "Conflict",
            Self::TooManyRequests => "Too Many Requests",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UnsupportedMediaType => "Unsupported Media Type",

            Self::BadGateway(_) => "Bad Gateway",
            Self::ServiceUnavailable(_) => "Service Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",

            Self::InternalServerError(_) => "Internal Server Error",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(msg)
            | Self::Conflict(msg)
            | Self::BadGateway(msg)
            | Self::ServiceUnavailable(msg)
            | Self::InternalServerError(msg) => msg.to_string(),

            Self::Unauthorized(msg) => {
                if msg.is_empty() {
                    msg.to_string()
                } else {
                    "Authentication required".into()
                }
            },
            Self::Forbidden => "Access denied".into(),
            Self::NotFound => "The requested resource was not found".into(),
            Self::MethodNotAllowed => "HTTP method not allowed".into(),
            Self::TooManyRequests => "Rate limit exceeded".into(),
            Self::PayloadTooLarge => "Payload too large".into(),
            Self::UnsupportedMediaType => "Unsupported media type".into(),
            Self::GatewayTimeout => "Upstream server timeout".into(),
        }
    }

    pub async fn write_to_session(
        session: &mut Session,
        error: GatewayError,
        cors: Option<&Arc<CorsConfig>>,
    ) -> pingora::Result<()> {
        let accept = session.req_header().headers.get("accept").and_then(|v| v.to_str().ok());
        let status = error.status_code();

        let request_id: Cow<'_, str> = match session.req_header().headers.get("x-request-id") {
            Some(value) => value.to_str().map_or_else(|_| Cow::Owned(Uuid::new_v4().to_string()), Cow::Borrowed),
            None => Cow::Owned(Uuid::new_v4().to_string()),
        };

        let response = ErrorResponse {
            status_code: status.as_u16(),
            message: error.message(),
            error: error.error_name(),
            request_id: request_id.to_string(),
        };

        let mut response_header = ResponseHeader::build(status.as_u16(), None)?;
        if let Ok(req_id_val) = HeaderValue::from_str(&request_id) {
            response_header.insert_header("x-request-id", req_id_val)?;
        }

        let origin = session.req_header().headers.get("origin").and_then(|v| v.to_str().ok());

        let (content_type, body) = match accept {
            // send JSON if client accepts it
            Some(accept) if accept.contains("application/json") => {
                let body = format!(
                    "{{\"status_code\":{},\"message\":\"{}\",\"error\":\"{}\",\"request_id\":\"{}\"}}\n",
                    response.status_code, response.message, response.error, response.request_id
                )
                .into_bytes();

                ("application/json", body)
            },
            // Otherwise send HTML
            _ => {
                let body = ERROR_TEMPLATE
                    .replace("{0}", &response.status_code.to_string())
                    .replace("{1}", response.error)
                    .replace("{2}", &response.message)
                    .replace("{3}", &response.request_id);

                ("text/html; charset=utf-8", body.into_bytes())
            },
        };

        let _ = response_header.insert_header(header::CONTENT_LENGTH, body.len());
        let _ = response_header.insert_header(header::CONTENT_TYPE, HeaderValue::from_static(content_type));

        // Inject CORS headers when origin is present and allowed
        if let (Some(origin), Some(cors)) = (origin, cors)
            && cors.allow_origins.iter().any(|a| a == "*" || a.eq_ignore_ascii_case(origin))
        {
            Self::inject_cors(origin, &mut response_header, cors);
        }

        session.write_response_header(Box::new(response_header), false).await?;
        session.write_response_body(Some(Bytes::from(body)), true).await?;
        Ok(())
    }

    fn inject_cors(origin: &str, resp: &mut ResponseHeader, cors: &CorsConfig) {
        let allows_any = cors.allow_origins.iter().any(|o| o == "*");
        let allow_origin_value = if allows_any && !cors.allow_credentials { "*" } else { origin };
        let _ = resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin_value);
        let _ = resp.insert_header(header::VARY, "Origin");

        if cors.allow_credentials && !allows_any {
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true").unwrap();
        }

        if !cors.expose_headers.is_empty() {
            let _ = resp.insert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, cors.expose_headers.join(", "));
        }
    }
}
