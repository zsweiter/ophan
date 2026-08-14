use http::HeaderValue;

#[derive(Debug, Default)]
pub struct CorsContext {
    /// Whether the request is a CORS preflight (OPTIONS) request.
    pub is_preflight: bool,

    /// Value for `Access-Control-Allow-Origin`. If value is Some is cors request
    pub allow_origin: Option<HeaderValue>,

    /// Value for `Access-Control-Allow-Headers`.
    ///
    /// Present only when the response should reflect the request's
    /// `Access-Control-Request-Headers` header.
    pub allow_headers: Option<HeaderValue>,

    /// Whether `Access-Control-Allow-Credentials: true` should be emitted.
    /// Ignore when allow_origins is wildcard
    /// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#preflight_requests_and_credentials
    pub allow_credentials: bool,
}
