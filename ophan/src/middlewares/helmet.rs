use http::{HeaderName, HeaderValue};
use ophan_net::http::header;
use ophan_net::proxy::ResponseParts;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HelmetTarget {
    Api,
    #[default]
    Web,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HelmetLevel {
    /// No security headers are added. only necesary
    Disabled,

    /// Recommended configuration for most applications.
    #[default]
    Standard,

    /// Stricter configuration. May break compatibility with
    /// applications that load third-party resources.
    Strict,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HelmetConfig {
    pub target: HelmetTarget,
    pub level: HelmetLevel,
}

impl std::str::FromStr for HelmetTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "web" => Ok(Self::Web),
            "api" => Ok(Self::Api),
            other => Err(format!("unknown helmet target '{other}', expected \"web\" or \"api\"")),
        }
    }
}

impl std::str::FromStr for HelmetLevel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "standard" => Ok(Self::Standard),
            "strict" => Ok(Self::Strict),
            "disabled" | "off" => Ok(Self::Disabled),
            other => Err(format!(
                "unknown helmet level '{other}', expected \"standard\", \"strict\" or \"disabled\""
            )),
        }
    }
}

impl HelmetConfig {
    pub const fn new(target: HelmetTarget, level: HelmetLevel) -> Self {
        Self { target, level }
    }

    /// This configuration with the `target` and `level` that are set replaced.
    pub fn with_overrides(self, target: Option<&str>, level: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            target: target.map(str::parse).transpose()?.unwrap_or(self.target),
            level: level.map(str::parse).transpose()?.unwrap_or(self.level),
        })
    }

    #[inline(always)]
    pub fn is_disabled(&self) -> bool {
        matches!(self.level, HelmetLevel::Disabled)
    }

    #[inline(always)]
    pub const fn is_web(&self) -> bool {
        matches!(self.target, HelmetTarget::Web)
    }
}

/// Prevents browsers from guessing/sniffing the MIME type of a response away from what is declared.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>
const CONTENT_TYPE_NOSNIFF: &str = "nosniff";

/// Controls whether the site can be embedded inside iframes to mitigate Clickjacking attacks.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options>
const FRAME_SAMEORIGIN: &str = "SAMEORIGIN";
const FRAME_DENY: &str = "DENY";

/// Limits how much path metadata is leaked in the `Referer` header during outbound navigation.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer-Policy>
const REFERRER_STRICT_ORIGIN: &str = "strict-origin-when-cross-origin";
const REFERRER_NO_REFERRER: &str = "no-referrer";

/// Isolates the browsing context entirely from other tabs/windows to mitigate side-channel leaks (Spectre).
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy>
const COOP_SAME_ORIGIN: &str = "same-origin";

/// Defines which external origins are allowed to embed or read the assets served by this backend.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy>
const CORP_SAME_ORIGIN: &str = "same-origin";

/// Advises the browser to allocate a dedicated, isolated OS process cluster for this origin.
/// @see <https://html.spec.whatwg.org/multipage/origin.html#origin-keyed-agent-clusters>
const OAC_ENABLED: &str = "?1";

/// Disables stealth background DNS pre-fetching for links on the page to enhance user privacy.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control>
const DNS_PREFETCH_OFF: &str = "off";

/// Forces cross-origin resources to explicitly grant loading permission via CORS or CORP.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy>
const COEP_REQUIRE_CORP: &str = "require-corp";

#[derive(Debug)]
pub struct Helmet;

impl Default for Helmet {
    fn default() -> Self {
        Self::new()
    }
}

impl Helmet {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluates the existing response headers (`Parts`) and inserts
    /// only the security headers that are missing, avoiding overriding
    /// route-level settings.
    /// Adds the security headers the upstream did not set.
    ///
    /// Every response gets `X-Content-Type-Options` and `Cross-Origin-Resource-Policy`.
    /// Documents a browser renders (HTML, XHTML, SVG) also get the framing, referrer and
    /// cross-origin isolation headers, which have no effect on other content types.
    pub fn prepare_response(&self, config: HelmetConfig, response: &mut ResponseParts) {
        push_if_missing(
            response,
            header::X_CONTENT_TYPE_OPTIONS,
            header::wire::X_CONTENT_TYPE_OPTIONS,
            CONTENT_TYPE_NOSNIFF,
        );

        if config.is_disabled() {
            return;
        }

        push_if_missing(
            response,
            header::CROSS_ORIGIN_RESOURCE_POLICY,
            header::wire::CROSS_ORIGIN_RESOURCE_POLICY,
            CORP_SAME_ORIGIN,
        );

        let strict = matches!(config.level, HelmetLevel::Strict);

        if !config.is_web() {
            if strict {
                push_if_missing(
                    response,
                    header::REFERRER_POLICY,
                    header::wire::REFERRER_POLICY,
                    REFERRER_NO_REFERRER,
                );
            }
            return;
        }

        if !Self::is_document(response) {
            return;
        }

        push_if_missing(
            response,
            header::CROSS_ORIGIN_OPENER_POLICY,
            header::wire::CROSS_ORIGIN_OPENER_POLICY,
            COOP_SAME_ORIGIN,
        );
        push_if_missing(
            response,
            header::ORIGIN_AGENT_CLUSTER,
            header::wire::ORIGIN_AGENT_CLUSTER,
            OAC_ENABLED,
        );
        push_if_missing(
            response,
            header::X_DNS_PREFETCH_CONTROL,
            header::wire::X_DNS_PREFETCH_CONTROL,
            DNS_PREFETCH_OFF,
        );
        push_if_missing(
            response,
            header::X_FRAME_OPTIONS,
            header::wire::X_FRAME_OPTIONS,
            if strict { FRAME_DENY } else { FRAME_SAMEORIGIN },
        );
        push_if_missing(
            response,
            header::REFERRER_POLICY,
            header::wire::REFERRER_POLICY,
            if strict {
                REFERRER_NO_REFERRER
            } else {
                REFERRER_STRICT_ORIGIN
            },
        );

        if strict {
            push_if_missing(
                response,
                header::CROSS_ORIGIN_EMBEDDER_POLICY,
                header::wire::CROSS_ORIGIN_EMBEDDER_POLICY,
                COEP_REQUIRE_CORP,
            );
        }
    }

    /// Whether the response is a document a browser renders.
    fn is_document(response: &ResponseParts) -> bool {
        let Some(content_type) = response.headers.get(header::CONTENT_TYPE) else {
            return false;
        };

        let media_type = content_type.as_bytes().split(|b| *b == b';').next().unwrap_or_default().trim_ascii();

        [b"text/html".as_slice(), b"application/xhtml+xml", b"image/svg+xml"]
            .iter()
            .any(|t| media_type.eq_ignore_ascii_case(t))
    }
}

#[inline]
fn push_if_missing(response: &mut ResponseParts, name: HeaderName, wire: &'static str, value: &'static str) {
    if !response.headers.contains_key(&name) {
        let _ = response.insert_header(wire, HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(content_type: Option<&'static str>) -> ResponseParts {
        let mut res = ResponseParts::build(200, None).unwrap();
        if let Some(ct) = content_type {
            res.insert_header(header::CONTENT_TYPE, ct).unwrap();
        }
        res
    }

    fn names(res: &ResponseParts) -> Vec<String> {
        let mut names: Vec<String> = res.headers.keys().map(|k| k.as_str().to_string()).collect();
        names.sort();
        names
    }

    #[test]
    fn api_responses_get_only_content_headers() {
        let mut res = response(Some("application/json"));
        Helmet::new().prepare_response(HelmetConfig::default(), &mut res);

        assert_eq!(
            names(&res),
            ["content-type", "cross-origin-resource-policy", "x-content-type-options"]
        );
    }

    #[test]
    fn html_documents_get_the_full_set() {
        let mut res = response(Some("text/html; charset=utf-8"));
        Helmet::new().prepare_response(HelmetConfig::default(), &mut res);

        for name in ["x-frame-options", "referrer-policy", "cross-origin-opener-policy", "origin-agent-cluster"] {
            assert!(res.headers.contains_key(name), "missing {name}");
        }
        for obsolete in ["x-xss-protection", "x-download-options", "x-permitted-cross-domain-policies"] {
            assert!(!res.headers.contains_key(obsolete), "unexpected {obsolete}");
        }
    }

    #[test]
    fn upstream_values_are_kept() {
        let mut res = response(Some("text/html"));
        res.insert_header(header::X_FRAME_OPTIONS, "ALLOW-FROM https://a.example").unwrap();
        Helmet::new().prepare_response(HelmetConfig::default(), &mut res);

        assert_eq!(
            res.headers.get(header::X_FRAME_OPTIONS).unwrap(),
            "ALLOW-FROM https://a.example"
        );
    }

    #[test]
    fn disabled_keeps_nosniff_only() {
        let mut res = response(Some("text/html"));
        Helmet::new().prepare_response(HelmetConfig::new(HelmetTarget::Web, HelmetLevel::Disabled), &mut res);

        assert_eq!(names(&res), ["content-type", "x-content-type-options"]);
    }
}
