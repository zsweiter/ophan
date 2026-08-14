use http::{HeaderName, HeaderValue};
use ophan_net::http::header;
use ophan_net::proxy::ResponseParts;

#[derive(Debug, Clone, Copy, Default)]
pub enum HelmetTarget {
    Api,
    #[default]
    Web,
}

#[derive(Debug, Clone, Copy, Default)]
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

#[derive(Debug, Clone, Copy, Default)]
pub struct HelmetConfig {
    pub target: HelmetTarget,
    pub level: HelmetLevel,
}

impl HelmetConfig {
    pub const fn new(target: HelmetTarget, level: HelmetLevel) -> Self {
        Self { target, level }
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

/// Disables the legacy buggy browser XSS auditor to prevent side-channel exploits.
/// @see <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection>
const XSS_PROTECTION: &str = "0";

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

/// Restricts Adobe Flash and PDF web clients from loading unauthorized cross-domain policy files.
/// @see <https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies>
const PERMITTED_CROSS_DOMAIN_NONE: &str = "none";

/// Legacy header for IE8+ that blocks running downloads directly in the site context.
/// @see <https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/dd565647(v=vs.85)>
const DOWNLOAD_NOOPEN: &str = "noopen";

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
    pub fn prepare_response(&self, config: HelmetConfig, response: &mut ResponseParts) {
        // ---------------------------------------------------------------------
        // NON-NEGOTIABLE SECURITY BASELINE (Always Enforcement)
        // These headers address systemic protocol/browser vulnerabilities and
        // MUST NEVER be disabled or overridden by route-level configs.
        // Only replace or remove via outbound_headers rules, explicit
        // ---------------------------------------------------------------------
        push_if_missing(response, header::X_CONTENT_TYPE_OPTIONS, CONTENT_TYPE_NOSNIFF);
        push_if_missing(response, header::X_XSS_PROTECTION, XSS_PROTECTION);
        push_if_missing(response, header::X_DOWNLOAD_OPTIONS, DOWNLOAD_NOOPEN);
        push_if_missing(
            response,
            header::X_PERMITTED_CROSS_DOMAIN_POLICIES,
            PERMITTED_CROSS_DOMAIN_NONE,
        );

        if config.is_disabled() {
            return;
        }

        push_if_missing(response, header::CROSS_ORIGIN_OPENER_POLICY, COOP_SAME_ORIGIN);
        push_if_missing(response, header::CROSS_ORIGIN_RESOURCE_POLICY, CORP_SAME_ORIGIN);
        push_if_missing(response, header::ORIGIN_AGENT_CLUSTER, OAC_ENABLED);
        push_if_missing(response, header::X_DNS_PREFETCH_CONTROL, DNS_PREFETCH_OFF);

        if config.is_web() {
            let frame_value = match config.level {
                HelmetLevel::Strict => FRAME_DENY,
                _ => FRAME_SAMEORIGIN,
            };
            push_if_missing(response, header::X_FRAME_OPTIONS, frame_value);

            let referrer_value = match config.level {
                HelmetLevel::Strict => REFERRER_NO_REFERRER,
                _ => REFERRER_STRICT_ORIGIN,
            };
            push_if_missing(response, header::REFERRER_POLICY, referrer_value);
        }

        if matches!(config.level, HelmetLevel::Strict) {
            push_if_missing(response, header::CROSS_ORIGIN_EMBEDDER_POLICY, COEP_REQUIRE_CORP);

            // API Strict also gets Referrer-Policy (Web already set it above)
            if matches!(config.target, HelmetTarget::Api) {
                push_if_missing(response, header::REFERRER_POLICY, REFERRER_NO_REFERRER);
            }
        }
    }
}

#[inline]
fn push_if_missing(response: &mut ResponseParts, name: HeaderName, value: &'static str) {
    if !response.headers.contains_key(&name) {
        let _ = response.insert_header(name, HeaderValue::from_static(value));
    }
}
