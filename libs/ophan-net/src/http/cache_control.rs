use http::{HeaderMap, HeaderValue, header};
use std::time::Duration;

const FLAG_NO_STORE: u8 = 1 << 0;
const FLAG_NO_CACHE: u8 = 1 << 1;
const FLAG_PRIVATE: u8 = 1 << 2;
const FLAG_PUBLIC: u8 = 1 << 3;
const FLAG_MUST_REVALIDATE: u8 = 1 << 4;
const FLAG_PROXY_REVALIDATE: u8 = 1 << 5;
const FLAG_STALE_IF_ERROR: u8 = 1 << 6;
const FLAG_STALE_WHILE_REVALIDATE: u8 = 1 << 7;

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheControl {
    flags: u8,
    /// `max-age` duration in seconds for browser/client caching.
    max_age: Option<u64>,
    /// `s-maxage` duration in seconds for public/shared caches (CDNs) only.
    s_maxage: Option<u64>,
    /// `stale-while-revalidate` window in seconds to serve stale data during async update.
    stale_while_revalidate: Option<u64>,
    /// `stale-if-error` window in seconds to serve stale data if origin server fails.
    stale_if_error: Option<u64>,
}

impl CacheControl {
    #[inline]
    pub fn parse(headers: &HeaderMap) -> Self {
        let Some(value) = headers.get(header::CACHE_CONTROL) else {
            return Self::default();
        };

        Self::parse_bytes(value.as_bytes())
    }

    #[inline]
    pub fn parse_bytes(bytes: &[u8]) -> Self {
        let mut policy = Self::default();

        for directive in bytes.split(|&b| b == b',') {
            let directive = trim_ows(directive);

            let Some(eq) = directive.iter().position(|&b| b == b'=') else {
                if eq_ignore_ascii_case(directive, b"no-store") {
                    policy.flags |= FLAG_NO_STORE;
                } else if eq_ignore_ascii_case(directive, b"no-cache") {
                    policy.flags |= FLAG_NO_CACHE;
                } else if eq_ignore_ascii_case(directive, b"private") {
                    policy.flags |= FLAG_PRIVATE;
                } else if eq_ignore_ascii_case(directive, b"public") {
                    policy.flags |= FLAG_PUBLIC;
                } else if eq_ignore_ascii_case(directive, b"must-revalidate") {
                    policy.flags |= FLAG_MUST_REVALIDATE;
                } else if eq_ignore_ascii_case(directive, b"proxy-revalidate") {
                    policy.flags |= FLAG_PROXY_REVALIDATE;
                }

                continue;
            };

            let name = trim_ows(&directive[..eq]);
            let value = trim_ows(&directive[eq + 1..]);

            if eq_ignore_ascii_case(name, b"max-age") {
                policy.max_age = parse_delta_seconds(value);
            } else if eq_ignore_ascii_case(name, b"s-maxage") {
                policy.s_maxage = parse_delta_seconds(value);
            } else if eq_ignore_ascii_case(name, b"stale-while-revalidate") {
                if let Some(seconds) = parse_delta_seconds(value) {
                    policy.flags |= FLAG_STALE_WHILE_REVALIDATE;
                    policy.stale_while_revalidate = Some(seconds);
                }
            } else if eq_ignore_ascii_case(name, b"stale-if-error")
                && let Some(seconds) = parse_delta_seconds(value)
            {
                policy.flags |= FLAG_STALE_IF_ERROR;
                policy.stale_if_error = Some(seconds);
            }
        }

        policy
    }

    #[inline]
    pub fn is_storable(self) -> bool {
        self.flags & FLAG_NO_STORE == 0
    }

    #[inline]
    pub fn is_public(self) -> bool {
        self.flags & FLAG_PUBLIC != 0
    }

    #[inline]
    pub fn is_no_cache(self) -> bool {
        self.flags & FLAG_NO_CACHE != 0
    }

    #[inline]
    pub fn must_revalidate(self) -> bool {
        self.flags & (FLAG_NO_CACHE | FLAG_MUST_REVALIDATE | FLAG_PROXY_REVALIDATE) != 0
    }

    /// Returns the Time-To-Live (TTL) duration.
    /// Prioritizes shared/CDN cache (`s_maxage`) over client cache (`max_age`).
    #[inline]
    pub fn ttl(self) -> Option<Duration> {
        self.s_maxage.or(self.max_age).map(Duration::from_secs)
    }

    pub fn stale_while_revalidate(self) -> Option<Duration> {
        self.stale_while_revalidate.map(Duration::from_secs)
    }

    pub fn stale_if_error(self) -> Option<Duration> {
        self.stale_if_error.map(Duration::from_secs)
    }

    // duration in seconds
    #[inline]
    pub fn max_age(self) -> Option<u64> {
        self.max_age
    }

    // duration in seconds
    #[inline]
    pub fn s_maxage(self) -> Option<u64> {
        self.s_maxage
    }
}

#[inline]
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&a, &b)| a.eq_ignore_ascii_case(&b))
}

#[inline]
fn parse_delta_seconds(mut value: &[u8]) -> Option<u64> {
    value = trim_ows(value);

    // Support quoted delta-seconds:
    // max-age="60"
    if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
        value = &value[1..value.len() - 1];
    }

    if value.is_empty() {
        return None;
    }

    let mut result = 0u64;

    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }

        let digit = (byte - b'0') as u64;

        // RFC 9111: delta-seconds overflow represents infinity.
        result = match result.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(value) => value,
            None => i64::MAX as u64,
        };
    }

    Some(result)
}

#[inline]
fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = value.split_first() {
        if first == b' ' || first == b'\t' {
            value = rest;
        } else {
            break;
        }
    }

    while let Some((&last, rest)) = value.split_last() {
        if last == b' ' || last == b'\t' {
            value = rest;
        } else {
            break;
        }
    }

    value
}

impl From<&HeaderMap> for CacheControl {
    #[inline]
    fn from(headers: &HeaderMap) -> Self {
        Self::parse(headers)
    }
}

impl From<&HeaderValue> for CacheControl {
    #[inline]
    fn from(value: &HeaderValue) -> Self {
        Self::parse_bytes(value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, header};
    use std::time::Duration;

    fn parse(value: &str) -> CacheControl {
        CacheControl::parse_bytes(value.as_bytes())
    }

    fn parse_headers(value: &str) -> CacheControl {
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_str(value).unwrap());

        CacheControl::parse(&headers)
    }

    #[test]
    fn empty_cache_control_has_default_semantics() {
        let policy = CacheControl::default();

        assert!(policy.is_storable());
        assert!(!policy.is_public());
        assert!(!policy.is_no_cache());
        assert!(!policy.must_revalidate());

        assert_eq!(policy.ttl(), None);
        assert_eq!(policy.stale_while_revalidate(), None);
        assert_eq!(policy.stale_if_error(), None);
        assert_eq!(policy.max_age(), None);
        assert_eq!(policy.s_maxage(), None);
    }

    #[test]
    fn no_store_makes_response_non_storable() {
        let policy = parse("no-store");

        assert!(!policy.is_storable());
        assert!(!policy.is_no_cache());
        assert!(policy.ttl().is_none());
    }

    #[test]
    fn no_cache_requires_revalidation_but_does_not_make_response_non_storable() {
        let policy = parse("no-cache");

        assert!(policy.is_storable());
        assert!(policy.is_no_cache());
        assert!(policy.must_revalidate());
    }

    #[test]
    fn private_response_is_storable_by_private_caches() {
        let policy = parse("private");

        // RFC 9111: private prevents storage by shared caches,
        // but private caches may still store the response.
        assert!(policy.is_storable());
    }

    #[test]
    fn public_marks_response_as_public() {
        let policy = parse("public");

        assert!(policy.is_storable());
        assert!(policy.is_public());
    }

    #[test]
    fn must_revalidate_requires_revalidation_when_stale() {
        let policy = parse("must-revalidate");

        assert!(policy.is_storable());
        assert!(policy.must_revalidate());
    }

    #[test]
    fn proxy_revalidate_requires_revalidation_for_shared_caches() {
        let policy = parse("proxy-revalidate");

        assert!(policy.is_storable());
        assert!(policy.must_revalidate());
    }

    #[test]
    fn max_age_defines_ttl() {
        let policy = parse("max-age=600");

        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.s_maxage(), None);
        assert_eq!(policy.ttl(), Some(Duration::from_secs(600)));
    }

    #[test]
    fn s_maxage_takes_precedence_over_max_age() {
        let policy = parse("max-age=600, s-maxage=120");

        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.s_maxage(), Some(120));

        // Shared-cache freshness is controlled by s-maxage.
        assert_eq!(policy.ttl(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn zero_max_age_is_a_valid_value() {
        let policy = parse("max-age=0");

        assert_eq!(policy.max_age(), Some(0));
        assert_eq!(policy.ttl(), Some(Duration::ZERO));
    }

    #[test]
    fn zero_s_maxage_is_a_valid_value() {
        let policy = parse("s-maxage=0");

        assert_eq!(policy.s_maxage(), Some(0));
        assert_eq!(policy.ttl(), Some(Duration::ZERO));
    }

    #[test]
    fn stale_while_revalidate_is_exposed_when_present() {
        let policy = parse("max-age=600, stale-while-revalidate=30");

        assert_eq!(policy.stale_while_revalidate(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn stale_if_error_is_exposed_when_present() {
        let policy = parse("max-age=600, stale-if-error=1200");

        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(1200)));
    }

    #[test]
    fn stale_directives_are_independent() {
        let policy = parse("max-age=600, stale-while-revalidate=30, stale-if-error=1200");

        assert_eq!(policy.stale_while_revalidate(), Some(Duration::from_secs(30)));

        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(1200)));
    }

    #[test]
    fn stale_while_revalidate_zero_is_valid() {
        let policy = parse("stale-while-revalidate=0");

        assert_eq!(policy.stale_while_revalidate(), Some(Duration::ZERO));
    }

    #[test]
    fn stale_if_error_zero_is_valid() {
        let policy = parse("stale-if-error=0");

        assert_eq!(policy.stale_if_error(), Some(Duration::ZERO));
    }

    #[test]
    fn directives_are_case_insensitive() {
        let policy = parse("No-StOrE, No-CaChE, PuBlIc, MaX-AgE=60, S-MaXaGe=30");

        assert!(!policy.is_storable());
        assert!(policy.is_no_cache());
        assert!(policy.is_public());

        assert_eq!(policy.max_age(), Some(60));
        assert_eq!(policy.s_maxage(), Some(30));
        assert_eq!(policy.ttl(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn unknown_directives_are_ignored() {
        let policy = parse("max-age=600, unknown-directive, another-extension=value");

        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.ttl(), Some(Duration::from_secs(600)));
        assert!(policy.is_storable());
    }

    #[test]
    fn optional_whitespace_around_directives_is_ignored() {
        let policy = parse("  max-age = 600  ,\tpublic\t, stale-if-error = 120");

        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(120)));
        assert!(policy.is_public());
    }

    #[test]
    fn multiple_directives_are_combined() {
        let policy = parse("public, max-age=600, must-revalidate, stale-if-error=1200");

        assert!(policy.is_public());
        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.ttl(), Some(Duration::from_secs(600)));

        assert!(policy.must_revalidate());

        // Cache-Control still contains the stale-if-error directive.
        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(1200)));
    }

    #[test]
    fn must_revalidate_does_not_remove_stale_directives() {
        let policy = parse("max-age=600, must-revalidate, stale-while-revalidate=30");

        assert!(policy.must_revalidate());

        assert_eq!(policy.stale_while_revalidate(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn no_cache_does_not_remove_stale_directives() {
        let policy = parse("max-age=600, no-cache, stale-while-revalidate=30, stale-if-error=120");

        assert!(policy.is_no_cache());
        assert!(policy.must_revalidate());

        assert_eq!(policy.stale_while_revalidate(), Some(Duration::from_secs(30)));

        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn stale_directives_can_coexist_with_s_maxage() {
        let policy = parse("s-maxage=600, stale-while-revalidate=30, stale-if-error=120");

        assert_eq!(policy.s_maxage(), Some(600));
        assert_eq!(policy.ttl(), Some(Duration::from_secs(600)));

        // The presence of s-maxage does not itself mean the
        // stale extensions are absent.
        assert_eq!(policy.stale_while_revalidate(), Some(Duration::from_secs(30)));

        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn quoted_delta_seconds_are_accepted() {
        let policy = parse(r#"max-age="600", stale-if-error="120""#);

        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.stale_if_error(), Some(Duration::from_secs(120)));
    }

    #[test]
    fn malformed_delta_seconds_are_ignored() {
        let policy = parse("max-age=abc, s-maxage=, stale-if-error=xyz");

        assert_eq!(policy.max_age(), None);
        assert_eq!(policy.s_maxage(), None);
        assert_eq!(policy.stale_if_error(), None);
    }

    #[test]
    fn negative_delta_seconds_are_invalid() {
        let policy = parse("max-age=-1");

        assert_eq!(policy.max_age(), None);
        assert_eq!(policy.ttl(), None);
    }

    #[test]
    fn non_numeric_delta_seconds_are_invalid() {
        let policy = parse("max-age=10x");

        assert_eq!(policy.max_age(), None);
        assert_eq!(policy.ttl(), None);
    }

    #[test]
    fn missing_argument_does_not_create_a_ttl() {
        let policy = parse("max-age");

        assert_eq!(policy.max_age(), None);
        assert_eq!(policy.ttl(), None);
    }

    #[test]
    fn header_map_api_has_same_semantics_as_bytes_api() {
        let from_bytes = parse("public, max-age=600");

        let from_headers = parse_headers("public, max-age=600");

        assert_eq!(from_headers.is_public(), from_bytes.is_public());
        assert_eq!(from_headers.max_age(), from_bytes.max_age());
        assert_eq!(from_headers.ttl(), from_bytes.ttl());
    }

    #[test]
    fn header_value_conversion_has_same_semantics_as_bytes_api() {
        let value = HeaderValue::from_static("public, max-age=600");

        let policy = CacheControl::from(&value);

        assert!(policy.is_public());
        assert_eq!(policy.max_age(), Some(600));
        assert_eq!(policy.ttl(), Some(Duration::from_secs(600)));
    }

    #[test]
    fn header_map_conversion_has_same_semantics_as_parse() {
        let mut headers = HeaderMap::new();

        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=600, public"));

        let parsed = CacheControl::parse(&headers);
        let converted = CacheControl::from(&headers);

        assert_eq!(converted.is_public(), parsed.is_public());
        assert_eq!(converted.max_age(), parsed.max_age());
        assert_eq!(converted.ttl(), parsed.ttl());
    }

    #[test]
    fn large_delta_seconds_is_saturated() {
        let policy = parse("max-age=999999999999999999999999999999999999999999999");

        assert_eq!(policy.max_age(), Some(i64::MAX as u64));
    }
}
