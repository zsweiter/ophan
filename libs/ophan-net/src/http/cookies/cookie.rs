//! HTTP cookie representation and serialization.
//!
//! # References
//!
//! - [RFC 6265 – HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
//! - [RFC 6265bis (draft) – SameSite & Partitioned](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
//! - [RFC 7231 §7.1.1.1 – IMF-fixdate](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.1)
//! - [CHIPS – Cookies Having Independent Partitioned State](https://developers.google.com/privacy-sandbox/cookies/chips)

use std::{
    borrow::Cow,
    fmt,
    time::{Duration, SystemTime},
};

use http::{header, HeaderValue};
use httpdate::HttpDate;
use itoa;

// =============================================================================
// SameSite
// =============================================================================

/// The `SameSite` cookie attribute.
///
/// Controls whether a cookie is sent with cross-site requests.
///
/// See [RFC 6265bis §5.3.7](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-14#section-5.3.7)
/// and the original incrementalism draft:
/// <https://tools.ietf.org/html/draft-west-cookie-incrementalism-00>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SameSite {
    /// Cookie is never sent on cross-site requests.
    Strict = 1,
    /// Cookie is withheld on cross-site subrequests (e.g. images) but sent
    /// when the user navigates to the URL from an external site.
    Lax = 2,
    /// Cookie is sent on all requests (requires `Secure`).
    None = 3,
}

impl SameSite {
    /// Returns `true` if this is `SameSite::Strict`.
    #[inline]
    pub const fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Returns `true` if this is `SameSite::Lax`.
    #[inline]
    pub const fn is_lax(self) -> bool {
        matches!(self, Self::Lax)
    }

    /// Returns `true` if this is `SameSite::None`.
    #[inline]
    pub const fn is_none(self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns the canonical attribute value (`"Strict"`, `"Lax"` or `"None"`).
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }

    /// Returns the attribute value as bytes.
    #[inline]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Strict => b"Strict",
            Self::Lax => b"Lax",
            Self::None => b"None",
        }
    }
}

impl fmt::Display for SameSite {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Expires
// =============================================================================

/// Cookie expiration.
///
/// Corresponds to the `Expires` attribute (absolute date) or the absence of
/// both `Expires` and `Max-Age` (session cookie).
///
/// See [RFC 6265 §5.2.1](https://datatracker.ietf.org/doc/html/rfc6265#section-5.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expires {
    /// A session cookie. Browsers discard it when the current session ends
    /// (typically when the browser is closed).
    Session,
    /// An absolute expiration date-time (serialized as IMF-fixdate).
    DateTime(SystemTime),
}

impl Expires {
    /// Returns `true` if this is a session cookie.
    #[inline]
    pub const fn is_session(self) -> bool {
        matches!(self, Self::Session)
    }

    /// Returns `true` if this carries an absolute date-time.
    #[inline]
    pub const fn is_datetime(self) -> bool {
        matches!(self, Self::DateTime(_))
    }

    /// Returns the contained `SystemTime` if this is `DateTime`.
    #[inline]
    pub fn datetime(self) -> Option<SystemTime> {
        match self {
            Self::DateTime(t) => Some(t),
            Self::Session => None,
        }
    }
}

impl From<SystemTime> for Expires {
    #[inline]
    fn from(t: SystemTime) -> Self {
        Self::DateTime(t)
    }
}

impl From<Option<SystemTime>> for Expires {
    #[inline]
    fn from(opt: Option<SystemTime>) -> Self {
        match opt {
            Some(t) => Self::DateTime(t),
            None => Self::Session,
        }
    }
}

// =============================================================================
// StrRef – owned or indexed (zero-copy) string
// =============================================================================

/// Internal string reference.
///
/// * `Indexed` – byte range into the original cookie string (used after parse).
/// * `Concrete` – an owned or borrowed `Cow<str>` (used when building).
#[derive(Debug, Clone)]
enum StrRef<'c> {
    #[allow(dead_code)]
    Indexed(u32, u32), // start, end (exclusive)
    Concrete(Cow<'c, str>),
}

impl<'c> StrRef<'c> {
    #[inline]
    fn as_str<'a>(&'a self, raw: Option<&'a str>) -> &'a str {
        match self {
            StrRef::Indexed(start, end) => {
                &raw.expect("indexed StrRef requires the original string")[*start as usize..*end as usize]
            }
            StrRef::Concrete(c) => c.as_ref(),
        }
    }

    #[inline]
    fn as_bytes<'a>(&'a self, raw: Option<&'a str>) -> &'a [u8] {
        self.as_str(raw).as_bytes()
    }

    fn into_owned(self, raw: Option<&str>) -> StrRef<'static> {
        match self {
            StrRef::Indexed(s, e) => {
                let slice = &raw.expect("indexed StrRef requires the original string")[s as usize..e as usize];
                StrRef::Concrete(Cow::Owned(slice.to_owned()))
            }
            StrRef::Concrete(c) => StrRef::Concrete(Cow::Owned(c.into_owned())),
        }
    }
}

// =============================================================================
// Cookie
// =============================================================================

/// An HTTP cookie.
///
/// Supports both construction (via [`Cookie::new`] / [`Cookie::build`]) and
/// zero-copy parsing (indices into the original header value).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// # use ophan_net::http::cookies::{Cookie, SameSite};
///
/// let cookie = Cookie::build("session", "abc123")
///     .path("/")
///     .secure(true)
///     .http_only(true)
///     .same_site(SameSite::Lax)
///     .max_age(Duration::from_secs(3600))
///     .build();
///
/// assert!(cookie.to_string().contains("session=abc123"));
/// ```
#[derive(Debug, Clone)]
pub struct Cookie<'c> {
    /// Original header string. Present only when the cookie was parsed.
    raw: Option<Cow<'c, str>>,
    name: StrRef<'c>,
    value: StrRef<'c>,
    path: Option<StrRef<'c>>,
    domain: Option<StrRef<'c>>,
    /// Max-Age in seconds (RFC 6265 §5.2.2).
    max_age: Option<u64>,
    expires: Option<Expires>,
    secure: Option<bool>,
    http_only: Option<bool>,
    partitioned: Option<bool>,
    same_site: Option<SameSite>,
}

impl<'c> Cookie<'c> {
    /// Creates a cookie with the given name and value.
    ///
    /// All attributes are left unset (session cookie, no path/domain, etc.).
    #[inline]
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        Self {
            raw: None,
            name: StrRef::Concrete(name.into()),
            value: StrRef::Concrete(value.into()),
            path: None,
            domain: None,
            max_age: None,
            expires: None,
            secure: None,
            http_only: None,
            partitioned: None,
            same_site: None,
        }
    }

    /// Returns a builder starting from the given name and value.
    #[inline]
    pub fn build<N, V>(name: N, value: V) -> CookieBuilder<'c>
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        CookieBuilder {
            cookie: Self::new(name, value),
        }
    }

    /// Converts `self` into an owned cookie (`'static`) with as few
    /// allocations as possible.
    pub fn into_owned(self) -> Cookie<'static> {
        let raw_str = self.raw.as_ref().map(|c| c.as_ref());

        let name = self.name.into_owned(raw_str);
        let value = self.value.into_owned(raw_str);
        let path = self.path.map(|p| p.into_owned(raw_str));
        let domain = self.domain.map(|d| d.into_owned(raw_str));
        let raw_owned = self.raw.map(|c| Cow::Owned(c.into_owned()));

        Cookie {
            name,
            value,
            path,
            domain,
            max_age: self.max_age,
            expires: self.expires,
            secure: self.secure,
            http_only: self.http_only,
            partitioned: self.partitioned,
            same_site: self.same_site,
            raw: raw_owned,
        }
    }
}

// -----------------------------------------------------------------------------
// Getters
// -----------------------------------------------------------------------------

impl<'c> Cookie<'c> {
    #[inline]
    fn raw_str(&self) -> Option<&str> {
        self.raw.as_ref().map(Cow::as_ref)
    }

    /// Returns the cookie name.
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_str(self.raw_str())
    }

    /// Returns the cookie value.
    #[inline]
    pub fn value(&self) -> &str {
        self.value.as_str(self.raw_str())
    }

    /// Returns the name and value as a tuple.
    #[inline]
    pub fn name_value(&self) -> (&str, &str) {
        (self.name(), self.value())
    }

    /// Returns the `Path` attribute, if set.
    #[inline]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(|p| p.as_str(self.raw_str()))
    }

    /// Returns the `Domain` attribute, if set.
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_ref().map(|d| d.as_str(self.raw_str()))
    }

    /// Returns the `Max-Age` attribute as a [`Duration`], if set.
    #[inline]
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age.map(Duration::from_secs)
    }

    /// Returns the expiration, if set.
    #[inline]
    pub fn expires(&self) -> Option<Expires> {
        self.expires
    }

    /// Returns `Some(true)` if the `Secure` attribute is present and true.
    #[inline]
    pub fn secure(&self) -> Option<bool> {
        self.secure
    }

    /// Returns `Some(true)` if the `HttpOnly` attribute is present and true.
    #[inline]
    pub fn http_only(&self) -> Option<bool> {
        self.http_only
    }

    /// Returns `Some(true)` if the `Partitioned` attribute is present and true.
    ///
    /// See [CHIPS](https://developers.google.com/privacy-sandbox/cookies/chips).
    #[inline]
    pub fn partitioned(&self) -> Option<bool> {
        self.partitioned
    }

    /// Returns the `SameSite` attribute, if set.
    #[inline]
    pub fn same_site(&self) -> Option<SameSite> {
        self.same_site
    }
}

// -----------------------------------------------------------------------------
// Setters
// -----------------------------------------------------------------------------

impl<'c> Cookie<'c> {
    /// Sets the `Path` attribute.
    #[inline]
    pub fn set_path<P: Into<Cow<'c, str>>>(&mut self, path: P) {
        self.path = Some(StrRef::Concrete(path.into()));
    }

    /// Sets the `Domain` attribute.
    #[inline]
    pub fn set_domain<D: Into<Cow<'c, str>>>(&mut self, domain: D) {
        self.domain = Some(StrRef::Concrete(domain.into()));
    }

    /// Sets the `Max-Age` attribute (seconds).
    #[inline]
    pub fn set_max_age(&mut self, age: Duration) {
        self.max_age = Some(age.as_secs());
    }

    /// Sets the `Expires` attribute.
    #[inline]
    pub fn set_expires(&mut self, expires: impl Into<Expires>) {
        self.expires = Some(expires.into());
    }

    /// Sets, clears, or explicitly unsets the `Secure` attribute.
    #[inline]
    pub fn set_secure(&mut self, on: impl Into<Option<bool>>) {
        self.secure = on.into();
    }

    /// Sets, clears, or explicitly unsets the `HttpOnly` attribute.
    #[inline]
    pub fn set_http_only(&mut self, on: impl Into<Option<bool>>) {
        self.http_only = on.into();
    }

    /// Sets, clears, or explicitly unsets the `Partitioned` attribute.
    #[inline]
    pub fn set_partitioned(&mut self, on: impl Into<Option<bool>>) {
        self.partitioned = on.into();
    }

    /// Sets or clears the `SameSite` attribute.
    #[inline]
    pub fn set_same_site(&mut self, ss: impl Into<Option<SameSite>>) {
        self.same_site = ss.into();
    }
}

// =============================================================================
// CookieBuilder
// =============================================================================

/// Fluent builder for [`Cookie`].
///
/// Obtained via [`Cookie::build`].
#[derive(Debug)]
pub struct CookieBuilder<'c> {
    cookie: Cookie<'c>,
}

impl<'c> CookieBuilder<'c> {
    /// Sets the `Path` attribute.
    #[inline]
    pub fn path<P: Into<Cow<'c, str>>>(mut self, path: P) -> Self {
        self.cookie.set_path(path);
        self
    }

    /// Sets the `Domain` attribute.
    #[inline]
    pub fn domain<D: Into<Cow<'c, str>>>(mut self, domain: D) -> Self {
        self.cookie.set_domain(domain);
        self
    }

    /// Sets the `Max-Age` attribute.
    #[inline]
    pub fn max_age(mut self, age: Duration) -> Self {
        self.cookie.set_max_age(age);
        self
    }

    /// Sets the `Expires` attribute.
    #[inline]
    pub fn expires(mut self, expires: impl Into<Expires>) -> Self {
        self.cookie.set_expires(expires);
        self
    }

    /// Sets the `Secure` attribute.
    #[inline]
    pub fn secure(mut self, on: impl Into<Option<bool>>) -> Self {
        self.cookie.set_secure(on);
        self
    }

    /// Sets the `HttpOnly` attribute.
    #[inline]
    pub fn http_only(mut self, on: impl Into<Option<bool>>) -> Self {
        self.cookie.set_http_only(on);
        self
    }

    /// Sets the `Partitioned` attribute.
    #[inline]
    pub fn partitioned(mut self, on: impl Into<Option<bool>>) -> Self {
        self.cookie.set_partitioned(on);
        self
    }

    /// Sets the `SameSite` attribute.
    #[inline]
    pub fn same_site(mut self, ss: impl Into<Option<SameSite>>) -> Self {
        self.cookie.set_same_site(ss);
        self
    }

    /// Consumes the builder and returns the finished [`Cookie`].
    #[inline]
    pub fn build(self) -> Cookie<'c> {
        self.cookie
    }
}

// =============================================================================
// Serialization (byte buffer – hot path)
// =============================================================================

impl<'c> Cookie<'c> {
    /// Serializes the cookie into a byte buffer.
    ///
    /// The output is pure ASCII (cookie-octet + attribute grammar from
    /// [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265)).  No UTF-8
    /// validation is required afterwards.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        let raw = self.raw_str();

        // name=value
        buf.extend_from_slice(self.name.as_bytes(raw));
        buf.push(b'=');
        buf.extend_from_slice(self.value.as_bytes(raw));

        // Path
        if let Some(path) = &self.path {
            buf.extend_from_slice(b"; Path=");
            buf.extend_from_slice(path.as_bytes(raw));
        }

        // Domain
        if let Some(domain) = &self.domain {
            buf.extend_from_slice(b"; Domain=");
            buf.extend_from_slice(domain.as_bytes(raw));
        }

        // Max-Age
        if let Some(secs) = self.max_age {
            buf.extend_from_slice(b"; Max-Age=");
            let mut itoa_buf = itoa::Buffer::new();
            buf.extend_from_slice(itoa_buf.format(secs).as_bytes());
        }

        // Expires (IMF-fixdate via httpdate)
        if let Some(Expires::DateTime(t)) = self.expires {
            buf.extend_from_slice(b"; Expires=");
            // HttpDate always formats to exactly 29 ASCII bytes:
            // "Wed, 21 Oct 2015 07:28:00 GMT"
            let date = HttpDate::from(t);
            let mut date_buf = [0u8; 29];
            let formatted = write_http_date(&date, &mut date_buf);
            buf.extend_from_slice(formatted);
        }

        // SameSite
        if let Some(ss) = self.same_site {
            buf.extend_from_slice(b"; SameSite=");
            buf.extend_from_slice(ss.as_bytes());
        }

        // Boolean attributes
        if self.secure == Some(true) {
            buf.extend_from_slice(b"; Secure");
        }
        if self.http_only == Some(true) {
            buf.extend_from_slice(b"; HttpOnly");
        }
        if self.partitioned == Some(true) {
            buf.extend_from_slice(b"; Partitioned");
        }
    }

    /// Converts the cookie into an [`HeaderValue`] without an intermediate
    /// `String` or UTF-8 validation.
    #[inline]
    pub fn to_header_value(&self) -> Result<HeaderValue, header::InvalidHeaderValue> {
        let mut buf = Vec::with_capacity(128);
        self.write_to(&mut buf);
        HeaderValue::from_bytes(&buf)
    }
}

impl<'c> TryFrom<Cookie<'c>> for HeaderValue {
    type Error = header::InvalidHeaderValue;

    #[inline]
    fn try_from(cookie: Cookie<'c>) -> Result<Self, Self::Error> {
        cookie.to_header_value()
    }
}

impl<'c> fmt::Display for Cookie<'c> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = Vec::with_capacity(128);
        self.write_to(&mut buf);
        // SAFETY: `write_to` only emits ASCII bytes (cookie grammar +
        // IMF-fixdate).  ASCII is always valid UTF-8.
        let s = unsafe { std::str::from_utf8_unchecked(&buf) };
        f.write_str(s)
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Formats an [`HttpDate`] into a fixed 29-byte buffer.
///
/// Returns the written slice (always 29 bytes for a valid date).
fn write_http_date<'a>(date: &HttpDate, buf: &'a mut [u8; 29]) -> &'a [u8] {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    // HttpDate's Display is pure ASCII and always fits in 29 bytes.
    write!(cursor, "{}", date).expect("HttpDate Display always fits in 29 bytes");
    let len = cursor.position() as usize;
    &buf[..len]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn builder_basic() {
        let c = Cookie::build("session", "abc123")
            .path("/")
            .domain("example.com")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(Duration::from_secs(3600))
            .build();

        let s = c.to_string();
        assert!(s.starts_with("session=abc123"));
        assert!(s.contains("; Path=/"));
        assert!(s.contains("; Domain=example.com"));
        assert!(s.contains("; Max-Age=3600"));
        assert!(s.contains("; SameSite=Lax"));
        assert!(s.contains("; Secure"));
        assert!(s.contains("; HttpOnly"));
        assert!(!s.contains("Partitioned"));
    }

    #[test]
    fn flags_roundtrip() {
        let mut c = Cookie::new("a", "b");
        assert_eq!(c.secure(), None);
        assert_eq!(c.http_only(), None);
        assert_eq!(c.partitioned(), None);
        assert_eq!(c.same_site(), None);

        c.set_secure(true);
        c.set_http_only(true);
        c.set_partitioned(true);
        c.set_same_site(SameSite::Strict);

        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.partitioned(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Strict));

        c.set_secure(false);
        assert_eq!(c.secure(), Some(false));
        // other flags remain
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.same_site(), Some(SameSite::Strict));

        // Clear using None
        c.set_secure(None);
        c.set_same_site(None);
        assert_eq!(c.secure(), None);
        assert_eq!(c.same_site(), None);
    }

    #[test]
    fn edge_case_empty_values() {
        let c = Cookie::new("", "");
        assert_eq!(c.to_string(), "=");

        let hv = c.to_header_value().unwrap();
        assert_eq!(hv.as_bytes(), b"=");
    }

    #[test]
    fn edge_case_indexed_strref_into_owned() {
        let raw_cookie_str = "foo=bar; Path=/app; Secure";
        let c = Cookie {
            raw: Some(Cow::Borrowed(raw_cookie_str)),
            name: StrRef::Indexed(0, 3),
            value: StrRef::Indexed(4, 7),
            path: Some(StrRef::Indexed(14, 18)),
            domain: None,
            max_age: None,
            expires: None,
            secure: Some(true),
            http_only: None,
            partitioned: None,
            same_site: None,
        };

        let owned: Cookie<'static> = c.into_owned();
        assert_eq!(owned.name(), "foo");
        assert_eq!(owned.value(), "bar");
        assert_eq!(owned.path(), Some("/app"));
        assert_eq!(owned.secure(), Some(true));
        assert_eq!(owned.to_string(), "foo=bar; Path=/app; Secure");
    }

    #[test]
    fn expires_imf_fixdate() {
        // 1994-11-06 08:49:37 UTC (classic RFC example)
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        let c = Cookie::build("x", "y").expires(t).build();
        let s = c.to_string();
        assert!(s.contains("Expires=Sun, 06 Nov 1994 08:49:37 GMT"));
    }

    #[test]
    fn to_header_value() {
        let c = Cookie::build("id", "42").secure(true).build();
        let hv = c.to_header_value().unwrap();
        assert_eq!(hv.as_bytes(), b"id=42; Secure");
    }

    #[test]
    fn into_owned() {
        let c = Cookie::new("n", "v");
        let owned: Cookie<'static> = c.into_owned();
        assert_eq!(owned.name_value(), ("n", "v"));
    }
}