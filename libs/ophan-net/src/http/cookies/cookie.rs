use std::{borrow::Cow, fmt, time::Duration};

use http::{HeaderValue, header};

/// The `SameSite` cookie attribute.
///
/// [HTTP draft]: https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    #[inline]
    pub fn is_strict(&self) -> bool {
        match *self {
            SameSite::Strict => true,
            SameSite::Lax | SameSite::None => false,
        }
    }

    #[inline]
    pub fn is_lax(&self) -> bool {
        match *self {
            SameSite::Lax => true,
            SameSite::Strict | SameSite::None => false,
        }
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        match *self {
            SameSite::None => true,
            SameSite::Lax | SameSite::Strict => false,
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expiration {
    /// Expiration for a "permanent" cookie at a specific date-time.
    DateTime(Duration),
    /// Expiration for a "session" cookie. Browsers define the notion of a
    /// "session" and will automatically expire session cookies when they deem
    /// the "session" to be over. This is typically, but need not be, when the
    /// browser is closed.
    Session,
}

impl Expiration {
    pub fn is_datetime(&self) -> bool {
        match self {
            Expiration::DateTime(_) => true,
            Expiration::Session => false,
        }
    }

    pub fn is_session(&self) -> bool {
        match self {
            Expiration::DateTime(_) => false,
            Expiration::Session => true,
        }
    }

    pub fn datetime(self) -> Option<Duration> {
        match self {
            Expiration::Session => None,
            Expiration::DateTime(v) => Some(v),
        }
    }
}

impl<T: Into<Option<Duration>>> From<T> for Expiration {
    fn from(option: T) -> Self {
        match option.into() {
            Some(value) => Expiration::DateTime(value),
            None => Expiration::Session,
        }
    }
}

#[derive(Debug, Clone)]
enum CookieStr<'c> {
    /// An string derived from indexes (start, end).
    Indexed(usize, usize),
    /// A string derived from a concrete string.
    Concrete(Cow<'c, str>),
}

impl<'c> CookieStr<'c> {
    /// Creates an indexed `CookieStr` that holds the start and end indices of
    /// `needle` inside of `haystack`, if `needle` is a substring of `haystack`.
    /// Otherwise returns `None`.
    ///
    /// The `needle` can later be retrieved via `to_str()`.
    fn indexed(needle: &str, haystack: &str) -> Option<CookieStr<'static>> {
        let haystack_start = haystack.as_ptr() as usize;
        let needle_start = needle.as_ptr() as usize;

        if needle_start < haystack_start {
            return None;
        }

        if (needle_start + needle.len()) > (haystack_start + haystack.len()) {
            return None;
        }

        let start = needle_start - haystack_start;
        let end = start + needle.len();
        Some(CookieStr::Indexed(start, end))
    }

    /// Retrieves the string `self` corresponds to. If `self` is derived from
    /// indices, the corresponding subslice of `string` is returned. Otherwise,
    /// the concrete string is returned.
    ///
    /// # Panics
    ///
    /// Panics if `self` is an indexed string and `string` is None.
    fn to_str<'s>(&'s self, string: Option<&'s Cow<str>>) -> &'s str {
        match *self {
            CookieStr::Indexed(i, j) => {
                let s = string.expect(
                    "`Some` base string must exist when \
                    converting indexed str to str! (This is a module invariant.)",
                );
                &s[i..j]
            },
            CookieStr::Concrete(ref cstr) => &*cstr,
        }
    }

    #[allow(clippy::ptr_arg)]
    fn to_raw_str<'s, 'b: 's>(&'s self, string: &'s Cow<'b, str>) -> Option<&'b str> {
        match *self {
            CookieStr::Indexed(i, j) => match *string {
                Cow::Borrowed(s) => Some(&s[i..j]),
                Cow::Owned(_) => None,
            },
            CookieStr::Concrete(_) => None,
        }
    }

    fn into_owned(self) -> CookieStr<'static> {
        match self {
            CookieStr::Indexed(a, b) => CookieStr::Indexed(a, b),
            CookieStr::Concrete(Cow::Owned(c)) => CookieStr::Concrete(Cow::Owned(c)),
            CookieStr::Concrete(Cow::Borrowed(c)) => CookieStr::Concrete(Cow::Owned(c.into())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cookie<'c> {
    /// Storage for the cookie string. Only used if this structure was derived
    /// from a string that was subsequently parsed.
    cookie_string: Option<Cow<'c, str>>,
    /// The cookie's name.
    name: CookieStr<'c>,
    /// The cookie's value.
    value: CookieStr<'c>,
    /// The cookie's expiration, if any.
    expires: Option<Expiration>,
    /// The cookie's maximum age, if any.
    max_age: Option<Duration>,
    /// The cookie's domain, if any.
    domain: Option<CookieStr<'c>>,
    /// The cookie's path domain, if any.
    path: Option<CookieStr<'c>>,
    /// Whether this cookie was marked Secure.
    secure: Option<bool>,
    /// Whether this cookie was marked HttpOnly.
    http_only: Option<bool>,
    /// The draft `SameSite` attribute.
    same_site: Option<SameSite>,
    /// The draft `Partitioned` attribute.
    partitioned: Option<bool>,
}

impl<'c> Cookie<'c> {
    #[inline]
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        Self {
            cookie_string: None,
            name: CookieStr::Concrete(name.into()),
            value: CookieStr::Concrete(value.into()),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: None,
            http_only: None,
            same_site: None,
            partitioned: None,
        }
    }
}

impl<'c> TryFrom<Cookie<'c>> for HeaderValue {
    type Error = header::InvalidHeaderValue;

    fn try_from(cookie: Cookie<'c>) -> Result<Self, Self::Error> {
        let mut buf = Vec::with_capacity(128);

        let name = cookie.name.to_str(cookie.cookie_string.as_ref());
        let value = cookie.value.to_str(cookie.cookie_string.as_ref());

        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(value.as_bytes());

        if let Some(path) = &cookie.path {
            buf.extend_from_slice(b"; Path=");
            buf.extend_from_slice(path.to_str(cookie.cookie_string.as_ref()).as_bytes());
        }

        if let Some(domain) = &cookie.domain {
            buf.extend_from_slice(b"; Domain=");
            buf.extend_from_slice(domain.to_str(cookie.cookie_string.as_ref()).as_bytes());
        }

        if let Some(max_age) = cookie.max_age {
            buf.extend_from_slice(b"; Max-Age=");

            let secs = max_age.as_secs();
            let mut itoa = itoa::Buffer::new();
            buf.extend_from_slice(itoa.format(secs).as_bytes());
        }

        if let Some(expires) = cookie.expires {
            match expires {
                Expiration::DateTime(_) => {
                    // TODO: Format as IMF-fixdate:
                    // Expires=Wed, 21 Oct 2015 07:28:00 GMT
                },
                Expiration::Session => {},
            }
        }

        if let Some(same_site) = cookie.same_site {
            match same_site {
                SameSite::Strict => buf.extend_from_slice(b"; SameSite=Strict"),
                SameSite::Lax => buf.extend_from_slice(b"; SameSite=Lax"),
                SameSite::None => buf.extend_from_slice(b"; SameSite=None"),
            }
        }

        if cookie.secure == Some(true) {
            buf.extend_from_slice(b"; Secure");
        }

        if cookie.http_only == Some(true) {
            buf.extend_from_slice(b"; HttpOnly");
        }

        if cookie.partitioned == Some(true) {
            buf.extend_from_slice(b"; Partitioned");
        }

        HeaderValue::from_bytes(&buf)
    }
}
