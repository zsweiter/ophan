use core::fmt;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};
use http::Method;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HttpMethod(pub u16);

impl HttpMethod {
    pub const NONE: Self = Self(0);

    pub const GET: Self = Self(1 << 0);
    pub const POST: Self = Self(1 << 1);
    pub const PUT: Self = Self(1 << 2);
    pub const DELETE: Self = Self(1 << 3);
    pub const PATCH: Self = Self(1 << 4);
    pub const HEAD: Self = Self(1 << 5);
    pub const OPTIONS: Self = Self(1 << 6);
    pub const TRACE: Self = Self(1 << 7);
    pub const CONNECT: Self = Self(1 << 8);

    pub const ALL: Self = Self(
        Self::GET.0
            | Self::POST.0
            | Self::PUT.0
            | Self::DELETE.0
            | Self::PATCH.0
            | Self::HEAD.0
            | Self::OPTIONS.0
            | Self::TRACE.0
            | Self::CONNECT.0,
    );

    #[inline]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    #[inline]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn as_str(self) -> Option<&'static str> {
        match self.0 {
            x if x == Self::GET.0 => Some("GET"),
            x if x == Self::POST.0 => Some("POST"),
            x if x == Self::PUT.0 => Some("PUT"),
            x if x == Self::DELETE.0 => Some("DELETE"),
            x if x == Self::PATCH.0 => Some("PATCH"),
            x if x == Self::HEAD.0 => Some("HEAD"),
            x if x == Self::OPTIONS.0 => Some("OPTIONS"),
            x if x == Self::TRACE.0 => Some("TRACE"),
            x if x == Self::CONNECT.0 => Some("CONNECT"),
            _ => None,
        }
    }

    #[inline]
    pub fn from_bytes(method: &[u8]) -> Option<Self> {
        match method {
            b"GET" => Some(Self::GET),
            b"POST" => Some(Self::POST),
            b"PUT" => Some(Self::PUT),
            b"DELETE" => Some(Self::DELETE),
            b"PATCH" => Some(Self::PATCH),
            b"HEAD" => Some(Self::HEAD),
            b"OPTIONS" => Some(Self::OPTIONS),
            b"TRACE" => Some(Self::TRACE),
            b"CONNECT" => Some(Self::CONNECT),
            _ => None,
        }
    }
}

impl From<&str> for HttpMethod {
    #[inline]
    fn from(s: &str) -> Self {
        match s {
            "GET" | "get" => HttpMethod::GET,
            "POST" | "post" => HttpMethod::POST,
            "PUT" | "put" => HttpMethod::PUT,
            "DELETE" | "delete" => HttpMethod::DELETE,
            "PATCH" | "patch" => HttpMethod::PATCH,
            "HEAD" | "head" => HttpMethod::HEAD,
            "OPTIONS" | "options" => HttpMethod::OPTIONS,
            "TRACE" | "trace" => HttpMethod::TRACE,
            "CONNECT" | "connect" => HttpMethod::CONNECT,
            _ => HttpMethod::NONE,
        }
    }
}

impl From<String> for HttpMethod {
    #[inline]
    fn from(s: String) -> Self {
        HttpMethod::from(s.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = ParseHttpMethodError;

    #[inline]
    fn from_str(method: &str) -> Result<Self, Self::Err> {
        match method {
            "GET" => Ok(Self::GET),
            "POST" => Ok(Self::POST),
            "PUT" => Ok(Self::PUT),
            "DELETE" => Ok(Self::DELETE),
            "PATCH" => Ok(Self::PATCH),
            "HEAD" => Ok(Self::HEAD),
            "OPTIONS" => Ok(Self::OPTIONS),
            "TRACE" => Ok(Self::TRACE),
            "CONNECT" => Ok(Self::CONNECT),
            _ => Err(ParseHttpMethodError),
        }
    }
}

impl FromIterator<HttpMethod> for HttpMethod {
    fn from_iter<T: IntoIterator<Item = HttpMethod>>(iter: T) -> Self {
        iter.into_iter().fold(HttpMethod::NONE, |acc, m| acc | m)
    }
}

impl BitOr for HttpMethod {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for HttpMethod {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOrAssign for HttpMethod {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for HttpMethod {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.as_str() {
            return f.write_str(name);
        }

        let methods = [
            (Self::GET, "GET"),
            (Self::POST, "POST"),
            (Self::PUT, "PUT"),
            (Self::DELETE, "DELETE"),
            (Self::PATCH, "PATCH"),
            (Self::HEAD, "HEAD"),
            (Self::OPTIONS, "OPTIONS"),
            (Self::TRACE, "TRACE"),
            (Self::CONNECT, "CONNECT"),
        ];

        let mut first = true;

        for (flag, name) in methods {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }

                first = false;
                f.write_str(name)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HttpMethodSet {
    standard: HttpMethod,
    custom: Vec<Box<[u8]>>,
}

impl Default for HttpMethodSet {
    #[inline]
    fn default() -> Self {
        Self::all()
    }
}

impl HttpMethodSet {
    #[inline]
    pub const fn new(standard: HttpMethod) -> Self {
        Self { standard, custom: Vec::new() }
    }

    #[inline]
    pub const fn all() -> Self {
        Self { standard: HttpMethod::ALL, custom: Vec::new() }
    }

    #[inline]
    pub fn with_custom(mut self, method: &[u8]) -> Self {
        self.custom.push(method.into());
        self
    }

    #[inline]
    pub fn add_custom(&mut self, method: &[u8]) {
        self.custom.push(method.into());
    }

    #[inline]
    pub fn add_standard(&mut self, method: HttpMethod) {
        self.standard |= method;
    }

    #[inline]
    pub fn contains_http(&self, method: HttpMethod) -> bool {
        self.standard.contains(method)
    }

    #[inline]
    pub fn contains_bytes(&self, method: &[u8]) -> bool {
        match method {
            b"GET" => self.standard.contains(HttpMethod::GET),
            b"POST" => self.standard.contains(HttpMethod::POST),
            b"PUT" => self.standard.contains(HttpMethod::PUT),
            b"DELETE" => self.standard.contains(HttpMethod::DELETE),
            b"PATCH" => self.standard.contains(HttpMethod::PATCH),
            b"HEAD" => self.standard.contains(HttpMethod::HEAD),
            b"OPTIONS" => self.standard.contains(HttpMethod::OPTIONS),
            b"TRACE" => self.standard.contains(HttpMethod::TRACE),
            b"CONNECT" => self.standard.contains(HttpMethod::CONNECT),

            custom => self.custom.iter().any(|m| m.as_ref() == custom),
        }
    }

    #[inline]
    pub fn contains_str(&self, method: &str) -> bool {
        self.contains_bytes(method.as_bytes())
    }

    #[inline]
    pub fn contains_method(&self, method: &Method) -> bool {
        self.contains_bytes(method.as_str().as_bytes())
    }

    #[inline]
    pub fn is_any(&self) -> bool {
        self.standard == HttpMethod::ALL && self.custom.is_empty()
    }

    #[inline]
    pub fn standard(&self) -> HttpMethod {
        self.standard
    }

    #[inline]
    pub fn custom(&self) -> &[Box<[u8]>] {
        &self.custom
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseHttpMethodError;

impl fmt::Display for ParseHttpMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP method")
    }
}

impl std::error::Error for ParseHttpMethodError {}
