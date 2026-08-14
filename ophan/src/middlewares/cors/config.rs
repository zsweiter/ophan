use http::HeaderValue;
use std::fmt;
use std::time::Duration;

#[derive(Debug)]
pub enum CorsConfigError {
    EmptyOrigin,
    WildcardMixed,
    InvalidWildcard(String),
    InvalidOrigin(String),
    InvalidScheme(String),
    OriginContainsPath,
    OriginContainsCredentials,
    ContainsWhitespace,
}

impl CorsConfigError {
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyOrigin => "origin is empty",
            Self::WildcardMixed => "wildcard '*' cannot be combined with other origins",
            Self::InvalidWildcard(_) => "invalid wildcard origin",
            Self::InvalidOrigin(_) => "invalid origin",
            Self::InvalidScheme(_) => "unsupported scheme",
            Self::OriginContainsPath => "origin contains path, query or fragment",
            Self::OriginContainsCredentials => "origin contains credentials",
            Self::ContainsWhitespace => "origin contains whitespace",
        }
    }
}

impl fmt::Display for CorsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOrigin => f.write_str("origin is empty"),

            Self::WildcardMixed => f.write_str("wildcard '*' cannot be combined with other origins"),

            Self::InvalidWildcard(origin) => {
                write!(f, "invalid wildcard origin '{origin}'")
            },

            Self::InvalidOrigin(origin) => {
                write!(f, "invalid origin '{origin}'")
            },

            Self::InvalidScheme(scheme) => {
                write!(f, "unsupported scheme '{scheme}'")
            },

            Self::OriginContainsPath => f.write_str("origin contains path, query or fragment"),

            Self::OriginContainsCredentials => f.write_str("origin contains credentials"),

            Self::ContainsWhitespace => f.write_str("origin contains whitespace"),
        }
    }
}

impl std::error::Error for CorsConfigError {}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allow_origins: AllowedOrigins,
    pub allow_credentials: bool,
    pub max_age: Option<Duration>, // saved in seconds
    pub allow_methods: Option<HeaderValue>,
    pub allow_headers: Option<HeaderValue>,
    pub allow_expose_headers: Option<HeaderValue>,
    pub allow_max_age: Option<HeaderValue>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origins: AllowedOrigins::List(Box::new([])),
            allow_credentials: false,
            max_age: None,
            allow_methods: Some(HeaderValue::from_static("GET, HEAD")),
            allow_headers: None,
            allow_expose_headers: None,
            allow_max_age: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AllowedOrigins {
    All,
    List(Box<[OriginPattern]>),
}

impl AllowedOrigins {
    pub const fn is_allow_all(&self) -> bool {
        matches!(self, Self::All)
    }

    pub fn matches(&self, origin: &[u8]) -> bool {
        match self {
            AllowedOrigins::All => true,
            AllowedOrigins::List(list) => list.iter().any(|p| p.matches(origin)),
        }
    }
}

impl TryFrom<&str> for AllowedOrigins {
    type Error = CorsConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.trim() == "*" {
            return Ok(Self::All);
        }

        Ok(Self::List(vec![OriginPattern::try_from(value)?].into_boxed_slice()))
    }
}

impl<'a> TryFrom<&'a [&'a str]> for AllowedOrigins {
    type Error = CorsConfigError;

    fn try_from(values: &'a [&'a str]) -> Result<Self, Self::Error> {
        if values.is_empty() {
            return Ok(Self::List(Box::new([])));
        }

        let mut list = Vec::with_capacity(values.len());

        for value in values {
            let value = value.trim();

            if value == "*" {
                if values.len() != 1 {
                    return Err(CorsConfigError::WildcardMixed);
                }

                return Ok(Self::All);
            }

            list.push(OriginPattern::try_from(value)?);
        }

        Ok(Self::List(list.into_boxed_slice()))
    }
}

impl<'a> TryFrom<Vec<&'a str>> for AllowedOrigins {
    type Error = CorsConfigError;

    fn try_from(value: Vec<&'a str>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<Vec<String>> for AllowedOrigins {
    type Error = CorsConfigError;

    fn try_from(values: Vec<String>) -> Result<Self, Self::Error> {
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        Self::try_from(refs.as_slice())
    }
}

#[derive(Debug, Clone)]
pub enum OriginPattern {
    Exact(Box<[u8]>),
    Wildcard(WildcardOrigin),
}

impl OriginPattern {
    pub fn matches(&self, origin: &[u8]) -> bool {
        match self {
            OriginPattern::Exact(allowed) => allowed.as_ref() == origin,
            OriginPattern::Wildcard(wilcard) => wilcard.matches(origin),
        }
    }
}

impl TryFrom<&str> for OriginPattern {
    type Error = CorsConfigError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (scheme, host) = sanitize_origin(value)?;

        if let Some(domain) = host.strip_prefix("*.") {
            if domain.is_empty() {
                return Err(CorsConfigError::InvalidWildcard(value.into()));
            }

            return Ok(Self::Wildcard(WildcardOrigin {
                scheme,
                suffix: format!(".{domain}").into_bytes().into_boxed_slice(),
            }));
        }

        let full_origin = format!("{}{host}", scheme.as_str()).into_bytes().into_boxed_slice();

        Ok(Self::Exact(full_origin))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Scheme::Http => b"http://".as_slice(),
            Scheme::Https => b"https://".as_slice(),
        }
    }

    pub const fn as_str(&self) -> &str {
        unsafe {
            // Always safe
            std::str::from_utf8_unchecked(self.as_bytes())
        }
    }
}

#[derive(Debug, Clone)]
pub struct WildcardOrigin {
    pub scheme: Scheme,
    pub suffix: Box<[u8]>,
}

impl WildcardOrigin {
    pub fn matches(&self, origin: &[u8]) -> bool {
        let scheme = self.scheme.as_bytes(); // e.g., b"https://"

        // Ensure the origin starts with the correct scheme
        let Some(host_part) = origin.strip_prefix(scheme) else {
            return false;
        };

        // (e.g., ".example.com")
        host_part.len() > self.suffix.len() && host_part.ends_with(&self.suffix)
    }
}

fn sanitize_origin(input: &str) -> Result<(Scheme, &str), CorsConfigError> {
    let input = input.trim();

    if input.is_empty() {
        return Err(CorsConfigError::EmptyOrigin);
    }

    if input.contains(char::is_whitespace) {
        return Err(CorsConfigError::ContainsWhitespace);
    }

    let (scheme, host) = if let Some(v) = input.strip_prefix("https://") {
        (Scheme::Https, v)
    } else if let Some(v) = input.strip_prefix("http://") {
        (Scheme::Http, v)
    } else if input.contains("://") {
        let scheme = input.split("://").next().unwrap_or("");
        return Err(CorsConfigError::InvalidScheme(scheme.into()));
    } else {
        (Scheme::Https, input)
    };

    if host.is_empty() {
        return Err(CorsConfigError::InvalidOrigin(input.into()));
    }

    if host.contains('/') || host.contains('?') || host.contains('#') {
        return Err(CorsConfigError::OriginContainsPath);
    }

    if host.contains('@') {
        return Err(CorsConfigError::OriginContainsCredentials);
    }

    if host.ends_with('.') || host.contains("..") {
        return Err(CorsConfigError::InvalidOrigin("malformed host structure".into()));
    }

    Ok((scheme, host))
}

#[cfg(test)]
mod cors_test {
    use super::*;

    #[test]
    fn parses_allow_all() {
        let origins = AllowedOrigins::try_from("*").unwrap();

        assert!(origins.is_allow_all());
    }

    #[test]
    fn parses_single_origin() {
        let origins = AllowedOrigins::try_from("https://example.com").unwrap();

        match origins {
            AllowedOrigins::List(list) => {
                assert_eq!(list.len(), 1);
            },
            _ => panic!(),
        }
    }

    #[test]
    fn parses_multiple_origins() {
        let origins = AllowedOrigins::try_from(vec!["https://example.com", "http://localhost:3000", "*.example.org"]).unwrap();

        match origins {
            AllowedOrigins::List(list) => assert_eq!(list.len(), 3),
            _ => panic!(),
        }
    }

    #[test]
    fn exact_origin_matches() {
        let p = OriginPattern::try_from("https://example.com").unwrap();

        assert!(p.matches(b"https://example.com"));
        assert!(!p.matches(b"www.example.com"));
        assert!(!p.matches(b"example.org"));
    }

    #[test]
    fn default_scheme_is_https() {
        let p = OriginPattern::try_from("example.com").unwrap();

        assert!(p.matches(b"https://example.com"));
    }

    // wildcard origin tests
    #[test]
    fn wildcard_matches_subdomains() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(p.matches(b"https://api.example.com"));
        assert!(p.matches(b"https://v1.api.example.com"));
    }

    #[test]
    fn wildcard_does_match_root_domain() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(!p.matches(b"example.com"));
    }

    #[test]
    fn wildcard_does_not_match_other_domain() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(!p.matches(b"example.org"));
        assert!(!p.matches(b"evil-example.com"));
    }

    // invalid wildcard
    #[test]
    fn rejects_invalid_wildcards() {
        assert!(OriginPattern::try_from("*.").is_err());
        assert!(OriginPattern::try_from("http://*.").is_err());
    }

    #[test]
    fn rejects_mixed_wildcard() {
        assert!(AllowedOrigins::try_from(vec!["*", "example.com",]).is_err());
    }

    #[test]
    fn empty_list_is_valid() {
        let origins = AllowedOrigins::try_from(Vec::<&str>::new()).unwrap();

        assert!(!origins.is_allow_all());
        assert!(!origins.matches(b"example.com"));
    }

    #[test]
    fn list_matches_any_origin() {
        let origins = AllowedOrigins::try_from(vec!["example.com", "*.example.org"]).unwrap();

        assert!(origins.matches(b"https://example.com"));
        assert!(origins.matches(b"https://api.example.org"));
        assert!(!origins.matches(b"google.com"));
    }

    // santization tests
    #[test]
    fn rejects_empty_origin() {
        assert!(OriginPattern::try_from("").is_err());
    }

    #[test]
    fn rejects_blank_origin() {
        assert!(OriginPattern::try_from("   ").is_err());
    }

    #[test]
    fn rejects_path() {
        assert!(OriginPattern::try_from("https://example.com/path").is_err());
    }

    #[test]
    fn rejects_query() {
        assert!(OriginPattern::try_from("https://example.com?q=1").is_err());
    }

    #[test]
    fn rejects_fragment() {
        assert!(OriginPattern::try_from("https://example.com#foo").is_err());
    }

    #[test]
    fn rejects_credentials() {
        assert!(OriginPattern::try_from("https://user@example.com").is_err());
    }

    #[test]
    fn rejects_invalid_scheme() {
        assert!(OriginPattern::try_from("ftp://example.com").is_err());
    }

    // limits
    #[test]
    fn wildcard_does_not_match_suffix_only() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(!p.matches(b"badexample.com"));
    }

    #[test]
    fn wildcard_requires_dot_boundary() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(!p.matches(b"myexample.com"));
    }

    #[test]
    fn wildcard_matches_deep_subdomains() {
        let p = OriginPattern::try_from("*.example.com").unwrap();

        assert!(p.matches(b"https://a.b.c.example.com"));
    }
}
