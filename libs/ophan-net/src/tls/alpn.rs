use std::str::FromStr;

/// The protocol for Application-Layer Protocol Negotiation, (IANA identifiers for now)
#[derive(Hash, Clone, Debug, PartialEq, PartialOrd, Default, Eq)]
pub enum ALPN {
    /// Prefer HTTP/1.1 only
    H1,
    /// Prefer HTTP/2 only
    #[default]
    H2,
    /// Prefer HTTP/2 over HTTP/1.1
    H2H1,
}

impl FromStr for ALPN {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "h1" | "http/1.1" | "http11" => Ok(Self::H1),
            "h2" | "http/2" | "http2" => Ok(Self::H2),

            "h2h1" | "h2,h1" | "h2, h1" | "h2/h1" | "http/2,http/1.1" => Ok(Self::H2H1),
            _ => Err(format!(
                "invalid ALPN protocol '{s}', expected one of: h1, h2, h2h1 (or standard IANA identifiers)"
            )),
        }
    }
}

impl TryFrom<&str> for ALPN {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ALPN> for Vec<String> {
    fn from(alpn: ALPN) -> Self {
        match alpn {
            ALPN::H1 => vec!["http/1.1".to_string()],
            ALPN::H2 => vec!["h2".to_string()],
            ALPN::H2H1 => vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }
}
