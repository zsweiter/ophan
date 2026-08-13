use core::fmt;
use core::str::FromStr;

/// Errors that can occur when parsing a [`TlsVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsParseError {
    /// The provided string or token did not match any known TLS version.
    InvalidVersion,
    /// The input provided was empty or contained no valid tokens.
    EmptyInput,
}

impl fmt::Display for TlsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion => write!(
                f,
                "invalid TLS version, expected one of: tls12, tls1.2, 1.2, tls13, tls1.3, 1.3"
            ),
            Self::EmptyInput => write!(f, "TLS version input cannot be empty"),
        }
    }
}

impl std::error::Error for TlsParseError {}

/// Represents supported TLS protocol floor or explicit version constraints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// Allow both TLS 1.2 and TLS 1.3 (Highly Recommended)
    /// This matches AWS 'ELBSecurityPolicy-TLS13-1-2' behavior.
    ///
    /// Provides broad client compatibility while enabling modern cipher suites
    /// and negotiation for clients supporting TLS 1.3.
    #[default]
    Tls12,

    /// Enforce strictly TLS 1.3 (Exclusive)
    /// Disables TLS 1.2 entirely. Matches AWS 'ELBSecurityPolicy-TLS13-1-3'.
    ///
    /// Maximize security and privacy by dropping legacy handshake mechanisms,
    /// at the cost of compatibility with older clients or legacysystems.
    Tls13,
}

impl TlsVersion {
    /// Returns the official TLS protocol version hexadecimal representation.
    /// This matches the constants used by BoringSSL/OpenSSL (`TLS1_2_VERSION` and `TLS1_3_VERSION`).
    pub const fn to_hex(self) -> u16 {
        match self {
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    /// Returns the exact s2n-tls security policy identifier.
    pub const fn to_s2n_policy(self) -> &'static str {
        match self {
            // "default_tls13" is industry standard for TLS 1.2 floor with TLS 1.3 preferences
            Self::Tls12 => "default_tls13",
            // This forces strict 1.3 exclusive handshakes
            Self::Tls13 => "20240415",
        }
    }

    /// Evaluates a slice or sequence of version tokens and resolves the effective [`TlsVersion`].
    ///
    /// If TLS 1.2 is present anywhere in the list, [`TlsVersion::Tls12`] is selected as the minimum floor.
    /// If only TLS 1.3 tokens are present, [`TlsVersion::Tls13`] is enforced exclusively.
    pub fn resolve_from_tokens<'a, I>(tokens: I) -> Result<Self, TlsParseError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut has_12 = false;
        let mut has_13 = false;
        let mut count = 0;

        for token in tokens {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            match Self::parse_single_token(trimmed) {
                Ok(Self::Tls12) => has_12 = true,
                Ok(Self::Tls13) => has_13 = true,
                Err(e) => return Err(e),
            }
            count += 1;
        }

        if count == 0 {
            return Err(TlsParseError::EmptyInput);
        }

        if has_12 {
            Ok(Self::Tls12)
        } else if has_13 {
            Ok(Self::Tls13)
        } else {
            Err(TlsParseError::InvalidVersion)
        }
    }

    #[inline]
    fn parse_single_token(token: &str) -> Result<Self, TlsParseError> {
        if token.eq_ignore_ascii_case("tls12")
            || token.eq_ignore_ascii_case("tls1.2")
            || token.eq_ignore_ascii_case("tlsv1.2")
            || token.eq_ignore_ascii_case("1.2")
        {
            Ok(Self::Tls12)
        } else if token.eq_ignore_ascii_case("tls13")
            || token.eq_ignore_ascii_case("tls1.3")
            || token.eq_ignore_ascii_case("tlsv1.3")
            || token.eq_ignore_ascii_case("1.3")
        {
            Ok(Self::Tls13)
        } else {
            Err(TlsParseError::InvalidVersion)
        }
    }
}

// Standard FromStr parsing for single values or whitespace-separated strings
impl FromStr for TlsVersion {
    type Err = TlsParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(TlsParseError::EmptyInput);
        }

        if trimmed.contains(' ') || trimmed.contains(',') {
            Self::resolve_from_tokens(trimmed.split_matches_or_whitespace())
        } else {
            Self::parse_single_token(trimmed)
        }
    }
}

// Helper trait to split string without heap allocations
trait SplitExt<'a> {
    fn split_matches_or_whitespace(self) -> impl Iterator<Item = &'a str>;
}

impl<'a> SplitExt<'a> for &'a str {
    #[inline]
    fn split_matches_or_whitespace(self) -> impl Iterator<Item = &'a str> {
        self.split(|c: char| c.is_whitespace() || c == ',').map(str::trim).filter(|s| !s.is_empty())
    }
}

impl TryFrom<&str> for TlsVersion {
    type Error = TlsParseError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

// Support for Vec<&str>
impl TryFrom<Vec<&str>> for TlsVersion {
    type Error = TlsParseError;

    #[inline]
    fn try_from(values: Vec<&str>) -> Result<Self, Self::Error> {
        Self::resolve_from_tokens(values)
    }
}

// Support for &[&str] slices directly
impl<'a> TryFrom<&[&'a str]> for TlsVersion {
    type Error = TlsParseError;

    #[inline]
    fn try_from(values: &[&'a str]) -> Result<Self, Self::Error> {
        Self::resolve_from_tokens(values.iter().copied())
    }
}

impl From<TlsVersion> for &'static str {
    fn from(value: TlsVersion) -> Self {
        match value {
            TlsVersion::Tls12 => "tls12",
            TlsVersion::Tls13 => "tls13",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_from_str_tls12() {
        for s in &["tls12", "tls1.2", "1.2"] {
            assert_eq!(TlsVersion::try_from(*s).unwrap(), TlsVersion::Tls12);
        }
    }

    #[test]
    fn test_tls_version_from_str_tls13() {
        for s in &["tls13", "tls1.3", "1.3"] {
            assert_eq!(TlsVersion::try_from(*s).unwrap(), TlsVersion::Tls13);
        }
    }

    #[test]
    fn test_tls_version_invalid() {
        let err = TlsVersion::try_from("tls1.0").unwrap_err();
        assert_eq!(err, TlsParseError::InvalidVersion);
    }

    #[test]
    fn test_tls_version_to_hex() {
        assert_eq!(TlsVersion::Tls12.to_hex(), 0x0303);
        assert_eq!(TlsVersion::Tls13.to_hex(), 0x0304);
    }

    #[test]
    fn test_tls_version_to_s2n_policy() {
        assert_eq!(TlsVersion::Tls12.to_s2n_policy(), "default_tls13");
        assert_eq!(TlsVersion::Tls13.to_s2n_policy(), "20240415");
    }

    #[test]
    fn test_tls_version_into_static_str() {
        let s: &'static str = TlsVersion::Tls12.into();
        assert_eq!(s, "tls12");
        let s: &'static str = TlsVersion::Tls13.into();
        assert_eq!(s, "tls13");
    }
}
