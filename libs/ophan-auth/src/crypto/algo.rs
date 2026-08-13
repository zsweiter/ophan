use serde::{Deserialize, Serialize};
use std::{ops::Deref, str::FromStr};

/// HMAC algorithm variants for symmetric key validation.
///
/// Used in `AuthMode::Static` with inline `secret_key` configuration.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum HmacAlg {
    #[default]
    HS256,
    HS384,
    HS512,
}

impl FromStr for HmacAlg {
    type Err = jsonwebtoken::errors::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            _ => Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl From<HmacAlg> for jsonwebtoken::Algorithm {
    #[inline]
    fn from(value: HmacAlg) -> Self {
        match value {
            HmacAlg::HS256 => Self::HS256,
            HmacAlg::HS384 => Self::HS384,
            HmacAlg::HS512 => Self::HS512,
        }
    }
}

impl Deref for HmacAlg {
    type Target = jsonwebtoken::Algorithm;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::HS256 => &jsonwebtoken::Algorithm::HS256,
            Self::HS384 => &jsonwebtoken::Algorithm::HS384,
            Self::HS512 => &jsonwebtoken::Algorithm::HS512,
        }
    }
}

/// Asymmetric signature algorithms.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum SignatureAlg {
    /// ECDSA using SHA-256.
    ES256,

    /// ECDSA using SHA-384.
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,

    /// RSASSA-PSS using SHA-256.
    PS256,

    /// RSASSA-PSS using SHA-384.
    PS384,

    /// RSASSA-PSS using SHA-512.
    PS512,

    /// Edwards-curve Digital Signature Algorithm (EdDSA).
    #[default]
    EdDSA,
}

impl From<SignatureAlg> for jsonwebtoken::Algorithm {
    #[inline]
    fn from(value: SignatureAlg) -> Self {
        match value {
            SignatureAlg::ES256 => Self::ES256,
            SignatureAlg::ES384 => Self::ES384,
            SignatureAlg::RS256 => Self::RS256,
            SignatureAlg::RS384 => Self::RS384,
            SignatureAlg::RS512 => Self::RS512,
            SignatureAlg::PS256 => Self::PS256,
            SignatureAlg::PS384 => Self::PS384,
            SignatureAlg::PS512 => Self::PS512,
            SignatureAlg::EdDSA => Self::EdDSA,
        }
    }
}

impl Deref for SignatureAlg {
    type Target = jsonwebtoken::Algorithm;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::ES256 => &jsonwebtoken::Algorithm::ES256,
            Self::ES384 => &jsonwebtoken::Algorithm::ES384,
            Self::RS256 => &jsonwebtoken::Algorithm::RS256,
            Self::RS384 => &jsonwebtoken::Algorithm::RS384,
            Self::RS512 => &jsonwebtoken::Algorithm::RS512,
            Self::PS256 => &jsonwebtoken::Algorithm::PS256,
            Self::PS384 => &jsonwebtoken::Algorithm::PS384,
            Self::PS512 => &jsonwebtoken::Algorithm::PS512,
            Self::EdDSA => &jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

/// Supported JWT algorithms.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256.
    #[default]
    HS256,

    /// HMAC using SHA-384.
    HS384,

    /// HMAC using SHA-512.
    HS512,

    /// ECDSA using SHA-256.
    ES256,

    /// ECDSA using SHA-384.
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,

    /// RSASSA-PSS using SHA-256.
    PS256,

    /// RSASSA-PSS using SHA-384.
    PS384,

    /// RSASSA-PSS using SHA-512.
    PS512,

    /// Edwards-curve Digital Signature Algorithm (EdDSA).
    EdDSA,
}

impl FromStr for Algorithm {
    type Err = jsonwebtoken::errors::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "EdDSA" => Ok(Self::EdDSA),
            _ => Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName.into()),
        }
    }
}

impl From<Algorithm> for jsonwebtoken::Algorithm {
    #[inline]
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::HS256 => Self::HS256,
            Algorithm::HS384 => Self::HS384,
            Algorithm::HS512 => Self::HS512,
            Algorithm::ES256 => Self::ES256,
            Algorithm::ES384 => Self::ES384,
            Algorithm::RS256 => Self::RS256,
            Algorithm::RS384 => Self::RS384,
            Algorithm::RS512 => Self::RS512,
            Algorithm::PS256 => Self::PS256,
            Algorithm::PS384 => Self::PS384,
            Algorithm::PS512 => Self::PS512,
            Algorithm::EdDSA => Self::EdDSA,
        }
    }
}

impl Deref for Algorithm {
    type Target = jsonwebtoken::Algorithm;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::HS256 => &jsonwebtoken::Algorithm::HS256,
            Self::HS384 => &jsonwebtoken::Algorithm::HS384,
            Self::HS512 => &jsonwebtoken::Algorithm::HS512,
            Self::ES256 => &jsonwebtoken::Algorithm::ES256,
            Self::ES384 => &jsonwebtoken::Algorithm::ES384,
            Self::RS256 => &jsonwebtoken::Algorithm::RS256,
            Self::RS384 => &jsonwebtoken::Algorithm::RS384,
            Self::RS512 => &jsonwebtoken::Algorithm::RS512,
            Self::PS256 => &jsonwebtoken::Algorithm::PS256,
            Self::PS384 => &jsonwebtoken::Algorithm::PS384,
            Self::PS512 => &jsonwebtoken::Algorithm::PS512,
            Self::EdDSA => &jsonwebtoken::Algorithm::EdDSA,
        }
    }
}
