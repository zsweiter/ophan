use bitflags::bitflags;
use http::HeaderValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vary {
    Star, // wilcard "*"
    Origin,
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    AcceptCharset,
    AccessControlRequestMethod,
    AccessControlRequestHeaders,
    UserAgent,
    Cookie,
    Authorization,
    SecFetchDest,
    SecFetchMode,
    SecFetchSite,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
}

impl Vary {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Star => "*",
            Self::Origin => "origin",
            Self::Accept => "accept",
            Self::AcceptEncoding => "accept-encoding",
            Self::AcceptLanguage => "accept-language",
            Self::AcceptCharset => "accept-charset",
            Self::AccessControlRequestMethod => "access-control-request-method",
            Self::AccessControlRequestHeaders => "access-control-request-headers",
            Self::UserAgent => "user-agent",
            Self::Cookie => "cookie",
            Self::Authorization => "authorization",
            Self::SecFetchDest => "sec-fetch-dest",
            Self::SecFetchMode => "sec-fetch-mode",
            Self::SecFetchSite => "sec-fetch-site",
            Self::SecChUa => "sec-ch-ua",
            Self::SecChUaMobile => "sec-ch-ua-mobile",
            Self::SecChUaPlatform => "sec-ch-ua-platform",
        }
    }
}

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VarySet: u32 {
        const STAR                           = 1 << 0;
        const ORIGIN                         = 1 << 1;
        const ACCEPT                         = 1 << 2;
        const ACCEPT_ENCODING                = 1 << 3;
        const ACCEPT_LANGUAGE                = 1 << 4;
        const ACCEPT_CHARSET                 = 1 << 5;
        const ACCESS_CONTROL_REQUEST_METHOD   = 1 << 6;
        const ACCESS_CONTROL_REQUEST_HEADERS  = 1 << 7;
        const USER_AGENT                     = 1 << 8;
        const COOKIE                         = 1 << 9;
        const AUTHORIZATION                  = 1 << 10;
        const SEC_FETCH_DEST                 = 1 << 11;
        const SEC_FETCH_MODE                 = 1 << 12;
        const SEC_FETCH_SITE                 = 1 << 13;
        const SEC_CH_UA                      = 1 << 14;
        const SEC_CH_UA_MOBILE               = 1 << 15;
        const SEC_CH_UA_PLATFORM             = 1 << 16;
    }
}

impl From<Vary> for VarySet {
    #[inline]
    fn from(vary: Vary) -> Self {
        match vary {
            Vary::Star => Self::STAR,
            Vary::Origin => Self::ORIGIN,
            Vary::Accept => Self::ACCEPT,
            Vary::AcceptEncoding => Self::ACCEPT_ENCODING,
            Vary::AcceptLanguage => Self::ACCEPT_LANGUAGE,
            Vary::AcceptCharset => Self::ACCEPT_CHARSET,
            Vary::AccessControlRequestMethod => Self::ACCESS_CONTROL_REQUEST_METHOD,
            Vary::AccessControlRequestHeaders => Self::ACCESS_CONTROL_REQUEST_HEADERS,
            Vary::UserAgent => Self::USER_AGENT,
            Vary::Cookie => Self::COOKIE,
            Vary::Authorization => Self::AUTHORIZATION,
            Vary::SecFetchDest => Self::SEC_FETCH_DEST,
            Vary::SecFetchMode => Self::SEC_FETCH_MODE,
            Vary::SecFetchSite => Self::SEC_FETCH_SITE,
            Vary::SecChUa => Self::SEC_CH_UA,
            Vary::SecChUaMobile => Self::SEC_CH_UA_MOBILE,
            Vary::SecChUaPlatform => Self::SEC_CH_UA_PLATFORM,
        }
    }
}

impl std::fmt::Display for VarySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;

        for (flag, vary) in ALL_VARIES {
            if self.contains(flag) {
                if !first {
                    f.write_str(", ")?;
                }
                f.write_str(vary.as_str())?;
                first = false;
            }
        }
        Ok(())
    }
}

impl From<VarySet> for Option<HeaderValue> {
    fn from(vary_set: VarySet) -> Self {
        if vary_set.is_empty() {
            None
        } else {
            HeaderValue::from_str(&vary_set.to_string()).ok()
        }
    }
}

const ALL_VARIES: [(VarySet, Vary); 17] = [
    (VarySet::STAR, Vary::Star),
    (VarySet::ORIGIN, Vary::Origin),
    (VarySet::ACCEPT, Vary::Accept),
    (VarySet::ACCEPT_ENCODING, Vary::AcceptEncoding),
    (VarySet::ACCEPT_LANGUAGE, Vary::AcceptLanguage),
    (VarySet::ACCEPT_CHARSET, Vary::AcceptCharset),
    (VarySet::ACCESS_CONTROL_REQUEST_METHOD, Vary::AccessControlRequestMethod),
    (VarySet::ACCESS_CONTROL_REQUEST_HEADERS, Vary::AccessControlRequestHeaders),
    (VarySet::USER_AGENT, Vary::UserAgent),
    (VarySet::COOKIE, Vary::Cookie),
    (VarySet::AUTHORIZATION, Vary::Authorization),
    (VarySet::SEC_FETCH_DEST, Vary::SecFetchDest),
    (VarySet::SEC_FETCH_MODE, Vary::SecFetchMode),
    (VarySet::SEC_FETCH_SITE, Vary::SecFetchSite),
    (VarySet::SEC_CH_UA, Vary::SecChUa),
    (VarySet::SEC_CH_UA_MOBILE, Vary::SecChUaMobile),
    (VarySet::SEC_CH_UA_PLATFORM, Vary::SecChUaPlatform),
];
