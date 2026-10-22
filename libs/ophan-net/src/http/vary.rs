use bitflags::bitflags;
use http::HeaderValue;
use http::header;

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

impl VarySet {
    /// Adds these tokens to the response `Vary`, keeping the tokens it already has.
    pub fn merge_into(self, response: &mut crate::proxy::ResponseParts) {
        if self.is_empty() {
            return;
        }

        let mut present = VarySet::empty();
        let mut received = 0;

        for value in response.headers.get_all(header::VARY) {
            received += value.len() + 2;
            for token in value.as_bytes().split(|b| *b == b',') {
                present |= Self::from_token(token.trim_ascii());
            }
        }

        if received == 0 {
            if let Some(value) = Option::<HeaderValue>::from(self) {
                let _ = response.insert_header(crate::http::header::wire::VARY, value);
            }
            return;
        }

        let missing = self.difference(present);
        if present.contains(VarySet::STAR) || missing.is_empty() {
            return;
        }

        let mut merged = Vec::with_capacity(received + 64);
        for value in response.headers.get_all(header::VARY) {
            if !merged.is_empty() {
                merged.extend_from_slice(b", ");
            }
            merged.extend_from_slice(value.as_bytes());
        }
        missing.write_tokens(&mut merged);

        if let Ok(value) = HeaderValue::from_maybe_shared(bytes::Bytes::from(merged)) {
            let _ = response.insert_header(crate::http::header::wire::VARY, value);
        }
    }

    fn from_token(token: &[u8]) -> VarySet {
        ALL_VARIES
            .iter()
            .find(|(_, vary)| vary.as_str().as_bytes().eq_ignore_ascii_case(token))
            .map_or(VarySet::empty(), |(flag, _)| *flag)
    }

    fn write_tokens(self, out: &mut Vec<u8>) {
        for (flag, vary) in ALL_VARIES {
            if self.contains(flag) {
                if !out.is_empty() {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(vary.as_str().as_bytes());
            }
        }
    }
}

impl From<VarySet> for Option<HeaderValue> {
    fn from(vary_set: VarySet) -> Self {
        if vary_set.is_empty() {
            return None;
        }
        if vary_set == VarySet::ORIGIN {
            return Some(HeaderValue::from_static("origin"));
        }

        let mut value = Vec::with_capacity(64);
        vary_set.write_tokens(&mut value);
        HeaderValue::from_maybe_shared(bytes::Bytes::from(value)).ok()
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

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::proxy::ResponseParts;

    fn response_with_vary(values: &[&'static str]) -> ResponseParts {
        let mut res = ResponseParts::build(200, None).unwrap();
        for v in values {
            res.append_header(header::VARY, HeaderValue::from_static(v)).unwrap();
        }
        res
    }

    fn vary_of(res: &ResponseParts) -> Vec<String> {
        res.headers.get_all(header::VARY).iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }

    #[test]
    fn keeps_upstream_tokens() {
        let mut res = response_with_vary(&["Accept-Encoding"]);
        VarySet::ORIGIN.merge_into(&mut res);
        assert_eq!(vary_of(&res), vec!["Accept-Encoding, origin"]);
    }

    #[test]
    fn does_not_duplicate_tokens() {
        let mut res = response_with_vary(&["origin"]);
        VarySet::ORIGIN.merge_into(&mut res);
        assert_eq!(vary_of(&res), vec!["origin"]);
    }

    #[test]
    fn matches_tokens_case_insensitively() {
        let mut res = response_with_vary(&["Accept-Encoding, ORIGIN"]);
        (VarySet::ORIGIN | VarySet::ACCEPT).merge_into(&mut res);
        assert_eq!(vary_of(&res), vec!["Accept-Encoding, ORIGIN, accept"]);
    }

    #[test]
    fn star_is_left_alone() {
        let mut res = response_with_vary(&["*"]);
        VarySet::ORIGIN.merge_into(&mut res);
        assert_eq!(vary_of(&res), vec!["*"]);
    }

    #[test]
    fn inserts_when_absent() {
        let mut res = response_with_vary(&[]);
        VarySet::ORIGIN.merge_into(&mut res);
        assert_eq!(vary_of(&res), vec!["origin"]);
    }
}
