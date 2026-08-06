use http::{HeaderMap, header};
use std::time::Duration;

pub const FLAG_NO_STORE: u8 = 0b0000_0001; // 1
pub const FLAG_NO_CACHE: u8 = 0b0000_0010; // 2
pub const FLAG_PRIVATE: u8 = 0b0000_0100; // 4
pub const FLAG_PUBLIC: u8 = 0b0000_1000; // 8
pub const FLAG_MUST_REVALIDATE: u8 = 0b0001_0000; // 16
pub const FLAG_PROXY_REVALIDATE: u8 = 0b0010_0000; // 32

#[derive(Debug, Default, Clone, Copy)]
pub struct CachePolicy {
    pub flags: u8,
    pub max_age: Option<Duration>,
    pub s_maxage: Option<Duration>,
}

impl CachePolicy {
    #[inline]
    pub fn is_nocacheable(&self) -> bool {
        (self.flags & (FLAG_NO_STORE | FLAG_PRIVATE)) != 0
    }

    #[inline]
    pub fn get_gateway_ttl(&self) -> Option<Duration> {
        self.s_maxage.or(self.max_age)
    }

    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut policy = CachePolicy::default();

        let cache_str = match headers.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
            Some(s) => s,
            None => return policy,
        };

        for directive in cache_str.split(',').map(|s| s.trim()) {
            match directive {
                "no-store" => policy.flags |= FLAG_NO_STORE,
                "no-cache" => policy.flags |= FLAG_NO_CACHE,
                "private" => policy.flags |= FLAG_PRIVATE,
                "public" => policy.flags |= FLAG_PUBLIC,
                "must-revalidate" => policy.flags |= FLAG_MUST_REVALIDATE,
                "proxy-revalidate" => policy.flags |= FLAG_PROXY_REVALIDATE,
                _ => {
                    if let Some(sec_str) = directive.strip_prefix("s-maxage=") {
                        if let Ok(secs) = sec_str.parse::<u64>() {
                            policy.s_maxage = Some(Duration::from_secs(secs));
                        }
                    } else if let Some(sec_str) = directive.strip_prefix("max-age=") {
                        if let Ok(secs) = sec_str.parse::<u64>() {
                            policy.max_age = Some(Duration::from_secs(secs));
                        }
                    }
                },
            }
        }

        policy
    }
}
