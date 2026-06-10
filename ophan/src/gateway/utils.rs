use std::borrow::Cow;
use std::net::SocketAddr;

pub fn get_real_client_ip<'a>(headers: &'a http::HeaderMap, peer_addr: Option<&SocketAddr>) -> Option<Cow<'a, str>> {
    if let Some(cf_ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return Some(Cow::Borrowed(cf_ip.trim()));
    }
    if let Some(true_ip) = headers.get("true-client-ip").and_then(|v| v.to_str().ok()) {
        return Some(Cow::Borrowed(true_ip.trim()));
    }

    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in forwarded.split(';') {
            let part = part.trim();
            if part.to_ascii_lowercase().starts_with("for=") {
                let ip = part.split('=').nth(1).unwrap_or("").trim().trim_matches('"');
                if !ip.is_empty() {
                    return Some(Cow::Borrowed(ip));
                }
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return Some(Cow::Borrowed(real_ip.trim()));
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first_ip) = xff.split(',').next()
    {
        let trimmed = first_ip.trim();
        if !trimmed.is_empty() {
            return Some(Cow::Borrowed(trimmed));
        }
    }

    peer_addr.map(|addr| Cow::Owned(addr.ip().to_string()))
}

const STR_SIZE: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackString {
    bytes: [u8; STR_SIZE],
    len: u8,
}

impl StackString {
    #[inline(always)]
    pub fn new(s: &str) -> Self {
        let mut bytes = [0u32 as u8; STR_SIZE];
        let len = s.len().min(STR_SIZE);
        bytes[..len].copy_from_slice(&s.as_bytes()[..len]);

        Self { bytes, len: len as u8 }
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.len as usize]) }
    }
}

impl std::ops::Deref for StackString {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}
