use flatkit::net::IpNet;
use http::{HeaderMap, HeaderName};
use ophan_net::http::header;
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    /// Immediately drops or rejects the request to prevent upstream IP spoofing.
    #[default]
    Deny,
    /// Graceful fallback: Ignores the application-layer identity headers and safely
    /// degrades trust by using the Layer 4 socket remote IP as the client's real IP.
    Degrade,
}

impl TryFrom<&str> for PolicyMode {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase().as_str() {
            "deny" => Ok(Self::Deny),
            "degrade" => Ok(Self::Degrade),
            _ => Err(format!(
                "Invalid network policy mode: '{value}'. Expected one of: 'deny', 'degrade'"
            )),
        }
    }
}

/// Unified Ingress Network Policy (Layer 4 + Layer 7 context).
#[derive(Debug, Clone)]
pub struct NetPolicy {
    /// The specific HTTP header used to retrieve the authentic client IP (e.g., `X-Forwarded-For`).
    /// This header is strictly processed *only* if the connection originates from an allowed range.
    pub real_ip_header: HeaderName,
    /// CIDR network ranges authorized at the transport level (Inbound Whitelist / Trusted Proxies).
    pub allowed_ip_ranges: Arc<Vec<IpNet>>,
    /// CIDR network ranges slated for immediate inline dropping at the ingress boundary (Inbound Blacklist).
    pub blocked_ip_ranges: Option<Arc<Vec<IpNet>>>,
    /// Enforcement behavior executed when a socket remote IP falls outside of the `allowed_ip_ranges`.
    pub policy: PolicyMode,
}

impl NetPolicy {
    pub fn new(real_ip_header: HeaderName, allowed_ip_ranges: Vec<IpNet>) -> Self {
        Self {
            real_ip_header,
            allowed_ip_ranges: Arc::new(allowed_ip_ranges),
            blocked_ip_ranges: None,
            policy: PolicyMode::default(),
        }
    }

    pub fn builder(real_ip_header: HeaderName, allowed_ip_ranges: Vec<IpNet>) -> NetPolicyBuilder {
        NetPolicyBuilder::new(real_ip_header, allowed_ip_ranges)
    }

    pub fn get_real_ip(&self, socket_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        let canonical_socket = socket_ip.to_canonical();

        match self.policy {
            // Short-circuit: True Public Edge deployment. Bypass headers to prevent L7 spoofing.
            PolicyMode::Degrade => canonical_socket,

            // Infrastructure Protected Mode.
            PolicyMode::Deny => {
                // is safe retrieve header ip because connection filter Droped unstrusted connections
                if let Some(header_ip) = self.extract_header_ip(headers) {
                    return header_ip;
                }

                // Fallback: If the socket is untrusted, or if the trusted proxy omitted/corrupted
                // the header, safely fall back to the physical socket address.
                canonical_socket
            },
        }
    }

    /// Extracts the client's IP address from HTTP headers using a target header config.
    ///
    /// # ⚠️ Security Warning
    /// **Do not use this function on the True Edge (exposed directly to the internet).**
    /// It does not verify the TCP socket. Anyone can spoof these headers. Only call this
    /// if you have already verified that the incoming socket IP belongs to a trusted proxy (e.g., Cloudflare).
    ///
    /// # Evaluation examples
    /// - `cf-connecting-ip` (Cloudflare Edge)
    /// - `true-client-ip` (Akamai / Cloudflare Enterprise)
    /// - `x-real-ip` (Nginx / standard reverse proxy)
    /// - `x-forwarded-for` (Left-most / first element only)
    ///
    #[inline(always)]
    fn extract_header_ip(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let header_value = headers.get(&self.real_ip_header).and_then(|v| v.to_str().ok())?;

        // RFC 7239 Standardized "Forwarded" Header
        if self.real_ip_header == header::FORWARDED {
            return parse_rfc7239_forwarded(header_value);
        }

        // Legacy De-facto Standard "X-Forwarded-For"
        if self.real_ip_header == header::X_FORWARDED_FOR {
            if let Some(first_ip_str) = header_value.split(',').next() {
                if let Ok(ip) = first_ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
            return None;
        }

        // Single IP Value Headers (e.g., CF-Connecting-IP, X-Real-IP)
        header_value.trim().parse::<IpAddr>().ok()
    }
}

#[derive(Debug)]
pub struct NetPolicyBuilder {
    real_ip_header: HeaderName,
    allowed_ip_ranges: Vec<IpNet>,
    blocked_ip_ranges: Option<Vec<IpNet>>,
    policy: PolicyMode,
}

impl NetPolicyBuilder {
    pub fn new(real_ip_header: HeaderName, allowed_ip_ranges: Vec<IpNet>) -> Self {
        Self {
            real_ip_header,
            allowed_ip_ranges,
            blocked_ip_ranges: None,
            policy: PolicyMode::default(),
        }
    }

    pub fn with_blocked_ranges(mut self, blocked_ranges: Vec<IpNet>) -> Self {
        self.blocked_ip_ranges = Some(blocked_ranges);
        self
    }

    pub fn with_policy_mode(mut self, policy: PolicyMode) -> Self {
        self.policy = policy;
        self
    }

    pub fn build(self) -> NetPolicy {
        NetPolicy {
            real_ip_header: self.real_ip_header,
            allowed_ip_ranges: Arc::new(self.allowed_ip_ranges),
            blocked_ip_ranges: self.blocked_ip_ranges.map(Arc::new),
            policy: self.policy,
        }
    }
}

/// Matches: `Forwarded: for=192.0.2.60;proto=http, for="[2001:db8:cafe::17]:4711"`
fn parse_rfc7239_forwarded(value: &str) -> Option<IpAddr> {
    // Isolated to the first hop entry (left-most proxy entry before the first comma)
    let first_hop = value.split(',').next()?;

    // Scan semi-colon separated directives for the "for=" token
    for directive in first_hop.split(';') {
        let mut kv = directive.splitn(2, '=');
        let key = kv.next()?.trim();
        let val = kv.next()?.trim();

        if key.eq_ignore_ascii_case("for") {
            // Strip wrapper quotes if present (common for IPv6 or ports: "[2001:db8::1]:443")
            let mut cleaned = val.strip_prefix('"').unwrap_or(val).strip_suffix('"').unwrap_or(val);

            // If it contains a port or is bracketed IPv6, isolate the pure IP address segment
            if cleaned.starts_with('[') {
                if let Some(end_bracket) = cleaned.find(']') {
                    cleaned = &cleaned[1..end_bracket];
                }
            } else if let Some(colon_idx) = cleaned.find(':') {
                // For IPv4 (e.g. 1.1.1.1:80), verify it's a port delimiter and not an IPv6 address
                if cleaned.match_indices(':').count() == 1 {
                    cleaned = &cleaned[..colon_idx];
                }
            }

            if let Ok(ip) = cleaned.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}
