use flatkit::net::{IpNet, IpSet};
use std::net::IpAddr;

/// Connection access control of one listener, evaluated against the socket address.
///
/// `deny` always wins; a non-empty `allow` admits only its networks.
#[derive(Debug, Clone, Default)]
pub struct ListenerFirewall {
    allow: Option<IpSet>,
    deny: Option<IpSet>,
}

impl ListenerFirewall {
    pub fn new(allow: &[IpNet], deny: &[IpNet]) -> Self {
        Self { allow: Self::ip_set(allow), deny: Self::ip_set(deny) }
    }

    /// `true` when the firewall has no rule and admits everyone.
    pub fn is_open(&self) -> bool {
        self.allow.is_none() && self.deny.is_none()
    }

    #[inline]
    pub fn admits(&self, peer: IpAddr) -> bool {
        if self.deny.as_ref().is_some_and(|set| set.contains(peer)) {
            return false;
        }

        self.allow.as_ref().is_none_or(|set| set.contains(peer))
    }

    fn ip_set(ranges: &[IpNet]) -> Option<IpSet> {
        if ranges.is_empty() {
            return None;
        }

        let mut builder = IpSet::builder();
        for net in ranges {
            builder.insert_network(net);
        }

        Some(builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(ranges: &[&str]) -> Vec<IpNet> {
        ranges.iter().map(|r| r.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_firewall_admits_everyone() {
        let fw = ListenerFirewall::new(&[], &[]);
        assert!(fw.is_open());
        assert!(fw.admits(ip("203.0.113.1")));
    }

    #[test]
    fn deny_wins_over_allow() {
        let fw = ListenerFirewall::new(&nets(&["10.0.0.0/8"]), &nets(&["10.0.0.66/32"]));
        assert!(fw.admits(ip("10.1.2.3")));
        assert!(!fw.admits(ip("10.0.0.66")));
        assert!(!fw.admits(ip("192.0.2.1")));
    }

    #[test]
    fn deny_only_admits_the_rest() {
        let fw = ListenerFirewall::new(&[], &nets(&["203.0.113.0/24"]));
        assert!(!fw.admits(ip("203.0.113.9")));
        assert!(fw.admits(ip("198.51.100.1")));
    }

    #[test]
    fn mapped_ipv4_is_matched() {
        let fw = ListenerFirewall::new(&nets(&["10.0.0.0/8"]), &[]);
        assert!(fw.admits(ip("::ffff:10.0.0.1")));
    }
}
