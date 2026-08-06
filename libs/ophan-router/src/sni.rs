use ahash::AHashMap;

/// Maximum valid DNS hostname length.
pub const MAX_SNI_LEN: usize = 1024;

/// Maximum number of DNS labels accepted during lookup.
///
/// Example:
/// - `api.example.com` => 3 labels
///
/// This prevents pathological hostnames from forcing excessive
/// wildcard lookups.
pub const MAX_LABELS: usize = 32;

/// Fast SNI router with exact and wildcard matching.
///
/// Supported routes:
/// - `example.com`
/// - `*.example.com`
///
/// No allocations are performed during routing.
#[derive(Debug, Default)]
pub struct SniTableRouter {
    exact: AHashMap<Box<str>, u32>,
    wildcard: AHashMap<Box<str>, u32>,
}

impl SniTableRouter {
    /// Creates an empty router.
    #[inline]
    pub fn new() -> Self {
        Self {
            exact: AHashMap::with_capacity(2),
            wildcard: AHashMap::with_capacity(1),
        }
    }

    /// Registers an exact or wildcard route.
    ///
    /// Wildcard routes must use the `*.domain.tld` format.
    #[inline]
    pub fn add_route(&mut self, host: &str, target_id: u32) {
        if let Some(suffix) = host.strip_prefix("*.") {
            self.wildcard.insert(suffix.into(), target_id);
        } else {
            self.exact.insert(host.into(), target_id);
        }
    }

    /// Resolves a target id from an SNI hostname.
    ///
    /// Returns `None` when:
    /// - the hostname is empty;
    /// - the hostname exceeds configured limits;
    /// - no route matches.
    ///
    /// Exact routes take precedence over wildcards.
    /// TODO: Handle error like MAX_SNI_LEN and MAX_LABELS
    #[inline]
    pub fn route(&self, sni: &str) -> Option<u32> {
        let len = sni.len();

        if len == 0 || len > MAX_SNI_LEN {
            return None;
        }

        if let Some(id) = self.exact.get(sni) {
            return Some(*id);
        }

        let bytes = sni.as_bytes();
        let mut labels = 1;

        for (i, &b) in bytes.iter().enumerate() {
            if b == b'.' {
                labels += 1;

                if labels > MAX_LABELS {
                    return None;
                }

                let suffix = unsafe { sni.get_unchecked(i + 1..) };

                if let Some(id) = self.wildcard.get(suffix) {
                    return Some(*id);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let mut router = SniTableRouter::new();

        router.add_route("example.com", 10);

        assert_eq!(router.route("example.com"), Some(10));
    }

    #[test]
    fn exact_has_priority_over_wildcard() {
        let mut router = SniTableRouter::new();

        router.add_route("*.example.com", 1);
        router.add_route("api.example.com", 2);

        assert_eq!(router.route("api.example.com"), Some(2));
    }

    #[test]
    fn wildcard_match() {
        let mut router = SniTableRouter::new();

        router.add_route("*.example.com", 1);

        assert_eq!(router.route("api.example.com"), Some(1));
        assert_eq!(router.route("test.example.com"), Some(1));
    }

    #[test]
    fn wildcard_matches_nested_subdomains() {
        let mut router = SniTableRouter::new();

        router.add_route("*.example.com", 1);

        assert_eq!(router.route("foo.bar.example.com"), Some(1));
    }

    #[test]
    fn wildcard_does_not_match_root_domain() {
        let mut router = SniTableRouter::new();

        router.add_route("*.example.com", 1);

        assert_eq!(router.route("example.com"), None);
    }

    #[test]
    fn unknown_host_returns_none() {
        let mut router = SniTableRouter::new();

        router.add_route("example.com", 1);

        assert_eq!(router.route("other.com"), None);
    }

    #[test]
    fn empty_sni_returns_none() {
        let router = SniTableRouter::new();

        assert_eq!(router.route(""), None);
    }

    #[test]
    fn multiple_wildcards() {
        let mut router = SniTableRouter::new();

        router.add_route("*.example.com", 1);
        router.add_route("*.internal.net", 2);

        assert_eq!(router.route("api.example.com"), Some(1));
        assert_eq!(router.route("db.internal.net"), Some(2));
    }

    #[test]
    fn oversized_sni_returns_none() {
        let router = SniTableRouter::new();

        let host = "a".repeat(MAX_SNI_LEN + 1);

        assert_eq!(router.route(&host), None);
    }

    #[test]
    fn too_many_labels_returns_none() {
        let router = SniTableRouter::new();

        let host = "a.".repeat(MAX_LABELS + 1) + "com";

        assert_eq!(router.route(&host), None);
    }

    #[test]
    fn wildcard_root_suffix_match() {
        let mut router = SniTableRouter::new();

        router.add_route("*.com", 42);

        assert_eq!(router.route("example.com"), Some(42));
        assert_eq!(router.route("api.example.com"), Some(42));
    }
}
