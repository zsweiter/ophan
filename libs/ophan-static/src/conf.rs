use flatkit::matchers::GlobSet;
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::fs::security::{FsFlags, SecurityHeaders};

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub root: PathBuf,
    pub skip_patterns: Option<GlobSet>,
    pub flags: FsFlags,
    pub security_headers: SecurityHeaders,
    pub cache_ttl: Option<Duration>,
    pub indexes: Option<Box<[Cow<'static, str>]>>,
}

impl ServeConfig {
    /// Create a new `ServeConfig` with a document root and secure defaults.
    #[inline]
    pub fn new<P>(root: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            root: root.into(),
            skip_patterns: None,
            flags: FsFlags::secure(),
            security_headers: SecurityHeaders::default(),
            cache_ttl: None,
            indexes: None,
        }
    }

    /// Create a config with a custom set of filesystem flags.
    #[inline]
    pub fn with_flags<P>(root: P, flags: FsFlags) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            root: root.into(),
            skip_patterns: None,
            flags,
            security_headers: SecurityHeaders::default(),
            cache_ttl: None,
            indexes: None,
        }
    }

    /// Create a config with glob-based skip patterns.
    #[inline]
    pub fn with_skip_patterns<P>(root: P, skip_patterns: GlobSet) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            root: root.into(),
            skip_patterns: Some(skip_patterns),
            flags: FsFlags::secure(),
            security_headers: SecurityHeaders::default(),
            cache_ttl: None,
            indexes: None,
        }
    }

    /// Create a config from all options.
    #[inline]
    pub fn with_options<P>(root: P, skip_patterns: Option<GlobSet>, flags: FsFlags) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            root: root.into(),
            skip_patterns,
            flags,
            security_headers: SecurityHeaders::default(),
            cache_ttl: None,
            indexes: None,
        }
    }

    #[inline(always)]
    pub fn is_blacklisted<P: AsRef<Path>>(&self, path: P) -> bool {
        self.skip_patterns.as_ref().is_some_and(|p| p.matches(path.as_ref().as_os_str().as_encoded_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_config_defaults() {
        let conf = ServeConfig::new("/var/www");
        assert_eq!(conf.root, PathBuf::from("/var/www"));
        assert!(conf.skip_patterns.is_none());
        assert!(conf.flags.contains(FsFlags::READ_FILES));
        assert!(conf.cache_ttl.is_none());
        assert!(conf.indexes.is_none());
    }

    #[test]
    fn config_with_flags() {
        let flags = FsFlags::DIRECTORY_LIST | FsFlags::DOTFILES;
        let conf = ServeConfig::with_flags("/tmp", flags);
        assert!(conf.flags.contains(FsFlags::DIRECTORY_LIST));
        assert!(conf.flags.contains(FsFlags::DOTFILES));
    }

    #[test]
    fn is_blacklisted_no_patterns() {
        let conf = ServeConfig::new("/tmp");
        assert!(!conf.is_blacklisted("/tmp/file.txt"));
        assert!(!conf.is_blacklisted("/tmp/.hidden"));
    }

    #[test]
    fn is_blacklisted_with_matching_pattern() {
        let glob = GlobSet::try_from(&["**/*.tmp"] as &[&str]).unwrap();
        let conf = ServeConfig::with_skip_patterns("/tmp", glob);
        assert!(conf.is_blacklisted("/tmp/file.tmp"));
        assert!(conf.is_blacklisted("/tmp/sub/dir/file.tmp"));
    }

    #[test]
    fn is_blacklisted_with_non_matching_pattern() {
        let glob = GlobSet::try_from(&["**/*.tmp"] as &[&str]).unwrap();
        let conf = ServeConfig::with_skip_patterns("/tmp", glob);
        assert!(!conf.is_blacklisted("/tmp/file.txt"));
        assert!(!conf.is_blacklisted("/tmp/file.html"));
    }

    #[test]
    fn is_blacklisted_accepts_string_ref() {
        let glob = GlobSet::try_from(&["**/secret*"] as &[&str]).unwrap();
        let conf = ServeConfig::with_skip_patterns("/tmp", glob);
        assert!(conf.is_blacklisted("/tmp/secret.txt"));
        assert!(!conf.is_blacklisted("/tmp/public.txt"));
    }

    #[test]
    fn is_blacklisted_accepts_path_buf() {
        let glob = GlobSet::try_from(&["**/*.log"] as &[&str]).unwrap();
        let conf = ServeConfig::with_skip_patterns("/tmp", glob);
        let path = PathBuf::from("/tmp/app.log");
        assert!(conf.is_blacklisted(path));
    }

    #[test]
    fn security_headers_default() {
        let conf = ServeConfig::new("/tmp");
        assert!(conf.security_headers.contains(SecurityHeaders::X_FRAME_OPTS));
        assert!(conf.security_headers.contains(SecurityHeaders::X_CONTENT_TYPE));
        assert!(conf.security_headers.contains(SecurityHeaders::REFERRER));
    }
}
