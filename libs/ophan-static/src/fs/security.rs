use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityHeaders: u8 {
        /// Send the Server header.
        const SERVER_TOKENS  = 1 << 0;

        /// X-Frame-Options: DENY
        const X_FRAME_OPTS   = 1 << 1;

        /// X-Content-Type-Options: nosniff
        const X_CONTENT_TYPE = 1 << 2;

        /// Strict-Transport-Security
        const HSTS           = 1 << 3;

        /// Referrer-Policy
        const REFERRER       = 1 << 4;

        /// Content-Security-Policy
        const CSP            = 1 << 5;
    }
}

#[allow(dead_code)]
impl SecurityHeaders {
    /// Conservative defaults.
    pub const fn default() -> Self {
        Self::from_bits_retain(Self::X_FRAME_OPTS.bits() | Self::X_CONTENT_TYPE.bits() | Self::REFERRER.bits())
    }

    /// Maximum security for HTTPS deployments.
    pub const fn secure() -> Self {
        Self::from_bits_retain(
            Self::X_FRAME_OPTS.bits() | Self::X_CONTENT_TYPE.bits() | Self::REFERRER.bits() | Self::HSTS.bits(),
        )
    }

    /// Disable all security headers.
    pub const fn none() -> Self {
        Self::empty()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FsFlags: u16 {
        /// Allow GET/HEAD of regular files.
        const READ_FILES      = 1 << 0;

        /// Serve index.html (or configured index files).
        const INDEX_FILES     = 1 << 1;

        /// Generate directory listings.
        const DIRECTORY_LIST  = 1 << 2;

        /// Show hidden files.
        const DOTFILES        = 1 << 3;

        /// Allow symbolic links.
        const FOLLOW_SYMLINKS = 1 << 4;

        /// Allow path traversal outside the root through symlinks.
        const ESCAPE_ROOT     = 1 << 5;

        /// Allow byte range requests.
        const RANGE_REQUESTS  = 1 << 6;

        /// Generate ETag.
        const ETAG            = 1 << 7;

        /// Generate Last-Modified.
        const LAST_MODIFIED   = 1 << 8;
    }
}

impl FsFlags {
    #[must_use]
    #[inline]
    pub const fn secure() -> Self {
        Self::from_bits_retain(
            Self::READ_FILES.bits()
                | Self::INDEX_FILES.bits()
                | Self::ETAG.bits()
                | Self::LAST_MODIFIED.bits()
                | Self::RANGE_REQUESTS.bits(),
        )
    }

    #[inline]
    pub fn is_blocked(&self, file_type: std::fs::FileType, filename: &str) -> bool {
        (!self.contains(FsFlags::FOLLOW_SYMLINKS) && file_type.is_symlink())
            || (!self.contains(FsFlags::DOTFILES) && filename.starts_with('.'))
    }
}

impl Default for FsFlags {
    fn default() -> Self {
        Self::secure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_symlink(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ophan_security_test_{id}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let target = dir.join("target.txt");
        fs::write(&target, b"data").unwrap();

        let link = dir.join(name);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        link
    }

    #[test]
    fn blocked_symlink_without_flag() {
        let link = temp_symlink("link1.txt");
        let meta = fs::symlink_metadata(&link).unwrap();
        let flags = FsFlags::empty();
        assert!(flags.is_blocked(meta.file_type(), "link1.txt"));
        let _ = fs::remove_dir_all(link.parent().unwrap());
    }

    #[test]
    fn allowed_symlink_with_flag() {
        let link = temp_symlink("link2.txt");
        let meta = fs::symlink_metadata(&link).unwrap();
        let flags = FsFlags::FOLLOW_SYMLINKS;
        assert!(!flags.is_blocked(meta.file_type(), "link2.txt"));
        let _ = fs::remove_dir_all(link.parent().unwrap());
    }

    #[test]
    fn blocked_dotfile_without_flag() {
        let dir = std::env::temp_dir().join("ophan_security_test_dot");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".hidden"), b"data").unwrap();

        let meta = fs::metadata(dir.join(".hidden")).unwrap();
        let flags = FsFlags::empty();
        assert!(flags.is_blocked(meta.file_type(), ".hidden"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowed_dotfile_with_flag() {
        let dir = std::env::temp_dir().join("ophan_security_test_dot_allow");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".hidden"), b"data").unwrap();

        let meta = fs::metadata(dir.join(".hidden")).unwrap();
        let flags = FsFlags::DOTFILES;
        assert!(!flags.is_blocked(meta.file_type(), ".hidden"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn normal_file_not_blocked() {
        let dir = std::env::temp_dir().join("ophan_security_test_normal");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ok.txt"), b"data").unwrap();

        let meta = fs::metadata(dir.join("ok.txt")).unwrap();
        let flags = FsFlags::empty();
        assert!(!flags.is_blocked(meta.file_type(), "ok.txt"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secure_flags_contains_expected() {
        let flags = FsFlags::secure();
        assert!(flags.contains(FsFlags::READ_FILES));
        assert!(flags.contains(FsFlags::INDEX_FILES));
        assert!(flags.contains(FsFlags::ETAG));
        assert!(flags.contains(FsFlags::LAST_MODIFIED));
        assert!(flags.contains(FsFlags::RANGE_REQUESTS));
        assert!(!flags.contains(FsFlags::DIRECTORY_LIST));
        assert!(!flags.contains(FsFlags::DOTFILES));
        assert!(!flags.contains(FsFlags::FOLLOW_SYMLINKS));
    }

    #[test]
    fn security_headers_default() {
        let h = SecurityHeaders::default();
        assert!(h.contains(SecurityHeaders::X_FRAME_OPTS));
        assert!(h.contains(SecurityHeaders::X_CONTENT_TYPE));
        assert!(h.contains(SecurityHeaders::REFERRER));
        assert!(!h.contains(SecurityHeaders::HSTS));
    }

    #[test]
    fn security_headers_secure() {
        let h = SecurityHeaders::secure();
        assert!(h.contains(SecurityHeaders::X_FRAME_OPTS));
        assert!(h.contains(SecurityHeaders::X_CONTENT_TYPE));
        assert!(h.contains(SecurityHeaders::REFERRER));
        assert!(h.contains(SecurityHeaders::HSTS));
    }

    #[test]
    fn security_headers_none() {
        let h = SecurityHeaders::none();
        assert!(h.is_empty());
    }
}
