use std::fs::{Metadata, OpenOptions};
use std::path::PathBuf;

use http::HeaderValue;
use tokio::fs::ReadDir;

use crate::http::conditional::{self, LastModified};

#[derive(Debug)]
pub struct FileObject {
    /// Path to the file on disk.
    pub path: PathBuf,

    /// Canonical path with every symbolic link resolved.
    pub real_path: PathBuf,

    /// File metadata (size, timestamps, permissions, etc.).
    pub metadata: Metadata,

    /// Whether this file is a symbolic link.
    pub is_symlink: bool,

    /// Precomputed ETag header.
    pub etag: HeaderValue,

    /// Precomputed Last-Modified header.
    pub last_modified: Option<LastModified>,

    /// Precomputed Content-Type header.
    pub content_type: HeaderValue,
}

impl FileObject {
    #[inline]
    pub fn new(path: PathBuf, real_path: PathBuf, metadata: Metadata, content_type: HeaderValue, is_symlink: bool) -> Self {
        let etag = conditional::create_etag(&metadata);
        let last_modified = LastModified::from_metadata(&metadata);

        Self {
            path,
            real_path,
            metadata,
            is_symlink,
            etag,
            last_modified,
            content_type,
        }
    }

    /// Same file location with validators recomputed from `metadata`.
    #[inline]
    pub fn with_metadata(&self, metadata: Metadata) -> Self {
        Self::new(
            self.path.clone(),
            self.real_path.clone(),
            metadata,
            self.content_type.clone(),
            self.is_symlink,
        )
    }

    /// Whether `metadata` (typically from `fstat`) describes the same file contents as the cached entry.
    #[inline]
    pub fn is_same_file(&self, metadata: &Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let cached = &self.metadata;
            cached.dev() == metadata.dev()
                && cached.ino() == metadata.ino()
                && cached.size() == metadata.size()
                && cached.mtime() == metadata.mtime()
                && cached.mtime_nsec() == metadata.mtime_nsec()
                && cached.ctime() == metadata.ctime()
                && cached.ctime_nsec() == metadata.ctime_nsec()
        }

        #[cfg(not(unix))]
        {
            self.metadata.len() == metadata.len() && self.metadata.modified().ok() == metadata.modified().ok()
        }
    }

    /// Blocking open for reading. With `follow_symlinks` off the final component must not be a link.
    #[inline]
    pub fn open_blocking(&self, follow_symlinks: bool) -> std::io::Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options.read(true);

        #[cfg(unix)]
        {
            use nix::fcntl::OFlag;
            use std::os::unix::fs::OpenOptionsExt;

            let mut flags = OFlag::O_NONBLOCK;
            if !follow_symlinks {
                flags |= OFlag::O_NOFOLLOW;
            }
            options.custom_flags(flags.bits());
        }

        #[cfg(not(unix))]
        let _ = follow_symlinks;

        options.open(&self.path)
    }
}

/// A cached directory object.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DirObject {
    /// Path to the directory on disk.
    pub path: PathBuf,

    /// Canonical path with every symbolic link resolved.
    pub real_path: PathBuf,

    /// Directory metadata.
    pub metadata: Metadata,

    /// Whether this directory is a symbolic link.
    pub is_symlink: bool,
}

#[allow(dead_code)]
impl DirObject {
    #[inline]
    pub fn new(path: PathBuf, real_path: PathBuf, metadata: Metadata, is_symlink: bool) -> Self {
        Self { path, real_path, metadata, is_symlink }
    }

    pub async fn read_dir(&self) -> std::io::Result<ReadDir> {
        tokio::fs::read_dir(&self.path).await
    }
}
