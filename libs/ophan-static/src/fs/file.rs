use std::fs::Metadata;
use std::path::PathBuf;

use http::HeaderValue;
use tokio::fs::ReadDir;

#[derive(Debug)]
pub struct FileObject {
    /// Path to the file on disk.
    pub path: PathBuf,

    /// File metadata (size, timestamps, permissions, etc.).
    pub metadata: Metadata,

    /// Whether this file is a symbolic link.
    pub is_symlink: bool,

    /// Precomputed ETag header.
    pub etag: HeaderValue,

    /// Precomputed Content-Type header.
    pub content_type: HeaderValue,
}

impl FileObject {
    #[inline]
    pub fn new(path: PathBuf, metadata: Metadata, etag: HeaderValue, content_type: HeaderValue, is_symlink: bool) -> Self {
        Self { path, metadata, etag, content_type, is_symlink }
    }

    #[inline]
    pub async fn open(&self) -> std::io::Result<tokio::fs::File> {
        tokio::fs::File::open(&self.path).await
    }
}

/// A cached directory object.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DirObject {
    /// Path to the directory on disk.
    pub path: PathBuf,

    /// Directory metadata.
    pub metadata: Metadata,

    /// Whether this directory is a symbolic link.
    pub is_symlink: bool,
}

#[allow(dead_code)]
impl DirObject {
    #[inline]
    pub fn new(path: PathBuf, metadata: Metadata, is_symlink: bool) -> Self {
        Self { path, metadata, is_symlink }
    }

    pub async fn read_dir(&self) -> std::io::Result<ReadDir> {
        tokio::fs::read_dir(&self.path).await
    }
}
