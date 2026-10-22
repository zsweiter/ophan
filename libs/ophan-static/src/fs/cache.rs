use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cache::MemoryCache;
use http::HeaderValue;
use ophan_net::http::header;

use crate::fs::file::DirObject;
use crate::fs::file::FileObject;

#[derive(Debug, Clone)]
pub enum CacheObject {
    File(Arc<FileObject>),
    Directory(Arc<DirObject>),
}

#[allow(dead_code)]
impl CacheObject {
    fn load_blocking(path: PathBuf) -> io::Result<Self> {
        let link_metadata = std::fs::symlink_metadata(&path)?;
        let is_symlink = link_metadata.file_type().is_symlink();

        let metadata = if is_symlink {
            std::fs::metadata(&path)?
        } else {
            link_metadata
        };
        let real_path = std::fs::canonicalize(&path)?;

        let object = if metadata.is_dir() {
            CacheObject::Directory(Arc::new(DirObject::new(path, real_path, metadata, is_symlink)))
        } else {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            let content_type = HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| header::CONTENT_TYPE_OCTET_STREAM.clone());

            CacheObject::File(Arc::new(FileObject::new(path, real_path, metadata, content_type, is_symlink)))
        };

        Ok(object)
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        match self {
            Self::File(file) => file.is_symlink,
            Self::Directory(dir) => dir.is_symlink,
        }
    }

    #[inline]
    pub fn real_path(&self) -> &Path {
        match self {
            Self::File(file) => &file.real_path,
            Self::Directory(dir) => &dir.real_path,
        }
    }

    #[inline]
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    #[inline]
    pub const fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }

    #[inline]
    pub fn as_file(&self) -> Option<&FileObject> {
        match self {
            Self::File(file) => Some(file.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn as_directory(&self) -> Option<&DirObject> {
        match self {
            Self::Directory(dir) => Some(dir.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn into_file(self) -> Option<Arc<FileObject>> {
        match self {
            Self::File(file) => Some(file),
            _ => None,
        }
    }

    #[inline]
    pub fn into_directory(self) -> Option<Arc<DirObject>> {
        match self {
            Self::Directory(dir) => Some(dir),
            _ => None,
        }
    }
}

pub struct Filesystem {
    cache: MemoryCache<PathBuf, CacheObject>,
    misses: MemoryCache<PathBuf, ()>,
    default_ttl: Duration,
}

/// Upper bound for how long a failed probe is remembered.
const MISS_TTL: Duration = Duration::from_secs(2);

#[allow(dead_code)]
impl Filesystem {
    #[inline]
    pub fn new(cache_size: usize, default_ttl: Duration) -> Self {
        Self {
            cache: MemoryCache::new(cache_size),
            misses: MemoryCache::new((cache_size / 4).max(16)),
            default_ttl,
        }
    }

    pub async fn fetch_or_load<P>(&self, target_path: P, ttl: Option<Duration>) -> io::Result<CacheObject>
    where
        P: AsRef<Path>,
    {
        let path = target_path.as_ref();

        if let Some(cached) = self.get(path) {
            return Ok(cached);
        }

        let owned = path.to_path_buf();
        let cached_object = tokio::task::spawn_blocking(move || CacheObject::load_blocking(owned))
            .await
            .map_err(io::Error::other)??;

        self.insert(path, cached_object.clone(), Some(ttl.unwrap_or(self.default_ttl)));

        Ok(cached_object)
    }

    /// Like [`Self::fetch_or_load`], but a missing path yields `Ok(None)` and is
    /// remembered for a short while so repeated probes skip the filesystem.
    pub async fn probe<P>(&self, target_path: P, ttl: Option<Duration>) -> io::Result<Option<CacheObject>>
    where
        P: AsRef<Path>,
    {
        let path = target_path.as_ref();

        if self.misses.get(path).0.is_some() {
            return Ok(None);
        }

        match self.fetch_or_load(path, ttl).await {
            Ok(object) => Ok(Some(object)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let miss_ttl = ttl.unwrap_or(self.default_ttl).min(MISS_TTL);
                self.misses.put(path, (), Some(miss_ttl));
                Ok(None)
            },
            Err(e) => Err(e),
        }
    }

    /// Drop the cached entry for `target_path` and load it again from disk.
    pub async fn reload<P>(&self, target_path: P, ttl: Option<Duration>) -> io::Result<CacheObject>
    where
        P: AsRef<Path>,
    {
        self.invalidate(target_path.as_ref());
        self.fetch_or_load(target_path, ttl).await
    }

    #[inline]
    pub fn invalidate<P>(&self, target_path: P)
    where
        P: AsRef<Path>,
    {
        let path = target_path.as_ref();
        self.cache.remove(path);
        self.misses.remove(path);
    }

    #[inline]
    fn get<P>(&self, path: P) -> Option<CacheObject>
    where
        P: AsRef<Path>,
    {
        self.cache.get(path.as_ref()).0
    }

    #[inline]
    fn insert<P>(&self, path: P, object: CacheObject, ttl: Option<Duration>)
    where
        P: AsRef<Path>,
    {
        self.cache.put(path.as_ref(), object, ttl);
    }

    #[inline]
    pub fn contains<P>(&self, path: P) -> bool
    where
        P: AsRef<Path>,
    {
        self.cache.get(path.as_ref()).0.is_some()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::{TempDir, tempdir};

    use super::*;
    use std::fs;

    fn temp_dir() -> TempDir {
        tempdir().unwrap()
    }

    #[tokio::test]
    async fn fetch_or_load_file() {
        let dir = temp_dir();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"hello").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(result.is_file());
        assert!(!result.is_symlink());
    }

    #[tokio::test]
    async fn fetch_or_load_directory() {
        let dir = temp_dir();
        fs::create_dir(dir.path().join("subdir")).unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&dir, None).await.unwrap();

        assert!(result.is_directory());
    }

    #[tokio::test]
    async fn cache_returns_same_object() {
        let dir = temp_dir();
        let file_path = dir.path().join("cached.txt");
        fs::write(&file_path, b"data").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let r1 = fs.fetch_or_load(&file_path, None).await.unwrap();
        let r2 = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(std::ptr::eq(
            Arc::as_ptr(&r1.into_file().unwrap()),
            Arc::as_ptr(&r2.into_file().unwrap())
        ));
    }

    #[tokio::test]
    async fn invalidate_removes_from_cache() {
        let dir = temp_dir();
        let file_path = dir.path().join("inv.txt");
        fs::write(&file_path, b"data").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let _ = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(fs.contains(&file_path));

        fs.invalidate(&file_path);

        assert!(!fs.contains(&file_path));
    }

    #[tokio::test]
    async fn contains_returns_false_for_missing() {
        let fs = Filesystem::new(100, Duration::from_secs(60));
        assert!(!fs.contains("/tmp/nonexistent_file_12345.txt"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_detected() {
        let dir = temp_dir();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");
        fs::write(&target, b"data").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&link, None).await.unwrap();

        assert!(result.is_symlink());
        assert_eq!(result.real_path(), fs::canonicalize(&target).unwrap());
    }

    #[tokio::test]
    async fn probe_remembers_missing_paths() {
        let dir = temp_dir();
        let file_path = dir.path().join("late.html");

        let fs = Filesystem::new(100, Duration::from_secs(60));
        assert!(fs.probe(&file_path, None).await.unwrap().is_none());

        std::fs::write(&file_path, b"data").unwrap();
        assert!(fs.probe(&file_path, None).await.unwrap().is_none());

        fs.invalidate(&file_path);
        assert!(fs.probe(&file_path, None).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn reload_refreshes_metadata() {
        let dir = temp_dir();
        let file_path = dir.path().join("grow.txt");
        fs::write(&file_path, b"abc").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let first = fs.fetch_or_load(&file_path, None).await.unwrap().into_file().unwrap();
        assert_eq!(first.metadata.len(), 3);

        std::fs::write(&file_path, b"abcdef").unwrap();
        let second = fs.reload(&file_path, None).await.unwrap().into_file().unwrap();
        assert_eq!(second.metadata.len(), 6);
    }

    #[test]
    fn cache_object_into_file() {
        let dir = temp_dir();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"data").unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let obj = CacheObject::File(Arc::new(FileObject::new(
            file_path.clone(),
            file_path.clone(),
            meta,
            HeaderValue::from_static("text/plain"),
            false,
        )));

        assert!(obj.into_file().is_some());
    }

    #[test]
    fn cache_object_into_directory() {
        let dir = temp_dir();
        let meta = fs::metadata(&dir).unwrap();

        let obj = CacheObject::Directory(Arc::new(DirObject::new(
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            meta,
            false,
        )));

        assert!(obj.into_directory().is_some());
    }

    #[test]
    fn cache_object_wrong_type_returns_none() {
        let dir = temp_dir();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, b"data").unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let obj = CacheObject::File(Arc::new(FileObject::new(
            file_path.clone(),
            file_path,
            meta,
            HeaderValue::from_static("text/plain"),
            false,
        )));

        assert!(obj.into_directory().is_none());
    }
}
