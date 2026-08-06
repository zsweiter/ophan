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
use crate::http::conditional;

#[derive(Debug, Clone)]
pub enum CacheObject {
    File(Arc<FileObject>),
    Directory(Arc<DirObject>),
}

#[allow(dead_code)]
impl CacheObject {
    #[inline]
    pub fn is_symlink(&self) -> bool {
        match self {
            Self::File(file) => file.is_symlink,
            Self::Directory(dir) => dir.is_symlink,
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
    default_ttl: Duration,
}

#[allow(dead_code)]
impl Filesystem {
    #[inline]
    pub fn new(cache_size: usize, default_ttl: Duration) -> Self {
        Self { cache: MemoryCache::new(cache_size), default_ttl }
    }

    pub async fn fetch_or_load<P>(&self, target_path: P, ttl: Option<Duration>) -> io::Result<CacheObject>
    where
        P: AsRef<Path>,
    {
        let path = target_path.as_ref();

        if let Some(cached) = self.get(path) {
            return Ok(cached);
        }

        let link_metadata = tokio::fs::symlink_metadata(path).await?;
        let is_symlink = link_metadata.file_type().is_symlink();

        let metadata = if is_symlink {
            tokio::fs::metadata(path).await?
        } else {
            link_metadata
        };

        let cached_object = if metadata.is_dir() {
            CacheObject::Directory(Arc::new(DirObject { path: path.to_path_buf(), metadata, is_symlink }))
        } else {
            let etag = conditional::create_etag(&metadata);
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let content_type = HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| header::CONTENT_TYPE_OCTET_STREAM.clone());

            CacheObject::File(Arc::new(FileObject::new(
                path.to_path_buf(),
                metadata,
                etag,
                content_type,
                is_symlink,
            )))
        };

        self.insert(path, cached_object.clone(), Some(ttl.unwrap_or(self.default_ttl)));

        Ok(cached_object)
    }

    #[inline]
    pub fn invalidate<P>(&self, target_path: P)
    where
        P: AsRef<Path>,
    {
        self.cache.remove(&target_path.as_ref().to_path_buf());
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
        self.cache.put(&path.as_ref().to_path_buf(), object, ttl);
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
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ophan_cache_test_{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn fetch_or_load_file() {
        let dir = temp_dir("file");
        let file_path = dir.join("test.txt");
        fs::write(&file_path, b"hello").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(result.is_file());
        assert!(!result.is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fetch_or_load_directory() {
        let dir = temp_dir("dir");
        fs::create_dir(dir.join("subdir")).unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&dir, None).await.unwrap();

        assert!(result.is_directory());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cache_returns_same_object() {
        let dir = temp_dir("cache");
        let file_path = dir.join("cached.txt");
        fs::write(&file_path, b"data").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let r1 = fs.fetch_or_load(&file_path, None).await.unwrap();
        let r2 = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(std::ptr::eq(
            Arc::as_ptr(&r1.into_file().unwrap()),
            Arc::as_ptr(&r2.into_file().unwrap())
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalidate_removes_from_cache() {
        let dir = temp_dir("invalidate");
        let file_path = dir.join("inv.txt");
        fs::write(&file_path, b"data").unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let _ = fs.fetch_or_load(&file_path, None).await.unwrap();

        assert!(fs.contains(&file_path));

        fs.invalidate(&file_path);

        assert!(!fs.contains(&file_path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn contains_returns_false_for_missing() {
        let fs = Filesystem::new(100, Duration::from_secs(60));
        assert!(!fs.contains("/tmp/nonexistent_file_12345.txt"));
    }

    #[tokio::test]
    async fn symlink_detected() {
        let dir = temp_dir("symlink");
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&target, b"data").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let fs = Filesystem::new(100, Duration::from_secs(60));
        let result = fs.fetch_or_load(&link, None).await.unwrap();

        assert!(result.is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_object_into_file() {
        let dir = temp_dir("into_file");
        let file_path = dir.join("test.txt");
        fs::write(&file_path, b"data").unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let obj = CacheObject::File(Arc::new(FileObject::new(
            file_path.clone(),
            meta,
            HeaderValue::from_static("\"test\""),
            HeaderValue::from_static("text/plain"),
            false,
        )));

        assert!(obj.into_file().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_object_into_directory() {
        let dir = temp_dir("into_dir");
        let meta = fs::metadata(&dir).unwrap();

        let obj = CacheObject::Directory(Arc::new(DirObject::new(dir.clone(), meta, false)));

        assert!(obj.into_directory().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_object_wrong_type_returns_none() {
        let dir = temp_dir("wrong_type");
        let file_path = dir.join("test.txt");
        fs::write(&file_path, b"data").unwrap();
        let meta = fs::metadata(&file_path).unwrap();

        let obj = CacheObject::File(Arc::new(FileObject::new(
            file_path,
            meta,
            HeaderValue::from_static("\"test\""),
            HeaderValue::from_static("text/plain"),
            false,
        )));

        assert!(obj.into_directory().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
