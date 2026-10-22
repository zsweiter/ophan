use bytes::Bytes;
use futures::Stream;
use http::{HeaderValue, Method, StatusCode};
use ophan_net::http::header;
use ophan_net::proxy::{HttpResponse, RequestParts};
use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::conf::ServeConfig;
use crate::error::{Error, Result};
use crate::fs::cache::{CacheObject, Filesystem};
use crate::fs::file::{DirObject, FileObject};
use crate::fs::path::{self, PathError};
use crate::fs::security::{FsFlags, SecurityHeaders};
use crate::http::conditional;
use crate::http::ranges::{ContentRange, HttpRange};
use crate::listing::DirectoryListing;

/// Bodies up to this size are read with a single blocking call and sent as one buffer.
const SMALL_FILE_MAX: u64 = 256 * 1024;

/// Read size per blocking call when streaming larger bodies.
const READ_CHUNK: u64 = 256 * 1024;

pub struct StaticService {
    filesystem: Filesystem,
    default_indexes: Box<[Cow<'static, str>]>,
}

impl StaticService {
    /// Read exactly `len` bytes starting at `offset`; a file that shrank yields `UnexpectedEof`.
    fn read_exact_at(file: &File, offset: u64, len: u64) -> io::Result<Bytes> {
        let mut buf = vec![0u8; len as usize];

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            file.read_exact_at(&mut buf, offset)?;
        }

        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut reader = file;
            reader.seek(SeekFrom::Start(offset))?;
            reader.read_exact(&mut buf)?;
        }

        Ok(Bytes::from(buf))
    }

    /// Stream `length` bytes from `offset`, one blocking read of up to [`READ_CHUNK`] per item.
    fn file_stream(file: File, offset: u64, length: u64) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
        futures::stream::try_unfold((file, offset, length), |(file, offset, remaining)| async move {
            if remaining == 0 {
                return Ok(None);
            }

            let n = remaining.min(READ_CHUNK);
            let (file, chunk) = tokio::task::spawn_blocking(move || {
                let chunk = Self::read_exact_at(&file, offset, n);
                (file, chunk)
            })
            .await
            .map_err(io::Error::other)?;

            Ok(Some((chunk?, (file, offset + n, remaining - n))))
        })
    }

    pub fn new(cache_size: usize, cache_ttl: Duration) -> Self {
        Self {
            filesystem: Filesystem::new(cache_size, cache_ttl),
            default_indexes: vec!["index.html".into(), "index.htm".into()].into_boxed_slice(),
        }
    }

    fn apply_security_headers(&self, response: &mut HttpResponse, headers: &SecurityHeaders) {
        if headers.contains(SecurityHeaders::X_FRAME_OPTS) {
            response.insert_header(header::X_FRAME_OPTIONS, header::DENY);
        }
        if headers.contains(SecurityHeaders::X_CONTENT_TYPE) {
            response.insert_header(header::X_CONTENT_TYPE_OPTIONS, header::NOSNIFF);
        }
        if headers.contains(SecurityHeaders::HSTS) {
            response.insert_header(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
        }
        if headers.contains(SecurityHeaders::REFERRER) {
            response.insert_header(header::REFERRER_POLICY, header::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
        }
        if headers.contains(SecurityHeaders::CSP) {
            response.insert_header(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'"),
            );
        }
    }

    /// Invalidate a cached path. Call after file modifications to force re-read on next request.
    pub fn invalidate(&self, path: &Path) {
        self.filesystem.invalidate(path);
    }

    pub async fn serve(&self, config: &ServeConfig, req: &RequestParts) -> Result<HttpResponse> {
        let uri_path = req.uri.path();
        let fs_path = path::resolve(&config.root, uri_path, config.flags.contains(FsFlags::DOTFILES)).map_err(|e| match e {
            PathError::Malformed => Error::bad_request(uri_path),
            PathError::Hidden => Error::forbidden(uri_path),
        })?;
        let relative_path = fs_path.strip_prefix(&config.root).unwrap_or(Path::new(""));

        if !relative_path.as_os_str().is_empty() && config.is_blacklisted(relative_path) {
            return Err(Error::forbidden(uri_path));
        }

        let object = self
            .filesystem
            .fetch_or_load(&fs_path, config.cache_ttl)
            .await
            .map_err(|e| Error::from_io(e, uri_path))?;

        self.check_confined(object.real_path(), relative_path, config, uri_path).await?;

        match object {
            CacheObject::Directory(dir_object) => self.resolve_directory(uri_path, &dir_object, relative_path, config, req).await,
            CacheObject::File(file) => {
                if !config.flags.contains(FsFlags::READ_FILES) {
                    tracing::info!(path = ?fs_path, "file reading disabled, returning 403");
                    return Err(Error::forbidden(uri_path));
                }

                self.resolve_file(file, relative_path, config, req, uri_path).await
            },
        }
    }

    /// Ensure `real_path` stays inside the document root.
    ///
    /// Without `FOLLOW_SYMLINKS` the canonical path must equal `root/relative` exactly,
    /// which rules out a symbolic link at any component below the root. With it, the
    /// target only has to remain under the canonical root unless `ESCAPE_ROOT` is set.
    async fn check_confined(&self, real_path: &Path, relative: &Path, conf: &ServeConfig, uri_path: &str) -> Result<()> {
        let follow = conf.flags.contains(FsFlags::FOLLOW_SYMLINKS);
        if follow && conf.flags.contains(FsFlags::ESCAPE_ROOT) {
            return Ok(());
        }

        let root = self
            .filesystem
            .fetch_or_load(&conf.root, conf.cache_ttl)
            .await
            .map_err(|e| Error::from_io(e, uri_path))?;

        let confined = match real_path.strip_prefix(root.real_path()) {
            Ok(inner) => follow || inner == relative,
            Err(_) => false,
        };

        if !confined {
            tracing::info!(path = ?real_path, "path leaves the root or crosses a symlink, returning 403");
            return Err(Error::forbidden(uri_path));
        }

        Ok(())
    }

    async fn resolve_directory(
        &self,
        uri_path: &str,
        dir_object: &DirObject,
        relative: &Path,
        conf: &ServeConfig,
        req: &RequestParts,
    ) -> Result<HttpResponse> {
        if conf.flags.contains(FsFlags::INDEX_FILES)
            && let Some((index, index_relative)) = self.find_index(dir_object, relative, conf, uri_path).await?
        {
            return self.resolve_file(index, &index_relative, conf, req, uri_path).await;
        }

        if !conf.flags.contains(FsFlags::DIRECTORY_LIST) {
            return Err(Error::forbidden(uri_path));
        }

        self.build_directory_response(uri_path, dir_object, conf).await
    }

    async fn find_index(
        &self,
        dir: &DirObject,
        relative: &Path,
        conf: &ServeConfig,
        uri_path: &str,
    ) -> Result<Option<(Arc<FileObject>, PathBuf)>, Error> {
        let indexes = conf.indexes.as_deref().unwrap_or(&self.default_indexes);

        for name in indexes {
            let candidate = dir.path.join(name.as_ref());
            match self.filesystem.probe(&candidate, conf.cache_ttl).await {
                Ok(Some(CacheObject::File(file))) => {
                    let index_relative = relative.join(name.as_ref());
                    if conf.is_blacklisted(&index_relative) {
                        continue;
                    }

                    self.check_confined(&file.real_path, &index_relative, conf, uri_path).await?;

                    return Ok(Some((file, index_relative)));
                },
                Ok(_) => continue,
                Err(e) => match e.kind() {
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AlreadyExists => continue,
                    _ => {
                        tracing::error!(candidate = ?candidate, error = %e, "index probe I/O failure");
                        return Err(Error::from_io(e, candidate.to_string_lossy().as_ref()));
                    },
                },
            }
        }
        Ok(None)
    }

    /// Open (or, for `HEAD`, stat) the file and make sure the cached entry still describes it.
    ///
    /// The returned object always matches the metadata of the returned handle, so headers
    /// derived from it agree with the bytes that will be read.
    async fn open_current(
        &self,
        mut object: Arc<FileObject>,
        relative: &Path,
        conf: &ServeConfig,
        uri_path: &str,
        head: bool,
    ) -> Result<(Arc<FileObject>, Option<File>)> {
        let follow = conf.flags.contains(FsFlags::FOLLOW_SYMLINKS);
        let mut reloaded = false;

        loop {
            let target = Arc::clone(&object);
            let (file, metadata) = tokio::task::spawn_blocking(move || -> io::Result<_> {
                if head {
                    let metadata = if follow {
                        std::fs::metadata(&target.path)?
                    } else {
                        std::fs::symlink_metadata(&target.path)?
                    };
                    Ok((None, metadata))
                } else {
                    let file = target.open_blocking(follow)?;
                    let metadata = file.metadata()?;
                    Ok((Some(file), metadata))
                }
            })
            .await
            .map_err(|e| Error::internal(uri_path, io::Error::other(e)))?
            .map_err(|e| Error::from_io(e, uri_path))?;

            if object.is_same_file(&metadata) {
                return Ok((object, file));
            }

            if reloaded {
                if !metadata.is_file() {
                    return Err(Error::forbidden(uri_path));
                }
                return Ok((Arc::new(object.with_metadata(metadata)), file));
            }

            let fresh = self
                .filesystem
                .reload(&object.path, conf.cache_ttl)
                .await
                .map_err(|e| Error::from_io(e, uri_path))?
                .into_file()
                .ok_or_else(|| Error::not_found(uri_path))?;

            self.check_confined(&fresh.real_path, relative, conf, uri_path).await?;

            if !fresh.metadata.is_file() {
                return Err(Error::forbidden(uri_path));
            }

            object = fresh;
            reloaded = true;
        }
    }

    async fn resolve_file(
        &self,
        object: Arc<FileObject>,
        relative: &Path,
        config: &ServeConfig,
        req: &RequestParts,
        uri_path: &str,
    ) -> Result<HttpResponse> {
        if !object.metadata.is_file() {
            return Err(Error::forbidden(uri_path));
        }

        let head = req.method == Method::HEAD;
        let headers = &req.headers;
        let (object, file) = self.open_current(object, relative, config, uri_path, head).await?;

        let file_size = object.metadata.len();
        let last_mod = object.last_modified.as_ref();

        // Conditional: If-None-Match / If-Modified-Since → 304
        if conditional::is_not_modified(headers, &object.etag, last_mod) {
            let mut response = HttpResponse::with_capacity(StatusCode::NOT_MODIFIED, 3)
                .with_header(header::ETAG, object.etag.clone())
                .with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"));

            if let Some(lm) = last_mod {
                response.insert_header(header::LAST_MODIFIED, lm.value.clone());
            }

            tracing::info!(path = ?object.path, "conditional request matched, returning 304 Not Modified");

            self.apply_security_headers(&mut response, &config.security_headers);

            return Ok(response);
        }

        let range = if config.flags.contains(FsFlags::RANGE_REQUESTS)
            && let Some(raw_ranges) = headers.get(header::RANGE)
            && conditional::if_range_allows(headers, &object.etag, last_mod)
        {
            match HttpRange::parse(raw_ranges.as_bytes(), file_size) {
                Ok(ranges_set) => {
                    if ranges_set.len() > 1 {
                        tracing::warn!("multiple ranges requested, but only one is supported");
                    }

                    match ranges_set.into_iter().next() {
                        Some(r) if r.len() == 0 => return Ok(self.range_not_satisfiable(file_size)),
                        first => first,
                    }
                },
                Err(err) => {
                    tracing::warn!(error = ?err, "failed to parse Range header");

                    let response = if err.is_invalid_range() || err.is_overlap_error() {
                        self.range_not_satisfiable(file_size)
                    } else {
                        HttpResponse::new(StatusCode::BAD_REQUEST)
                    };

                    return Ok(response);
                },
            }
        } else {
            None
        };

        let (status, offset, content_length, content_range) = match range {
            Some(r) => {
                let cr = ContentRange::new(r.start, r.len(), file_size)
                    .try_into_header_value()
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes 0-0/0"));
                (StatusCode::PARTIAL_CONTENT, r.start, r.len(), Some(cr))
            },
            None => (StatusCode::OK, 0, file_size, None),
        };

        let mut response = HttpResponse::with_capacity(status, 5)
            .with_header(header::ETAG, object.etag.clone())
            .with_header(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=3600"))
            .with_header(header::CONTENT_TYPE, object.content_type.clone())
            .with_header(header::ACCEPT_RANGES, header::RANGE_BYTES)
            .with_header(header::CONTENT_LENGTH, HeaderValue::from(content_length));

        if let Some(lm) = last_mod {
            response.insert_header(header::LAST_MODIFIED, lm.value.clone());
        }
        if let Some(cr) = content_range {
            response.insert_header(header::CONTENT_RANGE, cr);
        }

        self.apply_security_headers(&mut response, &config.security_headers);

        let Some(file) = file else {
            return Ok(response);
        };

        if content_length <= SMALL_FILE_MAX {
            let body = tokio::task::spawn_blocking(move || Self::read_exact_at(&file, offset, content_length))
                .await
                .map_err(|e| Error::internal(uri_path, io::Error::other(e)))?
                .map_err(|e| Error::internal(uri_path, e))?;

            response.bytes(body);
        } else {
            response.stream(Self::file_stream(file, offset, content_length));
        }

        Ok(response)
    }

    fn range_not_satisfiable(&self, file_size: u64) -> HttpResponse {
        let mut itoa = itoa::Buffer::new();
        let mut value = String::with_capacity(28);
        value.push_str("bytes */");
        value.push_str(itoa.format(file_size));

        HttpResponse::new(StatusCode::RANGE_NOT_SATISFIABLE)
            .with_header(
                header::CONTENT_RANGE,
                HeaderValue::from_maybe_shared(value).unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
            )
            .with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"))
    }

    async fn build_directory_response(&self, req_path: &str, dir_object: &DirObject, conf: &ServeConfig) -> Result<HttpResponse> {
        let html = DirectoryListing::build(req_path, &dir_object.path, conf)
            .await
            .map_err(|e| Error::from_io(e, req_path))?;

        let mut response = HttpResponse::with_capacity(StatusCode::OK, 3)
            .with_header(header::CONTENT_TYPE, header::CONTENT_TYPE_HTML)
            .with_header(header::ACCEPT_RANGES, header::RANGE_NONE);

        self.apply_security_headers(&mut response, &conf.security_headers);

        response.bytes(Bytes::from(html));

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use ophan_net::proxy::HttpBody;
    use std::fs;
    use tempfile::{TempDir, tempdir};

    use super::*;

    fn service() -> StaticService {
        StaticService::new(128, Duration::from_secs(60))
    }

    fn site() -> TempDir {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("hello.txt"), b"0123456789").unwrap();
        fs::write(dir.path().join("my file.txt"), b"spaced").unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), b"secret").unwrap();
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("docs/index.html"), b"<h1>docs</h1>").unwrap();
        dir
    }

    fn request(method: &str, path: &str, headers: &[(&'static str, &str)]) -> RequestParts {
        let mut req = RequestParts::build(method, path.as_bytes(), None).unwrap();
        for (name, value) in headers {
            req.insert_header(*name, *value).unwrap();
        }
        req
    }

    async fn get(svc: &StaticService, conf: &ServeConfig, path: &str, headers: &[(&'static str, &str)]) -> Result<HttpResponse> {
        svc.serve(conf, &request("GET", path, headers)).await
    }

    async fn body(response: HttpResponse) -> Vec<u8> {
        match response.into_body() {
            None => Vec::new(),
            Some(HttpBody::Bytes(bytes)) => bytes.to_vec(),
            Some(HttpBody::Stream(mut stream)) => {
                let mut out = Vec::new();
                while let Some(chunk) = stream.next().await {
                    out.extend_from_slice(&chunk.unwrap());
                }
                out
            },
        }
    }

    fn header_str(response: &HttpResponse, name: http::header::HeaderName) -> &str {
        response.headers.get(name).unwrap().to_str().unwrap()
    }

    #[tokio::test]
    async fn serves_plain_file() {
        let dir = site();
        let conf = ServeConfig::new(dir.path());
        let resp = get(&service(), &conf, "/hello.txt", &[]).await.unwrap();

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(header_str(&resp, header::CONTENT_LENGTH), "10");
        assert_eq!(body(resp).await, b"0123456789");
    }

    #[tokio::test]
    async fn dotfile_in_any_component_is_forbidden() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let err = get(&svc, &conf, "/.git/config", &[]).await.err().expect("expected error");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        let err = get(&svc, &conf, "/%2Egit/config", &[]).await.err().expect("expected error");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        let conf = ServeConfig::with_flags(dir.path(), FsFlags::secure() | FsFlags::DOTFILES);
        let resp = get(&svc, &conf, "/.git/config", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"secret");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_rejected_at_every_component() {
        use std::os::unix::fs::symlink;

        let outside = tempdir().unwrap();
        fs::write(outside.path().join("passwd"), b"root").unwrap();
        fs::write(outside.path().join("index.html"), b"outside index").unwrap();

        let dir = site();
        fs::create_dir_all(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/file.txt"), b"real").unwrap();
        symlink(dir.path().join("real"), dir.path().join("linkdir")).unwrap();
        symlink(outside.path(), dir.path().join("escape")).unwrap();
        fs::create_dir_all(dir.path().join("site")).unwrap();
        symlink(outside.path().join("index.html"), dir.path().join("site/index.html")).unwrap();

        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/real/file.txt", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"real");

        for path in ["/linkdir/file.txt", "/escape/passwd", "/site/", "/linkdir/"] {
            let err = get(&svc, &conf, path, &[]).await.err().expect("expected error");
            assert_eq!(err.status, StatusCode::FORBIDDEN, "{path}");
        }

        let follow = ServeConfig::with_flags(dir.path(), FsFlags::secure() | FsFlags::FOLLOW_SYMLINKS);
        let resp = get(&svc, &follow, "/linkdir/file.txt", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"real");

        for path in ["/escape/passwd", "/site/"] {
            let err = get(&svc, &follow, path, &[]).await.err().expect("expected error");
            assert_eq!(err.status, StatusCode::FORBIDDEN, "{path}");
        }

        let escape = ServeConfig::with_flags(
            dir.path(),
            FsFlags::secure() | FsFlags::FOLLOW_SYMLINKS | FsFlags::ESCAPE_ROOT,
        );
        let resp = get(&svc, &escape, "/escape/passwd", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_root_is_allowed() {
        use std::os::unix::fs::symlink;

        let dir = site();
        let holder = tempdir().unwrap();
        let root_link = holder.path().join("www");
        symlink(dir.path(), &root_link).unwrap();

        let conf = ServeConfig::new(&root_link);
        let resp = get(&service(), &conf, "/hello.txt", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"0123456789");
    }

    #[tokio::test]
    async fn content_range_header() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=2-4")]).await.unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(header_str(&resp, header::CONTENT_RANGE), "bytes 2-4/10");
        assert_eq!(header_str(&resp, header::CONTENT_LENGTH), "3");
        assert_eq!(body(resp).await, b"234");

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=-3")]).await.unwrap();
        assert_eq!(header_str(&resp, header::CONTENT_RANGE), "bytes 7-9/10");
        assert_eq!(body(resp).await, b"789");

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=20-")]).await.unwrap();
        assert_eq!(resp.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header_str(&resp, header::CONTENT_RANGE), "bytes */10");
    }

    #[tokio::test]
    async fn empty_file_range_is_not_satisfiable() {
        let dir = site();
        fs::write(dir.path().join("empty.txt"), b"").unwrap();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&service(), &conf, "/empty.txt", &[("range", "bytes=-1")]).await.unwrap();
        assert_eq!(resp.status, StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[tokio::test]
    async fn percent_decoded_paths() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/my%20file.txt", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"spaced");

        for path in ["/docs%2Findex.html", "/hello.txt%00", "/%2e%2e/hello.txt", "/docs/%2E%2E/hello.txt", "/%ff"] {
            let err = get(&svc, &conf, path, &[]).await.err().expect("expected error");
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn index_file_served_for_directory() {
        let dir = site();
        let conf = ServeConfig::new(dir.path());
        let resp = get(&service(), &conf, "/docs/", &[]).await.unwrap();
        assert_eq!(body(resp).await, b"<h1>docs</h1>");
    }

    #[tokio::test]
    async fn conditional_requests() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/hello.txt", &[]).await.unwrap();
        let etag = header_str(&resp, header::ETAG).to_owned();
        let last_mod = header_str(&resp, header::LAST_MODIFIED).to_owned();

        let list = format!("\"nope\", {etag}");
        let resp = get(&svc, &conf, "/hello.txt", &[("if-none-match", &list)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);

        let weak = format!("W/{etag}");
        let resp = get(&svc, &conf, "/hello.txt", &[("if-none-match", &weak)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);

        let resp = get(&svc, &conf, "/hello.txt", &[("if-none-match", "*")]).await.unwrap();
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);

        let resp = get(&svc, &conf, "/hello.txt", &[("if-modified-since", &last_mod)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);

        let resp = get(
            &svc,
            &conf,
            "/hello.txt",
            &[("if-none-match", "\"nope\""), ("if-modified-since", &last_mod)],
        )
        .await
        .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=0-1"), ("if-range", &etag)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body(resp).await, b"01");

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=0-1"), ("if-range", &last_mod)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);

        let resp = get(
            &svc,
            &conf,
            "/hello.txt",
            &[("range", "bytes=0-1"), ("if-range", "\"stale\"")],
        )
        .await
        .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.get(header::CONTENT_RANGE).is_none());
        assert_eq!(body(resp).await, b"0123456789");

        let resp = get(&svc, &conf, "/hello.txt", &[("range", "bytes=0-1"), ("if-range", &weak)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn replaced_file_uses_fresh_metadata() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/hello.txt", &[]).await.unwrap();
        let old_etag = header_str(&resp, header::ETAG).to_owned();

        let replacement = dir.path().join("hello.tmp");
        fs::write(&replacement, b"a much longer replacement body").unwrap();
        fs::rename(&replacement, dir.path().join("hello.txt")).unwrap();

        let resp = get(&svc, &conf, "/hello.txt", &[("if-none-match", &old_etag)]).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_ne!(header_str(&resp, header::ETAG), old_etag);
        assert_eq!(header_str(&resp, header::CONTENT_LENGTH), "30");
        assert_eq!(body(resp).await, b"a much longer replacement body");
    }

    #[tokio::test]
    async fn head_has_headers_but_no_body() {
        let dir = site();
        let conf = ServeConfig::new(dir.path());
        let resp = service().serve(&conf, &request("HEAD", "/hello.txt", &[])).await.unwrap();

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(header_str(&resp, header::CONTENT_LENGTH), "10");
        assert!(resp.into_body().is_none());
    }

    #[tokio::test]
    async fn large_file_is_streamed_in_full() {
        let dir = site();
        let data: Vec<u8> = (0..(SMALL_FILE_MAX as usize * 3 + 17)).map(|i| (i % 251) as u8).collect();
        fs::write(dir.path().join("big.bin"), &data).unwrap();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let resp = get(&svc, &conf, "/big.bin", &[]).await.unwrap();
        assert!(matches!(resp.body, Some(HttpBody::Stream(_))));
        assert_eq!(body(resp).await, data);

        let resp = get(&svc, &conf, "/big.bin", &[("range", "bytes=100-")]).await.unwrap();
        assert_eq!(body(resp).await, &data[100..]);
    }

    #[tokio::test]
    async fn missing_and_nested_paths() {
        let dir = site();
        let svc = service();
        let conf = ServeConfig::new(dir.path());

        let err = get(&svc, &conf, "/nope.txt", &[]).await.err().expect("expected error");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        let err = get(&svc, &conf, "/hello.txt/extra", &[]).await.err().expect("expected error");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }
}
