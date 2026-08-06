use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use ophan_net::http::header;
use ophan_net::proxy::{HttpResponse, RequestParts};
use std::borrow::Cow;
use std::io::{self, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::conf::ServeConfig;
use crate::error::{Error, Result};
use crate::fs::cache::{CacheObject, Filesystem};
use crate::fs::file::{DirObject, FileObject};
use crate::fs::security::{FsFlags, SecurityHeaders};
use crate::http::conditional;
use crate::http::ranges::HttpRange;
use crate::listing::DirectoryListing;

const DEFAULT_CHUNK: usize = 64 * 1024;

pub struct StaticService {
    filesystem: Filesystem,
    default_indexes: Box<[Cow<'static, str>]>,
}

impl StaticService {
    pub fn new() -> Self {
        Self {
            filesystem: Filesystem::new(2048, Duration::from_secs(15)),
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
        let relative_path = flatkit::path::normalize_path(Path::new(uri_path));
        let fs_path = config.root.join(&relative_path);
        let file_name = relative_path.file_name().unwrap_or_default();

        if !relative_path.as_os_str().is_empty() {
            if !config.flags.contains(FsFlags::DOTFILES) && file_name.as_encoded_bytes().starts_with(b".") {
                return Err(Error::forbidden(uri_path));
            }

            if config.is_blacklisted(&relative_path) {
                return Err(Error::forbidden(uri_path));
            }
        }

        let object = self
            .filesystem
            .fetch_or_load(&fs_path, config.cache_ttl)
            .await
            .map_err(|e| Error::from_io(e, uri_path))?;

        if !config.flags.contains(FsFlags::FOLLOW_SYMLINKS) && object.is_symlink() {
            return Err(Error::forbidden(uri_path));
        }

        match object {
            CacheObject::Directory(dir_object) => self.resolve_directory(uri_path, &dir_object, config, &req.headers).await,
            CacheObject::File(file) => {
                if !config.flags.contains(FsFlags::READ_FILES) {
                    tracing::info!(path = ?fs_path, "file reading disabled, returning 403");
                    return Err(Error::forbidden(uri_path));
                }

                self.resolve_file(file.as_ref(), config, &req.headers).await
            },
        }
    }

    async fn resolve_directory(
        &self,
        uri_path: &str,
        dir_object: &DirObject,
        conf: &ServeConfig,
        headers: &http::HeaderMap,
    ) -> Result<HttpResponse> {
        if conf.flags.contains(FsFlags::INDEX_FILES)
            && let Some(index) = self.find_index(dir_object, conf).await?
        {
            return self.resolve_file(index.as_ref(), conf, headers).await;
        }

        if !conf.flags.contains(FsFlags::DIRECTORY_LIST) {
            return Err(Error::forbidden(uri_path));
        }

        self.build_directory_response(uri_path, dir_object, conf).await
    }

    async fn find_index(&self, dir: &DirObject, conf: &ServeConfig) -> Result<Option<Arc<FileObject>>, Error> {
        let indexes = conf.indexes.as_deref().unwrap_or(&self.default_indexes);

        for name in indexes {
            let candidate = dir.path.join(name.as_ref());
            match self.filesystem.fetch_or_load(&candidate, conf.cache_ttl).await {
                Ok(obj) => {
                    if let Some(file) = obj.into_file() {
                        return Ok(Some(file));
                    }
                },
                Err(e) => match e.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::AlreadyExists => continue,
                    _ => {
                        tracing::error!(candidate = ?candidate, error = %e, "index probe I/O failure");
                        return Err(Error::from_io(e, candidate.to_string_lossy().as_ref()));
                    },
                },
            }
        }
        Ok(None)
    }

    async fn resolve_file(&self, object: &FileObject, config: &ServeConfig, headers: &HeaderMap) -> Result<HttpResponse> {
        let file_size = object.metadata.len();

        let etag_header = object.etag.clone();
        let last_mod = conditional::last_modified_header(&object.metadata);

        // Conditional: If-None-Match / If-Modified-Since → 304
        if conditional::is_not_modified(headers, &etag_header, last_mod.as_ref()) {
            let mut response = HttpResponse::with_capacity(StatusCode::NOT_MODIFIED, 3)
                .with_header(header::ETAG, etag_header)
                .with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"));

            if let Some(lm) = last_mod {
                response.insert_header(header::LAST_MODIFIED, lm);
            }

            tracing::info!(path = ?object.path, "conditional request matched, returning 304 Not Modified");

            self.apply_security_headers(&mut response, &config.security_headers);

            return Ok(response);
        }

        let ranges = if config.flags.contains(FsFlags::RANGE_REQUESTS) {
            match headers.get(header::RANGE) {
                Some(raw_ranges) => match HttpRange::parse(raw_ranges.as_bytes(), file_size) {
                    Ok(ranges_set) => {
                        if ranges_set.len() > 1 {
                            tracing::warn!("multiple ranges requested, but only one is supported");
                        }

                        ranges_set.into_iter().next()
                    },
                    Err(err) => {
                        tracing::warn!(error = ?err, "failed to parse Range header");

                        let response = if err.is_invalid_range() || err.is_overlap_error() {
                            HttpResponse::new(StatusCode::RANGE_NOT_SATISFIABLE)
                                .with_header(
                                    header::CONTENT_RANGE,
                                    HeaderValue::from_str(&format!("bytes */{file_size}"))
                                        .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
                                )
                                .with_header(header::CONTENT_LENGTH, HeaderValue::from_static("0"))
                        } else {
                            HttpResponse::new(StatusCode::BAD_REQUEST)
                        };

                        return Ok(response);
                    },
                },
                None => None,
            }
        } else {
            None
        };

        let mut file = object.open().await.map_err(|e| Error::from_io(e, object.path.to_string_lossy().as_ref()))?;

        let (status, content_length, content_range) = if let Some(r) = ranges {
            file.seek(SeekFrom::Start(r.start)).await.map_err(|e| Error::from_io(e, ""))?;

            let len = r.len();
            let cr = format!("bytes {}-{}/{}", r.start, r.length - 1, file_size);
            (
                StatusCode::PARTIAL_CONTENT,
                len,
                Some(HeaderValue::from_str(&cr).unwrap_or_else(|_| HeaderValue::from_static("bytes 0-0/0"))),
            )
        } else {
            (StatusCode::OK, file_size, None)
        };

        let reader = if let Some(r) = ranges {
            file.take(r.len())
        } else {
            file.take(u64::MAX)
        };

        let chunk_size = if content_length <= DEFAULT_CHUNK as u64 {
            (content_length as usize).saturating_add(2)
        } else {
            DEFAULT_CHUNK
        };

        let mut response = HttpResponse::with_capacity(status, 5)
            .with_header(header::ETAG, etag_header)
            .with_header(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=3600"))
            .with_header(header::CONTENT_TYPE, object.content_type.clone())
            .with_header(header::ACCEPT_RANGES, header::RANGE_BYTES)
            .with_header(header::CONTENT_LENGTH, HeaderValue::from(content_length));

        if let Some(lm) = last_mod {
            response.insert_header(header::LAST_MODIFIED, lm);
        }
        if let Some(cr) = content_range {
            response.insert_header(header::CONTENT_RANGE, cr);
        }

        self.apply_security_headers(&mut response, &config.security_headers);

        response.stream(ReaderStream::with_capacity(reader, chunk_size));

        Ok(response)
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
