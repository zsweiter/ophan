# ophan-static — Static File Serving

> ⚠️ **Active Development** — API may change without notice.

Async static file server with in-memory caching, directory listing, ETag/Last-Modified conditional requests, byte range requests, and configurable security headers.

## Architecture

```
src/
├── conf.rs          # ServeConfig builder
├── error.rs         # ServeError type mapping I/O → HTTP status
├── fs/
│   ├── cache.rs     # Filesystem object cache (MemoryCache)
│   ├── file.rs      # FileObject / DirObject types
│   └── security.rs  # FsFlags + SecurityHeaders bitflags
├── http/
│   ├── conditional.rs  # ETag generation, If-None-Match / If-Modified-Since
│   └── ranges.rs       # HTTP Range header parsing (RFC 7233)
├── listing.rs       # HTML directory listing builder
├── service.rs       # StaticService — main entry point
└── lib.rs           # Public re-exports
```

## Public API

### StaticService

Main entry point. Manages filesystem cache and request routing.

```rust
pub struct StaticService { /* private */ }

impl StaticService {
    /// Create with default cache (2048 entries, 300s TTL).
    pub fn new() -> Self;

    /// Serve a static file request.
    pub async fn serve(
        &self,
        config: &ServeConfig,
        req: &RequestParts,
    ) -> Result<Resource, ServeError>;

    /// Invalidate a cached path. Call after file modifications.
    pub fn invalidate(&self, path: &Path);
}

pub enum Resource {
    Bytes(Response),
    Stream(StreamingResponse<FileStream>),
}
```

### ServeConfig

Configuration for a static file serving location. Builder-style constructors.

```rust
pub struct ServeConfig {
    pub root: PathBuf,
    pub skip_patterns: Option<GlobSet>,
    pub flags: FsFlags,
    pub security_headers: SecurityHeaders,
    pub cache_ttl: Option<Duration>,
    pub indexes: Option<Box<[Cow<'static, str>]>>,
}

impl ServeConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    pub fn with_flags(root: impl Into<PathBuf>, flags: FsFlags) -> Self;
    pub fn with_skip_patterns(root: impl Into<PathBuf>, patterns: GlobSet) -> Self;
    pub fn with_options(root: impl Into<PathBuf>, patterns: Option<GlobSet>, flags: FsFlags) -> Self;

    /// Check if a path matches any skip pattern.
    pub fn is_blacklisted<P: AsRef<Path>>(&self, path: P) -> bool;
}
```

### FsFlags

Bitmask flags controlling filesystem serving behaviour.

```rust
pub struct FsFlags: u16;

impl FsFlags {
    const READ_FILES;       // Allow GET/HEAD of regular files
    const INDEX_FILES;      // Serve index.html / index.htm for directories
    const DIRECTORY_LIST;   // Generate directory listings
    const DOTFILES;         // Show hidden files (.git, .env)
    const FOLLOW_SYMLINKS;  // Allow symbolic links
    const ESCAPE_ROOT;      // Allow path traversal outside root via symlinks
    const RANGE_REQUESTS;   // Honor byte range requests
    const ETAG;             // Generate ETag headers
    const LAST_MODIFIED;    // Generate Last-Modified headers

    /// Secure defaults: READ_FILES | INDEX_FILES | ETAG | LAST_MODIFIED | RANGE_REQUESTS
    pub fn secure() -> Self;

    /// Check if a file type + name should be blocked.
    pub fn is_blocked(&self, file_type: FileType, filename: &str) -> bool;
}
```

### SecurityHeaders

Bitmask flags for HTTP security response headers.

```rust
pub struct SecurityHeaders: u8;

impl SecurityHeaders {
    const SERVER_TOKENS;    // Server header
    const X_FRAME_OPTS;    // X-Frame-Options: DENY
    const X_CONTENT_TYPE;  // X-Content-Type-Options: nosniff
    const HSTS;            // Strict-Transport-Security (max-age=31536000; includeSubDomains)
    const REFERRER;        // Referrer-Policy: strict-origin-when-cross-origin
    const CSP;             // Content-Security-Policy: default-src 'self'

    /// Default: X_FRAME_OPTS | X_CONTENT_TYPE | REFERRER
    pub fn secure() -> Self;   // + HSTS
    pub fn none() -> Self;
}
```

## Features

- **Path sanitisation**: Normalised via `flatkit::path::normalize_path`. Dotfiles blocked by default.
- **In-memory cache**: `pingora_memory-cache` with configurable TTL and size. Supports invalidation.
- **Conditional requests**: Strong ETag (size-mtime-inode), If-None-Match → 304, If-Modified-Since.
- **Byte range requests**: Full RFC 7233 parsing. Returns 206 Partial Content with Content-Range.
- **Directory listing**: Dark-themed HTML table with icons, sizes, file types. Configurable index files.
- **MIME types**: Detected via `mime_guess` on file extension.
- **Security headers**: X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, CSP — applied per config.
- **Symlink control**: Blocked by default; enabled via `FOLLOW_SYMLINKS` flag.
- **Streaming**: Large files streamed in 64KB chunks via `ReaderStream`.
