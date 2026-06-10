# ophan-static — Static File Serving

> ⚠️ **Active Development** — API may change without notice.

Zero-copy static file server with mmap, directory listing, ETag caching, and security controls.

## Public API

### FileServer

Main entry point for serving static files.

```rust
pub struct FileServer;

impl FileServer {
    pub fn new() -> Self;

    /// Handle a static file request.
    /// - `request`: inbound HTTP request parts (method, path, headers).
    /// - `request_path`: the URI path from the request.
    /// - `config`: static serving configuration.
    pub async fn handle_request(
        &self,
        request: &http::request::Parts,
        request_path: &str,
        config: &ServeConfig,
    ) -> Result<http::Response<Bytes>, (u16, String)>;
}
```

### ServeConfig

Configuration for a static file serving location.

```rust
pub struct ServeConfig {
    pub root: String,
    pub blacklist: Vec<GlobPattern>,
    pub flags: Flags,
}

impl ServeConfig {
    pub fn new(root: impl Into<String>) -> Self;
}
```

### Flags

Bitmask security flags for static file serving behaviour.

```rust
pub struct Flags(u64);

impl Flags {
    pub fn empty() -> Self;
    pub fn bits(&self) -> u64;
    pub fn contains(&self, other: Self) -> bool;
    pub fn intersects(&self, other: Self) -> bool;
    pub fn insert(&mut self, other: Self);
    pub fn remove(&mut self, other: Self);

    // Constants
    pub const LISTING: Flags;       // Enable directory listing
    pub const DOTFILES: Flags;      // Allow dotfiles (.git, .env)
    pub const SERVER_TOKENS: Flags; // Emit Server header
    pub const X_FRAME_OPTS: Flags;  // Emit X-Frame-Options: DENY
    pub const X_CONTENT_TYPE: Flags;// Emit X-Content-Type-Options: nosniff
    pub const HSTS: Flags;          // Emit Strict-Transport-Security
    pub const BLOCK_SYMLINKS: Flags;// Reject symlinked files

    /// Returns a secure default set: HSTS + X_FRAME_OPTS + X_CONTENT_TYPE + BLOCK_SYMLINKS.
    pub fn secure() -> Self;
}
```

### GlobPattern

Match patterns for blacklisted file names.

```rust
pub enum GlobPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
}

impl GlobPattern {
    /// Parse a pattern string:
    ///   `*.ext`   → Suffix
    ///   `prefix*` → Prefix
    ///   `exact`   → Exact
    pub fn parse(pattern: &str) -> Self;

    /// Returns true if file_name matches this pattern.
    pub fn matches(&self, file_name: &str) -> bool;
}
```

## Behaviour

- **Path sanitisation**: All paths are canonicalised via `std::fs::canonicalize`. Symlinks outside the root are rejected when `BLOCK_SYMLINKS` is set.
- **Directory listing**: When `LISTING` is enabled and a directory is requested, a styled HTML index is generated showing file names, sizes, and modification times.
- **ETag**: Generated from `(mtime, file_size)` for 304 Not Modified responses.
- **MIME types**: Detected via `mime_guess` based on file extension.
- **Security headers**: X-Frame-Options, X-Content-Type-Options, HSTS, Content-Security-Policy, Referrer-Policy, Permissions-Policy.
- **Byte range requests**: Not yet supported. Full file is always served.
