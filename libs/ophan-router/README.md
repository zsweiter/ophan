# ophan-router — Multi-Stage HTTP Router

> ⚠️ **Active Development** — API may change without notice.

High-performance, zero-copy HTTP request router for the Ophan gateway.
Resolution stages: **SNI / host matching → HTTP method filtering → radix tree path lookup**

## Public API

### Router

Generic multi-stage router. `T` is the user-defined value type (e.g. `Arc<RouteValue>`).

```rust
pub struct Router<T>;

impl<T> Router<T> {
    /// Create a new router with a default vhost (all methods allowed).
    pub fn new() -> Self;

    /// Add a route to the matching vhost (creates one if needed).
    /// - `path`: DSL pattern (e.g. `/users/:id`, `/api/*`).
    /// - `methods`: HTTP methods allowed (merged into vhost via OR).
    /// - `hosts`: SNI hostnames (`empty` = default vhost).
    /// - `value`: stored value returned on match.
    pub fn add_route(
        &mut self,
        path: &str,
        methods: HttpMethodSet,
        hosts: Vec<&str>,
        value: T,
    ) -> Result<(), InsertError>
    where
        T: Clone;

    /// Resolve a request.
    /// Returns the matched value and extracted path parameters.
    pub fn match_route<'path>(
        &self,
        host: Option<&str>,
        method: &'path str,
        path: &'path str,
    ) -> Result<Match<'_, 'path, &T>, MatchError>;

    /// Mutable variant of `find_route`. Regex fallback not supported.
    pub fn find_route_mut<'path>(
        &mut self,
        host: Option<&str>,
        method: &'path str,
        path: &'path str,
    ) -> Result<Match<'_, 'path, &mut T>, MatchError>;

    /// Remove a route from the default vhost.
    pub fn remove(&mut self, path: impl Into<String>) -> Option<T>;

    /// Remove a route from a specific vhost.
    pub fn remove_from_vhost(&mut self, vhost_id: u32, path: impl Into<String>) -> Option<T>;
}
```

### Match

Result of a successful route match.

```rust
pub struct Match<'k, 'v, V> {
    pub value: V,
    pub params: Params<'k, 'v>,
}
```

### Params

URL path parameters extracted from the matched route.

```rust
pub struct Params<'k, 'v>;

impl Params {
    pub fn new() -> Self;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn get(&self, key: impl AsRef<str>) -> Option<&'v str>;
    pub fn iter(&self) -> ParamsIter<'_, 'k, 'v>;
}
```

### VirtualHost

A virtual host with its own radix tree and method filter.

```rust
pub struct VirtualHost<T> {
    pub name: String,
    pub tree: Node<T>,
    pub methods: HttpMethodSet,
}

impl<T> VirtualHost<T> {
    pub fn new(name: impl Into<String>, methods: HttpMethodSet) -> Self;
}
```

### Pattern DSL

User partial path-to-regex syntax for captur named params, and wildcard. Don't support complex regex patterns

```rust
/// Converts pattern syntax:
///   /users/:id        → /users/{id}     (param)
///   /api/files/*      → /api/files/{*_}  (multi-segment, * at end)
///   /api/*/action     → /api/{_}/action  (single-segment, * mid-path)
///   /exact/path       → /exact/path     (static)
///   /*                → /{*_}           (catch-all)
pub fn normalize_pattern(pattern: &str) -> String;
```

### Errors

```rust
pub enum InsertError {
    Conflict { with: String },
    InvalidParamSegment,
    InvalidParam,
    InvalidCatchAll,
}

pub enum MatchError {
    NotFound,
    MethodNotAllowed,
    HostNotFound,
}
```

## Route Pattern Reference

| Type                   | DSL Pattern          | Example Match        | Example No Match |
| ---------------------- | -------------------- | -------------------- | ---------------- |
| Exact                  | `/api/users`         | `/api/users`         | `/api/users/123` |
| Param simple           | `/api/users/:id`     | `/api/users/1`       | `/api/users/1/x` |
| Multi-segment wildcard | `/api/files/*`       | `/api/files/a/b/c`   | —                |
| Param + wildcard mix   | `/users/:id/posts/*` | `/users/1/posts/a/b` | `/users/1/posts` |
| Catch-all              | `/*`                 | any path             | —                |
