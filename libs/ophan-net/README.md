# ophan-net — Networking Layer

> ⚠️ **Active Development** — API may change without notice.

HTTP client, ingress parsing, wire protocol encoding/decoding, and transport abstraction for the Ophan gateway.

## Public API

### HTTP Client (outbound)

`reqwest`-style async HTTP client for outbound requests.

```rust
pub struct Client;

impl Client {
    pub fn new() -> Self;
    pub fn head(&self, url: &str) -> Result<RequestBuilder, Error>;
    pub fn get(&self, url: &str) -> Result<RequestBuilder, Error>;
    pub fn post(&self, url: &str) -> Result<RequestBuilder, Error>;
    pub fn put(&self, url: &str) -> Result<RequestBuilder, Error>;
    pub fn patch(&self, url: &str) -> Result<RequestBuilder, Error>;
}

pub struct RequestBuilder;

impl RequestBuilder {
    pub fn version(self, version: Version) -> Self;
    pub fn header(self, name: &str, value: &str) -> Self;
    pub fn body(self, body: impl Into<Body>) -> Self;
    pub fn form(self, form: Vec<(&str, &str)>) -> Self;
    pub fn multipart(self) -> MultipartBuilder;
    pub async fn send(self) -> Result<Response, Error>;
}

pub struct Response;

impl Response {
    pub fn status(&self) -> u16;
    pub fn version(&self) -> Version;
    pub fn headers(&self) -> &HeaderMap;
    pub fn url(&self) -> &str;
    pub async fn text(self) -> Result<String, Error>;
    pub async fn json<T: DeserializeOwned>(self) -> Result<T, Error>;
    pub async fn bytes(self) -> Result<Bytes, Error>;
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, Error>;
    pub fn error_for_status(self) -> Result<Self, Error>;
}

// Multipart
pub struct MultipartBuilder;

impl MultipartBuilder {
    pub fn new() -> Self;
    pub fn field(self, name: &str, value: &str) -> Self;
    pub fn file(self, name: &str, filename: &str, data: Bytes) -> Self;
    pub fn finish(self) -> RequestBuilder;
}

// Error
pub struct Error { pub kind: ErrorKind, pub status: Option<u16>, pub url: Option<String> }
pub enum ErrorKind {
    Timeout,
    StatusCode(u16),
    ConnectFailed,
    InvalidUrl(String),
    Decode(String),
    Encode(String),
    Io(std::io::Error),
}
```

### HTTP Ingress (inbound)

Zero-copy request parsing from raw bytes.

```rust
pub struct IncomingRequest;

impl IncomingRequest {
    /// Parse a complete HTTP request from raw bytes.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), String>;
    pub fn method(&self) -> &str;
    pub fn path(&self) -> &str;
    pub fn version(&self) -> Version;
    pub fn headers(&self) -> &[(String, String)];
    pub fn header(&self, name: &str) -> Option<&str>;
    pub fn header_value(&self, name: &[u8]) -> Option<&[u8]>;
    pub fn header_str(&self, name: &str) -> Option<&str>;
    pub fn content_length(&self) -> Option<u64>;
    pub fn is_chunked(&self) -> bool;
    pub fn expects_body(&self) -> bool;
    pub fn body(&self) -> &[u8];
}
```

### Proxy Integration

Re-exports from Pingora for gateway proxy lifecycle.

```rust
pub trait HttpProxyGateway: pingora::proxy::ProxyHttp { type CTX; }
pub type Session = pingora::proxy::Session;
```

### HTTP Methods

Bitmask-style HTTP method representation.

```rust
pub struct HttpMethod(u16);

// Constants
pub const NONE: HttpMethod;
pub const GET: HttpMethod;
pub const POST: HttpMethod;
pub const PUT: HttpMethod;
pub const DELETE: HttpMethod;
pub const PATCH: HttpMethod;
pub const HEAD: HttpMethod;
pub const OPTIONS: HttpMethod;
pub const TRACE: HttpMethod;
pub const CONNECT: HttpMethod;
pub const ALL: HttpMethod;
```

### HttpMethodSet

Set of standard + custom HTTP methods.

```rust
pub struct HttpMethodSet;

impl HttpMethodSet {
    pub const fn new(standard: HttpMethod) -> Self;
    pub const fn all() -> Self;
    pub fn with_custom(self, method: &[u8]) -> Self;
    pub fn add_standard(&mut self, method: HttpMethod);
    pub fn add_custom(&mut self, method: &[u8]);
    pub fn contains_http(&self, method: HttpMethod) -> bool;
    pub fn contains_bytes(&self, method: &[u8]) -> bool;
    pub fn contains_str(&self, method: &str) -> bool;
    pub fn contains_method(&self, method: &Method) -> bool;
    pub fn is_any(&self) -> bool;
    pub fn standard(&self) -> HttpMethod;
    pub fn custom(&self) -> &[Box<[u8]>];
}
```

### Wire Protocol

Low-level HTTP request encoder and response decoder.

```rust
pub struct Decoder;

impl Decoder {
    pub fn new() -> Self;
    pub fn parse(&mut self, buf: &[u8]) -> Result<Option<(&[u8], &[u8])>, WireError>;
    pub fn parse_status_only(&mut self, buf: &[u8]) -> Result<Option<u16>, WireError>;
}

pub struct Encoder;

impl Encoder {
    pub fn new(method: &str, path: &str) -> Self;
    pub fn with_version(self, version: Version) -> Self;
    pub fn with_headers(self, headers: &HeaderMap) -> Self;
    pub fn with_body(self, body: Bytes) -> Self;
    pub fn finalize(self) -> Result<Bytes, WireError>;
}

pub enum WireError { /* ... */ }
```

### Transport

Async TCP / Unix stream abstraction.

```rust
pub enum Transport {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

impl Transport {
    pub fn set_nodelay(&self, nodelay: bool) -> Result<()>;
}

pub async fn connect_tcp(host: &str, port: u16) -> Result<Transport, std::io::Error>;
pub async fn connect_unix(path: &str) -> Result<Transport, std::io::Error>;
```
