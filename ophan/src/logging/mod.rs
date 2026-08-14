use bytes::Bytes;
use http::HeaderValue;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::OnceLock;
use uuid::Uuid;

/// Lazily initialized HTTP tracing identifier.
///
/// The identifier is stored internally as a [`HeaderValue`] to avoid repeated
/// conversions when writing HTTP headers.
///
/// If no value is explicitly provided, a UUID v4 is generated on first access.
#[derive(Debug)]
pub struct TracingId<T = ()> {
    inner: OnceLock<HeaderValue>,
    _marker: PhantomData<T>,
}

impl<T> Default for TracingId<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TracingId<T> {
    #[inline]
    pub const fn empty() -> Self {
        Self { inner: OnceLock::new(), _marker: PhantomData }
    }

    #[inline]
    pub const fn new() -> Self {
        Self { inner: OnceLock::new(), _marker: PhantomData }
    }

    /// Creates a tracing identifier initialized with a freshly generated UUID v4.
    #[inline]
    pub fn new_uuid() -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(Self::generate_header_value());

        Self { inner: cell, _marker: PhantomData }
    }

    /// Creates a tracing identifier from an existing HTTP header value.
    #[inline]
    pub fn from_header_value(value: HeaderValue) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(value);

        Self { inner: cell, _marker: PhantomData }
    }

    /// Creates a tracing identifier from raw header bytes.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the provided bytes are a valid HTTP
    /// header value. This constructor bypasses all validation.
    #[inline]
    pub unsafe fn from_bytes_unchecked<TBytes>(bytes: TBytes) -> Self
    where
        TBytes: Into<Bytes>,
    {
        let cell = OnceLock::new();

        let _ = cell.set(unsafe { HeaderValue::from_maybe_shared_unchecked(bytes.into()) });

        Self { inner: cell, _marker: PhantomData }
    }

    #[inline]
    fn generate_header_value() -> HeaderValue {
        let mut buffer = Uuid::encode_buffer();
        let uuid = Uuid::new_v4().hyphenated().encode_lower(&mut buffer);

        HeaderValue::from_str(uuid).expect("generated UUID must always be a valid HTTP header value")
    }

    /// Returns the header value, generating a UUID lazily if necessary.
    #[inline]
    pub fn as_header_value(&self) -> &HeaderValue {
        self.inner.get_or_init(Self::generate_header_value)
    }

    /// Returns the raw header bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_header_value().as_bytes()
    }

    /// Returns the identifier as a UTF-8 string.
    ///
    /// # Safety
    ///
    /// This conversion is sound because the value always originates from
    /// either:
    ///
    /// - a validated HTTP header value, or
    /// - an internally generated ASCII UUID.
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_bytes()) }
    }

    /// Returns `true` if the identifier has already been initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.inner.get().is_some()
    }
}

impl<T> Deref for TracingId<T> {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<T> fmt::Display for TracingId<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<T> AsRef<str> for TracingId<T> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<T> AsRef<[u8]> for TracingId<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T> AsRef<HeaderValue> for TracingId<T> {
    #[inline]
    fn as_ref(&self) -> &HeaderValue {
        self.as_header_value()
    }
}

impl<T> From<TracingId<T>> for HeaderValue {
    #[inline]
    fn from(value: TracingId<T>) -> Self {
        value.as_header_value().clone()
    }
}

impl<T> From<&TracingId<T>> for HeaderValue {
    #[inline]
    fn from(value: &TracingId<T>) -> Self {
        value.as_header_value().clone()
    }
}

impl<T> From<HeaderValue> for TracingId<T> {
    #[inline]
    fn from(value: HeaderValue) -> Self {
        Self::from_header_value(value)
    }
}

impl<T> From<&HeaderValue> for TracingId<T> {
    #[inline]
    fn from(value: &HeaderValue) -> Self {
        Self::from_header_value(value.clone())
    }
}

/// Marker type for request identifiers.
pub struct RequestIdMarker;

/// Marker type for trace identifiers.
pub struct TraceIdMarker;

/// HTTP request identifier.
pub type RequestId = TracingId<RequestIdMarker>;

/// Distributed tracing identifier.
pub type TraceId = TracingId<TraceIdMarker>;
