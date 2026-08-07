use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use bytes::Bytes;
use futures::Stream;
use http::{HeaderName, HeaderValue, StatusCode};

use crate::proxy::ResponseParts;

pub struct HttpResponse {
    pub header: ResponseParts,
    pub body: Option<HttpBody>,
}

pub type BoxBody = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static>>;

pub enum HttpBody {
    Bytes(Bytes),
    Stream(BoxBody),
}

impl HttpResponse {
    #[inline]
    pub fn new(status: StatusCode) -> Self {
        Self {
            header: ResponseParts::build(status, None).expect("unexpected status code"),
            body: None,
        }
    }

    #[inline]
    pub fn with_capacity(status: StatusCode, capacity: usize) -> Self {
        Self {
            header: ResponseParts::build(status, Some(capacity)).expect("unexpected status code"),
            body: None,
        }
    }

    #[inline]
    pub fn with_header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.insert_header(name, value);
        self
    }

    #[inline]
    pub fn with_body(mut self, body: HttpBody) -> Self {
        self.body = Some(body);
        self
    }

    #[inline]
    pub fn insert_header(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> &mut Self {
        let _ = self.header.insert_header(name.into(), value.into());
        self
    }

    #[inline]
    pub fn append_header(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> &mut Self {
        let _ = self.header.append_header(name.into(), value.into());
        self
    }

    #[inline]
    pub fn remove_header(&mut self, name: &HeaderName) -> &mut Self {
        self.header.remove_header(name);
        self
    }

    #[inline]
    pub fn bytes(&mut self, body: impl Into<Bytes>) -> &mut Self {
        self.body = Some(HttpBody::Bytes(body.into()));
        self
    }

    #[inline]
    pub fn stream<S>(&mut self, body: S) -> &mut Self
    where
        S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        self.body = Some(HttpBody::Stream(Box::pin(body)));
        self
    }

    #[inline]
    pub fn header(&self) -> &ResponseParts {
        &self.header
    }

    #[inline]
    pub fn header_mut(&mut self) -> &mut ResponseParts {
        &mut self.header
    }

    #[inline]
    pub fn into_body(self) -> Option<HttpBody> {
        self.body
    }

    #[inline]
    pub fn into_parts(self) -> (ResponseParts, Option<HttpBody>) {
        (self.header, self.body)
    }
}

impl Deref for HttpResponse {
    type Target = ResponseParts;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl DerefMut for HttpResponse {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}
