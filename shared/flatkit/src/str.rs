use std::sync::Arc;
use std::{
    borrow::{Borrow, Cow},
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

#[derive(Clone)]
pub struct SmartString<const N: usize = 23> {
    repr: Repr<N>,
}

#[derive(Clone)]
enum Repr<const N: usize> {
    Inline(InlineString<N>),
    Heap(String),
}

#[derive(Clone)]
struct InlineString<const N: usize> {
    len: u8,
    buf: [u8; N],
}

impl<const N: usize> InlineString<N> {
    const fn new() -> Self {
        Self { len: 0, buf: [0; N] }
    }

    fn len(&self) -> usize {
        self.len as usize
    }

    fn capacity(&self) -> usize {
        N
    }

    fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len()]) }
    }

    fn push_str(&mut self, s: &str) -> bool {
        if self.len() + s.len() > N {
            return false;
        }

        let len = self.len();

        self.buf[len..len + s.len()].copy_from_slice(s.as_bytes());

        self.len += s.len() as u8;
        true
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> SmartString<N> {
    pub fn new() -> Self {
        Self { repr: Repr::Inline(InlineString::new()) }
    }

    pub fn with_capacity(cap: usize) -> Self {
        if cap <= N {
            Self::new()
        } else {
            Self { repr: Repr::Heap(String::with_capacity(cap)) }
        }
    }

    pub fn is_inline(&self) -> bool {
        matches!(self.repr, Repr::Inline(_))
    }

    pub fn is_heap(&self) -> bool {
        matches!(self.repr, Repr::Heap(_))
    }

    pub fn len(&self) -> usize {
        match &self.repr {
            Repr::Inline(s) => s.len(),
            Repr::Heap(s) => s.len(),
        }
    }

    pub fn capacity(&self) -> usize {
        match &self.repr {
            Repr::Inline(s) => s.capacity(),
            Repr::Heap(s) => s.capacity(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_str(&self) -> &str {
        match &self.repr {
            Repr::Inline(s) => s.as_str(),
            Repr::Heap(s) => s.as_str(),
        }
    }

    pub fn clear(&mut self) {
        match &mut self.repr {
            Repr::Inline(s) => s.clear(),
            Repr::Heap(s) => s.clear(),
        }
    }

    pub fn push_str(&mut self, text: &str) {
        match &mut self.repr {
            Repr::Inline(inline) => {
                if inline.push_str(text) {
                    return;
                }

                let mut string = String::with_capacity(inline.len() + text.len());

                string.push_str(inline.as_str());
                string.push_str(text);

                self.repr = Repr::Heap(string);
            },

            Repr::Heap(string) => {
                string.push_str(text);
            },
        }
    }

    pub fn push(&mut self, ch: char) {
        let mut buf = [0u8; 4];
        self.push_str(ch.encode_utf8(&mut buf));
    }

    pub fn reserve(&mut self, additional: usize) {
        match &mut self.repr {
            Repr::Heap(s) => s.reserve(additional),

            Repr::Inline(inline) => {
                if inline.len() + additional <= N {
                    return;
                }

                let mut string = String::with_capacity(inline.len() + additional);

                string.push_str(inline.as_str());

                self.repr = Repr::Heap(string);
            },
        }
    }

    pub fn into_string(self) -> String {
        match self.repr {
            Repr::Heap(s) => s,

            Repr::Inline(s) => s.as_str().to_owned(),
        }
    }
}

impl<const N: usize> Default for SmartString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> From<&str> for SmartString<N> {
    fn from(value: &str) -> Self {
        let mut s = Self::new();
        s.push_str(value);
        s
    }
}

impl<const N: usize> From<String> for SmartString<N> {
    fn from(value: String) -> Self {
        if value.len() <= N {
            Self::from(value.as_str())
        } else {
            Self { repr: Repr::Heap(value) }
        }
    }
}

impl<const N: usize> Deref for SmartString<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> AsRef<str> for SmartString<N> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> Borrow<str> for SmartString<N> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> fmt::Display for SmartString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<const N: usize> fmt::Debug for SmartString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<const N: usize> PartialEq for SmartString<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<const N: usize> Eq for SmartString<N> {}

impl<const N: usize> Hash for SmartString<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

/// A thread-safe, optimized immutable string.
///
/// use for string keys that are shared across multiple threads but never change.
///
#[derive(Clone, Eq, Ord, PartialOrd, Hash)]
pub struct ImmerStr {
    inner: Arc<str>,
}

impl ImmerStr {
    pub fn new<S: AsRef<str>>(s: S) -> Self {
        Self { inner: Arc::from(s.as_ref()) }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl Deref for ImmerStr {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<str> for ImmerStr {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl<T: AsRef<str> + ?Sized> PartialEq<T> for ImmerStr {
    #[inline]
    fn eq(&self, other: &T) -> bool {
        self.as_str() == other.as_ref()
    }
}

impl PartialEq<ImmerStr> for str {
    #[inline]
    fn eq(&self, other: &ImmerStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<ImmerStr> for &str {
    #[inline]
    fn eq(&self, other: &ImmerStr) -> bool {
        *self == other.as_str()
    }
}

impl From<String> for ImmerStr {
    fn from(s: String) -> Self {
        Self { inner: Arc::from(s.into_boxed_str()) }
    }
}

impl From<&str> for ImmerStr {
    fn from(s: &str) -> Self {
        Self { inner: Arc::from(s) }
    }
}

impl Borrow<str> for ImmerStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<'a> From<Cow<'a, str>> for ImmerStr {
    #[inline]
    fn from(s: Cow<'a, str>) -> Self {
        Self::new(s)
    }
}

impl From<Box<str>> for ImmerStr {
    #[inline]
    fn from(s: Box<str>) -> Self {
        Self::new(s)
    }
}

impl From<ImmerStr> for String {
    #[inline]
    fn from(s: ImmerStr) -> Self {
        s.as_str().to_string()
    }
}

impl From<ImmerStr> for Arc<str> {
    #[inline]
    fn from(s: ImmerStr) -> Self {
        s.inner
    }
}

impl fmt::Display for ImmerStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl fmt::Debug for ImmerStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}
