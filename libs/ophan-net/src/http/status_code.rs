use http::StatusCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusPattern {
    Code(StatusCode),
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
}

impl From<StatusCode> for StatusPattern {
    fn from(status: StatusCode) -> Self {
        Self::Code(status)
    }
}

const MIN_STATUS: usize = 100;
const MAX_STATUS: usize = 599;
const WORDS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct StatusCodeSet {
    bits: [u64; WORDS],
}

impl StatusCodeSet {
    /// Creates an empty status code set.
    #[inline]
    pub const fn new() -> Self {
        Self { bits: [0; WORDS] }
    }

    /// Returns true if the set contains no status codes.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;

        while i < WORDS {
            if self.bits[i] != 0 {
                return false;
            }
            i += 1;
        }

        true
    }

    /// Removes all status codes.
    #[inline]
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }

    /// Inserts a status code into the set.
    ///
    /// Returns `true` if the value was not already present.
    #[inline]
    pub fn insert<P: Into<StatusPattern>>(&mut self, pattern: P) {
        match pattern.into() {
            StatusPattern::Code(status) => {
                let (word, mask) = Self::index(status);
                self.bits[word] |= mask;
            },

            StatusPattern::Informational => {
                self.bits[7] |= 1 << 52;
            },

            StatusPattern::Success => {
                self.bits[7] |= 1 << 53;
            },

            StatusPattern::Redirection => {
                self.bits[7] |= 1 << 54;
            },

            StatusPattern::ClientError => {
                self.bits[7] |= 1 << 55;
            },

            StatusPattern::ServerError => {
                self.bits[7] |= 1 << 56;
            },
        }
    }

    /// Removes a status code from the set.
    ///
    /// Returns `true` if the value was present.
    #[inline]
    pub fn remove(&mut self, status: StatusCode) -> bool {
        let (word, mask) = Self::index(status);

        let existed = (self.bits[word] & mask) != 0;
        self.bits[word] &= !mask;

        existed
    }

    /// Returns whether the set contains the status code.
    #[inline]
    pub fn contains(&self, status: StatusCode) -> bool {
        let (word, mask) = Self::index(status);
        (self.bits[word] & mask) != 0
    }

    #[inline(always)]
    fn index(status: StatusCode) -> (usize, u64) {
        let code = status.as_u16() as usize;

        debug_assert!(
            (MIN_STATUS..=MAX_STATUS).contains(&code),
            "status code {code} is outside the supported range (100..=599)"
        );

        let idx = code - MIN_STATUS;

        (idx >> 6, 1u64 << (idx & 63))
    }
}

impl<const N: usize> From<[StatusCode; N]> for StatusCodeSet {
    fn from(statuses: [StatusCode; N]) -> Self {
        let mut set = Self::new();

        for status in statuses {
            set.insert(status);
        }

        set
    }
}

impl FromIterator<StatusCode> for StatusCodeSet {
    fn from_iter<T: IntoIterator<Item = StatusCode>>(iter: T) -> Self {
        let mut set = Self::new();

        for status in iter {
            set.insert(status);
        }

        set
    }
}
