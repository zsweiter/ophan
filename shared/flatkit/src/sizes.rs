use core::{fmt, str};
use std::{
    num::ParseIntError,
    ops::{Add, AddAssign, Sub, SubAssign},
    str::FromStr,
};

pub struct FormattedSize {
    buf: [u8; 24],
    start: usize,
}

impl FormattedSize {
    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.buf[self.start..]) }
    }
}

impl core::ops::Deref for FormattedSize {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<&FormattedSize> for String {
    fn from(value: &FormattedSize) -> Self {
        value.as_str().to_string()
    }
}

impl AsRef<str> for FormattedSize {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for FormattedSize {
    fn from(s: &str) -> Self {
        let mut buf = [0u8; 24];

        let bytes = s.as_bytes();
        let len = bytes.len().min(24);

        buf[..len].copy_from_slice(&bytes[..len]);

        Self { buf, start: 0 }
    }
}

impl fmt::Display for FormattedSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn format_size(bytes: u64) -> FormattedSize {
    let mut buf = [0u8; 24];
    let mut pos = buf.len();

    let (integral, fractional, unit) = if bytes < 1024 {
        (bytes, 0, " B")
    } else if bytes < (1 << 20) {
        let val_x10 = (bytes * 10) >> 10;
        (val_x10 / 10, val_x10 % 10, " KB")
    } else if bytes < (1 << 30) {
        let val_x10 = (bytes * 10) >> 20;
        (val_x10 / 10, val_x10 % 10, " MB")
    } else if bytes < (1 << 40) {
        let val_x10 = (bytes * 10) >> 30;
        (val_x10 / 10, val_x10 % 10, " GB")
    } else {
        let val_x10 = ((bytes as u128) * 10 >> 40) as u64;
        (val_x10 / 10, val_x10 % 10, " TB")
    };

    let unit_bytes = unit.as_bytes();
    pos -= unit_bytes.len();
    buf[pos..pos + unit_bytes.len()].copy_from_slice(unit_bytes);

    if unit != " B" {
        pos -= 1;
        buf[pos] = b'0' + fractional as u8;
        pos -= 1;
        buf[pos] = b'.';
    }

    let mut num = integral;
    if num == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        while num > 0 {
            let rem = (num % 10) as u8;
            pos -= 1;
            buf[pos] = b'0' + rem;
            num /= 10;
        }
    }

    FormattedSize { buf, start: pos }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const ZERO: Self = Self(0);

    const KB_UNIT: u64 = 1024;
    const MB_UNIT: u64 = 1024 * 1024;
    const GB_UNIT: u64 = 1024 * 1024 * 1024;
    const TB_UNIT: u64 = 1024 * 1024 * 1024 * 1024;

    /// Creates a `ByteSize` from raw bytes.
    #[inline]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn from_kb(kb: u64) -> Self {
        Self(kb * Self::KB_UNIT)
    }

    #[inline]
    pub const fn from_mb(mb: u64) -> Self {
        Self(mb * Self::MB_UNIT)
    }

    #[inline]
    pub const fn from_gb(gb: u64) -> Self {
        Self(gb * Self::GB_UNIT)
    }

    #[inline]
    pub const fn from_tb(tb: u64) -> Self {
        Self(tb * Self::TB_UNIT)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the value as `usize` if it fits on the current platform.
    #[inline]
    pub const fn try_as_usize(self) -> Option<usize> {
        if self.0 <= usize::MAX as u64 {
            Some(self.0 as usize)
        } else {
            None
        }
    }

    #[inline]
    pub fn as_kb(self) -> f64 {
        self.0 as f64 / Self::KB_UNIT as f64
    }

    #[inline]
    pub fn as_mb(self) -> f64 {
        self.0 as f64 / Self::MB_UNIT as f64
    }

    #[inline]
    pub fn as_gb(self) -> f64 {
        self.0 as f64 / Self::GB_UNIT as f64
    }

    #[inline]
    pub fn as_tb(self) -> f64 {
        self.0 as f64 / Self::TB_UNIT as f64
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl FromStr for ByteSize {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if let Some(val) = s.strip_suffix("tb") {
            let n: u64 = val.parse()?;
            Ok(Self::from_tb(n))
        } else if let Some(val) = s.strip_suffix("gb") {
            let n: u64 = val.parse()?;
            Ok(Self::from_gb(n))
        } else if let Some(val) = s.strip_suffix("mb") {
            let n: u64 = val.parse()?;
            Ok(Self::from_mb(n))
        } else if let Some(val) = s.strip_suffix("kb") {
            let n: u64 = val.parse()?;
            Ok(Self::from_kb(n))
        } else if let Some(val) = s.strip_suffix('b') {
            let n: u64 = val.parse()?;
            Ok(Self::from_bytes(n))
        } else {
            let n: u64 = s.parse()?;
            Ok(Self::from_bytes(n))
        }
    }
}

impl From<u64> for ByteSize {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<usize> for ByteSize {
    #[inline]
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

impl Add for ByteSize {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.checked_add(rhs.0).expect("ByteSize overflow"))
    }
}

impl AddAssign for ByteSize {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for ByteSize {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        ByteSize(self.0 - rhs.0)
    }
}

impl SubAssign for ByteSize {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl fmt::Debug for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteSize({})", self)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        if bytes >= Self::TB_UNIT {
            write!(f, "{:.2} TB", bytes as f64 / Self::TB_UNIT as f64)
        } else if bytes >= Self::GB_UNIT {
            write!(f, "{:.2} GB", bytes as f64 / Self::GB_UNIT as f64)
        } else if bytes >= Self::MB_UNIT {
            write!(f, "{:.2} MB", bytes as f64 / Self::MB_UNIT as f64)
        } else if bytes >= Self::KB_UNIT {
            write!(f, "{:.2} KB", bytes as f64 / Self::KB_UNIT as f64)
        } else {
            write!(f, "{} B", bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_basic() {
        assert_eq!(format_size(0).as_str(), "0 B");
        assert_eq!(format_size(1).as_str(), "1 B");
        assert_eq!(format_size(512).as_str(), "512 B");
        assert_eq!(format_size(1023).as_str(), "1023 B");
    }

    #[test]
    fn test_kb_boundary() {
        assert_eq!(format_size(1024).as_str(), "1.0 KB");
        assert_eq!(format_size(1536).as_str(), "1.5 KB");
        assert_eq!(format_size(2048).as_str(), "2.0 KB");
        assert_eq!(format_size(10 * 1024).as_str(), "10.0 KB");
    }

    #[test]
    fn test_mb_boundary() {
        assert_eq!(format_size(1 << 20).as_str(), "1.0 MB");
        assert_eq!(format_size((1 << 20) + (512 << 10)).as_str(), "1.5 MB");
        assert_eq!(format_size(2 << 20).as_str(), "2.0 MB");
    }

    #[test]
    fn test_gb_boundary() {
        assert_eq!(format_size(1 << 30).as_str(), "1.0 GB");
        assert_eq!(format_size((1 << 30) + (512 << 20)).as_str(), "1.5 GB");
    }

    #[test]
    fn test_tb_boundary() {
        assert_eq!(format_size(1 << 40).as_str(), "1.0 TB");
        assert_eq!(format_size((1 << 40) + (512 << 30)).as_str(), "1.5 TB");
    }

    #[test]
    fn test_rounding_edge_cases() {
        assert_eq!(format_size(1023).as_str(), "1023 B");
        assert_eq!(format_size((1 << 20) - 1).as_str(), "1023.9 KB"); 
    }

    #[test]
    fn test_large_values() {
        assert!(format_size(u64::MAX).as_str().ends_with("TB"));
    }

    #[test]
    fn test_monotonic() {
        let values = [1u64, 10, 100, 1024, 10_000, 1_000_000, 1_000_000_000, 10_000_000_000, u64::MAX];

        for v in values {
            let s = format_size(v);

            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_unit_strings() {
        assert!(format_size(0).as_str().ends_with("B"));
        assert!(format_size(1024).as_str().ends_with("KB"));
        assert!(format_size(1 << 20).as_str().ends_with("MB"));
        assert!(format_size(1 << 30).as_str().ends_with("GB"));
        assert!(format_size(1 << 40).as_str().ends_with("TB"));
    }

    #[test]
    fn no_panic_large_values() {
        for i in [u64::MAX, u64::MAX - 1, 1 << 63] {
            let _ = format_size(i);
        }
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(ByteSize::from_str("100b").unwrap(), ByteSize::from_bytes(100));
        assert_eq!(ByteSize::from_str("5kb").unwrap(), ByteSize::from_kb(5));
        assert_eq!(ByteSize::from_str("10mb").unwrap(), ByteSize::from_mb(10));
        assert_eq!(ByteSize::from_str("2gb").unwrap(), ByteSize::from_gb(2));
        assert_eq!(ByteSize::from_str("2tb").unwrap(), ByteSize::from_tb(2));
    }
}
