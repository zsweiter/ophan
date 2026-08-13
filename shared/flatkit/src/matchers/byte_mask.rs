#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteMask {
    bits: [u8; 32],
}

impl ByteMask {
    pub const EMPTY: Self = Self { bits: [0; 32] };
    pub const ALL: Self = Self { bits: [0xFF; 32] };

    #[inline]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Set a single byte.
    #[inline]
    pub fn insert(&mut self, b: u8) {
        self.bits[(b >> 3) as usize] |= 1 << (b & 7);
    }

    /// Set an inclusive range (e.g. b'a'..=b'z').
    #[inline]
    pub fn insert_range(&mut self, from: u8, to: u8) {
        for b in from..=to {
            self.insert(b);
        }
    }

    /// Set many bytes at once.
    #[inline]
    pub fn insert_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.insert(b);
        }
    }

    #[inline]
    pub fn remove(&mut self, b: u8) {
        self.bits[(b >> 3) as usize] &= !(1 << (b & 7));
    }

    /// Invert the mask (useful for [^...]).
    #[inline]
    pub fn invert(&mut self) {
        for slot in &mut self.bits {
            *slot = !*slot;
        }
    }

    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.bits[(b >> 3) as usize] & (1 << (b & 7)) != 0
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&x| x == 0)
    }

    #[inline]
    pub fn union(&mut self, other: &Self) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    #[inline]
    pub fn intersection(&mut self, other: &Self) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a &= *b;
        }
    }

    /// Build from a classic glob/regex-style class body (without the brackets).
    /// Supports ranges `a-z` and negation if the first char is `^`.
    pub fn from_class_body(body: &[u8]) -> Self {
        let mut mask = Self::new();
        if body.is_empty() {
            return mask;
        }

        let mut i = 0;
        let negate = body[0] == b'^';
        if negate {
            i = 1;
        }

        while i < body.len() {
            if i + 2 < body.len() && body[i + 1] == b'-' {
                let lo = body[i];
                let hi = body[i + 2];
                mask.insert_range(lo.min(hi), lo.max(hi));
                i += 3;
            } else {
                mask.insert(body[i]);
                i += 1;
            }
        }

        if negate {
            mask.invert();
        }
        mask
    }

    /// Insert a single Unicode scalar value.
    /// Only the raw UTF-8 bytes are set (correct for byte-oriented globs).
    #[inline]
    pub fn insert_char(&mut self, c: char) {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.insert_bytes(s.as_bytes());
    }

    /// Insert every byte of the string.
    #[inline]
    pub fn insert_str(&mut self, s: &str) {
        self.insert_bytes(s.as_bytes());
    }

    /// Build from a class body given as `&str` (e.g. `"a-zA-Z0-9_"` or `"^ \t"`).
    #[inline]
    pub fn from_class_body_str(body: &str) -> Self {
        Self::from_class_body(body.as_bytes())
    }

    /// Convenience: mask containing all bytes of the given string.
    #[inline]
    pub fn from_str_bytes(s: &str) -> Self {
        let mut m = Self::new();
        m.insert_str(s);
        m
    }
}

impl Default for ByteMask {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ByteMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut chars = Vec::new();
        for b in 0u8..=255 {
            if self.contains(b) {
                if b.is_ascii_graphic() || b == b' ' {
                    chars.push(b as char);
                } else {
                    // keep it short
                }
            }
        }
        write!(f, "ByteMask({:?})", chars.iter().collect::<String>())
    }
}

#[cfg(test)]
mod happy_cases {
    use super::ByteMask;

    #[test]
    fn insert_and_contains() {
        let mut mask = ByteMask::new();
        mask.insert(b'a');
        assert!(mask.contains(b'a'));
    }

    #[test]
    fn insert_range_is_inclusive() {
        let mut mask = ByteMask::new();
        mask.insert_range(b'a', b'c');
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'b'));
        assert!(mask.contains(b'c'));
    }

    #[test]
    fn insert_bytes_many_at_once() {
        let mut mask = ByteMask::new();
        mask.insert_bytes(b"aeiou");
        for b in b"aeiou" {
            assert!(mask.contains(*b));
        }
    }

    #[test]
    fn from_class_body_with_ranges_and_literals() {
        let mask = ByteMask::from_class_body(b"a-cx");
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'c'));
        assert!(mask.contains(b'x'));
        assert!(!mask.contains(b'd'));
    }

    #[test]
    fn from_class_body_str() {
        let mask = ByteMask::from_class_body_str("a-zA-Z");
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'z'));
        assert!(mask.contains(b'A'));
        assert!(mask.contains(b'Z'));
    }

    #[test]
    fn from_str_bytes() {
        let mask = ByteMask::from_str_bytes("hey");
        assert!(mask.contains(b'h'));
        assert!(mask.contains(b'e'));
        assert!(mask.contains(b'y'));
    }

    #[test]
    fn union_combines_both_masks() {
        let mut a = ByteMask::new();
        a.insert(b'a');
        let mut b = ByteMask::new();
        b.insert(b'b');
        a.union(&b);
        assert!(a.contains(b'a'));
        assert!(a.contains(b'b'));
    }

    #[test]
    fn intersection_keeps_only_common() {
        let mut a = ByteMask::new();
        a.insert_bytes(b"abcd");
        let mut b = ByteMask::new();
        b.insert_bytes(b"cdef");
        a.intersection(&b);
        assert!(a.contains(b'c'));
        assert!(a.contains(b'd'));
        assert!(!a.contains(b'a'));
        assert!(!a.contains(b'e'));
    }

    #[test]
    fn invert_turns_empty_into_all() {
        let mut mask = ByteMask::new();
        mask.invert();
        assert!(mask.contains(b'a'));
        assert!(mask.contains(0));
        assert!(mask.contains(255));
        assert!(!mask.is_empty());
    }

    #[test]
    fn default_is_empty() {
        assert!(ByteMask::default().is_empty());
    }

    #[test]
    fn constants_empty_and_all() {
        assert!(ByteMask::EMPTY.is_empty());
        assert!(ByteMask::ALL.contains(0));
        assert!(ByteMask::ALL.contains(255));
    }
}

#[cfg(test)]
mod fail_cases {
    use super::ByteMask;

    #[test]
    fn contains_false_for_missing_byte() {
        let mask = ByteMask::from_str_bytes("abc");
        assert!(!mask.contains(b'z'));
    }

    #[test]
    fn remove_clears_the_byte() {
        let mut mask = ByteMask::from_str_bytes("abc");
        mask.remove(b'b');
        assert!(!mask.contains(b'b'));
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'c'));
    }

    #[test]
    fn remove_from_absent_byte_is_noop() {
        let mut mask = ByteMask::new();
        mask.remove(b'x');
        assert!(mask.is_empty());
    }

    #[test]
    fn disjoint_union_leaves_each_side_intact() {
        let mut a = ByteMask::new();
        a.insert(b'a');
        let mut b = ByteMask::new();
        b.insert(b'b');
        a.union(&b);
        assert!(!a.contains(b'c'));
    }

    #[test]
    fn disjoint_intersection_is_empty() {
        let mut a = ByteMask::from_str_bytes("abc");
        let b = ByteMask::from_str_bytes("xyz");
        a.intersection(&b);
        assert!(a.is_empty());
    }

    #[test]
    fn negated_class_excludes_everything_else() {
        let mask = ByteMask::from_class_body(b"^a-z");
        assert!(!mask.contains(b'a'));
        assert!(!mask.contains(b'z'));
        assert!(mask.contains(b'A'));
        assert!(mask.contains(0));
    }

    #[test]
    fn empty_class_body_is_empty() {
        let mask = ByteMask::from_class_body(b"");
        assert!(mask.is_empty());
    }

    #[test]
    fn invert_of_all_is_empty() {
        let mut mask = ByteMask::ALL;
        mask.invert();
        assert!(mask.is_empty());
    }

    #[test]
    fn is_empty_false_after_insert() {
        let mut mask = ByteMask::new();
        assert!(mask.is_empty());
        mask.insert(b'a');
        assert!(!mask.is_empty());
    }
}

#[cfg(test)]
mod edge_cases {
    use super::ByteMask;

    #[test]
    fn byte_boundaries_zero_and_255() {
        let mut mask = ByteMask::new();
        mask.insert(0);
        mask.insert(255);
        assert!(mask.contains(0));
        assert!(mask.contains(255));
        assert!(!mask.contains(1));
        assert!(!mask.contains(254));
    }

    #[test]
    fn full_range_0_255() {
        let mut mask = ByteMask::new();
        mask.insert_range(0, 255);
        assert_eq!(mask, ByteMask::ALL);
    }

    #[test]
    fn single_byte_range() {
        let mut mask = ByteMask::new();
        mask.insert_range(b'a', b'a');
        assert!(mask.contains(b'a'));
        assert!(!mask.contains(b'b'));
    }

    #[test]
    fn reversed_range_is_normalized() {
        let mask = ByteMask::from_class_body(b"z-a");
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'm'));
        assert!(mask.contains(b'z'));
    }

    #[test]
    fn descending_insert_range_is_empty() {
        let mut mask = ByteMask::new();
        mask.insert_range(b'z', b'a');
        assert!(mask.is_empty());
    }

    #[test]
    fn trailing_dash_is_a_literal() {
        let mask = ByteMask::from_class_body(b"a-");
        assert!(mask.contains(b'a'));
        assert!(mask.contains(b'-'));
    }

    #[test]
    fn lone_caret_means_everything() {
        let mask = ByteMask::from_class_body(b"^");
        assert_eq!(mask, ByteMask::ALL);
    }

    #[test]
    fn multi_byte_utf8_char_inserts_raw_bytes() {
        let mut mask = ByteMask::new();
        mask.insert_char('ñ');
        assert!(mask.contains(0xC3));
        assert!(mask.contains(0xB1));
        assert!(!mask.contains(b'n'));
    }

    #[test]
    fn insert_str_with_multibyte() {
        let mask = ByteMask::from_str_bytes("é");
        assert!(mask.contains(0xC3));
        assert!(mask.contains(0xA9));
    }

    #[test]
    fn all_minus_one_byte() {
        let mut mask = ByteMask::ALL;
        mask.remove(b'x');
        assert!(!mask.contains(b'x'));
        assert!(mask.contains(b'y'));
    }

    #[test]
    fn debug_output_lists_graphic_chars() {
        let mask = ByteMask::from_str_bytes("ab");
        assert_eq!(format!("{:?}", mask), "ByteMask(\"ab\")");
    }
}
