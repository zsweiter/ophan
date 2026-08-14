//! Per-field text matcher bundle.
//!
//! [`TextMatchers`] groups a field's compiled literal + regex matchers so the
//! engine can ask a single zero-copy `is_match(&[u8])` question per field
//! per request.
//!
//! ## Composition
//!
//! - [`aho_corasick::AhoCorasick`] — multi-literal exact / substring
//!   matching. Compiles all literal `Contains` / `Eq` patterns of a field
//!   into a single AC automaton so one scan over the input bytes finds any
//!   of them in `O(n + m)` where `n` = input length and `m` = patterns'
//!   total length. **This is the hot-path matcher** for
//!   `Contains`-heavy phases (path, query, headers, body literals).
//! - `prefix_patterns: Vec<String>` + `suffix_patterns: Vec<String>` —
//!   small vectors of `StartsWith` / `EndsWith` literals. Cheap enough to
//!   iterate linearly; once they grow past a hand-tuned threshold the
//!   compiler could upgrade them to a small trie (not done today).
//! - [`regex::bytes::RegexSet`] — set of compiled regexes for the field.
//!   One `is_match` call runs all of them in a single sweep. Reserved for
//!   the `Regex` operator; not used for literals.
//! - [`flatkit::matchers::PathMatcherSet`] — glob matcher (`Glob`
//!   operator). Backed by `flatkit`'s compact radix-based matcher; valid
//!   only for `Path` per `RULES.md`.
//!
//! ## Zero-copy guarantee
//!
//! [`TextMatchers::is_match`] borrows `&[u8]` from the caller. No allocation
//! is performed on the hot path. Header / path / query bytes coming from
//! the proxy's `RequestParts` are passed directly here without copying into
//! an owned buffer.
//!
//! [`flatkit::matchers::PathMatcherSet`]: flatkit::matchers::PathMatcherSet

use std::sync::Arc;

use aho_corasick::AhoCorasick;
use flatkit::matchers::PathMatcherSet;
use regex::bytes::RegexSet;

///Compiled, immutable, field-scoped matcher bundle. Cheap to clone.
#[derive(Debug, Clone)]
pub struct TextMatchers {
    /// Whole-value equality (`Eq` operator). Stored as raw byte strings —
    /// equality is checked as `input == pattern`, never as substring.
    /// Kept separate from `exact_patterns` because Aho-Corasick performs
    /// substring search, which would over-match an `Eq` predicate.
    pub eq_patterns: Vec<Vec<u8>>,
    /// Aho-Corasick automaton over all literal patterns of the field
    /// (`Contains`). `None` when the field has no literal patterns.
    pub exact_patterns: Option<Arc<AhoCorasick>>,
    /// Literal prefixes (`StartsWith`). `Vec` because these are typically a
    /// handful of short routes (`/api/v1/`, `internal.`). Linear scan.
    pub prefix_patterns: Vec<String>,
    /// Literal suffixes (`EndsWith`). Same reasoning as `prefix_patterns`.
    pub suffix_patterns: Vec<String>,
    /// Combined regex set (`Regex` operator). `None` if no regex.
    pub regex_patterns: Option<RegexSet>,
    /// Glob matcher (`Glob` operator, `Path` only per `RULES.md`). `None`
    /// if no glob patterns.
    pub glob_patterns: Option<PathMatcherSet>,
}

impl TextMatchers {
    /// Mark the matcher bundle as empty if every component is `None`/empty.
    /// Used at compile time to drop empty `CompiledRule` field slots.
    pub fn is_empty(&self) -> bool {
        self.eq_patterns.is_empty()
            && self.exact_patterns.is_none()
            && self.prefix_patterns.is_empty()
            && self.suffix_patterns.is_empty()
            && self.regex_patterns.is_none()
            && self.glob_patterns.is_none()
    }

    /// Answer the match question. **Zero-copy**: borrows `input` from the
    /// caller; no allocation. Order of checks is cheapest-first:
    /// eq → exact (AC) → prefix → suffix → regex → glob, so a regex/glob is
    /// only run when cheap alternatives miss. Fail-fast inside AC: AC scans
    /// all literals in a single sweep, but the function returns on the first
    /// component that hits.
    #[inline]
    pub fn is_match(&self, input: &[u8]) -> bool {
        for eq in &self.eq_patterns {
            if input == eq.as_slice() {
                return true;
            }
        }

        if self.exact_patterns.as_ref().is_some_and(|re| re.is_match(input)) {
            return true;
        }

        for prefix in &self.prefix_patterns {
            if input.starts_with(prefix.as_bytes()) {
                return true;
            }
        }

        for suffix in &self.suffix_patterns {
            if input.ends_with(suffix.as_bytes()) {
                return true;
            }
        }

        if self.regex_patterns.as_ref().is_some_and(|re| re.is_match(input)) {
            return true;
        }

        if self.glob_patterns.as_ref().is_some_and(|gb| gb.is_match(input)) {
            return true;
        }

        false
    }
}
