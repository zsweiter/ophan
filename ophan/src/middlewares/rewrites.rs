//! Path rewriting engine.
//!
//! This module provides [`RewriteEngine`], a high-performance URL / path
//! rewriter
//!
//! ## Matching order & priority
//!
//! Rules are registered in the order they appear. Lower priority numbers win
//! (first rule has priority 0). The engine always selects the rule with the
//! *lowest* priority number among all matching candidates.
//!
//! Matching engines (evaluated in priority order, with early exit when
//! priority 0 is found):
//!
//! 1. **Exact match** – O hash lookup
//! 2. **Prefix trie** – longest matching prefix (byte-oriented)
//! 3. **Suffix trie** – longest matching suffix (byte-oriented, reversed)
//! 4. **Regex set** – first matching regex (order of registration)
//!
//! After a rewrite is chosen, trailing-slash policy is applied.

use ahash::AHashMap;
use regex::{Error as RegexError, Regex, RegexSet};
use std::{borrow::Cow, str::FromStr};

/// Action to take regarding a trailing slash on the final rewritten path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrailingSlashAction {
    /// Leave the path unchanged.
    #[default]
    Ignore,
    /// Ensure the path ends with `/` (except the empty path is left as-is
    /// after other processing; only non-empty paths are forced).
    Always,
    /// Ensure the path does **not** end with `/`, except for the root path `"/"`.
    Never,
}

impl FromStr for TrailingSlashAction {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            "ignore" => Ok(Self::Ignore),
            _ => Err(()),
        }
    }
}

/// A single node in the flat trie.
#[derive(Debug, Clone, Default)]
struct CompactNode {
    /// Optional rewrite rule that ends at this node: `(priority, replacement)`.
    rule: Option<(u32, Box<str>)>,
    /// Outgoing edges: `(byte, child_node_index)`.
    children: Vec<(u8, u32)>,
}

/// Flat (vector-backed) trie used for both prefix and suffix matching.
#[derive(Debug, Clone)]
struct FlatTrie {
    nodes: Vec<CompactNode>,
    /// Lowest priority present in this trie. Used as a fast rejection filter
    /// before walking the trie.
    min_prio: u32,
}

impl Default for FlatTrie {
    #[inline]
    fn default() -> Self {
        Self { nodes: vec![CompactNode::default()], min_prio: u32::MAX }
    }
}

impl FlatTrie {
    #[inline]
    fn new() -> Self {
        Self::default()
    }

    /// Insert a key (as an iterator of bytes) with the given replacement and priority.
    ///
    /// If a rule already exists at the terminal node it is **not** overwritten
    /// (first registration wins, consistent with global priority order).
    fn insert<I: Iterator<Item = u8>>(&mut self, iter: I, to: Box<str>, priority: u32) {
        if priority < self.min_prio {
            self.min_prio = priority;
        }

        let mut current_idx: usize = 0;
        for b in iter {
            let child_idx = self.nodes[current_idx].children.iter().find(|(c, _)| *c == b).map(|(_, idx)| *idx);

            match child_idx {
                Some(next_idx) => {
                    current_idx = next_idx as usize;
                },
                None => {
                    let new_node_idx = self.nodes.len() as u32;
                    self.nodes.push(CompactNode::default());
                    self.nodes[current_idx].children.push((b, new_node_idx));
                    current_idx = new_node_idx as usize;
                },
            }
        }

        // First rule at this node wins.
        if self.nodes[current_idx].rule.is_none() {
            self.nodes[current_idx].rule = Some((priority, to));
        }
    }

    /// Walk the trie and return the best (lowest-priority) rule found along
    /// the path, together with the number of bytes consumed.
    ///
    /// Returns `None` if no rule matched.
    #[inline]
    fn find_best<I: Iterator<Item = u8>>(&self, iter: I) -> Option<(usize, &str, u32)> {
        let mut current_idx: usize = 0;
        let mut best: Option<(u32, usize, &str)> = self.nodes[0].rule.as_ref().map(|(prio, to)| (*prio, 0, to.as_ref()));

        let mut consumed: usize = 0;

        for b in iter {
            // Hot path: the next byte continues the current path.
            if let Some(&(_, next_idx)) = self.nodes[current_idx].children.iter().find(|(c, _)| *c == b) {
                current_idx = next_idx as usize;
                consumed += 1;
                if let Some((prio, to)) = self.nodes[current_idx].rule.as_ref() {
                    // Keep the lowest priority (earliest registration).
                    if best.is_none_or(|(bp, _, _)| *prio < bp) {
                        best = Some((*prio, consumed, to.as_ref()));
                    }
                }
            } else {
                // Cold path: mismatch – stop.
                break;
            }
        }

        best.map(|(prio, len, to)| (len, to, prio))
    }
}

/// High-performance path rewrite engine.
#[derive(Debug, Clone, Default)]
pub struct RewriteEngine {
    exact: AHashMap<Box<str>, (u32, Box<str>)>,
    prefix_trie: FlatTrie,
    suffix_trie: FlatTrie,
    regex_set: Option<RegexSet>,
    /// Sorted by registration order (priority == index).
    regexes: Vec<(u32, Regex, Box<str>)>,
    trailing_slash: TrailingSlashAction,
}

impl RewriteEngine {
    /// Build a new engine from a list of rewrite rules.
    ///
    /// # Arguments
    ///
    /// * `raw_rules` – list of `(from, to)` pairs. Order determines priority
    ///   (first rule = priority 0, highest precedence).
    /// * `strip_prefix` – optional prefix that is always stripped (inserted
    ///   with the next available priority).
    /// * `strip_suffix` – optional suffix that is always stripped.
    /// * `trailing_slash` – policy applied after every rewrite.
    ///
    /// # Rule syntax
    ///
    /// * Exact path (no special characters) → exact match.
    /// * Ends with `*` → prefix match (the `*` is not part of the matched text).
    /// * Starts with `*` → suffix match.
    /// * Otherwise → treated as a regular expression.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError`] if any regex pattern is invalid. The error is
    /// bubbled up so callers can surface configuration problems early.
    pub fn new(
        raw_rules: Vec<(String, String)>,
        strip_prefix: Option<&str>,
        strip_suffix: Option<&str>,
        trailing_slash: TrailingSlashAction,
    ) -> Result<Self, RegexError> {
        let mut exact = AHashMap::default();
        let mut prefix_trie = FlatTrie::new();
        let mut suffix_trie = FlatTrie::new();
        let mut regexes = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut priority: u32 = 0;

        // Optional global strip rules (highest priority if present).
        if let Some(prefix) = strip_prefix.filter(|s| !s.is_empty()) {
            prefix_trie.insert(prefix.bytes(), "".into(), priority);
            priority += 1;
        }

        if let Some(suffix) = strip_suffix.filter(|s| !s.is_empty()) {
            // Store reversed so that find_best can walk path.bytes().rev().
            suffix_trie.insert(suffix.bytes().rev(), "".into(), priority);
            priority += 1;
        }

        for (from, to) in raw_rules {
            let from_str = from.trim();
            let to_boxed: Box<str> = to.into_boxed_str();

            if let Some(prefix) = from_str.strip_suffix('*') {
                // Prefix rule: "foo*" matches anything starting with "foo".
                prefix_trie.insert(prefix.bytes(), to_boxed, priority);
            } else if let Some(suffix) = from_str.strip_prefix('*') {
                // Suffix rule: "*bar" matches anything ending with "bar".
                suffix_trie.insert(suffix.bytes().rev(), to_boxed, priority);
            } else if is_plain_path(from_str) {
                // No regex metacharacters → exact match.
                exact.insert(from_str.into(), (priority, to_boxed));
            } else {
                // Compile as regex. Failure bubbles up.
                let re = Regex::new(from_str)?;
                regex_patterns.push(from_str.to_string());
                regexes.push((priority, re, to_boxed));
            }
            priority += 1;
        }

        let regex_set = if regex_patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&regex_patterns)?)
        };

        Ok(Self {
            exact,
            prefix_trie,
            suffix_trie,
            regex_set,
            regexes,
            trailing_slash,
        })
    }

    /// Apply rewrite rules with full priority evaluation (no early exit
    /// assumptions beyond the normal priority logic).
    #[inline]
    pub fn apply_hold<'a>(&self, path: &'a str) -> Cow<'a, str> {
        if path.is_empty() {
            return Cow::Borrowed(path);
        }

        // Collect the best candidate. Lower priority number wins.
        let mut candidate: Option<(u32, Cow<'a, str>)> = None;

        // Exact match (most common fast path for many workloads).
        if let Some((prio, to)) = self.exact.get(path) {
            candidate = Some((*prio, Cow::Owned(to.to_string())));
        }

        if let Some((len, to, prio)) = self.prefix_trie.find_best(path.bytes())
            && candidate.as_ref().is_none_or(|(cp, _)| prio < *cp)
        {
            let rest = &path[len..];
            let rewritten = if to.is_empty() {
                Cow::Borrowed(rest)
            } else {
                let mut out = String::with_capacity(to.len() + rest.len());
                out.push_str(to);
                out.push_str(rest);
                Cow::Owned(out)
            };
            candidate = Some((prio, rewritten));
        }

        if let Some((len, to, prio)) = self.suffix_trie.find_best(path.bytes().rev())
            && candidate.as_ref().is_none_or(|(cp, _)| prio < *cp)
        {
            let rest = &path[..path.len() - len];
            let rewritten = if to.is_empty() {
                Cow::Borrowed(rest)
            } else {
                let mut out = String::with_capacity(rest.len() + to.len());
                out.push_str(rest);
                out.push_str(to);
                Cow::Owned(out)
            };
            candidate = Some((prio, rewritten));
        }

        // Note: we still evaluate even when candidate priority is 0 because
        // apply_hold is the “full evaluation” path; the optimised apply()
        // short-circuits earlier.
        if let Some((prio, rewritten)) = self.match_regex(path)
            && candidate.as_ref().is_none_or(|(cp, _)| prio < *cp)
        {
            candidate = Some((prio, Cow::Owned(rewritten)));
        }

        let result = match candidate {
            Some((_, res)) => res,
            None => Cow::Borrowed(path),
        };

        self.apply_trailing_slash(result)
    }

    /// Apply rewrite rules with aggressive early exits for priority-0 rules
    /// and min-priority filters.
    #[inline]
    pub fn apply<'a>(&self, path: &'a str) -> Cow<'a, str> {
        // Cold / rare: empty path.
        if path.is_empty() {
            return Cow::Borrowed(path);
        }

        enum MatchKind<'a> {
            Exact(&'a str),
            Prefix { len: usize, to: &'a str },
            Suffix { len: usize, to: &'a str },
            Regex(String),
        }

        let mut best_prio = u32::MAX;
        let mut best_match: Option<MatchKind<'_>> = None;

        if let Some((prio, to)) = self.exact.get(path) {
            if *prio == 0 {
                return self.apply_trailing_slash(Cow::Owned(to.to_string()));
            }
            best_prio = *prio;
            best_match = Some(MatchKind::Exact(to));
        }

        if best_prio > self.prefix_trie.min_prio
            && let Some((len, to, prio)) = self.prefix_trie.find_best(path.bytes())
            && prio < best_prio
        {
            if prio == 0 {
                let rest = &path[len..];
                let rewritten = if to.is_empty() {
                    Cow::Borrowed(rest)
                } else {
                    let mut out = String::with_capacity(to.len() + rest.len());
                    out.push_str(to);
                    out.push_str(rest);
                    Cow::Owned(out)
                };

                return self.apply_trailing_slash(rewritten);
            }

            best_prio = prio;
            best_match = Some(MatchKind::Prefix { len, to });
        }

        if best_prio > self.suffix_trie.min_prio
            && let Some((len, to, prio)) = self.suffix_trie.find_best(path.bytes().rev())
            && prio < best_prio
        {
            if prio == 0 {
                let rest = &path[..path.len() - len];
                let rewritten = if to.is_empty() {
                    Cow::Borrowed(rest)
                } else {
                    let mut out = String::with_capacity(rest.len() + to.len());
                    out.push_str(rest);
                    out.push_str(to);
                    Cow::Owned(out)
                };
                return self.apply_trailing_slash(rewritten);
            }
            best_prio = prio;
            best_match = Some(MatchKind::Suffix { len, to });
        }

        if let Some((min_regex_prio, _, _)) = self.regexes.first()
            && best_prio > *min_regex_prio
            && let Some((prio, rewritten)) = self.match_regex(path)
            && prio < best_prio
        {
            // best_prio = prio;
            best_match = Some(MatchKind::Regex(rewritten));
        }

        let final_path = match best_match {
            Some(MatchKind::Exact(to)) => Cow::Owned(to.to_string()),
            Some(MatchKind::Prefix { len, to }) => {
                let rest = &path[len..];
                if to.is_empty() {
                    Cow::Borrowed(rest)
                } else {
                    let mut out = String::with_capacity(to.len() + rest.len());
                    out.push_str(to);
                    out.push_str(rest);
                    Cow::Owned(out)
                }
            },
            Some(MatchKind::Suffix { len, to }) => {
                let rest = &path[..path.len() - len];
                if to.is_empty() {
                    Cow::Borrowed(rest)
                } else {
                    let mut out = String::with_capacity(rest.len() + to.len());
                    out.push_str(rest);
                    out.push_str(to);
                    Cow::Owned(out)
                }
            },
            Some(MatchKind::Regex(rewritten)) => Cow::Owned(rewritten),
            None => Cow::Borrowed(path),
        };

        self.apply_trailing_slash(final_path)
    }

    /// Returns the first matching regex (by registration order) together with
    /// its priority and the rewritten string.
    #[inline]
    fn match_regex(&self, path: &str) -> Option<(u32, String)> {
        let set = self.regex_set.as_ref()?;
        let matched = set.matches(path);
        // First match in the set follows registration order.
        let idx = matched.iter().next()?;
        let (prio, re, to) = &self.regexes[idx];
        Some((*prio, re.replace(path, to.as_ref()).into_owned()))
    }

    /// Apply the configured trailing-slash policy.
    ///
    /// Special care is taken to keep `Cow::Borrowed` when possible (zero
    /// allocation on the `Never` path for already-borrowed slices).
    #[inline]
    fn apply_trailing_slash<'a>(&self, path: Cow<'a, str>) -> Cow<'a, str> {
        match self.trailing_slash {
            TrailingSlashAction::Ignore => path,
            TrailingSlashAction::Always => {
                if path.ends_with('/') {
                    path
                } else {
                    let mut owned = path.into_owned();
                    owned.push('/');
                    Cow::Owned(owned)
                }
            },
            TrailingSlashAction::Never => {
                // Root "/" must stay as-is; everything else loses a trailing slash.
                if path == "/" || !path.ends_with('/') {
                    path
                } else {
                    match path {
                        Cow::Borrowed(s) => Cow::Borrowed(&s[..s.len() - 1]),
                        Cow::Owned(mut s) => {
                            s.pop();
                            Cow::Owned(s)
                        },
                    }
                }
            },
        }
    }
}

/// Returns true when the string contains none of the regex metacharacters we
/// care about. Used to decide between exact-match and regex engines.
///
/// Operates only on ASCII; multi-byte UTF-8 sequences cannot contain these
/// characters, so a byte-level check would be equivalent but is unnecessary
/// because we already have a valid `&str`.
#[inline]
fn is_plain_path(path: &str) -> bool {
    !path.contains(['^', '$', '[', ']', '(', ')', '+', '?', '|', '\\', '*', '{', '}'])
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(
        rules: Vec<(&str, &str)>,
        strip_prefix: Option<&str>,
        strip_suffix: Option<&str>,
        trailing: TrailingSlashAction,
    ) -> RewriteEngine {
        let raw: Vec<(String, String)> = rules.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        RewriteEngine::new(raw, strip_prefix, strip_suffix, trailing).unwrap()
    }

    // ----- Construction / error bubbling -----

    #[test]
    fn invalid_regex_bubbles_error() {
        let rules = vec![("[".to_string(), "x".to_string())]; // invalid
        let err = RewriteEngine::new(rules, None, None, TrailingSlashAction::Ignore);
        assert!(err.is_err());
    }

    #[test]
    fn valid_regex_ok() {
        let rules = vec![("^/api/.*".to_string(), "/v2$0".to_string())];
        assert!(RewriteEngine::new(rules, None, None, TrailingSlashAction::Ignore).is_ok());
    }

    // ----- Exact match -----

    #[test]
    fn exact_match_basic() {
        let e = engine(vec![("/foo", "/bar")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/foo"), "/bar");
        assert_eq!(e.apply("/foo/"), "/foo/"); // no match
        assert_eq!(e.apply("/other"), "/other");
    }

    #[test]
    fn exact_match_priority_0_short_circuit() {
        let e = engine(
            vec![("/first", "/A"), ("/second", "/B")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        // /first has prio 0 → should short-circuit
        assert_eq!(e.apply("/first"), "/A");
        assert_eq!(e.apply("/second"), "/B");
    }

    // ----- Prefix -----

    #[test]
    fn prefix_match() {
        let e = engine(vec![("/api/*", "/v2")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/api/users"), "/v2users");
        assert_eq!(e.apply("/api/"), "/v2");
        assert_eq!(e.apply("/api"), "/api"); // no match for exact "/api" without *
    }

    #[test]
    fn prefix_empty_replacement() {
        // strip-style prefix
        let e = engine(vec![("/static/*", "")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/static/css/app.css"), "css/app.css");
    }

    #[test]
    fn strip_prefix_option() {
        let e = engine(vec![], Some("/legacy"), None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/legacy/foo"), "/foo");
        assert_eq!(e.apply("/other"), "/other");
    }

    // ----- Suffix -----

    #[test]
    fn suffix_match() {
        let e = engine(vec![("*.html", ".htm")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/page.html"), "/page.htm");
        assert_eq!(e.apply("/dir/page.html"), "/dir/page.htm");
        assert_eq!(e.apply("/page.htm"), "/page.htm");
    }

    #[test]
    fn strip_suffix_option() {
        let e = engine(vec![], None, Some(".php"), TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/index.php"), "/index");
        assert_eq!(e.apply("/index"), "/index");
    }

    // ----- Regex -----

    #[test]
    fn regex_capture_replace() {
        let e = engine(
            vec![(r"^/user/(\d+)$", "/profile/$1")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        assert_eq!(e.apply("/user/42"), "/profile/42");
        assert_eq!(e.apply("/user/abc"), "/user/abc");
    }

    #[test]
    fn regex_first_match_wins_by_registration() {
        // Two overlapping regexes; first registered must win.
        let e = engine(
            vec![(r"^/a", "/FIRST"), (r"^/a", "/SECOND")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        assert_eq!(e.apply("/abc"), "/FIRSTbc");
    }

    // ----- Priority across engines -----

    #[test]
    fn lower_priority_number_wins_across_engines() {
        // Exact has prio 0, prefix has prio 1 → exact wins even if both match.
        let e = engine(
            vec![("/api/users", "/exact"), ("/api/*", "/prefix")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        assert_eq!(e.apply("/api/users"), "/exact");
        assert_eq!(e.apply("/api/other"), "/prefixother");
    }

    #[test]
    fn prefix_beats_later_exact() {
        let e = engine(
            vec![("/api/*", "/P"), ("/api/users", "/E")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        // Prefix registered first → wins.
        assert_eq!(e.apply("/api/users"), "/Pusers");
    }

    // ----- Trailing slash policies -----

    #[test]
    fn trailing_slash_always() {
        let e = engine(vec![("/foo", "/bar")], None, None, TrailingSlashAction::Always);
        assert_eq!(e.apply("/foo"), "/bar/");
        assert_eq!(e.apply("/other"), "/other/");
        assert_eq!(e.apply("/already/"), "/already/");
    }

    #[test]
    fn trailing_slash_never() {
        let e = engine(vec![("/foo", "/bar/")], None, None, TrailingSlashAction::Never);
        assert_eq!(e.apply("/foo"), "/bar");
        assert_eq!(e.apply("/keep/"), "/keep");
        assert_eq!(e.apply("/"), "/"); // root preserved
    }

    #[test]
    fn trailing_slash_ignore() {
        let e = engine(vec![("/foo", "/bar/")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/foo"), "/bar/");
        assert_eq!(e.apply("/keep/"), "/keep/");
    }

    // ----- Zero-allocation / Cow behaviour -----

    #[test]
    fn no_match_returns_borrowed() {
        let e = engine(vec![], None, None, TrailingSlashAction::Ignore);
        let path = "/untouched";
        match e.apply(path) {
            Cow::Borrowed(s) => assert_eq!(s, path),
            Cow::Owned(_) => panic!("expected borrowed"),
        }
    }

    #[test]
    fn never_trailing_on_borrowed_stays_borrowed() {
        let e = engine(vec![], None, None, TrailingSlashAction::Never);
        let path = "/foo/";
        match e.apply(path) {
            Cow::Borrowed(s) => assert_eq!(s, "/foo"),
            Cow::Owned(_) => panic!("expected borrowed after strip"),
        }
    }

    // ----- Edge cases -----

    #[test]
    fn empty_path() {
        let e = engine(vec![("", "/root")], None, None, TrailingSlashAction::Ignore);
        // Empty path is returned early before any matching.
        assert_eq!(e.apply(""), "");
    }

    #[test]
    fn root_path() {
        let e = engine(vec![("/", "/home")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/"), "/home");
    }

    #[test]
    fn prefix_that_is_whole_path() {
        let e = engine(vec![("/api*", "/v2")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/api"), "/v2");
        assert_eq!(e.apply("/api/users"), "/v2/users");
    }

    #[test]
    fn suffix_that_is_whole_path() {
        let e = engine(vec![("*.html", "index")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply(".html"), "index");
    }

    #[test]
    fn multiple_prefix_candidates_longest_lowest_prio() {
        // Longer prefix registered later still loses to earlier shorter one
        // only if priorities dictate; here earlier wins regardless of length.
        let e = engine(
            vec![("/a*", "/FIRST"), ("/ab*", "/SECOND")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        assert_eq!(e.apply("/abc"), "/FIRSTbc");
    }

    #[test]
    fn unicode_path_bytes_safe() {
        // Engine works on bytes; valid UTF-8 paths with non-ASCII are fine.
        let e = engine(vec![("/café/*", "/coffee")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/café/latte"), "/coffeelatte");
    }

    #[test]
    fn apply_and_apply_hold_agree_on_simple_cases() {
        let e = engine(
            vec![("/exact", "/E"), ("/pre*", "/P"), ("*suf", "/S"), (r"^/re", "/R")],
            None,
            None,
            TrailingSlashAction::Ignore,
        );
        for path in ["/exact", "/prefix", "/endsuf", "/regex", "/none"] {
            assert_eq!(e.apply(path), e.apply_hold(path), "disagree on {}", path);
        }
    }

    #[test]
    fn min_prio_filter_skips_empty_trie() {
        // No prefix rules → min_prio stays MAX → filter never walks.
        let e = engine(vec![("/only-exact", "/x")], None, None, TrailingSlashAction::Ignore);
        assert_eq!(e.apply("/only-exact"), "/x");
        assert_eq!(e.apply("/other"), "/other");
    }

    #[test]
    fn cow_borrowed_when_unchanged_owned_when_rewritten() {
        let e = engine(vec![("/foo", "/bar")], None, None, TrailingSlashAction::Ignore);

        // No match → must stay Borrowed (zero allocation)
        let path = "/untouched";
        match e.apply(path) {
            Cow::Borrowed(s) => assert_eq!(s, path),
            Cow::Owned(_) => panic!("expected Cow::Borrowed when nothing changed"),
        }

        // Match → must be Owned
        match e.apply("/foo") {
            Cow::Owned(s) => assert_eq!(s, "/bar"),
            Cow::Borrowed(_) => panic!("expected Cow::Owned after a rewrite"),
        }

        // TrailingSlash::Never on an already-borrowed path that only loses the slash
        // still returns Borrowed (no allocation)
        let e_never = engine(vec![], None, None, TrailingSlashAction::Never);
        let path_slash = "/keep/";
        match e_never.apply(path_slash) {
            Cow::Borrowed(s) => assert_eq!(s, "/keep"),
            Cow::Owned(_) => panic!("expected Cow::Borrowed after trailing-slash strip"),
        }
    }
}
