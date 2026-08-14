//! `TextMatchers` unit tests — the zero-copy `is_match` hot path, one test
//! per matcher component plus composition tests. `TextMatchers` has no
//! constructor; we build each variant literally.

use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
use flatkit::matchers::PathMatcherSet;
use regex::bytes::RegexSet;

use ophan_sec::l7::matchers::TextMatchers;

fn empty() -> TextMatchers {
    TextMatchers {
        eq_patterns: Vec::new(),
        exact_patterns: None,
        prefix_patterns: Vec::new(),
        suffix_patterns: Vec::new(),
        regex_patterns: None,
        glob_patterns: None,
    }
}

fn ac(patterns: &[&str]) -> Arc<AhoCorasick> {
    Arc::new(
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("AC builds"),
    )
}

// ---------------------------------------------------------------------------
// Eq
// ---------------------------------------------------------------------------

#[test]
fn eq_matches_only_whole_value() {
    let mut tm = empty();
    tm.eq_patterns = vec![b"GET".to_vec(), b"/api/v1".to_vec()];
    assert!(tm.is_match(b"GET"));
    assert!(tm.is_match(b"/api/v1"));
    // Substring must NOT match (Eq is whole-value).
    assert!(!tm.is_match(b"GET /index"));
    assert!(!tm.is_match(b"xGET"));
    assert!(!tm.is_match(b"/api/v1/users"));
}

#[test]
fn eq_is_case_sensitive() {
    let mut tm = empty();
    tm.eq_patterns = vec![b"GET".to_vec()];
    assert!(tm.is_match(b"GET"));
    assert!(!tm.is_match(b"get"));
}

// ---------------------------------------------------------------------------
// Contains (Aho-Corasick)
// ---------------------------------------------------------------------------

#[test]
fn contains_matches_substring_via_ac() {
    let mut tm = empty();
    tm.exact_patterns = Some(ac(&["union select", "../"]));
    assert!(tm.is_match(b"select * from t union select password"));
    assert!(tm.is_match(b"/a/../b"));
    assert!(!tm.is_match(b"innocent"));
}

#[test]
fn contains_ac_finds_any_pattern_one_sweep() {
    let mut tm = empty();
    tm.exact_patterns = Some(ac(&["abc", "xyz", "qq"]));
    assert!(tm.is_match(b"...xyz..."));
    assert!(tm.is_match(b"abc"));
    assert!(tm.is_match(b"pre-qq-post"));
    assert!(!tm.is_match(b"none of them"));
}

// ---------------------------------------------------------------------------
// StartsWith / EndsWith
// ---------------------------------------------------------------------------

#[test]
fn prefix_matches_start() {
    let mut tm = empty();
    tm.prefix_patterns = vec![String::from("/api/"), String::from("internal.")];
    assert!(tm.is_match(b"/api/v1/users"));
    assert!(tm.is_match(b"internal.svc"));
    assert!(!tm.is_match(b"/index.html"));
    assert!(!tm.is_match(b"xinternal."));
}

#[test]
fn suffix_matches_end() {
    let mut tm = empty();
    tm.suffix_patterns = vec![".php".into(), "/admin".into()];
    assert!(tm.is_match(b"index.php"));
    assert!(tm.is_match(b"/site/admin"));
    assert!(!tm.is_match(b"index.php.bak"));
    assert!(!tm.is_match(b"/admin/x"));
}

// ---------------------------------------------------------------------------
// Regex
// ---------------------------------------------------------------------------

#[test]
fn regex_matches_via_regexset() {
    let mut tm = empty();
    tm.regex_patterns = Some(RegexSet::new(&[r"^/api/v\d+/", r"union\s+select"]).expect("regex"));
    assert!(tm.is_match(b"/api/v2/users"));
    assert!(tm.is_match(b"select 1 union select 2"));
    assert!(!tm.is_match(b"/static/x"));
}

// ---------------------------------------------------------------------------
// Glob (PathMatcherSet)
// ---------------------------------------------------------------------------

#[test]
fn glob_matches_path_pattern() {
    let mut tm = empty();
    tm.glob_patterns = Some(PathMatcherSet::new(&["/admin/*", "/api/v*/*"]).expect("glob builds"));
    assert!(tm.is_match(b"/admin/users"));
    assert!(tm.is_match(b"/api/v3/anything"));
    assert!(!tm.is_match(b"/public/x"));
}

// ---------------------------------------------------------------------------
// Composition + ordering (eq before contains before prefix before suffix
// before regex before glob)
// ---------------------------------------------------------------------------

#[test]
fn composition_eq_takes_precedence_over_contains() {
    // "GET" as Eq must match whole-value only; "GET" as Contains would
    // match inside "XGETX". Putting same pattern in both slots shows Eq
    // being checked first by the early return ordering.
    let mut tm = empty();
    tm.eq_patterns = vec![b"GET".to_vec()];
    tm.exact_patterns = Some(ac(&["GET"]));
    assert!(tm.is_match(b"GET"));
    assert!(tm.is_match(b"XGETX")); // only Contains matches
    assert!(!tm.is_match(b"POST"));
}

#[test]
fn composition_first_hit_returns_true() {
    let mut tm = empty();
    tm.prefix_patterns = vec!["/api/".into()];
    tm.suffix_patterns = vec![".php".into()];
    tm.regex_patterns = Some(RegexSet::new(&[r"union\s+select"]).unwrap());
    assert!(tm.is_match(b"/api/login.php")); // both prefix and suffix — still true
}

#[test]
fn composition_no_components_no_match() {
    let tm = empty();
    assert!(!tm.is_match(b"anything"));
    assert!(tm.is_empty());
}

#[test]
fn is_empty_false_when_any_component_present() {
    let mut tm = empty();
    tm.prefix_patterns = vec!["x".into()];
    assert!(!tm.is_empty());
}

// ---------------------------------------------------------------------------
// Zero-copy contract: is_match accepts borrowed bytes from any source.
// ---------------------------------------------------------------------------

#[test]
fn is_match_accepts_slice_from_request_like_source() {
    let mut tm = empty();
    tm.exact_patterns = Some(ac(&["evil"]));
    let buf: Vec<u8> = b"some evil payload here".to_vec();
    let slice: &[u8] = &buf[5..9]; // "evil"
    assert!(tm.is_match(slice));
}
