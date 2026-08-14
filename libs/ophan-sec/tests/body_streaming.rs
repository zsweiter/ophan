//! Streaming body matcher tests: chunk-boundary handling (Aho-Corasick
//! overlap + steppable hybrid DFA), fail-fast, and end-of-body EOI.

use ophan_sec::l7::body::{BodyAction, StreamingBodyMatcher};
use ophan_sec::l7::expr::{Phase, RuleAction, RuleMeta};
use ophan_sec::l7::owasp::OwaspCategory;
use ophan_sec::l7::rules::CompiledBodyRule;

fn meta(id: &str) -> RuleMeta {
    RuleMeta {
        id: id.into(),
        score: 10,
        action: RuleAction::Block { status: 403 },
        category: OwaspCategory::A03Injection,
    }
}

fn rule(literals: &[&str], regexes: &[&str], id: &str) -> CompiledBodyRule {
    CompiledBodyRule {
        literals: literals.iter().map(|s| s.to_string()).collect(),
        regexes: regexes.iter().map(|s| s.to_string()).collect(),
        meta: Some(meta(id)),
        negated: false,
    }
}

fn phase_of(body: &str) -> Phase {
    let _ = body;
    Phase::InboundBody
}

#[test]
fn literal_match_in_single_chunk() {
    let rules = vec![rule(&["union select", "<script>"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"select * from users", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b" where 1=1 union select password", true), BodyAction::Block);
    assert_eq!(m.last_meta().unwrap().id.as_ref(), "r1");
}

#[test]
fn literal_match_across_chunk_boundary() {
    // Pattern spans a chunk boundary; the overlap window must catch it.
    let rules = vec![rule(&["union select"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"union sel", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b"ect from users", false), BodyAction::Block);
    assert_eq!(m.last_meta().unwrap().id.as_ref(), "r1");
}

#[test]
fn literal_match_across_many_small_chunks() {
    // Pattern "abcdef" fed one byte at a time.
    let rules = vec![rule(&["abcdef"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    for b in b"xxabcdefyy".iter() {
        let act = m.on_chunk(std::slice::from_ref(b), false);
        if act == BodyAction::Block {
            break;
        }
    }
    assert_eq!(
        m.on_chunk(b"", true),
        BodyAction::Block,
        "must match even when end_body arrives"
    );
}

#[test]
fn regex_match_across_chunk_boundary() {
    // A regex whose match spans chunks requires DFA state carried across
    // chunks. The hybrid DFA reports the match as soon as the pattern
    // completes (mid-chunk here), without waiting for EOI.
    let rules = vec![rule(&[], &[r"select\s+.*\s+from"], "r_re")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"select 1", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b" from dual", true), BodyAction::Block);
    assert_eq!(m.last_meta().unwrap().id.as_ref(), "r_re");
}

#[test]
fn regex_match_confirmed_at_eoi() {
    // Pattern that can only be resolved at EOI (e.g. anchored end `$`):
    // chunks stream in, match is confirmed only when end_body fires.
    let rules = vec![rule(&[], &[r"select$"], "r_re")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"select", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b"", true), BodyAction::Block);
    assert_eq!(m.last_meta().unwrap().id.as_ref(), "r_re");
}

#[test]
fn regex_match_within_one_chunk() {
    let rules = vec![rule(&[], &[r"union\s+select"], "r_re")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"SELECT union select from", true), BodyAction::Block);
}

#[test]
fn clean_body_returns_allow_at_end() {
    let rules = vec![rule(&["forbidden"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"innocent", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b"", true), BodyAction::Allow);
    // Terminal; further chunks are ignored.
    assert_eq!(m.on_chunk(b"forbidden", false), BodyAction::Allow);
}

#[test]
fn match_at_body_end_boundary() {
    // Pattern ends exactly at the end of the body.
    let rules = vec![rule(&["sakila"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"dvdrental", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b"!!sakila", true), BodyAction::Block);
}

#[test]
fn non_rewindable_body_skips_regex() {
    // Binary content type: regex scanning is skipped, literals still run.
    let rules = vec![rule(&["magic"], &[r"union\s+select"], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, false);
    assert_eq!(m.on_chunk(b"union select from t", true), BodyAction::Allow);
}

#[test]
fn reset_reuses_matcher() {
    let rules = vec![rule(&["evil"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"evil", true), BodyAction::Block);
    m.reset();
    assert_eq!(m.on_chunk(b"clean body", true), BodyAction::Allow);
}

#[test]
fn empty_matcher_always_allows() {
    let rules: Vec<CompiledBodyRule> = Vec::new();
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert!(m.is_empty());
    assert_eq!(m.on_chunk(b"anything", false), BodyAction::Continue);
    assert_eq!(m.on_chunk(b"", true), BodyAction::Allow);
}

#[test]
fn multi_rule_any_match_blocks() {
    let rules = vec![rule(&["harmless"], &[], "r1"), rule(&["select", "drop"], &[], "r2")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"drop table users", true), BodyAction::Block);
    assert_eq!(m.last_meta().unwrap().id.as_ref(), "r2");
}

#[test]
fn failfast_does_not_scan_rest() {
    let rules = vec![rule(&["forbidden"], &[], "r1")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    assert_eq!(m.on_chunk(b"this is forbidden", false), BodyAction::Block);
    // Subsequent chunks are ignored because the state is terminal.
    assert_eq!(m.on_chunk(b"more forbidden", false), BodyAction::Block);
}

#[test]
fn dfa_give_up_does_not_panic() {
    // Regex over a long non-matching body may blow the cache; the matcher
    // must degrade gracefully (skip regexes) instead of panicking.
    let rules = vec![rule(&[], &[r"(a+){100}b"], "r_re")];
    let mut m = StreamingBodyMatcher::from_rules(&rules, true);
    let mut outcome = BodyAction::Continue;
    let payload = vec![b'x'; 16 * 1024];
    for _ in 0..64 {
        outcome = m.on_chunk(&payload, false);
        if outcome == BodyAction::Block {
            break;
        }
    }
    let _ = phase_of("x");
    if outcome != BodyAction::Block {
        assert_eq!(m.on_chunk(b"", true), BodyAction::Allow);
    }
}
