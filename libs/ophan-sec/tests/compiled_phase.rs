//! CompiledBodyPhase / BodySession separation: compile-once automata with
//! cheap per-body sessions.
//!
//! - `from_rules` → `feed` vs `compile` → `session` → `feed` equivalence
//!   (match and no-match bodies, across chunk boundaries).
//! - Session independence: two `BodySession`s from one `CompiledBodyPhase`
//!   (incl. a DFA-cache give-up in one session) must not interfere.
//! - `reset()` reuse: same behaviour as a fresh session, no deviation.

use ophan_sec::l7::body::{BodyAction, BodyMatchInfo, CompiledBodyPhase, StreamingBodyMatcher};
use ophan_sec::l7::expr::{RuleAction, RuleMeta};
use ophan_sec::l7::owasp::OwaspCategory;
use ophan_sec::l7::rules::CompiledBodyRule;
use std::sync::Arc;

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

/// Feed a whole body through a streaming matcher, ending with `true` on the
/// last chunk; fails fast on the first non-`Continue`.
///
/// Returns the terminal action plus the matched rule id (resolved through
/// the shared compiled phase, mirroring how the engine resolves provenance).
fn run_wrapper(matcher: &mut StreamingBodyMatcher, chunks: &[&[u8]]) -> (BodyAction, Option<String>) {
    let mut action = BodyAction::Continue;
    let mut matched = None;
    for (i, chunk) in chunks.iter().enumerate() {
        action = matcher.on_chunk(chunk, i + 1 == chunks.len());
        if action != BodyAction::Continue {
            matched = matcher.last_meta().map(|m| m.id.as_ref().to_string());
            break;
        }
    }
    (action, matched)
}

/// Same shape as [`run_wrapper`] but over `CompiledBodyPhase` + `BodySession`.
fn run_phase(phase: &Arc<CompiledBodyPhase>, chunks: &[&[u8]], rewindable: bool) -> (BodyAction, Option<String>) {
    let mut session = phase.session();
    session.set_rewindable(rewindable);
    let mut action = BodyAction::Continue;
    let mut matched = None;
    for (i, chunk) in chunks.iter().enumerate() {
        action = session.feed(chunk, i + 1 == chunks.len());
        if action != BodyAction::Continue {
            matched = session.last_hit().and_then(|hit| phase.meta_of(Some(hit))).map(|m| m.id.as_ref().to_string());
            break;
        }
    }
    (action, matched)
}

// ---------------------------------------------------------------------------
// (a) from_rules → feed equivalence with the compiled-phase path
// ---------------------------------------------------------------------------

#[test]
fn session_matches_legacy_wrapper_semantics() {
    let rules = vec![rule(&["union select", "<script>"], &[r"union\s+\w+\s+from"], "r1")];
    let phase = Arc::new(CompiledBodyPhase::compile(&rules));

    // Bodies with matches and without; several span chunk boundaries and
    // exercise both the literal AC and the regex DFA automata.
    let cases: &[(&[&[u8]], bool)] = &[
        (&[b"innocent form data"], false),                   // no match
        (&[b"select 1; ", b"union", b" xxx select"], false), // no match (wrong order)
        (&[b"select 1 ", b"union select password"], true),   // AC literal mid-stream
        (&[b"union sel", b"ect from users"], true),          // literal split across chunks
        (&[b"xx", b"union select", b"from t"], true),        // literal inside second chunk
        (&[b"union", b" ", b"selec", b"t from a"], true),    // regex match, one-byte chunks
        (&[b"<script>alert(1)</script>"], true),             // second AC literal
        (&[b"union select from", b" everything"], true),     // literal first, DFA idle
    ];

    for (chunks, matches) in cases {
        let mut wrapper = StreamingBodyMatcher::from_rules(&rules, true);
        let (want, want_meta) = run_wrapper(&mut wrapper, chunks);

        let (got, got_meta) = run_phase(&phase, chunks, true);

        let expected_action = if *matches { BodyAction::Block } else { BodyAction::Allow };
        assert_eq!(want, expected_action, "legacy wrapper drifted for {chunks:?}");
        assert_eq!(got, want, "session must match wrapper for {chunks:?}");
        if *matches {
            assert_eq!(want_meta.as_deref(), Some("r1"));
            assert_eq!(got_meta, want_meta, "provenance must match wrapper");
        } else {
            assert!(want_meta.is_none() && got_meta.is_none());
        }
    }
}

#[test]
fn non_rewindable_session_skips_regex() {
    // Regex-only rule set with the regex gate off (binary content types):
    // literals must still run, regexes must be skipped.
    let rules = vec![rule(&["magic"], &[r"union\s+select"], "r1")];
    let phase = Arc::new(CompiledBodyPhase::compile(&rules));

    let (action, matched) = run_phase(&phase, &[b"union select from t"], false);
    assert_eq!(action, BodyAction::Allow, "regex must be skipped when not rewindable");
    assert!(matched.is_none());

    // …but with the gate on, the same body matches via the DFA.
    let (action, matched) = run_phase(&phase, &[b"union select from t"], true);
    assert_eq!(action, BodyAction::Block);
    assert_eq!(matched.as_deref(), Some("r1"));
}

#[test]
fn empty_phase_sessions_always_allow() {
    let rules: Vec<CompiledBodyRule> = Vec::new();
    let phase = Arc::new(CompiledBodyPhase::compile(&rules));
    assert!(phase.is_empty());
    let mut session = phase.session();
    assert_eq!(session.feed(b"anything", false), BodyAction::Continue);
    assert_eq!(session.feed(b"", true), BodyAction::Allow);
    assert_eq!(session.last_hit(), None);
}

// ---------------------------------------------------------------------------
// (b) two sessions from the same phase must not interfere
// ---------------------------------------------------------------------------

#[test]
fn sessions_are_independent() {
    let rules = vec![rule(&["evil"], &[r"union\s+select"], "r1")];
    let phase = Arc::new(CompiledBodyPhase::compile(&rules));

    // Session A: literal match (terminal Block state).
    let mut a = phase.session();
    assert_eq!(a.feed(b"some evil body", true), BodyAction::Block);
    let _committee_guard = a.last_hit();

    // Session B: clean, same shared automata — A's terminal state must not
    // leak into it.
    let mut b = phase.session();
    assert_eq!(b.feed(b"clean", true), BodyAction::Allow);
    assert_eq!(b.last_hit(), None);

    // Session C: a regex-heavy stream in one session must not disable or
    // poison the regex in a fresh session from the same compiled phase
    // (each session owns its DFA cache).
    let give_up_rules = vec![rule(&[], &[r"(a+){100}b", r"union\s+select"], "r_re")];
    let give_up_phase = Arc::new(CompiledBodyPhase::compile(&give_up_rules));
    let mut stress = give_up_phase.session();
    let payload = vec![b'a'; 16 * 1024];
    let outcome = stress.feed(&payload, true);
    assert_eq!(outcome, BodyAction::Allow, "the stress stream must never match");

    let mut c = give_up_phase.session();
    assert!(c.regex_active(), "fresh session must have its own, active DFA cache");
    assert_eq!(c.feed(b"union se", false), BodyAction::Continue);
    assert_eq!(
        c.feed(b"lect now", true),
        BodyAction::Block,
        "fresh session's regex must still work"
    );
    let hit: Option<BodyMatchInfo> = c.last_hit();
    assert_eq!(give_up_phase.meta_of(hit).map(|m| m.id.as_ref()), Some("r_re"));

    // Interference guard: A stays Block even after C finished.
    assert_eq!(a.feed(b"more", false), BodyAction::Block);
    assert_eq!(b.feed(b"more", true), BodyAction::Allow);
}

// ---------------------------------------------------------------------------
// (c) reset() reuse — no leak / no deviation
// ---------------------------------------------------------------------------

#[test]
fn reset_restores_fresh_semantics() {
    let rules = vec![rule(&["union select"], &[r"select\s+.*\s+from"], "r1")];
    let phase = Arc::new(CompiledBodyPhase::compile(&rules));
    let mut session = phase.session();

    // 1) Terminal Block → reset → identical outcome on the same body.
    assert_eq!(session.feed(b"do union select 1", true), BodyAction::Block);
    session.reset();
    assert_eq!(
        session.feed(b"do union select 1", true),
        BodyAction::Block,
        "same body after reset"
    );
    assert_eq!(phase.meta_of(session.last_hit()).map(|m| m.id.as_ref()), Some("r1"));

    // 2) Clean body → reset → chunk-boundary literal still caught (the
    //    overlap buffer was reset, not stale).
    session.reset();
    assert_eq!(session.feed(b"hello ", false), BodyAction::Continue);
    assert_eq!(session.feed(b"union sel", false), BodyAction::Continue);
    assert_eq!(session.feed(b"ect!", true), BodyAction::Block);
    session.reset();
    assert_eq!(session.feed(b"union sel", false), BodyAction::Continue);
    assert_eq!(session.feed(b"ect!", true), BodyAction::Block);
    assert_eq!(phase.meta_of(session.last_hit()).map(|m| m.id.as_ref()), Some("r1"));

    // 3) Chunks smaller than the overlap window, mixed with resets.
    session.reset();
    for b in b"xxunion sel".iter() {
        if session.feed(std::slice::from_ref(b), false) == BodyAction::Block {
            break;
        }
    }
    assert_eq!(session.feed(b"ect abc", true), BodyAction::Block);
    session.reset();
    assert_eq!(session.feed(b"xxunion sel", false), BodyAction::Continue);
    assert_eq!(session.feed(b"ect abc", true), BodyAction::Block);

    // 4) Reset clears the mid-stream automaton state: after a reset, the
    //    pinned DFA position and overlap of the previous body are gone, so
    //    the completion-only stream must be clean (a leaked state Would
    //    pretend "union select" completed across bodies).
    session.reset();
    let regex_phase = Arc::new(CompiledBodyPhase::compile(&[rule(&[], &[r"union\s+select"], "r_re")]));
    let mut s2 = regex_phase.session();
    assert_eq!(s2.feed(b"union sele", false), BodyAction::Continue);
    s2.reset();
    assert_eq!(s2.feed(b"ct now", true), BodyAction::Allow);
    // …while, without a reset in between, the same split body matches.
    let mut s3 = regex_phase.session();
    assert_eq!(s3.feed(b"union sele", false), BodyAction::Continue);
    assert_eq!(s3.feed(b"ct now", true), BodyAction::Block);

    // 5) Terminal state survives "unproductive" resets: reset must clear
    //    last_hit so provenance is never reused from the previous body.
    let mut s3 = phase.session();
    assert_eq!(s3.feed(b"union select leak", true), BodyAction::Block);
    assert!(s3.last_hit().is_some());
    s3.reset();
    assert_eq!(s3.last_hit(), None);
    assert_eq!(s3.feed(b"nothing here", true), BodyAction::Allow);
}
