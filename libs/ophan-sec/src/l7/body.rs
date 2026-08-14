//! Streaming body matcher — the WHO-IS.md Phase 5/7 engine.
//!
//! The body of an HTTP request/response is **streamed**: the proxy delivers
//! it chunk-by-chunk through `WafSession::on_request_body_chunk(chunk,
//! end_body)` / `on_response_body_chunk`. It is **never** held in memory as a
//! whole. Buffering an entire body (the old `BodyPhaseState::Buffering(Vec)`)
//! collapses the server under many concurrent large payloads; this module
//! instead keeps:
//!
//! - a **bounded overlap buffer** of `max_pattern_len - 1` bytes (typically
//!   tens of bytes) so an Aho-Corasick literal spanning two chunks is still
//!   caught, and
//! - a **steppable hybrid DFA** ([`regex_automata::hybrid::dfa::DFA`]) whose
//!   `LazyStateID` is carried across chunks, so regex rules resume exactly
//!   where the previous chunk left off.
//!
//! Memory is therefore **O(max_pattern_len + dfa_cache_capacity)** and
//! independent of body size.
//!
//! ## Content-type gating
//!
//! [`is_rewindable`] / [`default_rewindable_mimes`] describe which content
//! types are amenable to streaming text inspection. Today the list is
//! internal (hardcoded); in the future it will be caller-defined via
//! `WafConfig`. Non-rewindable types (binary) skip the regex DFA and rely on
//! literal Aho-Corasick only — regexes tuned for text would otherwise
//! false-positive on binary payloads.
//!
//! ## BodyAction
//!
//! - [`BodyAction::Continue`] — keep streaming; no match yet.
//! - [`BodyAction::Block`] — a rule matched; the session should reject /
//!   score immediately (fail-fast).
//! - [`BodyAction::Allow`] — `end_body == true` was delivered and nothing
//!   matched; the body is clean.
//!
//! [`WafSession`]: crate::l7::mod::WafSession

use std::io::Read;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use http::HeaderValue;
use regex_automata::Input;
use regex_automata::hybrid::LazyStateID;
use regex_automata::hybrid::dfa::{Cache as DfaCache, DFA};

use crate::l7::expr::RuleMeta;
use crate::l7::rules::CompiledBodyRule;

// =============================================================================
// Content-type rewindability (internal list; user-defined in the future)
// =============================================================================

/// Default set of content types that are amenable to streaming text
/// inspection. Kept as raw bytes for zero-copy comparison against a
/// `Content-Type` header value.
pub const DEFAULT_REWINDABLE_MIMES: &[&[u8]] = &[
    b"text/plain",
    b"text/html",
    b"text/xml",
    b"application/json",
    b"application/xml",
    b"application/ld+json",
    b"application/x-www-form-urlencoded",
];

/// The rewindable-content-type list used when the caller does not supply one.
///
/// This is the internal default; a future `WafConfig` field will let callers
/// override it. It is exposed so tests and callers can align with it.
pub fn default_rewindable_mimes() -> &'static [&'static [u8]] {
    DEFAULT_REWINDABLE_MIMES
}

/// Return `true` when the given `Content-Type` header value denotes a
/// rewindable (text-analyzable) body. The comparison strips any `;charset=..`
/// parameter and matches the base MIME type exactly.
#[inline]
pub fn is_rewindable(content_type: &HeaderValue) -> bool {
    let bytes = content_type.as_bytes();

    let mime = match bytes.iter().position(|&b| b == b';') {
        Some(pos) => &bytes[..pos],
        None => bytes,
    };

    let mime = mime.trim_ascii_end();

    default_rewindable_mimes().contains(&mime)
}

/// Bytes-based variant of [`is_rewindable`] — used when the caller has the
/// `Content-Type` as a borrowed byte slice rather than a `HeaderValue`.
#[inline]
pub fn is_rewindable_bytes(content_type: &[u8]) -> bool {
    let mime = match content_type.iter().position(|&b| b == b';') {
        Some(pos) => &content_type[..pos],
        None => content_type,
    };

    let mime = mime.trim_ascii_end();

    default_rewindable_mimes().contains(&mime)
}

// =============================================================================
// BodyAction
// =============================================================================

/// Outcome of one `on_chunk` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyAction {
    /// Keep streaming; no match yet.
    Continue,
    /// A rule matched — the session should act immediately (fail-fast).
    Block,
    /// `end_body` delivered, nothing matched — body is clean.
    Allow,
}

// =============================================================================
// Reader adapter — feeds the AC automaton `overlap ++ chunk` without copying
// the chunk (the only allocation is the bounded overlap tail).
// =============================================================================

struct ChunkReader<'a> {
    overlap: &'a [u8],
    chunk: &'a [u8],
    pos: usize,
}

impl<'a> Read for ChunkReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let total = self.overlap.len() + self.chunk.len();
        if self.pos >= total {
            return Ok(0);
        }

        let mut written = 0;
        if self.pos < self.overlap.len() {
            let src = &self.overlap[self.pos..];
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            self.pos += n;
            written += n;
            if written >= buf.len() {
                return Ok(written);
            }
        }
        if self.pos >= self.overlap.len() {
            let ci = self.pos - self.overlap.len();
            if ci < self.chunk.len() {
                let src = &self.chunk[ci..];
                let n = src.len().min(buf.len() - written);
                buf[written..written + n].copy_from_slice(&src[..n]);
                self.pos += n;
                written += n;
            }
        }

        Ok(written)
    }
}

// =============================================================================
// StreamingBodyMatcher
// =============================================================================

/// Per-body streaming matcher. Owned by `WafSession`; built once from the
/// compiled body rules and reused across chunks via `reset()`.
#[derive(Clone)]
pub struct StreamingBodyMatcher {
    /// Combined Aho-Corasick over every non-negated rule's literals.
    ac: Option<Arc<AhoCorasick>>,
    /// `ac`'s pattern index → originating rule meta.
    ac_meta: Arc<[Option<RuleMeta>]>,
    /// Maximum literal pattern length, used to size the overlap window.
    overlap_len: usize,
    /// Trailing bytes of the previous chunk (bounded, ≤ `overlap_len`).
    overlap: Vec<u8>,
    /// Combined steppable hybrid DFA over every non-negated rule's regexes.
    dfa: Option<DFA>,
    /// DFA cache — holds the lazily-built DFA states (bounded by config).
    dfa_cache: Option<DfaCache>,
    /// `dfa`'s pattern index → originating rule meta.
    dfa_meta: Arc<[Option<RuleMeta>]>,
    /// Current DFA state across chunks (`None` until the first chunk).
    dfa_state: Option<LazyStateID>,
    /// `false` once the DFA gave up (cache too small / quit byte) — regex
    /// rules are then skipped for the remainder of this body.
    regex_active: bool,
    /// Whether the body content type permits regex scanning.
    rewindable: bool,
    /// Terminal state: matched / ended clean.
    phase_state: BodyPhaseState,
    /// Provenance of the match that set [`BodyPhaseState::Matched`].
    last_meta: Option<RuleMeta>,
}

impl std::fmt::Debug for StreamingBodyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingBodyMatcher")
            .field("has_ac", &self.ac.is_some())
            .field("overlap_len", &self.overlap_len)
            .field("has_dfa", &self.dfa.is_some())
            .field("regex_active", &self.regex_active)
            .field("rewindable", &self.rewindable)
            .field("phase_state", &self.phase_state)
            .field("last_meta", &self.last_meta.as_ref().map(|m| m.id.as_ref()))
            .finish_non_exhaustive()
    }
}

/// Internal phase state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BodyPhaseState {
    /// No chunk delivered yet.
    #[default]
    Empty,
    /// Streaming in progress.
    Scanning,
    /// A rule matched; terminal.
    Matched,
    /// `end_body` delivered, nothing matched; terminal.
    Clean,
}

impl StreamingBodyMatcher {
    /// Build a streaming matcher from the compiled body rules of one phase.
    ///
    /// All literal patterns across all (non-negated) rules are merged into a
    /// single Aho-Corasick automaton; all regexes into a single hybrid DFA.
    /// Negated body rules are **rejected at compile time** (see
    /// `compiler.rs`) because "block when X is absent" cannot be decided
    /// mid-stream without buffering.
    pub fn from_rules(rules: &[CompiledBodyRule], rewindable: bool) -> Self {
        let mut literals: Vec<&str> = Vec::new();
        let mut ac_meta: Vec<Option<RuleMeta>> = Vec::new();
        let mut regexes: Vec<&str> = Vec::new();
        let mut dfa_meta: Vec<Option<RuleMeta>> = Vec::new();

        for rule in rules {
            // Skip empty / (defensively) negated rules.
            if rule.negated {
                continue;
            }
            for lit in &rule.literals {
                literals.push(lit);
                ac_meta.push(rule.meta.clone());
            }
            for re in &rule.regexes {
                regexes.push(re);
                dfa_meta.push(rule.meta.clone());
            }
        }

        let ac = if literals.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::Standard)
                .build(&literals)
                .ok()
                .map(Arc::new)
        };
        let overlap_len = ac.as_ref().map_or(0, |a| a.max_pattern_len().saturating_sub(1));

        let dfa = if regexes.is_empty() || !rewindable {
            None
        } else {
            DFA::builder()
                .configure(regex_automata::hybrid::dfa::Config::new().cache_capacity(256 * 1024))
                .build_many(&regexes)
                .ok()
        };
        let dfa_cache = dfa.as_ref().map(DFA::create_cache);
        let regex_active = dfa.is_some();

        Self {
            ac,
            ac_meta: ac_meta.into(),
            overlap_len,
            overlap: Vec::with_capacity(overlap_len),
            dfa,
            dfa_cache,
            dfa_meta: dfa_meta.into(),
            dfa_state: None,
            regex_active,
            rewindable,
            phase_state: BodyPhaseState::default(),
            last_meta: None,
        }
    }

    /// `true` when the matcher has nothing to do (no literals, no regexes).
    pub fn is_empty(&self) -> bool {
        self.ac.is_none() && self.dfa.is_none()
    }

    /// Provenance of the rule that matched (available after
    /// [`BodyAction::Block`]).
    pub fn last_meta(&self) -> Option<&RuleMeta> {
        self.last_meta.as_ref()
    }

    /// Feed one chunk. `end_body` must be `true` on the final call for this
    /// body. Returns [`BodyAction::Block`] on the first match (fail-fast);
    /// [`BodyAction::Allow`] only when `end_body` arrives with no match.
    ///
    /// **Zero-copy**: `chunk` is borrowed; the only allocation is the bounded
    /// overlap tail (≤ `max_pattern_len - 1` bytes) and the DFA cache.
    #[inline]
    pub fn on_chunk(&mut self, chunk: &[u8], end_body: bool) -> BodyAction {
        match self.phase_state {
            BodyPhaseState::Matched => return BodyAction::Block,
            BodyPhaseState::Clean => return BodyAction::Allow,
            BodyPhaseState::Empty | BodyPhaseState::Scanning => {},
        }

        // --- 1. Aho-Corasick over overlap ++ chunk ---
        if let Some(ac) = &self.ac {
            let mut reader = ChunkReader { overlap: &self.overlap, chunk, pos: 0 };
            let mut hit = None;
            for m in ac.stream_find_iter(&mut reader).flatten() {
                hit = Some(m.pattern().as_usize());
                break;
            }

            if let Some(pidx) = hit {
                if let Some(meta) = self.ac_meta.get(pidx).and_then(|m| m.as_ref()) {
                    self.last_meta = Some(meta.clone());
                }
                self.phase_state = BodyPhaseState::Matched;
                return BodyAction::Block;
            }
        }

        // --- 2. Update bounded overlap window (tail of overlap ++ chunk) ---
        if self.overlap_len > 0 {
            let total = self.overlap.len() + chunk.len();
            let keep = total.min(self.overlap_len);
            if keep > 0 {
                let mut tail = Vec::with_capacity(keep);
                if chunk.len() >= keep {
                    tail.extend_from_slice(&chunk[chunk.len() - keep..]);
                } else {
                    let from = self.overlap.len() - (keep - chunk.len());
                    tail.extend_from_slice(&self.overlap[from..]);
                    tail.extend_from_slice(chunk);
                }
                self.overlap = tail;
            } else {
                self.overlap.clear();
            }
        }

        // --- 3. Steppable hybrid DFA over chunk ---
        if self.regex_active {
            if let (Some(dfa), Some(cache)) = (&self.dfa, &mut self.dfa_cache) {
                let mut sid = match self.dfa_state {
                    Some(s) => s,
                    None => {
                        // First chunk: seed the unanchored start state.
                        let start = dfa.start_state_forward(cache, &Input::new(chunk));
                        match start {
                            Ok(s) => s,
                            Err(_) => {
                                self.regex_active = false;
                                return self.finish(end_body);
                            },
                        }
                    },
                };

                let mut gave_up = false;
                for &b in chunk {
                    match dfa.next_state(cache, sid, b) {
                        Ok(next) => {
                            sid = next;
                            if sid.is_match() {
                                let pidx = dfa.match_pattern(cache, sid, 0).as_usize();
                                if let Some(meta) = self.dfa_meta.get(pidx).and_then(|m| m.as_ref()) {
                                    self.last_meta = Some(meta.clone());
                                }
                                self.phase_state = BodyPhaseState::Matched;
                                return BodyAction::Block;
                            }
                            if sid.is_quit() {
                                gave_up = true;
                                break;
                            }
                        },
                        Err(_) => {
                            gave_up = true;
                            break;
                        },
                    }
                }
                if gave_up {
                    self.regex_active = false;
                } else {
                    self.dfa_state = Some(sid);
                }
            } else {
                self.regex_active = false;
            }
        }

        self.finish(end_body)
    }

    /// Handle end-of-body: finalize the DFA (matches are delayed by one byte
    /// and confirmed via the EOI transition) and set the terminal state.
    #[inline]
    fn finish(&mut self, end_body: bool) -> BodyAction {
        if !end_body {
            self.phase_state = BodyPhaseState::Scanning;
            return BodyAction::Continue;
        }

        // Confirm a pending regex match via the EOI transition.
        if self.regex_active {
            if let (Some(dfa), Some(cache)) = (&self.dfa, &mut self.dfa_cache) {
                if let Some(sid) = self.dfa_state {
                    if let Ok(sid) = dfa.next_eoi_state(cache, sid) {
                        if sid.is_match() {
                            let pidx = dfa.match_pattern(cache, sid, 0).as_usize();
                            if let Some(meta) = self.dfa_meta.get(pidx).and_then(|m| m.as_ref()) {
                                self.last_meta = Some(meta.clone());
                            }
                            self.phase_state = BodyPhaseState::Matched;
                            return BodyAction::Block;
                        }
                    }
                }
            }
        }

        self.phase_state = BodyPhaseState::Clean;
        BodyAction::Allow
    }

    /// Reset to the initial state so the matcher can be reused for the next
    /// request/response body (the session calls this on `reset()`).
    pub fn reset(&mut self) {
        self.overlap.clear();
        self.dfa_state = None;
        self.regex_active = self.dfa.is_some();
        self.phase_state = BodyPhaseState::Empty;
        self.last_meta = None;
    }
}
