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
// BodyMatchInfo — automaton-slot provenance of a streaming match
// =============================================================================

/// Identifies which compiled automaton reported a [`BodyAction::Block`] and
/// the automaton-local index of the matching pattern. The session resolves
/// the originating [`RuleMeta`] through [`CompiledBodyPhase::meta_of`], so a
/// match never has to clone rule data into the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyMatchInfo {
    /// Index of the matched literal (Aho-Corasick) or regex (hybrid DFA)
    /// within its own combined automaton.
    pub pattern_index: usize,
    /// `true` when the match came from the DFA, `false` from AC literals.
    pub from_dfa: bool,
}

// =============================================================================
// CompiledBodyPhase — immutable, compiled once
// =============================================================================

/// Immutable compilation of a body-inspection phase: the combined
/// Aho-Corasick automaton over every non-negated rule's literals and the
/// combined steppable hybrid DFA over their regexes, plus the per-pattern
/// [`RuleMeta`] tables.
///
/// Built **once** at configuration load (see `RuleCompiler::compile`) and
/// stored in [`crate::l7::rules::CompiledWafRules`] behind an `Arc`. Every
/// request/response body spins up a cheap [`BodySession`] via
/// [`Self::session`] — the automata are shared, never rebuilt per request.
#[derive(Clone)]
pub struct CompiledBodyPhase {
    /// Combined Aho-Corasick over every non-negated rule's literals.
    ac: Option<Arc<AhoCorasick>>,
    /// `ac`'s pattern index → originating rule meta.
    ac_meta: Arc<[Option<RuleMeta>]>,
    /// Maximum literal pattern length minus one — overlap window size.
    overlap_len: usize,
    /// Combined steppable hybrid DFA over every non-negated rule's regexes.
    dfa: Option<Arc<DFA>>,
    /// `dfa`'s pattern index → originating rule meta.
    dfa_meta: Arc<[Option<RuleMeta>]>,
}

impl std::fmt::Debug for CompiledBodyPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledBodyPhase")
            .field("has_ac", &self.ac.is_some())
            .field("ac_patterns", &self.ac_meta.len())
            .field("overlap_len", &self.overlap_len)
            .field("has_dfa", &self.dfa.is_some())
            .field("dfa_patterns", &self.dfa_meta.len())
            .finish()
    }
}

impl Default for CompiledBodyPhase {
    fn default() -> Self {
        Self::compile(&[])
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

impl CompiledBodyPhase {
    /// Compile the combined automata from a phase's compiled body rules.
    ///
    /// All literal patterns across all (non-negated) rules are merged into a
    /// single Aho-Corasick automaton; all regexes into a single hybrid DFA.
    /// Negated body rules are **rejected at compile time** (see
    /// `compiler.rs`) because "block when X is absent" cannot be decided
    /// mid-stream without buffering.
    ///
    /// This is the **one** place the automata are built; it must run at
    /// configuration load time, never in the request path.
    pub fn compile(rules: &[CompiledBodyRule]) -> Self {
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

        let dfa = if regexes.is_empty() {
            None
        } else {
            DFA::builder()
                .configure(regex_automata::hybrid::dfa::Config::new().cache_capacity(256 * 1024))
                .build_many(&regexes)
                .ok()
                .map(Arc::new)
        };

        Self {
            ac,
            ac_meta: ac_meta.into(),
            overlap_len,
            dfa,
            dfa_meta: dfa_meta.into(),
        }
    }

    /// `true` when the phase has nothing to do (no literals, no regexes).
    pub fn is_empty(&self) -> bool {
        self.ac.is_none() && self.dfa.is_none()
    }

    /// Spin up a per-body runtime state. **Cheap**: no automaton is rebuilt —
    /// the session allocates only its DFA cache (the `&mut`-only lazily
    /// expanded state machine memory) and the fixed overlap buffer.
    pub fn session(self: &Arc<Self>) -> BodySession {
        let dfa_cache = self.dfa.as_ref().map(|d| d.create_cache());
        BodySession {
            phase: Arc::clone(self),
            overlap: Vec::with_capacity(self.overlap_len),
            dfa_cache,
            dfa_state: None,
            rewindable: true,
            regex_gave_up: false,
            phase_state: BodyPhaseState::default(),
            last_hit: None,
        }
    }

    /// Resolve the originating [`RuleMeta`] for a match reported by
    /// [`BodySession::feed`] / [`BodySession::last_hit`].
    pub fn meta_of(&self, hit: Option<BodyMatchInfo>) -> Option<&RuleMeta> {
        let hit = hit?;
        let table = match hit.from_dfa {
            true => &self.dfa_meta,
            false => &self.ac_meta,
        };
        table.get(hit.pattern_index)?.as_ref()
    }
}

// =============================================================================
// BodySession — per-body runtime state (cheap, from a compiled phase)
// =============================================================================

/// Per-body runtime state driven by one shared [`CompiledBodyPhase`].
///
/// Holds the only mutable automaton attachment — the hybrid DFA cache (the
/// `regex_automata::hybrid::Cache` requires `&mut` and is therefore owned
/// per session; the DFA and Aho-Corasick automata themselves are shared
/// behind an `Arc`) — plus the bounded overlap buffer and the streaming
/// state machine. Reuse it across bodies with [`BodySession::reset`]: after
/// the first chunk of a body no further allocation happens (both the cache
/// memory pool and the overlap buffer capacity are retained).
#[derive(Clone)]
pub struct BodySession {
    phase: Arc<CompiledBodyPhase>,
    /// Trailing bytes of the previous chunk (bounded, ≤ `overlap_len`),
    /// preallocated at phase compile time and reused in place.
    overlap: Vec<u8>,
    /// DFA cache — holds the lazily-built DFA states (bounded by config).
    dfa_cache: Option<DfaCache>,
    /// Current DFA state across chunks (`None` until the first chunk).
    dfa_state: Option<LazyStateID>,
    /// Whether the body content type permits regex scanning.
    rewindable: bool,
    /// Sticky: `true` once the DFA gave up mid-body (cache too small / quit
    /// byte) — regex rules are then skipped until the next `reset()`.
    regex_gave_up: bool,
    /// Terminal state: matched / ended clean.
    phase_state: BodyPhaseState,
    /// Automaton slot provenance of the match that set
    /// [`BodyPhaseState::Matched`].
    last_hit: Option<BodyMatchInfo>,
}

impl std::fmt::Debug for BodySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySession")
            .field("overlap_len", &self.phase.overlap_len)
            .field("regex_active", &self.regex_active())
            .field("rewindable", &self.rewindable)
            .field("phase_state", &self.phase_state)
            .field("last_hit", &self.last_hit)
            .finish_non_exhaustive()
    }
}

impl BodySession {
    /// Feed one chunk. `end` must be `true` on the final call for this body.
    /// Returns [`BodyAction::Block`] on the first match (fail-fast);
    /// [`BodyAction::Allow`] only when `end` arrives with no match.
    ///
    /// **Zero-copy**: `chunk` is borrowed; the overlap tail is updated in
    /// place (no allocation after the first chunk) and the DFA cache memory
    /// pool comes from the session.
    #[inline]
    pub fn feed(&mut self, chunk: &[u8], end: bool) -> BodyAction {
        match self.phase_state {
            BodyPhaseState::Matched => return BodyAction::Block,
            BodyPhaseState::Clean => return BodyAction::Allow,
            BodyPhaseState::Empty | BodyPhaseState::Scanning => {},
        }

        // --- 1. Aho-Corasick over overlap ++ chunk ---
        if let Some(ac) = &self.phase.ac {
            let mut reader = ChunkReader { overlap: &self.overlap, chunk, pos: 0 };
            let mut hit = None;
            for m in ac.stream_find_iter(&mut reader).flatten() {
                hit = Some(m.pattern().as_usize());
                break;
            }

            if let Some(pidx) = hit {
                self.last_hit = Some(BodyMatchInfo { pattern_index: pidx, from_dfa: false });
                self.phase_state = BodyPhaseState::Matched;
                return BodyAction::Block;
            }
        }

        // --- 2. Update bounded overlap window (tail of overlap ++ chunk) ---
        //
        // In-place update of the preallocated buffer: after the first chunk
        // this never allocates regardless of how the window saturates,
        // including chunks shorter than the window itself.
        if self.phase.overlap_len > 0 {
            let total = self.overlap.len() + chunk.len();
            let keep = total.min(self.phase.overlap_len);
            if keep == 0 {
                self.overlap.clear();
            } else if keep <= chunk.len() {
                // The kept window is fully inside the chunk: overwrite the
                // buffer content (capacity ≥ keep, no reallocation).
                let from = chunk.len() - keep;
                self.overlap.resize(keep, 0); // pad or shrink in place
                self.overlap.copy_from_slice(&chunk[from..]);
            } else {
                // chunk.len() < keep: the window is the retained tail of the
                // previous overlap followed by the whole chunk. Rotate that
                // tail to the front, then splice the chunk right behind it.
                let old_keep = keep - chunk.len(); // ≤ self.overlap.len()
                let len = self.overlap.len();
                self.overlap.copy_within(len - old_keep..len, 0);
                if self.overlap.len() < keep {
                    // Early chunks before the window saturates; the padding
                    // is overwritten by the splice below. Fits in capacity.
                    self.overlap.resize(keep, 0);
                }
                self.overlap[old_keep..keep].copy_from_slice(chunk);
                self.overlap.truncate(keep);
            }
        }

        // --- 3. Steppable hybrid DFA over chunk ---
        if self.regex_active() {
            if let (Some(dfa), Some(cache)) = (&self.phase.dfa, &mut self.dfa_cache) {
                let mut sid = match self.dfa_state {
                    Some(s) => s,
                    None => {
                        // First chunk: seed the unanchored start state.
                        let start = dfa.start_state_forward(cache, &Input::new(chunk));
                        match start {
                            Ok(s) => s,
                            Err(_) => {
                                self.regex_gave_up = true;
                                return self.finish(end);
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
                                self.last_hit = Some(BodyMatchInfo { pattern_index: pidx, from_dfa: true });
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
                    self.regex_gave_up = true;
                } else {
                    self.dfa_state = Some(sid);
                }
            } else {
                self.regex_gave_up = true;
            }
        }

        self.finish(end)
    }

    /// `true` when regex (DFA) scanning is disabled for this body.
    pub fn regex_active(&self) -> bool {
        self.rewindable && !self.regex_gave_up && self.phase.dfa.is_some()
    }

    /// Enable / disable regex (DFA) scanning for the next body. Call before
    /// the first chunk of a body (e.g. to skip regexes for binary content
    /// types); mid-body switches between chunks are undefined.
    pub fn set_rewindable(&mut self, rewindable: bool) {
        self.rewindable = rewindable;
    }

    /// Whether regex (DFA) scanning is enabled for this body.
    pub fn rewindable(&self) -> bool {
        self.rewindable
    }

    /// Automaton-slot provenance of the latest [`BodyAction::Block`] (or of
    /// the match remembered by the terminal state).
    pub fn last_hit(&self) -> Option<BodyMatchInfo> {
        self.last_hit
    }

    /// Gating switch set before the first chunk (used by the
    /// [`StreamingBodyMatcher`] constructors).
    fn rewound(mut session: Self, rewindable: bool) -> Self {
        session.rewindable = rewindable;
        session
    }

    /// Reset per-body state so the session can be reused for the next
    /// request/response body. The DFA cache and the overlap buffer's
    /// capacity are retained — resetting allocates nothing (only the DFA
    /// state seed is dropped; its lazily-built states stay warm in the
    /// cache for the next body).
    pub fn reset(&mut self) {
        self.overlap.clear(); // keeps capacity — zero alloc on the next body
        self.dfa_state = None;
        self.regex_gave_up = false;
        self.phase_state = BodyPhaseState::Empty;
        self.last_hit = None;
    }

    /// Handle end-of-body: finalize the DFA (matches are delayed by one byte
    /// and confirmed via the EOI transition) and set the terminal state.
    #[inline]
    fn finish(&mut self, end: bool) -> BodyAction {
        if !end {
            self.phase_state = BodyPhaseState::Scanning;
            return BodyAction::Continue;
        }

        // Confirm a pending regex match via the EOI transition.
        if self.regex_active() {
            if let (Some(dfa), Some(cache)) = (&self.phase.dfa, &mut self.dfa_cache) {
                if let Some(sid) = self.dfa_state {
                    if let Ok(sid) = dfa.next_eoi_state(cache, sid) {
                        if sid.is_match() {
                            let pidx = dfa.match_pattern(cache, sid, 0).as_usize();
                            self.last_hit = Some(BodyMatchInfo { pattern_index: pidx, from_dfa: true });
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
}

// =============================================================================
// StreamingBodyMatcher — public wrapper over CompiledBodyPhase + BodySession
// =============================================================================

/// Per-body streaming matcher — the historical public API. Wraps an
/// [`Arc`]-shared [`CompiledBodyPhase`] with a [`BodySession`] so callers
/// that compile per phase keep a single value with the original streaming
/// interface. [`Self::from_rules`] preserves the old compile-per-call shape;
/// code paths that compile once (configuration load) should prefer
/// [`CompiledBodyPhase::session`] directly.
#[derive(Clone)]
pub struct StreamingBodyMatcher {
    phase: Arc<CompiledBodyPhase>,
    session: BodySession,
}

impl std::fmt::Debug for StreamingBodyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingBodyMatcher")
            .field("has_ac", &self.phase.ac.is_some())
            .field("overlap_len", &self.phase.overlap_len)
            .field("has_dfa", &self.phase.dfa.is_some())
            .field("regex_active", &self.session.regex_active())
            .field("rewindable", &self.session.rewindable)
            .field("phase_state", &self.session.phase_state)
            .field("last_meta", &self.phase.meta_of(self.session.last_hit).map(|m| m.id.as_ref()))
            .finish_non_exhaustive()
    }
}

impl StreamingBodyMatcher {
    /// Build a streaming matcher from the compiled body rules of one phase,
    /// compiling the automata now (see [`CompiledBodyPhase::compile`]).
    ///
    /// `rewindable = false` keeps the automata but skips regex (DFA)
    /// scanning for this body — literal Aho-Corasick still runs.
    pub fn from_rules(rules: &[CompiledBodyRule], rewindable: bool) -> Self {
        let phase = Arc::new(CompiledBodyPhase::compile(rules));
        Self::from_phase(Arc::clone(&phase), rewindable)
    }

    /// Wrap an existing (shared) compiled phase with a fresh runtime state.
    pub fn from_phase(phase: Arc<CompiledBodyPhase>, rewindable: bool) -> Self {
        let session = phase.session();
        Self { phase, session: BodySession::rewound(session, rewindable) }
    }

    /// `true` when the matcher has nothing to do (no reachable automaton).
    pub fn is_empty(&self) -> bool {
        self.phase.ac.is_none() && (self.phase.dfa.is_none() || !self.session.rewindable)
    }

    /// Provenance of the rule that matched (available after
    /// [`BodyAction::Block`]).
    pub fn last_meta(&self) -> Option<&RuleMeta> {
        self.phase.meta_of(self.session.last_hit)
    }

    /// Feed one chunk. Same contract as [`BodySession::feed`] (chunk, end
    /// of body) — see there for the streaming details.
    #[inline]
    pub fn on_chunk(&mut self, chunk: &[u8], end_body: bool) -> BodyAction {
        self.session.feed(chunk, end_body)
    }

    /// Reset to the initial state so the matcher can be reused for the next
    /// request/response body; no allocation after the first body.
    pub fn reset(&mut self) {
        self.session.reset();
    }
}
