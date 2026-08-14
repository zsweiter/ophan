//! Layer-7 WAF engine — WHO-IS.md Phase 4–7.
//!
//! This module owns the **decision layer**: a compiled ruleset
//! ([`CompiledWafRules`]) plus a per-request state machine
//! ([`WafSession`]) that walks the proxy's lifecycle hooks and produces a
//! [`WafResult`].
//!
//! # Ownership & lifetime model
//!
//! - [`WafEngine`] is a **stateless, `'static` handle** around an
//!   [`Arc<WafConfig>`]. It is `Send + Sync` and lives inside a stateful
//!   middleware (e.g. a `tower`/`pingora` middleware struct). It holds
//!   **no per-request buffers and no borrows** — exactly because we cannot
//!   know how long the middleware outlives the config, and because we must
//!   never retain request data between requests.
//! - [`WafSession`] is the **per-request state machine**. The middleware
//!   creates one per HTTP transaction (from `WafEngine::session`), drives
//!   it through the hooks in lifecycle order, and drops it when the
//!   transaction ends. It borrows `&WafEngine` for the request's duration
//!   only. All transitory state — the streaming body matchers, the anomaly
//!   score, the accumulated matches — lives here, never in the engine.
//!
//! # Hooks (lifecycle order)
//!
//! | Hook                            | WHO-IS.md phase | Payload                                   |
//! | ------------------------------- | --------------- | ----------------------------------------- |
//! | `on_request_headers`            | 4               | `host: Option<&str>`, `&RequestParts`, `Option<IpAddr>` |
//! | `on_request_body_chunk`         | 5               | `&[u8]`, `end_body: bool`                 |
//! | `on_response_headers`           | 6               | `StatusCode`, `&HeaderMap`                |
//! | `on_response_body_chunk`        | 7               | `&[u8]`, `end_body: bool`                 |
//!
//! # The `host: Option<&str>` convention
//!
//! The engine never reads the `Host` header itself. The proxy middleware
//! resolves the real host **externally** (see `proxy.rs`:
//! `client_host(request, false)`), because behind a load balancer / CDN the
//! authoritative host may be conveyed via `:authority` (HTTP/2, RFC 9113
//! §8.3.6), `X-Forwarded-Host`, or `Forwarded` rather than the `Host`
//! header; and an HTTP/1.0 request or a bare `curl` may omit `Host`
//! entirely (RFC 7230 §5.4 makes it optional). Hence `Option<&str>`.
//!
//! # The `end_body: bool` convention
//!
//! Bodies are streamed; the session does **not** buffer them. The proxy
//! signals the last chunk with `end_body = true`. The matcher finalizes its
//! hybrid-DFA via the EOI transition on that call and returns a definitive
//! [`WafResult`].

use std::sync::Arc;
use std::{net::IpAddr, str::FromStr};

use flatkit::{matchers::PathMatcherSet, sizes::ByteSize, str::ImmerStr};
use ophan_net::proxy::RequestParts;

pub mod body;
pub mod compiler;
pub mod expr;
pub mod matchers;
pub mod owasp;
pub mod rules;

pub use body::{BodyAction, StreamingBodyMatcher, default_rewindable_mimes, is_rewindable, is_rewindable_bytes};
pub use expr::{Expr, Field, Operator, Phase, Predicate, RuleAction, RuleMeta, Value};
pub use rules::{CompiledBodyRule, CompiledRule, CompiledWafRules, IpCompiledRules, MatchedField};

// =============================================================================
// WafConfig
// =============================================================================
/// Runtime configuration of the L7 engine. Immutable after construction;
/// shared via `Arc` from the engine to per-request sessions.
#[derive(Debug, Clone)]
pub struct WafConfig {
    pub mode: WafMode,
    /// Compiled ruleset (see `compiler.rs`).
    pub compiled: Arc<CompiledWafRules>,
    /// Maximum body size (bytes) — defensive cap; streaming keeps the peak
    /// memory far below this.
    pub max_body_size: ByteSize,
    /// Anomaly score at which a request is considered blocked.
    pub anomaly_threshold: u32,
    /// Optional path matcher: requests matching are skipped entirely.
    pub skip_patterns: Option<PathMatcherSet>,
    /// Content types considered rewindable (text-analyzable). `None` → use
    /// `default_rewindable_mimes()`. User-defined lists are a future
    /// extension; today the default is internal.
    pub body_content_types: Option<Arc<[Box<[u8]>]>>,
}

impl WafConfig {
    /// Construct with an already-compiled ruleset.
    pub fn new(compiled: CompiledWafRules, mode: WafMode, anomaly_threshold: u32) -> Self {
        Self {
            mode,
            compiled: Arc::new(compiled),
            max_body_size: ByteSize::from_bytes(4 * 1024 * 1024),
            anomaly_threshold,
            skip_patterns: None,
            body_content_types: None,
        }
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self::new(CompiledWafRules::default(), WafMode::default(), 10)
    }
}

// =============================================================================
// WafMode
// =============================================================================

/// Whether the engine blocks or only reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WafMode {
    /// Inspection disabled — the engine returns `WafResult::Pass` always.
    Disabled,
    /// Match → `WafResult::Log` (never `Block`), even past the threshold.
    DetectionOnly,
    #[default]
    /// Match + threshold/action reached → `WafResult::Block`.
    Blocking,
}

impl WafMode {
    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl FromStr for WafMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "detection_only" => Ok(Self::DetectionOnly),
            "block" | "blocking" => Ok(Self::Blocking),
            _ => Err(()),
        }
    }
}

// =============================================================================
// WafAction / ChallengeKind / WafResult / WafMatch
// =============================================================================

/// Concrete action for a blocked request — decided by the engine (and
/// reconciled with the rule's `RuleAction`).
#[derive(Debug, Clone, PartialEq)]
pub enum WafAction {
    /// Allow the request.
    Allow,
    /// Record only (detection mode).
    Log,
    /// Terminate the request with the given HTTP status.
    Block { status: u16 },
    /// Issue an interactive challenge.
    Challenge(ChallengeKind),
    /// Redirect the client.
    Redirect { to: ImmerStr, status: u16 },
}

/// Kind of interactive challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Captcha,
    JsChallenge,
}

/// Outcome of a hook call.
///
/// `Pass` is the fast path and is returned without allocation. `Log` and
/// `Block` carry the match provenance for metrics/logging.
#[derive(Debug, Clone, PartialEq)]
pub enum WafResult {
    /// No rule fired; nothing to report.
    Pass,
    /// Rule(s) fired but no terminal action taken (detection mode, or score
    /// below threshold in blocking mode).
    Log { score_delta: u32, matched: Vec<WafMatch> },
    /// Terminal decision: reject / challenge / redirect.
    Block { score_delta: u32, matched: Vec<WafMatch>, action: WafAction },
}

impl WafResult {
    pub fn score_delta(&self) -> u32 {
        match self {
            Self::Pass => 0,
            Self::Log { score_delta, .. } => *score_delta,
            Self::Block { score_delta, .. } => *score_delta,
        }
    }
}

/// A single rule match, recorded for metrics/logging.
#[derive(Debug, Clone, PartialEq)]
pub struct WafMatch {
    pub phase: Phase,
    pub rule_id: String,
    pub field: Field,
    pub category: Option<String>,
}

// =============================================================================
// WafEngine — stateless `'static` handle
// =============================================================================

/// Compiled, immutable, `'static` handle to the L7 engine.
///
/// - **No lifetime.** It owns an [`Arc<WafConfig>`], so it can be stored in
///   any stateful middleware regardless of that middleware's lifetime.
/// - **No per-request state.** No buffers, no scores — those belong to
///   [`WafSession`], which the middleware creates per request.
/// - **`Send + Sync`.** Safe to share across worker threads.
#[derive(Clone)]
pub struct WafEngine {
    config: Arc<WafConfig>,
}

impl std::fmt::Debug for WafEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafEngine")
            .field("mode", &self.config.mode)
            .field("anomaly_threshold", &self.config.anomaly_threshold)
            .field("num_request_headers_rules", &self.config.compiled.request_headers.len())
            .field("num_request_body_rules", &self.config.compiled.request_body.len())
            .field("num_response_headers_rules", &self.config.compiled.response_headers.len())
            .field("num_response_body_rules", &self.config.compiled.response_body.len())
            .finish()
    }
}

impl WafEngine {
    pub fn new(config: WafConfig) -> Self {
        Self { config: Arc::new(config) }
    }

    pub fn config(&self) -> &Arc<WafConfig> {
        &self.config
    }

    /// Start a per-request session. Cheap: no allocation beyond the session
    /// itself (body matchers are lazily created on first body chunk).
    pub fn session(&self, client_ip: Option<IpAddr>) -> WafSession<'_> {
        WafSession {
            engine: self,
            state: SessionState::Initial,
            total_score: 0,
            client_ip,
        }
    }
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new(WafConfig::default())
    }
}

// =============================================================================
// WafSession — per-request state machine
// =============================================================================

/// Per-request WAF state machine.
///
/// The middleware creates one session per HTTP transaction and drives it
/// through the hooks in WHO-IS.md phase order. All transitory state lives
/// here; the session borrows the [`WafEngine`] for the request's duration
/// and is dropped when the transaction ends.
pub struct WafSession<'e> {
    engine: &'e WafEngine,
    state: SessionState,
    total_score: u32,
    client_ip: Option<IpAddr>,
}

impl std::fmt::Debug for WafSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafSession")
            .field("state", &self.state)
            .field("total_score", &self.total_score)
            .field("client_ip", &self.client_ip)
            .finish()
    }
}

/// Transitory session state.
#[derive(Debug)]
enum SessionState {
    /// Awaiting the first hook (`on_request_headers`).
    Initial,
    /// Request body inspection in progress.
    RequestBody(StreamingBodyMatcher),
    /// Response headers delivered; body inspection pending.
    ResponseHeaders,
    /// Response body inspection in progress.
    ResponseBody(StreamingBodyMatcher),
    /// Terminal — a block/allow decision was already emitted.
    Done,
}

impl<'e> WafSession<'e> {
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }

    pub fn score(&self) -> u32 {
        self.total_score
    }

    pub fn config(&self) -> &WafConfig {
        &self.engine.config
    }

    /// Reset to the initial state (e.g. connection reuse in HTTP/1.1 keep-alive).
    pub fn reset(&mut self) {
        self.state = SessionState::Initial;
        self.total_score = 0;
    }

    // ========================================================================
    // Phase 4 — Request headers
    // ========================================================================

    /// WHO-IS.md phase 4 — inspect request line + headers.
    ///
    /// - `host`: externally-resolved host (see module docs — never read from
    ///   headers here). `None` for HTTP/1.0 or host-less `curl` (RFC 7230
    ///   §5.4).
    /// - `req`: borrowed `RequestParts`; matched against field matchers
    ///   (IP → method → path → host → query → user-agent → headers) in
    ///   fail-fast order.
    /// - `client_ip`: already-resolved real client IP (from the proxy's
    ///   `NetPolicy`); passed rather than re-derived.
    ///
    /// Returns [`WafResult::Block`] immediately (fail-fast) when a blocking
    /// rule fires, so the proxy can reject before touching the body.
    pub fn on_request_headers(&mut self, host: Option<&str>, req: &RequestParts, client_ip: Option<IpAddr>) -> WafResult {
        if self.is_done() {
            return WafResult::Pass;
        }
        if let Some(ip) = client_ip {
            self.client_ip = Some(ip);
        }

        self.state = SessionState::ResponseHeaders;

        let rules = &self.engine.config.compiled.request_headers;
        for rule in rules {
            if let Some(meta) = rule.evaluate_request(self.client_ip.as_ref(), host, req) {
                return self.apply_match(Phase::InboundHeaders, meta, Field::Host);
            }
        }
        WafResult::Pass
    }

    // ========================================================================
    // Phase 5 — Request body (streaming)
    // ========================================================================

    /// WHO-IS.md phase 5 — inspect one request-body chunk.
    ///
    /// - `chunk`: borrowed bytes; **never copied** by the engine (only the
    ///   bounded overlap tail of `max_pattern_len - 1` bytes and the DFA
    ///   cache are retained).
    /// - `end_body`: `true` on the final chunk. The matcher finalizes its
    ///   hybrid DFA (EOI transition) on that call and returns a definitive
    ///   result.
    ///
    /// Returns [`WafResult::Block`] on the first match (fail-fast).
    pub fn on_request_body_chunk(&mut self, chunk: &[u8], end_body: bool) -> WafResult {
        match &mut self.state {
            SessionState::Done => return WafResult::Pass,
            SessionState::Initial | SessionState::ResponseHeaders => {
                self.state = SessionState::RequestBody(Self::new_body_matcher(&self.engine.config, true));
            },
            SessionState::RequestBody(_) => {},
            SessionState::ResponseBody(_) => return WafResult::Pass,
        }

        let matcher = match &mut self.state {
            SessionState::RequestBody(m) => m,
            _ => unreachable!(),
        };

        match matcher.on_chunk(chunk, end_body) {
            BodyAction::Block => {
                let meta = matcher.last_meta().cloned();
                if let Some(meta) = meta {
                    self.apply_match(Phase::InboundBody, &meta, Field::Body)
                } else {
                    WafResult::Pass
                }
            },
            BodyAction::Continue => WafResult::Pass,
            BodyAction::Allow => {
                self.state = SessionState::ResponseHeaders;
                WafResult::Pass
            },
        }
    }

    // ========================================================================
    // Phase 6 — Response headers
    // ========================================================================

    /// WHO-IS.md phase 6 — inspect response status + headers.
    pub fn on_response_headers(&mut self, status_code: http::StatusCode, headers: &http::HeaderMap) -> WafResult {
        if self.is_done() {
            return WafResult::Pass;
        }
        self.state = SessionState::ResponseHeaders;

        let rules = &self.engine.config.compiled.response_headers;
        for rule in rules {
            if let Some(meta) = rule.evaluate_response(status_code, headers) {
                return self.apply_match(Phase::OutboundHeaders, meta, Field::StatusCode);
            }
        }
        WafResult::Pass
    }

    // ========================================================================
    // Phase 7 — Response body (streaming)
    // ========================================================================

    /// WHO-IS.md phase 7 — inspect one response-body chunk. Same streaming
    /// contract as [`Self::on_request_body_chunk`].
    pub fn on_response_body_chunk(&mut self, chunk: &[u8], end_body: bool) -> WafResult {
        match &mut self.state {
            SessionState::Done => return WafResult::Pass,
            SessionState::ResponseHeaders | SessionState::Initial => {
                self.state = SessionState::ResponseBody(Self::new_body_matcher(&self.engine.config, false));
            },
            SessionState::ResponseBody(_) => {},
            SessionState::RequestBody(_) => return WafResult::Pass,
        }

        let matcher = match &mut self.state {
            SessionState::ResponseBody(m) => m,
            _ => unreachable!(),
        };

        match matcher.on_chunk(chunk, end_body) {
            BodyAction::Block => {
                let meta = matcher.last_meta().cloned();
                if let Some(meta) = meta {
                    self.apply_match(Phase::OutboundBody, &meta, Field::Body)
                } else {
                    WafResult::Pass
                }
            },
            BodyAction::Continue => WafResult::Pass,
            BodyAction::Allow => {
                self.state = SessionState::ResponseHeaders;
                WafResult::Pass
            },
        }
    }

    // ========================================================================
    // Internals
    // ========================================================================

    fn is_done(&self) -> bool {
        matches!(self.state, SessionState::Done)
    }

    /// Apply a single rule match: reconcile the rule action with the engine
    /// mode and the anomaly threshold.
    fn apply_match(&mut self, phase: Phase, meta: &RuleMeta, field: Field) -> WafResult {
        let mode = self.engine.config.mode;

        // Explicit allowlist rule: pass regardless of other matches.
        if meta.action == RuleAction::Allow {
            return WafResult::Pass;
        }

        // Accumulate the anomaly score.
        self.total_score += meta.score;
        let score_delta = meta.score;

        let matched = vec![WafMatch {
            phase,
            rule_id: meta.id.to_string(),
            field,
            category: Some(meta.category.code().to_string()),
        }];

        match mode {
            WafMode::Disabled => WafResult::Pass,
            WafMode::DetectionOnly => WafResult::Log { score_delta, matched },
            WafMode::Blocking => match meta.action {
                // Rule-prescribed terminal actions are enforced immediately
                // (fail-fast), independent of the anomaly threshold.
                RuleAction::Block { status } => {
                    self.state = SessionState::Done;
                    WafResult::Block { score_delta, matched, action: WafAction::Block { status } }
                },
                RuleAction::Challenge => {
                    self.state = SessionState::Done;
                    WafResult::Block {
                        score_delta,
                        matched,
                        action: WafAction::Challenge(ChallengeKind::JsChallenge),
                    }
                },
                RuleAction::Log => {
                    // Score-accumulating rules block once the anomaly
                    // threshold is crossed.
                    let threshold_reached = self.total_score >= self.engine.config.anomaly_threshold;
                    if threshold_reached {
                        self.state = SessionState::Done;
                        WafResult::Block {
                            score_delta,
                            matched,
                            action: WafAction::Block { status: 403 },
                        }
                    } else {
                        WafResult::Log { score_delta, matched }
                    }
                },
                RuleAction::Allow => unreachable!("handled above"),
            },
        }
    }

    /// Lazily build the streaming body matcher for a phase.
    fn new_body_matcher(config: &WafConfig, request: bool) -> StreamingBodyMatcher {
        let rules: &[CompiledBodyRule] = if request {
            &config.compiled.request_body
        } else {
            &config.compiled.response_body
        };
        StreamingBodyMatcher::from_rules(rules, true)
    }
}
