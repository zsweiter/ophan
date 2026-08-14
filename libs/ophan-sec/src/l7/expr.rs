//! WAF rule expression language — Abstract Syntax Tree (AST).
//!
//! This module defines the AST that the compiler (`crate::l7::compiler`) walks
//! to produce optimized, fail-fast lookup structures (`crate::l7::rules`).
//!
//! # Lifecycle
//!
//! ```text
//!  parser (external) → Expr (this file) → RuleCompiler::compile
//!     → CompiledWafRules (rules.rs) → WafSession::on_* (mod.rs)
//! ```
//!
//! The parser is intentionally out of scope: this AST is the stable contract
//! between any rule authoring format (YAML, DSL, programmatic) and the
//! runtime. Multiple source languages may emit `Expr` nodes.
//!
//! # Tree shape
//!
//! - [`Expr::AllOf`] — logical AND over children. Short-circuits on first
//!   non-match during evaluation (compiler emits ordered fail-fast checks).
//! - [`Expr::AnyOf`] — logical OR over children. Short-circuits on first
//!   match. Each child is compiled into its own `CompiledRule` group so the
//!   engine can iterate the list with early exit.
//! - [`Expr::Not`] — logical negation. The wrapped child still compiles to
//!   its `CompiledRule`; evaluation inverts the match decision.
//! - [`Expr::Predicate`] — leaf node carrying a [`Field`], [`Operator`],
//!   [`Value`] and the [`RuleMeta`] that identifies the originating rule for
//!   scoring, OWASP classification, and action selection.
//!
//! # Whose lifetime?
//!
//! `Expr` owns via [`flatkit::str::ImmerStr`] and [`Box<[..]>`]; cloning a
//! whole `Expr` is cheap (refcounted inline storage). It is `Send + Sync` and
//! `'static` once built, so a parsed ruleset can be shared across worker
//! threads via `Arc<Expr>` and recompiled at hot-reload time without blocking
//! the data path.

use flatkit::{net::IpNet, str::ImmerStr};
use http::HeaderName;

use crate::l7::owasp::OwaspCategory;

// =============================================================================
// RuleMeta — provenance attached to every Predicate (and every CompiledRule)
// =============================================================================

/// Identity, weight, and policy of a single rule.
///
/// `RuleMeta` travels from the AST (`Predicate`) to the compiled form
/// (`CompiledRule`) so the engine — when a matcher fires — knows:
/// - which rule to log/metric (`id`),
/// - how much to bump the anomaly score (`score`),
/// - which high-level action to take (`action`),
/// - which OWASP Top 10:2021 category to attribute the request to
///   (`category`) for reporting.
///
/// `RuleMeta` is `Copy`-ish in spirit: it is stored by value in the compiled
/// struct and returned by reference from `CompiledRule::evaluate_*` so the
/// hot path can keep a single `&RuleMeta` alive while translating to a
/// `WafResult::Block` / `Log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    /// Stable, rule-author-defined identifier. Surfaced to logs/metrics.
    /// Two distinct predicates sharing an `id` belong to the same rule.
    pub id: Box<str>,
    /// Score added to the session's anomaly counter when this rule matches.
    /// Reaching `WafConfig::anomaly_threshold` triggers the configured
    /// `mode` (detection-only logs, blocking rejects).
    pub score: u32,
    /// Action prescribed by the rule. `WafSession` reconciles this with
    /// `WafMode` (e.g. a `Block` rule under `DetectionOnly` becomes a `Log`).
    pub action: RuleAction,
    /// OWASP Top 10:2021 (or custom `C1xx`) category. Pure metadata today;
    /// future integration may drive per-category thresholds / exemptions.
    pub category: OwaspCategory,
}

impl RuleMeta {
    /// Convenience constructor — defaults to `RuleAction::Log` and a zero
    /// score, suited for trace-only rules. Production rules normally
    /// override `action` and `score`.
    pub fn new(id: impl Into<Box<str>>, category: OwaspCategory) -> Self {
        Self {
            id: id.into(),
            score: 0,
            action: RuleAction::Log,
            category,
        }
    }
}

// =============================================================================
// RuleAction — what the engine should do once a rule matches
// =============================================================================

/// Per-rule action decided by the rule author. The session translates it to a
/// concrete [`crate::l7::WafResult`] honoring the configured [`WafMode`].
///
/// [`WafMode`]: crate::l7::WafMode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    /// Allow the request through, regardless of further matches in the same
    /// phase. Useful for explicit allowlist overrides (e.g. an IP allow rule
    /// that nullifies a deny rule).
    Allow,
    /// Record the match in `WafResult::Log` and continue evaluating. Score
    /// is still accumulated for the anomaly threshold.
    Log,
    /// Reject the request (`WafResult::Block`). Carries the HTTP status the
    /// proxy should write to the downstream client.
    Block { status: u16 },
    /// Issue an interactive challenge (JS / captcha) instead of blocking.
    /// Reserved for bot-level rules; the proxy middleware decides how to
    /// render it.
    Challenge,
}

impl Default for RuleAction {
    fn default() -> Self {
        Self::Log
    }
}

// =============================================================================
// Expr — top-level AST node
// =============================================================================

/// Root AST node.
///
/// Built by an external parser (TOML/YAML/DSL — out of scope for `l7/`) and
/// handed to [`crate::l7::compiler::RuleCompiler::compile`]. See module docs
/// for the lifecycle.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Logical AND. All children must match. Short-circuits on first
    /// non-match during evaluation.
    AllOf(Box<[Expr]>),
    /// Logical OR. At least one child must match. Short-circuits on first
    /// match. Compiled as a `Vec<CompiledRule>` so the session iterates with
    /// early exit.
    AnyOf(Box<[Expr]>),
    /// Logical NOT. Inverts the wrapped expression's match decision. The
    /// wrapped expression's `RuleMeta` is still surfaced on a match (which,
    /// after inversion, means "the child did NOT match").
    Not(Box<Expr>),
    /// Leaf: a single field/operator/value triple plus its provenance.
    Predicate(Predicate),
}

// =============================================================================
// Predicate — one matcher
// =============================================================================

/// One atomic inspection: look at `field`, compare against `value` using
/// `op`, during `phase`.
///
/// `phase` is informational here; the compiler uses it to route the predicate
/// into the correct per-phase `CompiledRule`. Multiple predicates with
/// different phases inside the same `AllOf`/`AnyOf` will be partitioned
/// accordingly — phase mismatch between joined predicates is **not** an
/// error, but the engine will only be able to assert cross-phase AND/OR
/// within the natural order of the request lifecycle (headers before body
/// before response).
#[derive(Debug, Clone)]
pub struct Predicate {
    pub phase: Phase,
    pub field: Field,
    pub op: Operator,
    pub value: Value,
    pub meta: RuleMeta,
}

/// Lifecycle phase of an HTTP transaction. Order is significant: it mirrors
/// the proxy hook order (`request_filter` → `request_body_filter` →
/// `response_filter` → `upstream_response_body_filter`).
///
/// See `WHO-IS.md` phases 4 → 5 → 6 → 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// WHO-IS.md phase 4 — request line + headers. Inspected once per
    /// request in `WafSession::on_request_headers`.
    InboundHeaders,
    /// WHO-IS.md phase 5 — request body, streamed chunk-by-chunk in
    /// `WafSession::on_request_body_chunk`.
    InboundBody,
    /// WHO-IS.md phase 6 — response headers + status. Inspected once in
    /// `WafSession::on_response_headers`.
    OutboundHeaders,
    /// WHO-IS.md phase 7 — response body, streamed chunk-by-chunk in
    /// `WafSession::on_response_body_chunk`.
    OutboundBody,
}

impl Phase {
    /// All phases in lifecycle order (request → response).
    pub const ALL: [Phase; 4] = [
        Phase::InboundHeaders,
        Phase::InboundBody,
        Phase::OutboundHeaders,
        Phase::OutboundBody,
    ];
}

// =============================================================================
// Operator — the comparison verb
// =============================================================================

/// Operators recognised by the compiler. **Not every operator is valid for
/// every field** — see `RULES.md` for the supported field × operator matrix.
/// The compiler rejects unsupported combinations at compile time (config
/// load) rather than silently ignoring them in the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Operator {
    /// `==` — exact equality. Bytes-equal for strings, numeric for numbers.
    Eq,
    /// `!=` — negation of `Eq`. Currently eliminated in `RULES.md` for all
    /// fields; express as `Not(Eq(..))` instead.
    Ne,
    /// `<` — numeric ordering. Reserved for future numeric fields.
    Lt,
    /// `<=` — numeric ordering. Reserved for future numeric fields.
    Le,
    /// `>` — numeric ordering. Reserved for future numeric fields.
    Gt,
    /// `>=` — numeric ordering. Reserved for future numeric fields.
    Ge,
    /// `IN [...]` — membership in a list of values. Field-specific:
    /// `Method In ["GET","HEAD"]`, `Ip IN_CIDR [...]`, `StatusCode In [401,403]`.
    In,
    /// Substring containment. Backed by Aho-Corasick for multi-literal batch
    /// scan; the dominant operator for body inspection.
    Contains,
    /// Prefix match. `Path StartsWith "/api/"` — O(prefix_len) per call.
    StartsWith,
    /// Suffix match. `Path EndsWith ".env"` — O(suffix_len) per call.
    EndsWith,
    /// Regular expression match. Compiled lazily into a `RegexSet` /
    /// hybrid DFA at config load.
    Regex,
    /// Glob pattern match. Backed by `flatkit::matchers::PathMatcherSet`.
    Glob,
}

// =============================================================================
// Field — what part of the request/response we inspect
// =============================================================================

/// Inspectable target. Each variant maps to a concrete matcher structure in
/// `rules.rs`; see the field-by-field justification in `RULES.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Field {
    /// HTTP method. Matches via `HttpMethodSet` (bitset, O(1)).
    Method,
    /// `Host` (HTTP/1.1) or `:authority` (HTTP/2). **Passed in
    /// externally** by the proxy middleware rather than re-extracted from
    /// headers: behind a load balancer the host may live in
    /// `X-Forwarded-Host`, `Forwarded`, or `:authority` (RFC 9113 §8.3.6);
    /// HTTP/1.0 / `curl` without `Host` yields `None` (RFC 7230 §5.4 makes
    /// `Host` optional in 1.0). The proxy resolves the host once via
    /// `ophan_net::http::utils::client_host` and hands the resolved value
    /// to `WafSession::on_request_headers`.
    Host,
    /// Path component (no query string). `TextMatchers` (AC + prefix/suffix +
    /// RegexSet + optional GlobSet).
    Path,
    /// Query string (without leading `?`). `TextMatchers`.
    Query,
    /// Named header value (case-insensitive name, bytes-value). Backed by
    /// `AHashMap<HeaderName, TextMatchers>` — one `TextMatchers` per
    /// header name across all rules.
    Header(HeaderName),
    /// Named cookie value. Cookies are pre-split by the proxy's cookie
    /// jar; the WAF receives a single `name → value` mapping per cookie.
    Cookie(ImmerStr),
    /// Client IP. **Resolved externally** by the proxy middleware using the
    /// per-listener `NetPolicy` (handles `X-Forwarded-For`,
    /// `CF-Connecting-IP`, `True-Client-IP`). Backed by `IpSet` (radix
    /// trie, O(W) where W = address bit-width).
    Ip,
    /// `User-Agent` header (convenience alias for `Header(USER_AGENT)`).
    UserAgent,
    /// Raw body bytes. Matches via streaming `BodyMatcher` (Aho-Corasick +
    /// hybrid DFA + ring buffer) — never the full body in memory at once.
    Body,
    /// Response status code. `StatusCodeSet` (512-bit bitset, O(1)).
    StatusCode,
}

// =============================================================================
// Value — the right-hand side of a predicate
// =============================================================================

/// Right-hand side of a [`Predicate`]. Each variant pairs with a restricted
/// set of operators and fields (see `RULES.md`).
#[derive(Debug, Clone)]
pub enum Value {
    /// UTF-8 string. Used by `Eq`, `Contains`, `StartsWith`, `EndsWith` on
    /// text fields. Stored as `ImmerStr` for cheap cloning across the AST.
    String(ImmerStr),
    /// Compiled regex. Used by `Regex` operator on text fields. Compiled
    /// eagerly so the parser surfaces invalid patterns at rule load time.
    Regex(regex::Regex),
    /// Glob source string. Used by `Glob` operator on `Path`. Stored as the
    /// raw pattern text; compiled into `PathMatcherSet` at compile time.
    Glob(ImmerStr),
    /// IP network (CIDR). Used by `Ip` field's `Eq`/`In` operators.
    Ip(IpNet),
    /// Integer scalar. Used by `StatusCode Eq <n>` and future numeric fields.
    Integer(i64),
    /// Float scalar. Reserved (no field uses it today).
    Float(f64),
    /// Boolean scalar. Reserved.
    Bool(bool),
    /// Heterogeneous list. Used by `In` operator across fields:
    /// `Method In ["GET","HEAD"]`, `StatusCode In [401,403]`, `Ip In [cidr, cidr, ...]`.
    List(Box<[Value]>),
}
