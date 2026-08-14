//! Compiled per-phase rule structure — the engine's hot-path data layout.
//!
//! [`RuleCompiler::compile`] produces one [`CompiledWafRules`] holding, per
//! [`Phase`], a list of [`CompiledRule`]s (non-body matchers) and a list of
//! [`CompiledBodyRule`]s (streaming body matchers). The session walks each
//! phase in order, asking every rule "did this fire?" via
//! [`CompiledRule::evaluate_request`] / [`CompiledRule::evaluate_response`],
//! failing fast on the first rule that matches.
//!
//! ## Boolean semantics
//!
//! Each `CompiledRule` is one **logical rule** — a disjunction (OR) over the
//! predicates that produced it (`AnyOf`, or a merged `AllOf` — see
//! `compiler.rs` docs for the AllOf note). A rule "fires" when any of its
//! field matchers hit. A `Not(..)` wraps a rule and inverts it
//! ([`CompiledRule::negated`]).
//!
//! Because the engine is disjunctive at both levels (rule ORs its fields,
//! the session ORs the rule list), the phase's semantics are "any rule
//! firing triggers the phase" — the natural model for a WAF ruleset.
//!
//! ## Fail-fast design
//!
//! `evaluate_*` returns `Option<&RuleMeta>`: the first matching rule returns
//! immediately with its provenance (`id`, `score`, `action`, `category`).
//! Within a rule, field checks are ordered cheapest-first:
//!
//! 1. `ip` — radix trie lookup, `O(W)`
//! 2. `methods` — bitset AND, `O(1)`
//! 3. `path` (text matchers)
//! 4. `host` (text matchers, if provided)
//! 5. `query` (text matchers)
//! 6. `user_agent` (text matchers)
//! 7. `headers[name]` / `cookies[name]` — hash lookup + text matchers
//!
//! Regex / glob always come after literal AC because they are noticeably
//! more expensive (lazy-DFA construction cost on first hit).
//!
//! [`RuleCompiler::compile`]: crate::l7::compiler::RuleCompiler
//! [`Phase`]: crate::l7::expr::Phase

use std::net::IpAddr;

use ahash::AHashMap;
use flatkit::{net::IpSet, str::ImmerStr};
use http::HeaderName;
use ophan_net::http::{HttpMethodSet, StatusCodeSet, header};
use ophan_net::proxy::RequestParts;

use crate::l7::expr::{Field, RuleMeta};
use crate::l7::matchers::TextMatchers;

// =============================================================================
// IpCompiledRules
// =============================================================================

/// IP allow / deny rules for a phase.
///
/// `is_denied` follows the OWASP "allowlist wins" pattern: if the IP is in
/// `allow_list` we short-circuit to "not denied" before consulting
/// `deny_list`. This lets a broad `deny_list` (e.g. "10.0.0.0/8") be
/// punctured by an explicit `allow_list` (a specific monitoring host).
#[derive(Debug, Clone)]
pub struct IpCompiledRules {
    /// Explicit allowlist. Wins over `deny_list`. Empty when unused.
    pub allow_list: IpSet,
    /// Denylist. Evaluated only when `allow_list` does not contain the IP.
    pub deny_list: IpSet,
}

impl IpCompiledRules {
    /// Cheap empty check; the compiler elides the slot entirely when both
    /// lists are empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.allow_list.is_empty() && self.deny_list.is_empty()
    }

    /// Returns `true` iff `ip` is in `deny_list` and NOT in `allow_list`.
    #[inline]
    pub fn is_denied(&self, ip: IpAddr) -> bool {
        if !self.allow_list.is_empty() && self.allow_list.contains(ip) {
            return false;
        }
        self.deny_list.contains(ip)
    }
}

// =============================================================================
// CompiledWafRules — top-level container, one list per phase
// =============================================================================

/// All compiled rules. Conceptually immutable after config load; cheap to
/// share via `Arc<CompiledWafRules>` from the engine to per-request
/// sessions.
#[derive(Debug, Clone, Default)]
pub struct CompiledWafRules {
    /// WHO-IS.md phase 4 — request line + headers.
    pub request_headers: Vec<CompiledRule>,
    /// WHO-IS.md phase 5 — request body (streaming rules).
    pub request_body: Vec<CompiledBodyRule>,
    /// WHO-IS.md phase 6 — response headers + status.
    pub response_headers: Vec<CompiledRule>,
    /// WHO-IS.md phase 7 — response body (streaming rules).
    pub response_body: Vec<CompiledBodyRule>,
}

impl CompiledWafRules {
    /// True when no phase has any rule.
    pub fn is_empty(&self) -> bool {
        self.request_headers.is_empty()
            && self.request_body.is_empty()
            && self.response_headers.is_empty()
            && self.response_body.is_empty()
    }
}

// =============================================================================
// CompiledRule — one non-body rule for one phase
// =============================================================================

/// Compiled matchers for a single rule in a single (non-body) phase.
///
/// Each `Option<…>` slot is `None` when the rule does not touch that field
/// in this phase — `evaluate_*` skips it for free (no allocation, no
/// lookup). See `RULES.md` for the field × operator matrix that drives
/// which slots a given rule fills.
#[derive(Debug, Clone, Default)]
pub struct CompiledRule {
    pub ip: Option<IpCompiledRules>,
    pub methods: Option<HttpMethodSet>,
    pub host: Option<TextMatchers>,
    pub path: Option<TextMatchers>,
    pub query: Option<TextMatchers>,
    pub user_agent: Option<TextMatchers>,
    pub headers: Option<AHashMap<HeaderName, TextMatchers>>,
    pub cookies: Option<AHashMap<ImmerStr, TextMatchers>>,
    pub response_status: Option<StatusCodeSet>,
    pub response_headers: Option<AHashMap<HeaderName, TextMatchers>>,
    /// Provenance of the rule. Surfaced by `evaluate_*` on a match so the
    /// session can log / score against the correct rule id, OWASP category,
    /// score and action.
    pub meta: Option<RuleMeta>,
    /// When `true`, this rule's match decision is inverted: it fires only
    /// when none of its field matchers hit (`Not(..)` in the AST).
    pub negated: bool,
}

impl CompiledRule {
    /// Cheap empty-rule check; the session can skip the rule entirely when
    /// `true`.
    pub fn is_empty(&self) -> bool {
        self.ip.is_none()
            && self.methods.is_none()
            && self.host.is_none()
            && self.path.is_none()
            && self.query.is_none()
            && self.user_agent.is_none()
            && self.headers.is_none()
            && self.cookies.is_none()
            && self.response_status.is_none()
            && self.response_headers.is_none()
    }

    /// Evaluate this rule's request-phase matchers. Returns
    /// `Some(&RuleMeta)` when the rule fires, `None` otherwise.
    ///
    /// For a non-negated rule this is **fail-fast**: the first field that
    /// matches returns immediately. For a negated rule (`Not`) every field
    /// must be checked before concluding.
    ///
    /// The `host` parameter is the **externally-resolved** host (see
    /// [`crate::l7::expr::Field::Host`] docs for why it is not read from
    /// headers here). The proxy's session passes the resolved value down.
    #[inline]
    pub fn evaluate_request(&self, ip: Option<&IpAddr>, host: Option<&str>, req: &RequestParts) -> Option<&RuleMeta> {
        if self.negated {
            if self.matches_request(ip, host, req) {
                None
            } else {
                self.meta.as_ref()
            }
        } else if self.matches_request(ip, host, req) {
            self.meta.as_ref()
        } else {
            None
        }
    }

    /// Evaluate this rule's response-phase matchers. Returns
    /// `Some(&RuleMeta)` when the rule fires.
    #[inline]
    pub fn evaluate_response(&self, status_code: http::StatusCode, headers: &http::HeaderMap) -> Option<&RuleMeta> {
        if self.negated {
            if self.matches_response(status_code, headers) {
                None
            } else {
                self.meta.as_ref()
            }
        } else if self.matches_response(status_code, headers) {
            self.meta.as_ref()
        } else {
            None
        }
    }

    /// Evaluate request cookies supplied externally by the session adapter.
    /// Cookies require pre-splitting (one `(name, value)` pair per cookie)
    /// which is the proxy's responsibility; the WAF cannot iterate a raw
    /// `Cookie` header reliably. Returns `Some(&RuleMeta)` on first cookie
    /// match.
    #[inline]
    pub fn evaluate_request_cookies<'a>(&self, cookies: impl Iterator<Item = (ImmerStr, &'a str)>) -> Option<&RuleMeta> {
        let cookie_rules = self.cookies.as_ref()?;
        for (name, value) in cookies {
            if let Some(matchers) = cookie_rules.get(&name) {
                if matchers.is_match(value.as_bytes()) {
                    return if self.negated {
                        if self.meta.is_some() { None } else { self.meta.as_ref() }
                    } else {
                        self.meta.as_ref()
                    };
                }
            }
        }
        None
    }

    /// Checks every request field slot; `true` when at least one matches.
    #[inline]
    fn matches_request(&self, ip: Option<&IpAddr>, host: Option<&str>, req: &RequestParts) -> bool {
        // --- 1. IP (radix trie lookup; cheapest non-trivial check) ---
        if let (Some(ip_rules), Some(client_ip)) = (&self.ip, ip) {
            if ip_rules.is_denied(*client_ip) {
                return true;
            }
        }

        // --- 2. Method (bitset AND; O(1)) ---
        if let Some(methods) = &self.methods {
            if methods.contains_method(&req.method) {
                return true;
            }
        }

        // --- 3. Path (text matchers: eq → AC → prefix/suffix → regex → glob) ---
        if let Some(path_matchers) = &self.path {
            if path_matchers.is_match(req.uri.path().as_bytes()) {
                return true;
            }
        }
        // --- 4. Host (text matchers). Skipped when host is None (RFC 7230 §5.4). ---
        if let (Some(host_matchers), Some(h)) = (&self.host, host) {
            if host_matchers.is_match(h.as_bytes()) {
                return true;
            }
        }

        // --- 5. Query (text matchers; only when query string exists) ---
        if let (Some(query_matchers), Some(q)) = (&self.query, req.uri.path_and_query().and_then(|a| a.query())) {
            if query_matchers.is_match(q.as_bytes()) {
                return true;
            }
        }

        // --- 6. User-Agent (text matchers) ---
        if let (Some(ua_matchers), Some(ua)) = (&self.user_agent, req.headers.get(header::USER_AGENT)) {
            if ua_matchers.is_match(ua.as_bytes()) {
                return true;
            }
        }

        // --- 7. Headers[name] (per-header AHashMap lookup, then text match) ---
        if let Some(header_rules) = &self.headers {
            for (name, matchers) in header_rules {
                if let Some(val) = req.headers.get(name) {
                    if matchers.is_match(val.as_bytes()) {
                        return true;
                    }
                }
            }
        }

        // --- 8. Cookies[name] (same shape as headers). The session adapter
        //         drives per-cookie evaluation via `evaluate_request_cookies`.
        false
    }

    /// Checks every response field slot; `true` when at least one matches.
    #[inline]
    fn matches_response(&self, status_code: http::StatusCode, headers: &http::HeaderMap) -> bool {
        // --- 1. StatusCode (bitset; O(1)) ---
        if self.response_status.as_ref().is_some_and(|set| set.contains(status_code)) {
            return true;
        }

        // --- 2. Header[name] matchers ---
        if let Some(header_rules) = &self.response_headers {
            for (name, matchers) in header_rules {
                if headers.get(name).is_some_and(|h| matchers.is_match(h.as_bytes())) {
                    return true;
                }
            }
        }

        false
    }
}

// =============================================================================
// CompiledBodyRule — one streaming body rule
// =============================================================================

/// One rule's request/response body condition, kept in a form the streaming
/// [`StreamingBodyMatcher`] can consume without holding the whole body in
/// memory.
///
/// `literals` are `Body Contains` patterns (fed into a single combined
/// Aho-Corasick automaton across all rules); `regexes` are `Body Regex`
/// patterns (fed into a combined `regex_automata::hybrid` DFA).
#[derive(Debug, Clone, Default)]
pub struct CompiledBodyRule {
    /// `Body Contains` literal patterns.
    pub literals: Vec<String>,
    /// `Body Regex` patterns (raw, compiled into a streaming hybrid DFA).
    pub regexes: Vec<String>,
    /// Rule provenance.
    pub meta: Option<RuleMeta>,
    /// `true` when wrapped in `Not(..)`.
    pub negated: bool,
}

impl CompiledBodyRule {
    /// Cheap empty-rule check.
    pub fn is_empty(&self) -> bool {
        self.literals.is_empty() && self.regexes.is_empty()
    }
}

// =============================================================================
// Legacy façade — kept for the old `is_request_blocked`/`is_response_blocked`
// public API used by `ophan-sec/src/engine.rs`. Thin wrapper over the new
// `evaluate_*` over a single rule (the legacy callers pass a single rule,
// not a list).

impl CompiledRule {
    /// Boolean façade over [`Self::evaluate_request`]. Preserved for legacy
    /// callers; new code should call `evaluate_request` directly to obtain
    /// provenance.
    #[inline]
    pub fn is_request_blocked(&self, ip: Option<&IpAddr>, host: Option<&str>, req: &RequestParts) -> bool {
        self.evaluate_request(ip, host, req).is_some()
    }

    /// Boolean façade over [`Self::evaluate_response`].
    #[inline]
    pub fn is_response_blocked(&self, status_code: http::StatusCode, headers: &http::HeaderMap) -> bool {
        self.evaluate_response(status_code, headers).is_some()
    }
}

// =============================================================================
// MatchedField — identifies which instance of the predicate matched, for the
// diagnostic `field` of `WafMatch`.
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedField {
    Ip,
    Method,
    Host,
    Path,
    Query,
    Header,
    Cookie,
    UserAgent,
    Body,
    StatusCode,
    ResponseHeader,
}

impl From<Field> for MatchedField {
    fn from(field: Field) -> Self {
        match field {
            Field::Ip => Self::Ip,
            Field::Method => Self::Method,
            Field::Host => Self::Host,
            Field::Path => Self::Path,
            Field::Query => Self::Query,
            Field::Header(_) => Self::Header,
            Field::Cookie(_) => Self::Cookie,
            Field::UserAgent => Self::UserAgent,
            Field::Body => Self::Body,
            Field::StatusCode => Self::StatusCode,
        }
    }
}
