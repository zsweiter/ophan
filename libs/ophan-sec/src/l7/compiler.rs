//! RuleCompiler — walks the AST and emits optimized, fail-fast matcher sets.
//!
//! # Input
//!
//! A top-level [`Expr`] (built by an external parser — see `expr.rs`). The
//! root is interpreted as a **rule set**:
//!
//! - `Expr::AllOf(children)` → each child is an independent rule. Any of
//!   them firing triggers the phase (OR across rules). This is how a rule
//!   list from `owasp.rs::default_rules()` is composed.
//! - any other `Expr` → a single rule.
//!
//! # Boolean semantics within a rule
//!
//! A rule is a **disjunction** over its predicates:
//!
//! - `AnyOf(..)` / `AllOf(..)` children are flattened into the rule's
//!   predicate set. Because the compiled engine evaluates a rule as "any
//!   field matcher hits", both are effectively OR at runtime. **Note:** a
//!   strict AND of multiple predicates inside a single rule is not
//!   expressible in this engine — write distinct rules instead (the session
//!   ORs rules per phase). This matches WAF practice (a rule is "block if
//!   any of these signatures is present").
//! - `Not(inner)` → compiles `inner` as a rule with `negated = true`; the
//!   session inverts its match decision (rule fires when none of its
//!   matchers hit).
//! - `Predicate(p)` → one matcher added to the rule.
//!
//! # Operator matrix (RULES.md)
//!
//! `compile_predicate` validates every `(field, op)` pair against the
//! `RULES.md` field × matcher matrix **at compile time** and returns an
//! `Err(String)` for unsupported combinations instead of silently ignoring
//! them in the hot path. Unsupported value types for an operator are also
//! rejected.
//!
//! # Output
//!
//! [`CompiledWafRules`] with `Vec<CompiledRule>` per non-body phase and
//! `Vec<CompiledBodyRule>` per body phase. Predicates are routed to the
//! phase declared in their `Predicate.phase`.

use std::sync::Arc;

use ahash::AHashMap;
use aho_corasick::AhoCorasick;
use flatkit::matchers::PathMatcherSet;
use flatkit::net::IpSetBuilder;
use flatkit::str::ImmerStr;
use http::HeaderName;
use ophan_net::http::status_code::{StatusCodeSet, StatusPattern};
use ophan_net::http::{HttpMethod, HttpMethodSet};
use regex::bytes::RegexSet;

use crate::l7::expr::{Expr, Field, Operator, Phase, Predicate, RuleMeta, Value};
use crate::l7::matchers::TextMatchers;
use crate::l7::rules::{CompiledBodyRule, CompiledRule, CompiledWafRules, IpCompiledRules};

// =============================================================================
// TextMatcherBuilder (staging for a single field)
// =============================================================================

#[derive(Default)]
struct TextMatcherBuilder {
    eq_patterns: Vec<String>,
    exact_patterns: Vec<String>,
    prefix_patterns: Vec<String>,
    suffix_patterns: Vec<String>,
    regex_patterns: Vec<String>,
    glob_patterns: Vec<String>,
}

impl TextMatcherBuilder {
    fn is_empty(&self) -> bool {
        self.eq_patterns.is_empty()
            && self.exact_patterns.is_empty()
            && self.prefix_patterns.is_empty()
            && self.suffix_patterns.is_empty()
            && self.regex_patterns.is_empty()
            && self.glob_patterns.is_empty()
    }

    fn build(self) -> Option<TextMatchers> {
        if self.is_empty() {
            return None;
        }

        let exact_patterns = if !self.exact_patterns.is_empty() {
            AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build(&self.exact_patterns)
                .ok()
                .map(Arc::new)
        } else {
            None
        };

        let regex_patterns = if !self.regex_patterns.is_empty() {
            RegexSet::new(&self.regex_patterns).ok()
        } else {
            None
        };

        let glob_patterns = if !self.glob_patterns.is_empty() {
            PathMatcherSet::new(&self.glob_patterns).ok()
        } else {
            None
        };

        Some(TextMatchers {
            eq_patterns: self.eq_patterns.into_iter().map(String::into_bytes).collect(),
            exact_patterns,
            prefix_patterns: self.prefix_patterns,
            suffix_patterns: self.suffix_patterns,
            regex_patterns,
            glob_patterns,
        })
    }
}

// =============================================================================
// Accumulators — one per rule, per phase
// =============================================================================

/// Accumulates non-body matchers for a single rule in a single header phase.
#[derive(Default)]
struct FieldAccumulator {
    allow_ips: IpSetBuilder,
    deny_ips: IpSetBuilder,
    methods: HttpMethodSet,
    host: TextMatcherBuilder,
    path: TextMatcherBuilder,
    query: TextMatcherBuilder,
    user_agent: TextMatcherBuilder,
    headers: AHashMap<HeaderName, TextMatcherBuilder>,
    cookies: AHashMap<ImmerStr, TextMatcherBuilder>,
    response_status: StatusCodeSet,
    response_headers: AHashMap<HeaderName, TextMatcherBuilder>,
}

impl FieldAccumulator {
    fn is_empty(&self) -> bool {
        self.allow_ips.is_empty()
            && self.deny_ips.is_empty()
            && self.methods.is_empty()
            && self.host.is_empty()
            && self.path.is_empty()
            && self.query.is_empty()
            && self.user_agent.is_empty()
            && self.headers.is_empty()
            && self.cookies.is_empty()
            && self.response_status.is_empty()
            && self.response_headers.is_empty()
    }
}

/// Accumulates streaming body matchers for a single rule in a body phase.
#[derive(Default)]
struct BodyAccumulator {
    literals: Vec<String>,
    regexes: Vec<String>,
}

impl BodyAccumulator {
    fn is_empty(&self) -> bool {
        self.literals.is_empty() && self.regexes.is_empty()
    }
}

// =============================================================================
// RuleBuilder — one rule's worth of accumulators across all phases
// =============================================================================

#[derive(Default)]
struct RuleBuilder {
    negated: bool,
    meta: Option<RuleMeta>,
    inbound_headers: FieldAccumulator,
    outbound_headers: FieldAccumulator,
    inbound_body: BodyAccumulator,
    outbound_body: BodyAccumulator,
}

impl RuleBuilder {
    fn field_acc(&mut self, phase: Phase) -> &mut FieldAccumulator {
        match phase {
            Phase::InboundHeaders => &mut self.inbound_headers,
            Phase::OutboundHeaders => &mut self.outbound_headers,
            Phase::InboundBody => unreachable!("body phases use body_acc"),
            Phase::OutboundBody => unreachable!("body phases use body_acc"),
        }
    }

    fn body_acc(&mut self, phase: Phase) -> &mut BodyAccumulator {
        match phase {
            Phase::InboundBody => &mut self.inbound_body,
            Phase::OutboundBody => &mut self.outbound_body,
            Phase::InboundHeaders => unreachable!("header phases use field_acc"),
            Phase::OutboundHeaders => unreachable!("header phases use field_acc"),
        }
    }

    #[allow(unused)]
    fn is_empty(&self) -> bool {
        self.inbound_headers.is_empty()
            && self.outbound_headers.is_empty()
            && self.inbound_body.is_empty()
            && self.outbound_body.is_empty()
    }
}

// =============================================================================
// Compiler
// =============================================================================

/// Entry point for compiling an AST into hot-path matcher sets.
///
/// See the module docs for semantics. This is expected to be called once at
/// configuration load time, never in the request path.
pub struct RuleCompiler;

impl RuleCompiler {
    /// Compile the given rule set. Returns `Err(String)` describing the
    /// first unsupported `(field, operator)` pair or value type, or a
    /// `Not(..)` applied where it cannot be represented.
    pub fn compile(root: &Expr) -> Result<CompiledWafRules, String> {
        let rules: Vec<&Expr> = match root {
            Expr::AllOf(children) => children.iter().collect(),
            other => vec![other],
        };

        let mut compiled = CompiledWafRules::default();

        for rule_expr in rules {
            let mut builder = RuleBuilder::default();
            Self::compile_rule(rule_expr, &mut builder)?;
            Self::push_rule(builder, &mut compiled);
        }

        Ok(compiled)
    }

    /// Compile one top-level rule into the per-phase accumulators.
    fn compile_rule(expr: &Expr, builder: &mut RuleBuilder) -> Result<(), String> {
        match expr {
            Expr::Predicate(p) => Self::compile_predicate(p, builder),
            Expr::Not(inner) => {
                builder.negated = !builder.negated;
                Self::compile_rule(inner, builder)?;
                builder.negated = !builder.negated;
                Ok(())
            },
            Expr::AnyOf(children) | Expr::AllOf(children) => {
                for child in children.iter() {
                    Self::compile_rule(child, builder)?;
                }
                Ok(())
            },
        }
    }

    /// Compile a single predicate into the rule's accumulators. Validates
    /// the `(field, operator)` matrix and value type compatibility.
    fn compile_predicate(p: &Predicate, builder: &mut RuleBuilder) -> Result<(), String> {
        validate_field_phase(p)?;
        validate_matrix(p)?;

        builder.meta.get_or_insert_with(|| p.meta.clone());

        match &p.field {
            Field::Body => {
                let acc = builder.body_acc(p.phase);
                match (&p.op, &p.value) {
                    (Operator::Contains, Value::String(s)) => acc.literals.push(s.to_string()),
                    (Operator::Regex, Value::Regex(r)) => acc.regexes.push(r.as_str().to_string()),
                    _ => unreachable!("validated by validate_matrix"),
                }
            },
            Field::Ip => {
                let acc = builder.field_acc(p.phase);
                match (&p.op, &p.value) {
                    (Operator::Eq | Operator::In, Value::Ip(ip)) => acc.deny_ips.insert_network(ip),
                    _ => unreachable!("validated by validate_matrix"),
                }
            },
            Field::Method => {
                let acc = builder.field_acc(p.phase);
                match (&p.op, &p.value) {
                    (Operator::Eq, Value::String(s)) => {
                        acc.methods.add_standard(HttpMethod::from(s.as_str()));
                    },
                    (Operator::In, Value::List(values)) => {
                        for val in values.iter() {
                            if let Value::String(s) = val {
                                acc.methods.add_standard(HttpMethod::from(s.as_str()));
                            }
                        }
                    },
                    _ => unreachable!("validated by validate_matrix"),
                }
            },
            Field::StatusCode => {
                let acc = builder.field_acc(p.phase);
                match (&p.op, &p.value) {
                    (Operator::Eq, Value::Integer(n)) => {
                        if let Ok(code) = http::StatusCode::from_u16(*n as u16) {
                            acc.response_status.insert(code);
                        }
                    },
                    (Operator::In, Value::List(values)) => {
                        for val in values.iter() {
                            if let Value::Integer(n) = val {
                                if let Ok(code) = http::StatusCode::from_u16(*n as u16) {
                                    acc.response_status.insert(code);
                                }
                            }
                        }
                    },
                    (Operator::Contains, Value::String(s)) => match s.as_str() {
                        "1xx" => acc.response_status.insert(StatusPattern::Informational),
                        "2xx" => acc.response_status.insert(StatusPattern::Success),
                        "3xx" => acc.response_status.insert(StatusPattern::Redirection),
                        "4xx" => acc.response_status.insert(StatusPattern::ClientError),
                        "5xx" => acc.response_status.insert(StatusPattern::ServerError),
                        _ => {},
                    },
                    _ => unreachable!("validated by validate_matrix"),
                }
            },
            // --- Text fields: Host / Path / Query / UserAgent / Header / Cookie ---
            _ => {
                let acc = builder.field_acc(p.phase);
                let text = text_builder_for(acc, &p.field)
                    .ok_or_else(|| format!("unsupported field {:?} for phase {:?}", p.field, p.phase))?;
                match (&p.op, &p.value) {
                    (Operator::Eq, Value::String(s)) => text.eq_patterns.push(s.to_string()),
                    (Operator::Contains, Value::String(s)) => text.exact_patterns.push(s.to_string()),
                    (Operator::StartsWith, Value::String(s)) => text.prefix_patterns.push(s.to_string()),
                    (Operator::EndsWith, Value::String(s)) => text.suffix_patterns.push(s.to_string()),
                    (Operator::Regex, Value::Regex(r)) => text.regex_patterns.push(r.as_str().to_string()),
                    (Operator::Glob, Value::Glob(g)) => text.glob_patterns.push(g.as_str().to_string()),
                    _ => unreachable!("validated by validate_matrix"),
                }
            },
        }

        Ok(())
    }

    /// Finalize one rule's accumulators into `CompiledWafRules`, pushing
    /// per-phase entries.
    fn push_rule(builder: RuleBuilder, compiled: &mut CompiledWafRules) {
        let RuleBuilder {
            negated,
            meta,
            inbound_headers,
            outbound_headers,
            inbound_body,
            outbound_body,
        } = builder;

        // Body phases
        if !inbound_body.is_empty() {
            compiled.request_body.push(CompiledBodyRule {
                literals: inbound_body.literals,
                regexes: inbound_body.regexes,
                meta: meta.clone(),
                negated,
            });
        }
        if !outbound_body.is_empty() {
            compiled.response_body.push(CompiledBodyRule {
                literals: outbound_body.literals,
                regexes: outbound_body.regexes,
                meta: meta.clone(),
                negated,
            });
        }

        // Header phases
        if !inbound_headers.is_empty() {
            compiled.request_headers.push(finalize_field_rule(inbound_headers, negated, meta.clone()));
        }
        if !outbound_headers.is_empty() {
            compiled.response_headers.push(finalize_field_rule(outbound_headers, negated, meta));
        }
    }
}

/// Convenience: pull the `TextMatcherBuilder` for a text field out of a
/// `FieldAccumulator`.
fn text_builder_for<'a>(acc: &'a mut FieldAccumulator, field: &Field) -> Option<&'a mut TextMatcherBuilder> {
    match field {
        Field::Host => Some(&mut acc.host),
        Field::Path => Some(&mut acc.path),
        Field::Query => Some(&mut acc.query),
        Field::UserAgent => Some(&mut acc.user_agent),
        Field::Header(name) => Some(acc.headers.entry(name.clone()).or_default()),
        Field::Cookie(name) => Some(acc.cookies.entry(name.clone()).or_default()),
        _ => None,
    }
}

/// Finalize a header-phase accumulator into a `CompiledRule`.
fn finalize_field_rule(acc: FieldAccumulator, negated: bool, meta: Option<RuleMeta>) -> CompiledRule {
    let ip = if !acc.allow_ips.is_empty() || !acc.deny_ips.is_empty() {
        Some(IpCompiledRules {
            allow_list: acc.allow_ips.build(),
            deny_list: acc.deny_ips.build(),
        })
    } else {
        None
    };

    let methods = if acc.methods.is_empty() { None } else { Some(acc.methods) };

    let headers = if acc.headers.is_empty() {
        None
    } else {
        let compiled: AHashMap<_, _> = acc.headers.into_iter().filter_map(|(k, v)| v.build().map(|m| (k, m))).collect();
        if compiled.is_empty() { None } else { Some(compiled) }
    };

    let cookies = if acc.cookies.is_empty() {
        None
    } else {
        let compiled: AHashMap<_, _> = acc.cookies.into_iter().filter_map(|(k, v)| v.build().map(|m| (k, m))).collect();
        if compiled.is_empty() { None } else { Some(compiled) }
    };

    let response_headers = if acc.response_headers.is_empty() {
        None
    } else {
        let compiled: AHashMap<_, _> = acc.response_headers.into_iter().filter_map(|(k, v)| v.build().map(|m| (k, m))).collect();
        if compiled.is_empty() { None } else { Some(compiled) }
    };

    CompiledRule {
        ip,
        methods,
        host: acc.host.build(),
        path: acc.path.build(),
        query: acc.query.build(),
        user_agent: acc.user_agent.build(),
        headers,
        cookies,
        response_status: if acc.response_status.is_empty() {
            None
        } else {
            Some(acc.response_status)
        },
        response_headers,
        meta,
        negated,
    }
}

// =============================================================================
// Validation — RULES.md field × operator matrix and phase coherence
// =============================================================================

/// Reject predicates whose `field` cannot appear in the declared `phase`.
fn validate_field_phase(p: &Predicate) -> Result<(), String> {
    let ok = match (p.phase, &p.field) {
        (Phase::InboundHeaders, Field::Ip)
        | (Phase::InboundHeaders, Field::Method)
        | (Phase::InboundHeaders, Field::Host)
        | (Phase::InboundHeaders, Field::Path)
        | (Phase::InboundHeaders, Field::Query)
        | (Phase::InboundHeaders, Field::UserAgent)
        | (Phase::InboundHeaders, Field::Header(_))
        | (Phase::InboundHeaders, Field::Cookie(_)) => true,
        (Phase::InboundBody, Field::Body) => true,
        (Phase::OutboundHeaders, Field::StatusCode) | (Phase::OutboundHeaders, Field::Header(_)) => true,
        (Phase::OutboundBody, Field::Body) => true,
        _ => false,
    };

    if ok {
        Ok(())
    } else {
        Err(format!(
            "field {:?} is not valid for phase {:?} (see RULES.md phase mapping)",
            p.field, p.phase
        ))
    }
}

/// Reject unsupported `(field, operator)` pairs per the RULES.md matrix, and
/// validate the `Value` variant matches the operator.
fn validate_matrix(p: &Predicate) -> Result<(), String> {
    let ok = match (&p.field, &p.op) {
        (Field::Method, Operator::Eq | Operator::In) => true,
        (Field::Ip, Operator::Eq | Operator::In) => true,
        (Field::Host, Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith) => true,
        (
            Field::Path,
            Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith | Operator::Regex | Operator::Glob,
        ) => true,
        (Field::Query, Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith | Operator::Regex) => true,
        (Field::Header(_), Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith | Operator::Regex) => {
            true
        },
        (Field::Cookie(_), Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith | Operator::Regex) => {
            true
        },
        (Field::UserAgent, Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::Regex) => true,
        (Field::Body, Operator::Contains | Operator::Regex) => true,
        (Field::StatusCode, Operator::Eq | Operator::Contains | Operator::In) => true,
        _ => false,
    };

    if !ok {
        return Err(format!(
            "unsupported operator {:?} for field {:?} (see RULES.md field × matcher matrix)",
            p.op, p.field
        ));
    }

    // Value type compatibility per operator.
    let value_ok = match (&p.op, &p.value) {
        (Operator::Eq | Operator::Contains | Operator::StartsWith | Operator::EndsWith, Value::String(_)) => true,
        (Operator::In, Value::List(_)) => true,
        (Operator::Regex, Value::Regex(_)) => true,
        (Operator::Glob, Value::Glob(_)) => true,
        (Operator::Eq | Operator::In, Value::Ip(_)) => true,
        (Operator::Eq | Operator::In, Value::Integer(_)) => true,
        _ => false,
    };

    if !value_ok {
        return Err(format!(
            "value type {:?} is not valid for operator {:?} on field {:?}",
            p.value, p.op, p.field
        ));
    }

    Ok(())
}
