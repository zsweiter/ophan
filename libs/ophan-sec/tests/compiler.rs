//! Compiler behaviour tests: RULES.md operator matrix, phase coherence,
//! AnyOf/Not semantics, and metadata propagation.

use ophan_sec::l7::compiler::RuleCompiler;
use ophan_sec::l7::expr::{Expr, Field, Operator, Phase, Predicate, RuleAction, RuleMeta, Value};
use ophan_sec::l7::owasp::{OwaspCategory, default_rules};

fn meta(id: &str) -> RuleMeta {
    RuleMeta {
        id: id.into(),
        score: 10,
        action: RuleAction::Block { status: 403 },
        category: OwaspCategory::A03Injection,
    }
}

fn pred(phase: Phase, field: Field, op: Operator, value: Value) -> Expr {
    Expr::Predicate(Predicate { phase, field, op, value, meta: meta("test") })
}

/// A single predicate with the given meta id (for metadata assertions).
fn pred_meta(phase: Phase, field: Field, op: Operator, value: Value, id: &str) -> Expr {
    Expr::Predicate(Predicate { phase, field, op, value, meta: meta(id) })
}

fn s(v: &str) -> Value {
    Value::String(flatkit::str::ImmerStr::new(v))
}

#[test]
fn rejects_unsupported_operator_for_field() {
    // RULES.md: `Path Lt 5` is not valid (comparison operators are
    // eliminated from Path).
    let r = RuleCompiler::compile(&pred(Phase::InboundHeaders, Field::Path, Operator::Lt, Value::Integer(5)));
    assert!(r.is_err(), "Path Lt 5 must be rejected");
    let msg = r.unwrap_err();
    assert!(msg.contains("unsupported operator"), "got: {msg}");

    // RULES.md: `Ip Contains "1.2"` is not valid.
    let r = RuleCompiler::compile(&pred(Phase::InboundHeaders, Field::Ip, Operator::Contains, s("1.2")));
    assert!(r.is_err(), "Ip Contains must be rejected");

    // RULES.md: `Body Eq "x"` is not valid (Body only Contains/Regex).
    let r = RuleCompiler::compile(&pred(Phase::InboundBody, Field::Body, Operator::Eq, s("x")));
    assert!(r.is_err(), "Body Eq must be rejected");

    // RULES.md: `Method Contains` is not valid.
    let r = RuleCompiler::compile(&pred(Phase::InboundHeaders, Field::Method, Operator::Contains, s("POST")));
    assert!(r.is_err(), "Method Contains must be rejected");
}

#[test]
fn rejects_field_in_wrong_phase() {
    // `StatusCode` is only valid in OutboundHeaders.
    let r = RuleCompiler::compile(&pred(
        Phase::InboundHeaders,
        Field::StatusCode,
        Operator::Eq,
        Value::Integer(500),
    ));
    assert!(r.is_err(), "StatusCode in InboundHeaders must be rejected");

    // `Path` is only valid in InboundHeaders (not OutboundHeaders).
    let r = RuleCompiler::compile(&pred(Phase::OutboundHeaders, Field::Path, Operator::Contains, s("../")));
    assert!(r.is_err(), "Path in OutboundHeaders must be rejected");
}

#[test]
fn rejects_bad_value_type() {
    // Regex operator requires Value::Regex.
    let r = RuleCompiler::compile(&pred(Phase::InboundHeaders, Field::Path, Operator::Regex, s("^/api")));
    assert!(r.is_err(), "Regex operator with String value must be rejected");
}

#[test]
fn compiles_valid_matrix() {
    let rules = Expr::AllOf(
        vec![
            pred(Phase::InboundHeaders, Field::Method, Operator::Eq, s("POST")),
            pred(
                Phase::InboundHeaders,
                Field::Path,
                Operator::Glob,
                Value::Glob(flatkit::str::ImmerStr::new("/api/v*/*")),
            ),
            pred(Phase::InboundHeaders, Field::Query, Operator::Contains, s("union")),
            pred(Phase::InboundHeaders, Field::UserAgent, Operator::StartsWith, s("curl")),
            pred(Phase::InboundBody, Field::Body, Operator::Contains, s("union select")),
            pred(
                Phase::OutboundHeaders,
                Field::StatusCode,
                Operator::In,
                Value::List(vec![Value::Integer(500), Value::Integer(502)].into_boxed_slice()),
            ),
        ]
        .into_boxed_slice(),
    );
    let compiled = RuleCompiler::compile(&rules).expect("valid matrix must compile");
    assert!(!compiled.request_headers.is_empty());
    assert!(!compiled.request_body.is_empty());
    assert!(!compiled.response_headers.is_empty());
}

#[test]
fn owasp_default_rules_compile() {
    let specs = default_rules();
    let exprs: Vec<Expr> = specs.iter().map(|rs| rs.expr.clone()).collect();
    let compiled = RuleCompiler::compile(&Expr::AllOf(exprs.into_boxed_slice())).expect("OWASP default rules must compile");

    // All default rules are body or headers rules.
    assert!(!compiled.request_body.is_empty(), "OWASP body rules must be present");
    assert!(
        compiled
            .request_headers
            .iter()
            .any(|r| r.meta.as_ref().map_or(false, |m| m.id.as_ref() == "custom_sql_injection_query")),
        "query regex rule must be present"
    );
}

#[test]
fn anyof_merges_literals_into_one_rule() {
    // An `AnyOf` of Body Contains predicates for the same rule id collapses
    // into a single CompiledBodyRule with all literals.
    let rule = Expr::AnyOf(
        vec![
            pred(Phase::InboundBody, Field::Body, Operator::Contains, s("union select")),
            pred(Phase::InboundBody, Field::Body, Operator::Contains, s("<script>")),
        ]
        .into_boxed_slice(),
    );
    let compiled = RuleCompiler::compile(&rule).expect("AnyOf must compile");
    assert_eq!(compiled.request_body.len(), 1, "AnyOf merges into one body rule");
    assert_eq!(compiled.request_body[0].literals.len(), 2);
}

#[test]
#[ignore]
fn not_wraps_rule_negated() {
    // `Not(Ip In [10.0.0.0/8])` compiles to a negated rule.
    let ip_net: flatkit::net::IpNet = "10.0.0.0/8".parse().unwrap();
    let inner = pred(Phase::InboundHeaders, Field::Ip, Operator::In, Value::Ip(ip_net));
    let not = Expr::Not(Box::new(inner));
    let compiled = RuleCompiler::compile(&not).expect("Not must compile");
    assert_eq!(compiled.request_headers.len(), 1);
    assert!(compiled.request_headers[0].negated, "rule must be negated");
}

#[test]
fn rule_meta_propagates() {
    let rule = pred_meta(
        Phase::InboundHeaders,
        Field::Path,
        Operator::Contains,
        s("..%2f"),
        "owasp_path_traversal",
    );
    let compiled = RuleCompiler::compile(&rule).expect("single rule compiles");
    let m = compiled.request_headers[0].meta.as_ref().expect("meta present");
    assert_eq!(m.id.as_ref(), "owasp_path_traversal");
    assert_eq!(m.score, 10);
    assert_eq!(m.action, RuleAction::Block { status: 403 });
    assert_eq!(m.category, OwaspCategory::A03Injection);
}

// ===========================================================================
// TDD tests — these encode behaviour that is documented but not yet
// enforced by the compiler. They are EXPECTED TO FAIL until the corresponding
// fix lands in compiler.rs (see TODO comments). Once the fix lands they become
// regression guards.
// ===========================================================================

/// `Not(Body Contains "x")` is not representable: the streaming body matcher
/// cannot decide "absent" mid-stream without buffering the whole body. The
/// compiler MUST reject it at compile time instead of silently emitting a
/// negated CompiledBodyRule that never fires (current bug).
///
/// TODO(compiler.rs): `compile_predicate` should return `Err` when
/// `builder.negated && p.field == Field::Body`.
#[test]
#[ignore]
fn not_on_body_rule_is_rejected_at_compile_time() {
    let inner = pred(Phase::InboundBody, Field::Body, Operator::Contains, s("union select"));
    let not = Expr::Not(Box::new(inner));
    let r = RuleCompiler::compile(&not);
    assert!(r.is_err(), "Not(Body ..) must be rejected at compile time");
    let msg = r.unwrap_err();
    assert!(
        msg.contains("not") || msg.contains("negat") || msg.contains("body"),
        "error should mention Not/body, got: {msg}"
    );
}

/// Same contract for the outbound (response) body phase.
#[test]
#[ignore]
fn not_on_response_body_rule_is_rejected_at_compile_time() {
    let inner = pred(Phase::OutboundBody, Field::Body, Operator::Contains, s("<script>"));
    let not = Expr::Not(Box::new(inner));
    assert!(RuleCompiler::compile(&not).is_err(), "Not(OutboundBody ..) must be rejected");
}

/// `Not` wrapping a non-body field is fine — only `Not(body)` is forbidden.
#[test]
#[ignore]
fn not_on_header_rule_still_compiles() {
    let inner = pred(Phase::InboundHeaders, Field::Path, Operator::Contains, s("../"));
    let not = Expr::Not(Box::new(inner));
    let compiled = RuleCompiler::compile(&not).expect("Not(headers) must compile");
    assert_eq!(compiled.request_headers.len(), 1);
    assert!(compiled.request_headers[0].negated);
}

/// `Regex` operator must reject non-regex values (String, Integer, etc.).
/// Currently only `Value::String` is rejected; `Value::Integer` should also
/// be rejected.TODO(compiler.rs): validate_matrix should cover all non-Regex
/// values for the Regex operator.
#[test]
fn regex_operator_rejects_integer_value() {
    let r = RuleCompiler::compile(&pred(
        Phase::InboundHeaders,
        Field::Path,
        Operator::Regex,
        Value::Integer(404),
    ));
    assert!(r.is_err(), "Regex operator with Integer value must be rejected");
}

/// `Eq` on Ip requires `Value::Ip`; an Integer must be rejected.
#[test]
#[ignore]
fn ip_eq_rejects_integer_value() {
    let r = RuleCompiler::compile(&pred(Phase::InboundHeaders, Field::Ip, Operator::Eq, Value::Integer(32)));
    assert!(r.is_err(), "Ip Eq with Integer must be rejected");
}

/// `Glob` operator is only valid on `Path`. `Host Glob "..*"` must be rejected
/// (per RULES.md matrix).
/// TODO(compiler.rs): validate_matrix should restrict Glob to Path only.
#[test]
fn glob_operator_only_valid_on_path() {
    let r = RuleCompiler::compile(&pred(
        Phase::InboundHeaders,
        Field::Host,
        Operator::Glob,
        Value::Glob(flatkit::str::ImmerStr::new("*.example.com")),
    ));
    assert!(r.is_err(), "Glob on non-Path field must be rejected");
}

/// `OwaspCategory::code()` returns the official OWASP code string. The engine
/// uses this for `WafMatch.category`. Pin the values so they never drift.
#[test]
fn owasp_category_code_is_pinned() {
    assert_eq!(OwaspCategory::A01BrokenAccessControl.code(), "A01:2021");
    assert_eq!(OwaspCategory::A03Injection.code(), "A03:2021");
    assert_eq!(OwaspCategory::A10ServerSideRequestForgery.code(), "A10:2021");
    assert_eq!(OwaspCategory::CustomBotProtection.code(), "C100:BOT");
}
