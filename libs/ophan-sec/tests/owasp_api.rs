//! OWASP API contract tests: `OwaspCategory::code()`/`description()` pinnings
//! and `default_rules()` structural invariants. These guard the public
//! surface that the engine and downstream consumers rely on.

use std::collections::HashSet;

use ophan_sec::l7::expr::{Phase, RuleAction};
use ophan_sec::l7::owasp::{OwaspCategory, default_rules};

#[test]
fn owasp_category_code_is_pinned_for_all_variants() {
    // The engine stores `OwaspCategory::code()` in `WafMatch.category`.
    // Pin all variants so a reorder or typo doesn't silently change log
    // identifiers.
    assert_eq!(OwaspCategory::A01BrokenAccessControl.code(), "A01:2021");
    assert_eq!(OwaspCategory::A02CryptographicFailures.code(), "A02:2021");
    assert_eq!(OwaspCategory::A03Injection.code(), "A03:2021");
    assert_eq!(OwaspCategory::A04InsecureDesign.code(), "A04:2021");
    assert_eq!(OwaspCategory::A05SecurityMisconfiguration.code(), "A05:2021");
    assert_eq!(
        OwaspCategory::A06VulnerableAndOutdatedComponents.code(),
        "A06:2021"
    );
    assert_eq!(
        OwaspCategory::A07IdentificationAndAuthenticationFailures.code(),
        "A07:2021"
    );
    assert_eq!(
        OwaspCategory::A08SoftwareAndDataIntegrityFailures.code(),
        "A08:2021"
    );
    assert_eq!(
        OwaspCategory::A09SecurityLoggingAndMonitoringFailures.code(),
        "A09:2021"
    );
    assert_eq!(
        OwaspCategory::A10ServerSideRequestForgery.code(),
        "A10:2021"
    );
    assert_eq!(OwaspCategory::CustomBotProtection.code(), "C100:BOT");
    assert_eq!(OwaspCategory::CustomIpReputation.code(), "C101:IP_REP");
    assert_eq!(OwaspCategory::CustomProtocolAnomaly.code(), "C102:PROTO");
    assert_eq!(OwaspCategory::CustomRateLimiting.code(), "C103:RATE");
}

#[test]
fn owasp_category_codes_are_unique() {
    let all = [
        OwaspCategory::A01BrokenAccessControl,
        OwaspCategory::A02CryptographicFailures,
        OwaspCategory::A03Injection,
        OwaspCategory::A04InsecureDesign,
        OwaspCategory::A05SecurityMisconfiguration,
        OwaspCategory::A06VulnerableAndOutdatedComponents,
        OwaspCategory::A07IdentificationAndAuthenticationFailures,
        OwaspCategory::A08SoftwareAndDataIntegrityFailures,
        OwaspCategory::A09SecurityLoggingAndMonitoringFailures,
        OwaspCategory::A10ServerSideRequestForgery,
        OwaspCategory::CustomBotProtection,
        OwaspCategory::CustomIpReputation,
        OwaspCategory::CustomProtocolAnomaly,
        OwaspCategory::CustomRateLimiting,
    ];
    let codes: HashSet<&str> = all.iter().map(|c| c.code()).collect();
    assert_eq!(codes.len(), all.len(), "OWASP codes must be unique");
}

#[test]
fn owasp_category_description_is_nonempty_for_all_variants() {
    let all = [
        OwaspCategory::A01BrokenAccessControl,
        OwaspCategory::A02CryptographicFailures,
        OwaspCategory::A03Injection,
        OwaspCategory::A04InsecureDesign,
        OwaspCategory::A05SecurityMisconfiguration,
        OwaspCategory::A06VulnerableAndOutdatedComponents,
        OwaspCategory::A07IdentificationAndAuthenticationFailures,
        OwaspCategory::A08SoftwareAndDataIntegrityFailures,
        OwaspCategory::A09SecurityLoggingAndMonitoringFailures,
        OwaspCategory::A10ServerSideRequestForgery,
        OwaspCategory::CustomBotProtection,
        OwaspCategory::CustomIpReputation,
        OwaspCategory::CustomProtocolAnomaly,
        OwaspCategory::CustomRateLimiting,
    ];
    for c in all {
        assert!(
            !c.description().is_empty(),
            "{:?} description must be non-empty",
            c
        );
    }
}

#[test]
fn default_rules_are_nonempty() {
    let rules = default_rules();
    assert!(!rules.is_empty(), "default_rules() must return at least one rule");
}

#[test]
fn default_rules_have_unique_ids() {
    let rules = default_rules();
    let ids: HashSet<&str> = rules.iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), rules.len(), "rule ids must be unique, got {:?}", rules.iter().map(|r| r.id).collect::<Vec<_>>());
}

#[test]
fn default_rules_known_set() {
    // The documented rule set (owasp.rs docs). Adding/removing a rule is a
    // breaking change — require an explicit update here.
    let rules = default_rules();
    let ids: HashSet<&str> = rules.iter().map(|r| r.id).collect();
    let expected: HashSet<&str> = [
        "owasp_sql_injection",
        "owasp_rce",
        "owasp_path_traversal",
        "owasp_xss",
        "owasp_xxe",
        "owasp_ssrf",
        "owasp_ldap_injection",
        "owasp_xpath_injection",
        "owasp_sql_token_match",
        "custom_sql_injection_query",
        "custom_path_traversal",
        "custom_scanner_user_agent",
    ]
    .into_iter()
    .collect();
    assert_eq!(ids, expected, "default rule set changed; update this test");
}

#[test]
fn default_rules_phase_matches_docs() {
    // The owasp.rs doc table maps each rule to a phase. Enforce it.
    let rules = default_rules();
    for r in &rules {
        match r.id {
            "owasp_sql_injection"
            | "owasp_rce"
            | "owasp_path_traversal"
            | "owasp_xss"
            | "owasp_xxe"
            | "owasp_ssrf"
            | "owasp_ldap_injection"
            | "owasp_xpath_injection"
            | "owasp_sql_token_match" => {
                assert_eq!(
                    r.phase,
                    Phase::InboundBody,
                    "{} should be InboundBody",
                    r.id
                );
            },
            "custom_sql_injection_query"
            | "custom_path_traversal"
            | "custom_scanner_user_agent" => {
                assert_eq!(
                    r.phase,
                    Phase::InboundHeaders,
                    "{} should be InboundHeaders",
                    r.id
                );
            },
            other => panic!("unknown rule id {other} — update phase table"),
        }
    }
}

#[test]
fn default_rules_action_is_block_or_log() {
    let rules = default_rules();
    for r in &rules {
        match r.action {
            RuleAction::Block { status } => assert_eq!(status, 403, "{} block status", r.id),
            RuleAction::Log => {},
            RuleAction::Allow | RuleAction::Challenge => {
                panic!("{} unexpected default action {:?}", r.id, r.action)
            },
        }
    }
}
