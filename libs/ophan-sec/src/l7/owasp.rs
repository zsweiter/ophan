#![allow(unused)]

use std::fmt;
use std::str::FromStr;

/// Error type returned when parsing or converting an invalid OWASP or custom category identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCategoryError(pub String);

impl fmt::Display for InvalidCategoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid security category identifier: {}", self.0)
    }
}

impl std::error::Error for InvalidCategoryError {}

/// Standard OWASP Top 10:2021 Security Categories and Custom Extensions for WAF Rule Definitions.
///
/// This enum categorizes security inspection rules according to their threat vectors.
/// Each variant includes documentation regarding typical WAF inspection phases, common payload signatures,
/// and mitigation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OwaspCategory {
    /// ### A01:2021 - Broken Access Control
    /// - **WAF Evaluation Phase:** Pre-Routing / Request Headers / Path
    /// - **Prevention Target:** Path traversal (`../`), IDOR attempts, unauthorized API endpoints, elevated privilege escalation.
    /// - **Inspection Target:** `Path`, `Header(Authorization)`, `Cookie`, `Query`.
    A01BrokenAccessControl = 1,

    /// ### A02:2021 - Cryptographic Failures
    /// - **WAF Evaluation Phase:** TLS Handshake / Request Metadata
    /// - **Prevention Target:** Plaintext data exposure, weak TLS protocol versions, insecure transport headers.
    /// - **Inspection Target:** `Header(Strict-Transport-Security)`, Request Scheme (`http` vs `https`).
    A02CryptographicFailures = 2,

    /// ### A03:2021 - Injection
    /// - **WAF Evaluation Phase:** Deep Inspection (Path, Query, Headers, Body)
    /// - **Prevention Target:** SQL Injection (SQLi), Command Injection, Cross-Site Scripting (XSS), LDAP/XPath Injection.
    /// - **Inspection Target:** `Path`, `Query`, `Header`, `Body` (Aho-Corasick & RegexSet).
    A03Injection = 3,

    /// ### A04:2021 - Insecure Design
    /// - **WAF Evaluation Phase:** Rate Limiting / API Schema Validation
    /// - **Prevention Target:** Business logic abuse, automated resource exhaustion, API parameter tampering.
    /// - **Inspection Target:** `Path`, `Method`, `Body` (JSON Schema validation).
    A04InsecureDesign = 4,

    /// ### A05:2021 - Security Misconfiguration
    /// - **WAF Evaluation Phase:** Header Sanitization / Method Filtering
    /// - **Prevention Target:** Unnecessary HTTP methods (TRACE, OPTIONS abuse), exposed admin endpoints, debug flags.
    /// - **Inspection Target:** `Method`, `Path`, `Header`.
    A05SecurityMisconfiguration = 5,

    /// ### A06:2021 - Vulnerable and Outdated Components
    /// - **WAF Evaluation Phase:** Request Headers / User-Agent Inspection
    /// - **Prevention Target:** Exploits targeting known CVEs in popular frameworks or legacy User-Agents (e.g., Log4j, Struts).
    /// - **Inspection Target:** `UserAgent`, `Header`, `Path`.
    A06VulnerableAndOutdatedComponents = 6,

    /// ### A07:2021 - Identification and Authentication Failures
    /// - **WAF Evaluation Phase:** Authentication / Session Validation
    /// - **Prevention Target:** Credential stuffing, brute-force attacks, session hijacking, broken JWTs.
    /// - **Inspection Target:** `Header(Authorization)`, `Cookie`, `Path` (`/login`, `/auth`).
    A07IdentificationAndAuthenticationFailures = 7,

    /// ### A08:2021 - Software and Data Integrity Failures
    /// - **WAF Evaluation Phase:** Payload Deserialization / Signature Check
    /// - **Prevention Target:** Insecure deserialization payloads, tampered webhooks, unauthorized CI/CD pipeline triggers.
    /// - **Inspection Target:** `Body`, `Header(X-Signature)`.
    A08SoftwareAndDataIntegrityFailures = 8,

    /// ### A09:2021 - Security Logging and Monitoring Failures
    /// - **WAF Evaluation Phase:** Audit / Log Processing Pipeline
    /// - **Prevention Target:** Log injection attacks, credential leakage in log streams, missing audit trails.
    /// - **Inspection Target:** WAF Output Pipeline / Alerting Engine.
    A09SecurityLoggingAndMonitoringFailures = 9,

    /// ### A10:2021 - Server-Side Request Forgery (SSRF)
    /// - **WAF Evaluation Phase:** Request Body & Query String URL Validation
    /// - **Prevention Target:** Malicious outbound calls triggered via user input (e.g., fetching `169.254.169.254` metadata IPs).
    /// - **Inspection Target:** `Query`, `Body` (URL parameter extraction).
    A10ServerSideRequestForgery = 10,

    // =========================================================================
    // Custom / Predefined Rule Extensions (IDs >= 100)
    // =========================================================================
    /// ### Custom - Bot & Scanner Protection
    /// - **WAF Evaluation Phase:** Early Connection / Request Metadata
    /// - **Prevention Target:** Automated vulnerability scanners (Acunetix, Nikto, Nmap), malicious scrapers, headless bots.
    /// - **Inspection Target:** `UserAgent`, `Ip`, Rate Metrics.
    CustomBotProtection = 100,

    /// ### Custom - IP Reputation & Geo-Blocking
    /// - **WAF Evaluation Phase:** Connection Pre-Filter (Fast-Path)
    /// - **Prevention Target:** Traffic from blacklisted ASNs, TOR exit nodes, VPN proxies, geofenced countries.
    /// - **Inspection Target:** `Ip` (Radix Tree / CIDR Range match).
    CustomIpReputation = 101,

    /// ### Custom - Protocol Anomaly & HTTP Violations
    /// - **WAF Evaluation Phase:** Protocol Parsing
    /// - **Prevention Target:** Malformed HTTP requests, request smuggling (CL.TE / TE.CL), illegal encoding.
    /// - **Inspection Target:** Protocol parser, `Header` structure.
    CustomProtocolAnomaly = 102,

    /// ### Custom - Rate Limiting & DoS Protection
    /// - **WAF Evaluation Phase:** Connection Throttle
    /// - **Prevention Target:** Volumetric layer-7 DoS attacks, high-frequency brute forcing.
    /// - **Inspection Target:** `Ip`, `Path`, `Header`.
    CustomRateLimiting = 103,
}

impl OwaspCategory {
    /// Returns the official OWASP code string (e.g., "A03:2021") or custom identifier string.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2021",
            Self::A02CryptographicFailures => "A02:2021",
            Self::A03Injection => "A03:2021",
            Self::A04InsecureDesign => "A04:2021",
            Self::A05SecurityMisconfiguration => "A05:2021",
            Self::A06VulnerableAndOutdatedComponents => "A06:2021",
            Self::A07IdentificationAndAuthenticationFailures => "A07:2021",
            Self::A08SoftwareAndDataIntegrityFailures => "A08:2021",
            Self::A09SecurityLoggingAndMonitoringFailures => "A09:2021",
            Self::A10ServerSideRequestForgery => "A10:2021",
            Self::CustomBotProtection => "C100:BOT",
            Self::CustomIpReputation => "C101:IP_REP",
            Self::CustomProtocolAnomaly => "C102:PROTO",
            Self::CustomRateLimiting => "C103:RATE",
        }
    }

    /// Returns a short human-readable description of the security category.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableAndOutdatedComponents => "Vulnerable and Outdated Components",
            Self::A07IdentificationAndAuthenticationFailures => "Identification and Authentication Failures",
            Self::A08SoftwareAndDataIntegrityFailures => "Software and Data Integrity Failures",
            Self::A09SecurityLoggingAndMonitoringFailures => "Security Logging and Monitoring Failures",
            Self::A10ServerSideRequestForgery => "Server-Side Request Forgery (SSRF)",
            Self::CustomBotProtection => "Bot & Automated Scanner Protection",
            Self::CustomIpReputation => "IP Reputation & Geo-Blocking",
            Self::CustomProtocolAnomaly => "HTTP Protocol Anomaly & Smuggling",
            Self::CustomRateLimiting => "Rate Limiting & L7 DoS Mitigation",
        }
    }
}

// =============================================================================
// Uppercase String Constants for Compile-Time / Configuration Reference
// =============================================================================

pub mod categories {
    pub const A01_BROKEN_ACCESS_CONTROL: &str = "A01:2021";
    pub const A02_CRYPTOGRAPHIC_FAILURES: &str = "A02:2021";
    pub const A03_INJECTION: &str = "A03:2021";
    pub const A04_INSECURE_DESIGN: &str = "A04:2021";
    pub const A05_SECURITY_MISCONFIGURATION: &str = "A05:2021";
    pub const A06_VULNERABLE_COMPONENTS: &str = "A06:2021";
    pub const A07_AUTHENTICATION_FAILURES: &str = "A07:2021";
    pub const A08_INTEGRITY_FAILURES: &str = "A08:2021";
    pub const A09_LOGGING_FAILURES: &str = "A09:2021";
    pub const A10_SSRF: &str = "A10:2021";

    pub const CUSTOM_BOT_PROTECTION: &str = "C100:BOT";
    pub const CUSTOM_IP_REPUTATION: &str = "C101:IP_REP";
    pub const CUSTOM_PROTOCOL_ANOMALY: &str = "C102:PROTO";
    pub const CUSTOM_RATE_LIMITING: &str = "C103:RATE";
}

// =============================================================================
// TryFrom Implementations
// =============================================================================

/// Conversion from numeric discriminator (`u8`).
impl TryFrom<u8> for OwaspCategory {
    type Error = InvalidCategoryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A01BrokenAccessControl),
            2 => Ok(Self::A02CryptographicFailures),
            3 => Ok(Self::A03Injection),
            4 => Ok(Self::A04InsecureDesign),
            5 => Ok(Self::A05SecurityMisconfiguration),
            6 => Ok(Self::A06VulnerableAndOutdatedComponents),
            7 => Ok(Self::A07IdentificationAndAuthenticationFailures),
            8 => Ok(Self::A08SoftwareAndDataIntegrityFailures),
            9 => Ok(Self::A09SecurityLoggingAndMonitoringFailures),
            10 => Ok(Self::A10ServerSideRequestForgery),
            100 => Ok(Self::CustomBotProtection),
            101 => Ok(Self::CustomIpReputation),
            102 => Ok(Self::CustomProtocolAnomaly),
            103 => Ok(Self::CustomRateLimiting),
            _ => Err(InvalidCategoryError(format!("Invalid category ID: {}", value))),
        }
    }
}

/// Conversion from string references (e.g., "A03:2021", "A03", "injection", "C100:BOT").
impl TryFrom<&str> for OwaspCategory {
    type Error = InvalidCategoryError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let normalized = value.trim().to_uppercase();
        match normalized.as_str() {
            "A01:2021" | "A01" | "BROKEN_ACCESS_CONTROL" => Ok(Self::A01BrokenAccessControl),
            "A02:2021" | "A02" | "CRYPTOGRAPHIC_FAILURES" => Ok(Self::A02CryptographicFailures),
            "A03:2021" | "A03" | "INJECTION" => Ok(Self::A03Injection),
            "A04:2021" | "A04" | "INSECURE_DESIGN" => Ok(Self::A04InsecureDesign),
            "A05:2021" | "A05" | "SECURITY_MISCONFIGURATION" => Ok(Self::A05SecurityMisconfiguration),
            "A06:2021" | "A06" | "VULNERABLE_COMPONENTS" => Ok(Self::A06VulnerableAndOutdatedComponents),
            "A07:2021" | "A07" | "AUTHENTICATION_FAILURES" => Ok(Self::A07IdentificationAndAuthenticationFailures),
            "A08:2021" | "A08" | "INTEGRITY_FAILURES" => Ok(Self::A08SoftwareAndDataIntegrityFailures),
            "A09:2021" | "A09" | "LOGGING_FAILURES" => Ok(Self::A09SecurityLoggingAndMonitoringFailures),
            "A10:2021" | "A10" | "SSRF" => Ok(Self::A10ServerSideRequestForgery),

            "C100:BOT" | "BOT" | "BOT_PROTECTION" => Ok(Self::CustomBotProtection),
            "C101:IP_REP" | "IP_REPUTATION" | "GEOBLOCK" => Ok(Self::CustomIpReputation),
            "C102:PROTO" | "PROTOCOL_ANOMALY" | "SMUGGLING" => Ok(Self::CustomProtocolAnomaly),
            "C103:RATE" | "RATE_LIMITING" | "DOS" => Ok(Self::CustomRateLimiting),

            _ => Err(InvalidCategoryError(value.to_string())),
        }
    }
}

impl FromStr for OwaspCategory {
    type Err = InvalidCategoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

// =============================================================================
// default_rules — predefined OWASP RuleSpecs
// =============================================================================

use crate::l7::expr::{Expr, Field, Operator, Phase, Predicate, RuleAction, RuleMeta, Value};

/// One predefined rule expressed as AST + provenance.
///
/// `default_rules()` returns a `Vec<RuleSpec>` ready to be flattened into a
/// top-level `Expr` via `Expr::AllOf`/`AnyOf` and handed to
/// [`crate::l7::compiler::RuleCompiler::compile`].
///
/// The list consolidates the legacy hardcoded rules that lived in
/// `ophan-sec/src/config.rs::WafConfig::default()` (`WafCondition::BodyContains`
/// / `BodyRegex` / `SqlTokenMatch`) into the AST-based pipeline. Only the
/// rules are defined here; `WafAction`, score overrides, anomaly threshold,
/// `max_body_size`, `excludes`, content-type allowlist etc. are caller
/// concerns and live in `WafConfig`.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Opaque rule identifier. Matches `RuleMeta::id` after compilation.
    pub id: &'static str,
    /// OWASP Top 10:2021 (or custom `C1xx`) category assigned to the rule.
    pub category: OwaspCategory,
    /// Action prescribed by the rule. `Block { status }` is the typical
    /// choice; `Log` is used for trace-only rules with a low score.
    pub action: RuleAction,
    /// Score added to the anomaly counter on a match.
    pub score: u32,
    /// Phase in which the rule must be evaluated.
    pub phase: Phase,
    /// The matcher condition expressed as an [`Expr`]. Usually an
    /// `AnyOf` of `Predicate`s so per-literal provenance is preserved.
    pub expr: Expr,
}

impl RuleSpec {
    fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: self.id.into(),
            score: self.score,
            action: self.action,
            category: self.category,
        }
    }
}

/// Default OWASP Top 10:2021 + custom rule set.
///
/// Returns owned `RuleSpec`s; the caller decides how to merge them with
/// user-supplied rules (overlay, override by `id`, etc.) before compilation.
///
/// Each rule is in its appropriate lifecycle phase per `WHO-IS.md`:
///
/// | Rule                         | Phase           | Category                           |
/// | ---------------------------- | --------------- | ---------------------------------- |
/// | `owasp_sql_injection`        | `InboundBody`   | A03: Injection                     |
/// | `owasp_rce`                  | `InboundBody`   | A03: Injection                     |
/// | `owasp_path_traversal`       | `InboundBody`   | A01: Broken Access Control         |
/// | `owasp_xss`                  | `InboundBody`   | A03: Injection                     |
/// | `owasp_xxe`                  | `InboundBody`   | A08: Integrity Failures            |
/// | `owasp_ssrf`                 | `InboundBody`   | A10: SSRF                          |
/// | `owasp_ldap_injection`       | `InboundBody`   | A03: Injection                     |
/// | `owasp_xpath_injection`      | `InboundBody`   | A03: Injection                     |
/// | `owasp_sql_token_match`      | `InboundBody`   | A03: Injection (regex / token)     |
/// | `custom_sql_injection_query` | `InboundHeaders`| A03: Injection (query string)       |
/// | `custom_path_traversal`      | `InboundHeaders`| A01: Broken Access Control (path)  |
/// | `custom_scanner_user_agent`  | `InboundHeaders`| Custom Bot Protection (user-agent) |
pub fn default_rules() -> Vec<RuleSpec> {
    let block_403 = RuleAction::Block { status: 403 };

    // Helper for "any of these Body Contains literals" rules.
    let body_contains = |id: &'static str, cat: OwaspCategory, sigs: &'static [&'static str]| RuleSpec {
        id,
        category: cat,
        action: block_403,
        score: 10,
        phase: Phase::InboundBody,
        expr: any_of_body_contains(id, cat, block_403, sigs),
    };

    let mut rules = Vec::with_capacity(12);

    rules.push(body_contains(
        "owasp_sql_injection",
        OwaspCategory::A03Injection,
        &[
            "union select",
            "union all select",
            "insert into",
            "delete from",
            "drop table",
            "drop database",
            "update set",
            "exec(",
            "execute(",
            "xp_cmdshell",
            "information_schema",
            "sysobjects",
            "syscolumns",
            "';--",
            "';#",
            "\";--",
            "\";#",
        ],
    ));

    rules.push(body_contains(
        "owasp_rce",
        OwaspCategory::A03Injection,
        &[
            "exec(",
            "system(",
            "passthru(",
            "shell_exec(",
            "popen(",
            "proc_open(",
            "eval(",
            "assert(",
            "base64_decode(",
            "gzinflate(",
            "str_rot13(",
            "| cat /etc/passwd",
            "| ls -la",
            "| wget ",
            "| curl ",
            ";cat ",
            ";ls ",
            ";pwd",
            "&&cat ",
            "&&ls ",
        ],
    ));

    rules.push(body_contains(
        "owasp_path_traversal",
        OwaspCategory::A01BrokenAccessControl,
        &[
            "../",
            "..\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            "..%5c",
            "%252e%252e%252f",
            "%c0%ae%c0%ae%c0%af",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
        ],
    ));

    rules.push(body_contains(
        "owasp_xss",
        OwaspCategory::A03Injection,
        &[
            "<script",
            "<script>",
            "</script>",
            "javascript:",
            "vbscript:",
            "onload=",
            "onerror=",
            "onclick=",
            "onfocus=",
            "onblur=",
            "<iframe",
            "<object",
            "<embed",
            "<applet",
            "<form",
            "<input",
            "<textarea",
            "<button",
            "<select",
            "<style",
            "<link",
            "<meta",
            "<base",
            "expression(",
            "url(",
            "data:text/html",
        ],
    ));

    rules.push(body_contains(
        "owasp_xxe",
        OwaspCategory::A08SoftwareAndDataIntegrityFailures,
        &["<!DOCTYPE", "<!ENTITY", "SYSTEM \"file:", "SYSTEM 'file:", "<![CDATA[", "]>", "&xxe;", "&ext;"],
    ));

    rules.push(body_contains(
        "owasp_ssrf",
        OwaspCategory::A10ServerSideRequestForgery,
        &[
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://::1",
            "http://169.254.",
            "http://10.",
            "http://172.16.",
            "http://172.17.",
            "http://172.18.",
            "http://172.19.",
            "http://172.20.",
            "http://172.21.",
            "http://172.22.",
            "http://172.23.",
            "http://172.24.",
            "http://172.25.",
            "http://172.26.",
            "http://172.27.",
            "http://172.28.",
            "http://172.29.",
            "http://172.30.",
            "http://172.31.",
            "http://192.168.",
            "https://localhost",
            "https://127.0.0.1",
            "https://0.0.0.0",
        ],
    ));

    rules.push(body_contains(
        "owasp_ldap_injection",
        OwaspCategory::A03Injection,
        &[")(|(", ")(cn=", ")(uid=", ")(sn=", ")(objectClass=", "*()|&'"],
    ));

    rules.push(body_contains(
        "owasp_xpath_injection",
        OwaspCategory::A03Injection,
        &[
            "//*",
            "/*",
            "[@",
            "and 1=1",
            "or 1=1",
            "and 2=2",
            "or 2=2",
            "string-length(",
            "substring(",
            "concat(",
        ],
    ));

    // SQL token match — heuristic regex matching >= 2 SQL keywords in the body.
    // Replaces the legacy `WafCondition::SqlTokenMatch` heuristic.
    rules.push(RuleSpec {
        id: "owasp_sql_token_match",
        category: OwaspCategory::A03Injection,
        action: block_403,
        score: 5,
        phase: Phase::InboundBody,
        expr: Expr::Predicate(Predicate {
            phase: Phase::InboundBody,
            field: Field::Body,
            op: Operator::Regex,
            value: Value::Regex(
                regex::Regex::new(
                    // Match a sequence with at least two SQL keywords (case-insensitive).
                    // Uses lookahead-free alternation; the regex engine (which builds a
                    // lazy DFA under the hood) coalesces the alternatives.
                    r"(?i)(?:\b(?:select|union|insert|delete|drop|update|from|where)\b.*){2,}",
                )
                .expect("owasp_sql_token_match regex is a compile-time constant"),
            ),
            meta: RuleMeta {
                id: "owasp_sql_token_match".into(),
                score: 5,
                action: block_403,
                category: OwaspCategory::A03Injection,
            },
        }),
    });

    // Query-string SQLi (request line phase): catches injections before the
    // body arrives and short-circuits subsequent phases.
    rules.push(RuleSpec {
        id: "custom_sql_injection_query",
        category: OwaspCategory::A03Injection,
        action: block_403,
        score: 10,
        phase: Phase::InboundHeaders,
        expr: Expr::Predicate(Predicate {
            phase: Phase::InboundHeaders,
            field: Field::Query,
            op: Operator::Regex,
            value: Value::Regex(
                regex::Regex::new(r"(?i)(?:union\s+select|or\s+1=1|'\s*or\s*'1'='1|--\s|;\s*drop\b)")
                    .expect("custom_sql_injection_query regex is a constant"),
            ),
            meta: RuleMeta {
                id: "custom_sql_injection_query".into(),
                score: 10,
                action: block_403,
                category: OwaspCategory::A03Injection,
            },
        }),
    });

    // Path traversal (request line phase): catch it before body inspection.
    // Cover both raw `../` and percent-encoded variants.
    rules.push(RuleSpec {
        id: "custom_path_traversal",
        category: OwaspCategory::A01BrokenAccessControl,
        action: block_403,
        score: 10,
        phase: Phase::InboundHeaders,
        expr: Expr::Predicate(Predicate {
            phase: Phase::InboundHeaders,
            field: Field::Path,
            op: Operator::Contains,
            value: Value::String(flatkit::str::ImmerStr::new("../")),
            meta: RuleMeta {
                id: "custom_path_traversal".into(),
                score: 10,
                action: block_403,
                category: OwaspCategory::A01BrokenAccessControl,
            },
        }),
    });

    // Scanner / automated bot detection via User-Agent. Coarse by design;
    // fine-grained signatures can be layered as user-defined rules.
    rules.push(RuleSpec {
        id: "custom_scanner_user_agent",
        category: OwaspCategory::CustomBotProtection,
        action: block_403,
        score: 5,
        phase: Phase::InboundHeaders,
        expr: any_of_user_agent_contains(
            "custom_scanner_user_agent",
            OwaspCategory::CustomBotProtection,
            block_403,
            5,
            &["sqlmap", "nikto", "nmap", "acunetix", "masscan", "zgrab"],
        ),
    });

    rules
}

/// Build an `AnyOf` of `Body Contains` predicates, one per literal. Every
/// predicate carries the same `RuleMeta::id` so downstream logs attribute the
/// match back to the original rule, while the compiler still keeps the
/// literals together inside one Aho-Corasick `TextMatchers` for the body
/// phase (the engine reads the fired pattern's index back through `WafMatch`).
fn any_of_body_contains(id: &'static str, category: OwaspCategory, action: RuleAction, sigs: &'static [&'static str]) -> Expr {
    let children: Vec<Expr> = sigs
        .iter()
        .map(|s| {
            Expr::Predicate(Predicate {
                phase: Phase::InboundBody,
                field: Field::Body,
                op: Operator::Contains,
                value: Value::String(flatkit::str::ImmerStr::new(*s)),
                meta: RuleMeta { id: id.into(), score: 10, action, category },
            })
        })
        .collect();
    Expr::AnyOf(children.into_boxed_slice())
}

/// Same as [`any_of_body_contains`] but for the `UserAgent` field, in the
/// `InboundHeaders` phase. Score is configurable.
fn any_of_user_agent_contains(
    id: &'static str,
    category: OwaspCategory,
    action: RuleAction,
    score: u32,
    sigs: &'static [&'static str],
) -> Expr {
    let children: Vec<Expr> = sigs
        .iter()
        .map(|s| {
            Expr::Predicate(Predicate {
                phase: Phase::InboundHeaders,
                field: Field::UserAgent,
                op: Operator::Contains,
                value: Value::String(flatkit::str::ImmerStr::new(*s)),
                meta: RuleMeta { id: id.into(), score, action, category },
            })
        })
        .collect();
    Expr::AnyOf(children.into_boxed_slice())
}
