# ophan-waf — Web Application Firewall Engine

> ⚠️ **Active Development** — API may change without notice.

Anomaly-scoring WAF engine with OWASP rule sets and multi-phase inspection (request headers, request body, response headers, response body).

## Public API

### WafEngine

Core inspection engine. Stateless — all config is passed on each call.

```rust
pub struct WafEngine;

impl WafEngine {
    pub fn new() -> Self;

    /// Inspect a request or response phase.
    /// Returns a `WafResult` indicating whether to allow, log, or block.
    pub fn inspect(
        &self,
        config: &WafConfig,
        phase: WafPhase,
        headers: &http::request::Parts,
        body: &[u8],
    ) -> WafResult;
}
```

### WafResult

Outcome of a WAF inspection.

```rust
pub enum WafResult {
    Allow,
    Log(String),
    Action(WafAction, String),
}
```

### WafConfig

Configuration for a WAF inspection context.

```rust
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub rules: Vec<WafRule>,
    pub max_body_size: usize,
    pub anomaly_threshold: u32,
    pub excludes: Vec<String>,
}

impl WafConfig {
    /// Merge another config into this one (non-empty fields overwrite).
    pub fn merge(&mut self, other: WafConfig);
}
```

### WafMode

Detection mode.

```rust
pub enum WafMode {
    DetectionOnly,
    Blocking,
}
```

### WafRule

Individual WAF rule definition.

```rust
pub struct WafRule {
    pub id: String,
    pub phase: WafPhase,
    pub condition: WafCondition,
    pub action: WafAction,
    pub score: u32,
}
```

### WafPhase

Inspection phase.

```rust
pub enum WafPhase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}
```

### WafAction

Action to take when a rule matches.

```rust
pub enum WafAction {
    Log,
    Block,
    Redirect(String),
    Challenge,
    RateLimit,
    Allow,
}
```

### WafCondition

Matching conditions for WAF rules.

```rust
pub enum WafCondition {
    IpMatch(Vec<String>),
    PathStartsWith(String),
    HeaderContains { header: String, value: String },
    BodyContains(Vec<String>),
    UserAgentContains(Vec<String>),
    SqlTokenMatch,
    BodyRegex(String),
}
```

## Included OWASP Rules

The `Default` implementation includes rule sets for:

| Rule ID | Attack Type | Score |
|---------|------------|-------|
| `owasp_sql_injection` | SQL Injection | 10 |
| `owasp_rce` | Remote Code Execution | 10 |
| `owasp_path_traversal` | Path Traversal | 10 |
| `owasp_xss` | Cross-Site Scripting | 10 |
| `owasp_xxe` | XML External Entities | 10 |
| `owasp_ssrf` | Server-Side Request Forgery | 8 |
| `owasp_ldap_injection` | LDAP Injection | 8 |
| `owasp_xpath_injection` | XPath Injection | 8 |
| `owasp_sql_token_match` | SQL Token Heuristic | 5 |

## Scoring

- Each matched rule adds its score to an anomaly counter.
- If the counter exceeds `anomaly_threshold`, the configured action is taken.
- In `DetectionOnly` mode, actions are logged but never enforced.
