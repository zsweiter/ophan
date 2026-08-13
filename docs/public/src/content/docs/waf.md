---
title: WAF (Web Application Firewall)
description: Anomaly-scoring WAF with OWASP rules and multi-phase inspection
tags: ["security"]
order: 401
---

Ophan ships an anomaly-scoring WAF engine with OWASP rule sets and multi-phase inspection (request headers, request body, response headers, response body).

> **⚠️ In development** — The WAF engine is being built. Custom rules and adaptive L4 reputation are planned.

---

## Minimal Policy

```hcl
policy waf "default" {
    ruleset = "owasp"
}
```

Everything else uses reasonable defaults.

## Full Policy

```hcl
policy waf "default" {
    mode              = "block"       # or "detection_only"
    ruleset           = "owasp"
    max_body_size     = "10mb"
    anomaly_threshold = 5

    rule "block_sqli" {
        phase  = "request"
        action = "block"
        score  = 5

        when = (
            request.method IN ("GET", "POST")
            AND (
                request.query_raw REGEX "(?i)(union\\s+select|select\\s+.*\\s+from)"
                OR request.body_bytes REGEX "(?i)(union\\s+select|select\\s+.*\\s+from)"
            )
            AND NOT (request.path IN ("/search", "/legacy/report"))
        )

        message = "Possible SQL injection payload"
    }

    exclude_paths = [
        "/health",
        "/metrics",
    ]
}
```

## Modes

| Mode             | Behavior                                   |
| ---------------- | ------------------------------------------ |
| `block`          | Enforce the configured action when triggered |
| `detection_only` | Log-only; actions are never enforced       |

## OWASP Rule Set

The default rule set covers the OWASP top attack classes with anomaly scores:

| Rule ID                 | Attack Type                 | Score |
| ----------------------- | --------------------------- | ----- |
| `owasp_sql_injection`   | SQL Injection               | 10    |
| `owasp_rce`             | Remote Code Execution       | 10    |
| `owasp_path_traversal`  | Path Traversal              | 10    |
| `owasp_xss`             | Cross-Site Scripting        | 10    |
| `owasp_xxe`             | XML External Entities       | 10    |
| `owasp_ssrf`            | Server-Side Request Forgery | 8     |
| `owasp_ldap_injection`  | LDAP Injection              | 8     |
| `owasp_xpath_injection` | XPath Injection             | 8     |
| `owasp_sql_token_match` | SQL Token Heuristic         | 5     |

## Scoring

- Each matched rule adds its score to an anomaly counter
- If the counter exceeds `anomaly_threshold`, the configured action is taken
- In `detection_only`, actions are logged but never enforced

## Inspection Phases

| Phase             | Scope                                            |
| ----------------- | ------------------------------------------------ |
| `request_headers` | User-Agent, cookies, auth, protocol compliance   |
| `request_body`    | SQLi, XSS, path traversal, RCE, command injection |
| `response_headers`| Removes implementation details (`Server`, `X-Powered-By`) |
| `response_body`   | PII detection, credit-card masking, token leakage (DLP) |

## Custom Rules (planned) <span class="status-badge badge-planned">Planned</span>

Custom rules use a declarative condition language:

```hcl
rule "block_suspicious_redirect" {
    phase  = "request"
    action = "block"
    score  = 5

    when = (
        request.method IN ("GET", "POST")
        AND request.query_param("redirect") EXISTS
        AND (
            request.query_param("redirect") STARTS_WITH "javascript:"
            OR request.query_param("redirect") CONTAINS "../"
        )
    )
}
```

Conditions: `IN`, `EXISTS`, `STARTS_WITH`, `CONTAINS`, `REGEX`, combined with `AND` / `OR` / `NOT`.

## Layer 4 ↔ Layer 7

WAF inspection runs at **Layer 7** (after TLS termination). Network filtering happens earlier at **Layer 4** (XDP/software). A planned feedback loop promotes malicious clients into the L4 blocklist. See [Network Filtering](/network-filtering).

## Next Steps

- [Authentication](/authentication)
- [Rate Limiting](/rate-limiting)
- [Network Filtering](/network-filtering)