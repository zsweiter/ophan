# WAF

The Web Application Firewall inspects HTTP requests and applies rules before the request is forwarded to the upstream service.

WAF rules can inspect request properties such as:

- HTTP method
- request path
- raw query string
- query parameters
- request body
- request headers
- other request metadata

Rules can either block requests directly or contribute to an anomaly score.

## Minimal

```hcl
policy waf "default" {
    ruleset = "owasp"
}
```

The minimal configuration enables the predefined OWASP ruleset.

---

## Full

```hcl
policy waf "default" {
    mode = "block"
    ruleset = "owasp"

    max_body_size = "10mb"
    anomaly_threshold = 5

    rule "block_sqli_like_request" {
        phase = "request"
        action = "block"
        score = 5

        when = (
            request.method IN ("GET", "POST")
            AND (
                request.query_raw REGEX "(?i)(union\\s+select|select\\s+.*\\s+from)"
                OR request.body_bytes REGEX "(?i)(union\\s+select|select\\s+.*\\s+from)"
            )
            AND NOT (
                request.path IN ("/search", "/legacy/report")
            )
        )

        message = "Possible SQL injection payload"
    }

    rule "block_suspicious_redirect" {
        phase = "request"
        action = "block"
        score = 5

        when = (
            request.method IN ("GET", "POST")
            AND request.query_param("redirect") EXISTS
            AND (
                request.query_param("redirect") STARTS_WITH "javascript:"
                OR request.query_param("redirect") CONTAINS "../"
                OR request.query_param("redirect") REGEX "(?i)(data|vbscript):"
            )
        )

        message = "Suspicious redirect parameter"
    }

    exclude_paths = [
        "/health",
        "/metrics"
    ]
}
```

### WAF mode

`mode` determines how matching rules are enforced.

```hcl
mode = "block"
```

causes matching requests to be rejected.

A detection-only mode can be used when deploying or tuning rules before enforcing them.

### Rulesets

`ruleset` selects a predefined collection of WAF rules.

```hcl
ruleset = "owasp"
```

provides a baseline ruleset based on common web-application attack patterns.

Custom rules can be added with the `rule` block.

### Anomaly scoring

Rules may assign a score to a matching request:

```hcl
score = 5
```

The accumulated score can then be compared against:

```hcl
anomaly_threshold = 5
```

This allows multiple low-confidence signals to be combined before deciding whether a request should be blocked.

### Rule expressions

The `when` expression defines the conditions under which a rule matches.

Supported operators include logical operators such as:

```text
AND
OR
NOT
```

and request matching operators such as:

```text
IN
EXISTS
REGEX
CONTAINS
STARTS_WITH
ENDS_WITH
```

This allows rules to combine multiple request properties into a single condition.

### Request phases

The `phase` determines when a rule is evaluated.

For example:

```hcl
phase = "request"
```

evaluates the rule during request processing.

This allows the WAF to be extended to other processing phases without changing the rule language.

### Request body limits

```hcl
max_body_size = "10mb"
```

limits the amount of request-body data that the WAF will inspect.

This prevents unnecessarily large request bodies from consuming excessive memory or processing resources.

### Path exclusions

Paths matching `exclude_paths` bypass the WAF policy.

```hcl
exclude_paths = [
    "/health",
    "/metrics"
]
```

Exclusions should be limited to endpoints that are intentionally outside the scope of WAF inspection.
