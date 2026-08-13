# Auth

## Minimal

```hcl
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
}
```

gateway defaults:

- OIDC Discovery
- JWT Bearer
- Authorization: Bearer | DPoP
- JWKS cache by default

---

## Full

```hcl
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
    client_id = "edge"

    mode "jwks" {
        uri = "http://localhost:4040/v1/oauth/.well-known/jwks.json" # optional if omited joined with issuer
        ttl = "1h"
        algorithms = ["RS256", "ES256"]
    }

    # mode "oidc" {
    #   discovery_url = "unix:///var/run/auth.sock/.well-known/openid-configuration" # optional if omited joined with issuer
    #   ttl = 1h
    # }

    # mode "static" {
    #   key = env("JWT_SECRET_KEY")
    #   alg = "HS256"
    # }

    dpop_poof = "required"    # auto | required | false | "disabled"

    sources {
        header {
            name = "Authorization",
            prefix = "Bearer "
        }
        cookie {
            name = "access_token"
        }
        query {
            name = "access_token"
        }
    }

    refresh {
        enabled = false
        endpoint = "http://localhost:4040/v1/oauth/token"

        sources {
            cookie {
                name = "refresh_token"
            }
        }
        # destination of new tokens, have varios ways because in mobile is best idea parse headers, in web only cookie
        inject {
            access_token {
                header { name = "X-Access-Token" }
                cookie {
                    name      = "op_token"
                    path      = "/"
                    http_only = true
                    secure    = true
                    same_site = "Lax"
                }
            }
            refresh_token {
                cookie {
                    name      = "op_refre"
                    path      = "/"
                    http_only = true
                    secure    = true
                }
            }
        }
    }

    # skip paths in this list based in glob expresion
    exclude_paths = [
        "src/*"
    ]
}
```

---

# Limiter

## Minimal

```hcl
policy limiter "default" {
    rate = "100/s"
}
```

---

## Full

```hcl
policy limiter "default" {
    rate = "100/s"
    burst = 50
    identifier = "ip" # "header:{name}" "token:{dotted json path}"
    strategy = "token_bucket"

    exclude_paths = [
        "src/*"
    ]
}
```

---

# CORS

## Minimal

```hcl
policy cors "default" {
    allow_origins = ["https://example.com"]
}
```

---

## Full

```hcl
policy cors "default" {
    allow_origins = ["app.example.me", "example.me", "admin.example.me", "api.example.me"]
    allow_methods = ["GET", "POST", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS"]
    allow_headers = ["Authorization", "X-Request-Id"]
    expose_headers = ["X-Request-Id"]
    allow_credentials = true
    max_age = "2h"

    exclude_paths = [
        "src/*"
    ]
}
```

---

# Helmet

```hcl
policy helmet "web-strict" {
    target = "web"
    level = "strict"
}
```

---

# WAF
## Minimal

```hcl
policy waf "default" {
    ruleset = "owasp"
}
```

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
