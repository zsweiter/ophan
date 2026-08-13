---
title: Authentication (JWT, OAuth2, HMAC)
description: Validate JWTs, OAuth2 tokens, and HMAC-signed requests at the edge
tags: ["security"]
order: 400
---

Ophan validates identity at the edge using JWT, OAuth2/OIDC, or HMAC-shared secrets.

> **⚠️ In development** — The auth engine is being built. DPoP and OIDC discovery are planned.

---

## Minimal Policy

```hcl
policy auth "default" {
    issuer   = "https://auth.example.com"
    audience = "api"
}
```

The gateway assumes OIDC discovery, `Authorization: Bearer`, and JWKS caching by default.

## Full Policy

```hcl
policy auth "default" {
    issuer    = "https://auth.example.com"
    audience  = "api"
    client_id = "edge"

    mode "jwks" {
        uri        = "http://localhost:4040/v1/oauth/.well-known/jwks.json"  # defaults to issuer discovery
        ttl        = "1h"
        algorithms = ["RS256", "ES256"]
    }

    # mode "oidc" {
    #     discovery_url = "unix:///var/run/auth.sock/.well-known/openid-configuration"
    #     ttl           = "1h"
    # }

    # mode "static" {
    #     key = env("JWT_SECRET_KEY")
    #     alg = "HS256"
    # }

    dpop_proof = "required"   # auto | required | disabled

    sources {
        header {
            name   = "Authorization"
            prefix = "Bearer "
        }
        cookie {
            name = "access_token"
        }
        query {
            name = "access_token"
        }
    }

    exclude_paths = [
        "src/*",
        "/health",
    ]
}
```

## Verification Modes

| Mode     | Purpose                                 | Status                                                     |
| -------- | --------------------------------------- | ---------------------------------------------------------- |
| `jwks`   | Validate against a remote JWKS endpoint | <span class="status-badge badge-dev">In development</span> |
| `oidc`   | Discover keys via OIDC configuration    | <span class="status-badge badge-dev">In development</span> |
| `static` | HMAC / symmetric key, no JWKS fetch     | <span class="status-badge badge-dev">In development</span> |

### HMAC (symmetric key)

For internal services that share a secret, use a static key with an HMAC algorithm:

```text
mode "static" {
    key = env("JWT_SECRET_KEY")
    alg = "HS256"   # or HS384, HS512
}
```

No JWKS endpoint is fetched; the token is validated locally against the shared secret.

## Token Sources

The `sources` block defines where the access token is extracted from:

| Source   | Properties       |
| -------- | ---------------- |
| `header` | `name`, `prefix` |
| `cookie` | `name`, `prefix` |
| `query`  | `name`, `prefix` |

## Refresh Tokens (planned) <span class="status-badge badge-planned">Planned</span>

```hcl
refresh {
    enabled  = false
    endpoint = "http://localhost:4040/v1/oauth/token"

    sources {
        cookie { name = "refresh_token" }
    }

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
    }
}
```

## Claims

A validated token is decoded into claims that can be propagated upstream:

- `sub`, `exp`, `iat`, `nbf`, `iss`, `aud`, `jti`, `scope`
- `extra_data` — additional custom claims

```rust
ctx.auth = Some(AuthContext { claims, user });
```

## Assigning to Routes

```hcl
path "/api/*" {
    backend = upstream("api")
    policies {
        auth = "default"
    }
}
```

## Next Steps

- [WAF](/waf)
- [Authorization Roadmap (RBAC & ABAC)](/authorization)
