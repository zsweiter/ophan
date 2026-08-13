# Authentication

Ophan authentication policies validate incoming access tokens and can optionally handle token refresh and DPoP sender-constrained authentication.

## Minimal

```hcl
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
}
```

With this minimal configuration, the gateway assumes:

- **OIDC Discovery** is available at the issuer's discovery endpoint.
- **JWT Bearer tokens** are used for authentication.
- The `Authorization` header accepts the `Bearer` authentication scheme.
- **JWKS caching** is enabled by default.
- The issuer is used as the base URL for discovering the OpenID configuration and JWKS endpoint.

The minimal configuration is intended for standard OIDC deployments where the identity provider exposes its discovery and JWKS endpoints according to the OIDC specification.

---

## Full

```hcl
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
    client_id = "edge"

    mode "jwks" {
        # Optional. If omitted, the JWKS URI is derived from the issuer.
        uri = "http://localhost:4040/v1/oauth/.well-known/jwks.json"

        ttl = "1h"
        algorithms = ["RS256", "ES256"]
    }

    # Alternative: use OIDC Discovery explicitly.
    #
    # mode "oidc" {
    #     discovery_url = "unix:///var/run/auth.sock/.well-known/openid-configuration"
    #     ttl = "1h"
    # }

    # Alternative: use a statically configured signing key.
    #
    # mode "static" {
    #     key = env("JWT_SECRET_KEY")
    #     alg = "HS256"
    # }

    # DPoP enforcement:
    #   auto     - accept Bearer or DPoP according to the token/request
    #   required - require a valid DPoP proof
    #   disabled - do not perform DPoP validation
    dpop_proof = "required"

    sources {
        header {
            name = "Authorization"
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

        # Refreshed tokens can be delivered through different channels.
        # This is useful when the same gateway serves browser and mobile
        # clients, which may have different token transport requirements.
        inject {
            access_token {
                header {
                    name = "X-Access-Token"
                }

                cookie {
                    name = "op_token"
                    path = "/"
                    http_only = true
                    secure = true
                    same_site = "Lax"
                }
            }

            refresh_token {
                cookie {
                    name = "op_refresh"
                    path = "/"
                    http_only = true
                    secure = true
                }
            }
        }
    }

    # Paths matching these glob patterns bypass this authentication policy.
    exclude_paths = [
        "src/*"
    ]
}
```

### Authentication sources

The `sources` block defines where the gateway looks for access tokens.

Supported sources include:

- **Header** — extracts the token from an HTTP header, optionally requiring a specific prefix.
- **Cookie** — extracts the token from a cookie.
- **Query parameter** — extracts the token from a URL query parameter.

For example:

```hcl
header {
    name = "Authorization"
    prefix = "Bearer "
}
```

requires an `Authorization` header using the `Bearer` scheme.

### Token verification modes

The authentication policy can obtain signing keys in different ways:

- **JWKS** — retrieve signing keys from a configured JWKS endpoint.
- **OIDC** — use OIDC Discovery to locate the provider's JWKS endpoint and other metadata.
- **Static** — use a statically configured signing key.

JWKS and OIDC modes support key caching to avoid fetching signing keys on every request.

### DPoP

DPoP can be used to bind an access token to a client's public key.

```hcl
dpop_proof = "required"
```

When DPoP is required, requests must provide a valid DPoP proof and the proof must be consistent with the key binding in the access token.

### Token refresh

The `refresh` block configures automatic access-token refresh using a refresh token.

The refreshed tokens can be injected into response headers, cookies, or other supported destinations. This allows the gateway to support different client architectures, such as browser applications using secure cookies and mobile clients using response headers.

### Path exclusions

`exclude_paths` accepts glob patterns. Matching paths bypass the authentication policy.

```hcl
exclude_paths = [
    "/health",
    "/metrics",
    "public/*"
]
```

This is commonly used for health checks, metrics endpoints, public assets, or other explicitly unauthenticated routes.
