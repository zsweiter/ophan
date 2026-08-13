# Rate Limiting

Rate-limiting policies restrict the number of requests that a client can make during a given period.

## Minimal

```hcl
policy limiter "default" {
    rate = "100/s"
}
```

The minimal configuration allows up to **100 requests per second** for each client identified by the default identifier.

---

## Full

```hcl
policy limiter "default" {
    rate = "100/s"
    burst = 50

    # Supported identifiers:
    #   ip
    #   header:{name}
    #   token:{dotted json path}
    identifier = "ip"

    strategy = "sliding_window"

    exclude_paths = [
        "src/*"
    ]
}
```

### Rate

`rate` defines the sustained request rate.

Examples:

```hcl
rate = "100/s"
rate = "1000/m"
rate = "10000/h"
```

### Burst

`burst` allows a client to temporarily exceed the configured sustained rate.

```hcl
burst = 50
```

This is useful for absorbing short traffic spikes without immediately rejecting requests.

### Identifier

The `identifier` determines how requests are grouped for rate limiting.

```hcl
identifier = "ip"
```

limits clients by their source IP address.

A request header can also be used:

```hcl
identifier = "header:X-API-Key"
```

A value from a JWT claim can be used through a dotted JSON path:

```hcl
identifier = "token:sub"
```

This makes it possible to rate-limit users, API clients, tenants, or other identities represented in the access token.

### Strategy

The `strategy` controls how the rate limit window is calculated.

```hcl
strategy = "sliding_window"
```

uses a sliding-window algorithm to provide smoother rate enforcement than a fixed window.

### Path exclusions

Paths matching `exclude_paths` bypass the rate limiter.

```hcl
exclude_paths = [
    "/health",
    "public/*"
]
```
