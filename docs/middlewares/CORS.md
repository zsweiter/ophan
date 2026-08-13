# CORS

CORS policies control which cross-origin browser requests are allowed to access the gateway.

## Minimal

```hcl
policy cors "default" {
    allow_origins = ["https://example.com"]
}
```

This configuration allows browser requests originating from `https://example.com`.

---

## Full

```hcl
policy cors "default" {
    allow_origins = [
        "https://app.example.me",
        "https://example.me",
        "https://admin.example.me",
        "https://api.example.me"
    ]

    allow_methods = [
        "GET",
        "POST",
        "DELETE",
        "PUT",
        "PATCH",
        "HEAD",
        "OPTIONS"
    ]

    allow_headers = [
        "Authorization",
        "X-Request-Id"
    ]

    expose_headers = [
        "X-Request-Id"
    ]

    allow_credentials = true
    max_age = "2h"

    exclude_paths = [
        "src/*"
    ]
}
```

### Allowed origins

`allow_origins` defines the origins that may access the resource from a browser.

Origins should include their scheme when required by the configuration, for example:

```hcl
allow_origins = [
    "https://app.example.com"
]
```

### Methods and headers

`allow_methods` defines the HTTP methods permitted for cross-origin requests.

`allow_headers` defines which request headers the browser is allowed to send.

`expose_headers` defines which response headers browser JavaScript is allowed to read.

### Credentials

```hcl
allow_credentials = true
```

allows browsers to include credentials such as cookies in cross-origin requests.

When credentials are enabled, wildcard origins must not be used because browsers do not allow credentialed CORS requests with `Access-Control-Allow-Origin: *`.

### Preflight caching

`max_age` controls how long browsers may cache the result of a CORS preflight request.

```hcl
max_age = "2h"
```

reduces the number of `OPTIONS` preflight requests required during that period.

### Path exclusions

Paths matching `exclude_paths` bypass the CORS policy.
